//! Architecture analyzer for GeneratedTransformer instances.
//!
//! Port of analyzer.py. Inspects whether key-generated architectures are
//! structurally healthy: diffusion coverage, dead inputs, weight
//! distribution, and S-box differential uniformity / fixed points. This
//! is a set of *structural sanity checks*, not a cryptanalytic security
//! proof.

use std::collections::{HashMap, HashSet};

use rand::{Rng, RngCore};

use crate::cipher::{
    self, generate_key, transformer_function, CipherContext, GeneratedTransformer, TopologyConstraints,
    TopologyDiagnostics, BLOCK_SIZE, HALF_SIZE,
};

// ============================================================
// Dependency / diffusion analysis
// ============================================================

/// For each of the HALF_SIZE output positions after the full transformer,
/// the set of raw input byte indices that could structurally influence it
/// (ignoring possible algebraic cancellation -- this is an upper bound on
/// what a linear/differential analysis could exploit, i.e. a lower bound
/// on how bad the diffusion could be).
pub fn dependency_sets(transformer: &GeneratedTransformer) -> Vec<HashSet<usize>> {
    let mut dep: Vec<HashSet<usize>> = (0..HALF_SIZE).map(|i| HashSet::from([i])).collect();
    for layer in 0..transformer.depth {
        let mut new_dep: Vec<HashSet<usize>> = vec![HashSet::new(); HALF_SIZE];
        let layer_connections = &transformer.connections[layer];
        for head in 0..transformer.heads {
            let connections = &layer_connections[head];
            for output_node in 0..HALF_SIZE {
                let (sources, _weights) = &connections[output_node];
                for &s in sources {
                    let src_dep = dep[s].clone();
                    new_dep[output_node].extend(src_dep);
                }
            }
        }
        dep = new_dep;
    }
    dep
}

pub struct DiffusionReport {
    pub depth: usize,
    pub heads: usize,
    pub full_diffusion: bool,
    pub coverage_fraction: f64, // 1.0 = every output depends on every input
    pub per_output_dependency_count: Vec<usize>,
    pub dead_inputs: Vec<usize>,
}

pub fn diffusion_report(transformer: &GeneratedTransformer) -> DiffusionReport {
    let dep = dependency_sets(transformer);
    let per_output_counts: Vec<usize> = dep.iter().map(|d| d.len()).collect();
    let full = per_output_counts.iter().all(|&c| c == HALF_SIZE);
    let coverage_fraction =
        per_output_counts.iter().sum::<usize>() as f64 / (HALF_SIZE * HALF_SIZE) as f64;

    let mut reachable_inputs: HashSet<usize> = HashSet::new();
    for d in &dep {
        reachable_inputs.extend(d.iter().copied());
    }
    let mut dead_inputs: Vec<usize> = (0..HALF_SIZE).filter(|i| !reachable_inputs.contains(i)).collect();
    dead_inputs.sort_unstable();

    DiffusionReport {
        depth: transformer.depth,
        heads: transformer.heads,
        full_diffusion: full,
        coverage_fraction,
        per_output_dependency_count: per_output_counts,
        dead_inputs,
    }
}

// ============================================================
// Weight distribution
// ============================================================

pub struct WeightStats {
    pub count: usize,
    pub mean: f64,
    pub stdev: f64,
    pub min: u8,
    pub max: u8,
    pub zero_count: usize, // should always be 0 (forced nonzero)
    pub source_usage: HashMap<usize, usize>,
}

pub fn weight_stats(transformer: &GeneratedTransformer) -> WeightStats {
    let mut weights: Vec<u8> = Vec::new();
    let mut source_usage: HashMap<usize, usize> = HashMap::new();
    for layer in &transformer.connections {
        for head in layer {
            for (sources, w) in head {
                weights.extend(w.iter().copied());
                for &s in sources {
                    *source_usage.entry(s).or_insert(0) += 1;
                }
            }
        }
    }

    let count = weights.len();
    let sum: f64 = weights.iter().map(|&w| w as f64).sum();
    let mean = sum / count as f64;
    let variance: f64 = if count > 1 {
        weights.iter().map(|&w| (w as f64 - mean).powi(2)).sum::<f64>() / count as f64
    } else {
        0.0
    };
    let stdev = variance.sqrt();
    let min = *weights.iter().min().unwrap();
    let max = *weights.iter().max().unwrap();
    let zero_count = weights.iter().filter(|&&w| w == 0).count();

    WeightStats { count, mean, stdev, min, max, zero_count, source_usage }
}

// ============================================================
// S-box quality metrics
// ============================================================

pub fn sbox_is_bijective(sbox: &[u8]) -> bool {
    let mut sorted: Vec<u8> = sbox.to_vec();
    sorted.sort_unstable();
    sorted.iter().enumerate().all(|(i, &v)| i as u8 == v) && sorted.len() == sbox.len()
}

pub fn sbox_fixed_points(sbox: &[u8]) -> usize {
    sbox.iter().enumerate().filter(|(i, &v)| *i as u8 == v).count()
}

/// Max over nonzero input differences of the max count of output
/// differences (standard differential uniformity metric). Lower is
/// better; AES's S-box achieves 4. A permutation with poor diffusion
/// can have much higher values (up to 256 for the identity function).
pub fn sbox_differential_uniformity(sbox: &[u8]) -> usize {
    let n = sbox.len();
    let mut max_count = 0usize;
    for delta_in in 1..n {
        let mut counts: HashMap<u8, usize> = HashMap::new();
        for x in 0..n {
            let delta_out = sbox[x] ^ sbox[x ^ delta_in];
            *counts.entry(delta_out).or_insert(0) += 1;
        }
        let local_max = *counts.values().max().unwrap();
        if local_max > max_count {
            max_count = local_max;
        }
    }
    max_count
}

/// Exact (fully exhaustive over all 256 inputs), deduplicated set of
/// output differences achievable for one specific input difference --
/// i.e. one full row of the S-box's differential distribution table
/// (DDT), rather than just its worst-case count. `delta_in = 0` returns
/// `[0]` trivially. Building block for exact (not sampled) multi-node
/// differential composition below.
pub fn sbox_ddt_row(sbox: &[u8], delta_in: u8) -> Vec<u8> {
    let mut seen = [false; 256];
    for x in 0..256usize {
        let delta_out = sbox[x] ^ sbox[x ^ delta_in as usize];
        seen[delta_out as usize] = true;
    }
    (0u16..256).filter(|&d| seen[d as usize]).map(|d| d as u8).collect()
}

/// Count of x where S(x) = x XOR 0xFF -- the bitwise-complement analogue
/// of a fixed point. Some S-box design guidance flags these alongside
/// ordinary fixed points because both are trivially predictable
/// input/output relationships an attacker can special-case.
pub fn sbox_opposite_fixed_points(sbox: &[u8]) -> usize {
    sbox.iter().enumerate().filter(|(i, &v)| v == (*i as u8) ^ 0xFF).count()
}

/// Cycle lengths of the S-box viewed as a permutation, longest first.
/// Not a strength metric by itself, but a very short cycle (especially a
/// 1-cycle, i.e. a fixed point) or a skewed cycle distribution is the
/// kind of structural regularity attackers look for first.
pub fn sbox_cycle_structure(sbox: &[u8]) -> Vec<usize> {
    let n = sbox.len();
    let mut visited = vec![false; n];
    let mut cycles = Vec::new();
    for start in 0..n {
        if visited[start] {
            continue;
        }
        let mut len = 0usize;
        let mut x = start;
        while !visited[x] {
            visited[x] = true;
            x = sbox[x] as usize;
            len += 1;
        }
        cycles.push(len);
    }
    cycles.sort_unstable_by(|a, b| b.cmp(a));
    cycles
}

/// Linear approximation table maximum bias, and the resulting
/// nonlinearity, using the standard convention LAT[a][b] = #{x : parity(a
/// AND x) = parity(b AND S(x))} - 128, taken over a in 0..256 and b in
/// 1..256 (b=0 is the trivial "predict a constant" case and excluded).
/// linearity = max |LAT[a][b]|; nonlinearity = 128 - linearity. AES's
/// S-box achieves nonlinearity 112 (linearity 16) -- the maximum
/// achievable for an 8-bit bijection is nonlinearity 116, so 112 is
/// already very close to optimal.
pub fn sbox_linearity_and_nonlinearity(sbox: &[u8]) -> (usize, usize) {
    let n = sbox.len();
    let mut linearity: i32 = 0;
    for b in 1..n {
        for a in 0..n {
            let mut count: i32 = 0;
            for x in 0..n {
                let lhs = (a & x).count_ones() & 1;
                let rhs = (b & sbox[x] as usize).count_ones() & 1;
                if lhs == rhs {
                    count += 1;
                }
            }
            let deviation = (count - (n as i32) / 2).abs();
            if deviation > linearity {
                linearity = deviation;
            }
        }
    }
    let nonlinearity = (n as i32) / 2 - linearity;
    (linearity as usize, nonlinearity as usize)
}

/// Algebraic degree: the maximum degree, over every nonzero linear
/// combination of output bits, of that Boolean function's algebraic
/// normal form (ANF). Computed via the standard in-place Mobius (XOR)
/// transform. Field inversion in GF(2^8), the core of both AES's S-box
/// and this one, achieves the maximum possible degree for an 8-bit
/// bijection: 7.
pub fn sbox_algebraic_degree(sbox: &[u8]) -> usize {
    let n_bits = 8;
    let size = 256;
    let mut max_degree = 0u32;
    for b in 1..size {
        let mut table: Vec<u8> = (0..size)
            .map(|x| ((b & sbox[x] as usize).count_ones() & 1) as u8)
            .collect();
        for i in 0..n_bits {
            let bit = 1usize << i;
            for x in 0..size {
                if x & bit != 0 {
                    table[x] ^= table[x ^ bit];
                }
            }
        }
        let deg = (0..size)
            .filter(|&u| table[u] == 1)
            .map(|u| (u as u32).count_ones())
            .max()
            .unwrap_or(0);
        max_degree = max_degree.max(deg);
    }
    max_degree as usize
}

/// Maximum absolute autocorrelation ("absolute indicator") over every
/// nonzero input shift a and every nonzero output combination b:
/// r(a,b) = sum_x (-1)^{f_b(x) XOR f_b(x XOR a)}. Values near 0 mean the
/// component functions look unrelated to shifted copies of themselves
/// (good avalanche behavior); a large value flags an exploitable
/// self-similarity. AES's S-box has an absolute indicator of 32 (out of
/// a max possible 256).
pub fn sbox_max_autocorrelation(sbox: &[u8]) -> usize {
    let n = sbox.len();
    let mut max_abs: i32 = 0;
    for b in 1..n {
        let f: Vec<i32> = (0..n)
            .map(|x| {
                let bit = (b & sbox[x] as usize).count_ones() & 1;
                if bit == 0 {
                    1
                } else {
                    -1
                }
            })
            .collect();
        for a in 1..n {
            let mut sum: i32 = 0;
            for x in 0..n {
                sum += f[x] * f[x ^ a];
            }
            max_abs = max_abs.max(sum.abs());
        }
    }
    max_abs as usize
}

/// Full quality report for one S-box, bundling every metric above.
pub struct SboxQualityReport {
    pub bijective: bool,
    pub fixed_points: usize,
    pub opposite_fixed_points: usize,
    pub differential_uniformity: usize,
    pub linearity: usize,
    pub nonlinearity: usize,
    pub algebraic_degree: usize,
    pub max_autocorrelation: usize,
    pub cycle_lengths: Vec<usize>,
}

pub fn sbox_quality_report(sbox: &[u8]) -> SboxQualityReport {
    let (linearity, nonlinearity) = sbox_linearity_and_nonlinearity(sbox);
    SboxQualityReport {
        bijective: sbox_is_bijective(sbox),
        fixed_points: sbox_fixed_points(sbox),
        opposite_fixed_points: sbox_opposite_fixed_points(sbox),
        differential_uniformity: sbox_differential_uniformity(sbox),
        linearity,
        nonlinearity,
        algebraic_degree: sbox_algebraic_degree(sbox),
        max_autocorrelation: sbox_max_autocorrelation(sbox),
        cycle_lengths: sbox_cycle_structure(sbox),
    }
}

// ============================================================
// Empirical differential / active-byte propagation analysis
// ============================================================
//
// Everything above (diffusion coverage, S-box DDT/LAT/ANF metrics) is
// either exact (S-box metrics: exhaustively computed over all 256
// inputs) or a structural upper bound (dependency_sets: "could this
// output possibly depend on this input", ignoring algebraic
// cancellation). Neither tells us how a specific *difference* actually
// propagates through the real, keyed F/G transformers or the full
// multi-round cipher.
//
// A real DDT-style exhaustive search is only feasible for the 8-bit
// S-box (256x256 table). F and G map HALF_SIZE=8 bytes to 8 bytes -- a
// domain of 256^8, far too large to search exhaustively -- and the full
// block is 256^16. So everything in this section is EMPIRICAL: random
// sampling of base states and difference patterns, repeated `trials`
// times, reporting the min/mean/max active-byte count observed.
//
// IMPORTANT CAVEAT: the "min" reported here is the minimum *observed*
// over the sampled trials, not a proven worst case the way the S-box's
// DU=4 is proven. A rare, structurally-special difference that happens
// to propagate poorly could exist without showing up in a few thousand
// random trials. This is a statistical health check, not a differential
// security proof -- see docs/DIFFERENTIAL_ANALYSIS.md at the repo root.
// It also does not address whether the accept/reject topology-constraint
// process in `cipher.rs` (candidate generation + rejection sampling)
// introduces its own structural bias into which architectures a key can
// produce; that question is open.

/// Counts the number of nonzero bytes in a byte-difference (i.e. how many
/// byte positions differ between the two states this difference relates).
pub fn active_bytes(diff: &[u8]) -> usize {
    diff.iter().filter(|&&b| b != 0).count()
}

fn random_nonzero_byte(rng: &mut impl Rng) -> u8 {
    rng.gen_range(1u8..=255u8)
}

/// Builds a random `size`-byte difference pattern with exactly
/// `active_in` nonzero bytes at random positions and random nonzero
/// values.
fn random_difference(size: usize, active_in: usize, rng: &mut impl Rng) -> Vec<u8> {
    let mut positions: Vec<usize> = (0..size).collect();
    for i in 0..active_in.min(size) {
        let j = rng.gen_range(i..size);
        positions.swap(i, j);
    }
    let mut delta = vec![0u8; size];
    for &p in &positions[..active_in.min(size)] {
        delta[p] = random_nonzero_byte(rng);
    }
    delta
}

pub struct ActiveByteExpansion {
    pub active_in: usize,
    pub trials: usize,
    pub min_active_out: usize,
    pub mean_active_out: f64,
    pub max_active_out: usize,
    /// Trials where the output difference was entirely zero despite a
    /// nonzero input difference -- an actual differential collision
    /// through this transformer. Not necessarily catastrophic on its own
    /// (the surrounding permutation/S-box/round-key layers may still
    /// break it up), but worth watching: it should be rare and ideally
    /// never observed for active_in > 0.
    pub zero_output_count: usize,
}

/// Empirically measures, for one `GeneratedTransformer` (F or G) in
/// isolation, how many output bytes end up active when `active_in` input
/// bytes are perturbed. See the module-level caveat above: this is a
/// sampled minimum, not a proven one.
pub fn active_byte_expansion(
    transformer: &GeneratedTransformer,
    active_in: usize,
    trials: usize,
) -> ActiveByteExpansion {
    let mut rng = rand::thread_rng();

    let mut min_active_out = usize::MAX;
    let mut max_active_out = 0usize;
    let mut sum_active_out = 0usize;
    let mut zero_output_count = 0usize;

    for _ in 0..trials {
        let mut base = vec![0u8; HALF_SIZE];
        rng.fill_bytes(&mut base);
        let delta = random_difference(HALF_SIZE, active_in, &mut rng);
        let other: Vec<u8> = base.iter().zip(delta.iter()).map(|(a, b)| a ^ b).collect();

        let y1 = transformer_function(&base, transformer);
        let y2 = transformer_function(&other, transformer);
        let out_diff: Vec<u8> = y1.iter().zip(y2.iter()).map(|(a, b)| a ^ b).collect();
        let active_out = active_bytes(&out_diff);

        min_active_out = min_active_out.min(active_out);
        max_active_out = max_active_out.max(active_out);
        sum_active_out += active_out;
        if active_out == 0 {
            zero_output_count += 1;
        }
    }

    ActiveByteExpansion {
        active_in,
        trials,
        min_active_out,
        mean_active_out: sum_active_out as f64 / trials as f64,
        max_active_out,
        zero_output_count,
    }
}

/// `active_byte_expansion` for every active_in from 1 to HALF_SIZE, so
/// callers get the full "input active bytes -> output active bytes"
/// curve for one transformer in one call.
pub fn active_byte_expansion_report(
    transformer: &GeneratedTransformer,
    trials_per_level: usize,
) -> Vec<ActiveByteExpansion> {
    (1..=HALF_SIZE)
        .map(|active_in| active_byte_expansion(transformer, active_in, trials_per_level))
        .collect()
}

pub struct RoundDifferentialStats {
    pub round: usize,
    pub active_in: usize,
    pub trials: usize,
    pub min_active_out: usize,
    pub mean_active_out: f64,
    pub max_active_out: usize,
    pub zero_output_count: usize,
}

/// Same idea as `active_byte_expansion`, but for one *full round*
/// (S-box -> permutation -> F/G coupling) of a real `CipherContext`,
/// operating on the full BLOCK_SIZE=16 state rather than one
/// transformer's HALF_SIZE=8 input. Round-key XOR is skipped (see
/// `cipher::round_transform_no_key`) since it's differential-invariant.
pub fn round_differential_stats(
    ctx: &CipherContext,
    round: usize,
    active_in: usize,
    trials: usize,
) -> RoundDifferentialStats {
    let mut rng = rand::thread_rng();

    let mut min_active_out = usize::MAX;
    let mut max_active_out = 0usize;
    let mut sum_active_out = 0usize;
    let mut zero_output_count = 0usize;

    for _ in 0..trials {
        let mut base = vec![0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut base);
        let delta = random_difference(BLOCK_SIZE, active_in, &mut rng);
        let other: Vec<u8> = base.iter().zip(delta.iter()).map(|(a, b)| a ^ b).collect();

        let out1 = cipher::round_transform_no_key(&base, ctx, round);
        let out2 = cipher::round_transform_no_key(&other, ctx, round);
        let out_diff: Vec<u8> = out1.iter().zip(out2.iter()).map(|(a, b)| a ^ b).collect();
        let active_out = active_bytes(&out_diff);

        min_active_out = min_active_out.min(active_out);
        max_active_out = max_active_out.max(active_out);
        sum_active_out += active_out;
        if active_out == 0 {
            zero_output_count += 1;
        }
    }

    RoundDifferentialStats {
        round,
        active_in,
        trials,
        min_active_out,
        mean_active_out: sum_active_out as f64 / trials as f64,
        max_active_out,
        zero_output_count,
    }
}

/// Per-round active-byte counts for ONE differential trail (one random
/// base block, one random difference, propagated through `rounds`
/// consecutive rounds of `ctx` with round-key XOR skipped throughout --
/// valid for the whole trail, not just the last round, by the same
/// XOR-cancellation argument as `round_transform_no_key`).
pub fn differential_trail(ctx: &CipherContext, active_in: usize, rounds: usize) -> Vec<usize> {
    let mut rng = rand::thread_rng();

    let mut base = vec![0u8; BLOCK_SIZE];
    rng.fill_bytes(&mut base);
    let delta = random_difference(BLOCK_SIZE, active_in, &mut rng);
    let mut cur1 = base.clone();
    let mut cur2: Vec<u8> = base.iter().zip(delta.iter()).map(|(a, b)| a ^ b).collect();

    let mut trace = Vec::with_capacity(rounds);
    for r in 0..rounds {
        cur1 = cipher::round_transform_no_key(&cur1, ctx, r);
        cur2 = cipher::round_transform_no_key(&cur2, ctx, r);
        let out_diff: Vec<u8> = cur1.iter().zip(cur2.iter()).map(|(a, b)| a ^ b).collect();
        trace.push(active_bytes(&out_diff));
    }
    trace
}

pub struct DifferentialTrailStats {
    pub active_in: usize,
    pub rounds: usize,
    pub trials: usize,
    /// per_round[r] = (min, mean, max) active bytes after round r+1,
    /// aggregated over `trials` independent trials (fresh random base
    /// block, fresh random difference positions/values each trial).
    pub per_round: Vec<(usize, f64, usize)>,
    /// 1-based index of the first round where EVERY trial had already
    /// reached full block activity (BLOCK_SIZE active bytes) -- i.e. the
    /// smallest r such that per_round[r-1].0 (the min) == BLOCK_SIZE.
    /// None if that was never observed within `rounds`.
    pub min_full_active_round: Option<usize>,
}

/// Multi-trial aggregate of `differential_trail`: shows how quickly a
/// difference with `active_in` initially-active bytes tends to spread to
/// the whole block, and how consistent that spread is across
/// independent random trials.
pub fn differential_trail_stats(
    ctx: &CipherContext,
    active_in: usize,
    rounds: usize,
    trials: usize,
) -> DifferentialTrailStats {
    let mut per_round_min = vec![usize::MAX; rounds];
    let mut per_round_max = vec![0usize; rounds];
    let mut per_round_sum = vec![0usize; rounds];

    for _ in 0..trials {
        let trace = differential_trail(ctx, active_in, rounds);
        for (r, &active) in trace.iter().enumerate() {
            per_round_min[r] = per_round_min[r].min(active);
            per_round_max[r] = per_round_max[r].max(active);
            per_round_sum[r] += active;
        }
    }

    let per_round: Vec<(usize, f64, usize)> = (0..rounds)
        .map(|r| (per_round_min[r], per_round_sum[r] as f64 / trials as f64, per_round_max[r]))
        .collect();

    let min_full_active_round = per_round.iter().position(|&(min_v, _, _)| min_v == BLOCK_SIZE).map(|idx| idx + 1);

    DifferentialTrailStats { active_in, rounds, trials, per_round, min_full_active_round }
}

// ============================================================
// EXACT (non-sampled) differential analysis -- layer 0 only
// ============================================================
//
// Everything in the section above is sampled: run N random trials,
// report the observed min/mean/max. That's a statistical health check,
// not a proof -- a rare bad difference could exist and never show up in
// a few hundred trials. This section proves something narrower but
// airtight, for exactly one well-defined sub-problem: layer 0 of one
// GeneratedTransformer (F or G), given a FULLY SPECIFIED input
// difference (not just a byte-position pattern -- the actual delta
// values).
//
// Why layer 0 specifically is provable with no sampling at all:
// each node's pre-S-box accumulator is
//     acc(X) = w1*gf(s1) XOR w2*gf(s2) XOR w3*gf(s3)
// (see `transformer_function` in cipher.rs) where `gf` is GF(2^8)
// multiplication by a fixed, key-derived weight. GF(2^8) multiplication
// by a constant is GF(2)-linear, so
//     Δacc = acc(X XOR ΔX) XOR acc(X)
//          = w1*Δs1 XOR w2*Δs2 XOR w3*Δs3
// does NOT depend on the base state X at all -- only on ΔX and the
// weights. And because the layer's S-box is a bijection, Δacc == 0
// exactly iff that head's output difference is 0, for EVERY X, with no
// exceptions. So per-head activity is exactly determined by one
// XOR/GF(256)-mult computation, with zero sampling.
//
// EARLIER VERSION OF THIS SECTION HAD A BUG, CAUGHT AND FIXED HERE.
// When 2+ heads are simultaneously active for the same output byte, an
// earlier version of this analyzer checked whether the heads' DDT rows
// merely *intersected* -- i.e. whether some value d is independently
// achievable by head 1 for SOME base state and independently achievable
// by head 2 for SOME (possibly different) base state. That's necessary
// for a real collision but NOT sufficient: both heads read the SAME
// underlying state X, so what's actually needed is a single X for which
// BOTH heads simultaneously produce that value. Row intersection alone
// doesn't establish that -- it was a genuine analysis bug, not just
// imprecise wording, and this section keeps both checks, clearly
// labeled, so the distinction (and the fact that they can disagree) is
// visible rather than silently corrected away:
//
//   - `ddt_compatible` (necessary, NOT sufficient): do the active heads'
//     DDT rows admit *some* combination (one value per row, chosen
//     independently) that XORs to zero? Computed by an O(heads * 256 *
//     row_size) reachable-set DP (`ddt_rows_can_cancel`) -- this is what
//     the earlier buggy version reported as "resolved_collision".
//   - `jointly_realizable` (the actual, correct answer): does there
//     exist a SINGLE base state X producing that same cancellation?
//     Each head's accumulator A_h(X) is GF(2)-linear in X restricted to
//     its 3 source bytes, so the STACKED map (A_1(X), ..., A_k(X)) is
//     itself GF(2)-linear from the union of relevant input bits to
//     8*heads_active output bits. Its image -- the exact set of
//     (a_1,...,a_k) tuples some real X can jointly produce -- is
//     computed via a standard GF(2) XOR/linear basis (`XorBasis64`),
//     which is tractable regardless of how many input bytes are
//     involved because it only depends on the (small) OUTPUT dimension.
//     Every tuple actually in that image is then checked directly
//     against the S-box for a true cancellation. `None` if the image's
//     rank exceeds `EXACT_JOINT_RANK_CAP` (enumeration would be too
//     large in this build) -- reported honestly as unresolved rather
//     than guessed.
//
// `ddt_compatible == false` implies `jointly_realizable == Some(false)`
// (if the rows don't even intersect independently, no shared-X solution
// can exist either) -- `exact_layer0_single_byte_sweep` below sanity-
// checks this invariant does not get violated by any tested case.

/// GF(2) XOR/linear basis over up to 64 bits: the standard technique for
/// tracking the exact span of a set of vectors and enumerating it, used
/// here to compute (and then enumerate) the true image of the joint
/// per-head accumulator map -- not just each head's image in isolation.
struct XorBasis64 {
    basis: [u64; 64],
}

impl XorBasis64 {
    fn new() -> Self {
        XorBasis64 { basis: [0u64; 64] }
    }

    fn insert(&mut self, mut v: u64) {
        for i in (0..64).rev() {
            if (v >> i) & 1 == 0 {
                continue;
            }
            if self.basis[i] == 0 {
                self.basis[i] = v;
                return;
            }
            v ^= self.basis[i];
        }
        // v reduced to 0: already in the span, nothing new to add.
    }

    fn rank(&self) -> usize {
        self.basis.iter().filter(|&&x| x != 0).count()
    }

    fn vectors(&self) -> Vec<u64> {
        self.basis.iter().copied().filter(|&x| x != 0).collect()
    }
}

/// Enumeration cap on the joint accumulator map's RANK (not head count):
/// 2^rank tuples get exhaustively checked, so this bounds worst-case work
/// to 2^EXACT_JOINT_RANK_CAP regardless of how many bytes or heads are
/// involved. 20 -> up to ~1,048,576 checks, fast.
const EXACT_JOINT_RANK_CAP: usize = 20;

/// Necessary-but-not-sufficient check: can SOME combination of one value
/// from each row (chosen independently, ignoring whether a shared base
/// state could realize them together) XOR to zero? Computed via a
/// reachable-value DP rather than a naive Cartesian product, so it stays
/// fast (O(rows * 256 * row_size)) for any number of rows.
fn ddt_rows_can_cancel(rows: &[Vec<u8>]) -> bool {
    let mut reachable = [false; 256];
    reachable[0] = true;
    for row in rows {
        let mut next = [false; 256];
        for (v, &was_reachable) in reachable.iter().enumerate() {
            if !was_reachable {
                continue;
            }
            for &r in row {
                next[v ^ r as usize] = true;
            }
        }
        reachable = next;
    }
    reachable[0]
}

/// The corrected, actually-exact check: does a SINGLE real base state X
/// exist for which all of `active_heads`' output-difference contributions
/// XOR to zero at this node? `active_heads` are (sources, weights,
/// delta_acc) for each head with a nonzero accumulator difference.
/// Returns `None` if the joint map's rank exceeds `EXACT_JOINT_RANK_CAP`
/// (too large to exhaustively enumerate in this build).
fn heads_can_jointly_cancel(active_heads: &[(&[usize], &[u8], u8)], sbox: &[u8]) -> Option<bool> {
    let k = active_heads.len();
    if k * 8 > 64 {
        return None; // can't pack into a u64; not reachable at this cipher's head counts anyway
    }

    let mut union_positions: Vec<usize> = active_heads.iter().flat_map(|(sources, _, _)| sources.iter().copied()).collect();
    union_positions.sort_unstable();
    union_positions.dedup();

    // Build the joint linear map's image as a GF(2) basis: for each
    // standard basis input bit (one union byte position, one bit set,
    // all other bytes zero), compute the resulting packed
    // (a_1, a_2, ..., a_k) tuple (8 bits per head) and insert it.
    let mut xb = XorBasis64::new();
    for &pos in &union_positions {
        for bit in 0..8u8 {
            let basis_byte = 1u8 << bit;
            let mut packed: u64 = 0;
            for (h_idx, (sources, weights, _)) in active_heads.iter().enumerate() {
                let mut contrib: u8 = 0;
                for (&s, &w) in sources.iter().zip(weights.iter()) {
                    if s == pos {
                        contrib ^= cipher::gf_mul(basis_byte, w);
                    }
                }
                packed |= (contrib as u64) << (8 * h_idx);
            }
            xb.insert(packed);
        }
    }

    let rank = xb.rank();
    if rank > EXACT_JOINT_RANK_CAP {
        return None;
    }

    let basis_vectors = xb.vectors();
    for mask in 0u64..(1u64 << rank) {
        let mut packed: u64 = 0;
        for (i, &bv) in basis_vectors.iter().enumerate() {
            if (mask >> i) & 1 == 1 {
                packed ^= bv;
            }
        }
        let mut total_diff: u8 = 0;
        for (h_idx, (_, _, c)) in active_heads.iter().enumerate() {
            let a_h = ((packed >> (8 * h_idx)) & 0xFF) as u8;
            total_diff ^= sbox[a_h as usize] ^ sbox[(a_h ^ c) as usize];
        }
        if total_diff == 0 {
            return Some(true);
        }
    }
    Some(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactActiveStatus {
    /// Zero heads have a nonzero accumulator difference for this output
    /// byte -- proven inactive for EVERY base state, not sampled.
    ProvenInactive,
    /// Exactly one head has a nonzero accumulator difference -- proven
    /// active for EVERY base state (bijectivity, no other term to cancel
    /// it), not sampled.
    ProvenActive,
    /// 2+ heads have a nonzero accumulator difference. See the module
    /// doc above for the difference between `ddt_compatible` (necessary,
    /// not sufficient -- the earlier version's buggy criterion) and
    /// `jointly_realizable` (the corrected, actually-exact answer; `None`
    /// if the joint rank exceeded this build's enumeration cap).
    Resolved { heads_active: usize, ddt_compatible: bool, jointly_realizable: Option<bool> },
}

/// EXACT (see module doc above) classification of every layer-0 output
/// byte's activity status for a `GeneratedTransformer`, given a fully
/// specified HALF_SIZE-byte input difference.
pub fn exact_layer0_active_status(transformer: &GeneratedTransformer, delta_in: &[u8]) -> Vec<ExactActiveStatus> {
    let layer_connections = &transformer.connections[0];
    let sbox = &transformer.sboxes[0];

    (0..HALF_SIZE)
        .map(|output_node| {
            let mut active: Vec<(&[usize], &[u8], u8)> = Vec::new();
            for head in 0..transformer.heads {
                let (sources, weights) = &layer_connections[head][output_node];
                let mut delta_acc: u8 = 0;
                for (&source, &weight) in sources.iter().zip(weights.iter()) {
                    delta_acc ^= cipher::gf_mul(delta_in[source], weight);
                }
                if delta_acc != 0 {
                    active.push((sources.as_slice(), weights.as_slice(), delta_acc));
                }
            }

            match active.len() {
                0 => ExactActiveStatus::ProvenInactive,
                1 => ExactActiveStatus::ProvenActive,
                k => {
                    let rows: Vec<Vec<u8>> = active.iter().map(|(_, _, c)| sbox_ddt_row(sbox, *c)).collect();
                    let ddt_compatible = ddt_rows_can_cancel(&rows);
                    let jointly_realizable = heads_can_jointly_cancel(&active, sbox);
                    debug_assert!(
                        ddt_compatible || jointly_realizable != Some(true),
                        "invariant violated: jointly realizable but not even DDT-compatible"
                    );
                    ExactActiveStatus::Resolved { heads_active: k, ddt_compatible, jointly_realizable }
                }
            }
        })
        .collect()
}

pub struct Layer0ExactSweep {
    pub active_position: usize,
    /// Number of distinct nonzero input-difference values swept (255 =
    /// every single one, i.e. genuinely exhaustive, not a sample).
    pub deltas_tested: usize,
    pub proven_inactive_count: usize,
    pub proven_active_count: usize,
    /// 2+ active heads, DDT-compatible (necessary condition) but proven
    /// NOT jointly realizable -- the earlier buggy version would have
    /// counted these as "resolved_collision"; they're false positives.
    pub ddt_compatible_but_not_realizable_count: usize,
    /// 2+ active heads, proven jointly realizable -- an ACTUAL collision,
    /// with a real base state that produces it.
    pub jointly_realizable_count: usize,
    /// 2+ active heads, not DDT-compatible at all -- proven no collision,
    /// cheaply (rows don't even intersect independently).
    pub not_ddt_compatible_count: usize,
    /// 2+ active heads, joint rank exceeded this build's enumeration cap
    /// -- genuinely open, not resolved either way.
    pub joint_rank_exceeded_count: usize,
    /// First (delta value, output node) pair, if any, PROVEN to admit a
    /// real, jointly-realizable collision.
    pub example_collision: Option<(u8, usize)>,
    /// First (delta value, output node) pair, if any, that the DDT-
    /// compatibility check alone would have wrongly flagged as a
    /// collision, but the joint check proves is NOT actually realizable.
    pub example_false_positive: Option<(u8, usize)>,
}

/// Runs `exact_layer0_active_status` over EVERY ONE of the 255 possible
/// nonzero difference values at a single active byte position (fully
/// exhaustive -- not a sample of 255, all 255), tallying how each of the
/// 8 output bytes was classified across the full sweep.
pub fn exact_layer0_single_byte_sweep(transformer: &GeneratedTransformer, active_position: usize) -> Layer0ExactSweep {
    let mut sweep = Layer0ExactSweep {
        active_position,
        deltas_tested: 0,
        proven_inactive_count: 0,
        proven_active_count: 0,
        ddt_compatible_but_not_realizable_count: 0,
        jointly_realizable_count: 0,
        not_ddt_compatible_count: 0,
        joint_rank_exceeded_count: 0,
        example_collision: None,
        example_false_positive: None,
    };

    for delta_val in 1u16..256 {
        let mut delta_in = vec![0u8; HALF_SIZE];
        delta_in[active_position] = delta_val as u8;
        sweep.deltas_tested += 1;

        for (node, status) in exact_layer0_active_status(transformer, &delta_in).into_iter().enumerate() {
            match status {
                ExactActiveStatus::ProvenInactive => sweep.proven_inactive_count += 1,
                ExactActiveStatus::ProvenActive => sweep.proven_active_count += 1,
                ExactActiveStatus::Resolved { ddt_compatible, jointly_realizable, .. } => match (ddt_compatible, jointly_realizable) {
                    (false, realizable) => {
                        debug_assert_ne!(realizable, Some(true));
                        sweep.not_ddt_compatible_count += 1;
                    }
                    (true, Some(true)) => {
                        sweep.jointly_realizable_count += 1;
                        if sweep.example_collision.is_none() {
                            sweep.example_collision = Some((delta_val as u8, node));
                        }
                    }
                    (true, Some(false)) => {
                        sweep.ddt_compatible_but_not_realizable_count += 1;
                        if sweep.example_false_positive.is_none() {
                            sweep.example_false_positive = Some((delta_val as u8, node));
                        }
                    }
                    (true, None) => sweep.joint_rank_exceeded_count += 1,
                },
            }
        }
    }

    sweep
}

// ============================================================
// Top-level report for one key
// ============================================================

pub struct RoundReport {
    pub round: u32,
    pub f_diffusion: DiffusionReport,
    pub f_weights: WeightStats,
    pub g_diffusion: DiffusionReport,
    pub g_weights: WeightStats,
}

/// Builds F and G transformers for each round in `rounds_to_check` and
/// reports diffusion/weight health. Returns a list of per-round reports;
/// optionally prints a summary.
pub fn analyze_key(key: &[u8], rounds_to_check: &[u32], verbose: bool) -> Vec<RoundReport> {
    let mut results = Vec::with_capacity(rounds_to_check.len());
    for &r in rounds_to_check {
        let f = GeneratedTransformer::new(key, r, b"TRANSFORMER_F");
        let g = GeneratedTransformer::new(key, r, b"TRANSFORMER_G");

        let f_diff = diffusion_report(&f);
        let g_diff = diffusion_report(&g);
        let f_w = weight_stats(&f);
        let g_w = weight_stats(&g);

        results.push(RoundReport { round: r, f_diffusion: f_diff, f_weights: f_w, g_diffusion: g_diff, g_weights: g_w });
    }

    if verbose {
        let n_full_f = results.iter().filter(|r| r.f_diffusion.full_diffusion).count();
        let n_full_g = results.iter().filter(|r| r.g_diffusion.full_diffusion).count();
        let n = results.len();
        println!("Rounds checked: {}", n);
        println!("  F reaches full diffusion (every output depends on every input): {}/{}", n_full_f, n);
        println!("  G reaches full diffusion: {}/{}", n_full_g, n);
        let avg_cov_f: f64 = results.iter().map(|r| r.f_diffusion.coverage_fraction).sum::<f64>() / n as f64;
        let avg_cov_g: f64 = results.iter().map(|r| r.g_diffusion.coverage_fraction).sum::<f64>() / n as f64;
        println!("  Avg coverage fraction F: {:.3}   G: {:.3}  (1.0 = ideal)", avg_cov_f, avg_cov_g);
        let dead_f: Vec<u32> = results.iter().filter(|r| !r.f_diffusion.dead_inputs.is_empty()).map(|r| r.round).collect();
        let dead_g: Vec<u32> = results.iter().filter(|r| !r.g_diffusion.dead_inputs.is_empty()).map(|r| r.round).collect();
        if !dead_f.is_empty() {
            println!("  Rounds where F has a dead input byte: {:?}", dead_f);
        }
        if !dead_g.is_empty() {
            println!("  Rounds where G has a dead input byte: {:?}", dead_g);
        }
    }

    results
}

// ============================================================
// Constrained-topology variant, for comparison against `analyze_key`
// ============================================================

pub struct ConstrainedRoundReport {
    pub round: u32,
    pub f_diffusion: DiffusionReport,
    pub f_topology: TopologyDiagnostics,
    pub g_diffusion: DiffusionReport,
    pub g_topology: TopologyDiagnostics,
}

/// Same shape as `analyze_key`, but builds F/G via
/// `GeneratedTransformer::new_constrained` instead of `new`, so the
/// resulting `DiffusionReport`s reflect the constrained topology
/// acceptance in `cipher.rs` rather than the first (attempt-0) candidate.
/// `f_topology`/`g_topology` carry the self-check diagnostics computed
/// during generation, which should agree with `f_diffusion`/`g_diffusion`
/// computed here independently -- useful as a cross-check that the two
/// implementations of "diffusion" (cipher.rs's internal one, analyzer.rs's
/// external one) haven't drifted apart.
pub fn analyze_key_constrained(
    key: &[u8],
    rounds_to_check: &[u32],
    constraints: &TopologyConstraints,
    verbose: bool,
) -> Vec<ConstrainedRoundReport> {
    let mut results = Vec::with_capacity(rounds_to_check.len());
    for &r in rounds_to_check {
        let (f, f_topology) = GeneratedTransformer::new_constrained(key, r, b"TRANSFORMER_F", constraints);
        let (g, g_topology) = GeneratedTransformer::new_constrained(key, r, b"TRANSFORMER_G", constraints);

        let f_diffusion = diffusion_report(&f);
        let g_diffusion = diffusion_report(&g);

        results.push(ConstrainedRoundReport { round: r, f_diffusion, f_topology, g_diffusion, g_topology });
    }

    if verbose {
        let n_full_f = results.iter().filter(|r| r.f_diffusion.full_diffusion).count();
        let n_full_g = results.iter().filter(|r| r.g_diffusion.full_diffusion).count();
        let n = results.len();
        println!("Rounds checked (constrained): {}", n);
        println!("  F reaches full diffusion: {}/{}", n_full_f, n);
        println!("  G reaches full diffusion: {}/{}", n_full_g, n);
        let attempts_f: Vec<u32> = results.iter().map(|r| r.f_topology.attempt).collect();
        let attempts_g: Vec<u32> = results.iter().map(|r| r.g_topology.attempt).collect();
        println!("  F acceptance attempt indices: {:?}", attempts_f);
        println!("  G acceptance attempt indices: {:?}", attempts_g);
    }

    results
}

#[allow(dead_code)]
pub fn run_standalone_demo() {
    let key = generate_key();
    println!("Analyzing architecture for one random key:\n");
    let rounds: Vec<u32> = (0..14).collect();
    analyze_key(&key, &rounds, true);
}