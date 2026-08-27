//! Differential propagation analysis, both empirical (sampled) and exact
//! (exhaustive, layer-0 only). Full background, the methodology, and the
//! false-positive bug this section's exact analysis found and fixed are
//! all documented in docs/DIFFERENTIAL_ANALYSIS.md and in the doc
//! comments on the corresponding `analyzer.rs` functions -- read those
//! before trusting any number printed here.

use kgrtc::analyzer;
use kgrtc::cipher;

fn active_byte_expansion(trials_per_level: usize) {
    println!("--- Active-byte expansion: F/G transformers in isolation ({trials_per_level} trials per input-active-byte level) ---");
    println!("  (empirical / sampled -- see docs/DIFFERENTIAL_ANALYSIS.md for caveats; NOT an exhaustive worst-case)");
    let key = cipher::generate_key();
    let f = cipher::GeneratedTransformer::new(&key, 0, b"TRANSFORMER_F");
    let reports = analyzer::active_byte_expansion_report(&f, trials_per_level);
    println!("  F (round 0), input active bytes -> output active bytes [min / mean / max] (zero-diff collisions):");
    for r in &reports {
        println!("    {} -> {} / {:.2} / {}  (zero_output_count={})", r.active_in, r.min_active_out, r.mean_active_out, r.max_active_out, r.zero_output_count);
    }
    println!();
}

fn round_differential(trials: usize) {
    println!("--- Round-level differential propagation (S -> P -> F -> G, round key skipped, {trials} trials per level) ---");
    let key = cipher::generate_key();
    let ctx = cipher::CipherContext::new(&key).unwrap();
    for &active_in in &[1usize, 2, 4, 8] {
        let stats = analyzer::round_differential_stats(&ctx, 0, active_in, trials);
        println!(
            "  round 0, {active_in} active input bytes (of 16) -> {} / {:.2} / {} active output bytes  (zero_output_count={})",
            stats.min_active_out, stats.mean_active_out, stats.max_active_out, stats.zero_output_count
        );
    }
    println!();
}

fn full_differential_trail(trials: usize) {
    println!("--- Multi-round differential trail: single active byte propagated through all {} rounds ({trials} trials) ---", cipher::ROUNDS);
    let key = cipher::generate_key();
    let ctx = cipher::CipherContext::new(&key).unwrap();
    let stats = analyzer::differential_trail_stats(&ctx, 1, cipher::ROUNDS, trials);
    println!("  round: min / mean / max active bytes (of {} total)", cipher::BLOCK_SIZE);
    for (i, &(min_v, mean_v, max_v)) in stats.per_round.iter().enumerate() {
        println!("    {:>2}: {:>2} / {:>5.2} / {:>2}", i + 1, min_v, mean_v, max_v);
    }
    match stats.min_full_active_round {
        Some(r) => println!("  every trial reached full block activity by round {r}"),
        None => println!("  did NOT reach full block activity (in every trial) within {} rounds", cipher::ROUNDS),
    }
    println!();
}

fn exact_layer0_differential(n_keys: usize) {
    println!("--- EXACT (exhaustive, not sampled) layer-0 differential analysis, {n_keys} keys ---");
    println!("  Every one of the 255 possible single-active-byte input differences (all of them, not a");
    println!("  random sample) at input position 0. Two multi-head checks are reported separately:");
    println!("  ddt_compatible (necessary, NOT sufficient -- rows merely intersect independently) vs.");
    println!("  jointly_realizable (the corrected, actually-exact answer -- see docs/DIFFERENTIAL_ANALYSIS.md).");

    for name in ["F", "G"] {
        let mut proven_inactive = 0usize;
        let mut proven_active = 0usize;
        let mut not_ddt_compatible = 0usize;
        let mut false_positives = 0usize;
        let mut real_collisions = 0usize;
        let mut rank_exceeded = 0usize;
        let mut first_collision: Option<(u8, usize)> = None;
        let mut first_false_positive: Option<(u8, usize)> = None;
        let mut deltas_tested = 0usize;

        for _ in 0..n_keys {
            let key = cipher::generate_key();
            let identifier: &[u8] = if name == "F" { b"TRANSFORMER_F" } else { b"TRANSFORMER_G" };
            let t = cipher::GeneratedTransformer::new(&key, 0, identifier);
            let sweep = analyzer::exact_layer0_single_byte_sweep(&t, 0);
            deltas_tested += sweep.deltas_tested;
            proven_inactive += sweep.proven_inactive_count;
            proven_active += sweep.proven_active_count;
            not_ddt_compatible += sweep.not_ddt_compatible_count;
            false_positives += sweep.ddt_compatible_but_not_realizable_count;
            real_collisions += sweep.jointly_realizable_count;
            rank_exceeded += sweep.joint_rank_exceeded_count;
            if first_collision.is_none() {
                first_collision = sweep.example_collision;
            }
            if first_false_positive.is_none() {
                first_false_positive = sweep.example_false_positive;
            }
        }

        let total_pairs = deltas_tested * 8;
        println!("  {name}: {total_pairs} (delta, output_node) pairs across {n_keys} keys x 255 deltas x 8 nodes");
        println!("    proven_inactive={proven_inactive}  proven_active={proven_active}  not_ddt_compatible={not_ddt_compatible}");
        println!(
            "    [of the 2+-active-head cases] jointly_realizable(real collision)={real_collisions}  ddt_compatible_but_NOT_realizable(false positive)={false_positives}  rank_exceeded(open)={rank_exceeded}"
        );
        match first_collision {
            Some((delta_val, node)) => println!(
                "    a real, jointly-realizable collision IS proven: input delta=0x{delta_val:02x} at byte 0 -> output byte {node} (a real base state X exists)"
            ),
            None => println!("    no jointly-realizable collision found among tested differences"),
        }
        match first_false_positive {
            Some((delta_val, node)) => println!(
                "    a DDT-compatible-but-NOT-jointly-realizable case IS proven: delta=0x{delta_val:02x}, output byte {node} (rows intersect, but no shared X can realize it)"
            ),
            None => println!("    no false positives found among tested differences (ddt_compatible and jointly_realizable agreed everywhere tested)"),
        }
    }
    println!();
}

fn main() {
    active_byte_expansion(500);
    round_differential(200);
    full_differential_trail(100);
    exact_layer0_differential(20);
}
