//! Key-Generated Reversible Transformer Cipher (KGRTC) -- v2 (Rust port)
//!
//! Direct port of the Python reference implementation. Architecture
//! (S-boxes, permutations, round keys, F/G transformer topology+weights)
//! is generated ONCE per key and cached in a `CipherContext`. Public
//! encrypt()/decrypt() use CTR mode plus HMAC-SHA256 in encrypt-then-MAC
//! form (confidentiality + integrity).
//!
//! IMPORTANT: This is an experimental / unproven primitive, exactly as in
//! the original Python docstring. Passing the structural checks in
//! analyzer.rs, tests/, and examples/ (diffusion, avalanche, tamper
//! detection) does
//! NOT establish resistance to differential/linear/algebraic cryptanalysis
//! or side-channel attacks. It has not been reviewed by cryptographers.
//! Do not use this to protect anything that matters -- use an audited,
//! standard AEAD such as AES-256-GCM or ChaCha20-Poly1305 instead.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

// ============================================================
// Configuration
// ============================================================

pub const BLOCK_SIZE: usize = 16; // 128-bit state
pub const KEY_SIZE: usize = 32; // 256-bit master key
pub const ROUNDS: usize = 14;

pub const HALF_SIZE: usize = BLOCK_SIZE / 2;

pub const NONCE_SIZE: usize = 12; // bytes (like AES-GCM convention)
pub const COUNTER_SIZE: usize = BLOCK_SIZE - NONCE_SIZE; // 4 bytes -> up to 2^32 blocks/nonce
pub const TAG_SIZE: usize = 32; // HMAC-SHA256 output

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum CipherError {
    InvalidKeyLength,
    InvalidNonceLength,
    MessageTooLong,
    CiphertextTooShort,
    AuthenticationFailed,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::InvalidKeyLength => {
                write!(f, "Key must contain exactly {} bytes ({} bits)", KEY_SIZE, KEY_SIZE * 8)
            }
            CipherError::InvalidNonceLength => {
                write!(f, "Nonce must be exactly {} bytes", NONCE_SIZE)
            }
            CipherError::MessageTooLong => {
                write!(f, "Message too long for this nonce size (counter would wrap)")
            }
            CipherError::CiphertextTooShort => write!(f, "Ciphertext too short to contain nonce + tag"),
            CipherError::AuthenticationFailed => {
                write!(f, "Authentication failed: ciphertext or nonce was modified")
            }
        }
    }
}
impl std::error::Error for CipherError {}

// ============================================================
// Deterministic key-derived byte stream
// ============================================================

/// Deterministic n-byte stream from a seed. Same seed -> same output.
pub fn stream_bytes(seed: &[u8], n: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; n];
    reader.read(&mut out);
    out
}

/// Deterministic integer in [0, maximum).
fn derive_int(seed: &[u8], label: &[u8], maximum: u64) -> u64 {
    let mut full_seed = Vec::with_capacity(seed.len() + label.len());
    full_seed.extend_from_slice(seed);
    full_seed.extend_from_slice(label);
    let data = stream_bytes(&full_seed, 8);
    let value = u64::from_be_bytes(data.try_into().unwrap());
    value % maximum
}

// ============================================================
// Key-derived permutation
// ============================================================

pub fn generate_permutation(seed: &[u8], size: usize) -> Vec<usize> {
    let mut permutation: Vec<usize> = (0..size).collect();
    let mut full_seed = Vec::with_capacity(seed.len() + 11);
    full_seed.extend_from_slice(seed);
    full_seed.extend_from_slice(b"PERMUTATION");
    let data = stream_bytes(&full_seed, size * 8);
    let mut position = 0usize;
    for i in (1..size).rev() {
        let value = u64::from_be_bytes(data[position..position + 8].try_into().unwrap());
        position += 8;
        let j = (value % (i as u64 + 1)) as usize;
        permutation.swap(i, j);
    }
    permutation
}

pub fn inverse_permutation(permutation: &[usize]) -> Vec<usize> {
    let mut inverse = vec![0usize; permutation.len()];
    for (i, &value) in permutation.iter().enumerate() {
        inverse[value] = i;
    }
    inverse
}

pub fn apply_permutation(data: &[u8], permutation: &[usize]) -> Vec<u8> {
    permutation.iter().map(|&p| data[p]).collect()
}

// ============================================================
// Key-dependent S-box: S_K(x) = A_K(x^-1) XOR b_K
// ============================================================
//
// Structured replacement for the old "random permutation" S-box generator.
// x^-1 is multiplicative inversion in GF(2^8) (0 maps to 0), the same
// nonlinear core the AES S-box is built from. A_K is a key-derived
// INVERTIBLE linear map over GF(2)^8 and b_K a key-derived constant byte.
//
// Why this guarantees differential uniformity (DU) = 4, not just tends
// toward it: for any invertible linear A,
//     S(x) XOR S(x XOR d) = A(x^-1) XOR A((x XOR d)^-1) = A(x^-1 XOR (x XOR d)^-1)
// Because A is linear and bijective, it only relabels output differences --
// it can't merge two of them together or change how many x map to a given
// difference. So the differential distribution table of S is a relabeling
// of the DDT of the bare inversion map, whose DU is the textbook value 4.
// This holds for every invertible A_K and every b_K, deterministically --
// there is no search or luck involved, unlike the old random-permutation
// generator.
//
// The affine layer still matters for other properties (fixed points,
// avoiding S(x) = x XOR c, etc.) even though it can't move DU off of 4.

use std::sync::OnceLock;

static GF256_INV_TABLE: OnceLock<[u8; 256]> = OnceLock::new();

/// Multiplicative inverse table over GF(2^8) under the AES reduction
/// polynomial (matches `gf_mul` above). inv[0] = 0 by convention.
fn gf256_inverse_table() -> &'static [u8; 256] {
    GF256_INV_TABLE.get_or_init(|| {
        let mut table = [0u8; 256];
        for a in 1u16..256 {
            for b in 1u16..256 {
                if gf_mul(a as u8, b as u8) == 1 {
                    table[a as usize] = b as u8;
                    break;
                }
            }
        }
        table
    })
}

/// Checks whether an 8x8 matrix over GF(2), given as 8 rows each packed
/// into one byte (bit i of row = matrix entry [row][i]), is invertible,
/// via Gaussian elimination.
fn is_invertible_gf2(rows: &[u8; 8]) -> bool {
    let mut m = *rows;
    let mut rank = 0usize;
    for bit in (0..8).rev() {
        let mask = 1u8 << bit;
        if let Some(pivot) = (rank..8).find(|&r| m[r] & mask != 0) {
            m.swap(rank, pivot);
            for r in 0..8 {
                if r != rank && (m[r] & mask) != 0 {
                    m[r] ^= m[rank];
                }
            }
            rank += 1;
        }
    }
    rank == 8
}

/// Matrix-vector product over GF(2): result bit i = parity(rows[i] AND y).
fn matrix_vec_mul_gf2(rows: &[u8; 8], y: u8) -> u8 {
    let mut result = 0u8;
    for (i, &row) in rows.iter().enumerate() {
        let parity = (row & y).count_ones() & 1;
        result |= (parity as u8) << i;
    }
    result
}

/// Deterministically derives an invertible 8x8 GF(2) matrix A_K and a
/// constant byte b_K from (key, round_number, identifier). Draws candidate
/// matrices from the KDF and retries (with a counter suffix) until one is
/// invertible -- ~29% of random 8x8 GF(2) matrices are invertible, so this
/// takes ~3-4 tries on average and is still fully deterministic per key.
fn derive_affine_gf2(key: &[u8], round_number: u32, identifier: &[u8]) -> ([u8; 8], u8) {
    let mut base_seed = Vec::with_capacity(key.len() + identifier.len() + 4 + 6);
    base_seed.extend_from_slice(key);
    base_seed.extend_from_slice(identifier);
    base_seed.extend_from_slice(&round_number.to_be_bytes());
    base_seed.extend_from_slice(b"AFFINE");

    let mut attempt: u32 = 0;
    loop {
        let mut seed = base_seed.clone();
        seed.extend_from_slice(b"TRY");
        seed.extend_from_slice(&attempt.to_be_bytes());
        let data = stream_bytes(&seed, 8);
        let rows: [u8; 8] = data.try_into().unwrap();
        if is_invertible_gf2(&rows) {
            let mut b_seed = base_seed.clone();
            b_seed.extend_from_slice(b"CONST");
            let b = stream_bytes(&b_seed, 1)[0];
            return (rows, b);
        }
        attempt += 1;
    }
}

pub fn generate_sbox(key: &[u8], round_number: u32, identifier: &[u8]) -> Vec<u8> {
    let inv_table = gf256_inverse_table();
    let (matrix, b) = derive_affine_gf2(key, round_number, identifier);
    (0u16..256)
        .map(|x| matrix_vec_mul_gf2(&matrix, inv_table[x as usize]) ^ b)
        .collect()
}

pub fn inverse_sbox(sbox: &[u8]) -> Vec<u8> {
    let mut inverse = vec![0u8; 256];
    for (i, &value) in sbox.iter().enumerate() {
        inverse[value as usize] = i as u8;
    }
    inverse
}

// ============================================================
// Key-generated "Transformer" (nonlinear mixing function)
// ============================================================

/// One (layer, head, output_node) -> (sources, weights) connection table,
/// the same shape used throughout `GeneratedTransformer`.
pub type Connections = Vec<Vec<Vec<(Vec<usize>, Vec<u8>)>>>;

/// A key-generated nonlinear mixing function operating on HALF_SIZE bytes.
///
/// NOT a language-model Transformer. depth/heads/topology/weights are all
/// deterministically derived from (key, round_number, identifier).
pub struct GeneratedTransformer {
    pub depth: usize,
    pub heads: usize,
    /// connections[layer][head][output_node] = (sources, weights), each len 3
    pub connections: Connections,
    pub sboxes: Vec<Vec<u8>>,
}

/// depth/heads are shape parameters and, by design, are NOT re-rolled by
/// topology retries below -- only which sources/weights feed each node
/// changes between attempts, so diagnostics stay comparable across
/// attempts for the same (key, round_number, identifier).
fn derive_shape(base_seed: &[u8]) -> (usize, usize) {
    let depth = derive_int(base_seed, b"DEPTH", 3) as usize + 2;
    let heads = derive_int(base_seed, b"HEADS", 3) as usize + 2;
    (depth, heads)
}

/// Generates one candidate connection table for the given shape. `attempt`
/// is mixed into every per-node seed so each attempt is an independent,
/// fully deterministic rewiring -- same key still means same result, but
/// different attempt counters explore different candidate topologies.
fn generate_connections(base_seed: &[u8], depth: usize, heads: usize, attempt: u32) -> Connections {
    let mut connections = Vec::with_capacity(depth);
    for layer in 0..depth {
        let mut layer_connections = Vec::with_capacity(heads);
        for head in 0..heads {
            let mut head_seed = base_seed.to_vec();
            head_seed.extend_from_slice(b"HEAD");
            head_seed.extend_from_slice(&(layer as u16).to_be_bytes());
            head_seed.extend_from_slice(&(head as u16).to_be_bytes());
            if attempt > 0 {
                head_seed.extend_from_slice(b"TOPO_ATTEMPT");
                head_seed.extend_from_slice(&attempt.to_be_bytes());
            }

            let mut head_connections = Vec::with_capacity(HALF_SIZE);
            for output_node in 0..HALF_SIZE {
                let mut node_seed = head_seed.clone();
                node_seed.extend_from_slice(b"NODE");
                node_seed.extend_from_slice(&(output_node as u16).to_be_bytes());

                let permutation = generate_permutation(&node_seed, HALF_SIZE);
                let sources: Vec<usize> = permutation[..3].to_vec();
                let mut weights = Vec::with_capacity(3);
                for &source in &sources {
                    let mut weight_seed = node_seed.clone();
                    weight_seed.extend_from_slice(b"WEIGHT");
                    weight_seed.extend_from_slice(&(source as u16).to_be_bytes());
                    let mut weight = derive_int(&weight_seed, b"W", 256) as u8;
                    if weight == 0 {
                        weight = 1;
                    }
                    weights.push(weight);
                }
                head_connections.push((sources, weights));
            }
            layer_connections.push(head_connections);
        }
        connections.push(layer_connections);
    }
    connections
}

// ============================================================
// Topology constraints: candidate-generate-and-check, key-derived
// ============================================================
//
// Fixes the "random graph happens to reach ~99.9% coverage" situation:
// instead of accepting whatever the first key-derived wiring produces,
// generate a candidate, score it against structural properties, and
// deterministically try further key-derived candidates (via `attempt`)
// until one satisfies them or a bounded number of tries is exhausted.
// The key still fully determines the result (same key -> same sequence
// of candidates -> same accepted topology); this only narrows *which*
// member of that key-derived family gets used.

/// Structural report for one candidate topology, computed independently
/// of analyzer.rs (kept here so `cipher.rs` can self-check during
/// generation without a cipher<->analyzer circular dependency). The
/// method mirrors `analyzer::dependency_sets` / `diffusion_report`, so
/// the two should always agree when cross-checked from outside.
#[derive(Clone, Debug)]
pub struct TopologyDiagnostics {
    pub attempt: u32,
    pub full_diffusion: bool,
    pub dead_inputs: Vec<usize>,
    /// Smallest, over every (layer, output_node), of the number of
    /// *distinct* sources feeding that output across all heads combined
    /// (heads' contributions are XORed together, so this is what actually
    /// determines how fast information spreads -- not the fixed
    /// per-head-per-node fan-in of 3).
    pub min_node_fanin: usize,
    /// Worst-case (max_count / mean_count) of how often each of the
    /// HALF_SIZE input indices is selected as a source, taken over all
    /// layers. 1.0 = perfectly even; higher = some inputs are leaned on
    /// much more than others within a layer.
    pub max_usage_ratio: f64,
}

impl TopologyDiagnostics {
    fn passes(&self, constraints: &TopologyConstraints) -> bool {
        (!constraints.require_full_diffusion || self.full_diffusion)
            && self.dead_inputs.is_empty()
            && self.min_node_fanin >= constraints.min_node_fanin
            && self.max_usage_ratio <= constraints.max_usage_ratio
    }

    /// Scalar used only to pick the *best available* candidate if every
    /// attempt exhausts `max_attempts` without fully passing -- never used
    /// to decide pass/fail. Higher is better.
    fn score(&self) -> f64 {
        let diffusion_term = if self.full_diffusion { 1000.0 } else { 0.0 };
        let dead_penalty = self.dead_inputs.len() as f64 * 200.0;
        diffusion_term - dead_penalty + self.min_node_fanin as f64 * 10.0 - self.max_usage_ratio
    }
}

#[derive(Clone, Debug)]
pub struct TopologyConstraints {
    /// Require every output byte, after `depth` layers, to structurally
    /// depend on every input byte of this transformer.
    pub require_full_diffusion: bool,
    /// Minimum acceptable `min_node_fanin` (see TopologyDiagnostics).
    pub min_node_fanin: usize,
    /// Maximum acceptable `max_usage_ratio` (see TopologyDiagnostics).
    pub max_usage_ratio: f64,
    /// Deterministic candidates to try (attempt = 0..max_attempts) before
    /// falling back to the best-scoring one seen so far.
    pub max_attempts: u32,
}

impl Default for TopologyConstraints {
    fn default() -> Self {
        TopologyConstraints {
            require_full_diffusion: true,
            // Exactly half of HALF_SIZE (8): each output must structurally
            // see at least half the state within a single layer, not just
            // eventually across all `depth` layers. (One notch below
            // HALF_SIZE/2 + 1 -- that stricter bar is satisfiable but,
            // combined with the usage-ratio bound below, needs far more
            // attempts for little extra diffusion benefit, since
            // full_diffusion is already the dominant term in `score()`.)
            min_node_fanin: HALF_SIZE / 2,
            // No source index selected more than 2.5x as often as average
            // within a layer -- loose enough to accept most full-diffusion
            // candidates outright instead of exhausting attempts chasing
            // near-perfect balance.
            max_usage_ratio: 2.5,
            max_attempts: 32,
        }
    }
}

/// Self-contained diffusion/usage analysis of one candidate connection
/// table (see the module doc comment above for why this duplicates, and
/// should agree with, `analyzer::diffusion_report`).
fn evaluate_topology(attempt: u32, depth: usize, heads: usize, connections: &Connections) -> TopologyDiagnostics {
    use std::collections::HashSet;

    let mut dep: Vec<HashSet<usize>> = (0..HALF_SIZE).map(|i| HashSet::from([i])).collect();
    let mut min_node_fanin = usize::MAX;
    let mut max_usage_ratio: f64 = 0.0;

    for layer in 0..depth {
        let mut new_dep: Vec<HashSet<usize>> = vec![HashSet::new(); HALF_SIZE];
        let mut node_union: Vec<HashSet<usize>> = vec![HashSet::new(); HALF_SIZE];
        let mut usage_counts = [0usize; HALF_SIZE];

        for head in 0..heads {
            for output_node in 0..HALF_SIZE {
                let (sources, _weights) = &connections[layer][head][output_node];
                for &s in sources {
                    usage_counts[s] += 1;
                    node_union[output_node].insert(s);
                    let src_dep = dep[s].clone();
                    new_dep[output_node].extend(src_dep);
                }
            }
        }

        let layer_min_fanin = node_union.iter().map(|u| u.len()).min().unwrap_or(0);
        min_node_fanin = min_node_fanin.min(layer_min_fanin);

        let total: usize = usage_counts.iter().sum();
        if total > 0 {
            let mean = total as f64 / HALF_SIZE as f64;
            let max_count = *usage_counts.iter().max().unwrap();
            max_usage_ratio = max_usage_ratio.max(max_count as f64 / mean);
        }

        dep = new_dep;
    }

    let mut reachable: HashSet<usize> = HashSet::new();
    for d in &dep {
        reachable.extend(d.iter().copied());
    }
    let mut dead_inputs: Vec<usize> = (0..HALF_SIZE).filter(|i| !reachable.contains(i)).collect();
    dead_inputs.sort_unstable();
    let full_diffusion = dep.iter().all(|d| d.len() == HALF_SIZE);

    TopologyDiagnostics { attempt, full_diffusion, dead_inputs, min_node_fanin, max_usage_ratio }
}

impl GeneratedTransformer {
    /// Original, unconstrained generation: accepts whatever the first
    /// key-derived candidate topology produces (attempt 0), exactly as
    /// before. Kept so the old behavior stays directly reproducible and
    /// benchmarkable against `new_constrained` below.
    pub fn new(key: &[u8], round_number: u32, identifier: &[u8]) -> Self {
        let mut base_seed = Vec::with_capacity(key.len() + identifier.len() + 4);
        base_seed.extend_from_slice(key);
        base_seed.extend_from_slice(identifier);
        base_seed.extend_from_slice(&round_number.to_be_bytes());

        let (depth, heads) = derive_shape(&base_seed);
        let connections = generate_connections(&base_seed, depth, heads, 0);

        let mut sboxes = Vec::with_capacity(depth);
        for layer in 0..depth {
            sboxes.push(generate_sbox(
                key,
                round_number * 100 + layer as u32,
                &[identifier, b"NN_SBOX"].concat(),
            ));
        }

        GeneratedTransformer { depth, heads, connections, sboxes }
    }

    /// Key-derived, constraint-checked generation: generates candidate
    /// topologies (attempt 0, 1, 2, ...), keeping the best-scoring one
    /// seen, and stops as soon as one satisfies `constraints`. Still
    /// fully deterministic per key -- nothing here is random beyond the
    /// same SHAKE-256 KDF the rest of the cipher uses. Returns the
    /// transformer plus diagnostics for the topology that was actually
    /// accepted, so callers (CipherContext, the test suite) can see
    /// whether constraints were satisfied outright or a fallback was used.
    pub fn new_constrained(
        key: &[u8],
        round_number: u32,
        identifier: &[u8],
        constraints: &TopologyConstraints,
    ) -> (Self, TopologyDiagnostics) {
        let mut base_seed = Vec::with_capacity(key.len() + identifier.len() + 4);
        base_seed.extend_from_slice(key);
        base_seed.extend_from_slice(identifier);
        base_seed.extend_from_slice(&round_number.to_be_bytes());

        let (depth, heads) = derive_shape(&base_seed);

        let mut best: Option<(Connections, TopologyDiagnostics)> = None;
        for attempt in 0..constraints.max_attempts {
            let connections = generate_connections(&base_seed, depth, heads, attempt);
            let diag = evaluate_topology(attempt, depth, heads, &connections);
            let passed = diag.passes(constraints);

            let is_better = match &best {
                None => true,
                Some((_, current_best)) => diag.score() > current_best.score(),
            };
            if is_better {
                best = Some((connections, diag.clone()));
            }
            if passed {
                break;
            }
        }
        // Safe: the loop runs at least once (max_attempts is never 0 in
        // TopologyConstraints::default(), and constructing one with 0 is
        // a caller error we surface immediately rather than silently).
        let (connections, diagnostics) =
            best.expect("TopologyConstraints::max_attempts must be at least 1");

        let mut sboxes = Vec::with_capacity(depth);
        for layer in 0..depth {
            sboxes.push(generate_sbox(
                key,
                round_number * 100 + layer as u32,
                &[identifier, b"NN_SBOX"].concat(),
            ));
        }

        (GeneratedTransformer { depth, heads, connections, sboxes }, diagnostics)
    }
}

// ============================================================
// GF(2^8) multiplication (AES reduction polynomial)
// ============================================================

pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result
}

/// 8 bytes -> 8 bytes. Need not be invertible itself (see coupling).
pub fn transformer_function(data: &[u8], transformer: &GeneratedTransformer) -> Vec<u8> {
    let mut state: Vec<u8> = data.to_vec();
    for layer in 0..transformer.depth {
        let mut new_state = vec![0u8; HALF_SIZE];
        let layer_connections = &transformer.connections[layer];
        let sbox = &transformer.sboxes[layer];
        for head in 0..transformer.heads {
            let connections = &layer_connections[head];
            let mut head_output = vec![0u8; HALF_SIZE];
            for output_node in 0..HALF_SIZE {
                let (sources, weights) = &connections[output_node];
                let mut accumulator: u8 = 0;
                for (&source, &weight) in sources.iter().zip(weights.iter()) {
                    accumulator ^= gf_mul(state[source], weight);
                }
                head_output[output_node] = sbox[accumulator as usize];
            }
            for i in 0..HALF_SIZE {
                new_state[i] ^= head_output[i];
            }
        }
        state = new_state;
    }
    state
}

// ============================================================
// Reversible coupling (Feistel-style; uses precomputed F/G)
// ============================================================

pub fn reversible_coupling(block: &[u8], f: &GeneratedTransformer, g: &GeneratedTransformer) -> Vec<u8> {
    let a = &block[..HALF_SIZE];
    let b = &block[HALF_SIZE..];
    let f_a = transformer_function(a, f);
    let b_prime: Vec<u8> = b.iter().zip(f_a.iter()).map(|(x, y)| x ^ y).collect();
    let g_b = transformer_function(&b_prime, g);
    let a_prime: Vec<u8> = a.iter().zip(g_b.iter()).map(|(x, y)| x ^ y).collect();
    let mut out = a_prime;
    out.extend(b_prime);
    out
}

pub fn inverse_reversible_coupling(block: &[u8], f: &GeneratedTransformer, g: &GeneratedTransformer) -> Vec<u8> {
    let a_prime = &block[..HALF_SIZE];
    let b_prime = &block[HALF_SIZE..];
    let g_b = transformer_function(b_prime, g);
    let a: Vec<u8> = a_prime.iter().zip(g_b.iter()).map(|(x, y)| x ^ y).collect();
    let f_a = transformer_function(&a, f);
    let b: Vec<u8> = b_prime.iter().zip(f_a.iter()).map(|(x, y)| x ^ y).collect();
    let mut out = a;
    out.extend(b);
    out
}

pub fn generate_round_key(key: &[u8], round_number: u32) -> Vec<u8> {
    let mut seed = Vec::with_capacity(key.len() + 9 + 4);
    seed.extend_from_slice(key);
    seed.extend_from_slice(b"ROUND_KEY");
    seed.extend_from_slice(&round_number.to_be_bytes());
    stream_bytes(&seed, BLOCK_SIZE)
}

// ============================================================
// CipherContext: generate architecture ONCE per key
// ============================================================

/// Precomputes and caches every key-dependent structure (S-boxes,
/// permutations, round keys, and the F/G GeneratedTransformers for every
/// round) exactly once. Reused across every block for this key.
pub struct CipherContext {
    pub key: Vec<u8>,
    pub round_sbox: Vec<Vec<u8>>,
    pub round_inv_sbox: Vec<Vec<u8>>,
    pub round_perm: Vec<Vec<usize>>,
    pub round_inv_perm: Vec<Vec<usize>>,
    pub round_key: Vec<Vec<u8>>,
    pub round_f: Vec<GeneratedTransformer>,
    pub round_g: Vec<GeneratedTransformer>,
    /// Topology diagnostics for the F/G transformer actually accepted in
    /// each round (see `TopologyDiagnostics`) -- lets callers (e.g. the
    /// test suite) check whether constraints were satisfied outright or a
    /// best-effort fallback was used, without recomputing anything.
    pub round_f_topology: Vec<TopologyDiagnostics>,
    pub round_g_topology: Vec<TopologyDiagnostics>,
    pub mac_key: Vec<u8>,
}

impl CipherContext {
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        Self::new_with_topology_constraints(key, &TopologyConstraints::default())
    }

    /// Same as `new`, but lets the caller tune (or disable, via a
    /// permissive `TopologyConstraints`) the F/G topology acceptance
    /// criteria instead of using the defaults.
    pub fn new_with_topology_constraints(
        key: &[u8],
        topology_constraints: &TopologyConstraints,
    ) -> Result<Self, CipherError> {
        if key.len() != KEY_SIZE {
            return Err(CipherError::InvalidKeyLength);
        }

        let mut round_sbox = Vec::with_capacity(ROUNDS);
        let mut round_inv_sbox = Vec::with_capacity(ROUNDS);
        let mut round_perm = Vec::with_capacity(ROUNDS);
        let mut round_inv_perm = Vec::with_capacity(ROUNDS);
        let mut round_key = Vec::with_capacity(ROUNDS);
        let mut round_f = Vec::with_capacity(ROUNDS);
        let mut round_g = Vec::with_capacity(ROUNDS);
        let mut round_f_topology = Vec::with_capacity(ROUNDS);
        let mut round_g_topology = Vec::with_capacity(ROUNDS);

        for r in 0..ROUNDS {
            let sbox = generate_sbox(key, r as u32, b"SBOX");
            round_inv_sbox.push(inverse_sbox(&sbox));
            round_sbox.push(sbox);

            let mut perm_seed = Vec::with_capacity(key.len() + 10 + 4);
            perm_seed.extend_from_slice(key);
            perm_seed.extend_from_slice(b"STATE_PERM");
            perm_seed.extend_from_slice(&(r as u32).to_be_bytes());
            let perm = generate_permutation(&perm_seed, BLOCK_SIZE);
            round_inv_perm.push(inverse_permutation(&perm));
            round_perm.push(perm);

            round_key.push(generate_round_key(key, r as u32));

            let (f, f_topo) = GeneratedTransformer::new_constrained(
                key,
                r as u32,
                b"TRANSFORMER_F",
                topology_constraints,
            );
            let (g, g_topo) = GeneratedTransformer::new_constrained(
                key,
                r as u32,
                b"TRANSFORMER_G",
                topology_constraints,
            );
            round_f.push(f);
            round_g.push(g);
            round_f_topology.push(f_topo);
            round_g_topology.push(g_topo);
        }

        // Independently-derived MAC key (domain-separated from cipher material).
        let mut mac_seed = Vec::with_capacity(key.len() + 10);
        mac_seed.extend_from_slice(key);
        mac_seed.extend_from_slice(b"MAC_KEY_V1");
        let mac_key = stream_bytes(&mac_seed, 32);

        Ok(CipherContext {
            key: key.to_vec(),
            round_sbox,
            round_inv_sbox,
            round_perm,
            round_inv_perm,
            round_key,
            round_f,
            round_g,
            round_f_topology,
            round_g_topology,
            mac_key,
        })
    }
}

// ============================================================
// Single-block encrypt/decrypt using a cached context
// ============================================================

/// Applies one round's S-box substitution, permutation, and reversible
/// F/G coupling to `block` -- but deliberately NOT the round-key XOR.
///
/// Used for empirical differential analysis (see `analyzer.rs`): because
/// `(X XOR K) XOR (Y XOR K) = X XOR Y`, XOR with a fixed round key never
/// changes a *difference* between two states, so it can be skipped when
/// studying how differences propagate through a round's nonlinear
/// components (S/P/F/G) -- at every round, not just the last. Skipping it
/// here means a differential trail computed by repeatedly calling this
/// function is the same trail the real `encrypt_block` round function
/// would produce, without needing to fix or guess a round key.
pub fn round_transform_no_key(block: &[u8], ctx: &CipherContext, round: usize) -> Vec<u8> {
    let mut block: Vec<u8> = block.iter().map(|&b| ctx.round_sbox[round][b as usize]).collect();
    block = apply_permutation(&block, &ctx.round_perm[round]);
    block = reversible_coupling(&block, &ctx.round_f[round], &ctx.round_g[round]);
    block
}

pub fn encrypt_block(block: &[u8], ctx: &CipherContext) -> Vec<u8> {
    let mut block = block.to_vec();
    for r in 0..ROUNDS {
        block = round_transform_no_key(&block, ctx, r);
        block = block
            .iter()
            .zip(ctx.round_key[r].iter())
            .map(|(x, y)| x ^ y)
            .collect();
    }
    block
}

pub fn decrypt_block(block: &[u8], ctx: &CipherContext) -> Vec<u8> {
    let mut block = block.to_vec();
    for r in (0..ROUNDS).rev() {
        block = block
            .iter()
            .zip(ctx.round_key[r].iter())
            .map(|(x, y)| x ^ y)
            .collect();
        block = inverse_reversible_coupling(&block, &ctx.round_f[r], &ctx.round_g[r]);
        block = apply_permutation(&block, &ctx.round_inv_perm[r]);
        block = block.iter().map(|&b| ctx.round_inv_sbox[r][b as usize]).collect();
    }
    block
}

// ============================================================
// CTR mode (stream construction: no padding, no block repeats)
// ============================================================

fn ctr_keystream_xor(data: &[u8], ctx: &CipherContext, nonce: &[u8]) -> Result<Vec<u8>, CipherError> {
    if nonce.len() != NONCE_SIZE {
        return Err(CipherError::InvalidNonceLength);
    }
    let max_blocks: u64 = 1u64 << (COUNTER_SIZE * 8);
    let n_blocks = (data.len() + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if n_blocks as u64 > max_blocks {
        return Err(CipherError::MessageTooLong);
    }

    let mut output = Vec::with_capacity(data.len());
    let mut counter: u32 = 0;
    for chunk in data.chunks(BLOCK_SIZE) {
        let mut counter_block = Vec::with_capacity(BLOCK_SIZE);
        counter_block.extend_from_slice(nonce);
        counter_block.extend_from_slice(&counter.to_be_bytes());
        let keystream = encrypt_block(&counter_block, ctx);
        for (x, y) in chunk.iter().zip(keystream.iter()) {
            output.push(x ^ y);
        }
        counter += 1;
    }
    Ok(output)
}

fn hmac_tag(mac_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().to_vec()
}

// ============================================================
// Public API: authenticated encryption (encrypt-then-MAC over CTR)
// ============================================================

pub fn generate_key() -> Vec<u8> {
    let mut key = vec![0u8; KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Returns: nonce || ciphertext || tag
///
/// Confidentiality: CTR mode (no ECB block-repetition leakage, no padding).
/// Integrity: HMAC-SHA256 over (nonce || ciphertext), encrypt-then-MAC,
///            with a MAC key independently derived from the cipher key.
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    ctx: Option<&CipherContext>,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    let owned_ctx;
    let ctx_ref = match ctx {
        Some(c) => c,
        None => {
            owned_ctx = CipherContext::new(key)?;
            &owned_ctx
        }
    };

    let owned_nonce;
    let nonce_ref: &[u8] = match nonce {
        Some(n) => {
            if n.len() != NONCE_SIZE {
                return Err(CipherError::InvalidNonceLength);
            }
            n
        }
        None => {
            owned_nonce = generate_nonce();
            &owned_nonce
        }
    };

    let ciphertext = ctr_keystream_xor(plaintext, ctx_ref, nonce_ref)?;
    let mut mac_input = Vec::with_capacity(nonce_ref.len() + ciphertext.len());
    mac_input.extend_from_slice(nonce_ref);
    mac_input.extend_from_slice(&ciphertext);
    let tag = hmac_tag(&ctx_ref.mac_key, &mac_input);

    let mut out = Vec::with_capacity(nonce_ref.len() + ciphertext.len() + tag.len());
    out.extend_from_slice(nonce_ref);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn decrypt(blob: &[u8], key: &[u8], ctx: Option<&CipherContext>) -> Result<Vec<u8>, CipherError> {
    if blob.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CipherError::CiphertextTooShort);
    }

    let nonce = &blob[..NONCE_SIZE];
    let tag = &blob[blob.len() - TAG_SIZE..];
    let ciphertext = &blob[NONCE_SIZE..blob.len() - TAG_SIZE];

    let owned_ctx;
    let ctx_ref = match ctx {
        Some(c) => c,
        None => {
            owned_ctx = CipherContext::new(key)?;
            &owned_ctx
        }
    };

    let mut mac_input = Vec::with_capacity(nonce.len() + ciphertext.len());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(ciphertext);
    let expected_tag = hmac_tag(&ctx_ref.mac_key, &mac_input);

    // Constant-time comparison.
    if !constant_time_eq(tag, &expected_tag) {
        return Err(CipherError::AuthenticationFailed);
    }

    ctr_keystream_xor(ciphertext, ctx_ref, nonce)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================
// Legacy raw ECB single-block encryption -- NOT SECURE, kept ONLY so
// the old (v1) behavior can be directly compared/benchmarked against
// the new construction. Do not use this for anything real.
// ============================================================

pub fn insecure_ecb_encrypt_single_block(block16: &[u8], ctx: &CipherContext) -> Vec<u8> {
    assert_eq!(block16.len(), BLOCK_SIZE);
    encrypt_block(block16, ctx)
}