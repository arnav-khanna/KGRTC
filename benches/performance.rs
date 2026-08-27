//! Plain `std::time::Instant` timing, not a criterion-style statistical
//! benchmark -- deliberately dependency-free. `harness = false` in
//! Cargo.toml means `cargo bench` just runs this file's `main()`
//! directly rather than expecting the nightly-only libtest bench
//! harness. Good enough for the order-of-magnitude numbers this project
//! needs (see docs/DESIGN.md's topology-constraints section for why
//! one-time setup cost matters here); not a substitute for a proper
//! criterion/iai run if you need confidence intervals or regression
//! detection.

use std::time::Instant;

use kgrtc::cipher;

fn main() {
    println!("--- Performance: setup (per key) vs per-block (amortized) ---");
    let key = cipher::generate_key();

    let t0 = Instant::now();
    let ctx = cipher::CipherContext::new(&key).unwrap();
    let t_setup = t0.elapsed();

    let n_blocks = 500;
    let mut rng = rand::thread_rng();
    let t0 = Instant::now();
    for _ in 0..n_blocks {
        let mut pt = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rng, &mut pt);
        cipher::encrypt_block(&pt, &ctx);
    }
    let t_blocks = t0.elapsed();

    println!("  one-time setup (CipherContext build, default TopologyConstraints): {:.2} ms", t_setup.as_secs_f64() * 1000.0);
    println!(
        "  per-block cost after setup: {:.3} ms/block ({} blocks, {:.3}s total)",
        t_blocks.as_secs_f64() * 1000.0 / n_blocks as f64,
        n_blocks,
        t_blocks.as_secs_f64()
    );
    println!(
        "  -> after setup, encrypting a 1 KB message takes roughly {:.2} ms",
        t_blocks.as_secs_f64() * 1000.0 / n_blocks as f64 * (1024.0 / 16.0)
    );

    // Also report setup cost under permissive (unconstrained-equivalent)
    // constraints, for direct comparison -- see docs/DESIGN.md.
    let permissive = cipher::TopologyConstraints {
        require_full_diffusion: false,
        min_node_fanin: 0,
        max_usage_ratio: f64::INFINITY,
        max_attempts: 1,
    };
    let t0 = Instant::now();
    let _ = cipher::CipherContext::new_with_topology_constraints(&key, &permissive).unwrap();
    let t_permissive = t0.elapsed();
    println!(
        "  one-time setup with permissive (attempt-0-only) constraints: {:.2} ms  (isolates the topology-search overhead)",
        t_permissive.as_secs_f64() * 1000.0
    );
}
