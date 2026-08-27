//! Structural diffusion of the key-generated F/G transformer topology,
//! and a head-to-head comparison between the old unconstrained
//! generation (accept whatever the first key-derived candidate
//! produces) and the current constrained generation (candidate-generate-
//! and-check, see `cipher::TopologyConstraints`). The corresponding hard
//! guarantee ("every accepted transformer reaches full diffusion") is
//! asserted in `tests/topology.rs`; this example is for the descriptive
//! comparison, not a pass/fail check. See docs/DESIGN.md.

use kgrtc::analyzer;
use kgrtc::cipher;

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn architecture_diffusion(n_keys: usize) {
    println!("--- Architecture diffusion check across {n_keys} random keys (all {} rounds each) ---", cipher::ROUNDS);
    let mut total_full_f = 0;
    let mut total_full_g = 0;
    let mut total_rounds = 0;
    let mut coverage_f_all = Vec::new();
    let mut coverage_g_all = Vec::new();
    let rounds: Vec<u32> = (0..cipher::ROUNDS as u32).collect();

    for _ in 0..n_keys {
        let key = cipher::generate_key();
        let results = analyzer::analyze_key(&key, &rounds, false);
        for r in &results {
            total_rounds += 1;
            if r.f_diffusion.full_diffusion {
                total_full_f += 1;
            }
            if r.g_diffusion.full_diffusion {
                total_full_g += 1;
            }
            coverage_f_all.push(r.f_diffusion.coverage_fraction);
            coverage_g_all.push(r.g_diffusion.coverage_fraction);
        }
    }
    println!("  F full diffusion: {total_full_f}/{total_rounds} rounds  (avg coverage {:.3})", mean(&coverage_f_all));
    println!("  G full diffusion: {total_full_g}/{total_rounds} rounds  (avg coverage {:.3})", mean(&coverage_g_all));
    println!();
}

fn topology_constraints(n_keys: usize) {
    println!("--- Topology constraints: unconstrained vs constrained F/G generation across {n_keys} random keys ---");
    let rounds: Vec<u32> = (0..cipher::ROUNDS as u32).collect();
    let constraints = cipher::TopologyConstraints::default();
    println!(
        "  constraints: require_full_diffusion={} min_node_fanin={} max_usage_ratio={:.2} max_attempts={}",
        constraints.require_full_diffusion, constraints.min_node_fanin, constraints.max_usage_ratio, constraints.max_attempts
    );

    let mut unconstrained_full_f = 0;
    let mut unconstrained_full_g = 0;
    let mut constrained_full_f = 0;
    let mut constrained_full_g = 0;
    let mut constrained_satisfied_f = 0;
    let mut constrained_satisfied_g = 0;
    let mut total_rounds = 0;
    let mut attempts_f = Vec::new();
    let mut attempts_g = Vec::new();

    for _ in 0..n_keys {
        let key = cipher::generate_key();

        let unconstrained = analyzer::analyze_key(&key, &rounds, false);
        for r in &unconstrained {
            total_rounds += 1;
            if r.f_diffusion.full_diffusion {
                unconstrained_full_f += 1;
            }
            if r.g_diffusion.full_diffusion {
                unconstrained_full_g += 1;
            }
        }

        let constrained = analyzer::analyze_key_constrained(&key, &rounds, &constraints, false);
        for r in &constrained {
            if r.f_diffusion.full_diffusion {
                constrained_full_f += 1;
            }
            if r.g_diffusion.full_diffusion {
                constrained_full_g += 1;
            }
            if r.f_topology.dead_inputs.is_empty()
                && r.f_topology.min_node_fanin >= constraints.min_node_fanin
                && r.f_topology.max_usage_ratio <= constraints.max_usage_ratio
            {
                constrained_satisfied_f += 1;
            }
            if r.g_topology.dead_inputs.is_empty()
                && r.g_topology.min_node_fanin >= constraints.min_node_fanin
                && r.g_topology.max_usage_ratio <= constraints.max_usage_ratio
            {
                constrained_satisfied_g += 1;
            }
            attempts_f.push(r.f_topology.attempt as f64);
            attempts_g.push(r.g_topology.attempt as f64);
        }
    }

    println!("  [unconstrained, attempt 0 only] F full diffusion: {unconstrained_full_f}/{total_rounds}   G full diffusion: {unconstrained_full_g}/{total_rounds}");
    println!("  [constrained]                   F full diffusion: {constrained_full_f}/{total_rounds}   G full diffusion: {constrained_full_g}/{total_rounds}");
    println!("  [constrained] F fully satisfies all constraints: {constrained_satisfied_f}/{total_rounds}   G fully satisfies all constraints: {constrained_satisfied_g}/{total_rounds}");
    println!(
        "  mean acceptance attempt index -- F: {:.2}   G: {:.2}  (0 = first candidate already passed)",
        mean(&attempts_f),
        mean(&attempts_g)
    );
    println!();
}

fn main() {
    architecture_diffusion(10);
    topology_constraints(10);
}
