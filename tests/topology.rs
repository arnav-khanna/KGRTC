//! Assertions on `GeneratedTransformer::new_constrained` / `CipherContext`'s
//! default topology constraints: every accepted F/G transformer must
//! reach full structural diffusion and have no dead inputs. See
//! docs/DESIGN.md for what "full diffusion" does and doesn't establish
//! (structural coverage, not a differential-security bound), and
//! `examples/topology_and_diffusion.rs` for a head-to-head comparison
//! against the old unconstrained generation this replaced.

use kgrtc::cipher;

#[test]
fn constrained_topology_always_reaches_full_diffusion() {
    let constraints = cipher::TopologyConstraints::default();

    for _ in 0..10 {
        let key = cipher::generate_key();
        for round in 0..cipher::ROUNDS {
            let (_f, f_topology) =
                cipher::GeneratedTransformer::new_constrained(&key, round as u32, b"TRANSFORMER_F", &constraints);
            let (_g, g_topology) =
                cipher::GeneratedTransformer::new_constrained(&key, round as u32, b"TRANSFORMER_G", &constraints);

            assert!(f_topology.full_diffusion, "round {round}: F failed to reach full diffusion");
            assert!(g_topology.full_diffusion, "round {round}: G failed to reach full diffusion");
            assert!(f_topology.dead_inputs.is_empty(), "round {round}: F has dead inputs {:?}", f_topology.dead_inputs);
            assert!(g_topology.dead_inputs.is_empty(), "round {round}: G has dead inputs {:?}", g_topology.dead_inputs);
        }
    }
}

#[test]
fn cipher_context_exposes_matching_topology_diagnostics() {
    let key = cipher::generate_key();
    let ctx = cipher::CipherContext::new(&key).unwrap();

    assert_eq!(ctx.round_f_topology.len(), cipher::ROUNDS);
    assert_eq!(ctx.round_g_topology.len(), cipher::ROUNDS);
    for (round, (f_topo, g_topo)) in ctx.round_f_topology.iter().zip(ctx.round_g_topology.iter()).enumerate() {
        assert!(f_topo.full_diffusion, "round {round}: CipherContext's F topology lacks full diffusion");
        assert!(g_topo.full_diffusion, "round {round}: CipherContext's G topology lacks full diffusion");
    }
}

#[test]
fn topology_generation_is_deterministic_per_key() {
    let key = cipher::generate_key();
    let constraints = cipher::TopologyConstraints::default();

    let (f1, diag1) = cipher::GeneratedTransformer::new_constrained(&key, 0, b"TRANSFORMER_F", &constraints);
    let (f2, diag2) = cipher::GeneratedTransformer::new_constrained(&key, 0, b"TRANSFORMER_F", &constraints);

    assert_eq!(f1.depth, f2.depth);
    assert_eq!(f1.heads, f2.heads);
    assert_eq!(f1.connections, f2.connections, "same key produced different topology across two calls");
    assert_eq!(diag1.attempt, diag2.attempt, "same key was accepted at a different attempt index across two calls");
}
