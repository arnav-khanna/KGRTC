//! S-box quality assertions. Unlike the differential-propagation
//! analysis in `examples/differential_analysis.rs`, these are EXACT --
//! `sbox_quality_report` computes every metric exhaustively over all 256
//! inputs -- so they're asserted as hard invariants, not reported as
//! statistics. See docs/DESIGN.md for why these are provably constant
//! across every key (the "invertible affine map only relabels the
//! spectrum" argument), not just observed to be constant.

use kgrtc::analyzer;
use kgrtc::cipher;

const SBOXES_TO_CHECK: u32 = 25;

#[test]
fn sbox_matches_aes_reference_metrics_for_every_key() {
    let key = cipher::generate_key();
    for r in 0..SBOXES_TO_CHECK {
        let sbox = cipher::generate_sbox(&key, r, b"SBOX");
        let report = analyzer::sbox_quality_report(&sbox);

        assert!(report.bijective, "round {r}: S-box is not bijective");
        assert_eq!(report.differential_uniformity, 4, "round {r}: DU != 4 (AES reference)");
        assert_eq!(report.nonlinearity, 112, "round {r}: nonlinearity != 112 (AES reference)");
        assert_eq!(report.linearity, 16, "round {r}: linearity != 16 (AES reference)");
        assert_eq!(report.algebraic_degree, 7, "round {r}: algebraic degree != 7 (AES reference)");
        assert_eq!(report.max_autocorrelation, 32, "round {r}: autocorrelation != 32 (AES reference)");
    }
}

#[test]
fn sbox_metrics_hold_across_many_independent_keys() {
    // Same assertions, but sweeping keys instead of rounds within one key
    // -- both axes matter, since the invariance argument is about the
    // affine-map construction, not about any particular key.
    for _ in 0..20 {
        let key = cipher::generate_key();
        let sbox = cipher::generate_sbox(&key, 0, b"SBOX");
        let report = analyzer::sbox_quality_report(&sbox);

        assert!(report.bijective);
        assert_eq!(report.differential_uniformity, 4);
        assert_eq!(report.nonlinearity, 112);
        assert_eq!(report.linearity, 16);
        assert_eq!(report.algebraic_degree, 7);
        assert_eq!(report.max_autocorrelation, 32);
    }
}

#[test]
fn ddt_row_multiplicities_never_exceed_differential_uniformity() {
    // sbox_ddt_row exposes the distinct achievable output-difference set
    // for one input difference; cross-check it against
    // sbox_differential_uniformity (computed independently in
    // analyzer.rs) by recomputing each row's actual multiplicities and
    // confirming none exceed the reported DU.
    let key = cipher::generate_key();
    let sbox = cipher::generate_sbox(&key, 0, b"SBOX");
    let du = analyzer::sbox_differential_uniformity(&sbox);

    for delta_in in 1u16..256 {
        let row = analyzer::sbox_ddt_row(&sbox, delta_in as u8);
        assert!(!row.is_empty(), "DDT row for delta_in={delta_in} was empty");
        assert!(row.len() <= 256, "DDT row larger than the codomain");

        let mut counts = [0usize; 256];
        for x in 0..256usize {
            let delta_out = sbox[x] ^ sbox[x ^ delta_in as usize];
            counts[delta_out as usize] += 1;
        }
        let max_multiplicity = *counts.iter().max().unwrap();
        assert!(
            max_multiplicity <= du,
            "delta_in={delta_in}: multiplicity {max_multiplicity} exceeds reported DU {du}"
        );
    }
}
