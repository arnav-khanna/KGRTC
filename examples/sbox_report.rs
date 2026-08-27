//! Prints the full S-box quality metric suite for a handful of
//! key-derived S-boxes. These metrics are EXACT (exhaustive over all 256
//! inputs), and asserted as hard invariants in `tests/sbox_quality.rs` --
//! this example is just for human-readable output. See docs/DESIGN.md
//! for why every metric except fixed points/cycle structure is
//! guaranteed constant across every key.

use kgrtc::analyzer;
use kgrtc::cipher;

fn main() {
    let n_sboxes = 8u32;
    println!("--- S-box quality: full metric suite ({n_sboxes} sboxes) ---");
    let key = cipher::generate_key();
    for r in 0..n_sboxes {
        let sbox = cipher::generate_sbox(&key, r, b"SBOX");
        let report = analyzer::sbox_quality_report(&sbox);
        println!(
            "  round {r}: bijective={}  DU={} (AES: 4)  nonlinearity={} (AES: 112, max possible: 116)  degree={} (AES/max: 7)",
            report.bijective, report.differential_uniformity, report.nonlinearity, report.algebraic_degree
        );
        println!(
            "            linearity={} (AES: 16)  autocorrelation={} (AES: 32)  fixed_points={}  opposite_fixed_points={}",
            report.linearity, report.max_autocorrelation, report.fixed_points, report.opposite_fixed_points
        );
        println!(
            "            cycle structure (longest first, top 8): {:?}{}",
            &report.cycle_lengths[..report.cycle_lengths.len().min(8)],
            if report.cycle_lengths.len() > 8 { " ..." } else { "" }
        );
    }
}
