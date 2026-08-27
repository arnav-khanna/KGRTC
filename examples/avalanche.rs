//! Avalanche distribution: single-bit plaintext/key flips should change
//! roughly half of the output bits. Sampled statistics, not an exact
//! guarantee -- see docs/DIFFERENTIAL_ANALYSIS.md for why "close to 0.5
//! on average" is a much weaker claim than a real differential bound.

use kgrtc::cipher;

fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn pstdev(v: &[f64]) -> f64 {
    let m = mean(v);
    (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64).sqrt()
}

fn main() {
    let trials = 500;
    println!("--- Avalanche distribution over {trials} trials (single block, no mode wrapper) ---");

    let key = cipher::generate_key();
    let ctx = cipher::CipherContext::new(&key).unwrap();
    let mut rng = rand::thread_rng();

    let mut pt_fracs = Vec::with_capacity(trials);
    for _ in 0..trials {
        let mut pt = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rng, &mut pt);
        let mut pt2 = pt.clone();
        pt2[0] ^= 0x01;
        let c1 = cipher::encrypt_block(&pt, &ctx);
        let c2 = cipher::encrypt_block(&pt2, &ctx);
        pt_fracs.push(hamming(&c1, &c2) as f64 / 128.0);
    }
    println!("  Plaintext-bit-flip avalanche:");
    println!("    mean = {:.4}  stdev = {:.4}  (ideal mean 0.5)", mean(&pt_fracs), pstdev(&pt_fracs));

    let mut key_fracs = Vec::with_capacity(trials);
    for _ in 0..trials {
        let mut pt = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rng, &mut pt);
        let k1 = cipher::generate_key();
        let mut k2 = k1.clone();
        k2[0] ^= 0x01;
        let ctx1 = cipher::CipherContext::new(&k1).unwrap();
        let ctx2 = cipher::CipherContext::new(&k2).unwrap();
        let c1 = cipher::encrypt_block(&pt, &ctx1);
        let c2 = cipher::encrypt_block(&pt, &ctx2);
        key_fracs.push(hamming(&c1, &c2) as f64 / 128.0);
    }
    println!("  Key-bit-flip avalanche:");
    println!("    mean = {:.4}  stdev = {:.4}  (ideal mean 0.5)", mean(&key_fracs), pstdev(&key_fracs));
}
