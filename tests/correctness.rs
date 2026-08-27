//! Round-trip correctness, ECB-pattern-leakage, and tamper-detection
//! properties of the public `cipher::encrypt` / `cipher::decrypt` API.
//!
//! These are hard pass/fail assertions, not statistical health checks --
//! see `tests/sbox_quality.rs` and `tests/topology.rs` for the exact
//! (deterministic) structural properties, and `examples/` for the
//! sampled/empirical differential analysis, which isn't assertion-shaped.

use std::collections::HashSet;

use kgrtc::cipher;

#[test]
fn round_trip_recovers_plaintext_for_many_random_messages() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let trials = 300;
    let mut failures = 0;

    for _ in 0..trials {
        let key = cipher::generate_key();
        let length: usize = rng.gen_range(0..=255); // exercises empty, partial-block, and multi-block messages
        let mut pt = vec![0u8; length];
        rand::RngCore::fill_bytes(&mut rng, &mut pt);

        let blob = cipher::encrypt(&pt, &key, None, None).unwrap();
        let recovered = cipher::decrypt(&blob, &key, None).unwrap();
        if recovered != pt {
            failures += 1;
        }
    }

    assert_eq!(failures, 0, "{}/{} round-trips failed to recover the original plaintext", failures, trials);
}

#[test]
fn legacy_ecb_path_leaks_identical_blocks_but_public_api_does_not() {
    let key = cipher::generate_key();
    let ctx = cipher::CipherContext::new(&key).unwrap();
    let pt = vec![b'A'; 64]; // four identical 16-byte blocks

    // The old (v1) raw single-block ECB path is kept around specifically
    // to demonstrate what it used to do wrong -- assert it still does.
    let ecb_blocks: Vec<Vec<u8>> = pt.chunks(16).map(|c| cipher::insecure_ecb_encrypt_single_block(c, &ctx)).collect();
    let unique_ecb: HashSet<&Vec<u8>> = ecb_blocks.iter().collect();
    assert_eq!(unique_ecb.len(), 1, "sanity check failed: legacy ECB path was expected to leak identical blocks");

    // The real public API (CTR+HMAC) must not have this problem.
    let blob1 = cipher::encrypt(&pt, &key, None, None).unwrap();
    let blob2 = cipher::encrypt(&pt, &key, None, None).unwrap(); // fresh random nonce each call
    let ct1 = &blob1[cipher::NONCE_SIZE..blob1.len() - cipher::TAG_SIZE];
    let ct2 = &blob2[cipher::NONCE_SIZE..blob2.len() - cipher::TAG_SIZE];

    let unique_ct1: HashSet<&[u8]> = ct1.chunks(16).collect();
    assert_ne!(unique_ct1.len(), 1, "identical plaintext blocks produced identical ciphertext blocks under the public CTR API");
    assert_ne!(ct1, ct2, "two encryptions of the same plaintext produced identical ciphertext (nonce reuse?)");
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let key = cipher::generate_key();
    let pt = b"transfer $100 to alice".to_vec();
    let mut blob = cipher::encrypt(&pt, &key, None, None).unwrap();
    blob[cipher::NONCE_SIZE] ^= 0x01; // flip one ciphertext bit

    let result = cipher::decrypt(&blob, &key, None);
    assert!(result.is_err(), "tampered ciphertext was accepted instead of rejected");
}

#[test]
fn wrong_key_is_rejected() {
    let key = cipher::generate_key();
    let wrong_key = cipher::generate_key();
    let pt = b"some message".to_vec();
    let blob = cipher::encrypt(&pt, &key, None, None).unwrap();

    let result = cipher::decrypt(&blob, &wrong_key, None);
    assert!(result.is_err(), "ciphertext decrypted successfully under the wrong key");
}
