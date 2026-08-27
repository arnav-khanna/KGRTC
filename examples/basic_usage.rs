//! Minimal encrypt/decrypt usage. See SECURITY.md before using this for
//! anything beyond experimentation.

use kgrtc::cipher;

fn main() {
    let key = cipher::generate_key();
    let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();

    let ciphertext = cipher::encrypt(&plaintext, &key, None, None).expect("encryption failed");
    println!("plaintext:  {}", String::from_utf8_lossy(&plaintext));
    println!("ciphertext: {} bytes (nonce + CTR ciphertext + HMAC tag)", ciphertext.len());

    let recovered = cipher::decrypt(&ciphertext, &key, None).expect("decryption failed");
    assert_eq!(recovered, plaintext);
    println!("recovered:  {}", String::from_utf8_lossy(&recovered));

    // Tampering is rejected: encrypt-then-MAC means a flipped ciphertext
    // bit is caught before any plaintext is returned.
    let mut tampered = ciphertext.clone();
    tampered[cipher::NONCE_SIZE] ^= 0x01;
    match cipher::decrypt(&tampered, &key, None) {
        Ok(_) => println!("unexpected: tampered ciphertext was accepted"),
        Err(e) => println!("tampering correctly rejected: {e}"),
    }
}
