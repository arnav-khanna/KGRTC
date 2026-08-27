# Security Policy

> The canonical cryptographic definition is [`SPECIFICATION.md`](SPECIFICATION.md). Its Section 7 is the authoritative security-status statement; this file is the repository-level deployment and reporting policy.

## Security status

KGRTC is an **experimental, unaudited cryptographic research project**.

It is not currently appropriate for protecting real-world secrets, credentials, personal data, financial information, production systems, or safety-critical data.

For production cryptography, use a standardized and independently reviewed AEAD construction such as AES-256-GCM or ChaCha20-Poly1305.

## What this repository does claim

The project makes implementation-level and mathematical claims only where they are supported by the code, tests, or derivations in the documentation.

Examples include:

- exact reversible block transformation;
- deterministic key-derived architecture generation;
- structural topology constraints;
- bijectivity and exact component metrics for the generated S-box construction;
- authenticated-message behavior for the current CTR + HMAC-SHA-256 encrypt-then-MAC wrapper, subject to correct key/context pairing and nonce management.

These statements should not be read as a claim of full-cipher security.

## What this repository does not claim

KGRTC has not been established secure against general cryptanalysis.

No guarantee is currently made regarding:

- differential cryptanalysis of the full cipher;
- linear cryptanalysis;
- algebraic cryptanalysis;
- related-key attacks;
- slide, invariant, impossible-differential, or meet-in-the-middle attacks;
- distinguishers against the full construction;
- side-channel leakage;
- fault attacks;
- misuse of the public API, including supplying a `CipherContext` generated from a different key than the separate `key` argument; the current API does not verify that association and, when a context is supplied, does not independently validate the separate key argument;
- weak platform randomness;
- implementation-specific compiler or hardware effects; or
- future attacks not covered by current analysis.

## Scope of the public API

The normal message API is:

```text
encrypt(plaintext, key, ..., nonce)
    -> nonce || ciphertext || HMAC-SHA-256 tag

decrypt(blob, key, ...)
    -> authenticate first, then decrypt
```

The raw block functions and the legacy ECB helper exist primarily for testing and research.

In particular, do **not** use:

```rust
insecure_ecb_encrypt_single_block(...)
```

for real data.

## Nonce management

The current CTR wrapper uses a 12-byte nonce followed by a 4-byte big-endian block counter starting at 0. Each counter block is `nonce || counter`. The counter provides at most `2^32` blocks per nonce.

The same nonce must not be reused with the same key.

`encrypt()` generates a fresh random nonce when one is not supplied. Providing an explicit nonce is intended for deterministic tests and advanced use where the caller can enforce correct nonce uniqueness.

## Reporting a vulnerability

Please do not publish an exploitable vulnerability as a public issue before giving maintainers an opportunity to investigate it.

Preferred reporting path:

1. Use GitHub's **Private vulnerability reporting / Security Advisories** for this repository if that feature is enabled.
2. Otherwise, contact the repository maintainer privately through the repository's available contact mechanism.

A useful report should include:

- a concise description of the issue;
- affected commit/version;
- exact reproduction steps;
- a minimal test case or proof of concept where practical;
- the expected behavior; and
- the observed behavior and why it matters.

Please avoid including real secrets or sensitive data in reports.

## Research disclosures

Cryptanalysis and reproducible attacks are valuable contributions to this project.

For issues that are not immediately exploitable, a public issue or pull request is generally appropriate after verifying the result and providing enough detail for independent reproduction.

The project intentionally favors transparent documentation of weaknesses over unsupported security claims.
