# KGRTC-256 Conformance Guide

> **Document status — implementation guide**
>
> This document is a practical checklist derived from the normative
> conformance requirements in [`../SPECIFICATION.md`](../SPECIFICATION.md).
> It does not add or modify any requirement. If this guide and the
> specification differ, the specification takes precedence.

## Purpose

An independent implementation should use the normative specification,
especially:

- Section 2.4 — Interoperability and Conformance Profile
- Sections 4–5 — mathematical primitives and KGRTC-256 algorithms
- Appendix A — architecture-generation examples
- Appendix B — cipher example
- Appendix C — authenticated-encryption example vector
- Appendix E — Independent Implementation Conformance Profile

## Recommended order

### 1. Primitive checks

Verify the low-level primitives first:

- SHAKE-256 stream generation over the exact seed bytes;
- `gf_mul()` using the specified reduction polynomial `0x11B`;
- the fixed inverse table, including `inv[0] = 0`;
- GF(2) matrix-vector multiplication and the specified affine construction;
- canonical byte and integer serialization.

### 2. Component-generation checks

Then reproduce the deterministic components:

- key-derived S-boxes and inverse S-boxes;
- state permutations and inverse permutations;
- transformer shape;
- candidate topology generation;
- topology acceptance and fallback;
- key-derived weights;
- transformer layer S-boxes;
- round keys.

The exact values and derivation rules are those in the specification.

### 3. Cipher checks

Verify:

```text
CIPHER(block, key)
INVCIPHER(CIPHER(block, key), key) = block
```

Use the worked values in Appendices A and B where applicable.

### 4. Authenticated-encryption checks

Verify the Appendix C authenticated-encryption vector byte-for-byte.

Also verify the documented tamper behavior: modifying authenticated
message data must cause authentication failure.

### 5. Independent implementation discipline

For interoperability, do not replace normative byte-string operations with
implementation-specific integer interpretations.

The specification defines byte sequences, serialization, indexing, and
domain-separated derivation explicitly. Reimplement those rules exactly.

## What conformance does and does not establish

Passing the conformance vectors establishes evidence that an implementation
matches the specified algorithms for the tested cases.

It does **not** establish that KGRTC is cryptographically secure.

The specification's Section 7 remains controlling for the security status:
KGRTC is experimental and unaudited, and the project does not claim
full-cipher resistance to differential, linear, algebraic, key-recovery,
or side-channel attacks.

## Reference material

- [`../SPECIFICATION.md`](../SPECIFICATION.md) — normative source of truth
- [`../SECURITY.md`](../SECURITY.md) — repository security policy
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — attacker model and analysis boundaries
