# Threat Model and Security Boundaries

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); it defines the research attacker model and boundaries rather than adding cryptographic guarantees.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §7.

This document defines what the current KGRTC repository is trying to build and what remains outside its established security claims.

## Intended research question

The project explores a deterministic key-generated block-cipher architecture in which the secret key influences:

```text
architecture
    ↓
topology
    ↓
weights
    ↓
nonlinear transformations
    ↓
round-specific computation
```

The construction is intended to remain exactly reversible even when internal F/G functions are not individually invertible.

## Intended attacker model

For cryptanalytic research, assume the attacker can obtain arbitrary ciphertexts and, depending on the experiment, chosen plaintext/ciphertext pairs.

The attacker is assumed to know:

- the complete public algorithm;
- the source code;
- the parameter-generation procedure;
- the topology constraints;
- the use of SHAKE-256, SHA-256, HMAC, and the finite-field arithmetic;
- the ciphertext/nonce/tag format.

The master key is the only intended secret. The public algorithm, derivation rules, topology constraints, and implementation are assumed known to the attacker.

This is Kerckhoffs-style public-algorithm analysis, not security through obscurity.

## Security goals of the message wrapper

The public wrapper is intended to provide an authenticated-encryption-style interface using CTR + HMAC-SHA-256 encrypt-then-MAC. This is not a standardized AEAD construction, and the security of the complete wrapper has not been independently established.

### Confidentiality

CTR mode converts the raw block transform into a stream construction so repeated plaintext blocks do not directly map to repeated ciphertext blocks under a fresh nonce.

### Integrity and authenticity

HMAC-SHA-256 authenticates:

```text
nonce || ciphertext
```

and decryption rejects the message when the tag does not verify.

### Deterministic key-specific internal construction

The same key, implementation/derivation rules, and topology-constraint configuration reconstruct the same internal cipher context.

This property is useful for the research construction but is not itself a security goal.

## Explicitly excluded claims

The project does not currently establish semantic security, PRP/PRF security, IND-CPA/IND-CCA security, or any comparable full-cipher theorem. It also does not claim nonce-misuse resistance: nonce reuse is outside the safe operating conditions of the CTR wrapper.

Likewise, a successful component-level property does not automatically compose into a full-cipher proof.

Examples:

```text
S-box DU = 4
        ≠
full cipher differential security

full structural diffusion
        ≠
bit-level independence or pseudorandomness

avalanche experiment
        ≠
proof of pseudorandomness
```

## Current analysis boundaries

The repository currently studies several properties:

- exact reversibility;
- authentication behavior;
- S-box algebraic and differential metrics;
- structural topology reachability;
- sampled avalanche behavior;
- sampled differential propagation; and
- exact differential behavior for narrowly defined internal cases.

These analyses are complementary, but none is by itself a complete security evaluation.

## High-priority future cryptanalysis

The most valuable next analyses would include:

1. full-cipher differential cryptanalysis across all 14 rounds;
2. linear approximations and correlation bounds;
3. algebraic degree growth and potential low-degree relations;
4. invariant-subspace and fixed-structure analysis;
5. related-key analysis;
6. reduced-round distinguishers;
7. impossible and truncated differential searches;
8. impossible/rebound-style searches where appropriate;
9. statistical distinguishers against the full block permutation; and
10. side-channel review of the implementation.

## Research philosophy

Security claims should move through the following ladder:

```text
idea
 ↓
implementation
 ↓
unit/invariant tests
 ↓
exhaustive component analysis
 ↓
independent reproduction
 ↓
reduced-round cryptanalysis
 ↓
full-cipher cryptanalysis
 ↓
formal security reasoning / third-party review
```

KGRTC is currently a research implementation rather than a cryptographically validated primitive.
