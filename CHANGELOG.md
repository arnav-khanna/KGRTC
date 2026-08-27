# Changelog

All notable changes to KGRTC are documented here.

The project is currently experimental, so version numbers describe repository releases rather than a claim of cryptographic maturity.

## Unreleased

### Documentation structure

- `SPECIFICATION.md` is the single normative source of truth for KGRTC-256.
- Concept, analysis, API, and security documents under `docs/` are explicitly scoped as non-normative supporting documentation.
- Added `docs/CONFORMANCE.md` as a practical guide to the normative Appendix E conformance profile.
- Removed the stale README reference to the absent `docs/CLAIMS_AUDIT.md`.

## [0.2.0] — current repository version

- Rust implementation of the KGRTC construction.
- Deterministic per-key generation of round S-boxes, state permutations, round keys, and F/G mixing networks.
- Constraint-checked F/G topology generation with deterministic retry and best-candidate fallback.
- Key-derived GF(2^8) weights.
- Reversible two-stage F/G coupling.
- Public CTR + HMAC-SHA-256 encrypt-then-MAC wrapper.
- Exact S-box metric tests.
- Structural topology tests.
- Correctness and authentication tests.
- Differential-analysis examples and documentation.

## Earlier prototype

KGRTC originated as a Python prototype before the current Rust implementation. Historical prototype material is referenced in the repository documentation where relevant.

## Versioning note

A version change does not imply that the primitive has been independently reviewed or declared secure. Consult [`SECURITY.md`](SECURITY.md) for the current security position.
