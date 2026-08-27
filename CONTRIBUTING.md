# Contributing to KGRTC

Thank you for contributing to KGRTC.

This repository is a cryptographic research project, so correctness, reproducibility, and careful wording are more important than simply adding features.

## Before you contribute

Please read:

- [`README.md`](README.md) for the architecture and project status;
- [`SECURITY.md`](SECURITY.md) for security boundaries and disclosure;
- [`docs/DESIGN.md`](docs/DESIGN.md) for existing design rationale; and
- [`docs/DIFFERENTIAL_ANALYSIS.md`](docs/DIFFERENTIAL_ANALYSIS.md) for the scope of current differential analysis.

## High-value contributions

The most useful contributions are those that improve evidence about the construction.

Examples:

- independent cryptanalysis;
- reproducible attack demonstrations;
- formal proofs of narrowly stated properties;
- exhaustive tests for component invariants;
- tests that expose edge cases in reversibility or authentication;
- independent performance measurements;
- documentation corrections; and
- refactors that preserve exact behavior.

## Development workflow

Create a branch for your change:

```bash
git checkout -b feature/my-change
```

Run the standard checks before opening a pull request:

```bash
cargo fmt --check
cargo test
cargo build --release
```

For research changes, also run the relevant example programs:

```bash
cargo run --release --example sbox_report
cargo run --release --example topology_and_diffusion
cargo run --release --example differential_analysis
```

Do not report a result from an example unless the experiment itself is clearly described and reproducible.

## Cryptographic claims

Be precise about the level of evidence.

Prefer:

> "The implementation exhaustively verifies DU = 4 for the generated S-box."

over:

> "The cipher has strong differential security."

Similarly, distinguish:

```text
proved mathematically
tested exhaustively
tested on a sample
observed experimentally
not yet established
```

A failing attack experiment is not evidence that an attack is impossible.

## Code style

Use standard Rust formatting:

```bash
cargo fmt
```

Prefer small, explicit functions and comments where an implementation detail is important for cryptographic reasoning.

When changing a mathematical transformation, update the relevant design document and tests together.

## Tests

New behavior should normally come with a test.

Use integration tests for public behavior and deterministic properties. Keep exploratory/statistical work in `examples/` when it is not naturally expressed as a hard pass/fail invariant.

## Documentation

Documentation should explain:

- the mathematical object being defined;
- the exact inputs to deterministic derivation;
- what is guaranteed by construction;
- what is only measured empirically; and
- what remains open.

Avoid describing a component as a "neural network" in the machine-learning sense. The F/G structures are key-generated nonlinear mixing networks; they are not trained models.

## Pull requests

A good pull request should:

- explain the motivation;
- describe the exact implementation change;
- include or update tests;
- identify any changed security assumptions;
- identify whether results are proof, exhaustive test, or experiment;
- update documentation when behavior or claims change; and
- avoid unrelated formatting or dependency changes.

For cryptanalytic findings, include enough information for an independent reader to reproduce the result.

## Reporting security issues

Do not use a normal public issue for a potentially exploitable vulnerability when private reporting is available. Follow [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are provided under the repository's MIT License.
