# KGRTC

**KGRTC (Key-Generated Reversible Transformer Cipher)** is an experimental Rust cryptography research project exploring a different design question:

> Can a block-cipher-like construction derive not only secret numerical parameters, but also parts of its internal computational structure from the key?

KGRTC is **research software, not a production cryptographic primitive**. It has not received independent cryptanalysis or a formal security proof. The repository is designed to make the construction reproducible, inspectable, testable, and easy to analyze. Researchers and independent analysts are explicitly encouraged to analyze and attempt to break the construction. Successful attacks and negative results are both valuable contributions.

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/status-experimental%20%2F%20unaudited-red.svg)](SECURITY.md)

> [!WARNING]
> **Do not use KGRTC to protect real or sensitive data.**
> Use a standardized, independently reviewed AEAD such as AES-256-GCM or ChaCha20-Poly1305 for real applications.

---

## Table of contents

- [What KGRTC is](#what-kgrtc-is)
- [Canonical specification](#canonical-specification)
- [Security status](#security-status)
- [Architecture at a glance](#architecture-at-a-glance)
- [How encryption works](#how-encryption-works)
- [Key-derived computation](#key-derived-computation)
- [Round construction](#round-construction)
- [Reversible coupling](#reversible-coupling)
- [Authenticated encryption wrapper](#authenticated-encryption-wrapper)
- [What has been established](#what-has-been-established)
- [What has not been established](#what-has-not-been-established)
- [Repository structure](#repository-structure)
- [Getting started](#getting-started)
- [Using the library](#using-the-library)
- [Analysis and experiments](#analysis-and-experiments)
- [Testing](#testing)
- [Documentation map](#documentation-map)
- [Design principles](#design-principles)
- [Known limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## What KGRTC is

KGRTC uses a 128-bit internal block state and a 256-bit master key. The current construction has 14 rounds.

The key is used as a deterministic source for multiple classes of round-specific material:

```text
                         256-bit master key
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
              domain separation          MAC-key domain
                    │
        ┌───────────┼────────────┬──────────────┐
        ▼           ▼            ▼              ▼
     S-boxes    permutations   round keys     F / G networks
                                                  │
                                ┌─────────────────┼────────────────┐
                                ▼                 ▼                ▼
                            architecture       topology         weights
                            (depth/heads)    (source graph)   (GF(2^8))
                                │                 │                │
                                └─────────────────┼────────────────┘
                                                  ▼
                                         nonlinear layers
```

The central research idea is therefore:

```text
fixed cipher structure
        │
        │        vs.
        ▼
key ──► parameters

key ──► architecture
   ├──► topology
   ├──► weights
   └──► nonlinear mappings
```

The generated architecture is deterministic: the same key, implementation/derivation rules, and topology-constraint configuration reproduce the same derived structures.

---

## Canonical specification

The repository has one normative source of truth: [`SPECIFICATION.md`](SPECIFICATION.md). It defines KGRTC-256 exactly, including parameters, byte and integer serialization, key-derived generation, round construction, CTR + HMAC-SHA-256 authenticated encryption, example vectors, and the independent implementation conformance profile.

The documents under `docs/` explain or analyze the construction; they do not define a second, competing version of the algorithm.

---

## Security status

KGRTC should currently be treated as an **experimental cryptographic construction**.

The repository contains useful evidence about the implementation, including:

- exact round-trip tests;
- authentication and tamper-detection tests;
- deterministic key-derived architecture generation;
- structural topology checks;
- exhaustive S-box quality metrics;
- sampled avalanche/differential experiments; and
- an exact, narrowly scoped differential analysis of selected internal components.

These results are useful for research, but they do **not** establish that KGRTC is secure against an attacker.

In particular, the project does not currently claim proven resistance to:

- differential cryptanalysis of the full construction;
- linear cryptanalysis;
- algebraic attacks;
- related-key attacks;
- impossible or truncated differential attacks;
- slide or invariant attacks;
- meet-in-the-middle attacks;
- statistical distinguishers on the full authenticated construction;
- side-channel attacks;
- fault attacks;
- implementation-level timing, cache, memory, or power leakage; or
- cryptanalytic attacks not covered by the existing analysis.

See [`SPECIFICATION.md`](SPECIFICATION.md) for the canonical KGRTC-256 definition and [`SECURITY.md`](SECURITY.md) for the project's security policy.

---

## Architecture at a glance

A 16-byte block is transformed through 14 key-derived rounds.

```text
Plaintext block (16 bytes)
          │
          ▼
┌─────────────────────────────┐
│          Round r            │
│                             │
│  1. Key-derived S-box       │
│             │               │
│             ▼               │
│  2. Key-derived permutation │
│             │               │
│             ▼               │
│       split: A || B         │
│             │               │
│             ▼               │
│  3. Reversible F/G coupling │
│             │               │
│             ▼               │
│  4. XOR round key Kᵣ        │
└──────────────┬──────────────┘
               │
             repeat
               │
               ▼
        Ciphertext block
```

The F/G coupling is:

```text
(A, B)
  │
  ├── F(A) ───────────────┐
  │                       ▼
  │                  B' = B ⊕ F(A)
  │                       │
  │                       ├── G(B') ───────┐
  │                       │                ▼
  └───────────────────────┴────────── A' = A ⊕ G(B')
                           │
                           ▼
                       (A', B')
```

The important property is that **F and G do not have to be invertible individually**. The coupling is invertible because one half of the state remains available at each XOR update.

---

## How encryption works

### 1. Build the key-dependent context

`CipherContext::new(key)` validates the 32-byte key and deterministically constructs the per-key state:

```text
K
│
├── 14 round S-boxes
├── 14 inverse S-boxes
├── 14 state permutations
├── 14 inverse permutations
├── 14 round keys
├── 14 F transformers
├── 14 G transformers
└── domain-separated MAC key
```

This generated state is cached and reused for subsequent blocks.

### 2. Transform each 16-byte block

For round `r`:

```text
Xᵣ
 │
 ▼
Sᵣ(Xᵣ)
 │
 ▼
Pᵣ(Sᵣ(Xᵣ))
 │
 ▼
(A, B)
 │
 ├── B' = B ⊕ Fᵣ(A)
 │
 └── A' = A ⊕ Gᵣ(B')
 │
 ▼
Cᵣ
 │
 ▼
Cᵣ ⊕ Kᵣ
 │
 ▼
Xᵣ₊₁
```

After all 14 rounds, this produces the raw block-cipher output.

### 3. Use the block transform inside CTR mode

The normal message API uses CTR rather than ECB-style message encryption; raw block operations remain exposed separately for research and testing.

For a nonce `N` and counter `i`:

```text
counter_blockᵢ = N || encode_be_u32(i)

keystreamᵢ = EncryptBlock(counter_blockᵢ)

ciphertextᵢ = plaintextᵢ ⊕ keystreamᵢ
```

There is no padding.

The current format is:

```text
nonce || ciphertext || authentication_tag
```

with the CTR input block constructed exactly as:

```text
CTR input = nonce[0..12] || counter[12..16]
counter = 32-bit big-endian integer starting at 0
```

where:

- nonce = 12 bytes;
- ciphertext = plaintext length;
- tag = 32-byte HMAC-SHA-256 value.

---

## Key-derived computation

KGRTC intentionally separates several concepts that are sometimes conflated.

### Key-derived architecture

The architecture determines the **shape** of each F/G transformer:

- depth: 2–4 layers;
- heads: 2–4 heads per layer.

The values are derived deterministically from the key, round number, and transformer identifier.

See [`docs/key-derived_architecture.md`](docs/key-derived_architecture.md) for a conceptual explanation; the exact derivation is normative in [`SPECIFICATION.md`](SPECIFICATION.md).

### Key-derived topology

The topology determines **which input bytes feed which output nodes**. The default generator attempts to satisfy structural constraints, but it has a bounded search and a deterministic best-candidate fallback; therefore those constraints are not unconditional guarantees for every possible key.

Each output node selects exactly three source indices per head. Candidate topologies are generated deterministically and checked against structural constraints such as:

- full structural diffusion;
- no dead inputs;
- minimum distinct fan-in; and
- bounded source-usage imbalance.

See [`docs/key-derived_topology.md`](docs/key-derived_topology.md) for the conceptual topology model; the exact generation and acceptance rules are normative in [`SPECIFICATION.md`](SPECIFICATION.md).

### Key-derived weights

Every selected source is paired with a nonzero 8-bit coefficient. The coefficients are derived with domain-separated SHAKE-256 input material and are used as multiplication factors in `GF(2^8)`.

See [`docs/key-derived_weights.md`](docs/key-derived_weights.md) for the conceptual role of weights; the exact derivation is normative in [`SPECIFICATION.md`](SPECIFICATION.md).

### Key-derived nonlinear transformations

The S-box construction is:

$$
S_K(x)=A_K(x^{-1})\oplus b_K
$$

where the inversion is in `GF(2^8)`, `A_K` is a key-derived invertible binary linear map, and `b_K` is a key-derived byte.

Because an invertible output linear map only relabels output differences, the differential-uniformity of the inversion-based construction remains 4. The S-box metrics are computed exhaustively over all 256 inputs for each S-box tested; the algebraic construction explains why the reported component metrics are invariant across valid affine choices.

See [`docs/key-derived_nonlinear_transformations.md`](docs/key-derived_nonlinear_transformations.md) for the mathematical explanation; the exact algorithms are normative in [`SPECIFICATION.md`](SPECIFICATION.md).

---

## Round construction

The current round can be summarized as:

$$
R_r =
XOR_{K_r}
\circ
C_r
\circ
P_r
\circ
S_r
$$

where:

- `Sᵣ` = round S-box;
- `Pᵣ` = round state permutation;
- `Cᵣ` = reversible F/G coupling;
- `Kᵣ` = 16-byte round key.

The complete block transform is:

$$
E_K = R_{13}\circ R_{12}\circ \cdots \circ R_1\circ R_0
$$

Decryption applies the same components in reverse order and uses the inverse S-boxes/permutations.

See [`docs/round_construction.md`](docs/round_construction.md).

---

## Reversible coupling

For an 8-byte/8-byte split:

$$
X=(A,B)
$$

the coupling computes:

$$
B'=B\oplus F(A)
$$

followed by:

$$
A'=A\oplus G(B')
$$

so:

$$
C(A,B)=(A',B')
$$

The inverse is:

$$
A=A'\oplus G(B')
$$

$$
B=B'\oplus F(A)
$$

This means the internal F/G networks can be non-bijective without preventing exact inversion of the overall coupling.

See [`docs/reversible_coupling.md`](docs/reversible_coupling.md).

---

## Authenticated encryption wrapper

The public message API is an **encrypt-then-MAC construction** that provides an authenticated-encryption-style interface. It is **not a standardized AEAD primitive**.

```text
plaintext
   │
   ▼
CTR using raw KGRTC block transform
   │
   ▼
ciphertext
   │
   ├───────────────┐
   ▼               │
nonce || ciphertext
   │               │
   ▼               │
HMAC-SHA-256  ◄────┘
   │
   ▼
tag

output = nonce || ciphertext || tag
```

The HMAC key is derived from the master key with a dedicated, domain-separated derivation label (`MAC_KEY_V1`). It is not a separately provisioned secret.

Decryption verifies the tag before decrypting the ciphertext. The tag comparison is implemented as a constant-time byte comparison.

### Important nonce rule

As with CTR-style constructions generally, **nonce reuse under the same key must be avoided**.

`encrypt()` generates a fresh 12-byte nonce when the caller does not provide one. Supplying a nonce manually is an advanced/testing interface and places nonce-management responsibility on the caller.

The 4-byte counter means a single nonce is limited to at most `2^32` counter blocks (at most `2^32 * 16` bytes) by the current implementation. Counter value 0 is used for the first block and increments as a 32-bit unsigned integer.

---

## What has been established

The repository intentionally distinguishes implementation invariants from cryptographic claims.

### Exact implementation properties

The test suite currently checks:

| Property | Status |
|---|---|
| Correct round-trip encryption/decryption | Tested |
| Wrong-key rejection | Tested |
| Ciphertext tamper rejection | Tested |
| Deterministic architecture for a fixed key | Tested |
| Full structural diffusion of default F/G topology candidates | Tested on 10 random keys × 14 rounds × F/G using the current test |
| No dead inputs in default F/G topology candidates | Tested on 10 random keys × 14 rounds × F/G using the current test |
| S-box bijectivity | Tested |
| S-box DU = 4 | Exhaustively tested |
| S-box nonlinearity = 112 | Exhaustively tested |
| S-box linearity = 16 | Exhaustively tested |
| S-box algebraic degree = 7 | Exhaustively tested |
| S-box maximum autocorrelation = 32 | Exhaustively tested |

These are implementation/test statements, not a claim that the full cipher is cryptographically secure. In particular, the default topology tests cover a finite random sample, while the generator itself can fall back after 32 deterministic candidates if no candidate satisfies every configured constraint.

### Analysis results

The repository also contains empirical and exact analysis. Those results are deliberately scoped to the exact experiment being performed.

For example, the exact differential-propagation analysis is currently limited to selected internal layer-0 F/G behavior rather than proving a property of the full 14-round cipher.

See [`docs/DIFFERENTIAL_ANALYSIS.md`](docs/DIFFERENTIAL_ANALYSIS.md).

---

## What has not been established

Passing the tests in this repository does **not** imply:

```text
"all structural tests pass"
        ≠
"the cipher is cryptographically secure"
```

In particular, the repository does not currently provide a security proof for the full primitive or a third-party cryptanalysis.

This distinction is a core part of the project's documentation policy: observations, exact mathematical properties, implementation invariants, experiments, and security claims are kept separate.

---

## Repository structure

```text
KGRTC/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── pull_request_template.md
├── SPECIFICATION.md                # Canonical normative KGRTC-256 specification
├── docs/
│   ├── API.md                      # Rust API and implementation interface
│   ├── CONFORMANCE.md              # Practical guide to the spec's conformance profile
│   ├── DESIGN.md                   # Design rationale and evidence boundaries
│   ├── DIFFERENTIAL_ANALYSIS.md    # Differential experiments and exact sub-analyses
│   ├── THREAT_MODEL.md             # Attacker model and security boundaries
│   ├── architecture-generation_procedure.md
│   ├── key-derived_architecture.md
│   ├── key-derived_nonlinear_transformations.md
│   ├── key-derived_topology.md
│   ├── key-derived_weights.md
│   ├── reversible_coupling.md
│   └── round_construction.md
├── examples/
│   ├── avalanche.rs
│   ├── basic_usage.rs
│   ├── differential_analysis.rs
│   ├── sbox_report.rs
│   └── topology_and_diffusion.rs
├── benches/
│   └── performance.rs
├── src/
│   ├── analyzer.rs
│   ├── cipher.rs
│   └── lib.rs
├── tests/
│   ├── correctness.rs
│   ├── sbox_quality.rs
│   └── topology.rs
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
└── SUPPORT.md
```

---

## Getting started

### Requirements

- Rust toolchain with Cargo;
- a current stable Rust compiler is recommended.

### Build

```bash
cargo build --release
```

### Run the test suite

```bash
cargo test
```

### Run the examples

```bash
cargo run --release --example basic_usage
cargo run --release --example avalanche
cargo run --release --example topology_and_diffusion
cargo run --release --example differential_analysis
cargo run --release --example sbox_report
```

### Run the benchmark harness

```bash
cargo bench
```

The benchmark target uses a simple `Instant`-based harness rather than Criterion.

---

## Using the library

A minimal example:

```rust
use kgrtc::cipher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = cipher::generate_key();

    let plaintext = b"experimental message";

    let encrypted = cipher::encrypt(plaintext, &key, None, None)?;
    let decrypted = cipher::decrypt(&encrypted, &key, None)?;

    assert_eq!(decrypted, plaintext);

    println!("round trip successful");
    Ok(())
}
```

For repeated operations under one key, construct and reuse a `CipherContext` so the key-dependent architecture is generated once. **The supplied context must correspond to the supplied key; the current API does not verify that association.**

```rust
use kgrtc::cipher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = cipher::generate_key();
    let ctx = cipher::CipherContext::new(&key)?;

    let ciphertext = cipher::encrypt(
        b"hello",
        &key,
        Some(&ctx),
        None,
    )?;

    let plaintext = cipher::decrypt(&ciphertext, &key, Some(&ctx))?;

    assert_eq!(plaintext, b"hello");
    Ok(())
}
```

### Raw block API

The repository also exposes lower-level block operations for research and analysis:

```rust
let ctx = cipher::CipherContext::new(&key)?;

let block = [0u8; cipher::BLOCK_SIZE];
let encrypted_block = cipher::encrypt_block(&block, &ctx);
let recovered_block = cipher::decrypt_block(&encrypted_block, &ctx);

assert_eq!(recovered_block, block);
```

The raw block interface is **not** a replacement for a standard authenticated-encryption scheme, and the public CTR + HMAC wrapper is not a standardized AEAD construction.

---

## Analysis and experiments

The `examples/` directory contains executable analyses rather than only demonstrations.

### Avalanche analysis

Measures output bit changes under small input changes.

```bash
cargo run --release --example avalanche
```

### Topology and diffusion

Compares structural dependency behavior and reports topology diagnostics.

```bash
cargo run --release --example topology_and_diffusion
```

### Differential analysis

Runs sampled and exact differential-propagation experiments.

```bash
cargo run --release --example differential_analysis
```

### S-box report

Computes exact metrics over the complete 256-entry S-box domain.

```bash
cargo run --release --example sbox_report
```

When interpreting these outputs, distinguish:

```text
exhaustive metric on a component
        ≠
proof of security of the full cipher
```

---

## Testing

The repository uses tests for deterministic implementation invariants and keeps exploratory measurements in `examples/`.

Run everything with:

```bash
cargo test
```

The main test groups are:

### `tests/correctness.rs`

Checks:

- round-trip behavior over many random messages;
- the difference between legacy raw ECB and the public CTR-based API;
- ciphertext tamper detection;
- wrong-key rejection.

### `tests/sbox_quality.rs`

Exhaustively checks S-box properties over all 256 inputs and verifies the expected structural metrics.

### `tests/topology.rs`

Checks deterministic topology generation and, for the selected candidates in its finite random-key sample, full structural diffusion and absence of dead inputs. It does not exhaustively prove the default constraints for every key and does not directly assert the default fan-in or usage-ratio thresholds.

---

## Documentation map

| Document | Role |
|---|---|
| [`SPECIFICATION.md`](SPECIFICATION.md) | **Canonical normative definition of KGRTC-256** |
| [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) | Practical implementation checklist based on Appendix E |
| [`docs/key-derived_architecture.md`](docs/key-derived_architecture.md) | Conceptual explanation of key-derived computational shape |
| [`docs/key-derived_topology.md`](docs/key-derived_topology.md) | Conceptual explanation of topology generation and structural screening |
| [`docs/key-derived_weights.md`](docs/key-derived_weights.md) | Conceptual explanation of key-derived GF(2^8) coefficients |
| [`docs/key-derived_nonlinear_transformations.md`](docs/key-derived_nonlinear_transformations.md) | Mathematical explanation of S-boxes and nonlinear layers |
| [`docs/architecture-generation_procedure.md`](docs/architecture-generation_procedure.md) | Human-readable walkthrough of complete context generation |
| [`docs/round_construction.md`](docs/round_construction.md) | Conceptual explanation of the 14-round construction |
| [`docs/reversible_coupling.md`](docs/reversible_coupling.md) | Explanation of the reversible F/G coupling and its inverse |
| [`docs/DESIGN.md`](docs/DESIGN.md) | Design rationale and distinction between proof, tests, and observation |
| [`docs/API.md`](docs/API.md) | Public Rust API and implementation behavior |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Security goals, attacker model, and analysis boundaries |
| [`docs/DIFFERENTIAL_ANALYSIS.md`](docs/DIFFERENTIAL_ANALYSIS.md) | Differential-propagation experiments and their scope |
| [`SECURITY.md`](SECURITY.md) | Repository security policy and deployment warning |

---

## Design principles

KGRTC's implementation is organized around several explicit principles:

1. **Deterministic key-derived construction** — the same key reconstructs the same internal architecture.
2. **Domain separation** — different components derive from distinct labels/identifiers.
3. **Structural screening** — topology candidates can be rejected based on explicit graph properties.
4. **Reversibility by construction** — F/G functions may be non-invertible while the coupling remains invertible.
5. **Separation of evidence** — exact properties, tests, experiments, and security claims are documented separately.
6. **Reproducibility** — examples and tests are included in the repository rather than relying only on prose.

---

## Known limitations

The current implementation is intentionally a research prototype.

Important limitations include:

- it is unaudited;
- it has no third-party cryptanalysis;
- it has no formal full-cipher security proof;
- the public authenticated wrapper is constructed from CTR + HMAC-SHA-256 rather than a standardized AEAD primitive;
- manual nonce management is possible and must be handled correctly;
- the raw block API is intentionally exposed for analysis and should not be treated as a complete messaging protocol;
- the topology analysis evaluates structural reachability, not cryptographic independence;
- the current exact differential analysis is deliberately scoped rather than a proof for the complete cipher; and
- implementation side-channel resistance has not been established.

---

## Contributing

Contributions are welcome, especially:

- reproducible cryptanalysis;
- independent analysis of the full 14-round construction;
- formalization of claimed properties;
- tests that distinguish true invariants from empirical observations;
- performance improvements that preserve behavior; and
- clearer technical documentation.

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request.

---

## License

KGRTC is released under the MIT License. See [`LICENSE`](LICENSE).
