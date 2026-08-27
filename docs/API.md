# API Reference

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); the Rust source remains authoritative for signatures; cryptographic behavior affecting interoperability is governed by the specification.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §§2–5.

This page summarizes the main public Rust API. It is a companion to the source documentation; the source code remains authoritative for exact signatures and behavior.

## Constants

| Constant | Value | Meaning |
|---|---:|---|
| `BLOCK_SIZE` | 16 bytes | Raw block state size |
| `KEY_SIZE` | 32 bytes | Master-key size |
| `ROUNDS` | 14 | Number of block-cipher rounds |
| `HALF_SIZE` | 8 bytes | Size of each F/G coupling half |
| `NONCE_SIZE` | 12 bytes | CTR nonce size |
| `COUNTER_SIZE` | 4 bytes | CTR counter size |
| `TAG_SIZE` | 32 bytes | HMAC-SHA-256 tag size |

## Key generation

```rust
pub fn generate_key() -> Vec<u8>
```

Generates a random 32-byte master key using the Rust `rand` crate.

## Nonce generation

```rust
pub fn generate_nonce() -> Vec<u8>
```

Generates a random 12-byte nonce.

## Cipher context

```rust
pub struct CipherContext { ... }

impl CipherContext {
    pub fn new(key: &[u8]) -> Result<Self, CipherError>;

    pub fn new_with_topology_constraints(
        key: &[u8],
        topology_constraints: &TopologyConstraints,
    ) -> Result<Self, CipherError>;
}
```

`CipherContext` is the cached, key-specific generated cipher instance. When a context is supplied to `encrypt()` or `decrypt()`, the implementation trusts that context and does not verify that it was generated from the separately supplied `key` argument.

Constructing it derives and stores:

- round S-boxes and inverse S-boxes;
- round permutations and inverse permutations;
- round keys;
- F transformers;
- G transformers;
- topology diagnostics; and
- the MAC key derived from the master key using the domain `MAC_KEY_V1`. It is not independently provisioned.

For repeated encryption/decryption under one key, reuse a context instead of reconstructing it for every message. If a context is supplied, it must correspond to the same master key supplied separately; the current API does not verify this invariant.

## Message encryption

```rust
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    ctx: Option<&CipherContext>,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError>
```

Returns:

```text
nonce || ciphertext || HMAC-SHA-256 tag
```

Behavior:

1. validate or construct the context;
2. validate or generate a 12-byte nonce;
3. generate CTR keystream blocks from the raw KGRTC block transform;
4. XOR plaintext with the keystream;
5. authenticate `nonce || ciphertext`;
6. return the concatenated result.

When `nonce` is `None`, a fresh random nonce is generated. If a nonce is supplied explicitly, nonce uniqueness under the same key becomes the caller's responsibility.

## Message decryption

```rust
pub fn decrypt(
    blob: &[u8],
    key: &[u8],
    ctx: Option<&CipherContext>,
) -> Result<Vec<u8>, CipherError>
```

The function:

1. parses nonce, ciphertext, and tag;
2. derives/loads the message context;
3. recomputes HMAC-SHA-256 over `nonce || ciphertext`;
4. compares the tags using a constant-time byte comparison;
5. rejects the message if authentication fails;
6. otherwise applies the same CTR keystream construction.

## Raw block operations

```rust
pub fn encrypt_block(block: &[u8], ctx: &CipherContext) -> Vec<u8>
pub fn decrypt_block(block: &[u8], ctx: &CipherContext) -> Vec<u8>
```

These operate on one 16-byte block.

They are exposed primarily for research, testing, and analysis.

They do not provide nonce handling or authentication.

## Round transformation without round-key XOR

```rust
pub fn round_transform_no_key(
    block: &[u8],
    ctx: &CipherContext,
    round: usize,
) -> Vec<u8>
```

This applies a round's:

```text
S-box → permutation → reversible F/G coupling
```

but omits the round-key XOR.

This is useful for differential analysis because XORing a fixed round key does not change the XOR difference between two states.

## Generated transformers

```rust
pub struct GeneratedTransformer {
    pub depth: usize,
    pub heads: usize,
    pub connections: Connections,
    pub sboxes: Vec<Vec<u8>>,
}
```

A generated transformer is the key-derived nonlinear mixing network operating on an 8-byte state.

### Constructor

```rust
GeneratedTransformer::new_constrained(
    key,
    round_number,
    identifier,
    constraints,
)
```

returns:

```text
(GeneratedTransformer, TopologyDiagnostics)
```

The constructor fixes depth and head count for the derivation domain, then searches through deterministic candidate topologies until a candidate satisfies the configured structural constraints or the best candidate is selected after the attempt budget is exhausted.

## Topology configuration

```rust
pub struct TopologyConstraints {
    pub require_full_diffusion: bool,
    pub min_node_fanin: usize,
    pub max_usage_ratio: f64,
    pub max_attempts: u32,
}
```

Default values currently are:

```text
require_full_diffusion = true
min_node_fanin         = 4
max_usage_ratio        = 2.5
max_attempts            = 32
```

These are structural generation constraints. The generator tries candidates in deterministic order for at most `max_attempts` candidates and, if none passes, returns the best-scoring candidate encountered. Therefore these constraints are acceptance criteria when satisfied, not unconditional guarantees for every key.

## S-box functions

```rust
pub fn generate_sbox(
    key: &[u8],
    round_number: u32,
    identifier: &[u8],
) -> Vec<u8>

pub fn inverse_sbox(sbox: &[u8]) -> Vec<u8>
```

The generated S-box contains 256 mappings and is bijective when constructed by the current algorithm.

## Utility functions for research

The module also exposes lower-level functions including:

```rust
pub fn stream_bytes(seed: &[u8], n: usize) -> Vec<u8>
pub fn generate_permutation(seed: &[u8], size: usize) -> Vec<usize>
pub fn inverse_permutation(permutation: &[usize]) -> Vec<usize>
pub fn apply_permutation(data: &[u8], permutation: &[usize]) -> Vec<u8>
pub fn gf_mul(a: u8, b: u8) -> u8
pub fn reversible_coupling(...)
pub fn inverse_reversible_coupling(...)
pub fn generate_round_key(...)
pub fn transformer_function(...)
```

These are primarily useful for research and analysis.

## Errors

The public encryption/decryption API uses:

```rust
pub enum CipherError {
    InvalidKeyLength,
    InvalidNonceLength,
    MessageTooLong,
    CiphertextTooShort,
    AuthenticationFailed,
}
```

The exact error semantics are defined by the implementation in `src/cipher.rs`.

## Security note

The API is intentionally more detailed than a production crypto crate because this project is a research implementation. The public message wrapper is CTR + HMAC-SHA-256 encrypt-then-MAC, not a standardized AEAD primitive.

Do not interpret exposure of a raw block function, topology structure, or analysis helper as a recommendation to use those interfaces in production.

See [`../SECURITY.md`](../SECURITY.md).
