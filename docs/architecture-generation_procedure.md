# Architecture-Generation Procedure

> **Document status — explanatory documentation**
>
> This document is a human-readable walkthrough of how the key-derived
> context is assembled. It is **not normative**. The exact algorithms,
> encodings, derivation domains, retry rules, topology acceptance rules,
> and fallback behavior are defined in [`../SPECIFICATION.md`](../SPECIFICATION.md),
> especially Section 5.2.

## Purpose

KGRTC turns one 256-bit master key into a complete, deterministic cipher
context. The context contains the round-specific components needed by the
14-round block transformation.

The important distinction is:

- the **specification** defines exactly how every byte is generated;
- this document explains the dependency structure so the reader can see
  how the pieces fit together.

## Complete dependency flow

```text
                         256-bit master key K
                                  │
                 ┌────────────────┼────────────────┐
                 │                │                │
                 ▼                ▼                ▼
             Round data      S-box data       Round-key data
                 │
                 ▼
        ┌───────────────────────┐
        │ For each round r      │
        │   r = 0 ... 13        │
        └───────────┬───────────┘
                    │
             ┌──────┴──────┐
             ▼             ▼
        Transformer F   Transformer G
             │             │
             ▼             ▼
      depth / heads   depth / heads
             │             │
             ▼             ▼
          topology       topology
             │             │
             ▼             ▼
           weights       weights
             │             │
             ▼             ▼
        layer S-boxes  layer S-boxes
             └──────┬──────┘
                    ▼
             cached CipherContext
```

## 1. Domain separation

The same master key feeds many different derivation domains. Round numbers,
transformer identifiers, layer identifiers, and other labels distinguish
one derived component from another.

Conceptually:

```text
K + round + identifier + component label
                     │
                     ▼
                 SHAKE-256
                     │
                     ▼
             deterministic bytes
```

The exact concatenation and integer encoding are normative in the
specification.

## 2. Transformer shape

Each round has two generated nonlinear transformers, **F** and **G**.

For each transformer, the key determines:

```text
depth  ∈ {2, 3, 4}
heads  ∈ {2, 3, 4}
```

The shape is determined before the topology candidates are evaluated.
Topology retries do not change the already-derived shape.

## 3. Candidate topology

Once the shape is known, the generator constructs a candidate connection
graph for every layer, head, and output node.

At a conceptual level:

```text
layer
  │
  ├── head 0 ──► output node
  ├── head 1 ──► output node
  ├── ...
  └── head h-1 ─► output node

each head selects exactly three distinct source positions
```

The selected source positions determine **which bytes contribute** to a
node. The key-derived weights determine **how those bytes contribute**.

## 4. Structural screening

A candidate topology is evaluated against the public KGRTC-256 structural
constraints.

The checks include:

```text
full structural diffusion
no dead inputs
minimum distinct fan-in
bounded source-usage imbalance
```

These checks describe graph reachability and source usage. They do **not**
prove differential security, linear security, pseudorandomness, or
full-cipher security.

## 5. Deterministic retries and fallback

Candidates are generated in a deterministic sequence.

```text
attempt 0
   │
   ├── passes? ── yes ──► select
   │
   ▼ no
attempt 1
   │
  ...
   │
attempt 31
   │
   ├── passing candidate exists ──► first passing candidate
   │
   └── none passes ──────────────► best-scoring candidate
```

The fallback is important: the topology constraints are acceptance criteria,
not an unconditional guarantee over every possible 256-bit key.

The exact score and selection rules are defined in the specification.

## 6. Layer nonlinearities

After the transformer topology has been selected, each transformer layer
has its own key-derived S-box.

Thus a transformer is more than a graph:

```text
Transformer
├── depth
├── heads
├── selected topology
├── key-derived weights
└── one key-derived S-box per layer
```

## 7. Per-key context

The complete process is repeated for both F and G in every round.

```text
K
│
├── Round 0: F0 + G0 + S0 + Perm0 + RoundKey0
├── Round 1: F1 + G1 + S1 + Perm1 + RoundKey1
├── ...
└── Round 13: F13 + G13 + S13 + Perm13 + RoundKey13
                    │
                    ▼
             CipherContext
```

The resulting structures are cached when the context is initialized. The
implementation therefore does not regenerate the internal architecture for
every plaintext block.

## 8. What this means conceptually

The central idea can be summarized as:

```text
                 fixed public algorithm
                         +
                  secret master key
                         │
                         ▼
              deterministic generation
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   architecture       topology          weights
        │                │                │
        └────────────────┼────────────────┘
                         ▼
                 nonlinear layers
                         │
                         ▼
                round-specific cipher
```

For the exact interoperable definition, always defer to
[`../SPECIFICATION.md`](../SPECIFICATION.md).
