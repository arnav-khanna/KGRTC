# KGRTC design notes

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); it records design rationale and separates mathematical guarantees from tests and empirical observations.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §7.

How the S-box and the F/G transformer topology are constructed, and exactly what's proven vs. merely observed about each. See [`DIFFERENTIAL_ANALYSIS.md`](DIFFERENTIAL_ANALYSIS.md) for the differential-propagation analysis (empirical and exact), and [`../SECURITY.md`](../SECURITY.md) plus [`../SPECIFICATION.md`](../SPECIFICATION.md) §7 for security status.

## S-box: inversion-based affine construction (DU = 4)

`generate_sbox` builds the S-box as:

$$
S_K(x)=A_K(x^{-1})\oplus b_K
$$

where:

- $x^{-1}$ is multiplicative inversion in the implementation's $GF(2^8)$ field, with $0^{-1}=0$;
- $A_K$ is a key-derived invertible linear map over $GF(2)^8$; and
- $b_K$ is a key-derived constant byte.

The matrix is generated deterministically and retried with an attempt counter until it is invertible. The retry is deterministic for a fixed key, round, and identifier.

### What is mathematically inherited

For a nonzero input difference $d$:

$$
S_K(x)\oplus S_K(x\oplus d)
=
A_K\left(x^{-1}\oplus(x\oplus d)^{-1}\right)
$$

because $b_K$ cancels. Since $A_K$ is invertible, it is a bijective relabeling of output differences. Therefore the differential multiplicities are the same as those of the underlying field-inversion map. Under the field arithmetic implemented here, the inversion map has differential uniformity 4, so every valid generated S-box has DU = 4.

The same affine-invariance argument supports the exact S-box metrics asserted by the current tests:

| metric | tested value |
|---|---:|
| bijectivity | true |
| differential uniformity | 4 |
| nonlinearity | 112 |
| linearity | 16 |
| algebraic degree | 7 |
| maximum autocorrelation | 32 |

These metrics are computed exhaustively over the 256-entry S-box domain for each S-box report. The test suite samples multiple generated S-boxes across keys and rounds; it does not need to enumerate all 256-bit keys because the construction supplies the invariance argument.

The analyzer can also compute fixed points, opposite fixed points, and cycle structure. Those quantities are not treated as constants of the construction and are not used as security guarantees.

### S-boxes inside F/G

Each generated transformer layer receives its own S-box. The layer-specific derivation uses the master key, the transformer identifier, and a layer-specific round-number value (`round_number * 100 + layer`) under the dedicated `NN_SBOX` domain.

Thus a transformer layer is a composition of key-derived source selection, key-derived GF(2^8) weighting, and a key-derived nonlinear substitution.

## F/G topology: key-derived and bounded-constraint-checked

The unconstrained constructor (`GeneratedTransformer::new`) accepts the first deterministic topology candidate. The constrained constructor (`new_constrained`) instead evaluates a bounded sequence of deterministic candidates and selects the first one satisfying the configured structural criteria.

The default configuration is:

```text
require_full_diffusion = true
min_node_fanin         = 4
max_usage_ratio        = 2.5
max_attempts            = 32
```

The topology generator evaluates attempts `0..31`. Attempts after zero incorporate the attempt index into their SHAKE-derived seeds, so every candidate is still deterministic from the master key and public derivation rules.

### Structural criteria

- **Full structural diffusion:** every final output dependency set contains every one of the eight original input positions.
- **No dead inputs:** every original input position is reachable by at least one final output.
- **Minimum distinct fan-in:** for every layer and output node, the union of source indices across heads has size at least 4.
- **Usage balance:** the maximum source-use count divided by the layer mean must not exceed 2.5.

These are structural properties. They do not establish differential probabilities, linear correlations, pseudorandomness, or security of the full 14-round cipher.

### Fallback behavior

If a candidate passes all configured criteria, generation stops immediately.

If all 32 candidates fail at least one criterion, the implementation still returns a topology: it retains the candidate with the highest score encountered. The score is:

$$
1000I_{\mathrm{diffusion}}
-200|\mathrm{dead\ inputs}|
+10F_{\min}
-R
$$

The fallback can therefore violate one or more configured constraints. The existence of the fallback is important: the default constraints are not unconditional guarantees over the entire 256-bit key space.

### What the current tests establish

`tests/topology.rs` generates 10 random keys and checks all 14 rounds and both F/G transformers. For the selected candidates it asserts:

- full structural diffusion; and
- no dead inputs.

The same test also checks deterministic topology reconstruction for repeated construction under one key. It does **not** exhaustively prove these properties for all possible keys, and it does not assert the default fan-in and usage-ratio thresholds directly.

The executable examples can provide broader empirical measurements, but those measurements are sample-dependent and should be reported with the exact command, sample count, build, and environment.

### What this does *not* cover

Full diffusion and balanced fan-in are structural sanity checks, not a
differential/linear security proof — they say the network *can*
propagate every input everywhere, not that it does so with provably
bounded differential/linear trail probabilities the way an MDS branch
number would guarantee for a linear layer. See the next section for a
first empirical pass at that question, and its own caveats.
