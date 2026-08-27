# Key-Derived Weights

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); the exact weight derivation and serialization are authoritative only in the specification.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §5.2.

KGRTC derives the numerical weights used by its nonlinear mixing network directly from the cryptographic key.

The weights are not stored as a fixed set of learned parameters and are not generated from external randomness. Instead, each weight is deterministically derived from the connection-specific key/round/domain seed, including the topology-attempt index for retry-generated candidates.

For each connection, the derivation can be represented as:

$$
w =
\operatorname{KDF}
(K,r,\text{transformer},l,h,o,s,a,\text{"WEIGHT"})
$$

where:

* $K$ is the cryptographic key,
* $r$ is the round,
* $l$ is the layer,
* $h$ is the head,
* $o$ is the output node,
* $s$ is the selected source byte,
* $a$ is the topology-attempt index (zero for the initial candidate).

The resulting value is interpreted as an element of $GF(2^8)$. KGRTC derives one byte using modulo-256 reduction and replaces zero with one, ensuring that every selected source contributes a nonzero multiplication coefficient. The implementation does not claim uniform coefficient sampling.

Thus each connection is represented by:

$$
(s_i,w_i)
$$

where $s_i$ identifies the source byte and $w_i$ is its key-derived coefficient.

For a node with three selected sources, the linear mixing portion is:

$$
y
=
w_1x_{s_1}
\oplus
w_2x_{s_2}
\oplus
w_3x_{s_3}
$$

where multiplication is performed in $GF(2^8)$ and $\oplus$ denotes XOR.

Multiple heads separately compute such contributions, and their per-node outputs are combined by XOR before the nonlinear transformation is applied.

### Key Binding

The weights are domain-separated from the other key-derived components. The implementation derives them using a dedicated `"WEIGHT"` domain together with the source index.

This means that the same source selected at different locations does not necessarily receive the same coefficient. The derived value depends on the complete position-specific seed.

Conceptually:

$$
(K,r,l,h,o,s,a)
\rightarrow
w
$$

Therefore:

$$
K_1 \neq K_2
\quad\Longrightarrow\quad
w_{K_1} \text{ generally differs from } w_{K_2}
$$

while the same key and the same connection coordinates always produce the same weight.

### Relationship to Topology

KGRTC separates **which bytes are connected** from **how strongly they contribute**.

The topology determines:

$$
s_1,s_2,s_3
$$

while the key-derived weight generation determines:

$$
w_1,w_2,w_3
$$

Together they define the complete connection:

$$
\boxed{
(s_i,w_i)
}
$$

Consequently, changing the key can alter both the wiring and the numerical transformation applied along that wiring.

This produces the following hierarchy:

$$
\text{Key}
\rightarrow
\begin{cases}
\text{Architecture}\\
\text{Topology}\\
\text{Weights}\\
\text{Nonlinear components}
\end{cases}
$$

### Role in the Mixing Function

The weights provide the linear diffusion component of each generated mixing layer.

For each active source:

$$
x_s
\xrightarrow{\times w}
w x_s
$$

and the resulting field elements are accumulated with XOR:

$$
a
=
\bigoplus_i w_i x_{s_i}
$$

The resulting accumulator is then passed through KGRTC's key-derived nonlinear transformation.

Thus, a simplified node can be viewed as:

$$
\boxed{
\text{source selection}
\rightarrow
\text{GF}(2^8)\text{ weighted mixing}
\rightarrow
\text{nonlinear transformation}
}
$$

The weights therefore connect the key-derived topology to the key-derived nonlinear layer, making the complete transformation dependent on both the structure of the graph and the numerical coefficients assigned to its edges.

### Determinism

Because the weights are generated through the deterministic SHAKE-256-based key derivation process, the complete weight set is reproducible from the key and the associated domain parameters:

$$
\boxed{
W_K =
\operatorname{GenerateWeights}(K,\text{round},\text{transformer},\ldots)
}
$$

The same key, derivation rules, topology attempt sequence, and connection coordinates reproduce the same architecture, selected topology, and weights when the context is reconstructed.

No stored model parameters are required to reproduce the generated network beyond the cryptographic key and the publicly defined generation procedure.
