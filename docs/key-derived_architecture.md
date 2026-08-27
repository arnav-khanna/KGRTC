# Key-Derived Architecture

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); the equations and exact derivation procedure are authoritative only in the specification.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §5.2.

KGRTC uses a cipher architecture whose structural configuration is deterministically generated from the cryptographic key rather than being permanently fixed in the algorithm.

For each encryption key, KGRTC derives the architecture of its internal nonlinear mixing functions. The same key therefore produces the same architecture, while a different key generally produces a different architecture.

At the transformer level, the architecture is defined primarily by two key-derived shape parameters:

* **Depth:** the number of sequential nonlinear mixing layers.
* **Heads:** the number of parallel mixing heads operating within each layer.

For a given key, round number, and transformer identifier, KGRTC derives these parameters through the deterministic key-derivation procedure:

$$
(\text{depth},\text{heads})
=
\operatorname{DeriveShape}
(K,\text{round},\text{identifier})
$$

In the current implementation, the values are generated as:

$$
\text{depth} = 2 + \operatorname{KDF}(K,\text{round},\text{identifier},\text{"DEPTH"}) \bmod 3
$$

$$
\text{heads} = 2 + \operatorname{KDF}(K,\text{round},\text{identifier},\text{"HEADS"}) \bmod 3
$$

giving a depth and number of heads in the range **2–4**.

The architecture is therefore not selected at runtime through nondeterministic randomness. It is a deterministic function of the key, round, and transformer identifier. KGRTC uses SHAKE-256 as the underlying deterministic expansion mechanism, so identical inputs to the derivation procedure always produce identical architectural parameters.

For each round, separate identifiers are used for the two nonlinear mixing functions, **F** and **G**. Consequently, the key determines a complete sequence of round-specific transformer architectures rather than a single global transformer architecture.

Conceptually:

$$
K
\rightarrow
\begin{cases}
\text{Round 0 architecture}\\
\text{Round 1 architecture}\\
\vdots\\
\text{Round 13 architecture}
\end{cases}
$$

and, within each round,

$$
K,\;r,\;\text{F}
\rightarrow
(\text{depth}_F,\text{heads}_F)
$$

$$
K,\;r,\;\text{G}
\rightarrow
(\text{depth}_G,\text{heads}_G)
$$

The resulting architecture is generated **once when the key is initialized** and stored in the `CipherContext`. It is then reused for every block encrypted under that key. Thus, key-derived architecture does not require repeatedly reconstructing the network for every plaintext block.

An important distinction is that the architecture parameters determine the **shape of the computation**, while the detailed wiring connecting nodes is a separate key-derived component. In KGRTC, the depth and number of heads are derived first; the specific connections between the nodes are subsequently generated from the same key-derived domain. This separation allows the architecture-generation procedure to determine both the overall computational structure and, separately, the particular topology that occupies that structure.

The central architectural property is therefore:

$$
\boxed{\text{Architecture} = F(K,r,\text{identifier})}
$$

rather than

$$
\boxed{\text{Architecture} = \text{fixed global constant}}
$$

This means that the cryptographic key does not merely select secret numerical parameters inside a fixed cipher. It participates in determining the structure of the internal computation itself.

In KGRTC, this key-dependent architectural generation is intended to form the first layer of the broader construction:

$$
\boxed{
\text{Key}
\rightarrow
\text{Architecture}
\rightarrow
\text{Topology}
\rightarrow
\text{Weights}
\rightarrow
\text{Nonlinear transformations}
}
$$

The architecture is therefore the structural foundation upon which the remaining key-derived components are constructed.
