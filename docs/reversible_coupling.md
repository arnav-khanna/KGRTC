# Reversible Coupling

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); the document focuses on the mathematical intuition and inverse; the normative algorithm is in the specification.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §5.1.

KGRTC uses a reversible coupling construction to combine two separately derived nonlinear functions, $F$ and $G$, while preserving exact invertibility of the complete transformation.

The important property is that **$F$ and $G$ themselves do not need to be invertible**. They may be arbitrary key-derived nonlinear transformations. Reversibility is obtained from the way their outputs are coupled with the two halves of the state.

For a 16-byte state:

$$
X=(A,B)
$$

where:

$$
A,B\in\{0,1\}^{64}
$$

each half contains 8 bytes.

The coupling proceeds in two stages.

## Forward Coupling

First, the first half is processed by the key-derived transformer $F$:

$$
F_A=F(A)
$$

The result is XORed into the second half:

$$
B'=B\oplus F(A)
$$

The updated second half is then processed by the second key-derived transformer $G$:

$$
G_B=G(B')
$$

Finally, this result is XORed into the original first half:

$$
A'=A\oplus G(B')
$$

The complete transformation is therefore:

$$
\boxed{
(A,B)
\rightarrow
(A,\;B\oplus F(A))
\rightarrow
(A\oplus G(B'),\;B')
}
$$

and the final coupled state is:

$$
C(A,B)=(A',B').
$$

Equivalently,

$$
\boxed{
A'=A\oplus G(B\oplus F(A))
}
$$

$$
\boxed{
B'=B\oplus F(A)
}
$$

## Why the Construction Is Reversible

The construction is reversible because each XOR operation can be undone when the required unchanged half is available.

Starting with the output:

$$
(A',B')
$$

the decryptor first reverses the $G$ stage.

Because $B'$ is already available unchanged:

$$
G(B')
$$

can be recomputed.

The original $A$ is then recovered:

$$
\boxed{
A=A'\oplus G(B')
}
$$

Once $A$ has been recovered, the original $B$ can be reconstructed by evaluating $F$:

$$
F(A)
$$

and undoing the first XOR:

$$
\boxed{
B=B'\oplus F(A)
}
$$

Thus:

$$
\boxed{
(A',B')
\rightarrow
(A,B)
}
$$

with no requirement that either $F$ or $G$ possess an inverse.

This gives KGRTC the useful property:

$$
\boxed{
F,G\text{ may be non-invertible}
\quad\text{while}\quad
C\text{ remains invertible}
}
$$

## Explicit Inverse

The inverse coupling is:

$$
\boxed{
A=A'\oplus G(B')
}
$$

followed by:

$$
\boxed{
B=B'\oplus F(A)
}
$$

so:

$$
C^{-1}(A',B')
=
\left(
A'\oplus G(B'),
\;
B'\oplus F(A'\oplus G(B'))
\right).
$$

The order is important: $G$ must be reversed first, because recovering $A$ provides the input required to evaluate $F$.

## Relationship to the Generated Transformers

In KGRTC, $F$ and $G$ are the two separately derived nonlinear mixing functions associated with a particular round:

$$
F_r=\operatorname{GeneratedTransformer}
(K,r,\text{"TRANSFORMER\_F"})
$$

$$
G_r=\operatorname{GeneratedTransformer}
(K,r,\text{"TRANSFORMER\_G"})
$$

Each transformer has its own key-derived:

$$
\{\text{depth},\text{heads},\text{topology},\text{weights},\text{S-boxes}\}.
$$

The coupling therefore connects two separately derived computational structures rather than using one shared nonlinear function twice.

The round-level construction is:

$$
(A,B)
\overset{F_r}{\longrightarrow}
(A,B')
\overset{G_r}{\longrightarrow}
(A',B')
$$

where:

$$
B'=B\oplus F_r(A)
$$

and:

$$
A'=A\oplus G_r(B').
$$

## Why Non-Invertible Internal Functions Are Possible

A generated transformer in KGRTC performs several nonlinear operations and does not need to be bijective as an 8-byte-to-8-byte function.

For example:

$$
F:\{0,1\}^{64}\rightarrow\{0,1\}^{64}
$$

may map multiple inputs to the same output.

Normally, placing such a function directly into an encryption pipeline would make exact decryption impossible.

The reversible coupling avoids this requirement by retaining one half of the state unchanged at each stage.

The first stage:

$$
(A,B)\rightarrow(A,B\oplus F(A))
$$

is reversible because $A$ is preserved.

The second stage:

$$
(A,B')\rightarrow(A\oplus G(B'),B')
$$

is reversible because $B'$ is preserved.

Consequently, their composition is reversible even when:

$$
F^{-1}
$$

and

$$
G^{-1}
$$

do not exist.

## Structural Form

The construction can be viewed as two reversible XOR-coupling layers:

$$
\boxed{
L_F(A,B)=(A,\;B\oplus F(A))
}
$$

$$
\boxed{
L_G(A,B)=(A\oplus G(B),\;B)
}
$$

and:

$$
\boxed{
C=L_G\circ L_F
}
$$

Their inverses are obtained by applying the same operations in reverse order:

$$
\boxed{
C^{-1}=L_F^{-1}\circ L_G^{-1}
}
$$

with:

$$
L_G^{-1}=L_G
$$

and:

$$
L_F^{-1}=L_F
$$

because XORing the same value twice cancels:

$$
x\oplus y\oplus y=x.
$$

Thus the coupling is self-inverting at the individual XOR-update level, even though $F$ and $G$ themselves are not.

## Role in KGRTC

The reversible coupling provides the bridge between the key-generated nonlinear networks and the cipher's requirement for exact round-trip reconstruction.

It provides three properties simultaneously:

| Property                 | Mechanism                                                   |
| ------------------------ | ----------------------------------------------------------- |
| Nonlinear transformation | Key-derived $F$ and $G$                                 |
| Cross-half diffusion     | Each transformer's output is XORed into the opposite half   |
| Exact reversibility      | One state half is retained unchanged at each coupling stage |

The resulting structure is:

$$
\boxed{
\text{Key-derived }F_r
+
\text{Key-derived }G_r
\rightarrow
\text{reversible round transformation}
}
$$

This is the mechanism that allows KGRTC to use dynamically generated, potentially non-invertible nonlinear computation while maintaining:

$$
\boxed{
D_K(E_K(X))=X
}
$$

at the block-transformation level.
