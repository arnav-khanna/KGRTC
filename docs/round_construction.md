# Round Construction

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); the document explains the round at a conceptual level; exact ordering and byte-level behavior are authoritative only in the specification.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §5.1.

KGRTC is constructed as a sequence of **14 key-derived rounds**. Each round contains a complete set of separately derived transformation components:

$$
\boxed{
\text{S-box}
\rightarrow
\text{state permutation}
\rightarrow
\text{reversible F/G coupling}
\rightarrow
\text{round-key XOR}
}
$$

The round is therefore not a single fixed primitive. It is a composition of several domain-separated transformations all derived from the same master key.

For round $r$, the transformation can be written as:

$$
X_{r+1}
=
\operatorname{XOR}
\left(
C_r(P_r(S_r(X_r))),
K_r
\right)
$$

where:

* $S_r$ is the round's key-derived S-box,
* $P_r$ is the round's key-derived byte permutation,
* $C_r$ is the reversible coupling constructed from the round's F and G transformers,
* $K_r$ is the round-specific key material.

### 1. Key-Derived S-box

The input state first undergoes byte-wise substitution:

$$
Y_i=S_r(X_i)
$$

The S-box is separately derived for each round from the master key and the round identifier.

This provides nonlinear substitution before the state is mixed across positions.

### 2. Key-Derived State Permutation

The substituted state is then permuted:

$$
Z=P_r(Y)
$$

The permutation is generated deterministically from:

$$
(K,\text{"STATE\_PERM"},r)
$$

so every round has its own key-derived byte ordering.

The permutation does not change individual byte values. Its purpose is to change which state positions enter the subsequent mixing functions.

### 3. Reversible F/G Coupling

The 16-byte state is divided into two 8-byte halves:

$$
Z=(A,B)
$$

The first generated nonlinear transformer $F_r$ operates on $A$:

$$
F_A=F_r(A)
$$

The result is XORed into the second half:

$$
B'=B\oplus F_A
$$

The second generated nonlinear transformer $G_r$ then operates on the modified second half:

$$
G_B=G_r(B')
$$

which is XORed into the first half:

$$
A'=A\oplus G_B
$$

The output of the coupling is:

$$
C_r(Z)=(A',B')
$$

or equivalently:

$$
\boxed{
(A,B)
\rightarrow
(A,\;B\oplus F_r(A))
\rightarrow
(A\oplus G_r(B'),\;B')
}
$$

This is a two-stage Feistel-style construction.

### Reversibility

The important property of the F/G coupling is that **F and G themselves do not need to be invertible**.

Decryption reverses the coupling in the opposite order.

Starting from:

$$
(A',B')
$$

the decryptor first computes:

$$
G_r(B')
$$

and recovers:

$$
A=A'\oplus G_r(B')
$$

It then computes:

$$
F_r(A)
$$

and recovers:

$$
B=B'\oplus F_r(A)
$$

Therefore:

$$
\boxed{
(A',B')
\rightarrow
(A,B)
}
$$

without requiring either $F_r$ or $G_r$ to possess an independent inverse.

This construction allows KGRTC to use complex, potentially non-invertible key-generated nonlinear transformations internally while retaining an exactly invertible overall round.

### 4. Round-Key Addition

After the reversible coupling, the resulting 16-byte state is XORed with the round-specific key:

$$
X_{r+1}=C_r(Z)\oplus K_r
$$

where:

$$
K_r=
\operatorname{KDF}(K,\text{"ROUND\_KEY"},r)
$$

produces a fresh 16-byte round key for each round.

The round-key XOR is itself reversible because:

$$
(X\oplus K_r)\oplus K_r=X
$$

Thus its inverse operation is identical to encryption:

$$
X=(X'\oplus K_r)
$$

### Complete Round

Combining the components gives the complete encryption round:

$$
\boxed{
X_r
\xrightarrow{S_r}
Y_r
\xrightarrow{P_r}
Z_r
\xrightarrow{F_r,G_r}
C_r
\xrightarrow{\oplus K_r}
X_{r+1}
}
$$

More explicitly:

$$
X_r
\rightarrow
S_r(X_r)
\rightarrow
P_r(S_r(X_r))
$$

$$
\rightarrow
\left(
A\oplus G_r(B\oplus F_r(A)),
\;
B\oplus F_r(A)
\right)
$$

$$
\rightarrow
\oplus K_r
$$

The same round components are generated once when the `CipherContext` is constructed and then reused for every block encrypted under that key.

### Decryption Order

Because each component is reversible, decryption applies the round operations in reverse order:

$$
\boxed{
X_{r+1}
\xrightarrow{\oplus K_r}
C_r
\xrightarrow{C_r^{-1}}
Z_r
\xrightarrow{P_r^{-1}}
Y_r
\xrightarrow{S_r^{-1}}
X_r
}
$$

The complete block decryption therefore processes the 14 rounds in reverse:

$$
r=13,12,\ldots,0
$$

This yields exact round-trip reconstruction:

$$
\boxed{
D_K(E_K(X))=X
}
$$

### Architectural Role

Each round combines four distinct mechanisms:

| Component               | Primary role                                        |
| ----------------------- | --------------------------------------------------- |
| Key-derived S-box       | Nonlinear byte substitution                         |
| Key-derived permutation | Reorders state positions                            |
| F/G coupling            | Cross-half diffusion while preserving reversibility |
| Round-key XOR           | Injects round-specific key material derived from the master key |

The resulting design separates **nonlinearity**, **position mixing**, **reversible coupling**, and **key injection** while making each round's internal parameters dependent on the master key.

At the full-cipher level:

$$
\boxed{
E_K
=
R_{13}\circ R_{12}\circ\cdots\circ R_1\circ R_0
}
$$

where each:

$$
R_r
=
\operatorname{XOR}_{K_r}
\circ
C_r
\circ
P_r
\circ
S_r
$$

is separately derived from the same master key and its round identifier.
