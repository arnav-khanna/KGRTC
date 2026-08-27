# Key-Derived Nonlinear Transformations

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); the exact S-box and nonlinear-layer algorithms are authoritative only in the specification.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §§4.2 and 5.2.

KGRTC uses nonlinear substitution functions whose construction is derived from the cryptographic key.

The core nonlinear primitive is a key-derived S-box defined as:

$$
S_K(x)=A_K(x^{-1})\oplus b_K
$$

where:

* $x^{-1}$ is the multiplicative inverse of $x$ in $GF(2^8)$, with $0^{-1}=0$,
* $A_K$ is a key-derived invertible linear transformation over $GF(2)^8$,
* $b_K$ is a key-derived constant byte.

The multiplicative inverse provides the nonlinear component, while the key-derived affine layer changes the resulting mapping for each key.

### Key-Derived Affine Transformation

For each round and nonlinear layer, KGRTC deterministically generates an $8\times8$ binary matrix:

$$
A_K\in GF(2)^{8\times8}
$$

and a constant byte:

$$
b_K\in GF(2)^8
$$

The matrix is generated from a SHAKE-256-based key derivation process using the key, round number, and domain identifier.

Candidate matrices are generated until an invertible matrix is obtained:

$$
\det(A_K)\neq0
$$

over $GF(2)$.

The retry counter is itself part of the deterministic derivation process. Therefore, the procedure does not rely on nondeterministic randomness:

$$
(K,r,\text{identifier})
\rightarrow
A_K,b_K
$$

always produces the same result.

### Nonlinear Construction

For every input byte $x$, KGRTC first computes its multiplicative inverse in $GF(2^8)$:

$$
x\rightarrow x^{-1}
$$

The inverse is then transformed by the key-derived binary linear map:

$$
x^{-1}
\rightarrow
A_K(x^{-1})
$$

and the key-derived constant is XORed into the result:

$$
S_K(x)
=
A_K(x^{-1})\oplus b_K
$$

The result is therefore a complete 256-entry permutation:

$$
S_K:\{0,\ldots,255\}\rightarrow\{0,\ldots,255\}
$$

with its inverse generated and stored for decryption.

### Differential-Uniformity Structure

Unlike an arbitrary key-generated permutation, KGRTC's construction preserves the known differential properties of the finite-field inversion function.

For a nonzero input difference $d$,

$$
S_K(x)\oplus S_K(x\oplus d)
=
A_K
\left(
x^{-1}\oplus(x\oplus d)^{-1}
\right)
$$

because the constant $b_K$ cancels.

Since $A_K$ is invertible, it is a bijective relabeling of output differences. Consequently, the affine transformation does not increase the maximum differential multiplicity of the underlying inversion function.

The resulting S-box therefore inherits the inversion function's differential-uniformity bound of **4**, rather than relying on a random search for an S-box with acceptable differential properties.

This is an important distinction from an unconstrained random permutation generator: the desired differential property follows from the algebraic construction itself.

### Nonlinear Mixing Inside the Generated Network

The key-derived S-boxes are also used inside each generated nonlinear mixing layer.

For a given output node, KGRTC first performs key-derived weighted mixing over $GF(2^8)$:

$$
a=
\bigoplus_i
w_i x_{s_i}
$$

where $s_i$ comes from the key-derived topology and $w_i$ comes from the key-derived weights.

The accumulated byte is then passed through the layer-specific key-derived S-box:

$$
y=S_K(a)
$$

Thus the complete node transformation is:

$$
\boxed{
\text{key-derived topology}
\rightarrow
\text{key-derived GF}(2^8)\text{ mixing}
\rightarrow
\text{key-derived nonlinear substitution}
}
$$

Each layer of a generated transformer has its own S-box, derived using the key together with the round, layer, transformer identifier, and the dedicated nonlinear-function domain.

### Key Dependence

The nonlinear transformation is therefore not a universal fixed S-box shared by every key.

Instead:

$$
K_1\neq K_2
\quad\Longrightarrow\quad
S_{K_1}\text{ generally differs from }S_{K_2}
$$

while:

$$
K,r,\text{identifier}
\rightarrow
\text{same S-box}
$$

for repeated construction under the same key and parameters.

This makes the nonlinear substitution function another component of the key-generated computation, alongside the architecture, topology, and weights.

The resulting hierarchy is:

$$
\boxed{
K
\rightarrow
\begin{cases}
\text{Architecture}\\
\text{Topology}\\
\text{Weights}\\
\text{Nonlinear transformations}
\end{cases}
}
$$

KGRTC therefore does not merely place a secret key into a fixed nonlinear cipher structure. The key determines the specific nonlinear mappings used by the generated computational network.
