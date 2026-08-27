```
                                KGRTC 2.0

                       Normative Specification

              Key-Generated Reversible Transformer Cipher (KGRTC)

            Category: Computer Security   Subcategory: Cryptography
```

Reference Implementation Project

This publication is available free of charge from the project repository
accompanying the reference implementation (`kgrtc`, v0.2.0).

Version 2.0 — this document

> **Document status — normative specification**
>
> This document is the canonical, normative specification of **KGRTC-256**.
> It defines the interoperable algorithms, parameters, serialization rules,
> generation procedures, authenticated-encryption construction, and
> conformance requirements for Version 2.0.
>
> The documents under `docs/` are explanatory, analytical, security, or
> implementation documentation. They are not independent definitions of the
> KGRTC-256 algorithm. If an explanatory document conflicts with this
> specification, this specification takes precedence.
>
> See [Appendix E — Independent Implementation Conformance Profile](#appendix-e--independent-implementation-conformance-profile)
> for the normative interoperability-testing procedure.


## Abstract

KGRTC (Key-Generated Reversible Transformer Cipher) is a 128-bit-block,
256-bit-key, 14-round iterated block cipher. This specification defines
one member of the KGRTC family: **KGRTC-256**, the only parameter set
this document standardizes (see Section 2.3 and Section 6.3 regarding
possible future parameter sets). Unlike a cipher such as AES, where the
S-box, diffusion layer, and key schedule are fixed public constants
applied identically for every key, KGRTC instead *generates* almost
every structural component of the cipher — substitution boxes,
byte-permutations, internal nonlinear mixing networks ("Transformers"),
and round keys — freshly from the master key using a single underlying
key-derivation primitive (SHAKE-256). Two different keys therefore
produce two structurally different ciphers, not merely two different
round-key schedules applied to one fixed cipher.

**Keywords:** KGRTC; block cipher; key-generated architecture; CTR mode;
HMAC-SHA-256; experimental cipher; not for production use.

## Key-Generated Reversible Transformer Cipher (KGRTC)


1. **Name.** Key-Generated Reversible Transformer Cipher
   (KGRTC), version 2.0. 
2. **Category.** Computer Security, Cryptography (informal
   categorization; see Foreword).
3. **Explanation.** KGRTC specifies an experimental symmetric block
   cipher, used only inside a CTR-mode-plus-HMAC-SHA-256
   authenticated-encryption construction (Section 5, Section 6.5). It
   uses one cryptographic key length: 256 bits.
4. **Applicability.** This specification may be used by anyone wishing
   to reimplement or study KGRTC. **It must not be used, by anyone, to
   protect information of real value** — see Section 7.
5. **Specifications.** This document (Sections 1–7 and Appendices A–D).
6. **Implementations.** KGRTC may be implemented in software, firmware,
   hardware, or any combination. No validation program (analogous to
   NIST's CMVP) exists for KGRTC. An implementation should be checked
   against Appendix C before being trusted to match this specification.
7. **Inquiries and Comments.** Direct inquiries to the maintainers of
    the reference implementation repository.

---

## Table of Contents

```
1  Introduction
2  Definitions
   2.1  Terms and Acronyms 
   2.2  List of Functions                                           
   2.3  Algorithm Parameters and Symbols                            
   2.4  Interoperability and Conformance Profile                     
3  Notation and Conventions                                        
   3.1  Inputs and Outputs                                          
   3.2  Bytes                                                       
   3.3  Indexing of Byte Sequences                                 
   3.4  The State                                                  
   3.5  Arrays of Words and Half-States                             
   3.6  Canonical Byte and Integer Serialization                    
4  Mathematical Preliminaries                                       
   4.1  Addition in GF(2^8)                                         
   4.2  Multiplication in GF(2^8)                                   
   4.3  Linear Maps over GF(2)^8 and Weighted Sums over GF(2^8)     
   4.4  Multiplicative Inverses in GF(2^8)                         
   4.5  Exact Interpretation of Symbolic Operations                 
5  Algorithm Specifications                                       
   5.1  CIPHER()                                                  
        5.1.1  SUBBYTES()                                         
        5.1.2  PERMUTEBYTES()                                     
        5.1.3  COUPLE()                                           
        5.1.4  ADDROUNDKEY()                                      
   5.2  GENERATECONTEXT()                                         
   5.3  INVCIPHER()                                                
        5.3.1  INVPERMUTEBYTES()                                  
        5.3.2  INVSUBBYTES()                                       
        5.3.3  INVCOUPLE()                                        
        5.3.4  Inverse of ADDROUNDKEY()                            
   5.4  Modes and Authentication: CTRTRANSFORM(), AEENCRYPT(),
        AEDECRYPT()                                                 
   5.4.4  Canonical Message Wire Format                              
6  Implementation Considerations                                  
   6.1  Key Length Requirements                                    
   6.2  Keying Restrictions                                        
   6.3  Parameter Extensions                                       
   6.4  Implementation Suggestions Regarding Various Platforms      
   6.5  Modes of Operation                                          
7  Security Status                                                  
References                                                          
Appendix A — Architecture Generation Examples                       
Appendix B — Cipher Example                                        
Appendix C — Example Vectors                            
Appendix D — Independent Implementation Conformance Profile            
```

---

## 1. Introduction

A block is a sequence of bits of a given fixed length. A block cipher is
a family of permutations of blocks that is parameterized by a sequence
of bits called the key.

KGRTC specifies one instantiation, **KGRTC-256**, with a 128-bit block
and a 256-bit key. Unlike Rijndael/AES — where a single fixed S-box,
fixed diffusion matrix, and key-driven-but-structurally-fixed key
schedule are shared by every key — KGRTC generates its S-boxes,
byte-permutations, internal nonlinear mixing networks, and round keys
anew for every master key, from one underlying key-derivation function
(SHAKE-256, Section 4 and Section 5.2). The cipher is designed to be
used only inside the CTR-mode-with-HMAC-SHA-256 construction of Section
5.4; the raw 14-round block transformation of Section 5.1 is a normative
block primitive. The reference implementation may expose raw block operations
for research, testing, and conformance, but the sanctioned message-level
construction for caller data is the CTR-mode-plus-HMAC-SHA-256 construction of Section 5.4.

This document is organized as follows:

- Section 2 defines the terms, acronyms, algorithm parameters, symbols,
  and functions used in this specification.
- Section 3 describes the notation and conventions for the ordering and
  indexing of bits, bytes, and words/half-states.
- Section 4 explains the mathematical components of the KGRTC
  specification: GF(2⁸) finite-field arithmetic (identical to AES's)
  and the GF(2)⁸ linear algebra and GF(2⁸)-weighted sums used
  elsewhere.
- Section 5 specifies KGRTC-256: the Cipher, the per-key architecture
  generation routine that replaces a conventional key schedule, the
  Inverse Cipher, and the CTR-mode/authentication constructions built on
  top of them.
- Section 6 provides implementation guidance on key length, keying
  restrictions, parameter extensions, and platform implementation
  considerations.
- Section 7 states plainly what is and is not established about KGRTC's
  security, and must be read before any deployment decision.
- Appendix A gives worked examples of the architecture-generation
  routines (the KGRTC analog of FIPS 197's key-expansion examples).
- Appendix B gives a full round-by-round example of one invocation of
  the Cipher.
- Appendix C gives authenticated-encryption example vectors.
- Appendix D sumarises the independent implementation conformance profile

---

## 2. Definitions

### 2.1 Terms and Acronyms

The following definitions are used in this specification:

| Term | Definition |
|---|---|
| **AEAD** | Authenticated Encryption with Associated Data; here realized as CTR-mode encryption plus a domain-separated HMAC-SHA-256 tag derived from the master key, with no associated-data input in this version. |
| **Affine transformation** | A transformation consisting of multiplication by a matrix, followed by the addition of a vector (constant). |
| **Array** | A fixed-size data structure that stores a collection of elements, where each element is identified by its integer index or indices. |
| **Bit** | A binary digit: 0 or 1. |
| **Block** | A sequence of bits of a given fixed length. In this specification, blocks consist of 128 bits, represented as arrays of bytes. |
| **Block cipher** | A family of permutations of blocks that is parameterized by the key. |
| **Byte** | A sequence of eight bits. |
| **Cipher Context** | The complete set of key-derived structures (S-boxes, permutations, Transformers, round keys, MAC key) generated once per master key and reused for every block; the KGRTC analog of a "key schedule," but covering the entire generated architecture, not only round keys. |
| **Couple / Coupling** | The reversible, Feistel-style mixing step (Section 5.1.3) that combines the two halves of the state using a round's Transformer pair. |
| **Half-state** | An 8-byte half of the 16-byte State, operated on inside COUPLE(ange). |
| **KDF** | Key-derivation function; here, SHAKE-256 used as an extendable-output function (XOF). |
| **KGRTC** | Key-Generated Reversible Transformer Cipher. |
| **Round** | A sequence of transformations of the state that is iterated `r` = 14 times in the specification of CIPHER() and INVCIPHER(). Unlike AES, every round in KGRTC has the identical sequence of four transformations — there is no round in which a step is omitted. |
| **Round key** | One of the 14 16-byte values derived from the master key using GENERATECONTEXT(); each round key is an input to one instance of ADDROUNDKEY(). |
| **S-box** | A non-linear, key-dependent substitution table used in SUBBYTES() to perform a one-to-one substitution of a byte value; unlike AES, a distinct S-box is generated per round (and, separately, per Transformer layer) from the master key. |
| **State** | Intermediate result of the KGRTC block cipher, represented as a one-dimensional array of 16 bytes (see Section 3.4; KGRTC does not use AES's 4×4 two-dimensional state array). |
| **Topology** | The wiring (choice of source half-state bytes and GF(2⁸) weights) of a Transformer's internal connections. |
| **Transformer** | The key-generated nonlinear mixing sub-circuit ("F" or "G") used inside COUPLE(); a stack of layers, each with several "heads," operating on an 8-byte half-state. Named for historical reasons in the reference implementation; **it is unrelated to, and shares no structure with, attention-based neural-network Transformers.** |
| **XOF** | Extendable-output function: a hash function producing an arbitrarily long, deterministic pseudorandom output for a given input. |

### 2.2 List of Functions

The following functions are specified in this document:

| Function | Description |
|---|---|
| `ADDROUNDKEY()` | The transformation of the state in which a round key is combined with the state. |
| `KGRTC-256()` | The block cipher specified in this document with a 256-bit key; equal to `CIPHER(in, GENERATECONTEXT(key))`. |
| `CIPHER()` | The transformation of blocks that underlies KGRTC-256; the Cipher Context is a parameter of the transformation. |
| `INVCIPHER()` | The inverse of `CIPHER()`. |
| `INVSUBBYTES()` | The inverse of `SUBBYTES()`. |
| `INVPERMUTEBYTES()` | The inverse of `PERMUTEBYTES()`. |
| `INVCOUPLE()` | The inverse of `COUPLE()`. |
| `INVSBOX()` | The inverse of a given round's `SBOX()`. |
| `GENERATECONTEXT()` | The routine that generates every key-derived structure (S-boxes, permutations, Transformers, round keys, MAC key) from the master key; the KGRTC analog of `KEYEXPANSION()`. |
| `GENERATESBOX()` | The routine that generates one 256-entry S-box from the master key, a round/layer number, and a purpose identifier. |
| `GENERATEPERMUTATION()` | The routine that generates one key-derived permutation of a given size. |
| `GENERATETRANSFORMER()` | The routine that generates one Transformer (F or G) — its shape, wiring, and per-layer S-boxes — for a given round. |
| `PERMUTEBYTES()` | The transformation of the state in which bytes are reordered according to a key-derived permutation. |
| `COUPLE()` | The transformation of the state that splits it into two halves and reversibly mixes them using a round's Transformer pair. |
| `SBOX()` | The transformation of bytes defined by a given round's (or layer's) S-box. |
| `SUBBYTES()` | The transformation of the state that applies a round's S-box independently to each byte of the state. |
| `TRANSFORM()` | The evaluation of one Transformer on an 8-byte half-state (Section 5.1.3). |
| `XTIMES()` | The transformation of bytes in which the polynomial representation of the input byte is multiplied by `x`, modulo m(x), to produce the polynomial representation of the output byte. Identical in definition to AES's `XTIMES()` (Section 4.2). |
| `CTRTRANSFORM()` | The counter-mode keystream generation and XOR transformation (Section 5.4). |
| `AEENCRYPT()` / `AEDECRYPT()` | The authenticated-encryption wrapper functions (Section 5.4). |



### 2.3 Algorithm Parameters and Symbols

| Symbol | Meaning |
|---|---|
| AK | A key-derived, invertible linear map on GF(2)⁸, used in the construction of a round's S-box. |
| bK | A key-derived constant byte, used in the construction of a round's S-box. |
| b⁻¹ | The multiplicative inverse of the element `b` in GF(2⁸). |
| GF(2) | Finite field with two elements. |
| GF(2⁸) | Finite field with 256 elements. |
| `h` | The half-block size, in bytes: h=8. |
| `in` | The data input to `CIPHER()` or `INVCIPHER()`, represented as an array of 16 bytes indexed from 0 to 15. |
| `k` | The key length, in bits: k=256 (this document's only parameter set). |
| `key` | The 32-byte (256-bit) master key. |
| m(x) | The modulus specified for the polynomial representation of bytes as elements of GF(2⁸): m(x)=x⁸+x⁴+x³+x+1. Identical to the AES modulus. |
| `n` | The block length, in bits: n=128. |
| `Nb` | The number of bytes comprising the state: Nb=16 (KGRTC's state is a flat 16-byte array, not a 4-column array of words as in AES; see Section 3.4). |
| `out` | The data output of `CIPHER()` or `INVCIPHER()`, represented as an array of 16 bytes indexed from 0 to 15. |
| `r` | The number of rounds: r=14 (this document's only parameter set). |
| `state` | The state, represented as a one-dimensional array of 16 bytes, indexed from 0 to 15. |
| S[ρ], Sinv[ρ] | The forward and inverse S-boxes for round `ρ`. |
| Perm[ρ], InvPerm[ρ] | The forward and inverse 16-byte permutations for round `ρ`. |
| F[ρ], G[ρ] | The two Transformers for round `ρ`. |
| RoundKey[ρ] | The 16-byte round key for round `ρ`, 0 ≤ ρ < r. |
| mackey | The 32-byte HMAC-SHA-256 key used for authentication (Section 5.4), domain-separated and derived from `key` using the `MAC_KEY_V1` derivation domain. |
| Nn | The nonce size for CTR mode, in bytes: `N_n = 12`. |
| Nc | The counter field size for CTR mode, in bytes: `N_c = 4`. |
| Nt | The authentication tag size, in bytes: `N_t = 32`. |
| ⊕ | Either the exclusive-OR operation on bits, or the bitwise exclusive-OR operation on bytes/blocks. |
| • | Multiplication in GF(2⁸). |
| ∥ | Concatenation of byte strings or byte arrays. |
| `∗` | Integer multiplication. |
| ← | Assignment of a variable in pseudocode. |
| `{}` | Delimiters for a byte in hexadecimal or binary notation (used identically to FIPS 197's convention, e.g. `{a3}`). |

---

## 3. Notation and Conventions


### 2.4 Interoperability and Conformance Profile

This section is **normative** for the KGRTC-256 parameter set. An implementation that
intends to interoperate with another KGRTC-256 implementation **must** use the
values and conventions stated here.

KGRTC-256 treats all keys, nonces, plaintexts, ciphertexts, seeds, and intermediate
byte strings as **ordered sequences of bytes**. Unless a field is explicitly
defined as an integer, no byte string is interpreted as a multi-byte integer.

The standard KGRTC-256 profile fixes all of the following:

| Item | Required value |
|---|---|
| Master-key length | 32 bytes |
| Block/state length | 16 bytes |
| Half-state length | 8 bytes |
| Number of rounds | 14 |
| Transformer depth | derived independently as 2, 3, or 4 |
| Transformer heads | derived independently as 2, 3, or 4 |
| Sources per node per head | exactly 3 |
| Weight size | 1 byte per selected source |
| Topology `require_full_diffusion` | `true` |
| Topology `min_node_fanin` | 4 |
| Topology `max_usage_ratio` | 2.5 |
| Topology maxattempts | 32 |
| Nonce length | 12 bytes |
| Counter length | 4 bytes |
| Authentication tag length | 32 bytes |
| KDF/XOF | SHAKE-256 |
| KDF input customization | none; the complete seed byte string is absorbed directly |
| KDF output interpretation | first `L` bytes of the SHAKE-256 XOF output |
| Integer encoding | unsigned, big-endian, at the field width explicitly specified below |

A conforming implementation **must not** substitute a different hash/XOF,
endianness, string encoding, label spelling, separator, counter encoding,
permutation procedure, field representation, S-box generation rule, topology
selection rule, or message serialization.

Custom `TopologyConstraints` are an implementation extension and are **not part of
the interoperable KGRTC-256 profile**. Two implementations using different
constraint values are implementing different parameterizations and may produce
different key-derived architectures and ciphertexts even when the master key,
nonce, and plaintext are identical.
### 3.1 Inputs and Outputs

A bit is a binary digit — 0 or 1. A block is a sequence of 128 bits; the
data input and output for `CIPHER()`/`INVCIPHER()` are blocks. The
master key is a 256-bit sequence, typically established beforehand and
maintained across many invocations of the block cipher.

### 3.2 Bytes

The basic processing unit in KGRTC, as in AES, is the byte — a sequence
of eight bits. A byte value is denoted by the concatenation of the
eight bits between braces, e.g. `{10100011}`, or in hexadecimal, e.g.
`{a3}`. The hexadecimal representation of 4-bit sequences follows the
identical table given in FIPS 197 Table 1 and is not reproduced here.

### 3.3 Indexing of Byte Sequences

Given a sequence of `8k` bits r₀ r₁ r₂ … r₈k₋₃ r₈k₋₂
r₈k₋₁` (for some positive integer `k`), the bytes `a_j` for `0 ≤ j ≤
k-1` are defined as aj = {r₈j r₈j₊₁ … r₈j₊₇}. This is
identical to the FIPS 197 convention (Section 3.3 of that document). In
particular, a 16-byte data block `in` is represented as the byte
sequence `in_0, in_1, ..., in_15`, with in₀ comprising the first
eight bits of the block and in₁5 the last eight.

### 3.4 The State

KGRTC's internal working value, the **state**, is represented as a
one-dimensional array of 16 bytes, indexed `state[0], ..., state[15]`,
in contrast to AES's two-dimensional 4-row-by-4-column array. This is a
deliberate simplification: KGRTC has no row/column-oriented
transformation analogous to AES's `SHIFTROWS()`/`MIXCOLUMNS()` pair —
its byte reordering (`PERMUTEBYTES()`, Section 5.1.2) is an arbitrary
key-derived permutation of all 16 positions at once, not a per-row
cyclic shift, so no two-dimensional structure is needed.

The first step in `CIPHER()`/`INVCIPHER()` (Section 5.1/5.3) is to copy
the input array of bytes `in_0, in_1, ..., in_15` directly into the
state array:

```
state[i] = in[i]     for 0 ≤ i < 16.
```

After the sequence of transformations in Section 5.1 (or 5.3) is
applied, the final state is copied to the output array identically:

```
out[i] = state[i]     for 0 ≤ i < 16.
```



### 3.5 Arrays of Words and Half-States

Where AES groups its 16-byte state into four 4-byte "words" (one per
column), KGRTC instead splits its 16-byte state into exactly **two**
8-byte **half-states**, denoted `A` and `B`, used only inside
`COUPLE()`/`INVCOUPLE()` (Section 5.1.3/5.3.3):

```
A = state[0..7],   B = state[8..15].
```

Within a Transformer (Section 5.1.3), an 8-byte half-state is itself
treated as an array of 8 individually-addressable bytes, indexed `0`
through `7`; there is no further word-grouping. Given a one-dimensional
byte or word array `u`, this document uses `u[i]` for the element
indexed by `i` and `u[i..j]` for the inclusive sub-sequence
`u[i], u[i+1], ..., u[j]`, exactly as in FIPS 197 Section 3.5.

---

## 4. Mathematical Preliminaries

For the `SUBBYTES()` and Transformer transformations specified in
Section 5, each byte is interpreted as one of the 256 elements of the
finite field GF(2⁸), exactly as in AES. Each byte `{b_7 b_6 b_5 b_4 b_3
b_2 b_1 b_0}` is interpreted as a polynomial

```
b(x) = b_7 x^7 + b_6 x^6 + b_5 x^5 + b_4 x^4 + b_3 x^3 + b_2 x^2 + b_1 x + b_0.
```


### 3.6 Canonical byte and integer serialization

The following serialization rules are **normative**.

1. A byte is an unsigned integer in the range `[0,255]` and is represented
   internally as exactly eight bits. No signed-byte interpretation is permitted.

2. A byte sequence is ordered from index 0 upward. Concatenation X ∥ Y means
   append all bytes of `Y` after all bytes of `X`; it never means numeric
   addition, XOR, or integer concatenation.

3. `be16(v)` means the two-byte representation:
   `[(v >> 8) & 0xff, v & 0xff]`.

4. `be32(v)` means the four-byte representation:
   `[(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]`.

5. `be64(v)` means the eight-byte representation:
   `[(v >> 56) & 0xff, ..., v & 0xff]`, in descending significance order.
   This is the representation used whenever a SHAKE output segment is decoded
   as the candidate `u64` in the permutation and integer-derivation routines.

6. ASCII labels are encoded as their literal 7-bit ASCII bytes, with no leading
   length field, trailing NUL byte, separator, whitespace, or Unicode normalization.

7. A master key is an opaque 32-byte sequence. It is **never** converted to an
   integer before derivation. Therefore there is no key endianness.

8. A nonce is an opaque 12-byte sequence. It is **never** converted to an integer;
   only the 4-byte counter field appended to it is an integer.

9. Plaintext and ciphertext are arbitrary byte sequences. Any text encoding
   (for example UTF-8) is an external application-level convention and is not
   part of KGRTC.

10. Hexadecimal and Base64 are presentation encodings only. When exchanging raw
    KGRTC data, the underlying byte values and ordering above are authoritative.
### 4.1 Addition in GF(2⁸)

Addition of two elements of GF(2⁸) is performed by adding the
coefficients of their polynomial representations modulo 2 — i.e., with
the exclusive-OR operation, ⊕. Equivalently, two bytes are added by
XOR-ing each pair of corresponding bits. This is byte-for-byte identical
to AES's Section 4.1, and KGRTC uses no other definition of addition on
GF(2⁸) elements anywhere in this specification.

### 4.2 Multiplication in GF(2⁸)

The symbol • denotes multiplication in GF(2⁸). As in AES, this
multiplication is defined by (1) multiplying the two polynomials that
represent the two bytes, and (2) reducing the result modulo the fixed
polynomial

```
m(x) = x^8 + x^4 + x^3 + x + 1.
```

This is the *identical* reduction polynomial used by AES (hex `0x11B`);
KGRTC introduces no new field or reduction polynomial. As in AES, the
special case of multiplication by `x` (i.e., by `{02}`) is denoted
`XTIMES(b)` and computed as:

```
XTIMES(b) = { b6 b5 b4 b3 b2 b1 b0 0                     if b7 = 0
            { b6 b5 b4 b3 b2 b1 b0 0  ⊕  {00011011}      if b7 = 1
```

and multiplication by any other field element is computed via the
standard repeated-`XTIMES()`-and-XOR method (identical to AES Section
4.2), which this specification packages as the single routine
`gf_mul(a, b)`:

> **Algorithm 4.1 — `gf_mul(a, b)`**
> ```
> Input:  bytes a, b
> Output: byte  result = a • b  in GF(2⁸)
>
> result ← 0
> for i = 0 to 7:
>     if (b & 1) ≠ 0:
>         result ← result ⊕ a
>     hi ← a & 0x80
>     a  ← (a << 1) mod 256
>     if hi ≠ 0:
>         a ← a ⊕ 0x1B
>     b ← b >> 1
> return result
> ```

This computes the same function, over the same field, as the
`XTIMES()`-based procedure of FIPS 197 Section 4.2, restated as a single
self-contained loop rather than a table of precomputed `{02}, {04}, ...,
{80}` multiples, since KGRTC has no analog of AES's fixed `MIXCOLUMNS()`
matrix (Section 4.3 explains what replaces it).

### 4.3 Linear Maps over GF(2)⁸ and Weighted Sums over GF(2⁸)

Unlike AES, KGRTC has **no fixed diffusion matrix** analogous to
`MIXCOLUMNS()`'s `[{02},{01},{01},{03}]`. Diffusion in KGRTC instead
comes from two different key-derived mechanisms, specified here as the
KGRTC analog of FIPS 197 Section 4.3 ("Multiplication of Words by a
Fixed Matrix"):

**(a) An 8×8 linear map over GF(2), used in each round's S-box
construction (Section 5.1.1).** A matrix over GF(2) — i.e. a linear map
on 8-bit vectors under XOR, *not* a GF(2⁸) field operation — is
represented as 8 rows, each packed into one byte: bit `i` of row byte
`rows[j]` is the matrix entry at row `j`, column `i`.

> **Algorithm 4.2 — `matrix_vec_mul_gf2(rows, y)`**
> ```
> Input:  rows[0..7]  (8 packed rows, each one byte)
>         y            (an 8-bit input vector, as a byte)
> Output: byte result = rows · y   (matrix-vector product over GF(2))
>
> result ← 0
> for i = 0 to 7:
>     parity ← popcount(rows[i] AND y) mod 2
>     result ← result | (parity << i)
> return result
> ```

> **Algorithm 4.3 — `is_invertible_gf2(rows)`**
> ```
> Input:  rows[0..7]
> Output: boolean — true iff the 8×8 GF(2) matrix `rows` has full rank 8
>
> m ← copy of rows
> rank ← 0
> for bit = 7 downto 0:
>     mask ← 1 << bit
>     find the smallest row index p ≥ rank with (m[p] AND mask) ≠ 0
>     if none exists: continue to next bit
>     swap m[rank] and m[p]
>     for every row r ≠ rank with (m[r] AND mask) ≠ 0:
>         m[r] ← m[r] ⊕ m[rank]
>     rank ← rank + 1
> return (rank = 8)
> ```

This is ordinary Gaussian elimination over GF(2), most-significant-bit
first; a matrix is invertible iff elimination achieves full rank 8.

**(b) Key-derived GF(2⁸)-weighted sums of 3 selected bytes, used inside
each Transformer node (Section 5.1.3).** Where AES's `MIXCOLUMNS()`
always multiplies a fixed word `[{02},{01},{01},{03}]` against all four
bytes of every column, a Transformer node computes

```
acc = w_1 • state[s_1]  ⊕  w_2 • state[s_2]  ⊕  w_3 • state[s_3]
```

where the three source indices `s_1, s_2, s_3` and three weight bytes
`w_1, w_2, w_3` are *themselves* key-derived per node (Section 5.2,
Algorithm 5.4) rather than fixed constants shared by every key — using
the same gfmul of Algorithm 4.1 for each multiplication `w_i •
state[s_i]`.



### 4.4 Multiplicative Inverses in GF(2⁸)

For a byte b ≠ {00}, its multiplicative inverse is the unique byte,
denoted b⁻¹, such that b • b⁻¹ = {01}. As in AES, {00}⁻¹
is defined by convention to be `{00}`. This value can be computed as
b⁻¹ = b²⁵⁴, or via the extended Euclidean algorithm applied to
`b(x)` and m(x), identically to FIPS 197 Section 4.4. KGRTC precomputes
this as a single, key-independent 256-entry table:

> **Algorithm 4.4 — `gf256_inverse_table()`**
> ```
> Output: table inv[0..255], where inv[0] = {00} and, for a ≠ 0,
>         inv[a] is the unique b with a • b = {01}
>
> inv[0] ← 0
> for a = 1 to 255:
>     for b = 1 to 255:
>         if gf_mul(a, b) = 1:
>             inv[a] ← b
>             break
> return inv
> ```

This table is identical, entry-for-entry, to the multiplicative-inverse
table AES's own S-box is built from — it is a fixed mathematical
constant of the field, **not** a key-derived value, and an
implementation may precompute it once, globally, rather than once per
key. (An implementation is free to use a faster closed-form
Itoh–Tsujii-style method instead of the O(256^2) search above; both
produce the identical table.)

---

## 5. Algorithm Specifications

The function for the block cipher specified in this document is denoted
`KGRTC-256()`; its inverse is denoted `INVKGRTC-256()`.[^1] Both are
built from two lower-level functions, `CIPHER()` and `INVCIPHER()`,
which take a **Cipher Context** — the KGRTC analog of a fully-expanded
key schedule — as a parameter, in place of AES's word array `w`.

The Cipher Context is generated from the master key by
`GENERATECONTEXT()` (Section 5.2), the KGRTC analog of
`KEYEXPANSION()`. Unlike `KEYEXPANSION()`, which only produces round
keys, `GENERATECONTEXT()` produces *every* key-dependent structure the
cipher uses: per-round S-boxes, per-round byte-permutations, per-round
Transformer pairs, per-round round keys, and the independent MAC key
used for authentication (Section 5.4).

There is exactly one parameter set in this document (Table 3 is the
KGRTC analog of FIPS 197's Table 3, "Key-Block-Round Combinations," but
has only one row because this specification, unlike FIPS 197, does not
define multiple key lengths):

**Table 3. Key-Block-Round Parameters**

| | Key length `k` (bits) | Block size `n` (bits) | Number of rounds `r` |
|---|---|---|---|
| KGRTC-256 | 256 | 128 | 14 |

Thus,

```
KGRTC-256(in, key) = CIPHER(in, GENERATECONTEXT(key)).
```

The inverse permutation is defined by replacing `CIPHER()` with
`INVCIPHER()` in the equation above.

The specifications of `CIPHER()`, `GENERATECONTEXT()`, and
`INVCIPHER()` are given in Sections 5.1, 5.2, and 5.3, respectively;
Section 5.4 specifies the CTR-mode and authenticated-encryption
constructions built on top of them, which is how a caller of the
reference implementation actually invokes the cipher.

[^1]: As in FIPS 197, these functions are sometimes informally called
"encryption" and "decryption," but neutral terminology is used here
because block ciphers have applications beyond direct encryption (e.g.
as the keystream generator inside CTR mode, Section 5.4).


### 4.5 Exact interpretation of symbolic operations

The mathematical symbols used in this document have one implementation-independent
meaning:

- ⊕ means bitwise XOR on byte values and is computed independently on all 8 bits.
- • means multiplication in GF(2⁸) under the modulus specified in Section 4.2.
- ∥ means byte-string concatenation.
- `A_K(x)` means the eight-row packed GF(2) matrix-vector multiplication of
  Algorithm 4.2.
- `inv[x]` means the value at index `x` in the fixed 256-entry multiplicative
  inverse table of Algorithm 4.4.
- Array indexing is zero-based.
- Ranges in pseudocode written `a..b` with an explicit loop bound are half-open
  unless the algorithm separately states otherwise.
- Any comparison involving `max_usage_ratio` is a comparison of the mathematical
  rational value `max_count / mean_usage`, not a rounded decimal representation.
### 5.1 CIPHER()

The rounds in the specification of `CIPHER()` are composed of the
following four byte-oriented transformations of the state:

- `SUBBYTES()` applies that round's key-derived S-box to each byte.
- `PERMUTEBYTES()` reorders all 16 bytes of the state according to that
  round's key-derived permutation.
- `COUPLE()` splits the state into two 8-byte halves and reversibly
  mixes them using that round's key-derived Transformer pair.
- `ADDROUNDKEY()` combines that round's round key with the state.

These four transformations are specified in Sections 5.1.1–5.1.4. As in
FIPS 197, a transformed byte or block is denoted by appending a prime
(`'`) to the original variable, e.g. `state'`.

`CIPHER()` is specified in the pseudocode of Algorithm 5.1.

> **Algorithm 5.1 — Pseudocode for `CIPHER()`**
> ```
>  1: procedure CIPHER(in, context)
>  2:     state ← in                                        ▷ See Sec. 3.4
>  3:     for round from 0 to r−1 do
>  4:         state ← SUBBYTES(state, context.S[round])       ▷ See Sec. 5.1.1
>  5:         state ← PERMUTEBYTES(state, context.Perm[round]) ▷ See Sec. 5.1.2
>  6:         state ← COUPLE(state, context.F[round], context.G[round]) ▷ See Sec. 5.1.3
>  7:         state ← ADDROUNDKEY(state, context.RoundKey[round]) ▷ See Sec. 5.1.4
>  8:     end for
>  9:     return state                                        ▷ See Sec. 3.4
> 10: end procedure
> ```

Line 2 copies the input into the state array using the convention of
Section 3.4. The state is then transformed by exactly r=14
applications of the round function (Lines 3–8), each an identical
sequence of the four transformations above. **Unlike AES, no round
differs from any other in which steps it applies** — there is no
"final round" that omits `COUPLE()` or any other step. The final state
is returned as the output (Line 9), as described in Section 3.4.

#### 5.1.1 SUBBYTES()

`SUBBYTES()` is an invertible, non-linear transformation of the state in
which a substitution table — an S-box — is applied independently to
each byte of the state. Where AES uses a single fixed table `SBOX()`
shared by every key, KGRTC generates a **distinct S-box per round**,
`S[round]`, from the master key; `SBOX()` below denotes this key-derived
table for whichever round is active.

Let `b` denote an input byte to `SBOX()`. Unlike AES — where the
"intermediate value" `b̃` is simply `b`'s multiplicative inverse — KGRTC's
`SBOX()` composes the multiplicative inverse with a **key-derived**
affine transformation, rather than the fixed AES affine constant matrix
and constant byte `{01100011}`:

1. Define the intermediate value `b̃` exactly as in AES:
   ```
   b̃ = { {00}     if b = {00}
        { b^{-1}   if b ≠ {00}    (Section 4.4)
   ```
2. Apply a **key-derived**, invertible affine transformation to the bits
   of `b̃` to produce the bits of `b'`:
   ```
   b' = A_K(b̃) ⊕ b_K
   ```
   where AK is an invertible linear map over GF(2)⁸ (Section 4.3(a))
   and bK is a constant byte — both derived from the master key, the
   round number, and a purpose identifier, per Algorithm 5.2 below —
   **in place of** AES's fixed matrix and fixed constant `{01100011}`.

The full construction, combining both steps, is:

```
S_K(x) = A_K( inv[x] ) ⊕ b_K       for all x in {0, ..., 255}
```

> **Algorithm 5.2 — `derive_affine_gf2(key, round_number, identifier)`**
> ```
> Input:  key (32 bytes), round_number (u32), identifier (ASCII string)
> Output: (rows[0..7], b) — an invertible GF(2)⁸ matrix and constant byte
>
> base_seed ← key ∥ identifier ∥ be32(round_number) ∥ "AFFINE"
> attempt ← 0
> loop:
>     seed ← base_seed ∥ "TRY" ∥ be32(attempt)
>     rows ← stream_bytes(seed, 8)                (Algorithm 5.3 below)
>     if is_invertible_gf2(rows):                  (Algorithm 4.3)
>         b_seed ← base_seed ∥ "CONST"
>         b ← stream_bytes(b_seed, 1)[0]
>         return (rows, b)
>     attempt ← attempt + 1
> ```

> **Algorithm 5.3 — `generate_sbox(key, round_number, identifier)`**
> ```
> Input:  key, round_number, identifier      (as in Algorithm 5.2)
> Output: S[0..255]     (a byte-permutation table; this round's SBOX())
>
> (rows, b) ← derive_affine_gf2(key, round_number, identifier)
> for x = 0 to 255:
>     S[x] ← matrix_vec_mul_gf2(rows, inv[x]) ⊕ b        (Algorithm 4.2, 4.4)
> return S
> ```

**Property 5.1 (differential uniformity).** For any invertible AK and
any bK, SK(x) ⊕ SK(x⊕d) = AK(inv[x] ⊕ inv[x⊕d]) for every
difference `d`. Because AK is linear and bijective, it can only
*relabel* the differential distribution table (DDT) of the bare
inversion map — never merge two distinct output differences — so the
DDT's maximum entry count (differential uniformity) is unchanged at 4,
the same value AES's own S-box has, for **every** key-derived
`(A_K, b_K)` pair, by proof rather than by search. The same
relabeling argument fixes nonlinearity (112), linearity/maximum LAT bias
(16), algebraic degree (7), and autocorrelation (32) at their AES
values for every key. Fixed points, opposite fixed points, and cycle
structure are **not** affine-invariant and vary key to key.

**Instantiation.** The per-round cipher S-box is
`S[ρ] = generate_sbox(key, ρ, "SBOX")` for `ρ = 0, ..., 13`. (A
second, independent family of S-boxes, used only inside Transformers,
is specified in Section 5.2.4.)

`SUBBYTES()` applies `S[round]` byte-wise:

```
state'[i] = S[round][ state[i] ]    for 0 ≤ i < 16.
```

The AES-style illustration of `SUBBYTES()` (FIPS 197 Fig. 2, an S-box
lookup applied independently to each byte of the state) applies to
KGRTC's `SUBBYTES()` identically, substituting the key-derived
`S[round]` for AES's fixed table.

#### 5.1.2 PERMUTEBYTES()

`PERMUTEBYTES()` is a transformation of the state in which **all 16**
bytes are reordered according to a key-derived permutation — in place
of AES's `SHIFTROWS()`, which only cyclically shifts the last three rows
of a 4×4 array by fixed, key-independent offsets. Because KGRTC's state
is a flat 16-byte array (Section 3.4), not a 4×4 array, `PERMUTEBYTES()`
has no rows to distinguish; every one of the 16! possible permutations
of the 16 positions is a candidate, and which one is used is entirely
determined by the master key and round number.

> **Algorithm 5.4 — `generate_permutation(seed, size)`**
> ```
> Input:  seed, size
> Output: perm[0..size-1], a permutation of {0, ..., size-1}
>
> perm ← [0, 1, ..., size-1]
> data ← stream_bytes(seed ∥ "PERMUTATION", size × 8)
> pos ← 0
> for i = size-1 downto 1:
>     value ← big-endian u64 decoded from data[pos..pos+8); pos ← pos+8
>     j ← value mod (i + 1)
>     swap(perm[i], perm[j])
> return perm
> ```

This is the standard Fisher–Yates shuffle, driven by the SHAKE-256
output stream (streambytes, Algorithm 5.7) in place of a random number
generator.

**Per-round instantiation:**

```
Perm[ρ] = generate_permutation(key ∥ "STATE_PERM" ∥ be32(ρ), 16)
```

for `ρ = 0, ..., 13`. `PERMUTEBYTES()` is then:

```
state'[i] = state[ Perm[round][i] ]    for 0 ≤ i < 16,
```

i.e. the byte written to output position `i` is read from **source**
position `Perm[round][i]`.

#### 5.1.3 COUPLE()

`COUPLE()` is the transformation of the state that mixes information
between its two 8-byte halves — the KGRTC analog of `MIXCOLUMNS()`, but
structured as a 2-stage unbalanced Feistel network rather than a
fixed-matrix multiplication, because KGRTC has no fixed diffusion
matrix (Section 4.3).

**The Transformer.** Each round has two independently domain-separated key-derived **Transformers**,
`F[round]` and `G[round]`, each a small circuit of `depth` layers (`depth
∈ {2,3,4}`) with `heads` independent "heads" per layer (`heads ∈
{2,3,4}`), operating on 8-byte half-states. `depth` and `heads` are
themselves key-derived (Algorithm 5.5) but fixed once generated — they
are not re-derived per block.

> **Algorithm 5.5 — `derive_shape(base_seed)`**
> ```
> Input:  base_seed = key ∥ identifier ∥ be32(round_number)
> Output: (depth, heads)
>
> depth ← derive_int(base_seed, "DEPTH", 3) + 2      (Algorithm 5.6; depth ∈ {2,3,4})
> heads ← derive_int(base_seed, "HEADS", 3) + 2       (heads ∈ {2,3,4})
> return (depth, heads)
> ```

> **Algorithm 5.6 — `derive_int(seed, label, maximum)`**
> ```
> Input:  seed, label, maximum
> Output: an integer in [0, maximum)
>
> data  ← stream_bytes(seed ∥ label, 8)
> value ← big-endian u64 decoded from data
> return value mod maximum
> ```

**Per-node wiring.** For every `(layer, head, output_node)` triple, with
outputnode ∈ {0, ..., 7}, exactly 3 source byte-indices and 3
GF(2⁸) weight bytes are derived (see Algorithm 5.8, Section 5.2, for
the full generation and topology-acceptance procedure — this includes a
key-derived candidate-generate-and-check search that guarantees full
structural diffusion, a minimum per-layer fan-in, and bounded
source-usage imbalance for every accepted Transformer). Evaluating a
Transformer on an 8-byte half-state is:

> **Algorithm 5.9 — `TRANSFORM(data, transformer)`**
> ```
> Input:  data[0..7], transformer = (depth, heads, connections, sboxes)
> Output: out[0..7]
>
> state ← copy of data
> for layer = 0 to depth-1:
>     new_state[0..7] ← all zero
>     for head = 0 to heads-1:
>         head_output[0..7] ← all zero
>         for output_node = 0 to 7:
>             (sources, weights) ← connections[layer][head][output_node]
>             acc ← 0
>             for i = 0 to 2:
>                 acc ← acc ⊕ gf_mul(state[sources[i]], weights[i])   (Algorithm 4.1)
>             head_output[output_node] ← sboxes[layer][acc]
>         for i = 0 to 7:
>             new_state[i] ← new_state[i] ⊕ head_output[i]
>     state ← new_state
> return state
> ```

`TRANSFORM()` need not itself be a bijection on 8 bytes; invertibility of
`COUPLE()` as a whole comes structurally from the Feistel arrangement
below, regardless of whether `TRANSFORM()` is invertible.

**The coupling itself.** Given the 16-byte state split into halves `A =
state[0..7]` and `B = state[8..15]` (Section 3.5):

> **Algorithm 5.10 — `COUPLE(state, F, G)`**
> ```
> Input:  state[0..15], F, G     (this round's Transformer pair)
> Output: state'[0..15]
>
> A ← state[0..7];  B ← state[8..15]
> F_A ← TRANSFORM(A, F)
> B'  ← B ⊕ F_A
> G_B ← TRANSFORM(B', G)
> A'  ← A ⊕ G_B
> return A' ∥ B'
> ```

**Property 5.2 (exact invertibility).** For any `F`, `G` (bijective or
not) and any 16-byte state, `INVCOUPLE(COUPLE(state, F, G), F, G) =
state` (Section 5.3.3 defines `INVCOUPLE()`). This holds by the standard
2-round Feistel argument: `B'` is already known as the second half of
`COUPLE()`'s output, so `TRANSFORM(B', G)` is immediately computable,
recovering `A`; `TRANSFORM(A, F)` is then computable, recovering `B` —
no matrix inversion or bijectivity requirement on `F`/`G` is needed,
exactly as in DES-style Feistel networks.


`maximum` must be a positive integer. KGRTC-256 uses only `maximum = 3` for
`DEPTH` and `HEADS`, `maximum = 256` for individual byte weights, and the
permutation routine uses its own `mod (i + 1)` rule.

#### 5.1.4 ADDROUNDKEY()

`ADDROUNDKEY()` is a transformation of the state in which a round key is
combined with the state by applying the bitwise XOR operation to all 16
bytes at once — simpler than AES's column-oriented version (FIPS 197
Eq. 5.9) only because KGRTC's state has no column structure to respect
(Section 3.4):

```
state'[i] = state[i] ⊕ RoundKey[round][i]    for 0 ≤ i < 16.
```

Round keys are generated in Section 5.2.3.

### 5.2 GENERATECONTEXT()

`GENERATECONTEXT()` is the routine applied to the master key to generate
every key-dependent structure `CIPHER()`/`INVCIPHER()` use: the Cipher
Context. This is the KGRTC analog of `KEYEXPANSION()`, but where
`KEYEXPANSION()` produces only round keys, `GENERATECONTEXT()`
additionally produces the S-boxes, permutations, and Transformer pairs
`KEYEXPANSION()` has no analog for, because in AES those structures are
fixed public constants, not generated per key.

`GENERATECONTEXT()` invokes one underlying primitive, SHAKE-256, used as
an extendable-output function (XOF), for every one of these
derivations — there is no separate cascade of round-constant XORs as in
AES's `KEYEXPANSION()` (Section 5.2 of FIPS 197); domain separation
(Section 5.2.1) plays the role AES's `Rcon[]` round constants play.

#### 5.2.1 The underlying XOF and domain separation

> **Algorithm 5.7 — `stream_bytes(seed, L)`**
> ```
> Input:  seed  (byte string), L (number of output bytes requested)
> Output: the first L bytes of SHAKE-256(seed)'s output stream
>
> instantiate a SHAKE-256 XOF state
> absorb(seed) into the XOF
> return the first L bytes squeezed from the XOF
> ```

Every derivation below constructs its `seed` by concatenating the
master key, one or more ASCII label literals identifying the purpose of
the draw (analogous to AES's `Rcon[]` acting as a per-round
differentiator, but with an explicit string rather than a single word),
and big-endian integer indices identifying which instance this is
(round, layer, head, node, source, attempt). The labels used in this
specification are: `SBOX`, STATEPERM, ROUNDKEY, TRANSFORMERF,
TRANSFORMERG, `PERMUTATION`, `AFFINE`, `CONST`, `TRY`, `DEPTH`,
`HEADS`, `HEAD`, `NODE`, `WEIGHT`, `W`, TOPOATTEMPT, NNSBOX, and
`MAC_KEY_V1`. **Conformance requires reproducing every label exactly
(case-sensitive ASCII, no delimiter) and every integer at the specified
byte width, in the specified order** — any difference produces an
unrelated key schedule for the same master key.

#### 5.2.2 Per-round S-boxes and permutations

For each round `ρ = 0, ..., 13`:

```
S[ρ]        ← generate_sbox(key, ρ, "SBOX")                            (Algorithm 5.3)
Sinv[ρ]     ← inverse_sbox(S[ρ])                                        (Algorithm 5.11, Sec. 5.3.2)
Perm[ρ]     ← generate_permutation(key ∥ "STATE_PERM" ∥ be32(ρ), 16)     (Algorithm 5.4)
InvPerm[ρ]  ← inverse_permutation(Perm[ρ])                               (Sec. 5.3.1)
```

#### 5.2.3 Round-key derivation

> **Algorithm 5.12 — `generate_round_key(key, round_number)`**
> ```
> Input:  key, round_number
> Output: RoundKey (16 bytes)
>
> seed ← key ∥ "ROUND_KEY" ∥ be32(round_number)
> return stream_bytes(seed, 16)
> ```

`RoundKey[ρ] = generate_round_key(key, ρ)` for `ρ = 0, ..., 13`. Each
round key is an **independent** SHAKE-256 draw — there is no linear or
additive relationship between RoundKey[ρ] and `RoundKey[ρ']` for `ρ ≠
ρ'`, unlike AES's recursively-defined key schedule (FIPS 197 Section
5.2, Eq. preceding Algorithm 2).

#### 5.2.4 Transformer generation

The KGRTC-256 standard profile uses only the default topology constraints in Table 5.1. Implementations may expose custom constraints as research extensions, but those extensions are outside the KGRTC-256 interoperability profile and must not be used when generating ciphertext intended for another conforming implementation.

For each round `ρ`, and for each `identifier ∈ {"TRANSFORMER_F",
"TRANSFORMER_G"}`:

> **Algorithm 5.8 — `GENERATETRANSFORMER(key, round_number, identifier, constraints)`**
> ```
> Input:  key, round_number, identifier, constraints (Table 5.1 below)
> Output: (transformer, diagnostics)
>
> base_seed ← key ∥ identifier ∥ be32(round_number)
> (depth, heads) ← derive_shape(base_seed)                              (Algorithm 5.5)
>
> best ← none
> for attempt = 0 to constraints.max_attempts − 1:
>     connections ← generate_connections(base_seed, depth, heads, attempt)   (a)
>     diag ← evaluate_topology(attempt, depth, heads, connections)           (b)
>     if best = none OR score(diag) > score(best.diag):
>         best ← (connections, diag)
>     if passes(diag, constraints):
>         break
>
> (connections, diagnostics) ← best
> for layer = 0 to depth-1:
>     sboxes[layer] ← generate_sbox(key, round_number*100 + layer, identifier ∥ "NN_SBOX")
>                                                                              (Algorithm 5.3)
> transformer ← { depth, heads, connections, sboxes }
> return (transformer, diagnostics)
> ```
>
> **(a) `generate_connections(base_seed, depth, heads, attempt)`:**
> ```
> for layer = 0 to depth-1:
>   for head = 0 to heads-1:
>     head_seed ← base_seed ∥ "HEAD" ∥ be16(layer) ∥ be16(head)
>     if attempt > 0: head_seed ← head_seed ∥ "TOPO_ATTEMPT" ∥ be32(attempt)
>     for output_node = 0 to 7:
>         node_seed ← head_seed ∥ "NODE" ∥ be16(output_node)
>         perm ← generate_permutation(node_seed, 8)                        (Algorithm 5.4)
>         sources ← perm[0], perm[1], perm[2]
>         for source in sources:
>             weight_seed ← node_seed ∥ "WEIGHT" ∥ be16(source)
>             w ← derive_int(weight_seed, "W", 256); if w = 0: w ← 1        (Algorithm 5.6)
>             append w to weights
>         connections[layer][head][output_node] ← (sources, weights)
> return connections
> ```
>
> **(b) `evaluate_topology(attempt, depth, heads, connections)`** computes,
> for the candidate wiring: fulldiffusion (every output byte
> structurally depends on every input byte after `depth` layers),
> deadinputs (input bytes reachable by no output), `min_node_fanin`
> (the smallest, over every layer and output node, count of distinct
> sources feeding that node summed across heads), and `max_usage_ratio`
> (the worst per-layer ratio of an input's usage count to the per-layer
> mean usage count). `passes()` requires fulldiffusion true,
> deadinputs empty, minnodefanin ≥ 4, and maxusageratio ≤ 2.5
> by default (Table 5.1); `score()` is used only to select a fallback
> candidate when no attempt passes within maxattempts.


##### Exact topology-evaluation procedure

For every candidate topology, an implementation shall compute the diagnostics in
Section 5.2.4 using the following exact procedure.

Initialize one dependency set for each of the eight input positions:

Di⁽⁰⁾={i},     i∈{0,…,7}.

For each layer `ℓ` from `0` through `depth-1`:

1. Initialize eight empty output dependency sets
   `new_dep[0..7]`.
2. Initialize eight empty per-output source-union sets
   `node_union[0..7]`.
3. Initialize eight integer `usage_counts[0..7]` to zero.
4. For each head and each output node, inspect the three source indices
   associated with that node.
5. For every source index `s`:
   - increment `usage_counts[s]` by exactly one;
   - insert `s` into `node_union[output_node]`;
   - union the **entire current dependency set** `D_s^(ℓ)` into
     `new_dep[output_node]`.
6. Set the layer's `min_node_fanin` candidate to the minimum cardinality of
   the eight nodeunion sets.
7. Let

T = ∑i₌₀⁷ ui

   Let `mean_usage = T / 8`. If `T > 0`, let the layer usage ratio be
   `c_max / mean_usage`, where cmax is the largest value in usagecounts;
   otherwise it is zero.
8. Update the overall `max_usage_ratio` to the maximum layer ratio.
9. Replace the dependency state with newdep and continue to the next layer.

After the final layer:

- fulldiffusion is true iff every final dependency set has cardinality 8.
- `reachable` is the union of all eight final dependency sets.
- deadinputs is the ascending list of every input index in `0..7` that is
  not in `reachable`.
- `min_node_fanin` is the minimum over **all layers and all output nodes**.
- `max_usage_ratio` is the maximum ratio over **all layers**.

No weights are used when computing dependency sets or topology diagnostics.
The diagnostics are structural and therefore depend only on the candidate source
connections.

A source occurring twice in two different heads is counted twice in
usagecounts, but a source occurring in multiple heads for the same output node
appears only once in that node's nodeunion. This distinction is normative.

**Table 5.1. Default Topology Acceptance Constraints**

| Field | Default | Meaning |
|---|---|---|
| `require_full_diffusion` | true | Every output byte must structurally depend on every input byte after `depth` layers. |
| `min_node_fanin` | 4 | Every node, in every layer, must combine ≥ 4 distinct sources across heads. |
| `max_usage_ratio` | 2.5 | No source index used more than 2.5× the per-layer average. |
| maxattempts | 32 | Candidates tried before falling back to the best-scoring one seen. |

This candidate-generate-and-check search is fully deterministic per key
— the same key always produces the same sequence of candidates and the
same selected topology — and never falls back to a source of randomness
outside the key-derived family; it only ever falls back to a different
member of that same family.

#
For interoperability, `score(diag)` is defined exactly as the following scalar:

S(d)=1000I + 200(-D) + 10F - R

where `I` is 1 when fulldiffusion is true and 0 otherwise, `D` is the number
of dead inputs, `F` is `min_node_fanin`, and `R` is `max_usage_ratio`.
This is algebraically identical to the reference implementation's score calculation.

The reference implementation computes `max_usage_ratio` as
`max_count / mean_usage`, where `mean_usage = total_selected_sources / 8`.
For the standard profile, every output node selects exactly 3 sources per head,
there are 8 output nodes, and `heads` is fixed for the candidate, so the total
number of selected source occurrences is `24 * heads` and `mean_usage = 3 * heads`.
An independent implementation may compute this value exactly as the rational
number

R = \frac{cmax}{3h}

and compare scores by exact rational arithmetic. This produces the same ordering as
the reference implementation for the standard parameter ranges.

Candidate selection is deterministic and uses **strictly greater-than** comparison.
The first candidate seen with a given maximum score is retained. Therefore, if two
candidates have exactly equal scores, the candidate with the **smaller attempt
number** wins.

The standard profile evaluates exactly the candidate sequence `attempt = 0, 1, ...,
31` until a candidate satisfies `passes()`. If no candidate passes, the highest-scoring
candidate is selected. The selected fallback candidate is not required to satisfy
the acceptance constraints.

For the standard profile, maxattempts is exactly 32. A value of zero is invalid
for an interoperable KGRTC-256 implementation.

### 5.2.5 The MAC key

```
mac_key = stream_bytes(key ∥ "MAC_KEY_V1", 32)
```

computed once, alongside every structure above, and cached as part of
the Cipher Context (Section 5.4.3).

#### 5.2.6 Full pseudocode

> **Algorithm 5.13 — Pseudocode for `GENERATECONTEXT()`**
> ```
>  1: procedure GENERATECONTEXT(key)
>  2:     require len(key) = 32, else error InvalidKeyLength
>  3:     for ρ from 0 to r−1 do
>  4:         S[ρ] ← generate_sbox(key, ρ, "SBOX")                        ▷ Sec. 5.2.2
>  5:         Sinv[ρ] ← inverse_sbox(S[ρ])
>  6:         Perm[ρ] ← generate_permutation(key ∥ "STATE_PERM" ∥ be32(ρ), 16)
>  7:         InvPerm[ρ] ← inverse_permutation(Perm[ρ])
>  8:         RoundKey[ρ] ← generate_round_key(key, ρ)                    ▷ Sec. 5.2.3
>  9:         (F[ρ], _) ← GENERATETRANSFORMER(key, ρ, "TRANSFORMER_F", default constraints) ▷ Sec. 5.2.4
> 10:         (G[ρ], _) ← GENERATETRANSFORMER(key, ρ, "TRANSFORMER_G", default constraints)
> 11:     end for
> 12:     mac_key ← stream_bytes(key ∥ "MAC_KEY_V1", 32)                   ▷ Sec. 5.2.5
> 13:     return context = { S, Sinv, Perm, InvPerm, RoundKey, F, G, mac_key }
> 14: end procedure
> ```

`GENERATECONTEXT()` must be computed exactly once per master key and its
output cached and reused for every block encrypted or decrypted under
that key.

### 5.3 INVCIPHER()

To implement `INVCIPHER()`, the transformations of `CIPHER()` (Section
5.1) are inverted and executed in reverse order — exactly the same
overall strategy as FIPS 197 Section 5.3, but here **every** round is
inverted identically, since (unlike AES) no round differs in structure
from any other.

> **Algorithm 5.14 — Pseudocode for `INVCIPHER()`**
> ```
>  1: procedure INVCIPHER(in, context)
>  2:     state ← in
>  3:     for round from r−1 downto 0 do
>  4:         state ← state ⊕ context.RoundKey[round]                 ▷ Inverse of ADDROUNDKEY(), Sec. 5.3.4
>  5:         state ← INVCOUPLE(state, context.F[round], context.G[round]) ▷ Sec. 5.3.3
>  6:         state ← INVPERMUTEBYTES(state, context.InvPerm[round])   ▷ Sec. 5.3.1
>  7:         state ← INVSUBBYTES(state, context.Sinv[round])          ▷ Sec. 5.3.2
>  8:     end for
>  9:     return state
> 10: end procedure
> ```

#### 5.3.1 INVPERMUTEBYTES()

`INVPERMUTEBYTES()` is the inverse of `PERMUTEBYTES()` (Section 5.1.2):

```
state'[i] = state[ InvPerm[round][i] ]     for 0 ≤ i < 16,
```

where `InvPerm[round]` is the index-inverse of `Perm[round]`
(`InvPerm[round][ Perm[round][i] ] = i` for all `i`), computed once as
part of `GENERATECONTEXT()` (Section 5.2.2).

#### 5.3.2 INVSUBBYTES()

`INVSUBBYTES()` is the inverse of `SUBBYTES()` (Section 5.1.1), in which
the inverse of that round's S-box, `Sinv[round]`, is applied to each
byte of the state:

```
state'[i] = Sinv[round][ state[i] ]     for 0 ≤ i < 16.
```

> **Algorithm 5.11 — `inverse_sbox(S)`**
> ```
> Input:  S[0..255]
> Output: Sinv[0..255] such that Sinv[S[x]] = x for all x
>
> for x = 0 to 255:
>     Sinv[ S[x] ] ← x
> return Sinv
> ```

Because each S[ρ] is a distinct, key-derived table (Section 5.1.1),
Sinv[ρ] is likewise distinct per round — where AES presents a single
fixed `INVSBOX()` table (FIPS 197 Table 6), KGRTC's `INVSBOX()` for
round `ρ` is computed by an implementation, not looked up from a
published constant. Appendix A gives one complete, worked 256-entry
S[ρ]/Sinv[ρ] pair for a specific example key, exactly the way FIPS
197 Table 4/Table 6 give the (fixed, key-independent) AES S-box and its
inverse.

#### 5.3.3 INVCOUPLE()

`INVCOUPLE()` is the inverse of `COUPLE()` (Section 5.1.3):

> **Algorithm 5.15 — `INVCOUPLE(state, F, G)`**
> ```
> Input:  state[0..15], F, G
> Output: state'[0..15]
>
> A' ← state[0..7];  B' ← state[8..15]
> G_B ← TRANSFORM(B', G)
> A   ← A' ⊕ G_B
> F_A ← TRANSFORM(A, F)
> B   ← B' ⊕ F_A
> return A ∥ B
> ```

By Property 5.2 (Section 5.1.3), this exactly undoes `COUPLE()` for any
`F`, `G`, and any 16-byte state.

#### 5.3.4 Inverse of ADDROUNDKEY()

`ADDROUNDKEY()`, described in Section 5.1.4, is its own inverse, exactly
as in AES.

**Property 5.3 (correctness).** For every valid 32-byte key and every
16-byte block `P`: `INVCIPHER(CIPHER(P, ctx), ctx) = P`, where `ctx =
GENERATECONTEXT(key)`. This follows from: (a) `SUBBYTES()`/
`INVSUBBYTES()` are exact table inverses (Algorithm 5.11); (b)
`PERMUTEBYTES()`/`INVPERMUTEBYTES()` are exact inverses for any
permutation; (c) `COUPLE()`/`INVCOUPLE()` are exact inverses for any
`(F, G)` (Property 5.2); (d) `ADDROUNDKEY()` is self-inverse; and the
four steps of one round, and the 14 rounds themselves, are undone in
exactly reversed order in `INVCIPHER()`.

*(This document does not define an equivalent-inverse-cipher analog to
FIPS 197 Section 5.3.5: `INVCIPHER()` above is the only inverse
construction KGRTC specifies. Because KGRTC's `COUPLE()`/`INVCOUPLE()`
pair does not decompose into row/column matrix operations the way
AES's `MIXCOLUMNS()`/`INVMIXCOLUMNS()` does, there is no analogous
efficiency transformation to derive.)*

### 5.4 Modes and Authentication

KGRTC's `CIPHER()` (Section 5.1) is the normative block primitive used inside
a counter-mode (CTR) keystream construction, wrapped with HMAC-SHA-256
authentication. Raw block operations may be exposed for research, testing,
and conformance; they are not the sanctioned unauthenticated message-level
interface for caller plaintext.

#### 5.4.1 CTRTRANSFORM()

For a 12-byte nonce `N` and keystream-block index `i` (`i = 0, 1, 2,
...`), the corresponding 16-byte counter block is `N ∥ be32(i)`.

> **Algorithm 5.16 — `CTRTRANSFORM(data, context, nonce)`**
> ```
> Input:  data[0..L-1], context, nonce[0..11]
> Output: out[0..L-1]  (data XORed with the CTR keystream)
>
> require len(nonce) = 12, else error InvalidNonceLength
> n_blocks ← ceil(L / 16)
> require n_blocks ≤ 2^32, else error MessageTooLong
>
> out ← empty
> for i = 0 to n_blocks-1:
>     counter_block ← nonce ∥ be32(i)
>     keystream ← CIPHER(counter_block, context)
>     chunk ← data[16i .. min(16(i+1), L))
>     for j = 0 to len(chunk)-1: append (chunk[j] ⊕ keystream[j]) to out
> return out
> ```

No padding is used. Because `CTRTRANSFORM()` only ever invokes the
forward `CIPHER()`, the same function serves as both the CTR encryption
and CTR decryption transform.


For the standard 12-byte nonce and 4-byte counter, the largest representable
message length is

2³²×16 = 2³⁶

bytes. The counter values are the unsigned 32-bit integers `0` through
`2^32-1`, encoded big-endian. The first counter value is exactly zero.
A `(key, nonce)` pair must not be reused for two distinct messages, including when
one or both messages are empty.

**Requirement 5.1.** A given `(key, nonce)` pair must never be reused
across two distinct messages (standard CTR-mode requirement).

#### 5.4.2 Authenticated encryption

> **Algorithm 5.17 — `AEENCRYPT(plaintext, key, nonce?)`**
> ```
> context    ← GENERATECONTEXT(key)                       (or a cached context)
> nonce      ← supplied, or 12 fresh CSPRNG-random bytes
> ciphertext ← CTRTRANSFORM(plaintext, context, nonce)
> tag        ← HMAC-SHA256(context.mac_key, nonce ∥ ciphertext)
> return nonce ∥ ciphertext ∥ tag
> ```

> **Algorithm 5.18 — `AEDECRYPT(blob, key)`**
> ```
> require len(blob) ≥ 12+32, else error CiphertextTooShort
> nonce      ← blob[0..11]
> tag        ← blob[len-32..len-1]
> ciphertext ← blob[12..len-33]
> context ← GENERATECONTEXT(key)
> expected_tag ← HMAC-SHA256(context.mac_key, nonce ∥ ciphertext)
> if NOT constant_time_equal(tag, expected_tag):
>     return error AuthenticationFailed          ▷ MUST abort before decrypting
> return CTRTRANSFORM(ciphertext, context, nonce)
> ```

Tag verification must run in time independent of where the two values
first differ, and must complete, and succeed, before any plaintext
byte is released.

#### 5.4.3 Cipher Context caching

Every structure produced by `GENERATECONTEXT()` (Section 5.2), together
with mackey, is generated once per master key and must be cached and
reused for every subsequent block, in every mode, for the lifetime of
that key.

#### 5.4.4 Canonical message wire format

The authenticated message returned by `AEENCRYPT()` is a raw byte string with no
version field, no algorithm identifier, no length field, and no associated-data field.

For a plaintext of `L` bytes and corresponding ciphertext of `L` bytes, the byte
layout is:

{blob} = {nonce}[0..12] ∥ {ciphertext}[0..L] ∥ {tag}[0..32]

Thus:

- bytes `0..11` are the nonce;
- bytes `12..(12+L-1)` are the ciphertext, if `L > 0`;
- the final 32 bytes are the HMAC-SHA-256 tag;
- total blob length is `L + 44` bytes.

For an empty plaintext, the ciphertext portion has length zero and the blob is
exactly 44 bytes: 12-byte nonce followed immediately by the 32-byte tag.

A decoder must therefore recover:

```text
nonce      = blob[0..12]
tag        = blob[len(blob)-32 .. len(blob)]
ciphertext = blob[12 .. len(blob)-32]
```

and must authenticate nonce ∥ ciphertext with the domain-separated mackey
before invoking the CTR transform.

A canonical textual representation may be hexadecimal or Base64, but such an
encoding is external to KGRTC. If hexadecimal is used, each byte is written as
exactly two hexadecimal digits in ascending byte-index order; if Base64 is used,
standard RFC 4648 encoding of the raw byte string is recommended.

---

## 6. Implementation Considerations

### 6.1 Key Length Requirements

An implementation of KGRTC shall support the one key length specified
in this document: 256 bits (k=256). Unlike AES, this specification
does not define 128-bit or 192-bit variants; see Section 6.3.

### 6.2 Keying Restrictions

When a cryptographic key has been generated appropriately (32
uniformly-random bytes from a CSPRNG; see NIST SP 800-133, Rev. 2 [6]
for general guidance on key generation, referenced here as it is
domain-independent of KGRTC's specific construction), no additional
restriction is imposed on its use with KGRTC.

### 6.3 Parameter Extensions

This document defines exactly one parameter set: n=128, k=256,
r=14 (Table 3). Unlike FIPS 197 — which explicitly reserves room for
128-, 192-, and 256-bit keys within one Standard — this version of
KGRTC does not define behavior for any other key length, block size, or
round count. A future revision of this specification could define
additional parameter sets (analogous to how Rijndael itself supports
block/key sizes beyond the three AES adopted); any such revision would
require its own full specification of Sections 2–5 for the new
parameter set, since almost every structural component in KGRTC (unlike
AES's fixed S-box and fixed diffusion matrix) is generated in a way
that depends on the specific byte/bit widths chosen.

### 6.4 Implementation Suggestions Regarding Various Platforms

KGRTC may be implemented in software, firmware, hardware, or any
combination. Given the same master key and the same data input, any
implementation that reproduces this specification's algorithms exactly
(Sections 4–5) will produce the same output; Appendices A–C provide
worked values to check this.

As with any block cipher, a physical implementation may leak
key-dependent information through side channels — timing, power, or
fault-injection — regardless of whether the underlying transformation
is otherwise correct. **No side-channel hardening is specified or
claimed by this document.** In particular: `GENERATECONTEXT()`'s
topology-acceptance search (Section 5.2.4) runs a data-dependent number
of iterations per Transformer, and `derive_affine_gf2` (Section 5.1.1)
runs a data-dependent number of iterations per S-box; both loop counts
depend only on the *key*, not on any subsequently-processed plaintext or
ciphertext, but an implementation intending any side-channel resistance
must still consider whether the *key-dependent* timing of these
one-time setup loops is externally observable in its deployment
context. Protecting implementations of KGRTC against implementation
attacks, where applicable, should be considered; such considerations
are outside the scope of this document, and — unlike AES — there is no
validation program (analogous to NIST's CMVP) that tests KGRTC
implementations for conformance or side-channel resistance.

### 6.5 Modes of Operation

This document specifies exactly one mode of operation for KGRTC's block
cipher: the CTR-mode-plus-HMAC-SHA-256 construction of Section 5.4. This
is not one of the NIST SP 800-38-series modes applied off-the-shelf to
an unmodified block cipher interface — Section 5.4's `AEENCRYPT()`/
`AEDECRYPT()` bundle CTR-mode confidentiality and HMAC-SHA-256 integrity
together as the *only* sanctioned way to use KGRTC's `CIPHER()`/
`INVCIPHER()` on caller data; the raw single-block `CIPHER()`/
`INVCIPHER()` functions of Sections 5.1/5.3 are not intended for direct
use as an unauthenticated encryption primitive.

---

## 7. Security Status

*(This section has no FIPS 197 analog, because AES's security status —
having survived the multi-year, worldwide AES competition and two
decades of subsequent public cryptanalysis — does not require restating
inside its own specification. KGRTC has no comparable history, so this
document states its status explicitly, as required reading before any
use of this specification for anything beyond study or reimplementation.)*

KGRTC is an **experimental, unaudited** cipher. This document defines
its behavior precisely enough to reimplement (Sections 2–5) and to check
an implementation against worked values (Appendices A–C). It does
**not** establish, and must not be read as implying, resistance to
differential, linear, algebraic, or side-channel cryptanalysis beyond
the two specific, narrowly-scoped guarantees stated inline above:

- **Property 5.1** (Section 5.1.1): the per-round S-box has differential
  uniformity exactly 4 for every key, by proof, with nonlinearity,
  linearity, algebraic degree, and autocorrelation additionally fixed
  at AES's own values for every key.
- The topology-acceptance search of Section 5.2.4 guarantees every
  accepted Transformer achieves full structural diffusion, a minimum
  per-layer fan-in, and bounded source-usage imbalance — a guarantee
  about *reachability*, not a bound on differential or linear trail
  *probabilities* through the Transformer (no MDS-style branch number is
  established or claimed for `COUPLE()` as a whole).

No claim is made about the composed 14-round cipher's resistance to
differential or linear cryptanalysis across all rounds, resistance to
algebraic attacks, key-recovery attacks exploiting the generation
procedure itself, or side-channel attacks against any implementation.
KGRTC has not been reviewed by cryptographers and has not been submitted
to, or evaluated in, any public cryptographic competition or standards
process. **Do not use KGRTC to protect data of real value.** Use a
standardized, publicly analyzed AEAD (e.g. AES-256-GCM,
ChaCha20-Poly1305) instead.

---

## References

1. NIST FIPS 197, *Advanced Encryption Standard (AES)*, updated 2023 —
   the structural and stylistic model for this document; GF(2⁸) and
   its reduction polynomial (Section 4 of this document) are identical
   to FIPS 197's.
2. NIST FIPS 202, *SHA-3 Standard: Permutation-Based Hash and
   Extendable-Output Functions* — defines SHAKE-256, the sole KDF
   primitive underlying Section 5.2 of this document.
3. NIST FIPS 198-1, *The Keyed-Hash Message Authentication Code
   (HMAC)* — defines HMAC, used with SHA-256 in Section 5.4.
4. NIST FIPS 180-4, *Secure Hash Standard* — defines SHA-256.
5. NIST SP 800-38A, *Recommendation for Block Cipher Modes of
   Operation* — the general counter (CTR) mode construction Section
   5.4.1 follows, adapted here to KGRTC's own single-block primitive.
6. Elaine Barker, Allen Roginsky, and Richard Davis. *Recommendation for
   Cryptographic Key Generation.* NIST Special Publication (SP)
   800-133, Rev. 2, June 2020. https://doi.org/10.6028/NIST.SP.800-133r2
   — referenced in Section 6.2 for general key-generation guidance,
   independent of any KGRTC-specific construction.
7. Joan Daemen and Vincent Rijmen. *The Design of Rijndael — The
   Advanced Encryption Standard (AES)*, Second Edition. Springer, 2020.
   — background on the Feistel-network invertibility argument that
   Property 5.2 (Section 5.1.3) generalizes.

---

## Appendix A — Architecture Generation Examples

This appendix shows the development of the Cipher Context for a specific
example master key — the KGRTC analog of FIPS 197 Appendix A's Key
Expansion Examples. All values were produced by executing the reference
implementation directly, exactly as they would be by any conformant
implementation of Sections 5.1–5.2. All values are given in hexadecimal.

```
key = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00      (32 zero bytes)
```

**A.1 Round 0 S-box, `S[0]` (Algorithm 5.3, `generate_sbox(key, 0,
"SBOX")`)**

The following 256-entry table gives `S[0][xy]` for input byte `xy`, in
the identical row-by-`x`/column-by-`y` layout FIPS 197 Table 4 uses for
the (fixed) AES S-box — the difference being that this table is
key-derived and would be different for every other 32-byte key.

```
        y
        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
   x
   0 |  10 c9 24 97 45 8b a3 53 14 f1 38 e5 f6 94 01 89
   1 |  96 63 e0 64 de 18 6c 9e f2 e2 37 29 17 c4 a1 d6
   2 |  ae 80 d2 fb e7 d1 c0 65 3c 69 07 33 d7 51 b9 c5
   3 |  74 88 7e a0 db 57 d9 e4 02 9b b8 59 6f 56 2b ff
   4 |  6a ce bb 00 ad 0e 6e ec f5 f9 39 86 3e f4 cd 90
   5 |  58 67 5c 9c 08 2d 5d c3 26 3b 98 22 72 81 b5 13
   6 |  ca 47 ac 73 44 2c 62 3d b7 a8 87 bf 2e a7 61 77
   7 |  83 9a 32 7d 7f ba 8f 1b 43 03 8a a5 40 5b e8 11
   8 |  c8 ef 36 31 eb fa 1a 1e fe b2 12 0a 4e 30 76 0c
   9 |  66 15 f7 79 d3 48 a4 23 c1 ea 6b 68 a2 46 b1 27
   a |  82 cf 54 1c 04 af 20 9d 0d bc 5f bd 09 21 aa 4c
   b |  dc 4d 4a 78 a6 4f 5a da d5 dd b6 c2 e3 3a 84 c7
   c |  b0 e1 8d 60 f3 1f d8 25 19 d4 52 85 df ee 55 f8
   d |  7a 7c 75 95 a9 2a 6d 34 cb 91 70 c6 4b 7b 5e cc
   e |  2f 05 3f ed 50 fc d0 8c 49 28 e6 b4 be ab 93 0f
   f |  0b 41 8e 42 35 71 e9 fd 9f 92 16 99 f0 06 1d b3
```

For example, if a byte of the state equals `{53}` in round 0 under this
key, `SUBBYTES()` replaces it with the value at row `5`, column `3`:
`S[0][0x53] = {c3}`.

**A.2 Round 0 inverse S-box, `Sinv[0]` (Algorithm 5.11)**

```
        y
        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
   x
   0 |  43 0e 38 79 a4 e1 fd 2a 54 ac 8b f0 8f a8 45 ef
   1 |  00 7f 8a 5f 08 91 fa 1c 15 c8 86 77 a3 fe 87 c5
   2 |  a6 ad 5b 97 02 c7 58 9f e9 1b d5 3e 65 55 6c e0
   3 |  8d 83 72 2b d7 f4 82 1a 0a 4a bd 59 28 67 4c e2
   4 |  7c f1 f3 78 64 04 9d 61 95 e8 b2 dc af b1 8c b5
   5 |  e4 2d ca 07 a2 ce 3d 35 50 3b b6 7d 52 56 de aa
   6 |  c3 6e 66 11 13 27 90 51 9b 29 40 9a 16 d6 46 3c
   7 |  da f5 5c 63 30 d2 8e 6f b3 93 d0 dd d1 73 32 74
   8 |  21 5d a0 70 be cb 4b 6a 31 0f 7a 05 e7 c2 f2 76
   9 |  4f d9 f9 ee 0d d3 10 03 5a fb 71 39 53 a7 17 f8
   a |  33 1e 9c 06 96 7b b4 6d 69 d4 ae ed 62 44 20 a5
   b |  c0 9e 89 ff eb 5e ba 68 3a 2e 75 42 a9 ab ec 6b
   c |  26 98 bb 57 1d 2f db bf 80 01 60 d8 df 4e 41 a1
   d |  e6 25 22 94 c9 b8 1f 2c c6 36 b7 34 b0 b9 14 cc
   e |  12 c1 19 bc 37 0b ea 24 7e f6 99 84 47 e3 cd 81
   f |  fc 09 18 c4 4d 48 0c 92 cf 49 85 23 e5 f7 88 3f
```

**A.3 Round 0 permutation, `Perm[0]` and `InvPerm[0]` (Algorithm 5.4)**

```
Perm[0]    = [3, 5, 4, 13, 12, 10, 6, 15, 2, 9, 14, 1, 8, 11, 0, 7]
InvPerm[0] = [14, 11, 8, 0, 2, 1, 6, 15, 12, 9, 5, 13, 4, 3, 10, 7]
```

**A.4 Round 0 round key, `RoundKey[0]` (Algorithm 5.12)**

```
RoundKey[0] = a3 34 16 96 fa 40 db 74 11 b7 54 df 3f 32 38 dc
```

**A.5 Round 0 Transformers, `F[0]` and `G[0]` (Algorithm 5.8)**

```
F[0]: depth = 4, heads = 4   (Algorithm 5.5 shape derivation)
G[0]: depth = 3, heads = 3
```

Both were accepted as their `attempt = 0` candidate wiring under
Table 5.1's default constraints for this key (i.e., the first
key-derived topology already satisfied full diffusion, minimum fan-in
4, and usage ratio ≤ 2.5 — no retry was required for this particular
key/round/identifier combination).

**A.5.1 Exact topology and weights excerpt**

For the same all-zero key, the complete connection records for `F[0]`, layer 0, head 0 are:

```text
F[0], layer 0, head 0
node 0: sources=[6, 2, 4] weights=[95, f9, 4b]
node 1: sources=[5, 6, 1] weights=[01, 52, 15]
node 2: sources=[0, 5, 3] weights=[d4, 93, f9]
node 3: sources=[5, 3, 0] weights=[6a, 62, f8]
node 4: sources=[1, 0, 2] weights=[da, 79, 05]
node 5: sources=[1, 5, 0] weights=[fe, b3, 09]
node 6: sources=[7, 0, 6] weights=[25, f6, 71]
node 7: sources=[5, 7, 0] weights=[97, a9, 69]
```

The complete connection records for `G[0]`, layer 0, head 0 are:

```text
G[0], layer 0, head 0
node 0: sources=[6, 3, 7] weights=[60, ab, 8a]
node 1: sources=[2, 0, 4] weights=[03, ea, 5a]
node 2: sources=[2, 3, 4] weights=[19, 29, 73]
node 3: sources=[3, 4, 0] weights=[73, de, 5f]
node 4: sources=[2, 1, 7] weights=[bf, 92, b9]
node 5: sources=[6, 3, 4] weights=[04, fe, 35]
node 6: sources=[4, 5, 0] weights=[b0, 65, 12]
node 7: sources=[1, 7, 5] weights=[e7, c4, 71]
```

These records are an implementation diagnostic, not an alternative definition of the
algorithm; a conforming implementation must derive them from the normative seed and
permutation rules rather than hard-code them.

**A.6 MAC key (Section 5.2.5)**

```
mac_key = 42 07 b6 c8 f8 85 bb b4 71 3f 13 97 ab b0 05 d7
          36 ab 87 b8 08 d2 07 71 17 93 1b 51 2e a8 8a 74
```

---

## Appendix B — Cipher Example

The following table shows the values of the state as `CIPHER()`
progresses, for the block and key given below — the KGRTC analog of
FIPS 197 Appendix B.

```
Input = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
Key   = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

The S-box, permutation, round key, and Transformer values are those
generated for this key in Appendix A (round 0) and by the identical
procedure for rounds 1–13.

| Round | Start of round | After `SUBBYTES()` | After `PERMUTEBYTES()` | After `COUPLE()` | Round key | After `ADDROUNDKEY()` |
|---|---|---|---|---|---|---|
| 0 | 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f | 10 c9 24 97 45 8b a3 53 14 f1 38 e5 f6 94 01 89 | 97 8b 45 94 f6 38 a3 89 24 f1 01 c9 14 e5 10 53 | 5e c2 c2 93 7d 06 43 35 08 e3 1a 28 14 ea 32 8a | a3 34 16 96 fa 40 db 74 11 b7 54 df 3f 32 38 dc | fd f6 d4 05 87 46 98 41 19 54 4e f7 2b d8 0a 56 |
| 1 | fd f6 d4 05 87 46 98 41 19 54 4e f7 2b d8 0a 56 | c7 35 09 cb 28 33 fd a4 df 7e be 99 b3 f7 59 0e | f7 a4 28 fd cb 09 df 7e 35 c7 b3 59 33 be 99 0e | d9 5d 30 ef 3b da aa a3 b5 fa cf 9f 23 e4 91 70 | 54 d9 f5 3e 4f 59 0c 36 cd 8c 2d 8b 73 bf 45 e1 | 8d 84 c5 d1 74 83 a6 95 78 76 e2 14 50 5b d4 91 |
| 2 | 8d 84 c5 d1 74 83 a6 95 78 76 e2 14 50 5b d4 91 | 43 39 f2 8b f5 6c 9d fd e4 26 42 60 23 cc df c4 | 8b fd df 39 f2 26 23 42 9d 6c f5 43 e4 60 c4 cc | 4d f8 8f 71 b0 69 fd d8 3d 83 0c 14 a8 57 6e 9b | de 11 fd 08 a3 fb 45 af f9 c1 fb 04 3c 77 66 2a | 93 e9 72 79 13 92 b8 77 c4 42 f7 10 94 20 08 b1 |
| 3 | 93 e9 72 79 13 92 b8 77 c4 42 f7 10 94 20 08 b1 | f8 6a a9 17 2f 0b d6 7b 7f 4e cb e8 0d f6 00 fd | a9 17 0b 6a cb 00 7b f8 0d d6 4e 2f 7f fd f6 e8 | de 99 ca 75 54 11 02 9a 05 6c 06 1e 07 72 2f 61 | ee 7b 53 78 0a 1b 73 d9 1e ae 6b e6 a1 69 af 7e | 30 e2 99 0d 5e 0a 71 43 1b c2 6d f8 a6 1b 80 1f |
| 4 | 30 e2 99 0d 5e 0a 71 43 1b c2 6d f8 a6 1b 80 1f | 3c 42 bb 25 49 cf 7a 2c 23 aa f9 1a f1 23 8b 89 | 3c 23 2c 8b 25 1a f1 cf 42 49 89 23 aa bb f9 7a | 7a 86 d5 84 09 d7 ae 76 54 a7 a2 02 89 6b 60 d8 | fc 20 36 23 54 65 c5 72 fd e3 99 3d c3 31 ed 5d | 86 a6 e3 a7 5d b2 6b 04 a9 44 3b 3f 4a 5a 8d 85 |
| 5 | 86 a6 e3 a7 5d b2 6b 04 a9 44 3b 3f 4a 5a 8d 85 | 8e e2 6d 42 e8 03 6e df 14 ec 75 ef 56 5c ee f1 | ee 03 75 14 6e ec 56 e2 ef 42 6d 5c f1 e8 df 8e | f7 ec 94 e3 85 23 3a 5e 0b fd da 39 d8 60 a3 87 | 79 09 9e 49 3a 9e 6c 08 20 63 28 0e 11 78 74 cc | 8e e5 0a aa bf bd 56 56 2b 9e f2 37 c9 18 d7 4b |
| 6 | 8e e5 0a aa bf bd 56 56 2b 9e f2 37 c9 18 d7 4b | 88 90 3d 89 4a 12 a6 a6 71 50 75 5d cb 79 fb 4c | 5d 50 fb 4c a6 75 cb 79 12 89 a6 4a 88 3d 90 71 | 88 9e 83 92 3f 10 e3 e3 95 ac 67 4b 6d a4 19 21 | 42 ff c9 83 22 3b 57 7a 0c 6d 40 c8 7b 6d c9 48 | ca 61 4a 11 1d 2b b4 99 99 c1 27 83 16 c9 d0 69 |
| 7 | ca 61 4a 11 1d 2b b4 99 99 c1 27 83 16 c9 d0 69 | fb 81 dd c2 31 4c eb e3 e3 cf e2 9c 1e 06 09 8a | 9c 06 c2 e3 e3 8a eb e2 cf fb dd 1e 09 4c 81 31 | 37 70 7a d1 60 6e 0f 80 09 11 e5 d8 ac 8d 7d 13 | c0 42 51 9b 32 b2 2e 88 38 09 8d 96 25 1e 91 92 | f7 32 2b 4a 52 dc 21 08 31 18 68 4e 89 93 ec 81 |
| 8 | f7 32 2b 4a 52 dc 21 08 31 18 68 4e 89 93 ec 81 | cd f9 10 ad 45 82 09 fa 3a 26 fc e0 aa 21 2a 5c | aa e0 26 3a 5c fc f9 2a ad 82 fa 45 10 09 cd 21 | 89 9d 01 6f 76 5a 3f 3e f4 10 22 3d e1 bb 79 a6 | fa e7 91 6e 12 5e dd 89 40 e9 c3 53 26 c0 a1 e1 | 73 7a 90 01 64 04 e2 b7 b4 f9 e1 6e c7 7b d8 47 |
| 9 | 73 7a 90 01 64 04 e2 b7 b4 f9 e1 6e c7 7b d8 47 | cc 95 00 a3 ca f0 c0 81 21 1a 85 aa 36 62 da c3 | a3 36 da 1a 62 cc 81 95 21 aa f0 00 c0 c3 ca 85 | d9 17 4d 6c 20 33 6b 5f e3 de 2c c0 e5 b0 e7 bc | c8 00 a9 49 21 f4 5e 88 69 94 f9 27 4c b8 76 6e | 11 17 e4 25 01 c7 35 d7 8a 4a d5 e7 a9 08 91 d2 |
| 10 | 11 17 e4 25 01 c7 35 d7 8a 4a d5 e7 a9 08 91 d2 | 1c 68 e6 b4 db 1a f8 af a2 37 88 81 27 ea bc b7 | a2 bc 68 e6 81 ea 1c b7 b4 af 88 f8 37 1a 27 db | da d4 37 a4 27 cc 82 54 b6 0f 94 27 ac 34 ac 6b | 43 f9 27 fa 85 8b 47 5c a2 d2 a8 54 b2 a8 27 f7 | 99 2d 10 5e a2 47 c5 08 14 dd 3c 73 1e 9c 8b 9c |
| 11 | 99 2d 10 5e a2 47 c5 08 14 dd 3c 73 1e 9c 8b 9c | 1e 29 4b ab ad 07 3f f6 44 9e b9 87 8c 11 1b 11 | 3f 07 f6 ad 1e 4b 1b 9e 44 11 8c 29 b9 87 ab 11 | 86 d9 35 93 a5 cb 96 e9 1b 4b 50 f4 91 83 4e 2f | 27 3b 94 1d 37 30 c8 0a 04 90 c6 50 94 27 07 d4 | a1 e2 a1 8e 92 fb 5e e3 1f db 96 a4 05 a4 49 fb |
| 12 | a1 e2 a1 8e 92 fb 5e e3 1f db 96 a4 05 a4 49 fb | f3 c4 f3 bb 47 d8 ab 2c 58 1d 53 b0 e0 b0 eb d8 | 58 b0 bb c4 53 ab e0 d8 b0 47 eb 1d d8 f3 f3 2c | 7b e0 a8 21 30 d3 2f c0 2b b2 be 8d 70 ca a9 e6 | 3f 5f ef c0 18 ef 7e 97 07 20 4e 7d ef d0 4e 41 | 44 bf 47 e1 28 3c 51 57 2c 92 f0 f0 9f 1a e7 a7 |
| 13 | 44 bf 47 e1 28 3c 51 57 2c 92 f0 f0 9f 1a e7 a7 | d5 d8 5f 23 06 2e e3 01 5d de 10 10 87 02 b8 d3 | d3 e3 01 5d d8 2e 87 5f 02 d5 10 23 b8 06 10 de | e2 52 15 04 43 78 4a 84 85 3b 0a 1f 35 ed 3b 0d | 76 ae 3c 4c 7d 2c bd c8 63 f0 a2 5a f6 31 9e b2 | 94 fc 29 48 3e 54 f7 4c e6 cb a8 45 c3 dc a5 bf |

```
Output = 94 fc 29 48 3e 54 f7 4c e6 cb a8 45 c3 dc a5 bf
```

Running `INVCIPHER()` on this output, with the same Cipher Context,
returns the original 16-byte input exactly (Property 5.3):

```
INVCIPHER(Output, context) = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f    ✔
```

**Key-sensitivity check.** Changing only the last bit of the key (`key'
= 00...0001` instead of `00...0000`) and re-running `CIPHER()` on the
identical input block gives:

```
CIPHER(Input, GENERATECONTEXT(key')) = 94 04 8c 1a 11 09 9b ee 21 14 17 12 d3 d6 45 6f
```

which differs from the `key = 0` output in 62 of 128 bits — consistent
with a construction where the entire round architecture, not only an
additive round key, depends on the key.

---

## Appendix C — Example Vectors

The following authenticated-encryption vector was produced directly by
the reference implementation and may be used to validate an independent
implementation of Section 5.4 end-to-end.

```
Key       = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Nonce     = 11 11 11 11 11 11 11 11 11 11 11 11
Plaintext = "KGRTC test vector message, 37 B!!!!"   (35 bytes)
          = 4b 47 52 54 43 20 74 65 73 74 20 76 65 63 74 6f
            72 20 6d 65 73 73 61 67 65 2c 20 33 37 20 42 21
            21 21

Ciphertext = 59 d2 71 75 30 cc c9 c8 9c e1 a6 e1 ff db 39 63
             bd bc 26 4a 21 58 7c dd 97 65 57 a9 25 a0 35 49
             44 e8 6d

Tag        = b8 f5 c8 06 88 c6 50 1b d0 5d 62 66 66 28 a6 a2
             9d ba 74 a6 95 9b f1 42 de 08 59 3a 2c a1 aa 0b

Blob = Nonce ∥ Ciphertext ∥ Tag
```

```
AEDECRYPT(Blob, Key) = Plaintext                          ✔  (verified)

Tamper test: flipping bit 0 of the first ciphertext byte and
re-running AEDECRYPT yields error = AuthenticationFailed   ✔  (verified)
```

Appendix B's single-block `CIPHER()`/`INVCIPHER()` example and this
appendix's `AEENCRYPT()`/`AEDECRYPT()` example together exercise every
numbered algorithm in Section 5 for at least one concrete input; an
independent implementation reproducing both exactly (byte-for-byte) has
strong evidence of conformance with Sections 4–5 of this document.

---

## Appendix D — Independent Implementation Conformance Profile

This appendix is normative for interoperability testing.

An independent implementation should perform the following checks in order:

### D.1 Primitive checks

1. Implement SHAKE-256 and verify that `stream_bytes(seed, L)` equals the first
   `L` bytes of SHAKE-256 over the exact seed bytes.
2. Implement `gf_mul()` and verify the reduction polynomial `0x11B`.
3. Generate the fixed inverse table and verify `inv[0] = 0`.
4. Implement the GF(2) matrix-vector multiplication and rank test.
5. Implement the deterministic affine S-box generation.
6. Implement the deterministic Fisher-Yates permutation generation with big-endian
   `u64` values and modulo reduction.
7. Implement exact `be16`, `be32`, and `be64` serialization.

### D.2 Architecture checks

For the all-zero 32-byte key:

```text
F[0]: depth = 4, heads = 4
G[0]: depth = 3, heads = 3

Perm[0] =
[3, 5, 4, 13, 12, 10, 6, 15, 2, 9, 14, 1, 8, 11, 0, 7]

InvPerm[0] =
[14, 11, 8, 0, 2, 1, 6, 15, 12, 9, 5, 13, 4, 3, 10, 7]

RoundKey[0] =
a3 34 16 96 fa 40 db 74 11 b7 54 df 3f 32 38 dc
```

The round-0 S-box and inverse S-box are given in Appendix A.

### D.3 Core block-cipher check

For:

```text
Key   =
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Input =
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
```

the required output is:

```text
94 fc 29 48 3e 54 f7 4c e6 cb a8 45 c3 dc a5 bf
```

Applying the specified inverse returns the input exactly.

### D.4 Message-level boundary vectors

All vectors below use:

```text
Key   = 32 zero bytes
Nonce = 12 bytes of 0x22
```

**Empty plaintext (0 bytes)**

```text
Blob =
22 22 22 22 22 22 22 22 22 22 22 22
45 59 22 86 c3 e4 44 98 47 20 aa cb 00 d1 c0 2f
25 76 17 37 c8 71 15 98 ad ec db 9d 7f ab 78 80
```

**One zero byte**

```text
Plaintext =
00

Blob =
22 22 22 22 22 22 22 22 22 22 22 22
fd 99 8b b9
77 05 b0 33 1c 64 71 b2 a8 25 78 30 26 4f dc 40
70 ae b6 b5 76 f9 f2 a5 43 38 1e 9d 51
```

**Sixteen bytes**

```text
Plaintext =
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f

Blob =
22 22 22 22 22 22 22 22 22 22 22 22
fd 21 d3 83 14 a0 2c d0 12 39 c3 5e 3f 83 40 e6
90 d1 e1 ca 8e 5c a0 fc 1f 4f b0 7b dc a3 ac 17
b4 6c 46 85 42 cd cc ce db 63 1f 2d 88 a3 93 db
```

**Seventeen bytes**

```text
Plaintext =
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10

Blob =
22 22 22 22 22 22 22 22 22 22 22 22
fd 21 d3 83 14 a0 2c d0 12 39 c3 5e 3f 83 40 e6
50 91 5b 67 a8 b3 f0 81 1a 85 24 ce 70 62 6d a7
f5 5a 6c 01 de f9 cd 0d 08 27 5a b9 94 ff 6e cc ca
```

These vectors test the zero-length case, a sub-block case, an exact block boundary,
and a multi-block message. The ciphertext length always equals the plaintext
length; the only fixed overhead in the blob is 44 bytes.

### D.5 Authentication behavior

An implementation must reject a blob when any authenticated byte is changed,
including:

- any nonce byte;
- any ciphertext byte;
- any tag byte.

The implementation must compare the received tag with the expected HMAC tag using
a comparison routine that does not branch on the first differing byte and must not
release plaintext before successful authentication.

### D.6 Cross-language interoperability requirement

Two independent implementations are conformant if, for the same:

```text
algorithm = KGRTC-256
key       = identical 32-byte sequence
nonce     = identical 12-byte sequence
plaintext = identical byte sequence
```

they produce:

```text
identical Cipher Context
identical round keys
identical S-boxes
identical permutations
identical Transformer shapes
identical Transformer topologies
identical Transformer weights
identical Transformer-layer S-boxes
identical block-cipher output
identical ciphertext
identical HMAC tag
identical blob bytes
```

and each can decrypt the other's blob successfully.

No programming language, operating system, CPU architecture, external package,
random-number generator, floating-point implementation, character encoding, or
library-specific default is permitted to alter those results.

Where floating-point arithmetic is used only to evaluate `max_usage_ratio`, the
exact rational definition in Section 4.5 and the score ordering rules in Section
5.2.4 are normative; implementations may use integer/rational arithmetic instead.
