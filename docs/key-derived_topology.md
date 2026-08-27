# Key-Derived Topology

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); the exact topology derivation, acceptance criteria, retry sequence, and fallback are authoritative only in the specification.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §5.2.

KGRTC does not use a fixed connection graph inside its nonlinear mixing functions. Instead, the connections between state bytes are deterministically generated from the master key and domain parameters.

For each generated transformer, the topology specifies **which state bytes feed each output node**, how those sources are grouped across heads, and the associated key-derived weights.

The current connection structure can be represented as:

$$
T_{K,r,i,a}[l,h,o]
=
\{(s_1,w_1),(s_2,w_2),(s_3,w_3)\}
$$

where:

* $K$ is the master key,
* $r$ is the round,
* $i$ is the transformer identifier (`TRANSFORMER_F` or `TRANSFORMER_G`),
* $a$ is the topology-attempt index,
* $l$ is the layer,
* $h$ is the head,
* $o$ is the output node,
* $s_j$ identifies a source byte, and
* $w_j$ is the corresponding key-derived weight.

Each output node selects **exactly three distinct source indices per head**. The implementation obtains those indices from the first three entries of a generated permutation of the eight-byte state. Contributions from multiple heads are XOR-combined before the layer's S-box is applied.

## Deterministic derivation

The topology is derived using SHAKE-256-based domain-separated inputs. The simplified dependency is:

$$
T_{K,r,i,a} = \operatorname{GenerateTopology}(K,r,i,a)
$$

For attempts after zero, the attempt index is mixed into the per-head/per-node seed:

```text
base seed = key || transformer identifier || round
attempt > 0:
    head seed += "TOPO_ATTEMPT" || attempt_be_u32
node seed = head seed || "NODE" || layer || head || output_node
sources = first 3 indices of GeneratePermutation(node_seed, 8)
```

Therefore the candidate sequence is deterministic. The same key, implementation/derivation rules, round, transformer identifier, and attempt index produce the same candidate topology.

Different keys will generally produce different source-selection patterns, but this is not a formal uniqueness guarantee:

$$
K_1 \ne K_2
\quad\Longrightarrow\quad
T_{K_1} \text{ generally differs from } T_{K_2}
$$

## Structural constraint evaluation

The default `TopologyConstraints` are:

```text
require_full_diffusion = true
min_node_fanin         = 4
max_usage_ratio        = 2.5
max_attempts            = 32
```

These are **structural acceptance criteria**, not unconditional cryptographic guarantees.

### Full structural diffusion

The implementation propagates symbolic dependency sets through all transformer layers. The condition is:

$$
\forall o,\qquad D(o)=\{0,1,\ldots,7\}
$$

where $D(o)$ is the set of original input-byte positions reachable by final output node $o$.

This establishes a structural reachability property. It does **not** prove that every output bit is numerically sensitive to every input bit for every input state, nor does it establish differential or linear security.

### Dead inputs

The implementation reports an input index as dead if it is absent from the union of all final dependency sets. A passing candidate has:

$$
\operatorname{DeadInputs}=\varnothing
$$

### Minimum distinct fan-in

For each layer and output node, source indices are unioned across heads because the head outputs are XOR-combined. The diagnostic is:

$$
F_{\min}
=
\min_{l,o}
\left|\bigcup_h S_{l,h,o}\right|
$$

The default threshold is:

$$
F_{\min}\ge4
$$

This is **not** “four sources per head”: every head contributes exactly three selected sources, while the diagnostic counts distinct sources across all heads for a node within a layer.

### Source-usage balance

Within each layer, the implementation counts source selections across all heads and output nodes. If $c_j$ is the number of times source $j$ is selected, the layer mean is:

$$
\mu = \frac{1}{8}\sum_{j=0}^{7}c_j
$$

and the layer ratio is:

$$
R = \frac{\max_j c_j}{\mu}
$$

The global diagnostic stores the maximum such ratio across layers. The default threshold is:

$$
R \le 2.5
$$

## Bounded candidate search and fallback

`GeneratedTransformer::new_constrained` evaluates deterministic candidate attempts in order:

```text
attempt 0
   ↓
attempt 1
   ↓
...
   ↓
attempt 31   (default max_attempts = 32)
```

A candidate passes when all enabled constraints are satisfied. The generator stops at the **first passing candidate**.

If no candidate passes within the attempt budget, the implementation does **not** reject the key or leave the topology undefined. It keeps the highest-scoring candidate encountered. The fallback score is used only to choose among available candidates; it does not convert a failing candidate into a passing one.

The current score is:

$$
\operatorname{Score}(T)
=
1000I_{\mathrm{diffusion}}
-200|\mathrm{dead\ inputs}|
+10F_{\min}
-R
$$

Thus the selected topology is:

$$
\boxed{
\text{first candidate satisfying all configured constraints}
}
$$

or, when none passes:

$$
\boxed{
\operatorname*{arg\,max}_{a\in\{0,\ldots,31\}}
\operatorname{Score}(T_{K,r,i,a})
}
$$

A fallback topology **may violate one or more configured constraints**.

## Determinism

For a fixed:

```text
master key
implementation / derivation rules
round
transformer identifier
topology-constraint configuration
```

the selected topology is deterministic:

$$
\boxed{\text{same inputs} \rightarrow \text{same selected topology}}
$$

This property is reproducibility, not a security theorem.

## Relationship to architecture and weights

Key-derived topology is distinct from key-derived architecture.

The **architecture** determines the transformer's shape (depth and heads).

The **topology** determines source connections within that shape.

The **weights** determine the nonzero GF(2^8) coefficients applied to those selected sources.

Conceptually:

$$
\text{Architecture}
+
\text{Topology}
+
\text{Weights}
\rightarrow
\text{key-specific nonlinear transformation}
$$

The topology therefore changes the computation's wiring without claiming that different keys must always produce unique graphs.
