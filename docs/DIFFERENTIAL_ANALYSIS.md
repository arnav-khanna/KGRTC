# Differential propagation analysis

> **Document status — explanatory documentation**
>
> This document is **not normative**. It explains or analyzes KGRTC-256 for
> readers and researchers. The canonical definition of the algorithm is
> [`SPECIFICATION.md`](../SPECIFICATION.md); its results are experimental evidence and are not normative security claims.
>
> See [`SPECIFICATION.md`](../SPECIFICATION.md) §7.

Two layers of analysis, empirical (sampled) and exact (exhaustive, layer-0 only), plus the story of a real bug caught in the exact layer's multi-head cancellation check. See [DESIGN.md](DESIGN.md) for the S-box and topology background this builds on, and [`../SECURITY.md`](../SECURITY.md) for what this section does and does not establish about the cipher's actual security.

## Differential propagation: active-byte expansion (empirical)

The diffusion checks above answer "*could* output byte i possibly depend
on input byte j" — a structural upper bound that ignores algebraic
cancellation. They don't say how an actual difference propagates through
the real, keyed F/G transformers or the full 14-round cipher. `analyzer.rs`
now also has an empirical differential layer for that:

- **`active_byte_expansion` / `active_byte_expansion_report`** — for one
  F or G transformer in isolation, perturbs a random base input at
  `active_in` random byte positions (random nonzero deltas), runs it
  through the transformer, and measures how many output bytes end up
  active. Repeated per active-byte-count level (1..HALF_SIZE) and across
  many trials to get min/mean/max.
- **`round_differential_stats`** — same idea for one full round
  (S-box → permutation → F/G coupling) of a real `CipherContext`,
  operating on the full 16-byte block. The round-key XOR is skipped via
  the new `cipher::round_transform_no_key` helper: since
  `(X⊕K)⊕(Y⊕K) = X⊕Y`, XOR with a fixed key never changes a *difference*,
  so it's safe to drop from a differential trail at every round, not
  just conceptually the last one.
- **`differential_trail` / `differential_trail_stats`** — propagates one
  difference through all 14 rounds (round-key XOR skipped throughout, by
  the same argument), tracking active-byte count round by round, then
  aggregates that over many independent trials.

**Important, unavoidable caveat:** the S-box's DDT/LAT/ANF metrics above
are *exact* — computed by exhaustively trying every one of the 256
inputs. F and G map 8 bytes to 8 bytes (a domain of 256⁸) and the full
block is 256¹⁶ — far too large to search exhaustively. Everything in
this section is **sampled**: the "min" reported is the minimum
*observed* over `trials` random draws, not a proven worst case. A rare,
structurally-special difference could exist that never shows up in a few
hundred random trials. This is a statistical health check, one step
closer to real cryptanalysis than the structural diffusion checks, but
still not a security proof — and it doesn't address whether the
topology accept/reject process itself biases which architectures a key
can produce, which remains an open question.

A representative single-key run (`cargo run --release --example differential_analysis`):

- F/G in isolation: even a single active input byte reaches 7–8 of 8
  active output bytes almost every trial (mean ~7.96/8) — the
  transformers spread a single-byte difference almost immediately.
- One full round (S→P→F→G): a single active input byte (of 16) reaches
  8–16 active output bytes, mean ~12.4/16 — expected, since one round
  alone isn't meant to fully saturate.
- The 14-round trail: a single active byte reaches a mean of ~13–16/16
  active bytes by round 2 and stays there — but the **minimum observed
  is not monotonic across rounds** (e.g. round 2's minimum can be higher
  than round 3's). That's a genuinely useful finding, not noise: it
  means a difference can partially collapse back down after nearing full
  spread, which is exactly the kind of behavior a real differential
  attack would try to exploit across specific round pairs. It's not
  evidence of a break — occasional partial cancellation is normal even
  in well-designed nonlinear networks — but it's a concrete, non-obvious
  lead for anyone doing the deeper trail-search analysis this section
  doesn't attempt.

The natural next step past this — finding actual high-probability
multi-round differential/linear *characteristics* (not just active-byte
counts) — needs a proper trail search (e.g. branch-and-bound over
round-by-round difference propagation) rather than random sampling, and
is out of scope here. See the next section for a first, narrower step in
that direction.

## Differential propagation: EXACT layer-0 analysis (not sampled)

The section above is honest about its own limit: a sampled minimum
isn't a proven one. This section proves something narrower, but with no
sampling at all — a fully exhaustive result for one well-defined
sub-problem, in `exact_layer0_active_status` / `exact_layer0_single_byte_sweep`.

**Why layer 0 is exactly provable.** Each F/G node's pre-S-box
accumulator is `acc(X) = w1·gf(s1) ⊕ w2·gf(s2) ⊕ w3·gf(s3)`, and GF(2⁸)
multiplication by a constant weight is linear. So

```
Δacc = acc(X ⊕ ΔX) ⊕ acc(X) = w1·Δs1 ⊕ w2·Δs2 ⊕ w3·Δs3
```

does **not depend on the base state X at all** — only on the difference
and the fixed, key-derived weights. And because the layer's S-box is a
bijection, `Δacc == 0` exactly iff that head's output difference is 0:
equal inputs give equal outputs, and *different* accumulator inputs are
guaranteed to give different outputs, for every possible X, no
exceptions. So per-head activity is exactly determined by one XOR/GF(256)
computation — genuinely zero sampling, not "sampling with a bigger N."

**A bug in an earlier version of this section, caught and fixed.** New
state byte `i` is the XOR of every head's contribution at node `i`. If 0
heads have `Δacc ≠ 0`: proven inactive. If exactly 1 head does: proven
active. Both of those are unaffected by the bug. The bug was in the 2+
active heads case: an earlier version checked whether the active heads'
DDT rows merely *intersected* — i.e. whether some difference value `d`
is independently achievable by head 1 for *some* base state, and
independently achievable by head 2 for *some other* base state. That's
necessary for a real collision, but **not sufficient** — both heads read
the *same* underlying state `X`, and row intersection alone doesn't
establish that one shared `X` produces `d` for both simultaneously. It's
a real analysis bug, not just loose wording, and the corrected code keeps
both checks, clearly separated, rather than quietly fixing it in place:

- **`ddt_compatible`** (necessary, not sufficient) — do the rows admit
  *some* combination that XORs to zero, each value chosen independently?
  Computed with a reachable-value DP (`ddt_rows_can_cancel`), O(heads ×
  256 × row size).
- **`jointly_realizable`** (the corrected, actually-exact answer) — does
  a *single* real base state `X` exist producing that cancellation? Each
  active head's accumulator is GF(2)-linear in `X` restricted to its 3
  source bytes, so the *stacked* map across all active heads is itself
  GF(2)-linear, and its true image (the exact set of jointly-achievable
  tuples — not each head's image considered separately) is computed via
  a standard GF(2) XOR/linear basis (`XorBasis64`) and then exhaustively
  checked against the S-box. This is tractable regardless of how many
  input bytes are involved, because the cost only depends on the
  (small, ≤ 32-bit for this cipher's head counts) *output* dimension —
  capped at rank ≤ 20 (~1M enumerated tuples) before honestly falling
  back to `None` (open) rather than guessing.

`ddt_compatible == false` provably implies `jointly_realizable == Some(false)`
(checked as an invariant on every tested case) — if the rows don't even
intersect independently, no shared-`X` solution can exist either.

**Extending past 2 heads for free.** The fix isn't just a correction —
it's also a generalization from "capped at 2 simultaneously-active
heads" (an earlier, more conservative limitation) to any number of
heads, since the rank-based enumeration doesn't care how many heads
contributed to the joint map, only how large its image turns out to be.

**Corrected result**, same sweep as before (all 255 possible single-byte
input differences, every one, at input byte 0, 20 random keys, F and G,
round 0):

```
F: proven_inactive=14025  proven_active=17595  not_ddt_compatible=0
   [of 2+-active-head cases] jointly_realizable=8415  ddt_compatible_but_NOT_realizable=0  rank_exceeded=765
G: proven_inactive=12240  proven_active=16575  not_ddt_compatible=0
   [of 2+-active-head cases] jointly_realizable=9435  ddt_compatible_but_NOT_realizable=0  rank_exceeded=2550
```

Two things worth noting honestly. First, **real, jointly-realizable
zero-difference collisions are still proven to exist** — a genuine base
state `X` was found for thousands of (difference, output-byte) pairs,
not just DDT-row overlap. The empirical `active_byte_expansion` section's
500-trial runs still reported `zero_output_count=0` every time — the gap
between "sampled minimum" and "proven minimum" this section exists to
demonstrate is real regardless of the earlier bug. Second, in this
particular run `ddt_compatible_but_NOT_realizable` came back **0** for
both F and G — every case the (flawed) necessary condition flagged also
turned out, once actually checked, to be jointly realizable. That's a
real, useful data point (it suggests this cipher's specific head/source
structure doesn't create many false positives in practice), **not** a
proof that the two checks always agree — they're different, and are kept
as separate fields precisely so the cases can be told apart when they do
diverge. `rank_exceeded` (765/40800 for F, 2550/40800 for G) is reported
honestly as unresolved rather than assumed either way.

None of this changes the broader picture: it does *not* mean the cipher
is broken (a single-node layer-0 collision doesn't by itself imply
anything about the full 14-round construction), and everything past
layer 0 — deeper layers, full multi-round trails, linear cryptanalysis,
related-key security — remains exactly as open as before. What changed
is that one specific claim moved from "sampled, no collisions seen" to
"exhaustively proven, real collisions exist, and the joint-realizability
check itself is now correct rather than merely necessary-condition
compatible."
