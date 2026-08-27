//! KGRTC: an experimental, unaudited key-generated reversible
//! transformer block cipher.
//!
//! **Not for protecting real data -- see `SECURITY.md` at the repo
//! root.** For design rationale and what's proven versus merely
//! observed about the S-box and F/G topology, see `docs/DESIGN.md`; for
//! the differential-propagation analysis, see
//! `docs/DIFFERENTIAL_ANALYSIS.md`.

pub mod analyzer;
pub mod cipher;
