//! The swept peg-ins (SPI) trie – spec 2026-08-06-bridge-state-singleton-design,
//! rules [SPI-1] .. [SPI-4].
//!
//! An MPF ([`mpf::Trie`]) recording every deposit a confirmed Treasury Movement
//! took into the treasury, mirroring [`crate::cardano::cpo_trie::CpoTrie`].
//! Keys and values are both 36-byte outpoints in the `tm_chain::outpoint_bytes`
//! encoding: txid internal order ++ vout LE.
//!
//! - Key: the swept deposit's `peg_in_utxo_id`.
//! - Value: the sweeping TM's own input-0 outpoint [SPI-3] – known before the
//!   TM is serialized, unlike its txid, and unique because a Bitcoin outpoint
//!   is spent once.
//! - [`SpiTrie::insert_for_confirmed_tm`] takes EVERY input of a confirmed TM,
//!   input 0 first, and records every input EXCEPT input 0 [SPI-1]. The epoch
//!   machine calls it once per confirmed TM (`advance_spi_trie`).
//! - [`SpiTrie::verify_proposed`] is the [SPI-2] co-signer gate: it recomputes
//!   the root that must hold after a proposed TM from this node's own trie and
//!   refuses a mismatch. `sign_phase` runs it before any signing material
//!   leaves the node (`verify_spi_root`).
//! - [`SpiTrie::prove_membership`] / [`SpiTrie::prove_non_membership`] verify
//!   via [`mpf::verify_inclusion`] / [`mpf::verify_exclusion`]. heimdall does
//!   NOT serve them over HTTP: [SPI-4] names binocular as the proof server and
//!   forbids heimdall the role — this node's trie is quorum-internal state for
//!   the [SPI-2] gate, and serving proofs from it would hand out roots the
//!   singleton may not hold.
//! - Persisted as `spi-trie.json` in `state_dir` ([`SpiTrie::load`] /
//!   [`SpiTrie::save`]): atomic temp+rename, 0600, with a load-time root
//!   self-check that refuses corrupt state.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cardano::mpf;
use crate::cardano::state_file;

/// The length of an outpoint in the `tm_chain::outpoint_bytes` encoding.
pub const OUTPOINT_LEN: usize = 36;

/// A 36-byte outpoint in the `tm_chain::outpoint_bytes` encoding:
/// txid internal order (32 bytes) ++ vout as 4 little-endian bytes.
pub type Outpoint = [u8; OUTPOINT_LEN];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can stop the swept peg-ins trie from advancing, proving, or
/// loading. Every variant is a refusal to guess: none of them is recoverable by
/// picking a default, because each default would be a root no TM committed.
#[derive(Debug)]
pub enum SpiTrieError {
    /// A confirmed TM was presented with no inputs at all — there is no input 0
    /// to take the value from, so the record is malformed.
    NoInputs,
    /// The same peg-in outpoint appears with a DIFFERENT sweeping-TM value.
    /// A Bitcoin outpoint can be spent once, so one of the sources must be
    /// wrong, and picking either would produce a root no TM ever committed.
    Conflict {
        peg_in_utxo_id: Outpoint,
        existing: Outpoint,
        incoming: Outpoint,
    },
    /// The underlying MPF rejected an operation.
    Mpf(String),
    /// Persisted state could not be read, written, or decoded.
    State(String),
    /// The [SPI-2] co-signer gate: a proposed TM's spi_root does not match the
    /// root this node recomputes from its own trie plus the TM's inputs.
    RootMismatch {
        proposed: [u8; 32],
        expected: [u8; 32],
    },
}

impl fmt::Display for SpiTrieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputs => write!(f, "confirmed TM has no inputs — no input 0 to sweep from"),
            Self::Conflict {
                peg_in_utxo_id,
                existing,
                incoming,
            } => write!(
                f,
                "peg-in outpoint {} recorded as swept by two different TMs ({} and {})",
                hex::encode(peg_in_utxo_id),
                hex::encode(existing),
                hex::encode(incoming)
            ),
            Self::Mpf(m) => write!(f, "MPF: {m}"),
            Self::State(m) => write!(f, "SPI trie state: {m}"),
            Self::RootMismatch { proposed, expected } => write!(
                f,
                "swept peg-ins root mismatch: proposed {}, local trie expects {}",
                hex::encode(proposed),
                hex::encode(expected)
            ),
        }
    }
}

impl std::error::Error for SpiTrieError {}

// ---------------------------------------------------------------------------
// The trie
// ---------------------------------------------------------------------------

/// The swept peg-ins trie plus the entries that built it.
///
/// Mirrors [`crate::cardano::cpo_trie::CpoTrie`]: the entry map is kept
/// alongside the MPF so the trie can be persisted, replayed, and diffed.
/// `BTreeMap` (not `HashMap`) so serialization order is deterministic.
#[derive(Clone, Default)]
pub struct SpiTrie {
    entries: BTreeMap<Outpoint, Outpoint>,
    trie: mpf::Trie,
}

/// The two halves of a [`SpiTrie`]: the entry map and the MPF built from it.
/// Only ever produced and consumed together, so [`insert_entry`] can advance
/// both a scratch copy ([`SpiTrie::applied`]) and a trie under construction
/// ([`SpiTrie::load`]) through one code path.
type TrieState = (BTreeMap<Outpoint, Outpoint>, mpf::Trie);

/// Record one swept deposit: key `peg_in_utxo_id`, value the sweeping TM's
/// input-0 outpoint [SPI-3].
///
/// Re-inserting a key with the SAME value is a no-op (replay tolerance); the
/// same key with a DIFFERENT value is [`SpiTrieError::Conflict`].
fn insert_entry(
    (entries, trie): &mut TrieState,
    peg_in_utxo_id: &Outpoint,
    value: &Outpoint,
) -> Result<(), SpiTrieError> {
    match entries.get(peg_in_utxo_id) {
        Some(existing) if existing == value => return Ok(()),
        Some(existing) => {
            return Err(SpiTrieError::Conflict {
                peg_in_utxo_id: *peg_in_utxo_id,
                existing: *existing,
                incoming: *value,
            });
        }
        None => {}
    }
    *trie = trie
        .insert(peg_in_utxo_id, value)
        .map_err(|e| SpiTrieError::Mpf(format!("insert {}: {e}", hex::encode(peg_in_utxo_id))))?;
    entries.insert(*peg_in_utxo_id, *value);
    Ok(())
}

impl fmt::Debug for SpiTrie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpiTrie")
            .field("root", &hex::encode(self.root()))
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl SpiTrie {
    /// The genesis state: nothing swept yet. Its [`Self::root`] is the empty
    /// MPF root, which is the root a node with no `spi-trie.json` serves.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The current 32-byte root.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.trie.root_hash()
    }

    /// How many deposits are recorded as swept. Not the number of TMs: one TM
    /// contributes one entry per input it took beyond input 0.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True while no deposit has been recorded as swept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a confirmed TM has already swept this deposit. Answers from the
    /// entry map, so it says nothing about proofs; use [`Self::prove_membership`]
    /// when the caller must be convinced rather than told.
    #[must_use]
    pub fn contains(&self, peg_in_utxo_id: &Outpoint) -> bool {
        self.entries.contains_key(peg_in_utxo_id)
    }

    /// The sweeping TM's input-0 outpoint recorded for `peg_in_utxo_id`.
    #[must_use]
    pub fn get(&self, peg_in_utxo_id: &Outpoint) -> Option<&[u8]> {
        self.entries.get(peg_in_utxo_id).map(Outpoint::as_slice)
    }

    /// Every entry, in key order.
    pub fn entries(&self) -> impl Iterator<Item = (&Outpoint, &Outpoint)> {
        self.entries.iter()
    }

    /// Record one confirmed TM's sweep and return the new root.
    ///
    /// `inputs` is EVERY input of the TM, input 0 first. Per [SPI-1] every
    /// input EXCEPT input 0 becomes a key; per [SPI-3] each gets the TM's own
    /// input-0 outpoint as its value.
    ///
    /// All-or-nothing: on any error `self` is untouched.
    pub fn insert_for_confirmed_tm(
        &mut self,
        inputs: &[Outpoint],
    ) -> Result<[u8; 32], SpiTrieError> {
        let (next_entries, next_trie) = self.applied(inputs)?;
        self.entries = next_entries;
        self.trie = next_trie;
        Ok(self.trie.root_hash())
    }

    /// The root that would hold after `inputs` were recorded, WITHOUT mutating
    /// self. With a TM that sweeps nothing (only input 0) this is [`Self::root`].
    pub fn root_after(&self, inputs: &[Outpoint]) -> Result<[u8; 32], SpiTrieError> {
        Ok(self.applied(inputs)?.1.root_hash())
    }

    /// The [SPI-2] co-signer gate: recompute the spi_root a proposed TM must
    /// commit — the local trie advanced by the TM's `inputs` — and compare it
    /// with `proposed_root`. Returns the recomputed root on a match; a
    /// mismatch is [`SpiTrieError::RootMismatch`]. Never mutates `self`.
    pub fn verify_proposed(
        &self,
        proposed_root: &[u8; 32],
        inputs: &[Outpoint],
    ) -> Result<[u8; 32], SpiTrieError> {
        let expected = self.root_after(inputs)?;
        if expected != *proposed_root {
            return Err(SpiTrieError::RootMismatch {
                proposed: *proposed_root,
                expected,
            });
        }
        Ok(expected)
    }

    /// The (entries, trie) pair after applying one TM's `inputs`, leaving
    /// `self` alone.
    fn applied(&self, inputs: &[Outpoint]) -> Result<TrieState, SpiTrieError> {
        let (input0, swept) = inputs.split_first().ok_or(SpiTrieError::NoInputs)?;
        let mut state = (self.entries.clone(), self.trie.clone());
        for key in swept {
            insert_entry(&mut state, key, input0)?;
        }
        Ok(state)
    }

    // --- proofs [SPI-4] ----------------------------------------------------

    /// A membership proof for a swept peg-in outpoint, verifiable with
    /// [`mpf::verify_inclusion`] against [`Self::root`].
    pub fn prove_membership(&self, peg_in_utxo_id: &Outpoint) -> Result<mpf::Proof, SpiTrieError> {
        self.trie
            .prove_membership(peg_in_utxo_id)
            .map_err(|e| SpiTrieError::Mpf(format!("{e:?}")))
    }

    /// A non-membership proof for an unswept outpoint, verifiable with
    /// [`mpf::verify_exclusion`] against [`Self::root`].
    pub fn prove_non_membership(
        &self,
        peg_in_utxo_id: &Outpoint,
    ) -> Result<mpf::Proof, SpiTrieError> {
        self.trie
            .prove_non_membership(peg_in_utxo_id)
            .map_err(|e| SpiTrieError::Mpf(format!("{e:?}")))
    }

    // --- persistence -------------------------------------------------------

    /// The trie state file inside `state_dir`.
    #[must_use]
    pub fn state_path(state_dir: &Path) -> PathBuf {
        state_dir.join("spi-trie.json")
    }

    /// Load the persisted trie. `Ok(None)` when the file does not exist.
    ///
    /// A file whose recorded root does not match the root recomputed from its
    /// own entries is rejected rather than silently trusted — same discipline
    /// as `CpoTrie::load`.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, SpiTrieError> {
        let path = Self::state_path(state_dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(SpiTrieError::State(format!("read {}: {e}", path.display())));
            }
        };
        let persisted: PersistedSpiTrie = serde_json::from_slice(&bytes)
            .map_err(|e| SpiTrieError::State(format!("decode {}: {e}", path.display())))?;
        if persisted.version != SPI_STATE_VERSION {
            return Err(SpiTrieError::State(format!(
                "{}: unsupported state version {} (expected {SPI_STATE_VERSION})",
                path.display(),
                persisted.version
            )));
        }
        let mut state = TrieState::default();
        for e in &persisted.entries {
            let key = outpoint_from_hex(&e.peg_in_utxo_id)?;
            let value = outpoint_from_hex(&e.value)?;
            insert_entry(&mut state, &key, &value)?;
        }
        let trie = Self {
            entries: state.0,
            trie: state.1,
        };
        let expected = hex::encode(trie.root());
        if expected != persisted.root.to_ascii_lowercase() {
            return Err(SpiTrieError::State(format!(
                "{}: recorded root {} but its {} entries hash to {} — refusing to load \
                 corrupt trie state",
                path.display(),
                persisted.root,
                persisted.entries.len(),
                expected,
            )));
        }
        Ok(Some(trie))
    }

    /// Load the persisted trie, falling back to the genesis (empty) trie when
    /// `state_dir` is unset or holds no file yet. A node that keeps no state has
    /// swept nothing, which is what both the TM builder and the [SPI-2]
    /// co-signer gate need. A file that exists but is corrupt is still an error.
    pub fn load_or_empty(state_dir: Option<&Path>) -> Result<Self, SpiTrieError> {
        match state_dir {
            Some(dir) => Ok(Self::load(dir)?.unwrap_or_default()),
            None => Ok(Self::empty()),
        }
    }

    /// Persist atomically (write a temp file, then rename), 0600, in a 0700
    /// directory — the same discipline as `CpoTrie::save`.
    pub fn save(&self, state_dir: &Path) -> Result<(), SpiTrieError> {
        let persisted = PersistedSpiTrie {
            version: SPI_STATE_VERSION,
            root: hex::encode(self.root()),
            entries: self
                .entries
                .iter()
                .map(|(k, v)| PersistedSpiEntry {
                    peg_in_utxo_id: hex::encode(k),
                    value: hex::encode(v),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&persisted)
            .map_err(|e| SpiTrieError::State(format!("encode: {e}")))?;
        state_file::write_atomic_0600(state_dir, &Self::state_path(state_dir), &bytes)
            .map_err(SpiTrieError::State)
    }
}

/// The builder-facing view: `build_tm` computes the `spi_root` its BTMR1
/// commitment carries through this trait, keeping the `bitcoin` modules free of
/// a `cardano` dependency (same story as `CpoTrieView`).
impl crate::bitcoin::tm_builder::SpiTrieView for SpiTrie {
    fn root_after_inputs(&self, inputs: &[[u8; 36]]) -> Result<[u8; 32], String> {
        self.root_after(inputs).map_err(|e| e.to_string())
    }
}

fn outpoint_from_hex(s: &str) -> Result<Outpoint, SpiTrieError> {
    let v = hex::decode(s.trim())
        .map_err(|e| SpiTrieError::State(format!("outpoint hex '{s}': {e}")))?;
    v.try_into().map_err(|v: Vec<u8>| {
        SpiTrieError::State(format!(
            "outpoint '{s}' is {} bytes, expected {OUTPOINT_LEN}",
            v.len()
        ))
    })
}

const SPI_STATE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct PersistedSpiTrie {
    version: u32,
    /// Recorded for the load-time self-check; recomputed on load, never trusted.
    root: String,
    entries: Vec<PersistedSpiEntry>,
}

#[derive(Serialize, Deserialize)]
struct PersistedSpiEntry {
    peg_in_utxo_id: String,
    value: String,
}

#[cfg(test)]
mod tests {
    use super::{Outpoint, SpiTrie};
    use crate::cardano::mpf;

    /// A 36-byte outpoint: txid internal order (32 bytes of `b`) ++ vout LE.
    fn op(b: u8, vout: u32) -> Outpoint {
        let mut o = [b; 36];
        o[32..].copy_from_slice(&vout.to_le_bytes());
        o
    }

    // [SPI-1]: every input of a confirmed TM goes into the trie, EXCEPT
    // input 0 (the treasury outpoint the TM sweeps forward).
    #[test]
    fn insert_for_confirmed_tm_excludes_input_0() {
        let t = op(0xaa, 0); // input 0: the previous treasury outpoint
        let a = op(0x01, 0); // a swept peg-in deposit
        let b = op(0x02, 3); // another swept peg-in deposit
        let mut trie = SpiTrie::empty();
        let root = trie.insert_for_confirmed_tm(&[t, a, b]).unwrap();
        assert_eq!(root, trie.root(), "insert returns the new root");
        assert_eq!(trie.len(), 2, "inputs [t, a, b] add exactly keys a and b");
        assert!(trie.contains(&a));
        assert!(trie.contains(&b));
        assert!(
            !trie.contains(&t),
            "input 0 (the treasury outpoint) must NOT become a trie key"
        );
        assert_ne!(trie.root(), SpiTrie::empty().root());
    }

    // [SPI-3]: all entries one TM adds share that TM's input-0 outpoint as
    // their value.
    #[test]
    fn entries_of_one_tm_share_the_input0_outpoint_value() {
        let t = op(0xaa, 0);
        let a = op(0x01, 0);
        let b = op(0x02, 3);
        let mut trie = SpiTrie::empty();
        trie.insert_for_confirmed_tm(&[t, a, b]).unwrap();
        assert_eq!(trie.get(&a), Some(t.as_slice()));
        assert_eq!(trie.get(&b), Some(t.as_slice()));

        // A second TM's entries carry the SECOND TM's input 0, not the first's.
        let t2 = op(0xbb, 0);
        let c = op(0x03, 1);
        trie.insert_for_confirmed_tm(&[t2, c]).unwrap();
        assert_eq!(trie.get(&c), Some(t2.as_slice()));
        assert_eq!(
            trie.get(&a),
            Some(t.as_slice()),
            "earlier entries keep their value"
        );
    }

    // [SPI-2]: before signing, recompute the spi_root the proposed TM must
    // commit from the local trie plus the TM's inputs. A mismatch is an error
    // and the local trie stays untouched.
    #[test]
    fn verify_proposed_recomputes_spi_root_and_rejects_mismatch() {
        let mut base = SpiTrie::empty();
        base.insert_for_confirmed_tm(&[op(0x10, 0), op(0x11, 0)])
            .unwrap();
        let base_root = base.root();

        let inputs = [op(0xaa, 0), op(0x01, 0), op(0x02, 3)];
        // The honest proposer's root: what the trie holds after this TM.
        let mut advanced = base.clone();
        let expected = advanced.insert_for_confirmed_tm(&inputs).unwrap();

        // A correct proposed root passes, returns the recomputed root, and
        // does not mutate the verifier's trie.
        let got = base.verify_proposed(&expected, &inputs).unwrap();
        assert_eq!(got, expected);
        assert_eq!(base.root(), base_root, "verify_proposed must not mutate");
        assert_eq!(base.len(), 1);

        // A proposed root that does not match the recomputation is an error.
        let wrong = base_root; // stale: misses this TM's entries
        assert!(
            base.verify_proposed(&wrong, &inputs).is_err(),
            "a stale/mismatched spi_root must be refused"
        );
    }

    // [SPI-4]: the trie must produce membership AND non-membership proofs
    // that verify against its root with the shared mpf verifiers.
    #[test]
    fn membership_proof_verifies_and_non_membership_proof_verifies() {
        let t = op(0xaa, 0);
        let a = op(0x01, 0);
        let b = op(0x02, 3);
        let mut trie = SpiTrie::empty();
        trie.insert_for_confirmed_tm(&[t, a, b]).unwrap();
        let root = trie.root();

        // Membership: key a maps to the sweeping TM's input-0 outpoint t.
        let proof = trie.prove_membership(&a).unwrap();
        mpf::verify_inclusion(&a, &t, &proof, &root)
            .expect("membership proof for a swept deposit verifies");

        // Non-membership: a never-swept outpoint.
        let absent = op(0x7f, 9);
        let ex = trie.prove_non_membership(&absent).unwrap();
        mpf::verify_exclusion(&absent, &ex, &root)
            .expect("non-membership proof for an unswept outpoint verifies");
    }

    // Persistence: a saved trie loads back with the same root and the same
    // entries, a missing file is the genesis state, and a file whose recorded
    // root does not match its own entries is refused rather than trusted.
    #[test]
    fn save_then_load_round_trips_and_a_corrupt_root_is_refused() {
        let dir = std::env::temp_dir().join(format!("spi-persist-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            SpiTrie::load(&dir).unwrap().is_none(),
            "no file yet is Ok(None), not an error"
        );

        let t = op(0xaa, 0);
        let a = op(0x01, 0);
        let b = op(0x02, 3);
        let mut trie = SpiTrie::empty();
        trie.insert_for_confirmed_tm(&[t, a, b]).unwrap();
        trie.save(&dir).unwrap();

        let loaded = SpiTrie::load(&dir).unwrap().expect("the saved trie loads");
        assert_eq!(loaded.root(), trie.root());
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get(&a), Some(t.as_slice()));
        assert_eq!(loaded.get(&b), Some(t.as_slice()));

        // Tamper with the recorded root: the load-time self-check must refuse.
        let path = SpiTrie::state_path(&dir);
        let text = std::fs::read_to_string(&path).unwrap();
        let corrupt = text.replace(&hex::encode(trie.root()), &hex::encode([0u8; 32]));
        std::fs::write(&path, corrupt).unwrap();
        SpiTrie::load(&dir).expect_err("a root that does not match the entries is refused");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
