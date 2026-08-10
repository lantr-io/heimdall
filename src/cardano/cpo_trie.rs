//! The completed-peg-outs (CPO) trie — heimdall's off-chain copy of the MPF whose
//! root every Treasury Movement attests.
//!
//! ## What the trie is
//!
//! Since rev 5.1 a peg-out is completed by proving MEMBERSHIP in an MPF, not by
//! re-scanning Bitcoin. `peg-out.ak`'s `CompletePegOut` branch checks
//!
//! ```text
//! mpf.has(completed_peg_outs, por_id, dest_spk ++ le8(locked - per_pegout_fee), proof)
//! ```
//!
//! so the trie is keyed by [`por_id`] and valued by [`trie_value`]. Both encodings
//! are load-bearing: change either and every peg-out completion stops verifying.
//!
//! ## Where the root comes from
//!
//! The root is **attested, not derived**. Each FROST-signed TM carries exactly one
//! `"CPOR1"` OP_RETURN output holding the root that must hold after it, and the
//! on-chain Confirm transition copies that root into the CPO singleton UTxO. The
//! chain therefore never recomputes the root — the quorum's signature is the only
//! integrity anchor.
//!
//! That puts the whole burden on the co-signers, which is what [`CpoTrie`] exists
//! for: every SPO keeps its own trie, and before signing recomputes the root the
//! proposed TM should commit ([`CpoTrie::verify_proposed`]). A leader proposing a
//! wrong root fails quorum.
//!
//! ## Persistence and reconstruction
//!
//! The trie is durable local state ([`CpoTrie::save`] / [`CpoTrie::load`], the same
//! 0600 atomic-rename pattern as the DKG state). It is also fully derivable from
//! chain history ([`reconstruct`]) for a cold start, a recovery, or a newly joined
//! SPO — that path must read the inline datums of SPENT outputs, because the
//! data-availability hint lives in the `Unconfirmed` record its own Confirm
//! transition consumes.
//!
//! Two backends serve that read, behind
//! [`crate::cardano::cpo_history::CpoHistorySource`]: a Kupo index (the production
//! recommendation for SPOs) and a plain Blockfrost-compatible API (heavier, for
//! test environments, demos, and non-SPO tooling). The ALGORITHM below is shared
//! verbatim — the backend decides only where the bytes come from.
//!
//! ## Datum-less outputs at bridge addresses
//!
//! Both the TM address and the peg-out address are permissionlessly payable, so
//! [`reconstruct`] reads a THREE-way state per output
//! ([`crate::cardano::cpo_history::DatumState`]), not a two-way one:
//!
//! - **No datum at all** ([`DatumState::Absent`]) is SKIPPED, even at the TM
//!   address. Every genuine `Unconfirmed`/`Confirmed` record, and every genuine
//!   peg-out request, is created with an inline datum, so a bare payment provably
//!   is not one.
//! - **A datum that exists but cannot be read** ([`DatumState::Unresolved`]) is a
//!   HARD ERROR at the TM address, naming the output. It might be an unread
//!   `Confirmed` record, and dropping it would yield a trie that silently omits a
//!   whole movement while still looking complete.
//!
//! Conflating the two — treating any absent datum as fatal — let a single junk,
//! datum-less payment to the TM address block reconstruction forever, for every
//! SPO. This module now matches binocular's Scala mirror,
//! `binocular.watchtower.CpoReconstruction` (`scanTmAddress`), which draws the
//! same distinction.
//!
//! The asymmetry between the two addresses is intentional and unchanged: an
//! UNRESOLVABLE datum at the PEG-OUT address is a skip, never fatal, because a
//! missing request cannot shrink the trie silently — it just makes some TM fail
//! its own running-root assertion, by name.
//!
//! ## Cardano rollbacks
//!
//! The persisted trie is APPEND-ONLY and has NO automatic rollback handling. A
//! Cardano rollback that un-confirms a Treasury Movement leaves this node's trie
//! holding entries the chain no longer backs, and every root it then proposes is
//! ahead of the quorum's.
//!
//! That failure is loud, not silent: the co-signer gate refuses to sign, and
//! [`CpoTrie::load`]'s successor `advance_cpo_trie` refuses to persist a root the
//! confirming TM did not commit. **Recovery is a full `reconstruct-cpo-trie`**,
//! which rebuilds from the post-rollback chain and cross-checks the result against
//! the on-chain CPO singleton.
//!
//! Rollbacks are already bounded here: [`crate::epoch::machine`] only advances the
//! trie after a TM is CONFIRMED, and a Bitcoin-confirmed movement deep enough to
//! have been oracle-proven is not a shallow reorg candidate. Automatic rollback
//! handling (watching for a chain-point regression and truncating the trie) is a
//! tracked follow-up, deliberately NOT implemented here — it needs a persisted
//! chain point per entry and a rollback signal heimdall does not yet consume.
//!
//! ## Query surface
//!
//! Steady-state operation (build, co-sign, publish) touches ONLY the
//! Blockfrost-compatible subset a Dolos node serves — see `cardano::bf_http`.
//! History queries happen exclusively inside [`reconstruct`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};

use pallas_primitives::PlutusData;
use serde::{Deserialize, Serialize};

use crate::bitcoin::tm_builder::{
    CPO_COMMITMENT_PREFIX, CPO_COMMITMENT_SCRIPT_LEN, CpoTrieView, FulfilledPegOut,
};
use crate::cardano::cpo_history::{CpoHistorySource, DatumState};
use crate::cardano::mpf;
use crate::cardano::treasury_datum::{ConfirmedTm, TreasuryDatumError, parse_confirmed_tm_datum};
use tracing::{info, warn};

/// Asset name of the completed-peg-outs trie NFT — Aiken
/// `bifrost/constants.ak::completed_peg_outs_root_asset_name`, the 3 ASCII bytes
/// `"CPO"`.
pub const CPO_ASSET_NAME: &[u8] = b"CPO";

/// Hex of [`CPO_ASSET_NAME`], for asset-unit strings.
pub const CPO_ASSET_NAME_HEX: &str = "43504f";

/// The genesis root: 32 zero bytes.
///
/// This is BOTH the MPF empty root (`mpf::Trie::empty().root_hash()`, confirmed
/// against scalus in the golden vectors) and the literal the Aiken bootstrap mint
/// pins in the genesis trie datum. The two agree, so a freshly bootstrapped bridge
/// and a freshly created [`CpoTrie`] are already in sync — no special-casing.
pub const EMPTY_ROOT: [u8; 32] = [0u8; 32];

/// The maximum number of candidate assignments the fallback matcher will try
/// before giving up on a TM. Reconstruction is a rare, operator-visible operation,
/// so a bounded search that reports failure beats an unbounded one that hangs.
const FALLBACK_SEARCH_BUDGET: usize = 200_000;

// ---------------------------------------------------------------------------
// Key / value encodings
// ---------------------------------------------------------------------------

/// `por_id` = `sha2_256(serialise_data(OutputReference{transaction_id, output_index}))`.
///
/// Aiken `bifrost/utils.hash_output_ref`, applied to the peg-out request UTxO's own
/// outpoint — `peg-out.ak` recomputes it on-chain from
/// `peg_out_input.output_reference`, so the encoding must match the Plutus
/// `serialiseData` builtin exactly. Delegates to the already-golden-tested
/// implementation in `cardano::treasury_bootstrap` rather than repeating it.
#[must_use]
pub fn por_id(tx_hash: &[u8; 32], output_index: u64) -> [u8; 32] {
    crate::cardano::treasury_bootstrap::hash_output_ref(tx_hash, output_index)
}

/// The trie value for a fulfilled peg-out: `scriptPubKey ‖ net amount as 8
/// little-endian bytes`.
///
/// Mirrors binocular's `CompletedPegOutsTrie.trieValue` and the bytes
/// `peg-out.ak` rebuilds with
/// `bytearray.concat(dest, integer_to_bytearray(False, 8, net))`.
#[must_use]
pub fn trie_value(script_pubkey: &[u8], net_sat: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(script_pubkey.len() + 8);
    v.extend_from_slice(script_pubkey);
    v.extend_from_slice(&net_sat.to_le_bytes());
    v
}

/// A Cardano outpoint in the 36-byte hint encoding: tx hash (32) ‖ output index
/// as 4 little-endian bytes. This is what a TM datum's `fulfilled_por_outpoints`
/// carries.
#[must_use]
pub fn hint_bytes(tx_hash: &[u8; 32], output_index: u32) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..32].copy_from_slice(tx_hash);
    out[32..].copy_from_slice(&output_index.to_le_bytes());
    out
}

/// Inverse of [`hint_bytes`]. `None` on any length other than 36 — a hint is
/// unverified attacker-supplied data, so a malformed entry must be rejected, not
/// guessed at.
#[must_use]
pub fn parse_hint(b: &[u8]) -> Option<([u8; 32], u32)> {
    if b.len() != 36 {
        return None;
    }
    let mut tx = [0u8; 32];
    tx.copy_from_slice(&b[..32]);
    let idx = u32::from_le_bytes(b[32..36].try_into().ok()?);
    Some((tx, idx))
}

/// Parse a Cardano tx-hash hex string into 32 bytes.
fn tx_hash_from_hex(s: &str) -> Result<[u8; 32], CpoTrieError> {
    let v = hex::decode(s.trim())
        .map_err(|e| CpoTrieError::Decode(format!("tx hash hex '{s}': {e}")))?;
    v.try_into()
        .map_err(|v: Vec<u8>| CpoTrieError::Decode(format!("tx hash '{s}' is {} bytes", v.len())))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum CpoTrieError {
    /// The same `por_id` appears twice with DIFFERENT values. One source must be
    /// wrong and picking either would produce a root no TM ever committed.
    Conflict {
        por_id: [u8; 32],
        existing: Vec<u8>,
        incoming: Vec<u8>,
    },
    /// The underlying MPF rejected an operation.
    Mpf(String),
    /// Persisted state could not be read, written, or decoded.
    State(String),
    /// A chain value could not be decoded.
    Decode(String),
    /// Reconstruction could not account for a TM: its committed root does not
    /// match any assignment of open peg-out requests to its payment outputs.
    Unreconstructable {
        btc_txid: [u8; 32],
        committed_root: [u8; 32],
        reason: String,
    },
    /// The network / index layer failed — either backend (see
    /// [`crate::cardano::cpo_history`]).
    Source(String),
    /// Reconstruction finished, but the trie it produced does not match the root
    /// the on-chain CPO singleton holds. The replay is missing or inventing
    /// entries; using it would make this node sign roots the chain disagrees with,
    /// and produce membership proofs `peg-out.ak` rejects.
    RootMismatch {
        reconstructed: [u8; 32],
        on_chain: [u8; 32],
        entries: usize,
    },
}

impl fmt::Display for CpoTrieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict {
                por_id,
                existing,
                incoming,
            } => write!(
                f,
                "POR id {} recorded twice with different values ({} and {})",
                hex::encode(por_id),
                hex::encode(existing),
                hex::encode(incoming)
            ),
            Self::Mpf(m) => write!(f, "MPF: {m}"),
            Self::State(m) => write!(f, "CPO trie state: {m}"),
            Self::Decode(m) => write!(f, "decode: {m}"),
            Self::Unreconstructable {
                btc_txid,
                committed_root,
                reason,
            } => write!(
                f,
                "cannot reconstruct TM {} (commits root {}): {reason}",
                hex::encode(btc_txid),
                hex::encode(committed_root)
            ),
            Self::Source(m) => write!(f, "chain history: {m}"),
            Self::RootMismatch {
                reconstructed,
                on_chain,
                entries,
            } => write!(
                f,
                "reconstruction produced root {} over {entries} entr(y|ies), but the on-chain \
                 completed-peg-outs singleton holds {} — refusing to persist a trie the chain \
                 disagrees with",
                hex::encode(reconstructed),
                hex::encode(on_chain),
            ),
        }
    }
}

impl std::error::Error for CpoTrieError {}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/// One completed peg-out, as the trie stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpoEntry {
    pub por_id: [u8; 32],
    pub value: Vec<u8>,
}

impl CpoEntry {
    #[must_use]
    pub fn new(por_id: [u8; 32], script_pubkey: &[u8], net_sat: u64) -> Self {
        Self {
            por_id,
            value: trie_value(script_pubkey, net_sat),
        }
    }
}

impl From<&FulfilledPegOut> for CpoEntry {
    fn from(f: &FulfilledPegOut) -> Self {
        Self {
            por_id: f.por_id,
            value: f.trie_value(),
        }
    }
}

// ---------------------------------------------------------------------------
// The trie
// ---------------------------------------------------------------------------

/// The completed-peg-outs trie plus the entries that built it.
///
/// The entries are kept alongside the MPF so the trie can be persisted, replayed,
/// and diffed. `BTreeMap` (not `HashMap`) so serialization order is deterministic
/// — a persisted file that differs only by map iteration order is a false
/// divergence signal for an operator comparing two nodes.
#[derive(Clone, Default)]
pub struct CpoTrie {
    entries: BTreeMap<[u8; 32], Vec<u8>>,
    trie: mpf::Trie,
}

/// The two halves of a [`CpoTrie`]: the entry map and the MPF built from it. They
/// are only ever produced and consumed together, by [`CpoTrie::applied`].
type TrieState = (BTreeMap<[u8; 32], Vec<u8>>, mpf::Trie);

impl fmt::Debug for CpoTrie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpoTrie")
            .field("root", &hex::encode(self.root()))
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl CpoTrie {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
            trie: mpf::Trie::empty(),
        }
    }

    /// The current 32-byte root — what a TM built now would commit if it fulfilled
    /// nothing.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.trie.root_hash()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn contains(&self, por_id: &[u8; 32]) -> bool {
        self.entries.contains_key(por_id)
    }

    #[must_use]
    pub fn get(&self, por_id: &[u8; 32]) -> Option<&[u8]> {
        self.entries.get(por_id).map(Vec::as_slice)
    }

    /// Every entry, in `por_id` order.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8; 32], &[u8])> {
        self.entries.iter().map(|(k, v)| (k, v.as_slice()))
    }

    /// Insert `entries` and return the new root.
    ///
    /// Re-inserting a `por_id` with the SAME value is a no-op: a TM that pays a
    /// peg-out the trie already records changes nothing, and reconstruction may
    /// legitimately see one completion twice. A `por_id` with a DIFFERENT value is
    /// [`CpoTrieError::Conflict`] — silently picking one would produce a root no
    /// TM ever committed.
    ///
    /// All-or-nothing: on any error `self` is untouched, so a caller that retries
    /// with a corrected batch is not building on half-applied state.
    pub fn insert_batch(&mut self, entries: &[CpoEntry]) -> Result<[u8; 32], CpoTrieError> {
        let (next_entries, next_trie) = self.applied(entries)?;
        self.entries = next_entries;
        self.trie = next_trie;
        Ok(self.trie.root_hash())
    }

    /// The root that would hold after `entries` were inserted, WITHOUT mutating
    /// self. With an empty slice this is [`Self::root`].
    pub fn root_after(&self, entries: &[CpoEntry]) -> Result<[u8; 32], CpoTrieError> {
        Ok(self.applied(entries)?.1.root_hash())
    }

    /// Recompute the root a proposed TM should commit, and compare.
    ///
    /// This is the co-signer gate. `proposed_root` is the root read out of the
    /// TM's `"CPOR1"` output; `entries` is the peg-out set the verifier
    /// independently determined the TM fulfils. A mismatch means the proposer's
    /// trie disagrees with this node's, and this node MUST refuse to sign — the
    /// root is attested, so an unchallenged wrong root becomes chain truth.
    pub fn verify_proposed(
        &self,
        proposed_root: &[u8; 32],
        entries: &[CpoEntry],
    ) -> Result<(), CpoTrieError> {
        let expected = self.root_after(entries)?;
        if expected != *proposed_root {
            return Err(CpoTrieError::Mpf(format!(
                "completed-peg-outs root mismatch: proposed {}, local trie expects {} \
                 after {} fulfilled peg-out(s) (local trie holds {} entr(y|ies), root {})",
                hex::encode(proposed_root),
                hex::encode(expected),
                entries.len(),
                self.entries.len(),
                hex::encode(self.root()),
            )));
        }
        Ok(())
    }

    /// The (entries, trie) pair after applying `entries`, leaving `self` alone.
    fn applied(&self, entries: &[CpoEntry]) -> Result<TrieState, CpoTrieError> {
        let mut next_entries = self.entries.clone();
        let mut next_trie = self.trie.clone();
        for e in entries {
            match next_entries.get(&e.por_id) {
                Some(existing) if *existing == e.value => continue,
                Some(existing) => {
                    return Err(CpoTrieError::Conflict {
                        por_id: e.por_id,
                        existing: existing.clone(),
                        incoming: e.value.clone(),
                    });
                }
                None => {}
            }
            next_trie = next_trie.insert(&e.por_id, &e.value).map_err(|err| {
                CpoTrieError::Mpf(format!("insert {}: {err}", hex::encode(e.por_id)))
            })?;
            next_entries.insert(e.por_id, e.value.clone());
        }
        Ok((next_entries, next_trie))
    }

    /// Build a trie holding exactly `entries`. Insertion ORDER IS IRRELEVANT — an
    /// MPF root is a function of the key/value set — so callers need not
    /// reconstruct the TM chain to compute a root.
    pub fn from_entries(entries: &[CpoEntry]) -> Result<Self, CpoTrieError> {
        let mut t = Self::empty();
        t.insert_batch(entries)?;
        Ok(t)
    }

    // --- persistence -------------------------------------------------------

    /// The trie state file inside `state_dir`.
    #[must_use]
    pub fn state_path(state_dir: &Path) -> PathBuf {
        state_dir.join("cpo-trie.json")
    }

    /// Load the persisted trie. `Ok(None)` when the file does not exist (a first
    /// run — the caller decides between "start empty" and "reconstruct").
    ///
    /// A file whose recorded root does not match the root recomputed from its own
    /// entries is rejected rather than silently trusted: it means the file was
    /// edited, truncated, or written by an incompatible MPF, and every root this
    /// node then attests would be wrong.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, CpoTrieError> {
        let path = Self::state_path(state_dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(CpoTrieError::State(format!("read {}: {e}", path.display())));
            }
        };
        let persisted: PersistedCpoTrie = serde_json::from_slice(&bytes)
            .map_err(|e| CpoTrieError::State(format!("decode {}: {e}", path.display())))?;
        if persisted.version != CPO_STATE_VERSION {
            return Err(CpoTrieError::State(format!(
                "{}: unsupported state version {} (expected {CPO_STATE_VERSION})",
                path.display(),
                persisted.version
            )));
        }
        let mut entries = Vec::with_capacity(persisted.entries.len());
        for e in &persisted.entries {
            let por_id: [u8; 32] = hex::decode(&e.por_id)
                .map_err(|err| CpoTrieError::State(format!("por_id hex: {err}")))?
                .try_into()
                .map_err(|v: Vec<u8>| {
                    CpoTrieError::State(format!("por_id is {} bytes, expected 32", v.len()))
                })?;
            let value = hex::decode(&e.value)
                .map_err(|err| CpoTrieError::State(format!("value hex: {err}")))?;
            entries.push(CpoEntry { por_id, value });
        }
        let trie = Self::from_entries(&entries)?;
        let expected = hex::encode(trie.root());
        if expected != persisted.root.to_ascii_lowercase() {
            return Err(CpoTrieError::State(format!(
                "{}: recorded root {} but its {} entries hash to {} — refusing to load \
                 corrupt trie state",
                path.display(),
                persisted.root,
                entries.len(),
                expected,
            )));
        }
        Ok(Some(trie))
    }

    /// Persist atomically (write a temp file, then rename), 0600, in a 0700
    /// directory — the same discipline as the DKG state. The trie is not secret,
    /// but it decides what this node signs, so it gets the same tamper surface.
    pub fn save(&self, state_dir: &Path) -> Result<(), CpoTrieError> {
        let persisted = PersistedCpoTrie {
            version: CPO_STATE_VERSION,
            root: hex::encode(self.root()),
            entries: self
                .entries
                .iter()
                .map(|(k, v)| PersistedEntry {
                    por_id: hex::encode(k),
                    value: hex::encode(v),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&persisted)
            .map_err(|e| CpoTrieError::State(format!("encode: {e}")))?;
        create_dir_0700(state_dir)?;
        let path = Self::state_path(state_dir);
        let tmp = path.with_extension("tmp");
        write_file_0600(&tmp, &bytes)?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| CpoTrieError::State(format!("rename to {}: {e}", path.display())))?;
        Ok(())
    }
}

impl CpoTrieView for CpoTrie {
    fn contains(&self, por_id: &[u8; 32]) -> bool {
        CpoTrie::contains(self, por_id)
    }

    fn root_after(&self, fulfilled: &[FulfilledPegOut]) -> Result<[u8; 32], String> {
        let entries: Vec<CpoEntry> = fulfilled.iter().map(CpoEntry::from).collect();
        CpoTrie::root_after(self, &entries).map_err(|e| e.to_string())
    }
}

const CPO_STATE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct PersistedCpoTrie {
    version: u32,
    /// Recorded for the load-time self-check; recomputed on load, never trusted.
    root: String,
    entries: Vec<PersistedEntry>,
}

#[derive(Serialize, Deserialize)]
struct PersistedEntry {
    por_id: String,
    value: String,
}

#[cfg(unix)]
fn create_dir_0700(dir: &Path) -> Result<(), CpoTrieError> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| CpoTrieError::State(format!("create {}: {e}", dir.display())))
}

#[cfg(not(unix))]
fn create_dir_0700(dir: &Path) -> Result<(), CpoTrieError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| CpoTrieError::State(format!("create {}: {e}", dir.display())))
}

#[cfg(unix)]
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), CpoTrieError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CpoTrieError::State(format!("open {}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| CpoTrieError::State(format!("write {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| CpoTrieError::State(format!("sync {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), CpoTrieError> {
    std::fs::write(path, bytes)
        .map_err(|e| CpoTrieError::State(format!("write {}: {e}", path.display())))
}

// ---------------------------------------------------------------------------
// Reading the commitment out of a Confirmed TM datum
// ---------------------------------------------------------------------------

/// The completed-peg-outs root a Confirmed TM record attests.
///
/// The Confirmed datum's `fulfilled_peg_outs` is EVERY output of the raw BTC tx,
/// commitment included, so the root is readable straight from chain state without
/// re-parsing Bitcoin bytes. Same rule as on-chain: exactly one commitment output.
pub fn confirmed_committed_root(tm: &ConfirmedTm) -> Result<[u8; 32], String> {
    let mut found = None;
    let mut count = 0usize;
    for out in &tm.outputs {
        let spk = &out.script_pub_key;
        if spk.len() == CPO_COMMITMENT_SCRIPT_LEN
            && spk[..CPO_COMMITMENT_PREFIX.len()] == CPO_COMMITMENT_PREFIX
        {
            count += 1;
            let mut root = [0u8; 32];
            root.copy_from_slice(&spk[CPO_COMMITMENT_PREFIX.len()..]);
            found = Some(root);
        }
    }
    match count {
        1 => Ok(found.expect("count == 1")),
        0 => Err("missing root commitment (no \"CPOR1\" output)".to_string()),
        n => Err(format!("multiple root commitments ({n})")),
    }
}

/// The TM's actual peg-out PAYMENTS: every output except the treasury
/// continuation (index 0) and the commitment.
#[must_use]
pub fn confirmed_payments(tm: &ConfirmedTm) -> Vec<(Vec<u8>, u64)> {
    tm.outputs
        .iter()
        .skip(1)
        .filter(|o| {
            !(o.script_pub_key.len() == CPO_COMMITMENT_SCRIPT_LEN
                && o.script_pub_key[..CPO_COMMITMENT_PREFIX.len()] == CPO_COMMITMENT_PREFIX)
        })
        .map(|o| (o.script_pub_key.clone(), o.amount))
        .collect()
}

/// The rev-5.1 data-availability hint from an Unconfirmed TM datum: field 5,
/// `fulfilled_por_outpoints`.
///
/// Tolerates the OLD 5-field shape (returns an empty hint) — those records confirm
/// fine on-chain, so real history contains them, and reconstruction must fall back
/// to matching rather than refuse to read the chain. A present-but-malformed entry
/// (not 36 bytes) is dropped: the hint is UNVERIFIED attacker-supplied data.
///
/// Constructor 0 is accepted in BOTH plutus-core encodings — the compact tag 121
/// form and the general tag-102 + `any_constructor` form — matching
/// `parse_pegout_datum` and the registry/treasury decoders. A node accepts either,
/// and reading a legitimate record as "no hint" would silently force the fallback
/// matcher.
///
/// Every failure path returns an empty hint rather than an error. That is safe
/// precisely because the hint is never trusted: `replay` checks each candidate
/// against the quorum-attested root, and an empty hint just means the fallback
/// matcher does the work.
#[must_use]
pub fn unconfirmed_hint(data: &PlutusData) -> Vec<[u8; 36]> {
    let Ok((constructor, fields)) = crate::cardano::plutus::as_constr(data) else {
        return Vec::new();
    };
    if constructor != 0 {
        return Vec::new();
    }
    let Some(PlutusData::Array(items)) = fields.get(5) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|d| match d {
            PlutusData::BoundedBytes(b) => {
                let v: Vec<u8> = b.clone().into();
                <[u8; 36]>::try_from(v.as_slice()).ok()
            }
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Reconstruction
// ---------------------------------------------------------------------------

/// Everything [`reconstruct`] needs to identify the protocol's UTxOs.
#[derive(Debug, Clone)]
pub struct ReconstructConfig {
    /// Bech32 address of the Treasury Movement validator.
    pub tm_address: String,
    /// Bech32 address of `peg_out.ak`.
    pub pegout_address: String,
    /// The bridged-token (fBTC) policy id, hex.
    pub fbtc_policy_id: String,
    /// The bridged-token asset name, hex (may be empty).
    pub fbtc_asset_name_hex: String,
    /// Policy id (script hash) of the completed-peg-outs trie validator, hex —
    /// Config field 3. Identifies the on-chain CPO singleton, whose datum holds
    /// the root the chain currently believes.
    ///
    /// `Some` turns on the final safety net: the reconstructed root MUST equal the
    /// singleton's. Every step of the replay is already checked against a
    /// quorum-attested root, but only this compares the FINISHED trie against the
    /// value peg-out completions will actually be proven against — it is what
    /// catches a replay that stopped early or skipped the last movement.
    ///
    /// `None` skips the check and logs loudly. Only for a bridge whose trie
    /// singleton is not deployed yet, and for tests.
    pub cpo_policy_id: Option<String>,
}

/// A peg-out request as chain history remembers it — open or long since spent.
#[derive(Debug, Clone)]
struct HistoricalPor {
    por_id: [u8; 32],
    outpoint: [u8; 36],
    script_pubkey: Vec<u8>,
    /// `gross − per_pegout_fee`: what a TM paying this request must have paid.
    net_sat: u64,
}

impl HistoricalPor {
    fn entry(&self) -> CpoEntry {
        CpoEntry::new(self.por_id, &self.script_pubkey, self.net_sat)
    }
}

/// Rebuild the completed-peg-outs trie from chain history alone.
///
/// The algorithm, per the rev-5.1 design:
///
/// 1. Read EVERY output ever created at the TM address (spent included — the
///    Confirm transition spends the `Unconfirmed` record) and split them into
///    Confirmed records and Unconfirmed records.
/// 2. Order the Confirmed records by treasury linkage: TM *B* follows TM *A* iff
///    *B* spends *A*'s treasury output `(A.btc_txid, 0)`.
/// 3. Read every peg-out request ever created (spent included — a completed
///    request's UTxO is gone) and index it by outpoint.
/// 4. Replay the chain. For each Confirmed TM: take the root it committed (from
///    its own `"CPOR1"` output), resolve its data-availability hint through the
///    matching Unconfirmed record, insert those entries, and ASSERT the running
///    root equals the committed root.
/// 5. If a hint is absent, garbled, or produces the wrong root, fall back to
///    matching the TM's payment outputs against the peg-out requests that were
///    open at that point, and search assignments until the running root matches.
/// 6. Cross-check the FINISHED trie against the on-chain CPO singleton's datum.
///
/// The committed root turns every step from trust into search-and-check: a hostile
/// hint cannot corrupt the result, only make reconstruction slower.
///
/// `source` decides only WHERE the bytes come from (Kupo or a plain
/// Blockfrost-compatible API). Every step above, and every check, is identical for
/// both — that is the point of the trait.
pub async fn reconstruct(
    source: &dyn CpoHistorySource,
    cfg: &ReconstructConfig,
) -> Result<CpoTrie, CpoTrieError> {
    info!(
        "[cpo] reconstruction backend: {} ({})",
        source.backend(),
        source.endpoint()
    );
    let tm_matches = source
        .address_history(&cfg.tm_address)
        .await
        .map_err(CpoTrieError::Source)?;

    let mut confirmed: Vec<ConfirmedTm> = Vec::new();
    // btc_txid -> EVERY hint published for that tx.
    //
    // A Vec, not one entry: posting a TM record is PERMISSIONLESS, so anyone can
    // publish a second record embedding the same signed BTC tx with a garbage
    // hint. Last-writer-wins would let that record displace the honest one and
    // push every replay of that TM into the (bounded, abortable) fallback search —
    // a cheap denial of service against reconstruction. Keeping all candidates
    // costs nothing: each is checked against the committed root before use, so a
    // hostile one is simply the one that does not verify.
    let mut hints: HashMap<[u8; 32], Vec<Vec<[u8; 36]>>> = HashMap::new();

    for m in &tm_matches {
        // A THREE-way read, not a two-way one (see the module doc).
        let datum = match &m.datum {
            // No datum AT ALL: provably not a TM record. Every TM record —
            // Unconfirmed and Confirmed alike — is created with an inline datum,
            // so a bare payment to the permissionlessly-payable TM address is
            // ordinary junk, and skipping it costs nothing. Conflating this with
            // the unresolvable case below let ONE junk UTxO block every
            // reconstruction forever.
            DatumState::Absent => continue,
            // A datum EXISTS and could not be read. This is a HARD ERROR, never a
            // skip: we cannot tell an unresolvable Confirmed record from
            // unresolvable junk, and silently dropping a Confirmed record produces
            // a trie that is missing a whole movement's entries while looking
            // complete. If the dropped record is the chain tip, nothing
            // downstream notices — the running-root assertion has no later TM to
            // fail against. That is precisely the confidently-wrong trie this
            // function exists to make impossible.
            //
            // The operational cause is an index that did not witness the datum
            // preimage (a Kupo run with `--prune-utxo`, or an index started after
            // the output was created); the fix is a full index, not a softer
            // reader. The backend supplies its own remediation line; the hash
            // names exactly which output is unaccounted for.
            DatumState::Unresolved { datum_hash } => {
                return Err(CpoTrieError::Source(format!(
                    "cannot resolve the datum (hash {datum_hash}) of {}#{} at the TM address {} \
                     ({}) — refusing to reconstruct with an unexplained gap: if that output is a \
                     Confirmed TM record, skipping it yields a trie that silently omits a \
                     movement. {}",
                    m.tx_hash,
                    m.output_index,
                    cfg.tm_address,
                    m.datum_note,
                    source.datum_gap_advice(),
                )));
            }
            DatumState::Resolved(d) => d,
        };
        match parse_confirmed_tm_datum(datum) {
            Ok(tm) => confirmed.push(tm),
            Err(TreasuryDatumError::NotConfirmed) => {
                // Unconfirmed record: the hint's home. Its txid is recomputed from
                // the embedded signed tx, never taken on trust.
                if let Some(u) = crate::cardano::treasury_datum::parse_unconfirmed_tm(datum) {
                    use bitcoin::hashes::Hash as _;
                    let hint = unconfirmed_hint(datum);
                    if !hint.is_empty() {
                        hints
                            .entry(u.btc_txid.to_byte_array())
                            .or_default()
                            .push(hint);
                    }
                }
            }
            // A junk UTxO at a permissionlessly-payable address is not an error —
            // its datum RESOLVED, it just is not a TM record.
            Err(_) => {}
        }
    }

    let ordered = chain_order(confirmed);
    let history = fetch_pegout_history(source, cfg).await?;

    let trie = replay(&ordered, &hints, &history)?;

    // --- the final safety net ---
    match cfg.cpo_policy_id.as_deref() {
        Some(policy) => {
            let on_chain = fetch_onchain_cpo_root(source, policy).await?;
            if on_chain != trie.root() {
                return Err(CpoTrieError::RootMismatch {
                    reconstructed: trie.root(),
                    on_chain,
                    entries: trie.len(),
                });
            }
            info!(
                "[cpo] reconstructed root matches the on-chain CPO singleton ({})",
                hex::encode(on_chain)
            );
        }
        None => warn!(
            "[cpo] WARNING: no cpo_policy_id configured — the reconstructed root was NOT \
             cross-checked against the on-chain CPO singleton. Set cardano.cpo_policy_id \
             before trusting this trie to sign with."
        ),
    }
    Ok(trie)
}

/// The root held by the on-chain completed-peg-outs singleton.
///
/// The singleton is the ONE unspent output carrying the CPO NFT (`policy` +
/// asset name `"CPO"`), and its datum's first field is the root — the same read
/// `bifrost/utils.get_mpf_from_output` performs on-chain, and the value
/// `peg-out.ak` proves membership against. Anything other than exactly one such
/// output is an error: zero means the trie is not deployed (or the backend is not
/// indexing it), and several mean the NFT is not a singleton, so no root is
/// authoritative.
///
/// Public because steady-state operation needs it too, not just reconstruction:
/// `CardanoChain::query_cpo_root` reads it before every TM so a persisted
/// `cpo-trie.json` that has fallen out of sync with the chain is caught before
/// anything is signed.
pub async fn fetch_onchain_cpo_root(
    source: &dyn CpoHistorySource,
    policy_hex: &str,
) -> Result<[u8; 32], CpoTrieError> {
    let policy = policy_hex.trim().to_ascii_lowercase();
    let unit = format!("{policy}.{CPO_ASSET_NAME_HEX}");
    let matches = source
        .unspent_with_asset(&policy, CPO_ASSET_NAME_HEX)
        .await
        .map_err(CpoTrieError::Source)?;
    let held: Vec<_> = matches
        .iter()
        .filter(|m| m.asset_quantity(&policy, CPO_ASSET_NAME_HEX) == 1)
        .collect();
    let m = match held.as_slice() {
        [only] => *only,
        [] => {
            return Err(CpoTrieError::Source(format!(
                "no unspent output holds the completed-peg-outs NFT {unit} — the trie \
                 singleton is not deployed, or the backend is not indexing that policy"
            )));
        }
        many => {
            return Err(CpoTrieError::Source(format!(
                "{} unspent outputs hold the completed-peg-outs NFT {unit} — it is not a \
                 singleton, so no root is authoritative",
                many.len()
            )));
        }
    };
    let datum = m.datum.resolved().ok_or_else(|| {
        CpoTrieError::Source(format!(
            "the completed-peg-outs singleton {}#{} has no resolvable datum ({})",
            m.tx_hash, m.output_index, m.datum_note
        ))
    })?;
    parse_cpo_trie_datum(datum).map_err(CpoTrieError::Decode)
}

/// Decode `CompletedPegOutsMerkleTreeDatum { root }` — the root is field 0 of the
/// datum's Constr, exactly as `bifrost/utils.get_mpf_from_output` reads it
/// on-chain (it takes the head of `unconstr_fields` and requires 32 bytes).
pub fn parse_cpo_trie_datum(data: &PlutusData) -> Result<[u8; 32], String> {
    let (_, fields) =
        crate::cardano::plutus::as_constr(data).map_err(|e| format!("CPO trie datum: {e}"))?;
    let root = crate::cardano::plutus::field_bytes(fields, 0)
        .map_err(|_| "CPO trie datum: field[0] (root) is not BoundedBytes".to_string())?;
    <[u8; 32]>::try_from(root.as_slice())
        .map_err(|_| format!("CPO trie datum: root is {} bytes, expected 32", root.len()))
}

/// Order Confirmed TM records by treasury linkage.
///
/// TM *B* follows TM *A* iff *B*'s inputs contain `(A.btc_txid, 0)`. Records that
/// do not link into the main chain (a re-confirmation of the same txid, a
/// divergent lineage) are appended after it in `btc_txid` order so the replay is
/// still deterministic and still sees them.
fn chain_order(confirmed: Vec<ConfirmedTm>) -> Vec<ConfirmedTm> {
    // Deduplicate on btc_txid: the same TM can be confirmed into two UTxOs.
    let mut by_txid: BTreeMap<[u8; 32], ConfirmedTm> = BTreeMap::new();
    for tm in confirmed {
        by_txid.entry(tm.btc_txid).or_insert(tm);
    }

    // successor[A.btc_txid] = B, where B spends (A, 0).
    let mut successor: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    let mut has_predecessor: HashSet<[u8; 32]> = HashSet::new();
    for (txid, tm) in &by_txid {
        for input in &tm.swept_inputs {
            let Some((prev_tx, vout)) = parse_hint(input) else {
                continue;
            };
            if vout != 0 || !by_txid.contains_key(&prev_tx) {
                continue;
            }
            successor.entry(prev_tx).or_insert(*txid);
            has_predecessor.insert(*txid);
        }
    }

    let mut ordered = Vec::with_capacity(by_txid.len());
    let mut placed: HashSet<[u8; 32]> = HashSet::new();
    // Roots (no predecessor) in txid order, so a forked history is still ordered
    // identically on every node.
    let roots: Vec<[u8; 32]> = by_txid
        .keys()
        .copied()
        .filter(|t| !has_predecessor.contains(t))
        .collect();
    for root in roots {
        let mut cur = Some(root);
        while let Some(txid) = cur {
            if !placed.insert(txid) {
                break; // a cycle cannot happen on Bitcoin, but never loop forever
            }
            if let Some(tm) = by_txid.get(&txid) {
                ordered.push(tm.clone());
            }
            cur = successor.get(&txid).copied();
        }
    }
    // Anything left (only reachable from a cycle) still gets replayed.
    for (txid, tm) in &by_txid {
        if !placed.contains(txid) {
            ordered.push(tm.clone());
        }
    }
    ordered
}

/// Every peg-out request ever created at `pegout_address`, indexed by its 36-byte
/// outpoint. Spent ones are included: a completed request's UTxO no longer exists,
/// but its entry is exactly what the trie must contain.
async fn fetch_pegout_history(
    source: &dyn CpoHistorySource,
    cfg: &ReconstructConfig,
) -> Result<HashMap<[u8; 36], HistoricalPor>, CpoTrieError> {
    let matches = source
        .address_history(&cfg.pegout_address)
        .await
        .map_err(CpoTrieError::Source)?;
    let mut out = HashMap::new();
    for m in &matches {
        let gross = m.asset_quantity(&cfg.fbtc_policy_id, &cfg.fbtc_asset_name_hex);
        if gross == 0 {
            continue; // no fBTC locked — not a peg-out request
        }
        // Unlike the TM-address scan, an unresolvable datum here is a SKIP, not an
        // error — and the asymmetry is deliberate.
        //
        // A missing peg-out request cannot silently shrink the trie: it just means
        // no candidate matches some TM's payment, and that TM then fails its
        // running-root assertion by name. The failure is loud either way, so
        // erroring here would buy nothing while handing anyone a denial of service
        // — the peg-out address is permissionlessly payable, so a single junk UTxO
        // with an unwitnessed datum would block every reconstruction forever.
        //
        // `resolved()` treats DatumState::Absent and DatumState::Unresolved alike
        // here — unlike the TM-address scan, this address does not distinguish
        // them: neither can silently shrink the trie, so both are a plain skip.
        let Some(datum) = m.datum.resolved() else {
            continue;
        };
        let Ok(parsed) = crate::cardano::pegout_datum::parse_pegout_datum(datum) else {
            continue; // junk UTxO at a permissionlessly-payable address
        };
        let tx_hash = tx_hash_from_hex(&m.tx_hash)?;
        let outpoint = hint_bytes(&tx_hash, m.output_index);
        out.insert(
            outpoint,
            HistoricalPor {
                por_id: por_id(&tx_hash, u64::from(m.output_index)),
                outpoint,
                script_pubkey: parsed.destination_script_pubkey,
                net_sat: gross.saturating_sub(parsed.per_pegout_fee),
            },
        );
    }
    Ok(out)
}

/// Replay the Confirmed chain into a trie, asserting the running root after every
/// TM.
///
/// The two `continue`s below (no commitment; commitment equals the current root)
/// are the only places a TM contributes nothing, and both are backstopped: the
/// caller cross-checks the finished trie against the on-chain CPO singleton, so a
/// TM wrongly treated as inert shows up as a root mismatch rather than as a
/// quietly short trie.
fn replay(
    ordered: &[ConfirmedTm],
    hints: &HashMap<[u8; 32], Vec<Vec<[u8; 36]>>>,
    history: &HashMap<[u8; 36], HistoricalPor>,
) -> Result<CpoTrie, CpoTrieError> {
    let mut trie = CpoTrie::empty();
    for tm in ordered {
        let committed = match confirmed_committed_root(tm) {
            Ok(r) => r,
            // A pre-rev-5.1 TM has no commitment. It also fulfilled nothing under
            // the trie regime, so it moves the root not at all — skip it.
            Err(_) => continue,
        };
        if committed == trie.root() {
            // Zero-peg-out TM re-committing the unchanged root.
            continue;
        }

        // --- 1. the published hints ---
        //
        // Every candidate hint for this txid is tried, and each is accepted only
        // if it reproduces the attested root. Posting a TM record is
        // permissionless, so one of these may be a hostile fabrication; it simply
        // fails the check while the honest one passes.
        let mut resolved = None;
        for outpoints in hints.get(&tm.btc_txid).map(Vec::as_slice).unwrap_or(&[]) {
            let hinted: Vec<CpoEntry> = outpoints
                .iter()
                .filter_map(|op| history.get(op))
                .map(HistoricalPor::entry)
                .collect();
            if !hinted.is_empty() && trie.root_after(&hinted).ok() == Some(committed) {
                resolved = Some(hinted);
                break;
            }
        }
        if let Some(hinted) = resolved {
            trie.insert_batch(&hinted)?;
            continue;
        }

        // --- 2. fallback: match the TM's payments against open requests ---
        let entries = fallback_match(tm, committed, &trie, history)?;
        trie.insert_batch(&entries)?;
    }
    Ok(trie)
}

/// Find the peg-out set that explains `tm`'s committed root when the hint is
/// missing or garbled.
///
/// Each payment output `(spk, net)` is matched against the requests in `history`
/// with the same `(spk, net)` that the trie does not already record. When every
/// payment has exactly one candidate the answer is immediate. When several
/// requests share a `(destination, amount)` pair — which the live bridge really
/// does have — the assignments are enumerated and checked against the committed
/// root, bounded by [`FALLBACK_SEARCH_BUDGET`].
///
/// Ambiguity is not a correctness risk, only a cost: every candidate assignment is
/// checked against the quorum-attested root, so a wrong guess is rejected.
fn fallback_match(
    tm: &ConfirmedTm,
    committed: [u8; 32],
    trie: &CpoTrie,
    history: &HashMap<[u8; 36], HistoricalPor>,
) -> Result<Vec<CpoEntry>, CpoTrieError> {
    let payments = confirmed_payments(tm);
    let unreconstructable = |reason: String| CpoTrieError::Unreconstructable {
        btc_txid: tm.btc_txid,
        committed_root: committed,
        reason,
    };

    // Candidate requests per payment, in a deterministic order.
    let mut candidates: Vec<Vec<&HistoricalPor>> = Vec::with_capacity(payments.len());
    for (spk, net) in &payments {
        let mut c: Vec<&HistoricalPor> = history
            .values()
            .filter(|p| p.script_pubkey == *spk && p.net_sat == *net && !trie.contains(&p.por_id))
            .collect();
        c.sort_by_key(|p| p.outpoint);
        if c.is_empty() {
            return Err(unreconstructable(format!(
                "no open peg-out request matches the payment of {net} sat to {}",
                hex::encode(spk)
            )));
        }
        candidates.push(c);
    }

    let mut chosen: Vec<&HistoricalPor> = Vec::with_capacity(payments.len());
    let mut used: HashSet<[u8; 36]> = HashSet::new();
    let mut budget = FALLBACK_SEARCH_BUDGET;
    if search(
        &candidates,
        0,
        &mut chosen,
        &mut used,
        trie,
        committed,
        &mut budget,
    ) {
        return Ok(chosen.iter().map(|p| p.entry()).collect());
    }
    Err(unreconstructable(if budget == 0 {
        format!(
            "search budget exhausted over {} payment(s) with {} candidate(s)",
            payments.len(),
            candidates.iter().map(Vec::len).sum::<usize>(),
        )
    } else {
        format!(
            "no assignment of {} payment(s) to the open peg-out requests reproduces the \
             committed root",
            payments.len()
        )
    }))
}

/// Depth-first assignment search. Returns true (with `chosen` filled) as soon as
/// an assignment reproduces `committed`.
fn search<'a>(
    candidates: &[Vec<&'a HistoricalPor>],
    depth: usize,
    chosen: &mut Vec<&'a HistoricalPor>,
    used: &mut HashSet<[u8; 36]>,
    trie: &CpoTrie,
    committed: [u8; 32],
    budget: &mut usize,
) -> bool {
    if depth == candidates.len() {
        let entries: Vec<CpoEntry> = chosen.iter().map(|p| p.entry()).collect();
        return trie.root_after(&entries).ok() == Some(committed);
    }
    for cand in &candidates[depth] {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        if !used.insert(cand.outpoint) {
            continue;
        }
        chosen.push(cand);
        if search(candidates, depth + 1, chosen, used, trie, committed, budget) {
            return true;
        }
        chosen.pop();
        used.remove(&cand.outpoint);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::treasury_datum::TmOutput;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../tests/fixtures/cpo_trie_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("golden vector file parses")
    }

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // --- golden vectors: por_id ------------------------------------------

    // The POR id is the trie KEY the on-chain `peg-out.ak` recomputes from the
    // request's own outpoint. If this drifts, every peg-out completion fails.
    #[test]
    fn por_id_matches_the_scalus_golden_vectors() {
        for v in vectors()["por_id"].as_array().unwrap() {
            let tx = h32(v["tx_hash"].as_str().unwrap());
            let idx = v["output_index"].as_u64().unwrap();
            assert_eq!(
                hex::encode(por_id(&tx, idx)),
                v["por_id"].as_str().unwrap(),
                "por_id({}, {idx})",
                v["tx_hash"].as_str().unwrap()
            );
        }
    }

    // --- golden vectors: trie value --------------------------------------

    #[test]
    fn trie_value_matches_the_scalus_golden_vectors() {
        for v in vectors()["trie_value"].as_array().unwrap() {
            let spk = hex::decode(v["script_pubkey"].as_str().unwrap()).unwrap();
            let amount = v["amount"].as_u64().unwrap();
            assert_eq!(
                hex::encode(trie_value(&spk, amount)),
                v["value"].as_str().unwrap()
            );
        }
    }

    // --- golden vectors: roots -------------------------------------------

    // The whole security argument rests on every implementation computing the SAME
    // root for the same entry set: heimdall proposes it, co-signers recompute it,
    // the Aiken validator proves membership against it.
    #[test]
    fn roots_match_the_scalus_golden_vectors() {
        let v = vectors();
        assert_eq!(
            hex::encode(CpoTrie::empty().root()),
            v["empty_root"].as_str().unwrap(),
            "empty root"
        );
        assert_eq!(CpoTrie::empty().root(), EMPTY_ROOT);

        for step in v["roots"].as_array().unwrap() {
            let entries: Vec<CpoEntry> = step["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    CpoEntry::new(
                        h32(e["por_id"].as_str().unwrap()),
                        &hex::decode(e["script_pubkey"].as_str().unwrap()).unwrap(),
                        e["amount"].as_u64().unwrap(),
                    )
                })
                .collect();
            let trie = CpoTrie::from_entries(&entries).unwrap();
            assert_eq!(
                hex::encode(trie.root()),
                step["root"].as_str().unwrap(),
                "root after {} entries",
                entries.len()
            );
            assert_eq!(trie.len(), entries.len());
        }
    }

    // An MPF root is a function of the key/value SET. Reconstruction relies on
    // this: it may resolve a TM's entries in any order.
    #[test]
    fn root_is_independent_of_insertion_order() {
        let v = vectors();
        let last = v["roots"].as_array().unwrap().last().unwrap();
        let mut entries: Vec<CpoEntry> = last["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                CpoEntry::new(
                    h32(e["por_id"].as_str().unwrap()),
                    &hex::decode(e["script_pubkey"].as_str().unwrap()).unwrap(),
                    e["amount"].as_u64().unwrap(),
                )
            })
            .collect();
        entries.reverse();
        assert_eq!(
            hex::encode(CpoTrie::from_entries(&entries).unwrap().root()),
            v["root_reversed_insert_order"].as_str().unwrap()
        );
    }

    // --- insert semantics -------------------------------------------------

    fn entry(k: u8, spk_byte: u8, sat: u64) -> CpoEntry {
        CpoEntry::new([k; 32], &[spk_byte; 22], sat)
    }

    #[test]
    fn reinserting_the_same_entry_is_a_no_op() {
        let mut t = CpoTrie::empty();
        t.insert_batch(&[entry(1, 0xaa, 1000)]).unwrap();
        let root = t.root();
        t.insert_batch(&[entry(1, 0xaa, 1000)]).unwrap();
        assert_eq!(t.root(), root);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn conflicting_value_for_the_same_por_id_is_rejected() {
        let mut t = CpoTrie::empty();
        t.insert_batch(&[entry(1, 0xaa, 1000)]).unwrap();
        let err = t.insert_batch(&[entry(1, 0xaa, 2000)]).unwrap_err();
        assert!(matches!(err, CpoTrieError::Conflict { .. }), "{err}");
        // Failure leaves the trie untouched.
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&[1u8; 32]).unwrap(), trie_value(&[0xaa; 22], 1000));
    }

    #[test]
    fn a_failed_batch_applies_nothing() {
        let mut t = CpoTrie::empty();
        t.insert_batch(&[entry(1, 0xaa, 1000)]).unwrap();
        let root = t.root();
        let err = t.insert_batch(&[entry(2, 0xbb, 5), entry(1, 0xaa, 9)]);
        assert!(err.is_err());
        assert_eq!(t.root(), root, "the good entry must not have landed");
        assert!(!t.contains(&[2u8; 32]));
    }

    #[test]
    fn root_after_does_not_mutate() {
        let t = CpoTrie::empty();
        let after = t.root_after(&[entry(1, 0xaa, 1000)]).unwrap();
        assert_ne!(after, t.root());
        assert_eq!(t.root(), EMPTY_ROOT);
        assert_eq!(t.root_after(&[]).unwrap(), EMPTY_ROOT, "empty batch = now");
    }

    // --- verify_proposed (the co-signer gate) -----------------------------

    #[test]
    fn verify_proposed_accepts_the_root_the_same_trie_computes() {
        let mut t = CpoTrie::empty();
        t.insert_batch(&[entry(1, 0xaa, 1000)]).unwrap();
        let batch = [entry(2, 0xbb, 2000)];
        let proposed = t.root_after(&batch).unwrap();
        t.verify_proposed(&proposed, &batch).unwrap();
    }

    #[test]
    fn verify_proposed_rejects_a_wrong_root() {
        let t = CpoTrie::empty();
        let batch = [entry(2, 0xbb, 2000)];
        assert!(t.verify_proposed(&[0xff; 32], &batch).is_err());
    }

    // A leader that omits an entry from the root (so the peg-out is paid but never
    // provable) must be refused, even though its root is a perfectly valid MPF root.
    #[test]
    fn verify_proposed_rejects_a_root_that_skips_a_paid_pegout() {
        let t = CpoTrie::empty();
        let paid = [entry(1, 0xaa, 1000), entry(2, 0xbb, 2000)];
        let dishonest = t.root_after(&paid[..1]).unwrap();
        assert!(t.verify_proposed(&dishonest, &paid).is_err());
    }

    // A co-signer whose trie is BEHIND must not sign: its root would differ.
    #[test]
    fn verify_proposed_rejects_when_the_local_trie_diverges() {
        let mut leader = CpoTrie::empty();
        leader.insert_batch(&[entry(9, 0x99, 77)]).unwrap();
        let batch = [entry(2, 0xbb, 2000)];
        let proposed = leader.root_after(&batch).unwrap();
        let behind = CpoTrie::empty();
        assert!(behind.verify_proposed(&proposed, &batch).is_err());
    }

    // --- persistence ------------------------------------------------------

    #[test]
    fn save_then_load_roundtrips() {
        let dir = std::env::temp_dir().join(format!("cpo-trie-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(CpoTrie::load(&dir).unwrap().is_none(), "no file yet");

        let mut t = CpoTrie::empty();
        t.insert_batch(&[entry(1, 0xaa, 1000), entry(2, 0xbb, 2000)])
            .unwrap();
        t.save(&dir).unwrap();

        let loaded = CpoTrie::load(&dir).unwrap().expect("state present");
        assert_eq!(loaded.root(), t.root());
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&[1u8; 32]));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(CpoTrie::state_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "trie state must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tampered_state_file_is_rejected() {
        let dir = std::env::temp_dir().join(format!("cpo-trie-tamper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut t = CpoTrie::empty();
        t.insert_batch(&[entry(1, 0xaa, 1000)]).unwrap();
        t.save(&dir).unwrap();

        let path = CpoTrie::state_path(&dir);
        let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["entries"][0]["value"] = Value::String(hex::encode(trie_value(&[0xaa; 22], 999)));
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();

        let err = CpoTrie::load(&dir).unwrap_err();
        assert!(format!("{err}").contains("corrupt trie state"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- commitment reading ------------------------------------------------

    fn commitment_out(root: [u8; 32]) -> TmOutput {
        let mut spk = CPO_COMMITMENT_PREFIX.to_vec();
        spk.extend_from_slice(&root);
        TmOutput {
            script_pub_key: spk,
            amount: 0,
        }
    }

    fn payment_out(spk_byte: u8, amount: u64) -> TmOutput {
        TmOutput {
            script_pub_key: vec![spk_byte; 22],
            amount,
        }
    }

    fn confirmed(txid: u8, inputs: Vec<[u8; 36]>, outputs: Vec<TmOutput>) -> ConfirmedTm {
        ConfirmedTm {
            btc_txid: [txid; 32],
            swept_inputs: inputs.iter().map(|i| i.to_vec()).collect(),
            outputs,
        }
    }

    #[test]
    fn confirmed_committed_root_reads_the_single_commitment() {
        let tm = confirmed(
            1,
            vec![],
            vec![
                payment_out(0x11, 500_000),
                payment_out(0xaa, 1000),
                commitment_out([0x5a; 32]),
            ],
        );
        assert_eq!(confirmed_committed_root(&tm).unwrap(), [0x5a; 32]);
        // Output 0 is the treasury and the commitment is not a payment.
        assert_eq!(confirmed_payments(&tm), vec![(vec![0xaa; 22], 1000u64)]);
    }

    #[test]
    fn confirmed_committed_root_rejects_zero_and_many() {
        let none = confirmed(1, vec![], vec![payment_out(0x11, 5)]);
        assert!(confirmed_committed_root(&none).is_err());
        let two = confirmed(
            1,
            vec![],
            vec![
                payment_out(0x11, 5),
                commitment_out([1; 32]),
                commitment_out([1; 32]),
            ],
        );
        assert!(confirmed_committed_root(&two).is_err());
    }

    // A 39-byte payment script must not be read as a commitment (the prefix check
    // is what stops it) — nor a short right-prefixed script (the length check).
    #[test]
    fn confirmed_committed_root_ignores_lookalikes() {
        let mut short = CPO_COMMITMENT_PREFIX.to_vec();
        short.extend_from_slice(&[0u8; 31]);
        let tm = confirmed(
            1,
            vec![],
            vec![
                payment_out(0x11, 5),
                TmOutput {
                    script_pub_key: vec![0x51; CPO_COMMITMENT_SCRIPT_LEN],
                    amount: 7,
                },
                TmOutput {
                    script_pub_key: short,
                    amount: 0,
                },
            ],
        );
        assert!(
            confirmed_committed_root(&tm).is_err(),
            "neither is a commitment"
        );
    }

    // --- hint parsing ------------------------------------------------------

    fn unconfirmed_datum(fields: Vec<PlutusData>) -> PlutusData {
        crate::cardano::plutus::constr(0, fields)
    }

    #[test]
    fn hint_reads_field_5_of_a_six_field_unconfirmed_datum() {
        use crate::cardano::plutus::{array, bytes, int};
        let op1 = hint_bytes(&[0xaa; 32], 1);
        let op2 = hint_bytes(&[0xbb; 32], 0);
        let d = unconfirmed_datum(vec![
            bytes(&[0x02, 0x00]),
            bytes(&[0x7a; 28]),
            int(1),
            int(2),
            int(3),
            array(vec![bytes(&op1), bytes(&op2)]),
        ]);
        assert_eq!(unconfirmed_hint(&d), vec![op1, op2]);
    }

    // Old 5-field records really are in history (they confirm fine on-chain), so
    // reading one must yield an empty hint, not an error — reconstruction then
    // falls back to matching.
    #[test]
    fn hint_of_an_old_five_field_datum_is_empty() {
        use crate::cardano::plutus::{bytes, int};
        let d = unconfirmed_datum(vec![
            bytes(&[0x02, 0x00]),
            bytes(&[0x7a; 28]),
            int(1),
            int(2),
            int(3),
        ]);
        assert!(unconfirmed_hint(&d).is_empty());
    }

    // The hint is UNVERIFIED. A wrong-length entry is dropped rather than trusted.
    #[test]
    fn malformed_hint_entries_are_dropped() {
        use crate::cardano::plutus::{array, bytes, int};
        let good = hint_bytes(&[0xcc; 32], 3);
        let d = unconfirmed_datum(vec![
            bytes(&[0x02]),
            bytes(&[0x7a; 28]),
            int(1),
            int(2),
            int(3),
            array(vec![bytes(&[0xde, 0xad]), bytes(&good), bytes(&[0u8; 40])]),
        ]);
        assert_eq!(unconfirmed_hint(&d), vec![good]);
    }

    // Constructor 0 in the general tag-102 form is legal Plutus data a node
    // accepts, and `parse_pegout_datum` already accepts it. Reading such a record
    // as "no hint" would silently force the fallback matcher.
    #[test]
    fn hint_reads_the_tag_102_constructor_0_form() {
        use crate::cardano::plutus::{array, bytes, int};
        use pallas_primitives::MaybeIndefArray;
        use pallas_primitives::conway::Constr;
        let op = hint_bytes(&[0xaa; 32], 1);
        let d = PlutusData::Constr(Constr {
            tag: 102,
            any_constructor: Some(0),
            fields: MaybeIndefArray::Indef(vec![
                bytes(&[0x02]),
                bytes(&[0x7a; 28]),
                int(1),
                int(2),
                int(3),
                array(vec![bytes(&op)]),
            ]),
        });
        assert_eq!(unconfirmed_hint(&d), vec![op]);
    }

    // A Confirmed record (constructor 1) has no hint field, and its field 5 is
    // `created` — reading it as a hint would be nonsense.
    #[test]
    fn hint_of_a_non_zero_constructor_is_empty() {
        use crate::cardano::plutus::{bytes, constr, int};
        let confirmed_datum = constr(
            1,
            vec![
                bytes(&[0xcc; 32]),
                crate::cardano::plutus::array(vec![]),
                crate::cardano::plutus::array(vec![]),
                crate::cardano::plutus::bool_data(false),
                bytes(&[0x7a; 28]),
                int(1_700_000_000_000),
            ],
        );
        assert!(unconfirmed_hint(&confirmed_datum).is_empty());
    }

    // --- CPO singleton datum ---

    // The hex form is what goes into Kupo asset patterns and asset-unit strings;
    // the byte form is what the Aiken constant says. Pin them to each other so the
    // singleton lookup cannot drift from `constants.ak`.
    #[test]
    fn the_cpo_asset_name_hex_matches_the_bytes() {
        assert_eq!(CPO_ASSET_NAME, b"CPO");
        assert_eq!(hex::encode(CPO_ASSET_NAME), CPO_ASSET_NAME_HEX);
    }

    #[test]
    fn parses_the_cpo_trie_datum_root() {
        use crate::cardano::plutus::{bytes, constr};
        let d = constr(0, vec![bytes(&[0x5a; 32])]);
        assert_eq!(parse_cpo_trie_datum(&d).unwrap(), [0x5a; 32]);
        // The Aiken reader takes the HEAD of unconstr_fields, so extra trailing
        // fields are irrelevant — but the root must be exactly 32 bytes.
        let padded = constr(0, vec![bytes(&[0x5a; 32]), bytes(b"extra")]);
        assert_eq!(parse_cpo_trie_datum(&padded).unwrap(), [0x5a; 32]);
        assert!(parse_cpo_trie_datum(&constr(0, vec![bytes(&[0x5a; 31])])).is_err());
        assert!(parse_cpo_trie_datum(&constr(0, vec![])).is_err());
        assert!(parse_cpo_trie_datum(&bytes(b"nope")).is_err());
    }

    #[test]
    fn hint_bytes_roundtrips_and_is_little_endian() {
        let b = hint_bytes(&[0xab; 32], 258);
        assert_eq!(&b[32..], &[0x02, 0x01, 0x00, 0x00]);
        assert_eq!(parse_hint(&b), Some(([0xab; 32], 258)));
        assert_eq!(parse_hint(&b[..35]), None);
    }

    // --- chain ordering ----------------------------------------------------

    #[test]
    fn chain_order_follows_the_treasury_linkage() {
        // C spends B's treasury, B spends A's. Fed in reverse.
        let a = confirmed(0xa1, vec![hint_bytes(&[0x00; 32], 0)], vec![]);
        let b = confirmed(0xb2, vec![hint_bytes(&[0xa1; 32], 0)], vec![]);
        let c = confirmed(0xc3, vec![hint_bytes(&[0xb2; 32], 0)], vec![]);
        let ordered = chain_order(vec![c, b, a]);
        let txids: Vec<u8> = ordered.iter().map(|t| t.btc_txid[0]).collect();
        assert_eq!(txids, vec![0xa1, 0xb2, 0xc3]);
    }

    #[test]
    fn chain_order_deduplicates_reconfirmations() {
        let a = confirmed(0xa1, vec![], vec![]);
        let a2 = confirmed(0xa1, vec![], vec![]);
        assert_eq!(chain_order(vec![a, a2]).len(), 1);
    }

    // --- replay ------------------------------------------------------------

    fn hist(outpoint_byte: u8, spk_byte: u8, net: u64) -> HistoricalPor {
        let tx = [outpoint_byte; 32];
        HistoricalPor {
            por_id: por_id(&tx, 0),
            outpoint: hint_bytes(&tx, 0),
            script_pubkey: vec![spk_byte; 22],
            net_sat: net,
        }
    }

    fn history_of(items: Vec<HistoricalPor>) -> HashMap<[u8; 36], HistoricalPor> {
        items.into_iter().map(|p| (p.outpoint, p)).collect()
    }

    #[test]
    fn replay_uses_the_hint_when_it_reproduces_the_committed_root() {
        let p = hist(0x11, 0xaa, 1000);
        let history = history_of(vec![p.clone()]);
        let root = CpoTrie::empty().root_after(&[p.entry()]).unwrap();
        let tm = confirmed(
            0xa1,
            vec![],
            vec![
                payment_out(0x00, 999_000),
                payment_out(0xaa, 1000),
                commitment_out(root),
            ],
        );
        let hints = HashMap::from([([0xa1u8; 32], vec![vec![p.outpoint]])]);
        let trie = replay(&[tm], &hints, &history).unwrap();
        assert_eq!(trie.root(), root);
        assert!(trie.contains(&p.por_id));
    }

    // A TM that fulfils nothing still commits — the unchanged root.
    #[test]
    fn replay_accepts_a_zero_pegout_tm() {
        let tm = confirmed(
            0xa1,
            vec![],
            vec![payment_out(0x00, 999_000), commitment_out(EMPTY_ROOT)],
        );
        let trie = replay(&[tm], &HashMap::new(), &HashMap::new()).unwrap();
        assert_eq!(trie.root(), EMPTY_ROOT);
        assert!(trie.is_empty());
    }

    // A garbled hint costs nothing: the committed root is the check, and the
    // fallback matcher recovers the true set.
    #[test]
    fn replay_falls_back_when_the_hint_is_garbage() {
        let p = hist(0x11, 0xaa, 1000);
        let history = history_of(vec![p.clone()]);
        let root = CpoTrie::empty().root_after(&[p.entry()]).unwrap();
        let tm = confirmed(
            0xa1,
            vec![],
            vec![
                payment_out(0x00, 999_000),
                payment_out(0xaa, 1000),
                commitment_out(root),
            ],
        );
        // Hint names an outpoint that is not in history at all.
        let hints = HashMap::from([([0xa1u8; 32], vec![vec![hint_bytes(&[0x77; 32], 4)]])]);
        let trie = replay(&[tm], &hints, &history).unwrap();
        assert_eq!(trie.root(), root);
        assert!(trie.contains(&p.por_id));
    }

    // No hint at all (an OLD 5-field Unconfirmed record) — same outcome.
    #[test]
    fn replay_falls_back_when_there_is_no_hint() {
        let p = hist(0x11, 0xaa, 1000);
        let history = history_of(vec![p.clone()]);
        let root = CpoTrie::empty().root_after(&[p.entry()]).unwrap();
        let tm = confirmed(
            0xa1,
            vec![],
            vec![
                payment_out(0x00, 999_000),
                payment_out(0xaa, 1000),
                commitment_out(root),
            ],
        );
        let trie = replay(&[tm], &HashMap::new(), &history).unwrap();
        assert_eq!(trie.root(), root);
    }

    // Several requests share one (destination, amount) — the live bridge really
    // has this. The search must find the assignment the root attests.
    #[test]
    fn fallback_disambiguates_identical_requests_by_the_committed_root() {
        let p1 = hist(0x11, 0xaa, 1000);
        let p2 = hist(0x22, 0xaa, 1000);
        let p3 = hist(0x33, 0xaa, 1000);
        let history = history_of(vec![p1.clone(), p2.clone(), p3.clone()]);
        // The TM paid exactly ONE of them — p2.
        let root = CpoTrie::empty().root_after(&[p2.entry()]).unwrap();
        let tm = confirmed(
            0xa1,
            vec![],
            vec![
                payment_out(0x00, 999_000),
                payment_out(0xaa, 1000),
                commitment_out(root),
            ],
        );
        let trie = replay(&[tm], &HashMap::new(), &history).unwrap();
        assert_eq!(trie.root(), root);
        assert!(trie.contains(&p2.por_id));
        assert!(!trie.contains(&p1.por_id));
        assert!(!trie.contains(&p3.por_id));
    }

    // Two TMs in a row, the second building on the first's root.
    #[test]
    fn replay_asserts_the_running_root_across_a_chain() {
        let p1 = hist(0x11, 0xaa, 1000);
        let p2 = hist(0x22, 0xbb, 2000);
        let history = history_of(vec![p1.clone(), p2.clone()]);
        let mut t = CpoTrie::empty();
        let root1 = t.insert_batch(&[p1.entry()]).unwrap();
        let root2 = t.insert_batch(&[p2.entry()]).unwrap();

        let tm1 = confirmed(
            0xa1,
            vec![],
            vec![
                payment_out(0x00, 999_000),
                payment_out(0xaa, 1000),
                commitment_out(root1),
            ],
        );
        let tm2 = confirmed(
            0xb2,
            vec![hint_bytes(&[0xa1; 32], 0)],
            vec![
                payment_out(0x00, 998_000),
                payment_out(0xbb, 2000),
                commitment_out(root2),
            ],
        );
        let hints = HashMap::from([
            ([0xa1u8; 32], vec![vec![p1.outpoint]]),
            ([0xb2u8; 32], vec![vec![p2.outpoint]]),
        ]);
        let trie = replay(&chain_order(vec![tm2, tm1]), &hints, &history).unwrap();
        assert_eq!(trie.root(), root2);
        assert_eq!(trie.len(), 2);
    }

    // A TM whose committed root no assignment reproduces is reported, not
    // silently absorbed — a wrong trie would make this node sign wrong roots.
    #[test]
    fn replay_reports_an_unreconstructable_tm() {
        let p = hist(0x11, 0xaa, 1000);
        let history = history_of(vec![p]);
        let tm = confirmed(
            0xa1,
            vec![],
            vec![
                payment_out(0x00, 999_000),
                payment_out(0xaa, 1000),
                commitment_out([0xde; 32]),
            ],
        );
        let err = replay(&[tm], &HashMap::new(), &history).unwrap_err();
        assert!(
            matches!(err, CpoTrieError::Unreconstructable { .. }),
            "{err}"
        );
    }

    #[test]
    fn replay_reports_a_payment_with_no_matching_request() {
        let tm = confirmed(
            0xa1,
            vec![],
            vec![
                payment_out(0x00, 999_000),
                payment_out(0xee, 4242),
                commitment_out([0xde; 32]),
            ],
        );
        let err = replay(&[tm], &HashMap::new(), &HashMap::new()).unwrap_err();
        assert!(
            format!("{err}").contains("no open peg-out request matches"),
            "{err}"
        );
    }

    // Posting a TM record is permissionless, so anyone can publish a SECOND record
    // embedding the same signed tx with a garbage hint. With last-writer-wins that
    // record would displace the honest hint and force the bounded fallback search —
    // a cheap denial of service. Every candidate must be tried.
    #[test]
    fn a_hostile_duplicate_hint_does_not_displace_the_honest_one() {
        let p = hist(0x11, 0xaa, 1000);
        let history = history_of(vec![p.clone()]);
        let root = CpoTrie::empty().root_after(&[p.entry()]).unwrap();
        let tm = confirmed(
            0xa1,
            vec![],
            vec![
                payment_out(0x00, 999_000),
                payment_out(0xaa, 1000),
                commitment_out(root),
            ],
        );
        // The garbage hint is stored FIRST, so a last-writer-wins map would keep
        // the honest one and this test would pass for the wrong reason. Order it
        // the other way round too.
        for hints in [
            vec![vec![hint_bytes(&[0x77; 32], 4)], vec![p.outpoint]],
            vec![vec![p.outpoint], vec![hint_bytes(&[0x77; 32], 4)]],
        ] {
            let trie = replay(
                std::slice::from_ref(&tm),
                &HashMap::from([([0xa1u8; 32], hints)]),
                &history,
            )
            .unwrap();
            assert_eq!(trie.root(), root);
            assert!(trie.contains(&p.por_id));
        }
    }

    // Pre-rev-5.1 TMs carry no commitment. They fulfilled nothing under the trie
    // regime, so replay must skip them rather than fail the whole reconstruction.
    #[test]
    fn replay_skips_a_tm_without_a_commitment() {
        let old = confirmed(0xa1, vec![], vec![payment_out(0x00, 999_000)]);
        let trie = replay(&[old], &HashMap::new(), &HashMap::new()).unwrap();
        assert_eq!(trie.root(), EMPTY_ROOT);
    }

    // --- reconstruct, over a trait-level fake -----------------------------
    //
    // These pin the parts of `reconstruct` that live ABOVE the fetch layer: the
    // hard error on an unresolvable TM datum, the deliberate SKIP on a
    // datum-less TM output and on a datum-less or unresolvable peg-out one, and
    // the final cross-check against the on-chain singleton. A fake source
    // reaches every one of them without a server, and being trait-level they
    // hold for both backends by construction. `cardano::cpo_history` covers the
    // two real backends over HTTP.

    use crate::cardano::cpo_history::{CpoHistorySource, DatumState, HistoricalOutput};
    use async_trait::async_trait;

    const T_ADDR: &str = "tm-address";
    const P_ADDR: &str = "pegout-address";
    const POLICY: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
    const FBTC: &str = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";

    #[derive(Default)]
    struct FakeSource {
        tm: Vec<HistoricalOutput>,
        pegout: Vec<HistoricalOutput>,
        singleton: Vec<HistoricalOutput>,
    }

    #[async_trait]
    impl CpoHistorySource for FakeSource {
        fn backend(&self) -> &'static str {
            "fake"
        }
        fn endpoint(&self) -> &str {
            "memory://"
        }
        fn datum_gap_advice(&self) -> &'static str {
            "fake advice"
        }
        async fn address_history(&self, address: &str) -> Result<Vec<HistoricalOutput>, String> {
            Ok(match address {
                T_ADDR => self.tm.clone(),
                P_ADDR => self.pegout.clone(),
                other => return Err(format!("unexpected address {other}")),
            })
        }
        async fn unspent_with_asset(
            &self,
            _policy_hex: &str,
            _asset_name_hex: &str,
        ) -> Result<Vec<HistoricalOutput>, String> {
            Ok(self.singleton.clone())
        }
    }

    /// `datum: None` builds a genuinely datum-less output ([`DatumState::Absent`])
    /// — junk at a permissionlessly-payable address, never an error. Use
    /// [`fake_out_unresolved`] for an output whose datum hash is known but whose
    /// preimage the backend could not supply.
    fn fake_out(
        tx: [u8; 32],
        index: u32,
        assets: &[(String, u64)],
        datum: Option<PlutusData>,
    ) -> HistoricalOutput {
        HistoricalOutput {
            tx_hash: hex::encode(tx),
            output_index: index,
            assets: assets.iter().cloned().collect(),
            datum_note: if datum.is_some() {
                "inline".into()
            } else {
                "no datum".into()
            },
            datum: match datum {
                Some(d) => DatumState::Resolved(d),
                None => DatumState::Absent,
            },
        }
    }

    /// An output whose datum hash IS known but whose preimage the backend could
    /// not supply — [`DatumState::Unresolved`], distinct from a genuinely
    /// datum-less output. This is the case that must still hard-error at the TM
    /// address.
    fn fake_out_unresolved(
        tx: [u8; 32],
        index: u32,
        assets: &[(String, u64)],
        datum_hash: &str,
    ) -> HistoricalOutput {
        HistoricalOutput {
            tx_hash: hex::encode(tx),
            output_index: index,
            assets: assets.iter().cloned().collect(),
            datum_note: format!("datum_hash={datum_hash} — no preimage"),
            datum: DatumState::Unresolved {
                datum_hash: datum_hash.to_string(),
            },
        }
    }

    /// A Confirmed TM datum paying `(spk, net)` and committing `root`.
    fn confirmed_datum(txid: [u8; 32], payments: &[(Vec<u8>, u64)], root: [u8; 32]) -> PlutusData {
        use crate::cardano::plutus::{array, bool_data, bytes, constr, int, int_from_u64};
        let mut spk = CPO_COMMITMENT_PREFIX.to_vec();
        spk.extend_from_slice(&root);
        let entry = |s: &[u8], a: u64| constr(0, vec![bytes(s), int_from_u64(a)]);
        let mut outs = vec![entry(&[0x51; 34], 900_000)];
        outs.extend(payments.iter().map(|(s, a)| entry(s, *a)));
        outs.push(entry(&spk, 0));
        constr(
            1,
            vec![
                bytes(&txid),
                array(vec![]),
                array(outs),
                bool_data(false),
                bytes(&[0x7a; 28]),
                int(1_700_000_000_000),
            ],
        )
    }

    fn pegout_request_datum(spk: &[u8], fee: u64) -> PlutusData {
        use crate::cardano::plutus::{bytes, constr, int, int_from_u64};
        constr(
            0,
            vec![
                constr(0, vec![bytes(&[0x01; 28])]),
                bytes(spk),
                int_from_u64(fee),
                int(1_700_000_000_000),
            ],
        )
    }

    fn fake_cfg() -> ReconstructConfig {
        ReconstructConfig {
            tm_address: T_ADDR.into(),
            pegout_address: P_ADDR.into(),
            fbtc_policy_id: FBTC.into(),
            fbtc_asset_name_hex: "66425443".into(),
            cpo_policy_id: Some(POLICY.into()),
        }
    }

    /// One TM, one request, no hint — the fallback matcher does the work, and the
    /// finished trie matches the singleton.
    fn one_movement_world() -> (FakeSource, [u8; 32]) {
        use crate::cardano::plutus::{bytes, constr};
        let por_tx = [0x11u8; 32];
        let spk = vec![0xaau8; 22];
        let (gross, fee) = (100_000u64, 1_000u64);
        let entry = CpoEntry::new(por_id(&por_tx, 0), &spk, gross - fee);
        let root = CpoTrie::from_entries(&[entry]).unwrap().root();
        let fbtc_unit = format!("{FBTC}66425443");
        (
            FakeSource {
                tm: vec![fake_out(
                    [0xb2; 32],
                    0,
                    &[],
                    Some(confirmed_datum(
                        [0xa1; 32],
                        &[(spk.clone(), gross - fee)],
                        root,
                    )),
                )],
                pegout: vec![fake_out(
                    por_tx,
                    0,
                    &[(fbtc_unit, gross)],
                    Some(pegout_request_datum(&spk, fee)),
                )],
                singleton: vec![fake_out(
                    [0xcf; 32],
                    0,
                    &[(format!("{POLICY}{CPO_ASSET_NAME_HEX}"), 1)],
                    Some(constr(0, vec![bytes(&root)])),
                )],
            },
            root,
        )
    }

    #[tokio::test]
    async fn reconstruct_rebuilds_the_trie_and_cross_checks_the_singleton() {
        let (world, root) = one_movement_world();
        let trie = reconstruct(&world, &fake_cfg()).await.unwrap();
        assert_eq!(trie.root(), root);
        assert_eq!(trie.len(), 1);
    }

    // An output at the TM address whose datum EXISTS but cannot be supplied
    // aborts the run. Skipping it could drop a whole movement while the trie
    // still looks complete — the one failure mode reconstruction must never
    // have. The message must name the datum hash, so an operator knows exactly
    // which output to re-index.
    #[tokio::test]
    async fn reconstruct_hard_errors_on_an_unresolvable_tm_datum() {
        let (mut world, _) = one_movement_world();
        let hash = "ab".repeat(32);
        world
            .tm
            .push(fake_out_unresolved([0xee; 32], 3, &[], &hash));
        let err = reconstruct(&world, &fake_cfg()).await.unwrap_err();
        assert!(matches!(err, CpoTrieError::Source(_)), "{err}");
        let msg = format!("{err}");
        assert!(msg.contains("unexplained gap"), "{msg}");
        assert!(msg.contains(&hash), "the message must name the hash: {msg}");
        assert!(
            msg.contains("fake advice"),
            "the backend's remediation: {msg}"
        );
    }

    // A TM-address output with NO datum at all is provably not a TM record —
    // every genuine Unconfirmed/Confirmed record carries an inline datum — so it
    // MUST be skipped rather than treated the same as an unresolvable one.
    // Before the fix this hard-errored exactly like the case above, meaning one
    // junk, datum-less payment to the TM address could block every SPO's
    // reconstruction forever.
    #[tokio::test]
    async fn reconstruct_skips_a_datum_less_output_at_the_tm_address() {
        let (mut world, root) = one_movement_world();
        world.tm.push(fake_out([0xee; 32], 3, &[], None));
        let trie = reconstruct(&world, &fake_cfg())
            .await
            .expect("a datum-less junk output at the TM address must not abort reconstruction");
        assert_eq!(trie.root(), root);
        assert_eq!(trie.len(), 1);
    }

    // The mirror image: at the PEG-OUT address BOTH a datum-less output and an
    // unresolvable one are skipped, never fatal. The address is permissionlessly
    // payable, so erroring on either would let anyone block every reconstruction
    // with one junk UTxO — and a missing request cannot silently shrink the
    // trie, it only makes some TM fail its own assertion.
    #[tokio::test]
    async fn reconstruct_skips_an_unresolvable_pegout_datum() {
        let (mut world, root) = one_movement_world();
        world.pegout.push(fake_out(
            [0xee; 32],
            0,
            &[(format!("{FBTC}66425443"), 5_000)],
            None,
        ));
        let trie = reconstruct(&world, &fake_cfg()).await.unwrap();
        assert_eq!(trie.root(), root);
    }

    #[tokio::test]
    async fn reconstruct_skips_a_hash_only_unresolvable_pegout_datum() {
        let (mut world, root) = one_movement_world();
        world.pegout.push(fake_out_unresolved(
            [0xef; 32],
            0,
            &[(format!("{FBTC}66425443"), 5_000)],
            &"cd".repeat(32),
        ));
        let trie = reconstruct(&world, &fake_cfg()).await.unwrap();
        assert_eq!(trie.root(), root);
    }

    // The last safety net: a replay that stopped short passes every per-movement
    // assertion and still yields a short trie. Only the singleton catches it.
    #[tokio::test]
    async fn reconstruct_refuses_a_trie_the_singleton_disagrees_with() {
        use crate::cardano::plutus::{bytes, constr};
        let (mut world, _) = one_movement_world();
        world.singleton = vec![fake_out(
            [0xcf; 32],
            0,
            &[(format!("{POLICY}{CPO_ASSET_NAME_HEX}"), 1)],
            Some(constr(0, vec![bytes(&[0x5a; 32])])),
        )];
        let err = reconstruct(&world, &fake_cfg()).await.unwrap_err();
        assert!(matches!(err, CpoTrieError::RootMismatch { .. }), "{err}");
    }

    // Zero outputs holding the NFT means the singleton is not deployed or not
    // indexed; several mean it is not a singleton. Neither may pass as "checked".
    #[tokio::test]
    async fn reconstruct_reports_a_missing_or_duplicated_singleton() {
        let (mut world, _) = one_movement_world();
        world.singleton = vec![];
        let err = reconstruct(&world, &fake_cfg()).await.unwrap_err();
        assert!(
            format!("{err}").contains("no unspent output holds"),
            "{err}"
        );

        let (mut world, root) = one_movement_world();
        use crate::cardano::plutus::{bytes, constr};
        let unit = format!("{POLICY}{CPO_ASSET_NAME_HEX}");
        world.singleton = vec![
            fake_out(
                [0xcf; 32],
                0,
                &[(unit.clone(), 1)],
                Some(constr(0, vec![bytes(&root)])),
            ),
            fake_out(
                [0xdf; 32],
                0,
                &[(unit, 1)],
                Some(constr(0, vec![bytes(&root)])),
            ),
        ];
        let err = reconstruct(&world, &fake_cfg()).await.unwrap_err();
        assert!(format!("{err}").contains("not a singleton"), "{err}");
    }
}
