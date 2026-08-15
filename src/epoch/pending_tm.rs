//! The Treasury Movement this node has signed and posted but has not yet folded
//! into its two cumulative tries.
//!
//! ## Why a file, and not a variable
//!
//! Both tries advance ONLY on a movement the chain has confirmed — an in-flight
//! TM can still be replaced (RBF) or simply never mine, and a trie that recorded
//! it would attest a root no chain state backs. So there is a gap between posting
//! a movement and folding it, and on a real bridge that gap is HOURS: heimdall
//! posts the `UnconfirmedTm` record to Cardano, a watchtower relays the bytes to
//! Bitcoin, and the head only advances after ~100 Bitcoin confirmations plus the
//! oracle's challenge-aging window.
//!
//! The machine used to hold the movement in memory and block in `AwaitConfirm`
//! until it saw it confirmed. That made a durable fold depend on one process
//! staying awake across that whole window (WI-032): a restart, a crash, or the
//! `tm_confirmation_timeout` expiring dropped the movement on the floor, the
//! tries never advanced, and every later build was refused by
//! `cross_check_bridge_roots` — permanently, because nothing re-derives the fold.
//!
//! Persisting the record instead makes the fold a function of what the node
//! OBSERVES rather than of how long it ran. It survives restarts, and the node
//! can spend the intervening hours doing its job — passing batch opportunities
//! the spec says to pass — instead of sitting in a poll loop.
//!
//! ## What it holds, and what it does not
//!
//! Only what the fold needs: the movement's identity, the treasury head it
//! spends, the two roots it committed, and the two entry sets. A whole
//! [`TreasuryMovement`] is not serializable (`TaprootSpendInfo`, `frost::Signature`)
//! and is not needed — this node already signed and posted; what remains is
//! bookkeeping.
//!
//! There is at most ONE record. The batch gate only builds when nothing is in
//! flight, so a second movement cannot exist while a first is pending, and a
//! fee-bumped rebuild of the same batch (spec §Stuck-TM recovery) simply
//! overwrites: it spends the same head and commits the same roots.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cardano::cpo_trie::CpoEntry;
use crate::cardano::state_file;
use crate::epoch::state::TreasuryMovement;

/// Bump when the on-disk shape changes incompatibly; an older/newer file is
/// refused rather than misread.
const PENDING_TM_STATE_VERSION: u32 = 1;

/// A movement posted by this node's roster, awaiting the chain's confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTm {
    /// The epoch that built it — carried for the log line only, so a fold that
    /// happens epochs later still names where the movement came from.
    pub epoch: u64,
    /// The movement's Bitcoin txid.
    pub txid: bitcoin::Txid,
    /// The treasury head this movement SPENDS (its input 0).
    ///
    /// This, not the txid, is what decides whether the fold is due: while the
    /// chain still reports this outpoint as the head, nothing has landed on top
    /// of it and there is nothing to fold. See `settle_pending_tm`.
    pub spends: bitcoin::OutPoint,
    /// The completed-peg-outs root the movement committed — the value the fold
    /// must reproduce.
    pub cpo_root: [u8; 32],
    /// The swept-peg-ins root the movement committed — likewise.
    pub spi_root: [u8; 32],
    /// The peg-outs it fulfils, already reduced to trie entries.
    pub fulfilled: Vec<CpoEntry>,
    /// Every tx input in the 36-byte outpoint encoding, input order — the exact
    /// argument `SpiTrie::insert_for_confirmed_tm` takes ([SPI-1], [SPI-3]).
    pub swept: Vec<[u8; 36]>,
}

impl PendingTm {
    /// Reduce a just-posted movement to the record the fold needs.
    ///
    /// Fails only on a movement with no inputs, which `build_tm` cannot produce
    /// — the treasury input is always input 0 — but which would otherwise leave
    /// `spends` guessed rather than known.
    pub fn from_movement(epoch: u64, tm: &TreasuryMovement) -> Result<Self, String> {
        let spends = tm
            .unsigned_tx
            .input
            .first()
            .map(|i| i.previous_output)
            .ok_or_else(|| format!("treasury movement {} has no inputs", tm.txid))?;
        Ok(Self {
            epoch,
            txid: tm.txid,
            spends,
            cpo_root: tm.cpo_root,
            spi_root: tm.spi_root,
            fulfilled: tm.fulfilled.iter().map(CpoEntry::from).collect(),
            swept: tm.input_outpoints(),
        })
    }

    /// The record's file inside `state_dir`.
    #[must_use]
    pub fn state_path(state_dir: &Path) -> PathBuf {
        state_dir.join("pending-tm.json")
    }

    /// Load the record. `Ok(None)` when there is none — the ordinary state of a
    /// node with nothing in flight.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, String> {
        let path = Self::state_path(state_dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        let persisted: Persisted = serde_json::from_slice(&bytes)
            .map_err(|e| format!("decode {}: {e}", path.display()))?;
        if persisted.version != PENDING_TM_STATE_VERSION {
            return Err(format!(
                "{}: unsupported state version {} (expected {PENDING_TM_STATE_VERSION})",
                path.display(),
                persisted.version
            ));
        }
        persisted
            .decode()
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Persist atomically, 0600 in a 0700 directory — the same discipline as the
    /// tries and the DKG share. The record is not secret, but it decides what
    /// this node folds into the roots it signs with.
    pub fn save(&self, state_dir: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&Persisted::encode(self))
            .map_err(|e| format!("encode: {e}"))?;
        state_file::write_atomic_0600(state_dir, &Self::state_path(state_dir), &bytes)
    }

    /// Drop the record once its movement has been folded. A missing file is
    /// success: the caller's intent is "no record remains".
    pub fn clear(state_dir: &Path) -> Result<(), String> {
        let path = Self::state_path(state_dir);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {}: {e}", path.display())),
        }
    }
}

// ---------------------------------------------------------------------------
// on-disk shape
// ---------------------------------------------------------------------------

/// Hex-encoded throughout, like the trie state files: the record is meant to be
/// readable by an operator diagnosing a stuck node, and every field in it is
/// something they would otherwise have to dig out of a log.
#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    epoch: u64,
    txid: String,
    spends_txid: String,
    spends_vout: u32,
    cpo_root: String,
    spi_root: String,
    fulfilled: Vec<PersistedEntry>,
    swept: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct PersistedEntry {
    por_id: String,
    value: String,
}

impl Persisted {
    fn encode(p: &PendingTm) -> Self {
        Self {
            version: PENDING_TM_STATE_VERSION,
            epoch: p.epoch,
            txid: p.txid.to_string(),
            spends_txid: p.spends.txid.to_string(),
            spends_vout: p.spends.vout,
            cpo_root: hex::encode(p.cpo_root),
            spi_root: hex::encode(p.spi_root),
            fulfilled: p
                .fulfilled
                .iter()
                .map(|e| PersistedEntry {
                    por_id: hex::encode(e.por_id),
                    value: hex::encode(&e.value),
                })
                .collect(),
            swept: p.swept.iter().map(hex::encode).collect(),
        }
    }

    fn decode(self) -> Result<PendingTm, String> {
        let txid: bitcoin::Txid = self.txid.parse().map_err(|e| format!("txid: {e}"))?;
        let spends_txid: bitcoin::Txid = self
            .spends_txid
            .parse()
            .map_err(|e| format!("spends_txid: {e}"))?;
        let mut fulfilled = Vec::with_capacity(self.fulfilled.len());
        for e in &self.fulfilled {
            fulfilled.push(CpoEntry {
                por_id: hex32(&e.por_id, "por_id")?,
                value: hex::decode(&e.value).map_err(|err| format!("value hex: {err}"))?,
            });
        }
        let mut swept = Vec::with_capacity(self.swept.len());
        for s in &self.swept {
            let bytes = hex::decode(s).map_err(|e| format!("swept outpoint hex: {e}"))?;
            swept.push(bytes.try_into().map_err(|v: Vec<u8>| {
                format!("swept outpoint is {} bytes, expected 36", v.len())
            })?);
        }
        Ok(PendingTm {
            epoch: self.epoch,
            txid,
            spends: bitcoin::OutPoint {
                txid: spends_txid,
                vout: self.spends_vout,
            },
            cpo_root: hex32(&self.cpo_root, "cpo_root")?,
            spi_root: hex32(&self.spi_root, "spi_root")?,
            fulfilled,
            swept,
        })
    }
}

fn hex32(s: &str, field: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| format!("{field} hex: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("{field} is {} bytes, expected 32", v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory per test, named so concurrent test binaries cannot
    /// collide — the same shape the trie state tests use.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("heimdall-pending-tm-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample() -> PendingTm {
        PendingTm {
            epoch: 42,
            txid: "1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            spends: bitcoin::OutPoint {
                txid: "2222222222222222222222222222222222222222222222222222222222222222"
                    .parse()
                    .unwrap(),
                vout: 3,
            },
            cpo_root: [0xaa; 32],
            spi_root: [0xbb; 32],
            fulfilled: vec![CpoEntry {
                por_id: [0xcc; 32],
                value: vec![1, 2, 3],
            }],
            swept: vec![[0xdd; 36], [0xee; 36]],
        }
    }

    #[test]
    fn a_saved_record_reloads_byte_for_byte() {
        let dir = TestDir::new("roundtrip");
        let p = sample();
        p.save(dir.path()).unwrap();
        assert_eq!(PendingTm::load(dir.path()).unwrap(), Some(p));
    }

    #[test]
    fn no_file_is_no_record_not_an_error() {
        let dir = TestDir::new("absent");
        assert_eq!(PendingTm::load(dir.path()).unwrap(), None);
    }

    #[test]
    fn clearing_is_idempotent() {
        let dir = TestDir::new("clear");
        PendingTm::clear(dir.path()).expect("clearing nothing succeeds");
        sample().save(dir.path()).unwrap();
        PendingTm::clear(dir.path()).unwrap();
        PendingTm::clear(dir.path()).expect("clearing twice succeeds");
        assert_eq!(PendingTm::load(dir.path()).unwrap(), None);
    }

    /// A record written by a future heimdall must not be silently half-read:
    /// folding a partial record would advance the tries to a root the chain
    /// does not hold.
    #[test]
    fn an_unknown_state_version_is_refused() {
        let dir = TestDir::new("version");
        sample().save(dir.path()).unwrap();
        let path = PendingTm::state_path(dir.path());
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, raw.replace("\"version\": 1", "\"version\": 99")).unwrap();
        let err = PendingTm::load(dir.path()).expect_err("a future version is refused");
        assert!(err.contains("unsupported state version 99"), "{err}");
    }

    #[test]
    fn a_truncated_root_is_refused_rather_than_padded() {
        let dir = TestDir::new("truncated");
        sample().save(dir.path()).unwrap();
        let path = PendingTm::state_path(dir.path());
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, raw.replace(&hex::encode([0xaa; 32]), "aabb")).unwrap();
        let err = PendingTm::load(dir.path()).expect_err("a short root is refused");
        assert!(err.contains("cpo_root is 2 bytes"), "{err}");
    }
}
