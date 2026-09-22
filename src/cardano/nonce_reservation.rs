//! The wallet UTxO a pending registration or exit signature is bound to.
//!
//! Since spec rev 5.6 both cold-signed messages end with the outpoint of an
//! input the transaction spends ([REG-10], [DRG-6]). That outpoint is chosen
//! when the request file is written and has to still be unspent when the signed
//! file comes back — which, in the air-gapped flow, is hours or days later.
//!
//! Nothing else in heimdall would leave it alone. `run-spo` posts treasury
//! movements and bans from this same wallet the whole time the operator is
//! walking a file to a safe, and fee selection takes the richest UTxO it can
//! find. So the outpoint is written here, [`mark_reserved`] flags it on the way
//! out of the wallet fetch, and `select_fee` / `select_collateral` /
//! `register_pool::select_inputs` skip anything flagged. The record is cleared
//! once the transaction it belongs to is confirmed.
//!
//! The file is one record, not a list: an operator registers or exits one pool
//! from one node, and two concurrent reservations would mean two signatures in
//! flight for the same pool, which is not a thing to support quietly.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cardano::airgap::Action;
use crate::cardano::publish::WalletUtxo;
use crate::cardano::state_file;
use crate::cardano::tx_common::NonceOutpoint;

/// Bumped when a field changes meaning. A mismatch is an error, not a silent
/// reset: forgetting a reservation is how the UTxO gets spent.
const RESERVATION_STATE_VERSION: u32 = 1;

/// What `heimdall reserve-nonce` — in practice, the request half of
/// `register-spo` / `deregister-spo` — wrote down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceReservation {
    pub version: u32,
    /// `<txid hex>#<index>`.
    pub outpoint: String,
    /// Which command the reservation belongs to, so a stale one can be named.
    pub action: Action,
    /// Unix seconds, for the `doctor` report.
    pub created_at: u64,
}

#[must_use]
pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("nonce-reservation.json")
}

impl NonceReservation {
    #[must_use]
    pub fn new(outpoint: NonceOutpoint, action: Action, created_at: u64) -> Self {
        Self {
            version: RESERVATION_STATE_VERSION,
            outpoint: outpoint.to_string(),
            action,
            created_at,
        }
    }

    /// The reserved outpoint, parsed.
    pub fn nonce(&self) -> Result<NonceOutpoint, String> {
        NonceOutpoint::parse(&self.outpoint)
    }

    /// Read the record, or `None` when there is no reservation.
    ///
    /// A version mismatch or a malformed outpoint is an ERROR rather than a
    /// `None`: both mean a reservation exists that this binary cannot honour,
    /// and treating that as "nothing reserved" is exactly how the UTxO under it
    /// gets spent for a fee.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, String> {
        let path = state_path(state_dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        let rec: Self =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
        if rec.version != RESERVATION_STATE_VERSION {
            return Err(format!(
                "{} is version {} and this heimdall writes version {RESERVATION_STATE_VERSION}",
                path.display(),
                rec.version,
            ));
        }
        rec.nonce()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Some(rec))
    }

    /// `load`, tolerating an unset state dir — the offline test paths have none.
    pub fn load_or_none(state_dir: Option<&Path>) -> Result<Option<Self>, String> {
        match state_dir {
            None => Ok(None),
            Some(dir) => Self::load(dir),
        }
    }

    pub fn save(&self, state_dir: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| format!("serialize the nonce reservation: {e}"))?;
        state_file::write_atomic_0600(state_dir, &state_path(state_dir), &bytes)
    }
}

/// Drop the record. Called once the transaction that spends the nonce is
/// confirmed, and by `--keep`-less cleanup paths.
///
/// Absent is success: clearing twice is not an error, and a caller that has
/// just confirmed a transaction should not fail over the bookkeeping.
pub fn clear(state_dir: &Path) -> Result<(), String> {
    let path = state_path(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

/// Flag the reserved UTxO in a freshly fetched wallet set.
///
/// Returns the list with at most one entry's `reserved` set. A reservation
/// naming an outpoint the wallet no longer holds sets nothing — the UTxO is
/// already gone, and the caller that cares (the builder, `doctor`) reports that
/// itself rather than having it hidden here.
#[must_use]
pub fn mark_reserved(utxos: Vec<WalletUtxo>, reserved: Option<NonceOutpoint>) -> Vec<WalletUtxo> {
    let Some(want) = reserved else {
        return utxos;
    };
    utxos
        .into_iter()
        .map(|mut u| {
            if u.outpoint() == Some(want) {
                u.reserved = true;
            }
            u
        })
        .collect()
}

/// Read the reservation from `state_dir` and flag it on a fetched wallet set,
/// in one call.
///
/// The form every command path should use. `mark_reserved` alone is easy to
/// forget — and forgetting it is not a visible failure, it is a wallet set in
/// which the nonce looks spendable to every selector that consults the flag.
/// `ensure-collateral` forgot exactly that, and `build_collateral_top_up`
/// reaches for SMALL UTxOs, which is what a 2 ADA reservation is.
pub fn mark_from_state_dir(
    utxos: Vec<WalletUtxo>,
    state_dir: Option<&Path>,
) -> Result<Vec<WalletUtxo>, String> {
    let reserved = NonceReservation::load_or_none(state_dir)?
        .map(|r| r.nonce())
        .transpose()?;
    Ok(mark_reserved(utxos, reserved))
}

/// Whether the reserved outpoint is still among the wallet's UTxOs.
#[must_use]
pub fn still_unspent(utxos: &[WalletUtxo], reserved: NonceOutpoint) -> bool {
    utxos.iter().any(|u| u.outpoint() == Some(reserved))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint(seed: u8, index: u32) -> NonceOutpoint {
        NonceOutpoint::new([seed; 32], index)
    }

    fn utxo(seed: u8, index: u32) -> WalletUtxo {
        WalletUtxo {
            tx_hash: hex::encode([seed; 32]),
            output_index: index,
            lovelace: 5_000_000,
            tokens: std::collections::BTreeMap::new(),
            has_ref_script: false,
            reserved: false,
        }
    }

    #[test]
    fn round_trips_through_the_state_dir() {
        let dir = std::env::temp_dir().join(format!("heimdall-nonce-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rec = NonceReservation::new(outpoint(7, 3), Action::Deregister, 1_700_000_000);
        rec.save(&dir).expect("save");
        let back = NonceReservation::load(&dir)
            .expect("load")
            .expect("present");
        assert_eq!(back, rec);
        assert_eq!(back.nonce().unwrap(), outpoint(7, 3));
        clear(&dir).expect("clear");
        assert!(NonceReservation::load(&dir).expect("load").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_version_mismatch_is_an_error_not_an_absent_reservation() {
        let dir = std::env::temp_dir().join(format!("heimdall-nonce-v-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            state_path(&dir),
            br#"{"version":99,"outpoint":"00#0","action":"register","created_at":0}"#,
        )
        .unwrap();
        let err = NonceReservation::load(&dir).expect_err("must not be read as absent");
        assert!(err.contains("version 99"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn marks_only_the_reserved_outpoint() {
        let set = vec![utxo(1, 0), utxo(2, 5), utxo(3, 1)];
        let marked = mark_reserved(set, Some(outpoint(2, 5)));
        assert_eq!(
            marked.iter().filter(|u| u.reserved).count(),
            1,
            "exactly one UTxO is reserved"
        );
        assert!(marked[1].reserved, "and it is the one named");
    }

    #[test]
    fn a_reservation_the_wallet_no_longer_holds_marks_nothing() {
        let set = vec![utxo(1, 0), utxo(2, 5)];
        assert!(!still_unspent(&set, outpoint(9, 9)));
        let marked = mark_reserved(set, Some(outpoint(9, 9)));
        assert!(marked.iter().all(|u| !u.reserved));
    }

    // Coin selection is where the reservation earns its keep: a daemon posting
    // a movement mid-round-trip must not take the nonce for a fee, even when it
    // is the richest UTxO in the wallet.
    #[test]
    fn fee_selection_skips_the_reservation() {
        use crate::cardano::tx_common::{select_collateral, select_fee};
        let mut rich = utxo(2, 5);
        rich.lovelace = 100_000_000;
        let set = mark_reserved(vec![utxo(1, 0), rich], Some(outpoint(2, 5)));
        let fee = select_fee(&set, 1_000_000).expect("the unreserved UTxO still pays");
        assert_eq!(fee.tx_hash, hex::encode([1u8; 32]));
        let coll = select_collateral(&set, &[]).expect("and still collateralizes");
        assert_eq!(coll.tx_hash, hex::encode([1u8; 32]));
    }
}
