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
    /// Unix seconds. Not decoration: it is how "the reservation transaction has
    /// not confirmed yet" is told apart from "the nonce was spent", which
    /// Blockfrost cannot distinguish — it reports confirmed UTxOs only, so a
    /// freshly created one is simply absent.
    pub created_at: u64,
    /// Whether the transaction that creates this UTxO was broadcast.
    ///
    /// False after `--no-submit-reservation`, which prints the transaction and
    /// leaves broadcasting to the operator. Without this the later "not in the
    /// wallet" would be diagnosed as a spent nonce and the operator told to
    /// throw away a signature that is perfectly good.
    pub submitted: bool,
}

/// How long after a reservation is written its UTxO may legitimately be missing
/// from a confirmed-only UTxO query. Preprod blocks are ~20 s; five minutes is
/// many blocks and still short enough that a genuinely spent nonce is not
/// mistaken for a slow one for long.
pub const CONFIRMATION_GRACE_SECS: u64 = 300;

/// Why a reserved outpoint is not among the wallet's UTxOs — which decides what
/// the operator should do, and they are not the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingNonce {
    /// The transaction was never broadcast. Broadcast it.
    NeverSubmitted,
    /// Broadcast recently enough that it may simply not have confirmed. Wait.
    NotConfirmedYet,
    /// Old enough that it should have confirmed. It was spent, and any
    /// signature bound to it is used up.
    Spent,
}

#[must_use]
pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("nonce-reservation.json")
}

impl NonceReservation {
    #[must_use]
    pub fn new(outpoint: NonceOutpoint, action: Action, created_at: u64, submitted: bool) -> Self {
        Self {
            version: RESERVATION_STATE_VERSION,
            outpoint: outpoint.to_string(),
            action,
            created_at,
            submitted,
        }
    }

    /// Why the reserved UTxO is missing, given the time now.
    #[must_use]
    pub fn why_missing(&self, now: u64) -> MissingNonce {
        if !self.submitted {
            return MissingNonce::NeverSubmitted;
        }
        if now.saturating_sub(self.created_at) < CONFIRMATION_GRACE_SECS {
            return MissingNonce::NotConfirmedYet;
        }
        MissingNonce::Spent
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

/// The form a wallet UTxO set must be built in on any path that can SPEND.
///
/// `WalletUtxo::from_bf` alone produces a set in which `reserved` is false for
/// everything, and that is not a visible failure — it is a set in which the
/// nonce looks spendable to every selector that consults the flag. Three
/// separate paths were built that way before this existed. So the mapping and
/// the marking are one call, it returns a `Result` the compiler will not let a
/// caller drop, and the name says which of the two it is for.
pub fn wallet_set(
    raw: &[crate::cardano::bf_http::BfUtxo],
    state_dir: Option<&Path>,
) -> Result<Vec<WalletUtxo>, String> {
    mark_from_state_dir(raw.iter().map(WalletUtxo::from_bf).collect(), state_dir)
}

/// [`wallet_set`] for the two callers where an unreadable record must NOT be
/// fatal.
///
/// The daemon, because refusing would stop `run-spo` posting treasury
/// movements, bans and the key handoff — over a file that belongs to a
/// registration flow, and surfacing as a chain error attached to an epoch
/// operation that has nothing to do with one. The node has already passed a
/// startup gate that reads this file (preflight step 12), so an unreadable one
/// here is a file that CHANGED under a running daemon.
///
/// And the `--nonce-utxo` override, because that flag IS the documented way out
/// of an unreadable record: the operator read the outpoint out of the signed
/// file and is naming it by hand. A strict read there would make the remedy
/// unreachable — the command would abort on the very file the operator is
/// working around.
///
/// Both say so loudly, once per read, and carry on with nothing marked: there
/// is no outpoint to protect if the record cannot be parsed.
pub fn wallet_set_lenient(
    raw: &[crate::cardano::bf_http::BfUtxo],
    state_dir: Option<&Path>,
) -> Vec<WalletUtxo> {
    let utxos: Vec<WalletUtxo> = raw.iter().map(WalletUtxo::from_bf).collect();
    match mark_from_state_dir(utxos.clone(), state_dir) {
        Ok(marked) => marked,
        Err(e) => {
            tracing::warn!(
                "the nonce reservation could not be read ({e}), so no wallet UTxO is being \
                 held back. If a registration or exit signature is at a cold key right now, \
                 its nonce is unprotected — fix the state dir, and check `heimdall doctor` \
                 step 12"
            );
            utxos
        }
    }
}

/// Whether an outpoint may be used as a nonce at all.
///
/// `still_unspent` answers "does the wallet hold it"; this adds the one
/// exclusion that matters and that a bare outpoint match cannot see. A UTxO
/// carrying a reference script is spendable, but spending one destroys a
/// deployed reference script and incurs the Conway per-byte fee no builder here
/// prices — and `deploy-registry-ref` leaves exactly such a UTxO at this
/// wallet, where `--nonce-utxo` would happily accept it.
pub fn usable_as_nonce(utxos: &[WalletUtxo], nonce: NonceOutpoint) -> Result<(), String> {
    match utxos.iter().find(|u| u.outpoint() == Some(nonce)) {
        None => Err(format!("{nonce} is not an unspent UTxO of this wallet")),
        Some(u) if u.has_ref_script => Err(format!(
            "{nonce} carries a reference script. Spending it would destroy a deployed script \
             — the registry reference script is very likely this one — and the transaction \
             would also carry it as a reference input. Choose an ordinary UTxO"
        )),
        Some(_) => Ok(()),
    }
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
        let rec = NonceReservation::new(outpoint(7, 3), Action::Deregister, 1_700_000_000, true);
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
            br#"{"version":99,"outpoint":"00#0","action":"register","created_at":0,"submitted":true}"#,
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

    /// Absent from a CONFIRMED-ONLY UTxO query is three different situations,
    /// and only one of them means the operator must make a second trip to the
    /// cold key. Reporting the other two as "spent" is how a perfectly good
    /// signature gets thrown away.
    #[test]
    fn a_missing_nonce_is_diagnosed_by_why_it_is_missing() {
        let never = NonceReservation::new(outpoint(1, 0), Action::Register, 1_000, false);
        assert_eq!(never.why_missing(1_000), MissingNonce::NeverSubmitted);
        // Still not submitted, however long ago: age cannot make a transaction
        // that was never broadcast into a spent one.
        assert_eq!(never.why_missing(9_999_999), MissingNonce::NeverSubmitted);

        let fresh = NonceReservation::new(outpoint(1, 0), Action::Register, 1_000, true);
        assert_eq!(fresh.why_missing(1_010), MissingNonce::NotConfirmedYet);
        assert_eq!(
            fresh.why_missing(1_000 + CONFIRMATION_GRACE_SECS - 1),
            MissingNonce::NotConfirmedYet
        );
        assert_eq!(
            fresh.why_missing(1_000 + CONFIRMATION_GRACE_SECS),
            MissingNonce::Spent
        );
    }

    /// A UTxO carrying a reference script is spendable, and spending it destroys
    /// a deployed script — `deploy-registry-ref` leaves exactly one at this
    /// wallet, and `--nonce-utxo` would otherwise take it.
    #[test]
    fn a_reference_script_utxo_is_not_usable_as_a_nonce() {
        let mut with_script = utxo(4, 0);
        with_script.has_ref_script = true;
        let set = vec![utxo(1, 0), with_script];
        assert!(usable_as_nonce(&set, outpoint(1, 0)).is_ok());
        let err = usable_as_nonce(&set, outpoint(4, 0)).expect_err("must refuse");
        assert!(err.contains("reference script"), "{err}");
        let err = usable_as_nonce(&set, outpoint(9, 9)).expect_err("must refuse");
        assert!(err.contains("not an unspent UTxO"), "{err}");
    }

    /// The daemon variant must not turn an unreadable record into a liveness
    /// failure: `run-spo` posts treasury movements, bans and the key handoff
    /// through it, and none of them has anything to do with a registration.
    #[test]
    fn the_lenient_variant_survives_an_unreadable_record() {
        let dir = std::env::temp_dir().join(format!("heimdall-nonce-d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(state_path(&dir), b"not json at all").unwrap();
        // The command variant refuses, which is right where an operator is
        // about to make a trip to a safe.
        assert!(mark_from_state_dir(vec![utxo(1, 0)], Some(&dir)).is_err());
        // The daemon carries on with nothing marked.
        let set = wallet_set_lenient(&[], Some(&dir));
        assert!(set.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
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
