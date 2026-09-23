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
    /// Whether the transaction that creates this UTxO is known to have been
    /// broadcast — accepted by the provider, or seen in the wallet since.
    ///
    /// False after `--no-submit-reservation`, which prints the transaction and
    /// leaves broadcasting to the operator, and after a broadcast that failed.
    /// Without this the later "not in the wallet" would be diagnosed as a spent
    /// nonce and the operator told to throw away a signature that is perfectly
    /// good. Set once the UTxO is SEEN, too ([`Self::seen_on_chain`]): a record
    /// left at false after its UTxO existed would read "never submitted"
    /// forever, including after the nonce was spent.
    pub submitted: bool,
    /// The signed transaction that creates the UTxO, hex — kept so a broadcast
    /// that failed, or one left to the operator, can be sent again from the
    /// record instead of from a terminal scrollback that may be gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_tx: Option<String>,
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
            reservation_tx: None,
        }
    }

    /// This record, carrying the signed transaction that creates the UTxO.
    #[must_use]
    pub fn with_tx(mut self, signed_tx_hex: String) -> Self {
        self.reservation_tx = Some(signed_tx_hex);
        self
    }

    /// Record that the UTxO has been seen in the wallet, so it WAS broadcast.
    ///
    /// Returns whether anything changed, so a caller saves only then. The
    /// transaction is dropped from the record once it cannot be needed again.
    pub fn seen_on_chain(&mut self) -> bool {
        if self.submitted && self.reservation_tx.is_none() {
            return false;
        }
        self.submitted = true;
        self.reservation_tx = None;
        true
    }

    /// Record a broadcast that the provider accepted, at `now` — the moment the
    /// confirmation grace starts from.
    pub fn broadcast_at(&mut self, now: u64) {
        self.submitted = true;
        self.created_at = now;
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
    Ok(mark_in_flight(mark_reserved(utxos, reserved)))
}

/// How long a wallet input this process spent is held back from selection
/// after its transaction was accepted. Long enough for many blocks — a
/// transaction that has not landed by then has been dropped, and its inputs
/// are spendable again.
const IN_FLIGHT_SECS: u64 = 600;

/// Wallet outpoints this process has spent in transactions the provider
/// accepted and that may not have confirmed yet, with when.
static IN_FLIGHT: std::sync::Mutex<Vec<(NonceOutpoint, std::time::Instant)>> =
    std::sync::Mutex::new(Vec::new());

/// Hold `spent` back from every wallet read in this process until its
/// transaction has had time to confirm.
///
/// Blockfrost reports CONFIRMED UTxOs only, so for a block or two after a
/// submission the inputs it spent still look unspent. One writer never notices;
/// two do. `run-spo` has two: the epoch loop, and the registry migration it
/// performs at startup and retries in the background from the same wallet. Both
/// take the richest UTxO for a fee, so without this the second transaction
/// spends what the first already did, and is rejected — which, when the second
/// is a treasury movement or the key handoff, is a missed epoch operation over
/// a registration chore.
pub fn note_in_flight(spent: impl IntoIterator<Item = NonceOutpoint>) {
    let now = std::time::Instant::now();
    let mut held = IN_FLIGHT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.extend(spent.into_iter().map(|o| (o, now)));
}

/// Flag every in-flight outpoint in a freshly fetched wallet set, dropping the
/// ones that have aged out.
fn mark_in_flight(utxos: Vec<WalletUtxo>) -> Vec<WalletUtxo> {
    let held: Vec<NonceOutpoint> = {
        let mut held = IN_FLIGHT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.retain(|(_, at)| at.elapsed().as_secs() < IN_FLIGHT_SECS);
        held.iter().map(|(o, _)| *o).collect()
    };
    if held.is_empty() {
        return utxos;
    }
    utxos
        .into_iter()
        .map(|mut u| {
            if u.outpoint().is_some_and(|o| held.contains(&o)) {
                u.reserved = true;
            }
            u
        })
        .collect()
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
        // The in-flight hold does not depend on the file, so it still applies.
        Err(e) => {
            tracing::warn!(
                "the nonce reservation could not be read ({e}), so no wallet UTxO is being \
                 held back. If a registration or exit signature is at a cold key right now, \
                 its nonce is unprotected — fix the state dir, and check `heimdall doctor` \
                 step 12"
            );
            mark_in_flight(utxos)
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

    /// A raw Blockfrost UTxO, so the lenient path can be exercised on a wallet
    /// that actually has something in it.
    fn bf_ada_utxo(tx_hash: &str, index: u32, lovelace: u64) -> crate::cardano::bf_http::BfUtxo {
        crate::cardano::bf_http::BfUtxo {
            tx_hash: tx_hash.to_string(),
            output_index: index,
            amount: vec![crate::cardano::bf_http::BfAmount {
                unit: "lovelace".into(),
                quantity: lovelace.to_string(),
            }],
            inline_datum: None,
            reference_script_hash: None,
        }
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

    /// A reservation made with `--no-submit-reservation` and broadcast by hand
    /// must stop reading "never submitted" once its UTxO has been seen —
    /// otherwise, after the registration spends it, every diagnosis says
    /// "submit it" instead of "used up", and the opposite command is refused
    /// with advice that can no longer be followed.
    #[test]
    fn a_reservation_seen_on_chain_is_diagnosed_as_spent_once_it_is_gone() {
        let mut rec = NonceReservation::new(outpoint(1, 0), Action::Register, 1_000, false)
            .with_tx("84a4".into());
        assert_eq!(rec.why_missing(1_000_000), MissingNonce::NeverSubmitted);
        assert!(rec.seen_on_chain(), "the first sighting changes the record");
        assert!(!rec.seen_on_chain(), "and the second does not");
        assert!(
            rec.reservation_tx.is_none(),
            "the transaction is no longer needed"
        );
        assert_eq!(rec.why_missing(1_000_000), MissingNonce::Spent);
    }

    /// The record written before a broadcast must carry the transaction, and a
    /// record written by an older binary — no `reservation_tx` field — must
    /// still load.
    #[test]
    fn the_reservation_transaction_round_trips_and_is_optional() {
        let dir = std::env::temp_dir().join(format!("heimdall-nonce-tx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rec = NonceReservation::new(outpoint(5, 1), Action::Deregister, 7, false)
            .with_tx("abcd".into());
        rec.save(&dir).expect("save");
        let back = NonceReservation::load(&dir)
            .expect("load")
            .expect("present");
        assert_eq!(back.reservation_tx.as_deref(), Some("abcd"));

        std::fs::write(
            state_path(&dir),
            format!(
                r#"{{"version":1,"outpoint":"{}","action":"register","created_at":0,"submitted":true}}"#,
                outpoint(5, 1)
            ),
        )
        .unwrap();
        let old = NonceReservation::load(&dir)
            .expect("load")
            .expect("present");
        assert!(old.reservation_tx.is_none());
        let _ = std::fs::remove_dir_all(&dir);
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
        // The daemon carries on WITH THE WALLET — that is the property, and an
        // empty input slice cannot check it: an implementation that returned
        // `Vec::new()` on a parse error would pass, and every daemon path would
        // then fail with "no wallet UTxO available for the fee input", which is
        // the liveness failure this function exists to prevent.
        let raw = [bf_ada_utxo(&hex::encode([1u8; 32]), 0, 9_000_000)];
        let set = wallet_set_lenient(&raw, Some(&dir));
        assert_eq!(set.len(), 1, "the wallet comes back intact");
        assert!(
            !set[0].reserved,
            "and unmarked — there is nothing to protect"
        );
        assert_eq!(set[0].lovelace, 9_000_000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An input spent by a transaction this process submitted is held back from
    /// the next wallet read, though the provider still lists it — the epoch
    /// loop must not pick the fee input a startup migration just spent.
    #[test]
    fn an_in_flight_input_is_held_back_from_the_next_read() {
        // A seed no other test uses: the hold is process-wide.
        let spent = outpoint(0xe7, 3);
        let raw = [
            bf_ada_utxo(&hex::encode([0xe7u8; 32]), 3, 90_000_000),
            bf_ada_utxo(&hex::encode([0xe8u8; 32]), 0, 5_000_000),
        ];
        note_in_flight([spent]);
        let set = wallet_set(&raw, None).expect("no state dir to read");
        assert!(set[0].reserved, "the spent input is held back");
        assert!(!set[1].reserved, "and nothing else is");
        let fee = crate::cardano::tx_common::select_fee(&set, 1_000_000).expect("the other pays");
        assert_eq!(fee.tx_hash, hex::encode([0xe8u8; 32]));
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
