//! The TM batch grid and deterministic batch selection (spec §TM batches and the
//! protocol schedule; plan N19).
//!
//! ## Why a grid
//!
//! Batch membership has to be a pure function of chain state at a slot every SPO
//! agrees on, because the members decide the TM's outputs and therefore its
//! sighashes: two SPOs who freeze different sets sign different messages and the
//! FROST aggregate is invalid. Before this module the daemon read peg-outs with a
//! bare query at whatever wall-clock moment each node reached `BuildTm`, so a
//! request locked inside that skew landed in one node's TM and not another's.
//!
//! The grid is *slot-anchored*, not event-driven ("freeze when the previous TM
//! confirms"), and the spec is explicit about why: slot numbers are absolute and
//! rollback-immune, whereas a Confirm transaction's inclusion slot wavers during
//! Cardano rollbacks, and any wobble in the freeze anchor flips boundary items in
//! or out of the batch.
//!
//! ```text
//! B_i = epoch_start + i × tm_batch_interval     (i = 1, 2, …; B_i ≤ final_tm_cutoff)
//! C_i = B_i − stability_window                  (the per-batch membership cutoff)
//! ```
//!
//! ## What is NOT here
//!
//! The gate evaluated at each `B_i` — "is the TM-chain tip Binocular-confirmed and
//! is no TM in flight?" — is the caller's, because answering it costs chain reads.
//! This module is pure: given slots and requests it says which requests are in the
//! batch and in what order, and nothing else.

use std::cmp::Ordering;

/// The schedule geometry, in Cardano slots. Sourced from the Config datum's
/// `schedule` (`params[0]`) — see [`crate::cardano::config_params::ScheduleParams`] — so
/// every SPO computes the same grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridParams {
    /// Absolute slot of the epoch boundary `E` the grid is anchored at.
    pub epoch_start_slot: u64,
    /// `tm_batch_interval` — the grid pitch. Zero is rejected by [`GridParams::new`].
    pub tm_batch_interval: u64,
    /// `stability_window` (3k/f). The distance a request must be behind a batch
    /// opportunity to be eligible for it.
    pub stability_window: u64,
    /// `final_tm_cutoff` as an absolute slot: the last opportunity in this epoch.
    /// `None` = unbounded (tests and deployments that have not set it).
    pub final_tm_cutoff_slot: Option<u64>,
}

/// One batch opportunity on the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchSlot {
    /// `i` in `B_i` — 1-based, as in the spec.
    pub index: u64,
    /// `B_i`, the absolute slot at which the batch is frozen and built.
    pub slot: u64,
    /// `C_i = B_i − stability_window`. A request is in this batch only if it was
    /// created at or before this slot.
    pub cutoff_slot: u64,
}

impl GridParams {
    /// Reject a pitch of zero up front: every grid query divides by it, and a
    /// governance datum carrying 0 would otherwise mean "a batch every slot".
    pub fn new(
        epoch_start_slot: u64,
        tm_batch_interval: u64,
        stability_window: u64,
        final_tm_cutoff_slot: Option<u64>,
    ) -> Result<Self, String> {
        if tm_batch_interval == 0 {
            return Err("schedule.tm_batch_interval is 0 — no batch grid exists".into());
        }
        Ok(Self {
            epoch_start_slot,
            tm_batch_interval,
            stability_window,
            final_tm_cutoff_slot,
        })
    }

    /// `B_i` and its cutoff for a given index. Indices are 1-based: `B_1` is one
    /// full interval after the boundary, never the boundary itself.
    #[must_use]
    pub fn opportunity(&self, index: u64) -> BatchSlot {
        let slot = self
            .epoch_start_slot
            .saturating_add(index.saturating_mul(self.tm_batch_interval));
        BatchSlot {
            index,
            slot,
            // Saturating: `C_1` legitimately reaches back before the epoch
            // boundary (the spec says so — that is what makes the first batch pick
            // up the previous epoch's leftovers with no special case). On a chain
            // young enough that it would go negative, clamp at 0 = "no lower bound".
            cutoff_slot: slot.saturating_sub(self.stability_window),
        }
    }

    /// The opportunity in force at `now_slot`: the LATEST `B_i ≤ now_slot`.
    ///
    /// `None` before the first opportunity, or once the grid has passed
    /// `final_tm_cutoff` — in the latter case the epoch's TM work is over and the
    /// caller waits for the next boundary rather than building.
    #[must_use]
    pub fn current(&self, now_slot: u64) -> Option<BatchSlot> {
        let elapsed = now_slot.checked_sub(self.epoch_start_slot)?;
        let index = elapsed / self.tm_batch_interval;
        if index == 0 {
            return None; // before B_1
        }
        let b = self.opportunity(index);
        match self.final_tm_cutoff_slot {
            Some(cutoff) if b.slot > cutoff => None,
            _ => Some(b),
        }
    }

    /// The next opportunity strictly after `now_slot` — what a scheduler sleeps
    /// until. `None` once the remaining grid is past `final_tm_cutoff`.
    #[must_use]
    pub fn next(&self, now_slot: u64) -> Option<BatchSlot> {
        let index = match now_slot.checked_sub(self.epoch_start_slot) {
            // Before the boundary: the next opportunity is B_1.
            None => 1,
            Some(elapsed) => elapsed / self.tm_batch_interval + 1,
        };
        let b = self.opportunity(index);
        match self.final_tm_cutoff_slot {
            Some(cutoff) if b.slot > cutoff => None,
            _ => Some(b),
        }
    }
}

/// Where a node stands relative to the batch grid.
///
/// "No opportunity is open" and "this deployment has no grid" are different
/// answers and must not collapse into one: past `final_tm_cutoff` the epoch's TM
/// work is over and the opportunity must pass UNUSED (spec §TM batches), whereas a
/// deployment with no Config `schedule` has no grid to respect and falls back to
/// its local cadence. Conflating them would have the mover build a batch the spec
/// says should not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchWindow {
    /// An opportunity is open at this slot: freeze and build.
    ///
    /// `next` matters to a node that has ALREADY built for this one, which is not
    /// a rare state: [`GridParams::current`] reports the same opportunity for the
    /// whole `tm_batch_interval`, so from `B_1` onward a running node sees `Open`
    /// continuously and never returns to `Closed` until the grid ends. Without the
    /// following opportunity here such a node has nothing to sleep towards and can
    /// only poll blindly — and then each node notices `B_{i+1}` at its own offset
    /// past it, which is exactly the freeze-anchor wobble the grid exists to
    /// remove.
    Open {
        batch: BatchSlot,
        next: Option<BatchSlot>,
    },
    /// The grid exists but no opportunity is open — before `B_1`, or past
    /// `final_tm_cutoff`. Wait; `next` is the following opportunity, if any remain
    /// this epoch.
    Closed { next: Option<BatchSlot> },
    /// No grid to follow (no Config `schedule`, or no epoch anchor).
    NoGrid,
}

impl BatchWindow {
    /// The open opportunity, if any — for callers that only need the cutoff.
    #[must_use]
    pub fn open(&self) -> Option<BatchSlot> {
        match self {
            Self::Open { batch, .. } => Some(*batch),
            _ => None,
        }
    }

    /// The opportunity AFTER the one in force — what a node sleeps towards, in
    /// both waiting states. `None` means the epoch's grid is exhausted, whether or
    /// not one is open right now.
    #[must_use]
    pub fn next(&self) -> Option<BatchSlot> {
        match self {
            Self::Open { next, .. } | Self::Closed { next } => *next,
            Self::NoGrid => None,
        }
    }
}

/// The FIFO total order the spec fixes for batch members:
/// `(creation slot, creating txid, output index)`.
///
/// A total order matters twice over. It decides WHICH requests make the cut when a
/// batch is oversubscribed — so a partial order would let two SPOs take different
/// subsets of equally-ranked requests — and it must be computable from chain data
/// alone, with no reference to the order a query happened to return. The txid
/// breaks slot ties (several requests per block is normal) and the output index
/// breaks txid ties (one transaction can create several requests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FifoKey {
    pub created_slot: u64,
    pub tx_hash: [u8; 32],
    pub output_index: u32,
}

impl Ord for FifoKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.created_slot
            .cmp(&other.created_slot)
            .then_with(|| self.tx_hash.cmp(&other.tx_hash))
            .then_with(|| self.output_index.cmp(&other.output_index))
    }
}

impl PartialOrd for FifoKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Which treasury spend path a TM uses. It decides how big the witness is, hence
/// how many inputs and outputs fit under the Post-TM byte budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendVariant {
    /// The 51% FROST key path — one 64-byte Schnorr signature per input.
    KeyPath,
    /// The federation CSV script path — signature + leaf script + control block
    /// per input, so roughly half as many items fit.
    Federation,
}

impl SpendVariant {
    /// Bytes one swept peg-in adds to the raw TM: 41 non-witness (outpoint 36 +
    /// scriptSig length 1 + sequence 4) plus the witness.
    ///
    /// Key path: 66 = witness item count 1 + a 65-byte signature item.
    /// Federation: 173 = item count 1 + signature 65 + revealed leaf ≈41 +
    /// control block 66. The deposit tree has TWO leaves — the federation sweep
    /// and the depositor refund — so its control block carries one sibling hash
    /// (33 + 32), unlike the treasury's own single-leaf tree.
    #[must_use]
    pub const fn pegin_input_bytes(self) -> u64 {
        match self {
            Self::KeyPath => 107,
            Self::Federation => 214,
        }
    }

    /// Bytes the TM costs before any peg-in or peg-out: version/marker/flag/
    /// locktime 10, one byte for each of the two count varints, the treasury
    /// input, the treasury change output (43) and the BTMR1 `OP_RETURN` (80 —
    /// value 8 + length 1 + a 71-byte scriptPubKey).
    ///
    /// The federation figure uses 182 for the treasury input, not the 214 a
    /// peg-in costs: the treasury tree has a single leaf, so its control block
    /// carries no sibling.
    #[must_use]
    pub const fn base_bytes(self) -> u64 {
        match self {
            Self::KeyPath => 242,
            Self::Federation => 317,
        }
    }
}

/// Bytes one peg-out payment adds to the raw TM: an 8-byte value, a 1-byte
/// script length, and a scriptPubKey of at most 34 (P2TR and P2WSH; every other
/// standard form is smaller). An upper bound, never an underestimate — which is
/// the direction that keeps a movement inside the budget rather than one byte
/// over it.
pub const PEGOUT_OUTPUT_BYTES: u64 = 43;

/// Bytes one peg-out adds to the **Cardano** Post-TM on top of its Bitcoin
/// output: one 36-byte outpoint in the `UnconfirmedTm` datum's
/// `fulfilled_por_outpoints` list, CBOR-encoded as a 2-byte header plus 36 bytes.
///
/// This is the term the pre-rev-5.6 model missed entirely, and it is very nearly
/// as large as the Bitcoin output it accompanies — which is why a ceiling on the
/// raw Bitcoin transaction could never have bounded the real constraint.
pub const POR_HINT_BYTES: u64 = 38;

/// Extra bytes a CBOR/Bitcoin count varint costs above the one byte
/// [`SpendVariant::base_bytes`] already budgets for.
const fn extra_count_varint_bytes(n: u64) -> u64 {
    if n < 0xFD {
        0
    } else if n <= 0xFFFF {
        2
    } else {
        4
    }
}

/// Size in bytes of the raw signed Bitcoin TM carrying `p` peg-ins and `q`
/// peg-outs (spec §Treasury Movement (Bitcoin), *Size (est.)*).
#[must_use]
pub fn raw_tm_bytes(variant: SpendVariant, p: u64, q: u64) -> u64 {
    variant.base_bytes()
        + variant.pegin_input_bytes() * p
        + PEGOUT_OUTPUT_BYTES * q
        // +1 input for the treasury, +2 outputs for the change and the BTMR1.
        + extra_count_varint_bytes(p + 1)
        + extra_count_varint_bytes(q + 2)
}

/// Bytes a `n`-byte string occupies as Plutus `bounded_bytes` — the encoding the
/// raw TM travels in, inside the Post-TM datum's `signed_btc_tx` field.
///
/// The ledger encodes any Plutus byte string longer than 64 bytes as an
/// indefinite-length CBOR byte string of 64-byte chunks (pallas' `plutus_data.rs`
/// says outright that it "matches the haskell implementation"): a `begin` byte, a
/// 2-byte header per chunk, and a `break` byte. On a ~15 kB transaction that is
/// ≈3.2 % — real bytes that no ceiling on the raw transaction ever counted.
///
/// Rounds UP when the final chunk is under 24 bytes and would take a 1-byte
/// header. Over-estimating shrinks the batch; under-estimating posts a movement
/// the chain rejects.
#[must_use]
pub fn plutus_chunked(n: u64) -> u64 {
    if n <= 64 {
        n + if n < 24 { 1 } else { 2 }
    } else {
        n + 2 * n.div_ceil(64) + 2
    }
}

/// Per-batch capacity: ONE byte budget over the assembled Cardano Post-TM
/// transaction (spec §TM batches, *Ordering, capacity, and the split rule*,
/// rev 5.6).
///
/// It replaces two independent per-class counts, which could not express a
/// capacity limit at all: each was satisfiable while their sum was not, and
/// nothing in the rule ever measured the assembly. The pair heimdall shipped —
/// 100 peg-ins and 100 peg-outs, applied independently to the same movement — is
/// 15 242 raw bytes, past the ~15 kB ceiling it was documented as deriving from.
/// And that ceiling was itself the wrong quantity: the limit is `max_tx_size` on
/// the **Post-TM**, where the raw TM is one of three batch-scaling terms, the
/// other two being the `bounded_bytes` chunking above and [`POR_HINT_BYTES`].
///
/// Every field here is a consensus input. Two SPOs with different budgets freeze
/// different batches, and that does not produce a bad signature — it produces
/// **no** signature, because the FROST binding factors commit to the signing
/// package. So none of it may come from operator configuration; `max_tx_size` is
/// read from the chain and `envelope` is derived from the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmBudget {
    /// The host Cardano protocol parameter, read per epoch — never hardcoded,
    /// because Conway governance can change it.
    pub max_tx_size: u64,
    /// `E`: Post-TM bytes that do NOT scale with the batch — body, redeemer,
    /// collateral, witness, the datum's non-batch fields, and the TM validator
    /// script when it rides inline rather than as a reference script.
    pub envelope: u64,
    /// Which spend path the movement will use, which sets the per-peg-in weight.
    pub variant: SpendVariant,
}

impl TmBudget {
    /// Size of the assembled Post-TM for `p` peg-ins and `q` peg-outs.
    #[must_use]
    pub fn post_tm_bytes(&self, p: u64, q: u64) -> u64 {
        self.envelope + plutus_chunked(raw_tm_bytes(self.variant, p, q)) + POR_HINT_BYTES * q
    }

    /// Whether that movement fits.
    #[must_use]
    pub fn fits(&self, p: u64, q: u64) -> bool {
        self.post_tm_bytes(p, q) <= self.max_tx_size
    }

    /// The largest number of peg-outs that fits with no peg-ins — the first half
    /// of the fill rule, since peg-outs are taken first.
    #[must_use]
    pub fn max_pegouts(&self) -> usize {
        largest(|q| self.fits(0, q))
    }

    /// The largest number of peg-ins that fits alongside `q` peg-outs — the
    /// second half, spending whatever room the peg-outs left.
    #[must_use]
    pub fn max_pegins_with(&self, q: u64) -> usize {
        largest(|p| self.fits(p, q))
    }

    /// Reject a budget that cannot carry even an empty movement.
    ///
    /// An `Err` here is a deployment fault, not a busy batch: the treasury still
    /// has to move at the epoch handoff whether or not anything is pending, so a
    /// budget this small would silently produce nothing for ever. Loud beats a
    /// permanently empty batch.
    pub fn validate(&self) -> Result<(), String> {
        if self.fits(0, 0) {
            return Ok(());
        }
        Err(format!(
            "TM byte budget cannot carry even an empty movement: a bare treasury move needs {} \
             bytes of Post-TM but max_tx_size is {} (non-batch overhead {}). Either the TM \
             validator script is too large to ride inline — deploy it as a reference script — or \
             max_tx_size was read from the wrong chain.",
            self.post_tm_bytes(0, 0),
            self.max_tx_size,
            self.envelope,
        ))
    }
}

/// Largest `n` for which `fits(n)` holds, given that `fits` is monotone
/// decreasing. Binary search rather than a scan, so a large budget cannot turn
/// the freeze into a long loop.
fn largest(fits: impl Fn(u64) -> bool) -> usize {
    if !fits(0) {
        return 0;
    }
    let (mut lo, mut hi) = (0u64, 1u64);
    // Grow until it stops fitting; the ceiling is a backstop against a budget so
    // large the doubling would run away, not a capacity limit anyone reaches.
    while hi < (1 << 20) && fits(hi) {
        hi *= 2;
    }
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if fits(mid) { lo = mid } else { hi = mid }
    }
    usize::try_from(lo).unwrap_or(usize::MAX)
}

/// The outcome of freezing one class of request against a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frozen<T> {
    /// In the batch, in FIFO order — exactly the order the caller must preserve.
    pub selected: Vec<T>,
    /// Held back because they were created after the cutoff. They are candidates
    /// for a later batch; nothing about them is wrong.
    pub too_new: Vec<T>,
    /// Held back because the batch is full. Also candidates for a later batch:
    /// since rev 5.1 retired the peg-out treasury-outpoint pin, overflow peg-outs
    /// roll over exactly like peg-ins, so missing a batch costs only latency. What
    /// eventually ends a peg-out's life is the fulfillment freshness filter, not
    /// overflow.
    pub over_cap: Vec<T>,
}

impl<T> Frozen<T> {
    /// Everything not taken by this batch, for the caller's log line.
    #[must_use]
    pub fn deferred(&self) -> usize {
        self.too_new.len() + self.over_cap.len()
    }
}

/// Freeze one class of request against a batch: drop everything created after the
/// cutoff, order the rest FIFO, take the first `cap`.
///
/// Determinism is the whole point, so nothing here may consult wall-clock time,
/// node configuration, or the order `items` arrived in — only `key`, which reads
/// chain facts. Given the same chain state and the same `BatchSlot`, every SPO
/// gets a byte-identical `selected`.
pub fn freeze<T>(
    items: Vec<T>,
    batch: BatchSlot,
    cap: usize,
    key: impl Fn(&T) -> FifoKey,
) -> Frozen<T> {
    let (mut eligible, too_new): (Vec<T>, Vec<T>) = items
        .into_iter()
        .partition(|it| key(it).created_slot <= batch.cutoff_slot);
    eligible.sort_by_key(&key);
    let over_cap = if eligible.len() > cap {
        eligible.split_off(cap)
    } else {
        Vec::new()
    };
    Frozen {
        selected: eligible,
        too_new,
        over_cap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const E: u64 = 1_000_000; // epoch boundary slot
    const INTERVAL: u64 = 21_600; // 6 h
    const STABILITY: u64 = 129_600; // 36 h = 3k/f

    fn grid() -> GridParams {
        GridParams::new(E, INTERVAL, STABILITY, None).unwrap()
    }

    #[test]
    fn a_zero_interval_is_rejected() {
        assert!(GridParams::new(E, 0, STABILITY, None).is_err());
    }

    /// Indices are 1-based: the boundary itself is not an opportunity.
    #[test]
    fn opportunities_start_one_interval_after_the_boundary() {
        assert_eq!(grid().opportunity(1).slot, E + INTERVAL);
        assert_eq!(grid().opportunity(4).slot, E + 4 * INTERVAL);
        assert_eq!(grid().current(E), None, "the boundary is before B_1");
        assert_eq!(grid().current(E + INTERVAL - 1), None);
    }

    /// The spec's note: C_1 reaches back into the PREVIOUS epoch, which is what
    /// makes the first batch pick up the last epoch's leftovers with no special
    /// case. With a 36 h window and a 6 h pitch it is 30 h before the boundary.
    #[test]
    fn the_first_cutoff_reaches_into_the_previous_epoch() {
        let b1 = grid().opportunity(1);
        assert_eq!(b1.cutoff_slot, E + INTERVAL - STABILITY);
        assert!(b1.cutoff_slot < E);
    }

    /// The property the whole item exists for: the batch in force is a function of
    /// the slot, so two nodes anywhere inside the same interval agree — which a
    /// wall-clock tick could never guarantee.
    #[test]
    fn every_slot_in_an_interval_maps_to_the_same_batch() {
        let g = grid();
        let b = g.current(E + INTERVAL).unwrap();
        assert_eq!(b.index, 1);
        for offset in [0, 1, 7_777, INTERVAL - 1] {
            assert_eq!(g.current(E + INTERVAL + offset), Some(b));
        }
        // …and the next slot is a different batch.
        assert_eq!(g.current(E + 2 * INTERVAL).unwrap().index, 2);
    }

    #[test]
    fn next_is_strictly_after_now() {
        let g = grid();
        assert_eq!(g.next(E).unwrap().slot, E + INTERVAL);
        assert_eq!(g.next(E + INTERVAL).unwrap().slot, E + 2 * INTERVAL);
        // Before the boundary (a node that started early) the next stop is B_1.
        assert_eq!(g.next(E - 5_000).unwrap().slot, E + INTERVAL);
    }

    /// Past `final_tm_cutoff` the epoch's TM work is over: no opportunity, so the
    /// caller waits for the next boundary instead of building a doomed batch.
    #[test]
    fn the_grid_stops_at_the_final_cutoff() {
        let g = GridParams::new(E, INTERVAL, STABILITY, Some(E + 3 * INTERVAL)).unwrap();
        assert_eq!(g.current(E + 3 * INTERVAL).unwrap().index, 3);
        assert_eq!(g.current(E + 4 * INTERVAL), None);
        assert_eq!(g.next(E + 3 * INTERVAL), None);
    }

    /// "No opportunity open" must never read as "no grid": past `final_tm_cutoff`
    /// the epoch's TM work is over and the opportunity passes UNUSED, whereas a
    /// deployment without a schedule has no grid to respect and falls back to its
    /// local cadence. Collapsing the two had the mover build a movement the spec
    /// says should not exist.
    #[test]
    fn a_closed_window_carries_the_next_opportunity() {
        let g = GridParams::new(E, INTERVAL, STABILITY, Some(E + 2 * INTERVAL)).unwrap();
        // Before B_1 the window is closed, but the grid still says what comes next.
        assert_eq!(g.current(E + 1), None);
        assert_eq!(g.next(E + 1).unwrap().index, 1);
        // Past the final cutoff nothing remains this epoch.
        assert_eq!(g.current(E + 3 * INTERVAL), None);
        assert_eq!(g.next(E + 3 * INTERVAL), None);
    }

    #[test]
    fn batch_window_exposes_only_the_open_opportunity() {
        let b = grid().opportunity(2);
        assert_eq!(
            BatchWindow::Open {
                batch: b,
                next: None
            }
            .open(),
            Some(b)
        );
        assert_eq!(BatchWindow::Closed { next: Some(b) }.open(), None);
        assert_eq!(BatchWindow::NoGrid.open(), None);
    }

    /// Both waiting states answer "what do I sleep towards" the same way, because
    /// a node that has already built for the open opportunity is waiting exactly
    /// as much as one before `B_1`. `None` from either is the end of the epoch's
    /// grid.
    #[test]
    fn both_waiting_states_name_the_following_opportunity() {
        let g = grid();
        let (b2, b3) = (g.opportunity(2), g.opportunity(3));
        assert_eq!(
            BatchWindow::Open {
                batch: b2,
                next: Some(b3)
            }
            .next(),
            Some(b3)
        );
        assert_eq!(BatchWindow::Closed { next: Some(b3) }.next(), Some(b3));
        assert_eq!(
            BatchWindow::Open {
                batch: b2,
                next: None
            }
            .next(),
            None,
            "an open-but-last opportunity ends the epoch once it is used"
        );
        assert_eq!(BatchWindow::NoGrid.next(), None);
    }

    // --- selection ---

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Req {
        slot: u64,
        tx: u8,
        ix: u32,
    }

    fn key(r: &Req) -> FifoKey {
        FifoKey {
            created_slot: r.slot,
            tx_hash: [r.tx; 32],
            output_index: r.ix,
        }
    }

    fn req(slot: u64, tx: u8, ix: u32) -> Req {
        Req { slot, tx, ix }
    }

    #[test]
    fn requests_after_the_cutoff_are_held_for_a_later_batch() {
        let b = grid().opportunity(1);
        let frozen = freeze(
            vec![
                req(b.cutoff_slot - 1, 1, 0),
                req(b.cutoff_slot, 2, 0), // exactly at the cutoff: eligible
                req(b.cutoff_slot + 1, 3, 0), // one slot too new
            ],
            b,
            100,
            key,
        );
        assert_eq!(frozen.selected.len(), 2);
        assert_eq!(frozen.too_new, vec![req(b.cutoff_slot + 1, 3, 0)]);
        assert!(frozen.over_cap.is_empty());
    }

    /// FIFO is (slot, txid, output index) — and the input order must not survive
    /// into the output, or the TM bytes would depend on how the query answered.
    #[test]
    fn selection_is_fifo_and_ignores_the_input_order() {
        let b = grid().opportunity(1);
        let c = b.cutoff_slot;
        let shuffled = vec![
            req(c - 1, 9, 1),
            req(c - 5, 2, 0),
            req(c - 1, 9, 0),
            req(c - 1, 3, 7),
            req(c - 5, 1, 0),
        ];
        let mut reversed = shuffled.clone();
        reversed.reverse();

        let a = freeze(shuffled, b, 100, key).selected;
        let d = freeze(reversed, b, 100, key).selected;
        assert_eq!(a, d, "two orderings of the same set freeze identically");
        assert_eq!(
            a,
            vec![
                req(c - 5, 1, 0), // oldest slot, lower txid
                req(c - 5, 2, 0),
                req(c - 1, 3, 7), // newer slot; txid orders within it
                req(c - 1, 9, 0), // same txid → output index orders
                req(c - 1, 9, 1),
            ]
        );
    }

    /// Oversubscription takes the FIFO prefix, and the overflow rolls over — for
    /// peg-outs too, since rev 5.1 retired the outpoint pin that used to make an
    /// unpicked peg-out permanently unpayable.
    #[test]
    fn overflow_rolls_over_in_fifo_order() {
        let b = grid().opportunity(1);
        let c = b.cutoff_slot;
        let frozen = freeze(
            vec![req(c - 3, 1, 0), req(c - 2, 2, 0), req(c - 1, 3, 0)],
            b,
            2,
            key,
        );
        assert_eq!(frozen.selected, vec![req(c - 3, 1, 0), req(c - 2, 2, 0)]);
        assert_eq!(frozen.over_cap, vec![req(c - 1, 3, 0)], "the newest waits");
        assert_eq!(frozen.deferred(), 1);
    }

    // ── The byte budget (WI-107) ──────────────────────────────────────────

    /// A budget with no TM validator script inline: `max_tx_size` as every
    /// Cardano network has carried it since Alonzo, and the non-batch overhead
    /// alone.
    fn budget() -> TmBudget {
        TmBudget {
            max_tx_size: 16_384,
            envelope: 1_024,
            variant: SpendVariant::KeyPath,
        }
    }

    /// The arithmetic that killed the two-count rule, kept as a test so it cannot
    /// quietly come back: the published key-path pair does not fit the raw ceiling
    /// it was documented as deriving from, while the federation pair does.
    #[test]
    fn the_withdrawn_key_path_pair_overshot_its_own_raw_ceiling() {
        assert_eq!(raw_tm_bytes(SpendVariant::KeyPath, 100, 100), 15_242);
        assert_eq!(raw_tm_bytes(SpendVariant::KeyPath, 98, 98), 14_942);
        assert_eq!(raw_tm_bytes(SpendVariant::Federation, 57, 57), 14_966);
        // 98 + 98 is the largest symmetric key-path pair under ~15 kB; 99 + 99 is not.
        assert!(raw_tm_bytes(SpendVariant::KeyPath, 99, 99) > 15_000);
    }

    /// The ledger's 64-byte chunking of a Plutus byte string — ≈3.2 % that the
    /// pre-rev-5.6 model never counted.
    #[test]
    fn plutus_chunking_is_charged() {
        assert_eq!(plutus_chunked(15_242), 15_722);
        assert_eq!(plutus_chunked(64), 66, "a 64-byte string is not chunked");
        assert_eq!(plutus_chunked(0), 1);
        // Never an underestimate: the encoding can only be smaller than the model.
        for n in [1u64, 23, 24, 65, 128, 1_000, 9_999] {
            assert!(plutus_chunked(n) > n, "n = {n}");
        }
    }

    /// The other missed term: a peg-out costs Cardano bytes as well as Bitcoin
    /// bytes, and the two are the same order of magnitude.
    #[test]
    fn a_pegout_costs_cardano_bytes_too() {
        let b = budget();
        let step = b.post_tm_bytes(0, 11) - b.post_tm_bytes(0, 10);
        assert!(
            step >= PEGOUT_OUTPUT_BYTES + POR_HINT_BYTES,
            "a peg-out costs its Bitcoin output AND its datum hint, got {step}"
        );
    }

    /// Why a fixed pair of counts can never be right: the two classes have
    /// different weights, so any pair is either wasteful or over the limit.
    ///
    /// Note WHERE the weights are compared. On the raw Bitcoin transaction a
    /// peg-in costs ≈2.5× a peg-out (107 vs 43) — but the budget measures the
    /// Post-TM, and there [`POR_HINT_BYTES`] nearly doubles the peg-out while the
    /// peg-in only picks up chunking, leaving a ratio closer to 4:3. The
    /// conclusion is unchanged and the intuition is not: peg-outs are far more
    /// expensive than the Bitcoin-side numbers suggest.
    #[test]
    fn the_two_classes_have_different_weights() {
        let b = budget();
        let pegin = b.post_tm_bytes(11, 0) - b.post_tm_bytes(10, 0);
        let pegout = b.post_tm_bytes(0, 11) - b.post_tm_bytes(0, 10);
        assert!(pegin > pegout, "{pegin} vs {pegout}");
        // The Bitcoin-side ratio, for contrast with the Post-TM one below.
        assert_eq!(
            SpendVariant::KeyPath.pegin_input_bytes(),
            PEGOUT_OUTPUT_BYTES * 2 + 21
        );
        assert!(
            pegin * 2 < pegout * 3,
            "on the Post-TM the gap is far narrower than 2.5x: {pegin} vs {pegout}"
        );
    }

    /// THE regression test. Under the old rule each class took its own full cap
    /// and the sum was never checked; here the two maxima are each valid alone
    /// and hopeless together, which is exactly the defect.
    #[test]
    fn the_two_maxima_do_not_fit_together() {
        let b = budget();
        let (max_q, max_p) = (b.max_pegouts() as u64, b.max_pegins_with(0) as u64);
        assert!(b.fits(0, max_q), "each is fine alone");
        assert!(b.fits(max_p, 0));
        assert!(
            !b.fits(max_p, max_q),
            "{max_p} peg-ins and {max_q} peg-outs must NOT fit together"
        );
        // …and the joint rule does hold: peg-outs first, peg-ins in what is left.
        assert!(b.fits(b.max_pegins_with(max_q) as u64, max_q));
    }

    /// Each maximum is the largest that fits — not one less, and not one more.
    #[test]
    fn the_maxima_are_tight() {
        let b = budget();
        let q = b.max_pegouts() as u64;
        assert!(b.fits(0, q) && !b.fits(0, q + 1));
        let p = b.max_pegins_with(0) as u64;
        assert!(b.fits(p, 0) && !b.fits(p + 1, 0));
        // A named case, so a change in the weights or the encoding is visible in
        // the diff rather than only in a ratio.
        assert_eq!((q, p), (183, 136));
    }

    /// A budget too small for a bare treasury move is a deployment fault, and it
    /// must say so rather than produce an empty movement for ever.
    #[test]
    fn a_budget_below_the_empty_movement_is_rejected() {
        assert!(budget().validate().is_ok());
        let tiny = TmBudget {
            max_tx_size: 1_000,
            ..budget()
        };
        let err = tiny.validate().expect_err("cannot carry an empty movement");
        assert!(err.contains("reference script"), "{err}");
    }

    /// The TM validator riding inline rather than as a reference script is worth
    /// roughly ten pairs of capacity — the claim the spec makes, checked.
    #[test]
    fn an_inline_validator_script_costs_real_capacity() {
        let with_script = TmBudget {
            envelope: 1_024 + 2_500,
            ..budget()
        };
        let (a, b) = (
            symmetric_max(&budget()) as i64,
            symmetric_max(&with_script) as i64,
        );
        assert!((8..=20).contains(&(a - b)), "{a} vs {b}");
    }

    fn symmetric_max(b: &TmBudget) -> u64 {
        (0..500).take_while(|n| b.fits(*n, *n)).last().unwrap_or(0)
    }
}
