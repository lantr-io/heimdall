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
/// `schedule` (#16) — see [`crate::cardano::config_params::ScheduleParams`] — so
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
    Open(BatchSlot),
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
            Self::Open(b) => Some(*b),
            _ => None,
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
/// how many inputs and outputs fit under the ~15 KB raw-transaction ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendVariant {
    /// The 51% FROST key path — one 64-byte Schnorr signature per input.
    KeyPath,
    /// The federation CSV script path — signature + leaf script + control block
    /// per input, so roughly half as many items fit.
    Federation,
}

/// Per-batch capacity, derived from the ~15 KB raw-TM ceiling (spec §TM batches).
///
/// NOT a Config tunable and NOT node-local: these numbers decide batch membership,
/// so they are consensus values like the grid itself. They are a function of the
/// spend variant alone, which every SPO derives identically from the treasury it
/// is spending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub max_pegins: usize,
    pub max_pegouts: usize,
}

impl Caps {
    #[must_use]
    pub fn for_variant(variant: SpendVariant) -> Self {
        match variant {
            SpendVariant::KeyPath => Self {
                max_pegins: 100,
                max_pegouts: 100,
            },
            SpendVariant::Federation => Self {
                max_pegins: 57,
                max_pegouts: 57,
            },
        }
    }
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
        assert_eq!(BatchWindow::Open(b).open(), Some(b));
        assert_eq!(BatchWindow::Closed { next: Some(b) }.open(), None);
        assert_eq!(BatchWindow::NoGrid.open(), None);
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

    #[test]
    fn caps_follow_the_spend_variant() {
        assert_eq!(Caps::for_variant(SpendVariant::KeyPath).max_pegouts, 100);
        assert_eq!(Caps::for_variant(SpendVariant::Federation).max_pegouts, 57);
    }
}
