//! A shorter, chain-derived ceremony cycle for a TEST bridge (WI-VMP6J).
//!
//! ## The problem
//!
//! Everything the bridge's cycle hangs off is an offset from the Cardano epoch
//! boundary: the DKG runs once per epoch, the batch grid is anchored at
//! `epoch_start`, and `final_tm_cutoff` closes the epoch's TM work four days
//! into it. A Cardano epoch is five days on preprod exactly as on mainnet, so a
//! tester who wants to watch a key rotation, a handoff and a movement complete
//! waits five days per attempt. That is not a schedule anyone iterates against.
//!
//! ## What a virtual epoch is
//!
//! A cycle of `slots` Cardano slots, numbered from slot 0 of the chain:
//!
//! ```text
//! virtual_epoch            = tip_slot / slots
//! virtual_epoch_start_slot = virtual_epoch × slots
//! ```
//!
//! Three properties earn that definition its place as a CONSENSUS value:
//!
//! * **Chain-derived, never a local clock.** Two nodes reading the same tip get
//!   the same answer, which is the whole requirement — the same one
//!   [`crate::epoch::batch`] states for the real grid.
//! * **Monotone.** `await_epoch_boundary` only advances on `epoch > seen`, and
//!   the served-payload GC drops namespaces below the current epoch. An anchor
//!   that reset at each real boundary (the obvious first idea) would number
//!   cycles 0,1,2,0,1,… and wedge both.
//! * **Needs no extra agreement.** Anchoring at slot 0 means there is no anchor
//!   to publish, mis-copy or drift on: the tip slot is the only input.
//!
//! ## What it does NOT touch
//!
//! The REAL Cardano epoch stays the index for every `/epochs/{n}` read — the
//! stake snapshot, the epoch-boundary time, `max_tx_size` (WI-107). Only the
//! bridge's own cycle is virtualised, and the split lives in
//! [`crate::cardano::blockfrost_chain`]: the adapter reads the chain under the
//! real epoch and labels the ceremony with the virtual one.
//!
//! ## Which schedule values rescale, and which must not
//!
//! The Config `schedule` is written for a five-day epoch: `final_tm_cutoff` is
//! 345600 slots (four days). Dropped unchanged into a 24-hour cycle that sits
//! three days past the end of its own epoch, so the "last opportunity" the spec
//! relies on never arrives and the grid silently never closes. So the values
//! measured as an OFFSET FROM THE CYCLE START rescale by
//! `slots / CARDANO_EPOCH_SLOTS`: `dkg_r1_deadline`, `dkg_r2_deadline`,
//! `update_y_deadline`, `final_tm_cutoff`. Being derived from two numbers every
//! node already agrees on, the rescale cannot itself diverge — which is why it
//! beats asking operators to hand-tune Config values consistently across a
//! roster.
//!
//! **Everything else stays exactly as published, and the reason is not
//! symmetry.** Each of the others is measured against something a shorter bridge
//! cycle does not shorten, and scaling it silently trades correctness for speed:
//!
//! * `stability_window` is `3k/f` of the HOST chain. Cardano does not settle
//!   faster because the bridge's cycle is shorter, so scaling it would understate
//!   how long a deposit must age before it is safe to spend.
//! * `tm_batch_interval` is coupled to `stability_window` by `C_i = B_i − W`, so
//!   it inherits that floor. **This one was scaled in the first version of this
//!   module and it stranded deposits.** The invariant is `P > W`: the leftovers
//!   of a cycle — requests whose `s + W` fell past `final_tm_cutoff` — are picked
//!   up by the NEXT cycle's `B_1`, whose cutoff is `anchor + P − W`. With
//!   `P > W` that cutoff is after the anchor, so every leftover is caught by
//!   `B_1`, which runs while the treasury head is still the outgoing key and is
//!   therefore sweepable. Scale `P` below `W` and the cutoff moves BEFORE the
//!   anchor: the leftovers miss `B_1`, `B_1` moves the head to the incoming key,
//!   and at `B_2` those deposits are `Retired` and unsweepable for ever. Real
//!   epochs never meet this because `P = 21600 > W`.
//! * `tm_recovery_window` is how long a submitted TM may go unconfirmed before
//!   the bridge builds a replacement against the same head. It is a BITCOIN
//!   settlement timeout, compared against wall-clock seconds, and Bitcoin does
//!   not confirm faster either. Scaled down it would have a node declare its own
//!   in-flight movement dead at nearly every opportunity and post competitors.
//! * `sign_r1_window`, `sign_r2_window` and `leader_slot_t` are network
//!   round-trip budgets. Peers do not answer faster on a test bridge.
//!
//! The rule, then: **an offset from the cycle start rescales; a duration
//! measured against the host chain or the network does not.**

use crate::cardano::config_params::ScheduleParams;

/// Slots in a Cardano epoch on the networks heimdall runs on — 432000, i.e.
/// five days at one slot per second, the same on preprod and on mainnet.
///
/// A constant rather than a chain read because it is only ever a RATIO
/// denominator here, and a constant is a value every node reproduces without a
/// query that can fail or answer differently. A network with a different epoch
/// length (preview's one-day epochs) would rescale by a factor computed against
/// five days — identically on every node, so still agreed, just more compressed
/// than the operator asked for. What actually protects the resulting schedule is
/// [`EpochScheme::schedule`]'s refusals, not this number's exactness.
pub const CARDANO_EPOCH_SLOTS: u64 = 432_000;

/// Shortest virtual epoch accepted: twelve hours.
///
/// Not a taste judgement — it is the floor at which the published preprod
/// schedule still works, and both binding constraints are checked exactly in
/// [`EpochScheme::schedule`] rather than assumed away here:
///
/// * `tm_batch_interval` does not rescale (see the module doc), so a cycle
///   shorter than it contains no batch opportunity at all. The published value
///   is 21600 slots.
/// * `update_y_deadline` DOES rescale, and it has to stay clear of the ceremony
///   window grid — a node cannot enter a ceremony before `dkg_window` has
///   elapsed from the cycle start, so a rotation deadline inside that is one no
///   node can ever meet.
///
/// This constant is the cheap early guard that catches a typo at config load;
/// the exact checks catch a bridge whose published schedule differs from
/// preprod's.
pub const MIN_VIRTUAL_EPOCH_SLOTS: u64 = 43_200;

/// Which cycle the bridge runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EpochScheme {
    /// Production: the Cardano epoch, whose boundary and length come from the
    /// chain.
    #[default]
    Cardano,
    /// TEST RUN: a cycle of `slots` slots, anchored at slot 0.
    Virtual { slots: u64 },
}

impl EpochScheme {
    /// Resolve an operator's `cardano.demo_virtual_epoch_slots`.
    ///
    /// Rejects the two values that are typos rather than choices: zero (every
    /// slot is a boundary, and the division panics) and anything at or above a
    /// real epoch, which is not a test speed-up at all — the operator has
    /// almost certainly typed a slot count where they meant something else.
    pub fn from_slots(slots: Option<u64>) -> Result<Self, String> {
        match slots {
            None => Ok(Self::Cardano),
            Some(s) if s < MIN_VIRTUAL_EPOCH_SLOTS => Err(format!(
                "{s} slots is shorter than the {MIN_VIRTUAL_EPOCH_SLOTS}-slot minimum \
                 (twelve hours) — below it a cycle holds no batch opportunity, because \
                 tm_batch_interval does not rescale, and the rescaled Update-Y deadline \
                 falls inside the ceremony window a node cannot start before"
            )),
            Some(s) if s >= CARDANO_EPOCH_SLOTS => Err(format!(
                "{s} slots is not shorter than a Cardano epoch ({CARDANO_EPOCH_SLOTS} \
                 slots), so it speeds nothing up. Leave the key unset to run on real \
                 epochs"
            )),
            Some(s) => Ok(Self::Virtual { slots: s }),
        }
    }

    /// The cycle length, or `None` on real epochs. This is the value published
    /// in the pre-ceremony handshake, so a peer on a different cycle is
    /// excluded before anything is generated.
    #[must_use]
    pub fn virtual_slots(self) -> Option<u64> {
        match self {
            Self::Cardano => None,
            Self::Virtual { slots } => Some(slots),
        }
    }

    /// The cycle length, guarded against the zero a caller could construct the
    /// variant with directly. [`Self::from_slots`] refuses it, but the variant is
    /// public and every use below divides by this.
    fn divisor(self) -> Option<u64> {
        self.virtual_slots().map(|slots| slots.max(1))
    }

    /// The ceremony epoch at `tip_slot` — `None` on real epochs, where the
    /// chain answers instead.
    #[must_use]
    pub fn epoch_at(self, tip_slot: u64) -> Option<u64> {
        self.divisor().map(|slots| tip_slot / slots)
    }

    /// The slot the current cycle began at, or `None` on real epochs.
    #[must_use]
    pub fn start_slot(self, tip_slot: u64) -> Option<u64> {
        self.divisor()
            .map(|slots| (tip_slot / slots).saturating_mul(slots))
    }

    /// The grid anchor: this cycle's start on a virtual scheme, otherwise the
    /// real epoch boundary the caller has already read.
    #[must_use]
    pub fn anchor_slot(self, chain_epoch_start_slot: u64, tip_slot: u64) -> u64 {
        self.start_slot(tip_slot).unwrap_or(chain_epoch_start_slot)
    }

    /// The schedule in force, rescaled to this cycle.
    ///
    /// Only the four cycle-relative offsets move; see the module doc for why the
    /// rest must not. `ceremony_floor_slots` is how far into a cycle a node can
    /// first ENTER a ceremony — `protocol.dkg_window_secs` plus the join wait —
    /// which the caller holds and this needs in order to check the Update-Y
    /// deadline against it.
    ///
    /// The refusals are the point of returning a `Result`. A schedule whose
    /// opportunities never arrive produces a bridge that looks alive and moves
    /// nothing, which is worse than one that says why it will not start.
    pub fn schedule(
        self,
        raw: &ScheduleParams,
        ceremony_floor_slots: u64,
    ) -> Result<ScheduleParams, String> {
        let Some(slots) = self.divisor() else {
            return Ok(raw.clone());
        };
        let scale = |v: i64, name: &str| -> Result<i64, String> {
            let scaled = i128::from(v) * i128::from(slots) / i128::from(CARDANO_EPOCH_SLOTS);
            let scaled = i64::try_from(scaled).unwrap_or(i64::MAX);
            if v > 0 && scaled == 0 {
                return Err(format!(
                    "schedule.{name} is {v} slots, which a {slots}-slot virtual epoch \
                     rescales to 0 — the virtual epoch is too short for this bridge's \
                     schedule"
                ));
            }
            Ok(scaled)
        };
        let out = ScheduleParams {
            dkg_r1_deadline: scale(raw.dkg_r1_deadline, "dkg_r1_deadline")?,
            dkg_r2_deadline: scale(raw.dkg_r2_deadline, "dkg_r2_deadline")?,
            update_y_deadline: scale(raw.update_y_deadline, "update_y_deadline")?,
            final_tm_cutoff: scale(raw.final_tm_cutoff, "final_tm_cutoff")?,
            // NOT rescaled — each is measured against the host chain or the
            // network, neither of which a shorter bridge cycle speeds up. The
            // module doc gives the failure each one would cause.
            tm_batch_interval: raw.tm_batch_interval,
            stability_window: raw.stability_window,
            tm_recovery_window: raw.tm_recovery_window,
            sign_r1_window: raw.sign_r1_window,
            sign_r2_window: raw.sign_r2_window,
            leader_slot_t: raw.leader_slot_t,
        };
        let nonneg = |v: i64| u64::try_from(v).unwrap_or(0);

        // THE STRANDING INVARIANT, `P > W`. Below it the next cycle's `B_1`
        // cutoff falls before its own anchor, so a cycle's leftover deposits miss
        // the one opportunity that still runs against the outgoing key and are
        // unsweepable for ever. `tm_batch_interval` no longer rescales, so this
        // can only trip on a bridge whose published `stability_window` exceeds
        // its own batch pitch — which is a governance mistake worth naming rather
        // than silently stranding deposits over.
        if nonneg(out.stability_window) >= nonneg(out.tm_batch_interval) {
            return Err(format!(
                "schedule.stability_window ({}) is not shorter than schedule.tm_batch_interval \
                 ({}) — a cycle's leftover deposits would miss the next cycle's first batch, \
                 which is the last one that runs before the treasury head rotates, and would \
                 be unsweepable for ever",
                out.stability_window, out.tm_batch_interval
            ));
        }
        // At least one opportunity inside the cycle. `B_1` is one full interval
        // in, and the interval does not rescale, so a short cycle can contain no
        // grid line at all.
        if nonneg(out.tm_batch_interval) >= slots {
            return Err(format!(
                "schedule.tm_batch_interval is {} slots, so B_1 falls outside a {slots}-slot \
                 virtual epoch — the cycle would hold no batch opportunity. The interval does \
                 not rescale (it is bounded below by stability_window), so the cycle must be \
                 longer than it",
                out.tm_batch_interval
            ));
        }
        // `B_i ≤ final_tm_cutoff` bounds the grid, so a cutoff at or past the end
        // of the cycle means the epoch's TM work never closes and the "last
        // opportunity" the spec relies on does not exist.
        if nonneg(out.final_tm_cutoff) >= slots {
            return Err(format!(
                "schedule.final_tm_cutoff rescales to {} slots, which is not inside a \
                 {slots}-slot virtual epoch — the epoch's last batch opportunity would \
                 never arrive",
                out.final_tm_cutoff
            ));
        }
        // THE CEREMONY FLOOR. A node joins at the next `cycle_start + k·dkg_window`
        // grid line, so it cannot enter before one window has passed; a rotation
        // deadline inside that is one no honest node can meet, and the failure is
        // silent — the signing window opens already closed, which the short-window
        // diagnostic does not report because it is guarded on a non-zero window.
        if nonneg(out.update_y_deadline) <= ceremony_floor_slots {
            return Err(format!(
                "schedule.update_y_deadline rescales to {} slots, which is inside the \
                 {ceremony_floor_slots}-slot ceremony window a node cannot enter before \
                 (protocol.dkg_window_secs + dkg_join_wait_secs) — the rotation would close \
                 before any node could start one. Lengthen the virtual epoch, or shorten \
                 protocol.dkg_window_secs on every node",
                out.update_y_deadline
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published preprod schedule, as the fixtures carry it.
    pub(super) fn schedule() -> ScheduleParams {
        ScheduleParams {
            dkg_r1_deadline: 3_600,
            dkg_r2_deadline: 7_200,
            update_y_deadline: 10_800,
            tm_batch_interval: 21_600,
            sign_r1_window: 1_800,
            sign_r2_window: 1_800,
            leader_slot_t: 600,
            tm_recovery_window: 129_600,
            final_tm_cutoff: 345_600,
            stability_window: 7_200,
        }
    }

    /// `protocol.dkg_window_secs + dkg_join_wait_secs` at their defaults.
    const FLOOR: u64 = 900;

    #[test]
    fn a_real_epoch_scheme_changes_nothing() {
        let s = EpochScheme::Cardano;
        assert_eq!(s.virtual_slots(), None);
        assert_eq!(s.epoch_at(96_000_000), None);
        assert_eq!(s.anchor_slot(95_000_000, 96_000_000), 95_000_000);
        assert_eq!(s.schedule(&schedule(), FLOOR).unwrap(), schedule());
    }

    /// The cycle is a pure function of the tip slot, so two nodes reading the
    /// same tip agree with no anchor to exchange.
    #[test]
    fn the_cycle_is_derived_from_the_tip_alone() {
        let day = EpochScheme::Virtual { slots: 86_400 };
        assert_eq!(day.epoch_at(86_400 * 7), Some(7));
        assert_eq!(day.epoch_at(86_400 * 7 + 5), Some(7));
        assert_eq!(day.start_slot(86_400 * 7 + 5), Some(86_400 * 7));
        // …and it is the anchor the grid uses, in place of the real boundary.
        assert_eq!(day.anchor_slot(95_000_000, 86_400 * 7 + 5), 86_400 * 7);
    }

    /// Monotone across a real epoch boundary: an anchor that reset at each one
    /// would renumber cycles and wedge both `await_epoch_boundary` and the
    /// served-payload GC.
    #[test]
    fn the_cycle_number_never_goes_backwards() {
        let day = EpochScheme::Virtual { slots: 86_400 };
        let mut last = 0;
        for tip in (95_000_000..95_900_000).step_by(50_000) {
            let e = day.epoch_at(tip).unwrap();
            assert!(e >= last, "tip {tip}: {e} < {last}");
            last = e;
        }
    }

    /// Exactly the four cycle-relative offsets rescale, and nothing else.
    #[test]
    fn only_the_cycle_relative_offsets_are_rescaled() {
        let day = EpochScheme::Virtual { slots: 86_400 };
        let s = day.schedule(&schedule(), FLOOR).unwrap();
        // Scaled: a fifth of an epoch gets a fifth of each offset.
        assert_eq!(s.dkg_r1_deadline, 720);
        assert_eq!(s.dkg_r2_deadline, 1_440);
        assert_eq!(s.update_y_deadline, 2_160);
        assert_eq!(s.final_tm_cutoff, 69_120);
        assert!(
            u64::try_from(s.final_tm_cutoff).unwrap() < 86_400,
            "the cutoff must be inside its own epoch"
        );
        // Untouched: each is measured against the host chain or the network.
        let raw = schedule();
        assert_eq!(s.tm_batch_interval, raw.tm_batch_interval);
        assert_eq!(s.stability_window, raw.stability_window);
        assert_eq!(s.tm_recovery_window, raw.tm_recovery_window);
        assert_eq!(s.sign_r1_window, raw.sign_r1_window);
        assert_eq!(s.sign_r2_window, raw.sign_r2_window);
        assert_eq!(s.leader_slot_t, raw.leader_slot_t);
    }

    /// THE STRANDING INVARIANT, and the reason `tm_batch_interval` stopped being
    /// rescaled. A cycle's leftovers are picked up by the next cycle's `B_1`,
    /// whose cutoff is `anchor + P − W`; that has to land at or after the anchor,
    /// or they miss the last opportunity that still runs against the outgoing
    /// treasury key and are unsweepable for ever.
    #[test]
    fn the_batch_pitch_stays_above_the_stability_window() {
        let day = EpochScheme::Virtual { slots: 86_400 };
        let s = day.schedule(&schedule(), FLOOR).unwrap();
        assert!(
            s.tm_batch_interval > s.stability_window,
            "P={} must exceed W={}, or a cycle's leftovers strand",
            s.tm_batch_interval,
            s.stability_window
        );
        // A bridge whose published window exceeds its own pitch is refused rather
        // than run — the deposits it would strand are not recoverable.
        let mut raw = schedule();
        raw.stability_window = raw.tm_batch_interval;
        let e = day.schedule(&raw, FLOOR).expect_err("must refuse");
        assert!(e.contains("stability_window"), "{e}");
        assert!(e.contains("unsweepable"), "{e}");
    }

    /// A published cutoff longer than an epoch still overruns after rescaling,
    /// and is refused rather than run.
    #[test]
    fn a_schedule_that_overruns_its_epoch_is_refused() {
        let mut raw = schedule();
        raw.final_tm_cutoff = CARDANO_EPOCH_SLOTS as i64 * 2;
        let e = EpochScheme::Virtual { slots: 86_400 }
            .schedule(&raw, FLOOR)
            .expect_err("must refuse");
        assert!(e.contains("final_tm_cutoff"), "{e}");
        assert!(e.contains("never arrive"), "{e}");
    }

    /// A cycle that cannot hold one batch opportunity builds nothing, so it is
    /// refused. `tm_batch_interval` does not rescale, so this is the constraint
    /// that actually sets the practical floor.
    #[test]
    fn a_cycle_shorter_than_the_batch_pitch_is_refused() {
        let mut raw = schedule();
        raw.tm_batch_interval = 60_000; // a bridge on a slower grid than preprod
        let e = EpochScheme::Virtual { slots: 43_200 }
            .schedule(&raw, FLOOR)
            .expect_err("must refuse");
        assert!(e.contains("tm_batch_interval"), "{e}");
        assert!(e.contains("no batch opportunity"), "{e}");
    }

    /// The rotation deadline must clear the window a node cannot enter a
    /// ceremony before, or no honest node can ever meet it — and the failure is
    /// silent, because the signing window simply opens already closed.
    #[test]
    fn an_update_y_deadline_inside_the_ceremony_window_is_refused() {
        // 43200 slots rescales update_y_deadline to 1080, which clears the
        // default 900-slot floor…
        assert!(
            EpochScheme::Virtual { slots: 43_200 }
                .schedule(&schedule(), FLOOR)
                .is_ok()
        );
        // …but not a roster that widened its ceremony window.
        let e = EpochScheme::Virtual { slots: 43_200 }
            .schedule(&schedule(), 1_200)
            .expect_err("must refuse");
        assert!(e.contains("update_y_deadline"), "{e}");
        assert!(e.contains("ceremony window"), "{e}");
    }

    /// Compression that zeroes a positive offset is refused: a deadline of 0 is
    /// one that has already passed.
    #[test]
    fn a_value_compressed_to_zero_is_refused() {
        let mut raw = schedule();
        raw.dkg_r1_deadline = 1;
        let e = EpochScheme::Virtual { slots: 43_200 }
            .schedule(&raw, FLOOR)
            .expect_err("must refuse");
        assert!(e.contains("dkg_r1_deadline"), "{e}");
        assert!(e.contains("rescales to 0"), "{e}");
    }

    /// Zero, and any value that is not actually shorter than a real epoch, are
    /// typos rather than choices.
    #[test]
    fn an_unusable_cycle_length_is_refused_at_config_load() {
        assert_eq!(EpochScheme::from_slots(None).unwrap(), EpochScheme::Cardano);
        assert!(EpochScheme::from_slots(Some(0)).is_err());
        assert!(EpochScheme::from_slots(Some(60)).is_err());
        assert!(EpochScheme::from_slots(Some(MIN_VIRTUAL_EPOCH_SLOTS - 1)).is_err());
        assert!(EpochScheme::from_slots(Some(CARDANO_EPOCH_SLOTS)).is_err());
        assert!(EpochScheme::from_slots(Some(CARDANO_EPOCH_SLOTS * 2)).is_err());
        assert_eq!(
            EpochScheme::from_slots(Some(86_400)).unwrap(),
            EpochScheme::Virtual { slots: 86_400 }
        );
    }

    /// The advertised minimum actually works against the published preprod
    /// schedule — otherwise it is a number that only looks like a guarantee.
    #[test]
    fn the_minimum_cycle_runs_the_published_schedule() {
        let s = EpochScheme::from_slots(Some(MIN_VIRTUAL_EPOCH_SLOTS)).unwrap();
        let out = s
            .schedule(&schedule(), FLOOR)
            .expect("the minimum must hold the schedule it is chosen for");
        assert!(u64::try_from(out.tm_batch_interval).unwrap() < MIN_VIRTUAL_EPOCH_SLOTS);
        assert!(u64::try_from(out.final_tm_cutoff).unwrap() < MIN_VIRTUAL_EPOCH_SLOTS);
        assert!(u64::try_from(out.update_y_deadline).unwrap() > FLOOR);
    }
}

#[cfg(test)]
mod operator_guide {
    use super::*;

    /// The worked table in `docs/operator-guide.md` §"Choosing the number".
    ///
    /// The guide tells an operator to pick a cycle length by how many batch
    /// opportunities it leaves, and prints the arithmetic for three candidates. It
    /// is arithmetic nobody would recompute by hand after a change to the rescale
    /// rule, and a guide that quietly goes wrong about `update_y_deadline` costs a
    /// roster a ceremony window. So the numbers are pinned here rather than
    /// trusted.
    ///
    /// Against the schedule the shared preprod bridge publishes: pitch 21600,
    /// cutoff 345600, `update_y_deadline` 10800.
    #[test]
    fn the_guides_worked_table_still_holds() {
        let raw = super::tests::schedule();
        // (slots, cycle, final_tm_cutoff, batch opportunities, update_y_deadline)
        for (slots, cutoff, opportunities, update_y) in [
            (43_200u64, 34_560i64, 1i64, 1_080i64),
            (86_400, 69_120, 3, 2_160),
            (172_800, 138_240, 6, 4_320),
        ] {
            let s = EpochScheme::Virtual { slots }
                .schedule(&raw, 900)
                .unwrap_or_else(|e| panic!("{slots}-slot cycle must be usable: {e}"));
            assert_eq!(s.final_tm_cutoff, cutoff, "cutoff for {slots} slots");
            assert_eq!(s.update_y_deadline, update_y, "update_y for {slots} slots");
            // `B_i <= final_tm_cutoff`, and the pitch does NOT rescale — which is
            // the whole point the table is making.
            assert_eq!(
                s.final_tm_cutoff / s.tm_batch_interval,
                opportunities,
                "batch opportunities in a {slots}-slot cycle"
            );
            assert_eq!(
                s.tm_batch_interval, raw.tm_batch_interval,
                "the pitch must not rescale, or the table's premise is gone"
            );
        }
    }

    /// The guide's rule of thumb: the usable minimum is 40x the ceremony floor,
    /// because the published `update_y_deadline` rescales to `slots / 40` while the
    /// floor does not move.
    #[test]
    fn the_guides_forty_times_the_ceremony_floor_rule_holds() {
        let raw = super::tests::schedule();
        for slots in [43_200u64, 86_400, 172_800] {
            let s = EpochScheme::Virtual { slots }.schedule(&raw, 900).unwrap();
            assert_eq!(
                s.update_y_deadline,
                i64::try_from(slots / 40).unwrap(),
                "the guide states the scaled deadline is slots/40"
            );
        }
        // Default floor 900 -> 36000, comfortably under the 43200 hard minimum.
        assert!(
            EpochScheme::Virtual { slots: 43_200 }
                .schedule(&raw, 900)
                .is_ok()
        );
        // A 20-minute ceremony window moves the requirement to 48000, so the
        // 12-hour cycle the guide warns about is refused.
        assert!(
            EpochScheme::Virtual { slots: 43_200 }
                .schedule(&raw, 1_200)
                .is_err(),
            "a widened ceremony window must refuse a 12-hour cycle, as the guide says"
        );
    }
}
