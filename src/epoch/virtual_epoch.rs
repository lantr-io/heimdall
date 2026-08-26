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
//! ## Why the schedule has to rescale with it
//!
//! The Config `schedule` is written for a five-day epoch: `final_tm_cutoff` is
//! 345600 slots (four days) and `tm_batch_interval` 21600 (six hours). Dropped
//! unchanged into a 24-hour cycle the cutoff sits three days past the end of its
//! own epoch, so the "last opportunity" it names never arrives and the grid
//! silently never closes. Rescaling by `slots / CARDANO_EPOCH_SLOTS` keeps the
//! shape of the schedule — the same number of batch opportunities per cycle, the
//! rounds in the same proportions — and, being derived from two numbers every
//! node already agrees on, it cannot itself diverge. That is the reason it beats
//! the alternative of asking operators to hand-tune five Config values
//! consistently across a roster.
//!
//! [`ScheduleParams::stability_window`] is the one exception and it is not an
//! oversight: it is `3k/f` of the HOST chain. Cardano does not settle faster
//! because the bridge's cycle is shorter, so scaling it would understate how
//! long a deposit must age before it is safe to spend — a safety value bent to
//! make a test run faster. It stays exactly as published, and what it costs a
//! test bridge is set out in the operator guide.

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

/// Shortest virtual epoch accepted: one hour. Below this the rescaled schedule
/// is compressed by more than 100×, and a DKG round would close before the
/// nodes had finished exchanging packages.
pub const MIN_VIRTUAL_EPOCH_SLOTS: u64 = 3_600;

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
                 (one hour) — the rescaled ceremony rounds would close before the nodes \
                 could exchange their packages"
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

    /// The ceremony epoch at `tip_slot` — `None` on real epochs, where the
    /// chain answers instead.
    #[must_use]
    pub fn epoch_at(self, tip_slot: u64) -> Option<u64> {
        self.virtual_slots().map(|slots| tip_slot / slots)
    }

    /// The slot the current cycle began at, or `None` on real epochs.
    #[must_use]
    pub fn start_slot(self, tip_slot: u64) -> Option<u64> {
        self.virtual_slots()
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
    /// Every value scales except `stability_window` (see the module doc). The
    /// refusals are the point of returning a `Result`: a schedule that overruns
    /// its own epoch, or one compressed until a positive value reaches zero, is
    /// a schedule whose opportunities never arrive, and running it produces a
    /// bridge that looks alive and moves nothing. Better to say so.
    pub fn schedule(self, raw: &ScheduleParams) -> Result<ScheduleParams, String> {
        let Some(slots) = self.virtual_slots() else {
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
            tm_batch_interval: scale(raw.tm_batch_interval, "tm_batch_interval")?,
            sign_r1_window: scale(raw.sign_r1_window, "sign_r1_window")?,
            sign_r2_window: scale(raw.sign_r2_window, "sign_r2_window")?,
            leader_slot_t: scale(raw.leader_slot_t, "leader_slot_t")?,
            tm_recovery_window: scale(raw.tm_recovery_window, "tm_recovery_window")?,
            final_tm_cutoff: scale(raw.final_tm_cutoff, "final_tm_cutoff")?,
            // NOT rescaled — a host-chain settlement depth, not bridge pacing.
            stability_window: raw.stability_window,
        };
        // `B_i ≤ final_tm_cutoff` bounds the grid, so a cutoff at or past the end
        // of the cycle means the epoch's TM work never closes and the "last
        // opportunity" the spec relies on does not exist. Rescaling makes this
        // hold for any sane published schedule; it is checked rather than assumed
        // because the Config is governance-set and could carry a cutoff longer
        // than an epoch.
        if out.final_tm_cutoff >= 0
            && u64::try_from(out.final_tm_cutoff).unwrap_or(u64::MAX) >= slots
        {
            return Err(format!(
                "schedule.final_tm_cutoff rescales to {} slots, which is not inside a \
                 {slots}-slot virtual epoch — the epoch's last batch opportunity would \
                 never arrive",
                out.final_tm_cutoff
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published preprod schedule, as the fixtures carry it.
    fn schedule() -> ScheduleParams {
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

    #[test]
    fn a_real_epoch_scheme_changes_nothing() {
        let s = EpochScheme::Cardano;
        assert_eq!(s.virtual_slots(), None);
        assert_eq!(s.epoch_at(96_000_000), None);
        assert_eq!(s.anchor_slot(95_000_000, 96_000_000), 95_000_000);
        assert_eq!(s.schedule(&schedule()).unwrap(), schedule());
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

    /// A 24-hour cycle is a fifth of an epoch, so the schedule is a fifth of
    /// itself — and the cutoff now lands INSIDE the cycle, which is the whole
    /// point of rescaling it.
    #[test]
    fn the_schedule_is_rescaled_in_proportion() {
        let day = EpochScheme::Virtual { slots: 86_400 };
        let s = day.schedule(&schedule()).unwrap();
        assert_eq!(s.tm_batch_interval, 4_320);
        assert_eq!(s.final_tm_cutoff, 69_120);
        assert_eq!(s.update_y_deadline, 2_160);
        assert!(
            u64::try_from(s.final_tm_cutoff).unwrap() < 86_400,
            "the cutoff must be inside its own epoch"
        );
        // The same NUMBER of opportunities as a real epoch: 345600/21600 = 16.
        assert_eq!(
            s.final_tm_cutoff / s.tm_batch_interval,
            schedule().final_tm_cutoff / schedule().tm_batch_interval
        );
    }

    /// The host chain does not settle faster because the bridge's cycle is
    /// shorter. Scaling this would be a safety value bent for a test's
    /// convenience.
    #[test]
    fn the_stability_window_is_not_rescaled() {
        let day = EpochScheme::Virtual { slots: 86_400 };
        assert_eq!(
            day.schedule(&schedule()).unwrap().stability_window,
            schedule().stability_window
        );
    }

    /// A published cutoff longer than an epoch still overruns after rescaling,
    /// and is refused rather than run.
    #[test]
    fn a_schedule_that_overruns_its_epoch_is_refused() {
        let mut raw = schedule();
        raw.final_tm_cutoff = CARDANO_EPOCH_SLOTS as i64 * 2;
        let e = EpochScheme::Virtual { slots: 86_400 }
            .schedule(&raw)
            .expect_err("must refuse");
        assert!(e.contains("final_tm_cutoff"), "{e}");
        assert!(e.contains("never arrive"), "{e}");
    }

    /// Compression that zeroes a positive value is refused too: a
    /// `tm_batch_interval` of 0 has no grid at all, and the round windows
    /// collapse to nothing.
    #[test]
    fn a_value_compressed_to_zero_is_refused() {
        let mut raw = schedule();
        raw.leader_slot_t = 1;
        let e = EpochScheme::Virtual { slots: 3_600 }
            .schedule(&raw)
            .expect_err("must refuse");
        assert!(e.contains("leader_slot_t"), "{e}");
        assert!(e.contains("rescales to 0"), "{e}");
    }

    /// Zero, and any value that is not actually shorter than a real epoch, are
    /// typos rather than choices.
    #[test]
    fn an_unusable_cycle_length_is_refused_at_config_load() {
        assert_eq!(EpochScheme::from_slots(None).unwrap(), EpochScheme::Cardano);
        assert!(EpochScheme::from_slots(Some(0)).is_err());
        assert!(EpochScheme::from_slots(Some(60)).is_err());
        assert!(EpochScheme::from_slots(Some(CARDANO_EPOCH_SLOTS)).is_err());
        assert!(EpochScheme::from_slots(Some(CARDANO_EPOCH_SLOTS * 2)).is_err());
        assert_eq!(
            EpochScheme::from_slots(Some(86_400)).unwrap(),
            EpochScheme::Virtual { slots: 86_400 }
        );
    }
}
