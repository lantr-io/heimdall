//! The state machine's trace macros.
//!
//! `dkg.rs`, `signing.rs`, `machine.rs` and `rotation.rs` narrate the protocol
//! through these, in a deliberate line-based format so a developer running
//! `heimdall demo` in three terminals can follow DKG and signing step by step.
//!
//! Each line carries `[spo=N epoch=E]` so interleaved output from concurrent
//! SPOs stays attributable. That prefix stays in the message text rather than
//! becoming a tracing field: it is what makes the three-terminal view scannable,
//! and fields render *after* the message.
//!
//! The four variants exist so severity survives the trip to journald — see
//! [`crate::logging`]. Use `epoch_log!` for protocol progress, `epoch_debug!`
//! for per-peer and per-packet detail, `epoch_warn!` when the node degrades or
//! drops something, `epoch_error!` when it gives up.
//!
//! `epoch_event!` is the fifth: `info`, but under [`crate::logging::EVENT_TARGET`]
//! so the handful of lines an operator wants pushed to them can be selected on
//! their own — see there for what qualifies.

use std::collections::BTreeMap;

use frost_secp256k1_tr::Identifier;

use crate::epoch::state::SpoInfo;

/// Render an `Identifier` as the small integer participant index (1, 2, 3, …)
/// for trace output. The same value the wire layer binds into canonical bytes —
/// see [`crate::frost::identifier_u16`], which owns the conversion.
pub fn id_short(id: Identifier) -> u16 {
    crate::frost::identifier_u16(id)
}

/// Format the first `take` bytes of `data` as hex with an ellipsis if
/// there's more. Used for showing wire payloads compactly in trace
/// output.
pub fn short_hex(data: &[u8], take: usize) -> String {
    if data.len() <= take {
        hex::encode(data)
    } else {
        format!(
            "{}…({} more)",
            hex::encode(&data[..take]),
            data.len() - take
        )
    }
}

/// Protocol progress: the steps an operator expects to see on a healthy node.
#[macro_export]
macro_rules! epoch_log {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::info!(
            "[spo={} epoch={}] {}",
            $crate::epoch::log::id_short($me),
            $epoch,
            format_args!($($arg)*)
        );
    }};
}

/// An operator-facing protocol event: a DKG round opening with its participant
/// list, the key and address a ceremony produced, a treasury movement built,
/// posted or confirmed. `info`, under [`crate::logging::EVENT_TARGET`], with the
/// same `[spo=N epoch=E]` prefix as the rest.
///
/// One event is ONE line and says everything it has to say by itself. A relay
/// forwards lines, not stretches of log, so an event that leans on the
/// `epoch_log!` lines around it arrives out of context.
#[macro_export]
macro_rules! epoch_event {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::info!(
            target: $crate::logging::EVENT_TARGET,
            "[spo={} epoch={}] {}",
            $crate::epoch::log::id_short($me),
            $epoch,
            format_args!($($arg)*)
        );
    }};
}

/// Per-peer, per-packet and per-input detail. Off by default.
#[macro_export]
macro_rules! epoch_debug {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::debug!(
            "[spo={} epoch={}] {}",
            $crate::epoch::log::id_short($me),
            $epoch,
            format_args!($($arg)*)
        );
    }};
}

/// The node degraded, dropped a peer's contribution, or fell back to a weaker
/// guarantee — it is still running, but an operator should know.
#[macro_export]
macro_rules! epoch_warn {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::warn!(
            "[spo={} epoch={}] {}",
            $crate::epoch::log::id_short($me),
            $epoch,
            format_args!($($arg)*)
        );
    }};
}

/// The node could not do what it set out to do.
#[macro_export]
macro_rules! epoch_error {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::error!(
            "[spo={} epoch={}] {}",
            $crate::epoch::log::id_short($me),
            $epoch,
            format_args!($($arg)*)
        );
    }};
}

/// A DKG participant list as one clause — `#1 pool1… http://…, #2 …` — in
/// identifier order, which is the order the roster assigned. The full bech32
/// pool id, not a prefix: an operator reading this in a channel is matching it
/// against a pool they know or pasting it into an explorer, and either wants
/// the whole string.
pub fn describe_participants<'a>(
    participants: impl IntoIterator<Item = (&'a Identifier, &'a SpoInfo)>,
) -> String {
    participants
        .into_iter()
        .map(|(id, info)| {
            format!(
                "#{} {} {}",
                id_short(*id),
                pool_label(&info.pool_id),
                info.bifrost_url
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The SUBSET of a roster named by `ids`, as `#N <url>`, in index order.
///
/// Exists because the DKG's later rounds used to print bare indices
/// (`(#1 #2 #3)`) while Round 1 printed the full list. An operator reading the
/// Discord relay could see that a round went ahead with three of four, but not
/// WHICH node was missing, and matching an index back to a URL meant scrolling
/// to the Round-1 line for the same attempt — an index is positional, so it is
/// only meaningful next to the roster it came from.
///
/// The URL and not the pool id, deliberately: these lines say who was PRESENT,
/// and the URL is the thing an operator acts on — it is what they reach for to
/// check whether a node is up. A bech32 pool id is 56 characters, so carrying
/// both would treble the length of a line that already repeats per round, for
/// an identifier that Round 1 has already published alongside the same index.
///
/// An id with no entry in the roster is shown as `#N (not in roster)` rather
/// than dropped: a set that names someone the roster does not is a bug worth
/// seeing, and silently rendering fewer entries than the count beside it would
/// hide exactly that.
pub fn describe_selected<'a>(
    ids: impl IntoIterator<Item = &'a Identifier>,
    roster: &BTreeMap<Identifier, SpoInfo>,
) -> String {
    ids.into_iter()
        .map(|id| match roster.get(id) {
            Some(info) => format!("#{} {}", id_short(*id), info.bifrost_url),
            None => format!("#{} (not in roster)", id_short(*id)),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The registry as this ceremony reads it: who is eligible, and who is
/// registered but is NOT, with the reason.
///
/// The reason half is the point. A pool that registers and is then dropped —
/// banned, a bad or duplicate `bifrost_url`, no stake at this snapshot — appears
/// in `registered` and not in `eligible`, and until this nothing said which it
/// was or why. The operator of that pool sees their node do nothing at all, and
/// the roster sees a count that does not match. `NoStake` is the cruellest of
/// them, because it is not a fault: it is what every registration looks like
/// until its stake activates, so the honest answer is "we see you, wait".
///
/// URLs for the eligible, pool ids for the excluded: an excluded pool may have
/// been dropped BECAUSE of its URL, so the pool id is the identifier that is
/// certainly still meaningful.
pub fn describe_registry(ctx: &crate::cardano::dkg_roster::DkgContext) -> String {
    let eligible = ctx
        .participants
        .iter()
        .map(|p| format!("#{} {}", p.index, p.bifrost_url))
        .collect::<Vec<_>>()
        .join(", ");
    let registered = ctx.participants.len() + ctx.excluded.len();
    if ctx.excluded.is_empty() {
        return format!("{registered} registered, all eligible: {eligible}");
    }
    let excluded = ctx
        .excluded
        .iter()
        .map(|x| format!("{} ({})", pool_label(&x.pool_id), x.reason))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{registered} registered, {} eligible: {eligible} — NOT eligible: {excluded}",
        ctx.participants.len()
    )
}

/// `pool1…` for a 28-byte pool id. Fixtures predating WI-013 carry none, and a
/// malformed one is shown as it is rather than hidden.
pub fn pool_label(pool_id: &[u8]) -> String {
    match <[u8; 28]>::try_from(pool_id) {
        Ok(id) => crate::cardano::hash::pool_id_bech32(&id),
        Err(_) if pool_id.is_empty() => "(no pool id)".to_string(),
        Err(_) => hex::encode(pool_id),
    }
}

/// `#1 #3 #4` — a set of participants by index, in the order given.
pub fn id_list<'a>(ids: impl IntoIterator<Item = &'a Identifier>) -> String {
    ids.into_iter()
        .map(|id| format!("#{}", id_short(*id)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Peers whose fetch is CURRENTLY failing in a round, and why.
///
/// Every poll in this crate treats a per-peer fetch failure as "this peer has
/// not published" — unreachable, unparseable and silent are one bucket, because
/// exclusion has to be deterministic or two nodes close different subsets
/// (WI-098, spec §Failure handling). The operator still needs them apart:
/// silence is a peer that is down or not participating, an error is a peer that
/// is up and broken, and only the second is worth paging about.
///
/// Shared rather than re-implemented per poll because the easy half to get wrong
/// is [`Self::answered`] — a clean 404 IS an answer, so a peer that errors once
/// and then serves 404s for the rest of the round has RECOVERED. Reporting it as
/// unreachable is the false positive that teaches operators to skip the line.
#[derive(Debug, Default)]
pub struct Unreachable {
    peers: std::collections::BTreeMap<Identifier, String>,
}

impl Unreachable {
    /// Record a failing fetch. Returns `true` the FIRST time this peer fails in
    /// this round, which is when to log: at a 10 ms poll interval against a
    /// 30-minute window, logging every failure is tens of thousands of identical
    /// lines.
    pub fn record(&mut self, id: Identifier, why: impl std::fmt::Display) -> bool {
        self.peers.insert(id, why.to_string()).is_none()
    }

    /// Note that this peer answered — with a payload OR with a clean "nothing
    /// published yet". Both mean it is reachable.
    pub fn answered(&mut self, id: Identifier) {
        self.peers.remove(&id);
    }

    /// A clause for the round's closing line, empty when every peer was
    /// reachable. Already in identifier order: it is a `BTreeMap`, and sorting
    /// the rendered strings instead would put "10" before "2".
    #[must_use]
    pub fn note(&self) -> String {
        if self.peers.is_empty() {
            return String::new();
        }
        let listed: Vec<String> = self
            .peers
            .iter()
            .map(|(id, why)| format!("{} ({why})", id_short(*id)))
            .collect();
        format!(" UNREACHABLE (up but erroring): {}.", listed.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn ident(n: u16) -> Identifier {
        Identifier::try_from(n).unwrap()
    }

    #[test]
    fn participants_render_in_identifier_order_with_full_pool_ids() {
        let mut roster = BTreeMap::new();
        for (n, byte) in [(2u16, 0x22u8), (1, 0x11)] {
            roster.insert(
                ident(n),
                SpoInfo {
                    identifier: ident(n),
                    pool_id: vec![byte; 28],
                    bifrost_url: format!("http://spo{n}.example:1850{n}"),
                    bifrost_id_pk: Vec::new(),
                },
            );
        }
        let line = describe_participants(roster.iter());
        let (first, second) = line.split_once(", ").unwrap();
        assert!(first.starts_with("#1 pool1"), "{line}");
        assert!(first.ends_with(" http://spo1.example:18501"), "{line}");
        assert!(second.starts_with("#2 pool1"), "{line}");
        // A bech32 pool id is 56 characters and stays whole.
        let pool = first.split(' ').nth(1).unwrap();
        assert_eq!(pool.len(), 56, "{pool}");
        assert_eq!(pool, pool_label(&[0x11; 28]));
    }

    /// The subset a later DKG round went ahead with, named rather than numbered.
    ///
    /// Round 1 prints the whole roster with URLs; the rounds after it used to
    /// print bare indices, so "3 of 4" told an operator that someone was missing
    /// but not who — and an index only means anything beside the roster it came
    /// from.
    #[test]
    fn a_selected_subset_names_who_it_kept_and_who_it_does_not_know() {
        let mut roster = BTreeMap::new();
        for (n, byte) in [(1u16, 0x11u8), (2, 0x22), (3, 0x33)] {
            roster.insert(
                ident(n),
                SpoInfo {
                    identifier: ident(n),
                    pool_id: vec![byte; 28],
                    bifrost_url: format!("http://spo{n}.example:1850{n}"),
                    bifrost_id_pk: Vec::new(),
                },
            );
        }

        // The realistic case: one member did not publish.
        let kept = [ident(1), ident(3)];
        let line = describe_selected(kept.iter(), &roster);
        assert!(line.starts_with("#1 http://spo1.example:18501"), "{line}");
        assert!(
            !line.contains("pool1"),
            "these lines carry the URL only — Round 1 already published the pool id: {line}"
        );
        assert!(line.contains("http://spo3.example:18503"), "{line}");
        assert!(
            !line.contains("spo2"),
            "the absent member must not appear: {line}"
        );
        assert_eq!(
            line.split(", ").count(),
            kept.len(),
            "the list has to be as long as the count printed beside it: {line}"
        );

        // An id the roster does not know is SHOWN, not dropped — otherwise the
        // list would be shorter than the count and hide the disagreement.
        let stray = [ident(1), ident(9)];
        let line = describe_selected(stray.iter(), &roster);
        assert!(line.contains("#9 (not in roster)"), "{line}");
        assert_eq!(line.split(", ").count(), 2, "{line}");
    }

    /// The registry line, and specifically the half that did not exist before:
    /// a pool that registered and is NOT eligible, with the reason.
    #[test]
    fn the_registry_line_says_who_is_not_eligible_and_why() {
        use crate::cardano::dkg_roster::{
            DkgContext, DkgParticipant, ExcludedSpo, ExclusionReason,
        };

        let participant = |n: u16, byte: u8| DkgParticipant {
            index: n,
            identifier: ident(n),
            pool_id: vec![byte; 28],
            bifrost_id_pk: vec![byte; 32],
            bifrost_url: format!("http://spo{n}.example:1850{n}"),
            active_stake: 20_000_000,
        };
        let mut ctx = DkgContext {
            epoch: 1543,
            attempt: 0,
            threshold: 2,
            total_stake: 40_000_000,
            participants: vec![participant(1, 0x11), participant(2, 0x22)],
            excluded: Vec::new(),
            schedule_anchor_ms: None,
            read_time_ms: 0,
            live_stake: false,
        };

        // A steady roster reads as one clause, no "NOT eligible" tail.
        let line = describe_registry(&ctx);
        assert!(line.starts_with("2 registered, all eligible:"), "{line}");
        assert!(line.contains("#1 http://spo1.example:18501"), "{line}");
        assert!(!line.contains("NOT eligible"), "{line}");

        // A pool that registered and is waiting for its stake: named, with the
        // reason, because "we see you, wait" is the whole point of the line.
        ctx.excluded.push(ExcludedSpo {
            pool_id: vec![0x33; 28],
            bifrost_id_pk: vec![0x33; 32],
            reason: ExclusionReason::NoStake,
        });
        let line = describe_registry(&ctx);
        assert!(line.starts_with("3 registered, 2 eligible:"), "{line}");
        assert!(line.contains("NOT eligible:"), "{line}");
        assert!(line.contains(&pool_label(&[0x33; 28])), "{line}");
        assert!(
            line.contains("activates two epoch boundaries later"),
            "the reason has to be the actionable one, not just a label: {line}"
        );
    }

    #[test]
    fn a_missing_or_malformed_pool_id_is_said_not_hidden() {
        assert_eq!(pool_label(&[]), "(no pool id)");
        assert_eq!(pool_label(&[0xab, 0xcd]), "abcd");
    }

    #[test]
    fn id_list_is_hash_prefixed_indices() {
        let ids = [ident(1), ident(3), ident(4)];
        assert_eq!(id_list(ids.iter()), "#1 #3 #4");
        assert_eq!(id_list(std::iter::empty()), "");
    }
}
