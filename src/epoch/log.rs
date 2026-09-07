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
