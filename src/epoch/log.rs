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

use frost_secp256k1_tr::Identifier;

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
