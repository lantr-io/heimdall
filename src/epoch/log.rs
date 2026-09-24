//! The state machine's trace macros.
//!
//! `dkg.rs`, `signing.rs`, `machine.rs` and `rotation.rs` narrate the protocol
//! through these, in a deliberate line-based format so a developer running
//! `heimdall demo` in three terminals can follow DKG and signing step by step.
//!
//! Each line carries `[epoch=<bridge epoch>]`, and `[<pool label> epoch=…]`
//! once a process has logged under more than one identity — see [`prefix`] for
//! why the label is conditional. The prefix stays in the message text rather
//! than becoming a tracing field: fields render *after* the message, which would
//! put the attribution behind the sentence it attributes.
//!
//! The epoch is the BRIDGE epoch, which the ceremony, the batch grid and the
//! persisted state are all keyed by; on a test run it is the virtual epoch, and
//! the startup block maps it to Cardano's.
//!
//! Where a label IS printed it is the pool's own bech32 id, shortened —
//! `pool1zk3ns…q7wd` — and never the FROST index. An index is assigned per
//! roster read in the lexicographic order of bifrost keys, so it moves whenever
//! a pool joins or leaves: `spo=4` named a different node in different epochs,
//! and named nothing at all to the operator, who knows their pool id and has
//! never seen that number.
//!
//! The four level variants exist so severity survives the trip to journald — see
//! [`crate::logging`]. Use `epoch_log!` for protocol progress, `epoch_debug!`
//! for per-peer and per-packet detail, `epoch_warn!` when the node degrades or
//! drops something, `epoch_error!` when it gives up.
//!
//! Two more carry the operator-facing events, under
//! [`crate::logging::EVENT_TARGET`], so the handful of lines an operator wants
//! pushed to them can be selected on their own — see there for what qualifies.
//! `epoch_event!` is the `info` one; `epoch_event_warn!` is the same channel at
//! `warn`, for an event that reports a FAILURE. Reach for the second whenever
//! the event is the unhappy outcome of one the first already reports, so a relay
//! keeping only failures does not end up keeping only the successes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, RwLock};
use std::time::Instant;

use frost_secp256k1_tr::Identifier;

use crate::epoch::state::SpoInfo;

/// Render an `Identifier` as the small integer participant index (1, 2, 3, …)
/// for trace output. The same value the wire layer binds into canonical bytes —
/// see [`crate::frost::identifier_u16`], which owns the conversion.
pub fn id_short(id: Identifier) -> u16 {
    crate::frost::identifier_u16(id)
}

// ── This node's label, for the line prefix ──────────────────────────

/// Identifier -> pool label, for the PREFIX of every line this node writes
/// (spec [LG-4]).
///
/// Process-wide because the macros take only `me` and an epoch, and threading a
/// roster through every call site of six macros would be a worse trade than one
/// uncontended read lock per line.
///
/// Deliberately NOT used to name a PEER ([LG-4a]). The index an identifier
/// stands for is assigned per roster read, in the lexicographic order of bifrost
/// keys, so one pool joining shifts every index above it — and a signing round
/// can run under a previous epoch's persisted ceremony while this table already
/// holds the newer roster. `me` is safe because the node re-derives its own
/// identifier from the same read that fills this table.
static LABELS: LazyLock<RwLock<BTreeMap<Identifier, String>>> = LazyLock::new(RwLock::default);

/// Replace the label table from a roster read (spec [LG-5]).
///
/// Replaces rather than merges: a stale entry for a pool that has left would
/// otherwise outlive the roster that justified it.
pub fn set_labels(roster: &BTreeMap<Identifier, SpoInfo>) {
    let next: BTreeMap<Identifier, String> = roster
        .iter()
        .map(|(id, info)| (*id, pool_short(&info.pool_id, id_short(*id))))
        .collect();
    if let Ok(mut table) = LABELS.write() {
        *table = next;
    }
}

/// This node's label for the line prefix, or `spo#N` before the first roster
/// read (spec [HL-2]).
pub fn label(id: Identifier) -> String {
    LABELS
        .read()
        .ok()
        .and_then(|t| t.get(&id).cloned())
        .unwrap_or_else(|| format!("spo#{}", id_short(id)))
}

/// Every identity this process has written a line under. Almost always one.
static SEEN: LazyLock<RwLock<BTreeSet<Identifier>>> = LazyLock::new(RwLock::default);

/// The body of the `[…]` prefix: `epoch=E`, or `<pool label> epoch=E` once this
/// process has logged under more than one identity (spec [LG-1]).
///
/// A daemon runs ONE pool, so its label never varies within a stream and
/// `journalctl -u <unit>` has already scoped the reader to that node. Eighteen
/// constant characters on every line buy nothing there, and the startup block
/// states the full pool id once while the roster table marks `(this node)`.
///
/// The epoch always stays: it moves, and the ceremony, the batch grid and the
/// persisted state are all keyed by it, so a line without it cannot be placed.
///
/// The label returns automatically if a process ever interleaves two identities
/// — several nodes driven from one test, a future in-process demo — because
/// there the label is the only thing telling two lines apart.
pub fn prefix(me: Identifier, epoch: u64) -> String {
    let many = match SEEN.write() {
        Ok(mut seen) => {
            seen.insert(me);
            seen.len() > 1
        }
        // A poisoned lock must not cost the line its epoch.
        Err(_) => false,
    };
    if many {
        format!("{} epoch={epoch}", label(me))
    } else {
        format!("epoch={epoch}")
    }
}

// ── Times, amounts, counts ──────────────────────────────────────────

/// `HH:MM:SS UTC` for a POSIX-millisecond instant (spec [LG-10]).
///
/// No date: every moment a line names is hours away at most, the log's own
/// timestamp carries the date, and [`countdown`] says which day when it is more
/// than one. UTC only, for the reason `crate::logging` gives — a bridge log is
/// read beside Cardano slots and Bitcoin block times, both of which are UTC.
pub fn utc_hms(unix_ms: i64) -> String {
    let rem = unix_ms.div_euclid(1000).rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// How long until `target_ms`, as `(in 2h30m)` — or `(now)` when it is not in
/// the future (spec [LG-11], [LG-11a]).
///
/// Rounded DOWN to the minute and parenthesised, because every caller appends it
/// to an absolute time: "09:00:00 UTC (in 2h30m)" answers both "when" and "how
/// long" without the reader doing arithmetic against a clock in another zone.
pub fn countdown(target_ms: i64, now_ms: i64) -> String {
    let secs = (target_ms - now_ms).div_euclid(1000);
    if secs <= 0 {
        return "(now)".to_string();
    }
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("(in {d}d{h}h{m}m)")
    } else if h > 0 {
        format!("(in {h}h{m}m)")
    } else {
        format!("(in {m}m)")
    }
}

/// When a future slot falls, in POSIX milliseconds (spec [HL-6]).
///
/// `now_ms` and `now_slot` must be the aligned pair a `BatchSnapshot` carries —
/// the tip block's own time and the tip slot — so no local-clock skew enters.
/// One second per slot, which holds on mainnet, preprod and the devnet, and is
/// the same assumption the batch grid in `cardano::config_params` already makes.
pub fn slot_time_ms(now_ms: i64, now_slot: u64, slot: u64) -> i64 {
    let delta = i64::try_from(slot).unwrap_or(i64::MAX) - i64::try_from(now_slot).unwrap_or(0);
    now_ms.saturating_add(delta.saturating_mul(1000))
}

/// `1 entry` / `3 entries` (spec [LG-14]).
///
/// Exists so no line has to write `entr(y|ies)` or `peg-in(s)`, which is a regex
/// where a sentence belongs.
pub fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {many}")
    }
}

/// Lovelace as ADA: `1,234,567 ADA`, `5 ADA`, `2.5 ADA` (spec [HL-8], [LG-9]).
///
/// Never lovelace. A stake figure is the one number in this log an operator
/// already knows by heart in ADA, and seven extra digits is how a reader loses
/// the order of magnitude they were checking.
pub fn ada(lovelace: u64) -> String {
    // Hundredths of an ADA, rounded half-up, so the carry out of `.995` lands in
    // the whole part instead of printing `2.100`.
    let hundredths = lovelace.saturating_add(5_000) / 10_000;
    let (whole, frac) = (hundredths / 100, hundredths % 100);
    let mut out = thousands(whole);
    if frac > 0 {
        out.push('.');
        out.push_str(format!("{frac:02}").trim_end_matches('0'));
    }
    out.push_str(" ADA");
    out
}

/// `1234567` -> `1,234,567`.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.char_indices() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A share of the total, as a percentage with one decimal. `0.0` for an empty
/// total rather than a panic: a roster with no stake is a deployment fault the
/// lines around this one already report.
fn percent(part: u128, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / total as f64
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
            "[{}] {}",
            $crate::epoch::log::prefix($me, $epoch),
            format_args!($($arg)*)
        );
    }};
}

/// An operator-facing protocol event: a DKG round opening with its participant
/// list, the key and address a ceremony produced, a treasury movement built,
/// posted or confirmed. `info`, under [`crate::logging::EVENT_TARGET`], with the
/// same `[<pool label> epoch=<bridge epoch>]` prefix as the rest.
///
/// One event is ONE line and says everything it has to say by itself. A relay
/// forwards lines, not stretches of log, so an event that leans on the
/// `epoch_log!` lines around it arrives out of context.
#[macro_export]
macro_rules! epoch_event {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::info!(
            target: $crate::logging::EVENT_TARGET,
            "[{}] {}",
            $crate::epoch::log::prefix($me, $epoch),
            format_args!($($arg)*)
        );
    }};
}

/// An operator-facing protocol event that is also a FAILURE: same
/// [`crate::logging::EVENT_TARGET`] as [`crate::epoch_event!`], at `warn`.
///
/// The severity and the channel are two different questions and this answers
/// both. A posted movement is an event; a movement that could NOT be posted is
/// the same event's other outcome, and an operator who is told the first and not
/// the second reads silence as success. Emitting it as an ordinary `epoch_warn!`
/// would reach the relay's level filter but not its event filter, so a relay run
/// with `--min-level error` — "keep only failures" — would drop the failure, and
/// one run with `--min-level off` would show the posts and none of the misses.
///
/// `warn` passes the `heimdall::event=info` directive a bare `--log-level` pins,
/// so these survive a quiet node exactly as the `info` events do.
#[macro_export]
macro_rules! epoch_event_warn {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::warn!(
            target: $crate::logging::EVENT_TARGET,
            "[{}] {}",
            $crate::epoch::log::prefix($me, $epoch),
            format_args!($($arg)*)
        );
    }};
}

/// Collapse a multi-line error into one line, for an event that must stay one
/// line.
///
/// The formatter repeats the `<N>target:` prefix on every line of a multi-line
/// message, so nothing is LOST to the relay — but the continuation lines lose
/// the `[<pool label> epoch=E]` prefix and arrive as free-standing fragments. A
/// Blockfrost rejection is exactly that shape (`Status code: 400` / `Error: …` /
/// `Message: <the ledger error>`), so the one line naming the actual cause would
/// reach the channel with nothing tying it to the movement it is about, and
/// would be split off entirely if it fell outside the relay's coalesce window.
///
/// Whitespace-collapsing rather than newline-replacing: the SDK pretty-prints an
/// unparseable JSON error body, which is indented, and the indentation is not
/// worth carrying into a chat line.
pub fn one_line(e: &impl std::fmt::Display) -> String {
    one_line_within(e, ONE_LINE_BUDGET)
}

/// Room for ONE interpolated cause on a line, with the event's own text around
/// it. An event that interpolates two must divide the line between them with
/// [`one_line_within`] — two of these do not fit together.
const ONE_LINE_BUDGET: usize = 900;

/// `e` on one line, whole, when [`one_line`] would cut it short — and `None`
/// when it would not, because then the line reporting it already said all of it.
pub fn full_text_if_cut(e: &impl std::fmt::Display) -> Option<String> {
    let joined = collapse(e);
    (joined.len() > ONE_LINE_BUDGET).then_some(joined)
}

/// Log the whole of `e` when [`one_line`] cuts it short — which is what
/// makes its "full error in this node's log" true.
///
/// Nothing wrote it there before. Every line reporting a failed step goes through
/// `one_line`, so a Blockfrost rejection whose cause runs past the budget reached
/// the log cut off everywhere it appeared, and the note sent the operator looking
/// for a line that did not exist. On preprod that was a `ValueNotConservedUTxO`
/// on a key handoff, cut off before its `expected` half — the half that says what
/// the transaction got wrong.
///
/// At the level of the line it completes (`warn`): WARN for a warning, so that
/// it is written wherever that warning is — a node run at `--log-level warn`
/// keeps it too, and the note is true there as well. The relay forwards it with
/// the warning, and past its 2000-byte cut a long one arrives in pieces — the
/// price of the whole error being on record on every node. INFO for a line that
/// went to INFO, so that a routine repeat does not arrive in the channel as a
/// dump with no warning in front of it. One line, so it carries the
/// `[epoch=E]` prefix the journal is grepped by.
///
/// Once per distinct error: `last_logged` holds the text last written out, and
/// the same text again is skipped. A failure that repeats on the backoff ramp
/// would otherwise post the same kilobytes to the channel at every retry.
pub fn log_full_error_if_cut(
    me: Identifier,
    epoch: u64,
    e: &impl std::fmt::Display,
    warn: bool,
    last_logged: &mut Option<String>,
) {
    let Some(full) = full_text_if_cut(e) else {
        return;
    };
    if last_logged.as_deref() == Some(full.as_str()) {
        return;
    }
    if warn {
        crate::epoch_warn!(
            me,
            epoch,
            "the full error, which the warning for it cut short: {full}"
        );
    } else {
        crate::epoch_log!(
            me,
            epoch,
            "the full error, which the line for it cut short: {full}"
        );
    }
    *last_logged = Some(full);
}

/// Whitespace collapsed to single spaces — see [`one_line`].
fn collapse(e: &impl std::fmt::Display) -> String {
    e.to_string()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// [`one_line`] with the byte budget stated, for an event that interpolates more
/// than one value.
///
/// The budget is in BYTES because that is what the relay measures:
/// `heimdall-discord` cuts anything past `2000 - fences` bytes into pieces that
/// carry no `[<pool label> epoch=E]` prefix — the very fragmentation this exists to
/// prevent — so a cap in characters would leave a multi-byte error body splitting
/// anyway.
pub fn one_line_within(e: &impl std::fmt::Display, max_bytes: usize) -> String {
    let joined = collapse(e);
    if joined.len() <= max_bytes {
        return joined;
    }
    // Truncating rather than splitting, and saying so: a cause that does not fit
    // is still worth its first `max_bytes`. The note says only that the text was
    // cut and where the whole of it is — deliberately not a length, which would be
    // the length AFTER collapsing and so would not match the multi-line, indented
    // original an operator finds in the log.
    let mut end = max_bytes;
    while !joined.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}… [truncated; full error in this node's log]",
        &joined[..end]
    )
}

/// Per-peer, per-packet and per-input detail. Off by default.
#[macro_export]
macro_rules! epoch_debug {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::debug!(
            "[{}] {}",
            $crate::epoch::log::prefix($me, $epoch),
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
            "[{}] {}",
            $crate::epoch::log::prefix($me, $epoch),
            format_args!($($arg)*)
        );
    }};
}

/// The node could not do what it set out to do.
#[macro_export]
macro_rules! epoch_error {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        ::tracing::error!(
            "[{}] {}",
            $crate::epoch::log::prefix($me, $epoch),
            format_args!($($arg)*)
        );
    }};
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
/// Both halves, deliberately: the pool label is the name an operator knows
/// their own node by, and the URL is the thing they act on when a node is
/// silent. A bare `#N` is neither — the FROST index is an artefact of
/// `bifrost_id_pk` ordering, so one pool joining shifts every index above it,
/// and a reader comparing two epochs' lines by index compares the wrong pools.
///
/// An id with no entry in the roster is shown as `spo#N (not in roster)` rather
/// than dropped: a set that names someone the roster does not is a bug worth
/// seeing, and silently rendering fewer entries than the count beside it would
/// hide exactly that. `spo#N` is the same fallback [`pool_short`] uses when it
/// has no pool id to render.
pub fn describe_selected<'a>(
    ids: impl IntoIterator<Item = &'a Identifier>,
    roster: &BTreeMap<Identifier, SpoInfo>,
) -> String {
    cap_list(
        ids.into_iter()
            .map(|id| match roster.get(id) {
                Some(info) => describe_peer(info),
                None => format!("spo#{} (not in roster)", id_short(*id)),
            })
            .collect(),
        PEER_LIST_CAP,
    )
}

/// One peer of a roster, per [LG-6] — or `spo#N (not in roster)` when the
/// roster does not know it, which is a bug worth seeing rather than hiding.
pub fn named_peer(roster: &BTreeMap<Identifier, SpoInfo>, id: Identifier) -> String {
    roster.get(&id).map_or_else(
        || format!("spo#{} (not in roster)", id_short(id)),
        describe_peer,
    )
}

/// The posting order for one movement, numbered from 1 and capped per
/// [`PEER_LIST_CAP`]: `1 pool1s7wet…z2sj (http://…), 2 pool16qm84…7rmq (this
/// node, http://…), …`.
///
/// Numbered rather than joined by "then", because the number is what the wait
/// is proportional to: the node at position 3 posts two hops late if the two
/// ahead of it are silent. `me` is marked so a reader finds their own place
/// without matching the label against the prefix.
pub fn describe_posting_order(
    ids: impl IntoIterator<Item = Identifier>,
    roster: &BTreeMap<Identifier, SpoInfo>,
    me: Identifier,
) -> String {
    cap_list(
        ids.into_iter()
            .enumerate()
            .map(|(i, id)| {
                let at = i + 1;
                match roster.get(&id) {
                    Some(info) => format!(
                        "{at} {} ({}{})",
                        pool_short(&info.pool_id, id_short(id)),
                        if id == me { "this node, " } else { "" },
                        info.bifrost_url
                    ),
                    None => format!("{at} spo#{} (not in roster)", id_short(id)),
                }
            })
            .collect(),
        PEER_LIST_CAP,
    )
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
/// Label and URL for the eligible, label alone for the excluded: an excluded
/// pool may have been dropped BECAUSE of its URL, so the pool id is the
/// identifier that is certainly still meaningful.
///
/// An excluded pool has no FROST index — it is excluded, so no index was
/// assigned — hence the `0` passed to [`pool_short`]. That argument is only the
/// `spo#N` fallback for a pool id that is not 28 bytes, which the registry
/// reader rejects before it reaches here.
///
/// `cap` bounds each half separately, per [`PEER_LIST_CAP`]. The caller passes
/// `usize::MAX` when the string is compared rather than read: the `registry:`
/// event fires on the string changing, so a capped string would miss one pool
/// leaving and another joining beyond the cap — the counts match and the ten
/// named pools are the same, so nothing would look different.
pub fn describe_registry(ctx: &crate::cardano::dkg_roster::DkgContext, cap: usize) -> String {
    let eligible = cap_list(
        ctx.participants
            .iter()
            .map(|p| format!("{} ({})", pool_short(&p.pool_id, p.index), p.bifrost_url))
            .collect(),
        cap,
    );
    let registered = ctx.participants.len() + ctx.excluded.len();
    if ctx.excluded.is_empty() {
        return format!("{registered} registered, all eligible: {eligible}");
    }
    let excluded = cap_list(
        ctx.excluded
            .iter()
            .map(|x| format!("{} ({})", pool_short(&x.pool_id, 0), x.reason))
            .collect(),
        cap,
    );
    format!(
        "{registered} registered, {} eligible: {eligible} — NOT eligible: {excluded}",
        ctx.participants.len()
    )
}

/// The roster an epoch runs on, and how its threshold was derived — one string
/// per line, for the caller to emit one at a time (spec [RS-1] to [RS-8]).
///
/// One call per line rather than one multi-line event ([RS-9]): the formatter
/// repeats the target and the syslog priority on every line, but the
/// `[label epoch=E]` prefix is message text and would appear on the first line
/// only, leaving the rows as free-standing fragments an operator cannot attribute.
///
/// ASCENDING by stake, with a running total, because that is the derivation made
/// visible: the threshold is the first row whose running total passes the
/// security threshold. An operator asked to trust "6 of 7" can read why off the
/// table without knowing the algorithm, and can see it move when stake moves.
pub fn roster_table(ctx: &crate::cardano::dkg_roster::DkgContext, me: Identifier) -> Vec<String> {
    use crate::cardano::dkg_roster::SECURITY_THRESHOLD_PERCENT;

    let total = ctx.total_stake;
    let mut ascending: Vec<&crate::cardano::dkg_roster::DkgParticipant> =
        ctx.participants.iter().collect();
    // By index after stake, so two pools with equal stake keep a stable order
    // across nodes and across epochs rather than wandering with the read.
    ascending.sort_by_key(|p| (p.active_stake, p.index));

    let eligible = ctx.participants.len();
    let registered = eligible + ctx.excluded.len();
    let mut out = vec![format!(
        "roster for bridge epoch {}: {registered} registered, {eligible} eligible, total stake {}",
        ctx.epoch,
        ada(total)
    )];

    let label_width = ascending
        .iter()
        .map(|p| pool_short(&p.pool_id, p.index).chars().count())
        .max()
        .unwrap_or(0);
    let stake_width = ascending
        .iter()
        .map(|p| ada(p.active_stake).chars().count())
        .max()
        .unwrap_or(0);
    let mut running: u128 = 0;
    for p in &ascending {
        running += u128::from(p.active_stake);
        out.push(format!(
            "  {:<label_width$} {:>stake_width$}  {:>5.1}%  so far {:>5.1}%  {}{}",
            pool_short(&p.pool_id, p.index),
            ada(p.active_stake),
            percent(u128::from(p.active_stake), total),
            percent(running, total),
            p.bifrost_url,
            if p.identifier == me {
                "  (this node)"
            } else {
                ""
            },
        ));
    }

    let stakes: Vec<u64> = ascending.iter().map(|p| p.active_stake).collect();
    let cumulative = |k: usize| -> u128 { stakes.iter().take(k).map(|s| u128::from(*s)).sum() };
    let t = usize::from(ctx.threshold);
    let derived = usize::from(crate::cardano::dkg_roster::security_threshold_k(
        &stakes, total,
    ));
    out.push(if t > derived {
        // The degenerate single-whale case: one pool holds so much that a single
        // signer already clears the security threshold, and FROST's own minimum
        // is what sets `t`. Saying so is the difference between a threshold an
        // operator can check and one that looks arbitrary.
        format!(
            "threshold {t} of {eligible}: raised to the FROST minimum of {t}; the {derived} \
             smallest stakes already hold {:.1}% of total, above the {SECURITY_THRESHOLD_PERCENT}% \
             security threshold",
            percent(cumulative(derived), total)
        )
    } else {
        format!(
            "threshold {t} of {eligible}: the {t} smallest stakes hold {:.1}% of total; the {} \
             smallest hold {:.1}%, not above the {SECURITY_THRESHOLD_PERCENT}% security threshold",
            percent(cumulative(t), total),
            t - 1,
            percent(cumulative(t - 1), total)
        )
    });

    // The pools that registered and did NOT make the eligible set, each with its
    // reason. `NoStake` is the cruellest of them and is not a fault: it is what
    // every registration looks like until its stake activates, so the honest
    // answer is "we see you, wait".
    for x in &ctx.excluded {
        out.push(format!(
            "  not eligible: {} — {}",
            pool_short(&x.pool_id, 0),
            x.reason
        ));
    }
    out
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

/// How many peers one line may name before it stops naming them (spec [LG-22]).
///
/// A bridge is not capped at seven pools. At n=100 an uncapped list runs to
/// about 5,000 characters — one unreadable journal line, and three Discord
/// messages out of the relay, which cuts at 2,000. Ten names is enough to
/// recognise a round's stragglers or a roster's newcomers; past that the
/// operator wants `heimdall show-roster`, not a wall of text.
pub const PEER_LIST_CAP: usize = 10;

/// `a, b, c` up to `cap` entries, then `… and 97 more` (spec [LG-22]).
///
/// The count of the remainder, not just an ellipsis: "and 97 more" tells the
/// reader the scale of what is hidden, which is the difference between a list
/// that was trimmed and one that was short.
fn cap_list(items: Vec<String>, cap: usize) -> String {
    let n = items.len();
    if n <= cap {
        return items.join(", ");
    }
    format!("{} … and {} more", items[..cap].join(", "), n - cap)
}

/// What is left of a round's window, as `45s` or `2m30s` (spec [PR-7]).
///
/// How long the round HAS, not the hour it ends. A round deadline is a
/// monotonic `Instant`, which carries no wall-clock epoch to convert from, and
/// for a window measured in seconds "up to 90s" is the number the operator
/// wanted anyway — "until 09:12:30 UTC" makes them do the subtraction.
pub fn remaining(deadline: Instant, now: Instant) -> String {
    let secs = deadline.saturating_duration_since(now).as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    format!("{}m{}s", secs / 60, secs % 60)
}

/// The SHORT pool id a log line carries: the bech32's first 10 characters, an
/// ellipsis, and its last 4 — `pool1zk3ns…q7wd` (spec [LG-2]).
///
/// A node with no pool id falls back to `spo#N` ([LG-3]): a federation member
/// need not be a Cardano SPO, and fixtures predating WI-013 carry none.
///
/// 14 characters of a 56-character identifier, and deliberately from BOTH ends.
/// The `pool1` prefix is shared by every pool on every network, so a prefix-only
/// form would distinguish pools by 5 characters; taking the tail as well makes a
/// collision between two registered pools something an operator will not meet.
/// The operator reads this against `show-roster`, which prints the whole thing.
pub fn pool_short(pool_id: &[u8], index: u16) -> String {
    let Ok(id) = <[u8; 28]>::try_from(pool_id) else {
        return format!("spo#{index}");
    };
    let full = crate::cardano::hash::pool_id_bech32(&id);
    // bech32 over 28 bytes is always 56 ASCII characters, so this cannot split a
    // character — but a shorter string is returned whole rather than panicking.
    if full.len() <= 14 {
        return full;
    }
    format!("{}…{}", &full[..10], &full[full.len() - 4..])
}

/// One peer, as every line that names one renders it: `pool1abc…9fj (<url>)`
/// (spec [LG-6]).
///
/// The URL is half the point. A line that says a peer is missing is read by an
/// operator who is about to go and check whether that node is up, and the URL is
/// the thing they act on — the pool id alone sends them to `show-roster` first.
pub fn describe_peer(info: &SpoInfo) -> String {
    format!(
        "{} ({})",
        pool_short(&info.pool_id, id_short(info.identifier)),
        info.bifrost_url
    )
}

/// The members of `peers` that are NOT in `answered`, rendered per
/// [`describe_peer`]; `none` when every one of them answered (spec [HL-11],
/// [PR-10a]).
///
/// Resolved from the SESSION's own `peers`, never from a process-wide table
/// keyed by identifier ([LG-4a]). A signing round can run under a previous
/// epoch's persisted ceremony while the current roster has one more pool, and
/// indices follow the lexicographic order of bifrost keys — so one added pool
/// shifts every index above it, and a table refreshed at the newer read would
/// put the wrong pool id next to the wrong URL on exactly the line an operator
/// is acting on.
pub fn describe_absent<T>(peers: &[&SpoInfo], answered: &BTreeMap<Identifier, T>) -> String {
    let listed: Vec<String> = peers
        .iter()
        .filter(|p| !answered.contains_key(&p.identifier))
        .map(|p| describe_peer(p))
        .collect();
    if listed.is_empty() {
        return "none".to_string();
    }
    cap_list(listed, PEER_LIST_CAP)
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
    /// identifier -> (peer as [`describe_peer`] rendered it, why it failed).
    peers: std::collections::BTreeMap<Identifier, (String, String)>,
}

impl Unreachable {
    /// Record a failing fetch. Returns `true` the FIRST time this peer fails in
    /// this round, which is when to log: at a 10 ms poll interval against a
    /// 30-minute window, logging every failure is tens of thousands of identical
    /// lines.
    ///
    /// Takes the peer's [`SpoInfo`] and renders it HERE (spec [HL-10]), because
    /// [`Self::erroring`] is called at the round's close with no roster in hand —
    /// and resolving a label from anywhere but the session's own peer list is the
    /// mismatch [`describe_absent`] exists to avoid.
    pub fn record(&mut self, info: &SpoInfo, why: impl std::fmt::Display) -> bool {
        self.peers
            .insert(info.identifier, (describe_peer(info), why.to_string()))
            .is_none()
    }

    /// Note that this peer answered — with a payload OR with a clean "nothing
    /// published yet". Both mean it is reachable.
    pub fn answered(&mut self, id: Identifier) {
        self.peers.remove(&id);
    }

    /// The peers that are up and erroring, or `none` (spec [PR-10a]).
    ///
    /// Always says something, because the line it belongs to is read after a
    /// round has just failed: "none" is the answer that sends an operator to look
    /// at the silent peers instead, and an omitted clause is one they have to
    /// guess about. Already in identifier order: it is a `BTreeMap`, and sorting
    /// the rendered strings instead would put "10" before "2".
    #[must_use]
    pub fn erroring(&self) -> String {
        if self.peers.is_empty() {
            return "none".to_string();
        }
        cap_list(
            self.peers
                .values()
                .map(|(peer, why)| format!("{peer} — {why}"))
                .collect(),
            PEER_LIST_CAP,
        )
    }

    /// A trailing clause for a round's closing line, EMPTY when every peer was
    /// reachable — for the lines that already read as complete sentences without
    /// it.
    #[must_use]
    pub fn note(&self) -> String {
        if self.peers.is_empty() {
            return String::new();
        }
        format!(" Up but erroring: {}.", self.erroring())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::*;

    fn ident(n: u16) -> Identifier {
        Identifier::try_from(n).unwrap()
    }

    /// The shape a Blockfrost submit rejection actually has — three lines, with
    /// the ledger's reason on the last one. All of it has to end up on the ONE
    /// line of the event, because the reason is the whole point of relaying the
    /// failure.
    #[test]
    fn a_multi_line_chain_error_collapses_to_one_line() {
        let e = "Response error for URL https://cardano-preprod.blockfrost.io/api/v0/tx/submit: \
                 Status code: 400\nError: Bad Request\nMessage: transaction submit error \
                 ShelleyTxValidationError (ApplyTxError [UtxowFailure (UtxoFailure \
                 (ValueNotConservedUTxO))])";
        let collapsed = one_line(&e);
        assert!(!collapsed.contains('\n'), "{collapsed}");
        assert!(
            collapsed.contains("Message: transaction submit error"),
            "{collapsed}"
        );
        assert!(collapsed.contains("ValueNotConservedUTxO"), "{collapsed}");
        assert!(
            collapsed.ends_with("(ValueNotConservedUTxO))])"),
            "{collapsed}"
        );

        // Indented JSON, which is what the SDK produces from an error body it
        // could not parse: collapsed to single spaces, not carried through.
        assert_eq!(one_line(&"{\n    \"a\": 1\n}"), "{ \"a\": 1 }");
        // A single-line error is untouched.
        assert_eq!(one_line(&"plain failure"), "plain failure");
    }

    /// A tripwire on the event inventory, not a proof of pairing.
    ///
    /// The failure mode it exists for is someone adding an `epoch_event!` and
    /// stopping there, leaving the channel showing a bridge that only ever
    /// succeeds — a roster that stopped rotating then looks exactly like one that
    /// was not due to. It cannot verify that a given success event has a matching
    /// failure event, only that the totals are what the last person to think
    /// about it left behind, so if it fires the question to answer is which half
    /// of which pair changed. Update the numbers WITH that answer, not to make it
    /// pass.
    ///
    /// Counts every source file, so an event added in a module this test has
    /// never heard of still trips it.
    #[test]
    fn the_operator_event_inventory_is_what_we_last_agreed() {
        fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("source tree is readable") {
                let path = entry.expect("readable entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(std::fs::read_to_string(&path).expect("source is readable"));
                }
            }
        }
        let mut sources = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut sources,
        );
        // The success needle ends in a bang, so it cannot also match the _warn
        // spelling. Neither needle may appear literally anywhere in this file, or
        // the scan counts its own source.
        let count =
            |needle: &str| -> usize { sources.iter().map(|s| s.matches(needle).count()).sum() };
        // Assembled rather than written out, because this file is inside the tree
        // being scanned and a literal needle would count itself.
        // Both spellings: these are `#[macro_export]`, so a call site may write
        // the bare name. Assembled rather than written out, because this file is
        // inside the tree being scanned and a literal needle would count itself.
        let success = format!("epoch_{}!(", "event");
        let failure = format!("epoch_{}!(", "event_warn");

        // dkg: round1/round2/part3/complete. machine: TM confirmed, federation
        // handoff, registry, new treasury address, Update-Y posted, TM built,
        // TM posted.
        assert_eq!(
            count(&success),
            11,
            "the set of SUCCESS events changed — does each one still have a failure counterpart?"
        );
        // DKG aborted, fault ban failed, Update-Y failed, Update-Y did not take,
        // TM not signed, TM post failed.
        assert_eq!(
            count(&failure),
            6,
            "the set of FAILURE events changed — does each success event still have one?"
        );
    }

    /// The budget is per CALL, so an event interpolating two values can divide one
    /// line between them. `DKG ABORTED` does, and two default budgets plus its own
    /// text would overflow the relay's 1992-byte body.
    #[test]
    fn a_stated_budget_is_honoured_in_bytes_and_two_of_them_still_fit() {
        let note = "… [truncated; full error in this node's log]";
        for (budget, body) in [(300usize, "x"), (600, "は")] {
            let capped = one_line_within(&body.repeat(4_000), budget);
            assert!(capped.len() <= budget + note.len(), "{}", capped.len());
            assert!(capped.ends_with(note), "{capped}");
        }
        // What `DKG ABORTED` actually spends: two budgets, their truncation notes
        // and the fixed text, against what the relay will carry on one line.
        const RELAY_BODY_BUDGET: usize = 2000 - 8;
        assert!(
            300 + 600 + 2 * note.len() + 400 < RELAY_BODY_BUDGET,
            "the abort event no longer fits on one relayed line"
        );
    }

    /// An unparseable error body is pretty-printed JSON and runs to kilobytes.
    /// Collapsing it without a cap only moves the fragmentation downstream: the
    /// relay splits anything past ~2000 characters into pieces that carry no
    /// `[<pool label> epoch=E]`, which is what `one_line` exists to prevent.
    #[test]
    fn an_enormous_error_is_truncated_rather_than_left_for_the_relay_to_split() {
        let huge = format!("Message: {}", "x".repeat(5_000));
        let collapsed = one_line(&huge);
        assert!(collapsed.len() < 1_000, "{}", collapsed.len());
        assert!(collapsed.starts_with("Message: xxx"), "{collapsed}");
        assert!(collapsed.contains("[truncated;"), "{collapsed}");
        assert!(!collapsed.contains('\n'));

        // The cap is in BYTES and must not split a character. A body of
        // three-byte characters is a third of the length in chars, so a
        // char-counted cap would sail past the relay's byte budget.
        let multibyte = one_line(&"は".repeat(2_000));
        assert!(multibyte.len() < 1_000, "{}", multibyte.len());
        assert!(multibyte.starts_with("はは"), "{multibyte}");
        assert!(multibyte.contains("[truncated;"));
    }

    /// What the truncation note points to has to exist: an error `one_line` cuts
    /// is logged whole, tail included, and one it does not cut is not logged
    /// twice.
    #[test]
    fn an_error_cut_short_is_available_whole() {
        let ledger = format!(
            "Status code: 400\n  Message: {{ \"supplied\": {} }},\n  expected: MaryValue (Coin 7)",
            "x".repeat(2_000)
        );
        assert!(one_line(&ledger).contains("[truncated;"));
        let full = full_text_if_cut(&ledger).expect("a cut error has a full text");
        assert!(
            full.ends_with("expected: MaryValue (Coin 7)"),
            "the tail the one-line version dropped must be there: …{}",
            &full[full.len() - 60..]
        );
        assert!(
            !full.contains('\n') && !full.contains("[truncated;"),
            "{full}"
        );

        assert_eq!(full_text_if_cut(&"Status code: 502 Bad Gateway"), None);
    }

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
        assert!(line.starts_with("pool1"), "{line}");
        assert!(
            line.contains("(http://spo1.example:18501)"),
            "a named peer carries its pool label AND its URL, because the FROST \
             index alone moves when the roster gains a pool: {line}"
        );
        assert!(line.contains("(http://spo3.example:18503)"), "{line}");
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
        assert!(line.contains("spo#9 (not in roster)"), "{line}");
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
        let participants = vec![participant(1, 0x11), participant(2, 0x22)];
        let mut ctx = DkgContext {
            epoch: 1543,
            attempt: 0,
            threshold: 2,
            total_stake: 40_000_000,
            read: crate::cardano::dkg_roster::RosterRead::of(&participants, 2, true),
            participants,
            excluded: Vec::new(),
            schedule_anchor_ms: None,
            read_time_ms: 0,
            live_stake: false,
        };

        // A steady roster reads as one clause, no "NOT eligible" tail.
        let line = describe_registry(&ctx, PEER_LIST_CAP);
        assert!(line.starts_with("2 registered, all eligible:"), "{line}");
        assert!(line.contains("(http://spo1.example:18501)"), "{line}");
        assert!(line.contains(&pool_short(&[0x11; 28], 1)), "{line}");
        assert!(!line.contains("NOT eligible"), "{line}");

        // A pool that registered and is waiting for its stake: named, with the
        // reason, because "we see you, wait" is the whole point of the line.
        ctx.excluded.push(ExcludedSpo {
            pool_id: vec![0x33; 28],
            bifrost_id_pk: vec![0x33; 32],
            reason: ExclusionReason::NoStake,
        });
        let line = describe_registry(&ctx, PEER_LIST_CAP);
        assert!(line.starts_with("3 registered, 2 eligible:"), "{line}");
        assert!(line.contains("NOT eligible:"), "{line}");
        assert!(line.contains(&pool_short(&[0x33; 28], 0)), "{line}");
        assert!(
            line.contains("activates two epoch boundaries later"),
            "the reason has to be the actionable one, not just a label: {line}"
        );
    }

    /// [LG-22]. The boundary is the point: a list of exactly `cap` is whole, and
    /// one past it must say how many it hid rather than trail off.
    #[test]
    fn a_peer_list_stops_at_the_cap_and_counts_what_it_hid() {
        let names = |n: usize| (1..=n).map(|i| format!("p{i}")).collect::<Vec<_>>();
        assert_eq!(cap_list(names(0), 3), "");
        assert_eq!(cap_list(names(3), 3), "p1, p2, p3");
        assert_eq!(cap_list(names(4), 3), "p1, p2, p3 … and 1 more");
        assert_eq!(cap_list(names(100), 3), "p1, p2, p3 … and 97 more");
        // The comparison path asks for everything, and must get it.
        assert_eq!(cap_list(names(4), usize::MAX), "p1, p2, p3, p4");
    }

    /// [LG-22] through the callers that matter: a hundred-pool roster must not
    /// put a hundred names on one line.
    #[test]
    fn a_hundred_pool_roster_names_ten_of_them() {
        let roster: BTreeMap<Identifier, SpoInfo> = (1..=100u16)
            .map(|n| {
                let id = ident(n);
                (
                    id,
                    SpoInfo {
                        identifier: id,
                        pool_id: vec![u8::try_from(n % 256).unwrap(); 28],
                        bifrost_url: format!("http://spo{n}.example:18500"),
                        bifrost_id_pk: Vec::new(),
                    },
                )
            })
            .collect();
        let line = describe_selected(roster.keys(), &roster);
        assert_eq!(line.matches("http://").count(), PEER_LIST_CAP, "{line}");
        assert!(line.ends_with("… and 90 more"), "{line}");
    }

    /// [PR-7]. A round that has already closed must read `0s`, not underflow:
    /// the poll logs its window and then checks the deadline, so the two can
    /// straddle the close.
    #[test]
    fn a_round_window_reads_in_seconds_and_never_underflows() {
        let now = Instant::now();
        assert_eq!(remaining(now + Duration::from_secs(45), now), "45s");
        assert_eq!(remaining(now + Duration::from_secs(59), now), "59s");
        assert_eq!(remaining(now + Duration::from_secs(60), now), "1m0s");
        assert_eq!(remaining(now + Duration::from_secs(150), now), "2m30s");
        assert_eq!(remaining(now - Duration::from_secs(5), now), "0s");
    }

    /// [LG-11], [LG-11a]. The boundaries are the point: "in the past" and "under
    /// a minute" are where a countdown reads wrong, and a reader who sees
    /// `(in 0m)` learns something different from one who sees `(now)`.
    #[test]
    fn a_countdown_rounds_down_and_says_now_at_the_boundary() {
        let at = |secs: i64| countdown(secs * 1000, 0);
        assert_eq!(at(-1), "(now)");
        assert_eq!(at(0), "(now)");
        assert_eq!(at(59), "(in 0m)");
        assert_eq!(at(60), "(in 1m)");
        assert_eq!(at(9_000), "(in 2h30m)");
        assert_eq!(at(90_000), "(in 1d1h0m)");
        // The live grid: a 3-hour batch interval, read a second after the batch.
        assert_eq!(at(10_799), "(in 2h59m)");
    }

    /// [LG-10]: the wall-clock half of every progress line.
    #[test]
    fn a_time_is_rendered_as_utc_to_the_second() {
        assert_eq!(utc_hms(0), "00:00:00 UTC");
        // `date -u -d @1234567890`.
        assert_eq!(utc_hms(1_234_567_890_000), "23:31:30 UTC");
        // The live node's 09:00 batch: 2026-09-21T09:00:00Z.
        assert_eq!(utc_hms(1_789_981_200_000), "09:00:00 UTC");
        // Before the epoch, where a truncating remainder would go negative.
        assert_eq!(utc_hms(-1_000), "23:59:59 UTC");
    }

    /// [HL-6]: one second per slot, from the tip's own aligned time and slot.
    #[test]
    fn a_future_slot_is_dated_from_the_tip_pair() {
        // The live node: tip slot 134286880 at 05:55:14Z, batch B_2 at 134287200.
        let now_ms = 1_789_970_114_000;
        let at = slot_time_ms(now_ms, 134_286_880, 134_287_200);
        assert_eq!(at - now_ms, 320_000, "320 slots is 320 seconds");
        assert_eq!(countdown(at, now_ms), "(in 5m)");
        // A slot already past dates backwards rather than wrapping.
        assert!(slot_time_ms(now_ms, 134_286_880, 134_286_000) < now_ms);
    }

    /// [LG-14]: the rule that retires `entr(y|ies)` and `peg-in(s)`.
    #[test]
    fn a_count_reads_as_a_phrase_not_a_regex() {
        assert_eq!(plural(0, "entry", "entries"), "0 entries");
        assert_eq!(plural(1, "entry", "entries"), "1 entry");
        assert_eq!(plural(3, "peg-in", "peg-ins"), "3 peg-ins");
    }

    /// [HL-8], [LG-9]: ADA, grouped, at most two decimals, never lovelace.
    #[test]
    fn an_amount_reads_in_ada_with_the_digits_grouped() {
        assert_eq!(ada(0), "0 ADA");
        assert_eq!(ada(5_000_000), "5 ADA");
        assert_eq!(ada(2_500_000), "2.5 ADA");
        assert_eq!(ada(2_510_000), "2.51 ADA");
        assert_eq!(ada(1_234_567_000_000), "1,234,567 ADA");
        // Rounding must carry into the whole part, not print "2.100".
        assert_eq!(ada(2_999_500), "3 ADA");
        // A sub-cent dust amount rounds to zero rather than printing 7 digits.
        assert_eq!(ada(1), "0 ADA");
    }

    /// [RS-6]: the threshold line is the derivation, in words. The operator
    /// asked how "6 of 7" follows from the stake, and this is the answer they
    /// read — so the two percentages must straddle the security threshold.
    #[test]
    fn the_threshold_line_shows_why_t_is_what_it_is() {
        use crate::cardano::dkg_roster::{DkgContext, DkgParticipant, RosterRead};

        // Six small pools and one whale: the 6 smallest hold 27.9%, the 5
        // smallest 19.8%, so the rule lands on 6 of 7 — the live roster's shape.
        let stakes = [30_000u64, 40_000, 45_000, 60_000, 70_000, 100_000, 889_567];
        let participants: Vec<DkgParticipant> = stakes
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let n = u16::try_from(i + 1).expect("small roster");
                DkgParticipant {
                    index: n,
                    identifier: ident(n),
                    pool_id: vec![n as u8; 28],
                    bifrost_id_pk: vec![n as u8; 32],
                    bifrost_url: format!("http://spo{n}.example:1850{n}"),
                    active_stake: s * 1_000_000,
                }
            })
            .collect();
        let total: u64 = participants.iter().map(|p| p.active_stake).sum();
        let ctx = DkgContext {
            epoch: 1554,
            attempt: 0,
            threshold: 6,
            total_stake: total,
            read: RosterRead::of(&participants, 6, true),
            participants,
            excluded: Vec::new(),
            schedule_anchor_ms: None,
            read_time_ms: 0,
            live_stake: false,
        };

        let table = roster_table(&ctx, ident(3));
        assert!(
            table[0].starts_with("roster for bridge epoch 1554: 7 registered, 7 eligible"),
            "{}",
            table[0]
        );
        assert!(table[0].contains("1,234,567 ADA"), "{}", table[0]);

        // Ascending, with the running total, so the threshold can be read off it.
        assert!(table[1].contains("30,000 ADA"), "{}", table[1]);
        assert!(table[7].contains("889,567 ADA"), "{}", table[7]);
        assert!(
            table[3].ends_with("(this node)"),
            "the operator's own row is marked: {}",
            table[3]
        );
        assert!(
            table.iter().all(|l| !l.contains("cum")),
            "the running total is labelled 'so far': {table:?}"
        );

        let threshold = table.last().expect("a threshold line");
        assert!(threshold.starts_with("threshold 6 of 7:"), "{threshold}");
        assert!(
            threshold.contains("the 6 smallest stakes hold 27.9%"),
            "{threshold}"
        );
        assert!(
            threshold.contains("the 5 smallest hold 19.8%"),
            "{threshold}"
        );
        assert!(
            threshold.contains("not above the 20% security threshold"),
            "{threshold}"
        );
    }

    /// [RS-7]: when one pool holds nearly everything, a single signer already
    /// clears the security threshold and FROST's own minimum is what sets `t`.
    /// Saying so is the difference between a threshold an operator can check and
    /// one that looks arbitrary.
    #[test]
    fn a_clamped_threshold_says_the_frost_minimum_decided_it() {
        use crate::cardano::dkg_roster::{DkgContext, DkgParticipant, RosterRead};

        let stakes = [500_000u64, 500_000];
        let participants: Vec<DkgParticipant> = stakes
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let n = u16::try_from(i + 1).expect("small roster");
                DkgParticipant {
                    index: n,
                    identifier: ident(n),
                    pool_id: vec![n as u8; 28],
                    bifrost_id_pk: vec![n as u8; 32],
                    bifrost_url: format!("http://spo{n}.example:1850{n}"),
                    active_stake: s * 1_000_000,
                }
            })
            .collect();
        let total: u64 = participants.iter().map(|p| p.active_stake).sum();
        let ctx = DkgContext {
            epoch: 9,
            attempt: 0,
            threshold: 2,
            total_stake: total,
            read: RosterRead::of(&participants, 2, true),
            participants,
            excluded: Vec::new(),
            schedule_anchor_ms: None,
            read_time_ms: 0,
            live_stake: false,
        };

        let table = roster_table(&ctx, ident(1));
        let threshold = table.last().expect("a threshold line");
        assert!(
            threshold.contains("raised to the FROST minimum of 2"),
            "{threshold}"
        );
        assert!(
            threshold.contains(
                "the 1 smallest stakes already hold 50.0% of total, above the 20% \
                 security threshold"
            ) || threshold.contains("already hold 50.0% of total, above the 20% security"),
            "the clamped line says the rule was ALREADY satisfied: {threshold}"
        );
    }

    /// [LG-2]: 10 leading characters and 4 trailing ones, from a 56-character
    /// bech32 pool id. Both ends, because `pool1` is shared by every pool that
    /// exists — a prefix-only form would distinguish them by 5 characters.
    #[test]
    fn a_pool_label_keeps_both_ends_of_the_bech32_id() {
        let full = pool_label(&[0x11; 28]);
        assert_eq!(full.len(), 56, "{full}");
        let short = pool_short(&[0x11; 28], 4);
        assert_eq!(short.chars().count(), 15, "10 + ellipsis + 4: {short}");
        assert!(short.starts_with(&full[..10]), "{short} vs {full}");
        assert!(short.ends_with(&full[52..]), "{short} vs {full}");
        assert!(short.contains('…'), "{short}");

        // Two pools differing only in their LAST bytes stay distinguishable,
        // which a prefix-only label would not manage.
        let mut other = [0x11u8; 28];
        other[27] = 0x12;
        assert_ne!(pool_short(&other, 4), short);
    }

    /// [LG-3]: a federation member need not be a Cardano SPO, and a fixture
    /// predating WI-013 carries no pool id. Neither may render as an empty label
    /// beside a count that says someone is there.
    #[test]
    fn a_node_without_a_pool_id_falls_back_to_its_index() {
        assert_eq!(pool_short(&[], 4), "spo#4");
        assert_eq!(pool_short(&[0xab, 0xcd], 7), "spo#7");
    }

    /// [HL-11] / [PR-10]: the line an operator acts on after a round fails has
    /// to name WHO to go and check, by pool id and by the URL they will open.
    #[test]
    fn the_absent_peers_are_named_with_the_url_to_check() {
        let peers: Vec<SpoInfo> = (1u16..=3)
            .map(|n| SpoInfo {
                identifier: ident(n),
                pool_id: vec![n as u8; 28],
                bifrost_url: format!("http://spo{n}.example:1850{n}"),
                bifrost_id_pk: Vec::new(),
            })
            .collect();
        let refs: Vec<&SpoInfo> = peers.iter().collect();

        let mut answered: BTreeMap<Identifier, ()> = BTreeMap::new();
        answered.insert(ident(2), ());
        let line = describe_absent(&refs, &answered);
        assert!(line.contains(&pool_short(&[1u8; 28], 1)), "{line}");
        assert!(line.contains("http://spo1.example:18501"), "{line}");
        assert!(line.contains("http://spo3.example:18503"), "{line}");
        assert!(
            !line.contains("spo2.example"),
            "the peer that answered must not be listed: {line}"
        );

        // [PR-10a]: always says something. An omitted clause is one the reader
        // has to guess about, on a line read right after a failure.
        for id in [ident(1), ident(3)] {
            answered.insert(id, ());
        }
        assert_eq!(describe_absent(&refs, &answered), "none");
    }

    /// Silence and an error are one bucket for EXCLUSION (two nodes must close
    /// the same subset) and two different things for the operator: only the
    /// second is a node that is up and broken.
    #[test]
    fn peers_that_are_up_and_erroring_are_reported_apart_from_the_silent_ones() {
        let info = SpoInfo {
            identifier: ident(2),
            pool_id: vec![0x22; 28],
            bifrost_url: "http://spo2.example:18502".into(),
            bifrost_id_pk: Vec::new(),
        };
        let mut unreachable = Unreachable::default();
        assert_eq!(unreachable.erroring(), "none");

        assert!(unreachable.record(&info, "502 Bad Gateway"));
        assert!(
            !unreachable.record(&info, "502 Bad Gateway"),
            "a second failure in the same round must not log again"
        );
        let line = unreachable.erroring();
        assert!(line.contains(&pool_short(&[0x22; 28], 2)), "{line}");
        assert!(line.contains("http://spo2.example:18502"), "{line}");
        assert!(line.contains("502 Bad Gateway"), "{line}");

        // A clean 404 IS an answer: a peer that errors once and then serves 404s
        // has recovered, and naming it is the false positive that teaches
        // operators to skip the line.
        unreachable.answered(ident(2));
        assert_eq!(unreachable.erroring(), "none");
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
