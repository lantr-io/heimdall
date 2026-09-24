//! What a peer must agree with this node about before a ceremony (WI-067).
//!
//! ## Why a version is a protocol value here
//!
//! heimdall's version decides bytes every SPO must produce identically — the TM
//! batch weights and the byte budget they feed, the leader election and its
//! cascade, the canonical payload layouts, and the embedded blueprint from which
//! every policy id is derived. Two nodes on different minors can therefore
//! compute different rosters, different addresses, or different signed bytes,
//! and the failure is the one this codebase keeps meeting: no error anywhere,
//! just a ceremony that never converges and no log line naming the cause.
//!
//! ## The rule, and its limit
//!
//! **`major.minor` must match; `patch` is free.** heimdall is `0.x`, where semver
//! puts the breaking position at MINOR — so "0.1 and 0.2 differ, 0.1.3 and 0.1.9
//! agree" is both the correct reading and what is wanted.
//!
//! That is a *convention*, and it is only as good as the discipline that no
//! consensus constant moves in a patch release. So a second value travels beside
//! it: the digest of the embedded blueprint, which is an exact fact rather than a
//! promise — a differing blueprint means differing policy ids, i.e. a different
//! bridge, whatever the version says.
//!
//! **What is deliberately NOT here is a digest over "the protocol constants".**
//! It was considered and rejected: such a digest is only correct if the list of
//! constants is complete, and a hand-maintained list that must be complete is the
//! same class of defect it is meant to catch — it would fail silently, in the
//! direction of saying two incompatible nodes agree. The blueprint digest is
//! mechanical (it hashes a file), the version is a human promise, and neither
//! pretends to be the other.
//!
//! ## The one named constant, and why it is not that digest
//!
//! `SECURITY_THRESHOLD_PERCENT` travels as its own field. That is not a partial
//! version of the rejected digest: it claims nothing about completeness, it names
//! one value and compares it, and a mismatch says exactly which value differs.
//!
//! It earns the exception because of where it fails. The percentage decides the
//! FROST `t` each node derives from the same registry, and `t` is the degree of
//! the polynomial each node commits to in Round 1 — but the DKG namespace carries
//! the constant LABEL 51, not the derived `t`. So two nodes on different
//! percentages address the same namespace, exchange payloads, and produce
//! commitment vectors of different length that cannot combine: a ceremony that
//! runs to completion and yields nothing, with no error naming the cause. Every
//! other build difference either shows up in the blueprint or is caught by the
//! version. This one is invisible to both, and it is the value most likely to be
//! deliberately changed for a test deployment.
//!
//! ## The deployment's own values, and why they are here rather than in the payload
//!
//! [`NodeFacts`] carries values that are not build identity at all: the
//! deployment settings (`cardano.demo_virtual_epoch_slots`,
//! `cardano.demo_live_stake`, `stake_source`, `demo_exclude_unstaked`) and the
//! roster this node READ for the ceremony — its candidate-set digest and `t`,
//! before the gate narrowed anything. They live in this gate for three reasons
//! the DKG payload cannot match.
//!
//! **It is the only channel that survives a namespace split.** The DKG namespace
//! is `(epoch, threshold, attempt)`, so two nodes on different epoch schemes
//! publish into namespaces that cannot see each other: neither ever fetches
//! anything of the other's, and every detector built into a payload is dead
//! before it runs. `/health` is un-namespaced, which is precisely what makes it
//! able to name that failure.
//!
//! **It runs before anything is published, and it converges.** The gate is
//! `wait_for_roster_health`, and a peer it excludes is simply not in the
//! candidate set: `t` is re-derived over the survivors and `attempt` does not
//! move. A majority that agrees therefore completes the ceremony while the odd
//! node out is left alone — where a chain-view check fires only once payloads
//! are already exchanged and the attempt is spent.
//!
//! **It works for a peer that publishes no view at all**, which the chain-view
//! comparison counts as agreeing.
//!
//! The verdict carries a [`Mismatch`] kind, because the three causes want
//! different things from the operator. A version or blueprint mismatch is
//! PERMANENT for the epoch and one side must upgrade; a settings mismatch needs
//! the setting matched; a roster-read difference is two reads that saw different
//! chain state — a pool registering mid-epoch, or `live_stake` drift — and clears
//! once both re-derive, at the latest at the next epoch. A peer too old to report
//! a roster digest is compared on `t` alone, and a difference there is its own
//! kind, because that build advertises a narrowed `t` and upgrading it is the
//! fix. The exclusion itself is the same for all of them, but an operator must
//! never be told to upgrade when the answer is "your read of the registry
//! differs".

use serde::{Deserialize, Serialize};

/// This build's version — `major.minor.patch` from Cargo.
#[must_use]
pub fn own_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// First 16 hex chars of `blake2b_256` over the embedded CIP-57 blueprint of
/// the contracts release the bridge's registry runs.
///
/// Truncated because it is an equality check between peers, not a commitment
/// anybody signs: 64 bits is far past what a misconfiguration collides on, and a
/// short digest is one an operator can compare by eye in two log lines.
///
/// The release IN EFFECT, not the newest this binary carries: this heimdall
/// runs a bridge whose registry has not been revised exactly as the previous
/// release does, with the previous release's blueprint, and reports that
/// blueprint's digest — so a roster can upgrade one node at a time and keep
/// holding ceremonies. When the Config moves the registry, every node's report
/// moves with it at its next Config read.
#[must_use]
pub fn own_blueprint_digest() -> String {
    blueprint_digest(crate::cardano::blueprint::release_in_effect().embedded())
}

/// The stake percentage a threshold subset must exceed — this build's
/// [`crate::cardano::dkg_roster::SECURITY_THRESHOLD_PERCENT`].
#[must_use]
pub fn own_threshold_percent() -> u32 {
    u32::try_from(crate::cardano::dkg_roster::SECURITY_THRESHOLD_PERCENT).unwrap_or(u32::MAX)
}

fn blueprint_digest(blueprint: &str) -> String {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(blueprint.as_bytes());
    hex::encode(&hash.as_bytes()[..8])
}

/// What this DEPLOYMENT reports, as opposed to what its build is.
///
/// Everything here comes from the operator's configuration or from this node's
/// own roster read, so — unlike the version and the blueprint digest — two nodes
/// of the same build can differ on it. See the module doc for why these are
/// compared in the handshake rather than in the DKG payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeFacts {
    /// `cardano.demo_virtual_epoch_slots` — the length of this node's ceremony
    /// cycle, or `None` for real Cardano epochs.
    pub virtual_epoch_slots: Option<u64>,
    /// `cardano.demo_live_stake` — whether the roster is weighted by `live_stake`
    /// (test runs) or by the epoch snapshot.
    pub live_stake: Option<bool>,
    /// `cardano.stake_source` — which backend per-pool stake is read from.
    /// Two nodes on different backends weight an identical registry differently.
    pub stake_source: Option<&'static str>,
    /// `cardano.demo_exclude_unstaked` — whether a pool with unresolvable stake
    /// is dropped from the roster or makes the derivation fatal. A difference
    /// changes the candidate set itself.
    pub exclude_unstaked: Option<bool>,
    /// The ceremony epoch [`Self::threshold`] was derived for.
    ///
    /// Carried so a stale threshold is never compared against a live one. A node
    /// publishes its `t` once per ceremony entry and keeps serving it until the
    /// next; without this tag, a node that crosses an epoch boundary first would
    /// compare its NEW `t` against a peer's PREVIOUS epoch's `t` and exclude a
    /// peer that agrees with it — on a production bridge, with no test flag
    /// anywhere near it.
    pub epoch: Option<u64>,
    /// The FROST `t` this node derived from its roster read for [`Self::epoch`],
    /// BEFORE the handshake dropped any incompatible peer
    /// ([`crate::cardano::dkg_roster::RosterRead::threshold`]).
    ///
    /// Not necessarily the length its Round-1 commitment vector will have: when
    /// the gate narrows the candidate set, `t` is re-derived over the survivors
    /// and that value is kept local. What peers compare is whether two nodes read
    /// the same roster, and advertising the narrowed value made a node whose gate
    /// finished first look like a disagreement to every peer still polling — see
    /// `narrow_at_handshake` in the epoch machine. Still published beside
    /// [`Self::roster_digest`] because a build that predates the digest compares
    /// only this.
    ///
    /// Live state, not configuration: `None` until this node has read a roster,
    /// exactly as `dkg_epoch`/`dkg_attempt` are absent until it has published a
    /// Round 1. A peer that has not yet entered a ceremony is therefore a
    /// reporting gap, not a disagreement.
    pub threshold: Option<u16>,
    /// [`crate::cardano::dkg_roster::RosterRead::digest`] of the same read: the
    /// candidate set in ceremony order, and `t`. Two reads with an equal `t` over
    /// different candidates differ here, which `t` alone cannot show.
    pub roster_digest: Option<[u8; 8]>,
    /// [`crate::cardano::dkg_roster::RosterRead::n`] — the read's candidate count,
    /// so a digest mismatch can be described in words.
    pub roster_size: Option<u16>,
}

/// What `/health` reports about the software behind it, plus the deployment
/// values of [`NodeFacts`].
///
/// Every field is `Option` on the reading side because a peer running a build
/// that predates one reports it as absent — see [`Compatibility::of`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerBuild {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub blueprint_digest: Option<String>,
    /// The stake percentage a threshold subset must exceed. `None` from a build
    /// that predates this field — see [`Compatibility::of`] for why that is
    /// allowed rather than refused.
    #[serde(default)]
    pub threshold_percent: Option<u32>,
    /// [`NodeFacts::virtual_epoch_slots`]. Absent means real Cardano epochs, so
    /// a production node and a build predating the field report the same thing —
    /// which is correct: a build without virtual epochs runs on real ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_epoch_slots: Option<u64>,
    /// [`NodeFacts::live_stake`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_stake: Option<bool>,
    /// [`NodeFacts::stake_source`]. `String` on the wire because a peer may run a
    /// build that knows a backend this one does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stake_source: Option<String>,
    /// [`NodeFacts::exclude_unstaked`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_unstaked: Option<bool>,
    /// [`NodeFacts::epoch`] — which ceremony [`Self::threshold`] belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dkg_threshold_epoch: Option<u64>,
    /// [`NodeFacts::threshold`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u16>,
    /// [`NodeFacts::roster_digest`], as 16 hex chars. Absent from a build that
    /// predates it — such a peer is compared on [`Self::threshold`] alone, so a
    /// roster that is mid-upgrade still runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_digest: Option<String>,
    /// [`NodeFacts::roster_size`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_size: Option<u16>,
}

impl PeerBuild {
    /// This node's own answer: its build identity plus the deployment values it
    /// currently holds.
    #[must_use]
    pub fn own(facts: NodeFacts) -> Self {
        Self {
            version: Some(own_version().to_string()),
            blueprint_digest: Some(own_blueprint_digest()),
            threshold_percent: Some(own_threshold_percent()),
            virtual_epoch_slots: facts.virtual_epoch_slots,
            live_stake: facts.live_stake,
            stake_source: facts.stake_source.map(str::to_string),
            exclude_unstaked: facts.exclude_unstaked,
            dkg_threshold_epoch: facts.epoch,
            threshold: facts.threshold,
            roster_digest: facts.roster_digest.map(hex::encode),
            roster_size: facts.roster_size,
        }
    }
}

/// The verdict on one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    /// Same `major.minor` and same blueprint. Safe to run a ceremony with.
    Compatible,
    /// The peer reports no version at all — a build older than this check.
    ///
    /// ALLOWED, deliberately. Refusing here would make the very upgrade that
    /// introduces the check an outage: every node would reject every peer until
    /// the last one restarted. Revisit once no supported release omits it.
    Unknown,
    /// A definite mismatch, with both sides named so either log line is enough
    /// to diagnose it.
    Incompatible { kind: Mismatch, reason: String },
}

/// Which kind of disagreement excluded a peer — it decides what the operator
/// must do, so a summary over several peers must never collapse the kinds into
/// one sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mismatch {
    /// Version series, blueprint or security percentage — or a settings
    /// difference against a peer too old to report a version, which cannot set
    /// the value at all. One side must move to the other's release.
    Build,
    /// A consensus setting of the deployment: one side must match the other's
    /// configuration. Same build, so an upgrade would change nothing.
    Settings,
    /// The roster read for the same epoch differs — candidate set or `t` — while
    /// both nodes report its digest: two reads that saw different chain state.
    /// Nothing to upgrade or configure.
    Roster,
    /// Only the advertised `t` differs, against a peer too old to report a roster
    /// digest. Such a build advertises its `t` AFTER dropping incompatible peers,
    /// so the difference may be that peer having narrowed rather than a different
    /// read — which upgrading it removes.
    LegacyThreshold,
}

/// One clause per kind present, each with its count and its own instruction —
/// the three want opposite things from the operator: telling a node whose only
/// difference is a threshold read to upgrade sends it chasing a build problem it
/// does not have.
#[must_use]
pub fn exclusion_causes(kinds: impl IntoIterator<Item = Mismatch>) -> String {
    let mut counts = std::collections::BTreeMap::new();
    for kind in kinds {
        *counts.entry(kind).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .map(|(kind, n)| match kind {
            Mismatch::Build => format!(
                "{n} on an incompatible build — whichever side runs the other release must \
                 upgrade (the ⚠ EXCLUDING lines name both versions)"
            ),
            Mismatch::Settings => format!(
                "{n} with different consensus settings — match the setting the ⚠ EXCLUDING \
                 lines name; no upgrade is needed"
            ),
            Mismatch::Roster => format!(
                "{n} read a different roster for this epoch — NOT a build or settings problem \
                 and no upgrade is needed: the nodes read the registry or stake at different \
                 moments, as when a pool registers mid-epoch, and it clears once they re-derive, \
                 at the latest at the next epoch"
            ),
            Mismatch::LegacyThreshold => format!(
                "{n} advertise a different FROST threshold from an older build that reports no \
                 roster digest — upgrade those nodes: that build advertises its threshold after \
                 dropping peers, which reads as a disagreement even when the rosters agree. If \
                 it persists once they run this release, the reads really differ"
            ),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The reason of a DKG abort after the gate excluded peers and what is left
/// cannot run a ceremony. `candidates` counts this node too.
///
/// When EVERY peer was excluded it says so: the comparison is symmetric, so a
/// node that disagrees with all of its peers is the odd one out itself, and
/// that is the one fact its operator most needs.
#[must_use]
pub fn exclusion_summary(kinds: impl IntoIterator<Item = Mismatch>, candidates: usize) -> String {
    let kinds: Vec<Mismatch> = kinds.into_iter().collect();
    let excluded = kinds.len();
    let outlier = if excluded > 0 && excluded + 1 == candidates {
        " — every peer was excluded, so it is THIS node that differs from the roster; \
         compare its /health against any peer's"
    } else {
        ""
    };
    format!(
        "{excluded} of {candidates} candidates excluded at the pre-ceremony handshake and the \
         rest cannot run a ceremony{outlier}: {}",
        exclusion_causes(kinds)
    )
}

impl Compatibility {
    /// Compare a peer's reported build against this node's.
    #[must_use]
    pub fn of(peer: &PeerBuild, own: NodeFacts) -> Self {
        Self::between(peer, &PeerBuild::own(own))
    }

    /// Pure form, for tests: compare `peer` against `own`.
    ///
    /// ORDER MATTERS. The deployment values are compared FIRST, before the
    /// version is even looked at, because the version check can return
    /// `Unknown` — which is an admission. A peer running a build that predates
    /// these fields, or one whose `/health` body could not be parsed, arrives
    /// here as `PeerBuild::default()`; letting that short-circuit would make the
    /// epoch-scheme mismatch invisible against exactly the build most likely to
    /// cause it, and that mismatch is the one no other channel can ever see.
    #[must_use]
    pub fn between(peer: &PeerBuild, own: &PeerBuild) -> Self {
        // THE EPOCH SCHEME. Compared even when only one side reports it, unlike
        // the build fields below: absent means "real Cardano epochs", which is a
        // definite answer rather than a reporting gap — a build that does not
        // know about virtual epochs is running real ones. Two nodes on different
        // cycles derive different epoch NUMBERS, and the DKG namespace is
        // `(epoch, threshold, attempt)`, so they publish into namespaces that
        // never fetch each other. Nothing errors on either side; the ceremony
        // simply never has a second participant.
        // A peer too old to report a version cannot set these values at all, so a
        // difference against it is a build problem: "match the setting" would
        // send its operator looking for a key that build does not have.
        let settings = if peer.version.is_none() {
            Mismatch::Build
        } else {
            Mismatch::Settings
        };
        if peer.virtual_epoch_slots != own.virtual_epoch_slots {
            let describe = |v: Option<u64>| match v {
                Some(s) => format!("a {s}-slot virtual epoch (TEST RUN)"),
                None => "real Cardano epochs".to_string(),
            };
            return Self::Incompatible {
                kind: settings,
                reason: format!(
                    "the peer runs on {} and we run on {} — we would number epochs \
                     differently, publish into DKG namespaces that never fetch each other, \
                     and each wait for a ceremony the other cannot see. Set \
                     cardano.demo_virtual_epoch_slots identically on every node of the roster",
                    describe(peer.virtual_epoch_slots),
                    describe(own.virtual_epoch_slots),
                ),
            };
        }
        // THE ROSTER WEIGHTING, all three inputs to it. Same rule: absent is the
        // production answer, not a gap. Each gives two nodes a different `t` —
        // or, for `exclude_unstaked`, a different candidate set — from identical
        // chain state.
        if peer.live_stake.unwrap_or(false) != own.live_stake.unwrap_or(false) {
            let describe = |v: bool| {
                if v {
                    "live_stake (TEST RUN)"
                } else {
                    "the epoch snapshot"
                }
            };
            return Self::Incompatible {
                kind: settings,
                reason: format!(
                    "the peer weights the roster by {} and we by {} — the candidate set would \
                     AGREE while the derived thresholds differ, so nothing we exchange can \
                     aggregate. Set cardano.demo_live_stake identically on every node of the \
                     roster",
                    describe(peer.live_stake.unwrap_or(false)),
                    describe(own.live_stake.unwrap_or(false)),
                ),
            };
        }
        if let (Some(t), Some(o)) = (peer.stake_source.as_deref(), own.stake_source.as_deref())
            && t != o
        {
            return Self::Incompatible {
                kind: settings,
                reason: format!(
                    "the peer reads per-pool stake from {} and we from {o} — the same registry \
                     weighs differently on the two backends, so we derive different FROST \
                     thresholds. Set cardano.stake_source identically on every node of the \
                     roster",
                    shown(t)
                ),
            };
        }
        if peer.exclude_unstaked.unwrap_or(false) != own.exclude_unstaked.unwrap_or(false) {
            return Self::Incompatible {
                kind: settings,
                reason: format!(
                    "cardano.demo_exclude_unstaked is {} on the peer and {} here — a pool whose \
                     stake will not resolve is dropped from one node's candidate set and fatal \
                     on the other, so we would not even be running the same roster",
                    peer.exclude_unstaked.unwrap_or(false),
                    own.exclude_unstaked.unwrap_or(false),
                ),
            };
        }

        let Some(theirs) = peer.version.as_deref() else {
            return Self::Unknown;
        };
        let ours = own.version.as_deref().unwrap_or_default();
        if minor_series(theirs) != minor_series(ours) {
            return Self::Incompatible {
                kind: Mismatch::Build,
                reason: format!("version {} against our {ours}", shown(theirs)),
            };
        }
        // Only compared when BOTH report one: a peer new enough to send a
        // version but not a digest is not a bridge mismatch, it is a gap in what
        // it reports, and `Unknown` is reserved for the version.
        if let (Some(t), Some(o)) = (
            peer.blueprint_digest.as_deref(),
            own.blueprint_digest.as_deref(),
        ) && t != o
        {
            return Self::Incompatible {
                kind: Mismatch::Build,
                reason: format!(
                    "same version {}, but blueprint {} against our {o} — \
                     different contracts, so a different bridge",
                    shown(theirs),
                    shown(t)
                ),
            };
        }
        // Compared only when BOTH report one, for the same reason as the
        // blueprint: a peer that sends a version but not this is a reporting gap,
        // not a disagreement. A differing percentage IS a disagreement, and a
        // total one — the two nodes derive different thresholds from identical
        // chain state, so nothing they exchange can combine.
        if let (Some(t), Some(o)) = (peer.threshold_percent, own.threshold_percent)
            && t != o
        {
            return Self::Incompatible {
                kind: Mismatch::Build,
                reason: format!(
                    "same version {}, but the security threshold is {t}% against our {o}% \
                     — we would derive different FROST thresholds from the same registry, commit \
                     to polynomials of different degree, and produce no key at all",
                    shown(theirs)
                ),
            };
        }
        // THE ROSTER READ itself — the value all of the above exist to protect,
        // compared directly so a cause nobody anticipated is still caught.
        //
        // Compared only FOR THE SAME CEREMONY EPOCH. A node publishes its read at
        // each ceremony entry and goes on serving it until the next, so at an
        // epoch boundary the node that crosses first would otherwise compare this
        // epoch's read against a peer's previous one and exclude a peer that
        // agrees with it. Absent means "has not read a roster yet", which is not a
        // disagreement.
        let (Some(pe), Some(oe)) = (peer.dkg_threshold_epoch, own.dkg_threshold_epoch) else {
            return Self::Compatible;
        };
        if pe != oe {
            return Self::Compatible;
        }
        // A digest this build cannot read is a format difference, i.e. another
        // release — never "the same read, differently" — and it is peer-supplied
        // text, so only a bounded, escaped form of it reaches a log line.
        if let Some(pd) = peer.roster_digest.as_deref()
            && !is_roster_digest(pd)
        {
            return Self::Incompatible {
                kind: Mismatch::Build,
                reason: format!(
                    "the peer reports roster digest {} in a format this build does not read — \
                     it runs a different release",
                    shown(pd)
                ),
            };
        }
        // Both report a digest: compare the whole read. The candidate set is in
        // it, so two reads with an equal `t` over different pools are caught.
        if let (Some(pd), Some(od)) = (peer.roster_digest.as_deref(), own.roster_digest.as_deref())
        {
            if pd == od {
                return Self::Compatible;
            }
            let describe = |n: Option<u16>, t: Option<u16>, d: &str| {
                let n = n.map_or_else(|| "?".to_string(), |n| n.to_string());
                let t = t.map_or_else(|| "?".to_string(), |t| t.to_string());
                format!("{n} candidates with t={t} (roster {d})")
            };
            return Self::Incompatible {
                kind: Mismatch::Roster,
                reason: format!(
                    "for epoch {pe} the peer read {} and we read {} — different indices, \
                     endpoints, weights or thresholds, so the two ceremonies cannot combine. \
                     Every setting we compare agrees, so this is NOT a build problem and needs no \
                     upgrade: the two nodes read the registry or stake at different moments (a \
                     pool that registered or changed its URL mid-epoch, or live_stake drift), and \
                     it clears once both re-derive — at the latest at the next epoch",
                    describe(peer.roster_size, peer.threshold, pd),
                    describe(own.roster_size, own.threshold, od),
                ),
            };
        }
        // One side reports no digest — in production always the PEER, since every
        // read this build publishes carries one. Compare `t`, so a roster mid-upgrade
        // keeps running. What an older build advertises is its NARROWED `t`, so a
        // difference here may be that and not a different read; the kind says so,
        // and says to upgrade.
        if let (Some(t), Some(o)) = (peer.threshold, own.threshold)
            && t != o
        {
            let older = if peer.roster_digest.is_none() {
                "the peer reports no roster digest, so it runs an older build"
            } else {
                "this node reports no roster digest, so it runs an older build"
            };
            return Self::Incompatible {
                kind: Mismatch::LegacyThreshold,
                reason: format!(
                    "for epoch {pe} the peer advertises FROST threshold t={t} and we t={o}; \
                     {older} — one that advertises its threshold AFTER dropping incompatible \
                     peers, so this may be that node having narrowed rather than a different \
                     read. Upgrading it removes that case; if it persists afterwards, the two \
                     nodes read the registry or stake at different moments"
                ),
            };
        }
        Self::Compatible
    }

    #[must_use]
    pub fn is_incompatible(&self) -> bool {
        matches!(self, Self::Incompatible { .. })
    }
}

/// Whether `d` is a roster digest as this build publishes one: 16 lowercase hex.
fn is_roster_digest(d: &str) -> bool {
    d.len() == 16
        && d.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A peer-supplied string as it may appear in a log line or on `/health`:
/// escaped, so it cannot forge lines, and bounded, so it cannot fill them.
fn shown(s: &str) -> String {
    const MAX: usize = 40;
    let mut out: String = s.chars().take(MAX).flat_map(char::escape_debug).collect();
    if s.chars().count() > MAX {
        out.push('…');
    }
    format!("\"{out}\"")
}

/// `major.minor` of a semver string, as text.
///
/// Text rather than parsed numbers so an unparseable version compares unequal to
/// everything except an identical one — the safe direction. A build reporting
/// nonsense should be excluded, not silently treated as `0.0`.
fn minor_series(v: &str) -> &str {
    let mut parts = v.match_indices('.');
    match (parts.next(), parts.next()) {
        (Some(_), Some((second, _))) => &v[..second],
        // Fewer than two dots: no patch position to ignore, so the whole string
        // is the series.
        _ => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same build as [`build`], carrying this node's deployment values — so
    /// a comparison isolates the facts instead of tripping over the version.
    fn build_with(facts: NodeFacts) -> PeerBuild {
        PeerBuild {
            version: Some("0.1.0".into()),
            blueprint_digest: Some("aa".into()),
            threshold_percent: Some(51),
            ..PeerBuild::own(facts)
        }
    }

    fn build(v: &str, d: &str) -> PeerBuild {
        PeerBuild {
            version: Some(v.into()),
            blueprint_digest: Some(d.into()),
            threshold_percent: Some(51),
            ..PeerBuild::default()
        }
    }

    /// The rule the item asks for, on 0.x where MINOR is the breaking position.
    #[test]
    fn patch_is_free_and_minor_is_not() {
        assert_eq!(
            Compatibility::between(&build("0.1.3", "aa"), &build("0.1.9", "aa")),
            Compatibility::Compatible
        );
        assert!(
            Compatibility::between(&build("0.2.0", "aa"), &build("0.1.0", "aa")).is_incompatible()
        );
        assert!(
            Compatibility::between(&build("1.1.0", "aa"), &build("0.1.0", "aa")).is_incompatible()
        );
    }

    /// Both sides are named, so whichever node's log an operator reads first is
    /// enough to diagnose it. The excluded node runs the same comparison from its
    /// own side, so it learns why it was dropped rather than seeing silence.
    #[test]
    fn a_mismatch_names_both_versions() {
        let Compatibility::Incompatible { reason, .. } =
            Compatibility::between(&build("0.2.5", "aa"), &build("0.1.0", "aa"))
        else {
            panic!("expected a mismatch");
        };
        assert!(reason.contains("0.2.5"), "{reason}");
        assert!(reason.contains("0.1.0"), "{reason}");
    }

    /// The blueprint catches what the version convention cannot: a patch release
    /// that moved the contracts.
    #[test]
    fn the_same_version_over_a_different_blueprint_is_incompatible() {
        let v = Compatibility::between(&build("0.1.0", "aaaa"), &build("0.1.0", "bbbb"));
        assert!(v.is_incompatible(), "{v:?}");
        let Compatibility::Incompatible { reason, .. } = v else {
            unreachable!()
        };
        assert!(reason.contains("different bridge"), "{reason}");
    }

    /// A build whose security threshold differs is excluded, and the reason
    /// names both percentages — the failure it prevents is a ceremony that
    /// completes and yields nothing, which no log would otherwise explain.
    #[test]
    fn a_different_security_threshold_is_incompatible() {
        let mut peer = build("0.1.0", "aa");
        peer.threshold_percent = Some(20);
        let v = Compatibility::between(&peer, &build("0.1.0", "aa"));
        assert!(v.is_incompatible(), "{v:?}");
        let Compatibility::Incompatible { reason, .. } = v else {
            unreachable!()
        };
        assert!(reason.contains("20%"), "{reason}");
        assert!(reason.contains("51%"), "{reason}");
    }

    /// The epoch scheme is compared even when only ONE side reports it: absent
    /// means real Cardano epochs, which is a definite answer rather than a
    /// reporting gap. Getting this wrong in the permissive direction would make
    /// the mismatch invisible in exactly the deployment it matters for — an old
    /// node beside a virtual-epoch one.
    #[test]
    fn a_virtual_epoch_difference_is_incompatible_in_both_directions() {
        let mut peer = build("0.1.0", "aa");
        peer.virtual_epoch_slots = Some(86_400);
        let Compatibility::Incompatible { reason, .. } =
            Compatibility::between(&peer, &build_with(NodeFacts::default()))
        else {
            panic!("a virtual epoch against real epochs must be incompatible");
        };
        assert!(reason.contains("86400"), "{reason}");
        assert!(reason.contains("real Cardano epochs"), "{reason}");

        // …and the other way round, which is the same misconfiguration seen from
        // the other node.
        let mine = NodeFacts {
            virtual_epoch_slots: Some(86_400),
            ..NodeFacts::default()
        };
        let plain = build("0.1.0", "aa");
        assert!(Compatibility::between(&plain, &build_with(mine)).is_incompatible());

        // Two nodes on the SAME cycle agree.
        assert_eq!(
            Compatibility::between(&peer, &build_with(mine)),
            Compatibility::Compatible
        );
    }

    /// The stake weighting reads the same way: absent is "the epoch snapshot",
    /// which is what a build predating the field actually does.
    #[test]
    fn a_live_stake_difference_is_incompatible_even_against_an_older_build() {
        let mut peer = build("0.1.0", "aa");
        peer.live_stake = None;
        let mine = NodeFacts {
            live_stake: Some(true),
            ..NodeFacts::default()
        };
        let Compatibility::Incompatible { reason, .. } =
            Compatibility::between(&peer, &build_with(mine))
        else {
            panic!("live_stake against the epoch snapshot must be incompatible");
        };
        assert!(reason.contains("demo_live_stake"), "{reason}");
        assert!(reason.contains("candidate set would AGREE"), "{reason}");
    }

    /// The derived `t` is the opposite case: absent means "has not read a roster
    /// yet", so a peer still starting up must NOT be excluded for it.
    #[test]
    fn a_derived_threshold_is_compared_only_when_both_report_one() {
        let mut peer = build("0.1.0", "aa");
        peer.threshold = None;
        peer.dkg_threshold_epoch = None;
        let mine = NodeFacts {
            epoch: Some(7),
            threshold: Some(3),
            ..NodeFacts::default()
        };
        assert_eq!(
            Compatibility::between(&peer, &build_with(mine)),
            Compatibility::Compatible
        );

        peer.threshold = Some(2);
        peer.dkg_threshold_epoch = Some(7);
        let Compatibility::Incompatible { kind, reason } =
            Compatibility::between(&peer, &build_with(mine))
        else {
            panic!("two derived thresholds that differ cannot combine");
        };
        assert!(reason.contains("t=2"), "{reason}");
        assert!(reason.contains("t=3"), "{reason}");
        // Without a digest on the peer only `t` can be compared, and that is an
        // older build's signal — the "needs no upgrade" wording belongs to a
        // digest comparison (`an_equal_threshold_over_a_different_roster_is_caught`).
        assert_eq!(kind, Mismatch::LegacyThreshold, "{reason}");
    }

    /// A digest this build cannot read is another release, and the peer's text
    /// reaches the reason only escaped and bounded.
    #[test]
    fn a_malformed_roster_digest_is_a_build_mismatch_and_is_not_echoed_raw() {
        let hostile = PeerBuild {
            roster_digest: Some(format!("ZZ\nforged log line{}", "x".repeat(4_000))),
            ..read(1548, 5, 5, "unused")
        };
        let Compatibility::Incompatible { kind, reason } =
            Compatibility::between(&hostile, &read(1548, 5, 5, "1111111111111111"))
        else {
            panic!("a digest in an unknown format must not pass");
        };
        assert_eq!(kind, Mismatch::Build);
        assert!(!reason.contains('\n'), "{reason}");
        assert!(reason.len() < 300, "bounded: {} bytes", reason.len());
        let upper = PeerBuild {
            roster_digest: Some("1111111111111111".to_uppercase().replace('1', "A")),
            ..read(1548, 5, 5, "unused")
        };
        assert_eq!(
            kind_of(Compatibility::between(
                &upper,
                &read(1548, 5, 5, "1111111111111111")
            )),
            Mismatch::Build
        );
    }

    /// A `t` from a DIFFERENT ceremony epoch is not a disagreement, and treating
    /// it as one is a PRODUCTION fault with no test flag anywhere near it.
    ///
    /// A node publishes its `t` at each ceremony entry and serves it until the
    /// next. At a boundary where the roster's threshold moves — a fourth SPO
    /// registers, so `t` goes 2 to 3 — the node that crosses first would compare
    /// its new `t` against peers still serving the previous epoch's, and exclude
    /// the very nodes that are about to agree with it.
    #[test]
    fn a_threshold_from_another_epoch_is_not_compared() {
        let mut peer = build("0.1.0", "aa");
        peer.threshold = Some(2);
        peer.dkg_threshold_epoch = Some(41); // still on the previous epoch
        let mine = NodeFacts {
            epoch: Some(42),
            threshold: Some(3),
            ..NodeFacts::default()
        };
        assert_eq!(
            Compatibility::between(&peer, &build_with(mine)),
            Compatibility::Compatible,
            "a stale threshold must not exclude a peer that agrees with us"
        );
        // Once the peer crosses into the same epoch, a real difference IS caught.
        peer.dkg_threshold_epoch = Some(42);
        assert!(Compatibility::between(&peer, &build_with(mine)).is_incompatible());
    }

    /// The stake BACKEND and the unstaked-exclusion rule are compared too. The
    /// old chain-view detector named both by name; folding them into an
    /// undifferentiated `t` difference would tell an operator to wait for
    /// something that never resolves.
    #[test]
    fn the_other_two_weighting_inputs_are_compared_by_name() {
        let own = NodeFacts {
            stake_source: Some("blockfrost"),
            exclude_unstaked: Some(false),
            ..NodeFacts::default()
        };
        let mut peer = build_with(own);
        peer.stake_source = Some("yaci_store".into());
        let Compatibility::Incompatible { reason, .. } =
            Compatibility::between(&peer, &build_with(own))
        else {
            panic!("two stake backends cannot derive one threshold");
        };
        assert!(reason.contains("stake_source"), "{reason}");

        let mut peer = build_with(own);
        peer.exclude_unstaked = Some(true);
        let Compatibility::Incompatible { reason, .. } =
            Compatibility::between(&peer, &build_with(own))
        else {
            panic!("differing exclusion rules are different rosters");
        };
        assert!(reason.contains("demo_exclude_unstaked"), "{reason}");
    }

    /// The deployment values are compared BEFORE the version, so a peer that
    /// reports no version at all — an older build, or one whose `/health` body
    /// could not be parsed — is still caught on the epoch scheme.
    ///
    /// This is the case the whole channel exists for: that peer is exactly the
    /// one most likely to be on real epochs while this node is not, and
    /// `Unknown` is an ADMISSION.
    #[test]
    fn a_peer_reporting_no_version_is_still_checked_for_the_epoch_scheme() {
        let mine = NodeFacts {
            virtual_epoch_slots: Some(86_400),
            ..NodeFacts::default()
        };
        let v = Compatibility::between(&PeerBuild::default(), &build_with(mine));
        let Compatibility::Incompatible { reason, .. } = v else {
            panic!("an unknown build on real epochs must not be admitted: {v:?}");
        };
        assert!(reason.contains("86400"), "{reason}");
        // …and with the scheme agreeing, the missing version is `Unknown` again.
        let peer = PeerBuild {
            virtual_epoch_slots: Some(86_400),
            ..PeerBuild::default()
        };
        assert_eq!(
            Compatibility::between(&peer, &build_with(mine)),
            Compatibility::Unknown
        );
    }

    /// A peer that reports no threshold is a reporting gap, not a disagreement —
    /// same rule as the blueprint, so the upgrade introducing this is not itself
    /// an outage.
    #[test]
    fn a_missing_threshold_is_not_a_disagreement() {
        let mut peer = build("0.1.0", "aa");
        peer.threshold_percent = None;
        assert_eq!(
            Compatibility::between(&peer, &build("0.1.0", "aa")),
            Compatibility::Compatible
        );
    }

    /// This build reports the constant it actually derives thresholds from —
    /// the property that makes the comparison mean anything.
    #[test]
    fn the_reported_threshold_is_the_one_in_force() {
        assert_eq!(
            u128::from(own_threshold_percent()),
            crate::cardano::dkg_roster::SECURITY_THRESHOLD_PERCENT
        );
    }

    /// A build predating this check reports nothing and is ALLOWED — otherwise
    /// the upgrade introducing the check is itself the outage.
    #[test]
    fn a_peer_reporting_no_version_is_unknown_not_incompatible() {
        assert_eq!(
            Compatibility::of(&PeerBuild::default(), NodeFacts::default()),
            Compatibility::Unknown
        );
        assert!(!Compatibility::of(&PeerBuild::default(), NodeFacts::default()).is_incompatible());
    }

    /// A version but no digest is a reporting gap, not a bridge mismatch.
    #[test]
    fn a_version_without_a_digest_is_compatible_on_the_version_alone() {
        let peer = PeerBuild {
            version: Some("0.1.0".into()),
            ..PeerBuild::default()
        };
        assert_eq!(
            Compatibility::between(&peer, &build("0.1.7", "aa")),
            Compatibility::Compatible
        );
    }

    /// An unparseable version matches only itself — excluded rather than
    /// silently read as some default.
    #[test]
    fn an_unparseable_version_matches_only_itself() {
        assert_eq!(minor_series("weird"), "weird");
        assert_eq!(minor_series("0.1"), "0.1");
        assert_eq!(minor_series("0.1.2"), "0.1");
        assert_eq!(minor_series("0.1.2-rc.1"), "0.1");
        assert!(
            Compatibility::between(&build("weird", "aa"), &build("0.1.0", "aa")).is_incompatible()
        );
    }

    /// This node's own answer compares equal to itself — the property every
    /// healthy roster depends on.
    #[test]
    fn own_build_is_compatible_with_itself() {
        let facts = NodeFacts {
            virtual_epoch_slots: Some(86_400),
            live_stake: Some(true),
            threshold: Some(3),
            ..NodeFacts::default()
        };
        for f in [NodeFacts::default(), facts] {
            assert_eq!(
                Compatibility::of(&PeerBuild::own(f), f),
                Compatibility::Compatible
            );
        }
        assert_eq!(own_blueprint_digest().len(), 16);
    }

    /// The digest tracks the blueprint, which is the whole point of carrying it.
    #[test]
    fn the_digest_changes_with_the_blueprint() {
        assert_ne!(blueprint_digest("{}"), blueprint_digest("{ }"));
        assert_eq!(blueprint_digest("{}"), blueprint_digest("{}"));
    }

    fn kind_of(v: Compatibility) -> Mismatch {
        let Compatibility::Incompatible { kind, .. } = v else {
            panic!("expected a mismatch, got {v:?}");
        };
        kind
    }

    /// Each verdict carries the kind that decides what the operator does, so a
    /// summary over several peers can keep them apart.
    #[test]
    fn every_mismatch_carries_its_kind() {
        let base = build("0.1.0", "aa");
        assert_eq!(
            kind_of(Compatibility::between(&build("0.2.0", "aa"), &base)),
            Mismatch::Build
        );
        assert_eq!(
            kind_of(Compatibility::between(&build("0.1.0", "bb"), &base)),
            Mismatch::Build
        );
        let live = PeerBuild {
            live_stake: Some(true),
            ..base.clone()
        };
        assert_eq!(
            kind_of(Compatibility::between(&live, &base)),
            Mismatch::Settings
        );
        let settings = [
            PeerBuild {
                virtual_epoch_slots: Some(86_400),
                ..base.clone()
            },
            PeerBuild {
                stake_source: Some("koios".into()),
                ..base.clone()
            },
            PeerBuild {
                exclude_unstaked: Some(true),
                ..base.clone()
            },
        ];
        let own_source = PeerBuild {
            stake_source: Some("blockfrost".into()),
            ..base.clone()
        };
        for peer in settings {
            assert_eq!(
                kind_of(Compatibility::between(&peer, &own_source)),
                Mismatch::Settings,
                "{peer:?}"
            );
        }
        let percent = PeerBuild {
            threshold_percent: Some(33),
            ..base.clone()
        };
        assert_eq!(
            kind_of(Compatibility::between(&percent, &base)),
            Mismatch::Build
        );
        // A peer too old to report a version cannot set the value, so matching
        // the setting is not an option its operator has.
        let ancient = PeerBuild {
            virtual_epoch_slots: Some(86_400),
            ..PeerBuild::default()
        };
        assert_eq!(
            kind_of(Compatibility::between(&PeerBuild::default(), &ancient)),
            Mismatch::Build
        );
        let at = |t, digest: Option<&str>| PeerBuild {
            dkg_threshold_epoch: Some(1548),
            threshold: Some(t),
            roster_digest: digest.map(str::to_string),
            ..base.clone()
        };
        assert_eq!(
            kind_of(Compatibility::between(
                &at(2, Some("aaaaaaaaaaaaaaaa")),
                &at(5, Some("bbbbbbbbbbbbbbbb"))
            )),
            Mismatch::Roster
        );
        assert_eq!(
            kind_of(Compatibility::between(
                &at(2, None),
                &at(5, Some("bbbbbbbbbbbbbbbb"))
            )),
            Mismatch::LegacyThreshold
        );
    }

    fn read(epoch: u64, n: u16, t: u16, digest: &str) -> PeerBuild {
        PeerBuild {
            dkg_threshold_epoch: Some(epoch),
            roster_size: Some(n),
            threshold: Some(t),
            roster_digest: Some(digest.into()),
            ..build("0.1.0", "aa")
        }
    }

    /// Two reads with the SAME `t` over different candidates are a disagreement
    /// — the case `t` alone passed as compatible — and the reason names both
    /// reads in words.
    #[test]
    fn an_equal_threshold_over_a_different_roster_is_caught() {
        let v = Compatibility::between(
            &read(1548, 5, 3, "1111111111111111"),
            &read(1548, 4, 3, "2222222222222222"),
        );
        let Compatibility::Incompatible { kind, reason } = v else {
            panic!("different rosters must not pass: {v:?}");
        };
        assert_eq!(kind, Mismatch::Roster);
        assert!(reason.contains("5 candidates with t=3"), "{reason}");
        assert!(reason.contains("4 candidates with t=3"), "{reason}");
        assert!(reason.contains("NOT a build problem"), "{reason}");
    }

    /// The same read is compatible, and a read from another epoch is not
    /// compared at all — the boundary rule the threshold already had.
    #[test]
    fn the_roster_read_is_compared_only_within_one_epoch() {
        assert_eq!(
            Compatibility::between(
                &read(1548, 5, 5, "1111111111111111"),
                &read(1548, 5, 5, "1111111111111111")
            ),
            Compatibility::Compatible
        );
        assert_eq!(
            Compatibility::between(
                &read(1547, 4, 2, "2222222222222222"),
                &read(1548, 5, 5, "1111111111111111")
            ),
            Compatibility::Compatible
        );
    }

    /// A roster mid-upgrade keeps running. A peer from before the digest is
    /// compared on `t` alone — admitted when it agrees, and when it does not,
    /// reported as an older build to upgrade rather than as "nothing to do".
    #[test]
    fn a_peer_without_a_digest_is_compared_on_its_threshold() {
        let mine = read(1548, 5, 5, "1111111111111111");
        let legacy = |t| PeerBuild {
            roster_digest: None,
            roster_size: None,
            ..read(1548, 5, t, "unused")
        };
        assert_eq!(
            Compatibility::between(&legacy(5), &mine),
            Compatibility::Compatible
        );
        let Compatibility::Incompatible { kind, reason } =
            Compatibility::between(&legacy(4), &mine)
        else {
            panic!("a different t from an older build is still a mismatch");
        };
        assert_eq!(kind, Mismatch::LegacyThreshold);
        assert!(reason.contains("older build"), "{reason}");
        let s = exclusion_summary([kind], 3);
        assert!(s.contains("upgrade those nodes"), "{s}");
    }

    /// Both `/health` formats parse: an old body (no digest) reads as absent
    /// fields, and a new body carries the digest an old build simply ignores.
    #[test]
    fn both_health_formats_parse() {
        let old: PeerBuild = serde_json::from_str(
            r#"{"version":"0.1.0","blueprint_digest":"e8987f35bc2e577f","threshold_percent":20,
                "dkg_threshold_epoch":1548,"threshold":2,"status":"ok"}"#,
        )
        .expect("an old /health body parses");
        assert_eq!(old.threshold, Some(2));
        assert_eq!(old.roster_digest, None);

        let facts = NodeFacts {
            epoch: Some(1548),
            threshold: Some(5),
            roster_digest: Some([0xab; 8]),
            roster_size: Some(5),
            ..NodeFacts::default()
        };
        let body = serde_json::to_value(PeerBuild::own(facts)).unwrap();
        assert_eq!(body["roster_digest"], "abababababababab");
        assert_eq!(body["roster_size"], 5);
        assert_eq!(body["threshold"], 5, "still published for an older peer");
    }

    /// The reported abort: a node that registered mid-epoch derives a different
    /// `t` than the roster that already read the registry, excludes all four
    /// peers, and must not be told its build is at fault.
    #[test]
    fn a_threshold_only_abort_does_not_blame_the_build() {
        let s = exclusion_summary([Mismatch::Roster; 4], 5);
        assert!(s.starts_with("4 of 5 candidates excluded"), "{s}");
        assert!(s.contains("THIS node that differs"), "{s}");
        assert!(s.contains("read a different roster"), "{s}");
        assert!(s.contains("no upgrade is needed"), "{s}");
        assert!(!s.contains("incompatible build"), "{s}");
        assert!(!s.contains("must upgrade"), "{s}");
    }

    /// Mixed causes are each named with their own count and instruction, not
    /// collapsed into whichever came first.
    #[test]
    fn a_mixed_abort_names_every_kind_with_its_count() {
        let s = exclusion_summary(
            [
                Mismatch::Roster,
                Mismatch::Build,
                Mismatch::Roster,
                Mismatch::Settings,
            ],
            6,
        );
        assert!(s.starts_with("4 of 6 candidates excluded"), "{s}");
        assert!(
            !s.contains("THIS node"),
            "a peer survived, so this node is not the outlier: {s}"
        );
        assert!(s.contains("1 on an incompatible build"), "{s}");
        assert!(s.contains("1 with different consensus settings"), "{s}");
        assert!(s.contains("2 read a different roster"), "{s}");
    }
}
