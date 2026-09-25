//! The `show-roster` status report (spec `2026-09-25-show-roster-status-design`).
//!
//! Pure: `run_show_roster` gathers the roster, the probes and the next batch,
//! and this module only lays them out. Everything an operator reads off the
//! report is decided here, so it is what the tests pin.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bitcoin::Txid;
use bitcoin::hashes::Hash as _;

use crate::cardano::dkg_roster::DkgParticipant;
use crate::epoch::leader::{Cascade, TmSequence};
use crate::epoch::log::utc_hms;
use crate::epoch::traits::PeerHealth;
use crate::http::compat::PeerBuild;

/// One `/health` probe and how long it took.
#[derive(Debug, Clone)]
pub struct Probe {
    pub health: PeerHealth,
    pub latency_ms: u64,
}

/// The Treasury Movement the report elects a cascade for.
#[derive(Debug, Clone)]
pub enum NextTm {
    /// The next batch opportunity `B_index`, at `at_ms`, spending the treasury
    /// outpoint whose txid is `spends`.
    Batch {
        index: u64,
        at_ms: i64,
        spends: Txid,
    },
    /// The grid has no opportunity left this epoch.
    NoneLeft,
    /// The grid or the treasury head could not be read.
    Unavailable(String),
}

/// A registered pool that is not in the roster.
#[derive(Debug, Clone)]
pub struct Excluded {
    pub pool: String,
    pub reason: String,
}

/// The key the treasury is under NOW (spec [SR-17]).
///
/// Distinct from the roster the rest of the report derives, which is what the
/// NEXT ceremony would run over if it ran now. The two are the same set while
/// the registry holds still; once a pool leaves or is banned mid-epoch they are
/// not, and a report that shows only the second reads as if this epoch's key
/// had already changed — "threshold 2 of 5" on an epoch whose key is 6-of-6.
#[derive(Debug, Clone)]
pub enum CurrentKey {
    /// No key to report: the `treasury_info` datum could not be read.
    Unread(String),
    /// The key is known, but no ceremony saved on this node made it, so its
    /// members are not known here. `why` when the state could not be looked at.
    NotHeld {
        key: String,
        source: KeySource,
        why: Option<String>,
    },
    /// The key is known, and a ceremony saved on this node made it.
    Held {
        key: String,
        source: KeySource,
        /// The bridge epoch whose ceremony made it.
        made_in: u64,
        threshold: u16,
        members: Vec<KeyMember>,
    },
}

/// Where the current key came from — which is also how sure the report is that
/// it is the key movements are signed with.
///
/// The signer is the key the treasury head is LOCKED under (`TreasuryUtxo::y_51`),
/// not the one `treasury_info` AUTHORIZES: the two differ while a handoff is in
/// flight, and it is the locked one that signs the handoff itself. Only the
/// running daemon knows the locked key (it reconstructs the head's script from
/// Cardano history on every treasury read), so the report asks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// The local daemon reports the head locked under this key, and the datum
    /// authorizes the same one.
    Locked,
    /// The local daemon reports the head still locked under this key, while the
    /// datum already authorizes `authorized`: a handoff is in flight.
    HandoffInFlight { authorized: String },
    /// The local daemon did not answer (`why`), so this is the datum's key — the
    /// locked one too, except while a handoff is in flight.
    AuthorizedOnly { why: String },
}

/// One member of the current key.
#[derive(Debug, Clone)]
pub struct KeyMember {
    /// Its FROST index IN THE KEY — the one the cascade and every signing
    /// session of this epoch use, whatever index the registry would give it now.
    pub identifier: frost_secp256k1_tr::Identifier,
    pub pool_id: Vec<u8>,
    pub bifrost_id_pk: Vec<u8>,
    pub bifrost_url: String,
    pub standing: Standing,
    /// Its `/health` probe, so a member outside the next roster — the cascade
    /// leader, possibly — is not reported without a word on whether it is up.
    pub probe: Option<Probe>,
}

/// Where a member of the current key stands in the registry as it reads now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// In the roster the next ceremony would run over.
    NextRoster,
    /// Registered, but not eligible: the reason the roster derivation gives.
    NotEligible(String),
    /// Registered; whether it is eligible could not be derived (`why`).
    Registered(String),
    /// Its pool is registered again, under a different bifrost key — so this
    /// share's holder is not the pool's registered identity any more.
    RegisteredUnderNewKey,
    /// Not in the registry at all.
    NotRegistered,
}

#[derive(Debug, Clone)]
pub struct RosterReport<'a> {
    /// The Cardano epoch.
    pub epoch: u64,
    /// The ceremony epoch of a virtual-epoch deployment, `None` on real epochs.
    pub bridge_epoch: Option<u64>,
    pub live_stake: bool,
    pub threshold: u16,
    pub threshold_percent: u32,
    pub total_stake: u64,
    pub active_bans: usize,
    pub participants: &'a [DkgParticipant],
    pub next_tm: NextTm,
    pub leader_slot_t: u64,
    /// Keyed by SPO index. A missing entry renders as `down`.
    pub probes: &'a BTreeMap<u16, Probe>,
    /// This node's own build, the reference for the ✓/✗ marks.
    pub own: &'a PeerBuild,
    pub excluded: &'a [Excluded],
    /// The key in force now, reported before the next-ceremony projection.
    pub current: &'a CurrentKey,
}

/// The whole report, as printed.
#[must_use]
pub fn render(r: &RosterReport<'_>) -> String {
    // The next TM of THIS epoch is posted by the roster of the key it is
    // signed under, so the cascade is elected over that roster when it is
    // known (spec [SR-4b]) — over the registry's only when it is not.
    let key_members = match r.current {
        CurrentKey::Held { members, .. } => Some(members.as_slice()),
        CurrentKey::Unread(_) | CurrentKey::NotHeld { .. } => None,
    };
    let cascade = match &r.next_tm {
        NextTm::Batch { index, spends, .. } => {
            let roster: Vec<(frost_secp256k1_tr::Identifier, &[u8])> = match key_members {
                Some(members) => members
                    .iter()
                    .map(|m| (m.identifier, m.pool_id.as_slice()))
                    .collect(),
                None => r
                    .participants
                    .iter()
                    .map(|p| (p.identifier, p.pool_id.as_slice()))
                    .collect(),
            };
            Cascade::elect(roster, &spends.to_byte_array(), TmSequence::Tm(*index))
        }
        NextTm::NoneLeft | NextTm::Unavailable(_) => None,
    };
    // How a cascade position is named: by the key's own members when the
    // cascade is theirs (their registry index may be gone or different), by
    // registry index otherwise, as before.
    let name_of = |id| match key_members {
        Some(members) => members
            .iter()
            .find(|m| m.identifier == id)
            .map_or_else(String::new, |m| {
                crate::epoch::log::pool_short(&m.pool_id, crate::epoch::log::id_short(id))
            }),
        None => format!(
            "#{}",
            r.participants
                .iter()
                .find(|p| p.identifier == id)
                .map_or(0, |p| p.index)
        ),
    };

    let mut out = String::new();
    // spec [SR-1], [SR-2]
    let source = if r.live_stake {
        "live_stake (TEST RUN)"
    } else {
        "epoch snapshot"
    };
    // spec [SR-1a]
    let bridge = r
        .bridge_epoch
        .map_or_else(String::new, |e| format!(" (bridge epoch {e})"));
    let _ = writeln!(out, "epoch {}{bridge} · stake: {source}", r.epoch);
    // spec [SR-17]..[SR-19]
    render_current(&mut out, r.current, r.own);
    // spec [SR-4], [SR-4a]
    match (&r.next_tm, &cascade) {
        (
            NextTm::Batch {
                index,
                at_ms,
                spends,
            },
            Some(c),
        ) => {
            let chain = c.sequence().map(name_of).collect::<Vec<_>>().join(" → ");
            let _ = writeln!(
                out,
                "next TM: batch B_{index} at {}, spends {spends} · cascade {chain}",
                utc_hms(*at_ms)
            );
        }
        (NextTm::NoneLeft, _) => out.push_str("next TM: no batch left this epoch\n"),
        (NextTm::Unavailable(why), _) => {
            let _ = writeln!(out, "next TM: unavailable ({why})");
        }
        (NextTm::Batch { .. }, None) => out.push_str("next TM: empty roster\n"),
    }
    // spec [SR-1], [SR-3], [SR-20]: everything below is the projection.
    let _ = writeln!(
        out,
        "next ceremony, from the registry as it reads now: threshold {} of {} ({}% security \
         threshold)",
        r.threshold,
        r.participants.len(),
        r.threshold_percent
    );
    let _ = writeln!(
        out,
        "total stake {} ADA · bans: {} active",
        ada(r.total_stake),
        r.active_bans
    );

    // spec [SR-6], [SR-7]
    let mut sorted: Vec<&DkgParticipant> = r.participants.iter().collect();
    sorted.sort_by(|a, b| {
        b.active_stake
            .cmp(&a.active_stake)
            .then(a.index.cmp(&b.index))
    });
    for p in sorted {
        out.push('\n');
        // spec [SR-8], [SR-9]
        let pool = <[u8; 28]>::try_from(p.pool_id.as_slice()).map_or_else(
            |_| hex::encode(&p.pool_id),
            |id| super::hash::pool_id_bech32(&id),
        );
        let _ = writeln!(
            out,
            "#{:<3} {pool}  stake {} ADA ({})",
            p.index,
            ada(p.active_stake),
            share(p.active_stake, r.total_stake)
        );
        // spec [SR-10], [SR-11]
        let _ = writeln!(out, "    bifrost_id_pk: {}", hex::encode(&p.bifrost_id_pk));
        let _ = writeln!(out, "    bifrost_url:   {}", p.bifrost_url);
        let _ = writeln!(
            out,
            "    health:  {}",
            health(r.probes.get(&p.index), r.own)
        );
        // spec [SR-14a], [SR-14b]
        // The cascade is the key's when the key is known: find this pool in
        // it by bifrost key, since its index there need not be its index here.
        let in_cascade = match key_members {
            Some(members) => members
                .iter()
                .find(|m| m.bifrost_id_pk == p.bifrost_id_pk)
                .map(|m| m.identifier),
            None => Some(p.identifier),
        };
        let position = match (in_cascade, cascade.as_ref()) {
            (None, _) => "- (not in the current key)".to_string(),
            (Some(id), Some(c)) => match c.hops_before(id) {
                Some(0) => "leader".to_string(),
                Some(n) => format!("hop {n} (+{} slots)", n.saturating_mul(r.leader_slot_t)),
                None => "-".to_string(),
            },
            (Some(_), None) => "-".to_string(),
        };
        let _ = writeln!(out, "    cascade: {position}");
    }

    // spec [SR-15]
    if !r.excluded.is_empty() {
        out.push_str("\nexcluded:\n");
        for ex in r.excluded {
            let _ = writeln!(out, "    {}  {}", ex.pool, ex.reason);
        }
    }
    out
}

/// Where one member of the current key stands in the registry now (spec
/// [SR-18]).
///
/// By bifrost key first — the identity the key's share is bound to — and then
/// by pool, so a pool that re-registered under a new bifrost key is not called
/// gone. A pool excluded only for want of stake under `demo_exclude_unstaked`
/// gets the same label the excluded list gives it, not "banned".
#[must_use]
pub fn standing_of(
    member: &crate::epoch::state::SpoInfo,
    snapshot: &crate::cardano::roster::RegistrySnapshot,
    next: Result<&crate::cardano::dkg_roster::DkgContext, &str>,
    active_bans: &std::collections::BTreeSet<Vec<u8>>,
    exclude_unstaked: bool,
) -> Standing {
    let pk = &member.bifrost_id_pk;
    if !snapshot.spos.iter().any(|s| &s.bifrost_id_pk == pk) {
        let pool_registered =
            !member.pool_id.is_empty() && snapshot.spos.iter().any(|s| s.pool_id == member.pool_id);
        return if pool_registered {
            Standing::RegisteredUnderNewKey
        } else {
            Standing::NotRegistered
        };
    }
    match next {
        Err(why) => Standing::Registered(format!("eligibility not derived: {why}")),
        Ok(ctx) if ctx.own_participant(pk).is_some() => Standing::NextRoster,
        Ok(ctx) => Standing::NotEligible(
            ctx.excluded
                .iter()
                .find(|x| &x.bifrost_id_pk == pk)
                .map_or_else(
                    || "not in the eligible set".to_string(),
                    |x| {
                        if exclude_unstaked && !active_bans.contains(&x.pool_id) {
                            "no active stake (excluded via demo_exclude_unstaked)".to_string()
                        } else {
                            x.reason.to_string()
                        }
                    },
                ),
        ),
    }
}

/// The current-key section alone, for when the next ceremony's roster cannot be
/// derived and the rest of the report cannot be printed — which is when a
/// departure has thinned the registry, and exactly when this section matters.
#[must_use]
pub fn render_current_key(current: &CurrentKey, own: &PeerBuild) -> String {
    let mut out = String::new();
    render_current(&mut out, current, own);
    out
}

/// The current key and, when its ceremony is known, its members' standing and
/// what that means for its handoff (spec [SR-17]..[SR-19]).
fn render_current(out: &mut String, current: &CurrentKey, own: &PeerBuild) {
    let origin = |source: &KeySource| match source {
        KeySource::Locked => "the treasury is locked under it".to_string(),
        KeySource::HandoffInFlight { authorized } => format!(
            "the treasury is still locked under it; treasury_info already authorizes \
             {authorized}: a handoff is in flight"
        ),
        KeySource::AuthorizedOnly { why } => format!(
            "authorized on chain; the local daemon did not say which key the treasury is \
             locked under ({why}), which differs from this one only during a handoff"
        ),
    };
    match current {
        CurrentKey::Unread(why) => {
            let _ = writeln!(out, "current key: unknown — {why}");
        }
        CurrentKey::NotHeld { key, source, why } => {
            let _ = writeln!(out, "current key: {key} ({})", origin(source));
            let _ = writeln!(
                out,
                "    not made by a ceremony saved on this node{}, so its members are not known \
                 here",
                why.as_ref().map_or_else(String::new, |w| format!(" ({w})"))
            );
        }
        CurrentKey::Held {
            key,
            source,
            made_in,
            threshold,
            members,
        } => {
            let _ = writeln!(out, "current key: {key} ({})", origin(source));
            let _ = writeln!(
                out,
                "    made in bridge epoch {made_in}, threshold {threshold} of {}",
                members.len()
            );
            let name = |m: &KeyMember| {
                crate::epoch::log::describe_peer(&crate::epoch::state::SpoInfo {
                    identifier: m.identifier,
                    pool_id: m.pool_id.clone(),
                    bifrost_url: m.bifrost_url.clone(),
                    bifrost_id_pk: m.bifrost_id_pk.clone(),
                })
            };
            for m in members {
                let standing = match &m.standing {
                    Standing::NextRoster => "in the next roster".to_string(),
                    Standing::NotEligible(why) => format!("registered, NOT eligible: {why}"),
                    Standing::Registered(why) => format!("registered ({why})"),
                    Standing::RegisteredUnderNewKey => {
                        "its pool is registered again under ANOTHER bifrost key".to_string()
                    }
                    Standing::NotRegistered => "NO LONGER REGISTERED".to_string(),
                };
                let _ = writeln!(
                    out,
                    "    {}  {standing} · {}",
                    name(m),
                    health(m.probe.as_ref(), own)
                );
            }
            // [SR-19]: the handoff is signed from the NEXT epoch's roster
            // (`epoch::rotation`, WI-078), so members outside it cannot sign it.
            let staying = members
                .iter()
                .filter(|m| m.standing == Standing::NextRoster)
                .count();
            let unknown = members
                .iter()
                .any(|m| matches!(m.standing, Standing::Registered(_)));
            let need = usize::from(*threshold);
            if staying >= need {
                let _ = writeln!(
                    out,
                    "    handoff: signed from the next epoch's roster — {staying} of these {} are \
                     in it, threshold {threshold}",
                    members.len()
                );
            } else if unknown {
                let _ = writeln!(
                    out,
                    "    handoff: signed from the next epoch's roster, which could not be derived \
                     now — it needs {threshold} of these {} there",
                    members.len()
                );
            } else {
                let missing: Vec<String> = members
                    .iter()
                    .filter(|m| m.standing != Standing::NextRoster)
                    .map(name)
                    .collect();
                let short = need - staying;
                let _ = writeln!(
                    out,
                    "    handoff: signed from the next epoch's roster, so it needs {threshold} of \
                     these {} there, and only {staying} are. It cannot complete unless {short} \
                     more of {} {} back in the registry's eligible set before the next boundary",
                    members.len(),
                    missing.join(", "),
                    if short == 1 { "is" } else { "are" }
                );
            }
        }
    }
}

/// spec [SR-12a]..[SR-12e]
fn health(probe: Option<&Probe>, own: &PeerBuild) -> String {
    let Some(probe) = probe.filter(|p| p.health.reachable) else {
        return "down".to_string();
    };
    let b = &probe.health.build;
    let dkg = probe
        .health
        .published_dkg
        .map_or_else(|| "-".to_string(), |(e, a)| format!("{e}/{a}"));
    format!(
        "up {}ms · v{} · blueprint {} roster {} · dkg {dkg}",
        probe.latency_ms,
        b.version.as_deref().unwrap_or("?"),
        mark(b.blueprint_digest.as_ref(), own.blueprint_digest.as_ref()),
        mark(b.roster_digest.as_ref(), own.roster_digest.as_ref()),
    )
}

fn mark(peer: Option<&String>, own: Option<&String>) -> &'static str {
    match peer {
        None => "?",
        Some(v) if Some(v) == own => "✓",
        Some(_) => "✗",
    }
}

/// Lovelace as ADA with 2 decimals (rounded half up) and thousands separators.
fn ada(lovelace: u64) -> String {
    let cents = lovelace.saturating_add(5_000) / 10_000;
    let whole = (cents / 100).to_string();
    let mut grouped = String::new();
    for (i, c) in whole.chars().enumerate() {
        if i > 0 && (whole.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(c);
    }
    format!("{grouped}.{:02}", cents % 100)
}

/// `part / total` as a percentage with 2 decimals, rounded half up.
fn share(part: u64, total: u64) -> String {
    if total == 0 {
        return "-".to_string();
    }
    let bp = (u128::from(part) * 20_000 + u128::from(total)) / (2 * u128::from(total));
    format!("{}.{:02}%", bp / 100, bp % 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1_tr::Identifier;
    use std::str::FromStr;

    fn participant(index: u16, pool_byte: u8, stake: u64) -> DkgParticipant {
        DkgParticipant {
            index,
            identifier: Identifier::try_from(index).unwrap(),
            pool_id: vec![pool_byte; 28],
            bifrost_id_pk: vec![index as u8; 32],
            bifrost_url: format!("http://spo{index}.example:18500"),
            active_stake: stake,
        }
    }

    fn own() -> PeerBuild {
        PeerBuild {
            version: Some("0.9.3".into()),
            blueprint_digest: Some("bp1".into()),
            roster_digest: Some("rd1".into()),
            ..PeerBuild::default()
        }
    }

    fn up(build: PeerBuild, dkg: Option<(u64, u64)>, ms: u64) -> Probe {
        Probe {
            health: PeerHealth {
                reachable: true,
                build,
                published_dkg: dkg,
            },
            latency_ms: ms,
        }
    }

    const TXID: &str = "0067141ba104dff43ce620a5a7be6153ae5ba4e332ca8a1a4978a28edc7a7f27";

    fn report<'a>(
        participants: &'a [DkgParticipant],
        probes: &'a BTreeMap<u16, Probe>,
        own: &'a PeerBuild,
        next_tm: NextTm,
    ) -> RosterReport<'a> {
        RosterReport {
            epoch: 315,
            bridge_epoch: None,
            live_stake: false,
            threshold: 2,
            threshold_percent: 20,
            total_stake: participants.iter().map(|p| p.active_stake).sum(),
            active_bans: 0,
            participants,
            next_tm,
            leader_slot_t: 600,
            probes,
            own,
            excluded: &[],
            current: &UNREAD,
        }
    }

    /// The report before [SR-17]: no treasury_info to name the current key, so
    /// everything keyed off it falls back to the registry, as it always did.
    static UNREAD: CurrentKey = CurrentKey::Unread(String::new());

    fn batch() -> NextTm {
        NextTm::Batch {
            index: 3,
            at_ms: 9 * 3_600_000,
            spends: Txid::from_str(TXID).unwrap(),
        }
    }

    /// Index of the line that opens the block of SPO `#index`.
    fn block_start(out: &str, index: u16) -> usize {
        let tag = format!("#{index} ");
        out.lines()
            .position(|l| l.starts_with(&tag))
            .unwrap_or_else(|| panic!("no block for #{index} in:\n{out}"))
    }

    fn block(out: &str, index: u16) -> Vec<String> {
        let start = block_start(out, index);
        out.lines()
            .skip(start)
            .take_while(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn blocks_are_sorted_by_stake_descending_ties_by_index() {
        // spec [SR-6], [SR-7]
        let ps = [
            participant(1, 0x10, 500),
            participant(2, 0x20, 900),
            participant(3, 0x30, 500),
        ];
        let out = render(&report(&ps, &BTreeMap::new(), &own(), batch()));
        let (b1, b2, b3) = (
            block_start(&out, 1),
            block_start(&out, 2),
            block_start(&out, 3),
        );
        assert!(b2 < b1 && b1 < b3, "order must be #2, #1, #3:\n{out}");
    }

    #[test]
    fn stake_is_ada_with_two_decimals_and_share_is_rounded_percent() {
        // spec [SR-8], [SR-9]
        let ps = [
            participant(1, 0x10, 1_403_765_239_178),
            participant(2, 0x20, 943_796_717_295),
        ];
        let out = render(&report(&ps, &BTreeMap::new(), &own(), batch()));
        let first = &block(&out, 1)[0];
        assert!(first.contains("pool1"), "bech32 pool id: {first}");
        assert!(
            first.ends_with("stake 1,403,765.24 ADA (59.80%)"),
            "got: {first}"
        );
    }

    #[test]
    fn header_names_the_stake_source() {
        // spec [SR-1], [SR-2], [SR-3]
        let ps = [
            participant(1, 0x10, 1_000_000),
            participant(2, 0x20, 1_000_000),
        ];
        let (probes, own) = (BTreeMap::new(), own());
        let mut r = report(&ps, &probes, &own, batch());
        let snap = render(&r);
        assert!(
            snap.lines()
                .next()
                .unwrap()
                .contains("stake: epoch snapshot"),
            "{snap}"
        );
        assert!(
            snap.contains("threshold 2 of 2 (20% security threshold)"),
            "{snap}"
        );
        assert!(
            snap.contains("total stake 2.00 ADA · bans: 0 active"),
            "{snap}"
        );
        r.live_stake = true;
        let live = render(&r);
        assert!(
            live.lines()
                .next()
                .unwrap()
                .contains("stake: live_stake (TEST RUN)"),
            "{live}"
        );
    }

    #[test]
    fn header_names_the_bridge_epoch_of_a_virtual_epoch_deployment() {
        // spec [SR-1a]
        let ps = [participant(1, 0x10, 1), participant(2, 0x20, 1)];
        let (probes, own) = (BTreeMap::new(), own());
        let mut r = report(&ps, &probes, &own, batch());
        assert!(
            render(&r).starts_with("epoch 315 · stake:"),
            "{}",
            render(&r)
        );
        r.bridge_epoch = Some(1558);
        let out = render(&r);
        assert!(
            out.starts_with("epoch 315 (bridge epoch 1558) · stake:"),
            "{out}"
        );
    }

    #[test]
    fn a_reachable_peer_shows_latency_version_marks_and_last_dkg() {
        // spec [SR-12a], [SR-12c], [SR-12d], [SR-12e]
        let ps = [
            participant(1, 0x10, 3),
            participant(2, 0x20, 2),
            participant(3, 0x30, 1),
        ];
        let mut probes = BTreeMap::new();
        probes.insert(1, up(own(), Some((1557, 17)), 132));
        let differs = PeerBuild {
            blueprint_digest: Some("bp2".into()),
            roster_digest: Some("rd2".into()),
            ..own()
        };
        probes.insert(2, up(differs, None, 5));
        let old = PeerBuild {
            version: Some("0.8.0".into()),
            ..PeerBuild::default()
        };
        probes.insert(3, up(old, None, 40));
        let own = own();
        let out = render(&report(&ps, &probes, &own, batch()));

        let health = |i| {
            block(&out, i)
                .into_iter()
                .find(|l| l.trim_start().starts_with("health:"))
                .unwrap()
        };
        assert!(
            health(1).ends_with("health:  up 132ms · v0.9.3 · blueprint ✓ roster ✓ · dkg 1557/17"),
            "{}",
            health(1)
        );
        assert!(
            health(2).ends_with("blueprint ✗ roster ✗ · dkg -"),
            "{}",
            health(2)
        );
        assert!(
            health(3).ends_with("up 40ms · v0.8.0 · blueprint ? roster ? · dkg -"),
            "{}",
            health(3)
        );
    }

    #[test]
    fn an_unreachable_or_unprobed_peer_is_down_and_still_rendered() {
        // spec [SR-12b], [SR-13]
        let ps = [participant(1, 0x10, 2), participant(2, 0x20, 1)];
        let mut probes = BTreeMap::new();
        probes.insert(
            1,
            Probe {
                health: PeerHealth::unreachable(),
                latency_ms: 2000,
            },
        );
        let own = own();
        let out = render(&report(&ps, &probes, &own, batch()));
        for i in [1, 2] {
            let b = block(&out, i);
            assert!(
                b.iter().any(|l| l.ends_with("health:  down")),
                "#{i}: {b:?}"
            );
        }
    }

    #[test]
    fn cascade_marks_the_leader_and_counts_hops_in_slots() {
        // spec [SR-4], [SR-14], [SR-14a], [SR-14b]
        let ps: Vec<_> = (1..=4)
            .map(|i| participant(i, 0x10 * i as u8, 10))
            .collect();
        let (probes, own) = (BTreeMap::new(), own());
        let out = render(&report(&ps, &probes, &own, batch()));

        let txid = Txid::from_str(TXID).unwrap().to_byte_array();
        let cascade = Cascade::elect(
            ps.iter().map(|p| (p.identifier, p.pool_id.as_slice())),
            &txid,
            TmSequence::Tm(3),
        )
        .unwrap();
        let index_of = |id| ps.iter().find(|p| p.identifier == id).unwrap().index;
        let order: Vec<u16> = cascade.sequence().map(index_of).collect();

        let header = out.lines().nth(2).unwrap();
        let chain = order
            .iter()
            .map(|i| format!("#{i}"))
            .collect::<Vec<_>>()
            .join(" → ");
        assert_eq!(
            header,
            format!("next TM: batch B_3 at 09:00:00 UTC, spends {TXID} · cascade {chain}")
        );
        for (hop, idx) in order.iter().enumerate() {
            let want = if hop == 0 {
                "cascade: leader".to_string()
            } else {
                format!("cascade: hop {hop} (+{} slots)", hop * 600)
            };
            let b = block(&out, *idx);
            assert!(b.iter().any(|l| l.trim_start() == want), "#{idx}: {b:?}");
        }
    }

    /// A key member: its index in the KEY, its pool and bifrost key bytes.
    fn member(key_index: u16, byte: u8, standing: Standing) -> KeyMember {
        KeyMember {
            identifier: Identifier::try_from(key_index).unwrap(),
            pool_id: vec![byte; 28],
            bifrost_id_pk: vec![byte; 32],
            bifrost_url: format!("http://key{byte}.example:18500"),
            standing,
            probe: None,
        }
    }

    fn held(threshold: u16, members: Vec<KeyMember>) -> CurrentKey {
        CurrentKey::Held {
            key: "46f4e530".into(),
            source: KeySource::Locked,
            made_in: 1558,
            threshold,
            members,
        }
    }

    /// spec [SR-17], [SR-18], [SR-19], [SR-20]: the key in force comes first,
    /// each member placed against the registry now and probed, then what that
    /// means for the handoff — and only then the next ceremony's projection.
    #[test]
    fn the_current_key_comes_first_with_its_members_and_its_handoff() {
        let ps = [participant(1, 0x01, 10), participant(2, 0x02, 10)];
        let (probes, own) = (BTreeMap::new(), own());
        let current = held(
            4,
            vec![
                member(1, 0x01, Standing::NextRoster),
                member(2, 0x06, Standing::NextRoster),
                member(3, 0x07, Standing::NotRegistered),
                member(4, 0x08, Standing::NotEligible("banned".into())),
                member(5, 0x09, Standing::RegisteredUnderNewKey),
            ],
        );
        let mut r = report(&ps, &probes, &own, batch());
        r.current = &current;
        let out = render(&r);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("epoch 315 · stake:"), "{out}");
        assert_eq!(
            lines[1],
            "current key: 46f4e530 (the treasury is locked under it)"
        );
        assert_eq!(lines[2], "    made in bridge epoch 1558, threshold 4 of 5");
        assert!(
            lines[3].ends_with("(http://key1.example:18500)  in the next roster · down"),
            "{out}"
        );
        assert!(lines[5].contains("  NO LONGER REGISTERED · "), "{out}");
        assert!(
            lines[6].contains("  registered, NOT eligible: banned · "),
            "{out}"
        );
        assert!(
            lines[7].contains("  its pool is registered again under ANOTHER bifrost key · "),
            "{out}"
        );
        // Needs 4, has 2: TWO more of the three gone — not all three.
        assert!(
            lines[8].contains("needs 4 of these 5 there, and only 2 are")
                && lines[8].contains("unless 2 more of ")
                && lines[8].contains("key7.example")
                && lines[8].contains("key8.example")
                && lines[8].contains("key9.example")
                && lines[8]
                    .ends_with("are back in the registry's eligible set before the next boundary"),
            "{out}"
        );
        assert!(lines[9].starts_with("next TM: batch B_3"), "{out}");
        assert_eq!(
            lines[10],
            "next ceremony, from the registry as it reads now: threshold 2 of 2 (20% security \
             threshold)"
        );

        // One short: "1 more of … is back".
        let one_short = held(
            2,
            vec![
                member(1, 0x01, Standing::NextRoster),
                member(2, 0x07, Standing::NotRegistered),
                member(3, 0x08, Standing::NotRegistered),
            ],
        );
        r.current = &one_short;
        let out = render(&r);
        assert!(out.contains("unless 1 more of "), "{out}");
        assert!(
            out.contains(" is back in the registry's eligible set"),
            "{out}"
        );

        // Enough staying: the handoff line says so, and names nobody.
        let enough = held(
            1,
            vec![
                member(1, 0x01, Standing::NextRoster),
                member(2, 0x07, Standing::NotRegistered),
            ],
        );
        r.current = &enough;
        assert!(
            render(&r).contains(
                "handoff: signed from the next epoch's roster — 1 of these 2 are in it, \
                 threshold 1"
            ),
            "{}",
            render(&r)
        );

        // The next roster could not be derived: no verdict is invented.
        let unknown = held(
            2,
            vec![
                member(
                    1,
                    0x01,
                    Standing::Registered("eligibility not derived: x".into()),
                ),
                member(2, 0x07, Standing::NotRegistered),
            ],
        );
        r.current = &unknown;
        let out = render(&r);
        assert!(
            out.contains("registered (eligibility not derived: x)"),
            "{out}"
        );
        assert!(out.contains("which could not be derived now"), "{out}");
    }

    /// spec [SR-17]: which key is "current" says where it came from. The signer
    /// is the key the head is locked under, and a handoff in flight is named.
    #[test]
    fn the_current_key_says_where_it_came_from() {
        let mut out = String::new();
        let in_flight = CurrentKey::NotHeld {
            key: "old".into(),
            source: KeySource::HandoffInFlight {
                authorized: "new".into(),
            },
            why: None,
        };
        render_current(&mut out, &in_flight, &own());
        assert_eq!(
            out.lines().next().unwrap(),
            "current key: old (the treasury is still locked under it; treasury_info already \
             authorizes new: a handoff is in flight)"
        );

        let mut out = String::new();
        let fallback = CurrentKey::NotHeld {
            key: "k".into(),
            source: KeySource::AuthorizedOnly {
                why: "no answer at 127.0.0.1:18580".into(),
            },
            why: None,
        };
        render_current(&mut out, &fallback, &own());
        assert!(
            out.starts_with(
                "current key: k (authorized on chain; the local daemon did not say which key the \
                 treasury is locked under (no answer at 127.0.0.1:18580)"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "not made by a ceremony saved on this node, so its members are not \
                 known here"
            ),
            "{out}"
        );
    }

    /// spec [SR-4b], [SR-14c]: with the key known, this epoch's cascade is the
    /// key's roster's — named by pool, since a key member's registry index may
    /// be gone — and a pool the key does not hold has no place in it.
    #[test]
    fn with_the_key_known_the_cascade_is_the_keys() {
        // Next roster: pool 0x01 (also in the key, at key index 2) and 0x02 (not).
        let ps = [participant(1, 0x01, 10), participant(2, 0x02, 10)];
        let (probes, own) = (BTreeMap::new(), own());
        let members = vec![
            member(1, 0x09, Standing::NotRegistered),
            member(2, 0x01, Standing::NextRoster),
        ];
        let current = held(2, members.clone());
        // participant() gives 0x01 the bifrost key [1;32]; member() gives [byte;32].
        let mut r = report(&ps, &probes, &own, batch());
        r.current = &current;
        let out = render(&r);

        let txid = Txid::from_str(TXID).unwrap().to_byte_array();
        let cascade = Cascade::elect(
            members.iter().map(|m| (m.identifier, m.pool_id.as_slice())),
            &txid,
            TmSequence::Tm(3),
        )
        .unwrap();
        let chain: Vec<String> = cascade
            .sequence()
            .map(|id| {
                let m = members.iter().find(|m| m.identifier == id).unwrap();
                crate::epoch::log::pool_short(&m.pool_id, crate::epoch::log::id_short(id))
            })
            .collect();
        let tm = out.lines().find(|l| l.starts_with("next TM:")).unwrap();
        assert!(
            tm.ends_with(&format!("cascade {}", chain.join(" → "))),
            "{tm}"
        );

        let hops = cascade
            .hops_before(Identifier::try_from(2u16).unwrap())
            .unwrap();
        let want = if hops == 0 {
            "cascade: leader".to_string()
        } else {
            format!("cascade: hop {hops} (+{} slots)", hops * 600)
        };
        assert!(
            block(&out, 1).iter().any(|l| l.trim_start() == want),
            "{out}"
        );
        assert!(
            block(&out, 2)
                .iter()
                .any(|l| l.trim_start() == "cascade: - (not in the current key)"),
            "{out}"
        );
    }

    /// spec [SR-17]: a key that cannot be read is said to be so — and
    /// everything keyed off it falls back to the registry.
    #[test]
    fn a_current_key_not_known_here_is_said_so() {
        let ps = [participant(1, 0x01, 10), participant(2, 0x02, 10)];
        let (probes, own) = (BTreeMap::new(), own());
        let mut r = report(&ps, &probes, &own, batch());
        let unread = CurrentKey::Unread("no treasury_info".into());
        r.current = &unread;
        assert_eq!(
            render(&r).lines().nth(1).unwrap(),
            "current key: unknown — no treasury_info"
        );
        // The section also stands alone, for when the next roster cannot be derived.
        assert_eq!(
            render_current_key(&unread, &own),
            "current key: unknown — no treasury_info\n"
        );
    }

    /// spec [SR-18]: a member is found by its bifrost key, then by its pool, and
    /// a pool excluded only for want of stake is not called banned.
    #[test]
    fn standing_is_read_by_key_then_by_pool() {
        use crate::cardano::dkg_roster::derive_dkg_context;
        use crate::cardano::roster::{RegisteredSpo, RegistrySnapshot};
        use crate::cardano::treasury_info::TreasuryInfoDatum;
        use crate::cardano::treasury_spend::TreasuryStateUtxo;
        use crate::epoch::state::SpoInfo;

        let reg = |pool: u8, pk: u8| RegisteredSpo {
            pool_id: vec![pool; 28],
            bifrost_id_pk: vec![pk; 32],
            bifrost_url: format!("http://spo{pool}.example:18500").into_bytes(),
            tx_hash: format!("{pool:02x}").repeat(32),
            output_index: 0,
        };
        // Pool 1 eligible; pool 2 banned; pool 3 re-registered under key 0x33.
        let snapshot = RegistrySnapshot {
            spos: vec![reg(1, 1), reg(2, 2), reg(3, 0x33), reg(4, 4)],
            identity_root: [0u8; 32],
            treasury_state: TreasuryStateUtxo {
                tx_hash: "00".repeat(32),
                output_index: 0,
                lovelace: 2_000_000,
                asset_name_hex: "ab".into(),
                datum: TreasuryInfoDatum {
                    bifrost_identity_root: [0u8; 32],
                    current_spos_frost_key: vec![],
                },
            },
        };
        let stakes: BTreeMap<Vec<u8>, u64> =
            [(vec![1; 28], 10), (vec![3; 28], 10), (vec![4; 28], 10)]
                .into_iter()
                .collect();
        let bans: std::collections::BTreeSet<Vec<u8>> = [vec![2; 28]].into_iter().collect();
        let ctx = derive_dkg_context(&snapshot, &bans, &stakes, 0, 0).unwrap();
        let info = |pool: u8, pk: u8| SpoInfo {
            identifier: Identifier::try_from(1u16).unwrap(),
            pool_id: vec![pool; 28],
            bifrost_url: String::new(),
            bifrost_id_pk: vec![pk; 32],
        };
        let at = |pool, pk, exclude_unstaked| {
            standing_of(
                &info(pool, pk),
                &snapshot,
                Ok(&ctx),
                &bans,
                exclude_unstaked,
            )
        };

        assert_eq!(at(1, 1, false), Standing::NextRoster);
        assert_eq!(at(2, 2, false), Standing::NotEligible("banned".into()));
        assert_eq!(
            at(3, 3, false),
            Standing::RegisteredUnderNewKey,
            "pool kept, key moved"
        );
        assert_eq!(at(9, 9, false), Standing::NotRegistered);
        // Excluded through the ban SET but not an active ban: the demo's unstaked.
        let no_active_bans = std::collections::BTreeSet::new();
        assert_eq!(
            standing_of(&info(2, 2), &snapshot, Ok(&ctx), &no_active_bans, true),
            Standing::NotEligible("no active stake (excluded via demo_exclude_unstaked)".into())
        );
        // No next roster: registered, eligibility not derived — no guess.
        assert_eq!(
            standing_of(&info(1, 1), &snapshot, Err("too few"), &bans, false),
            Standing::Registered("eligibility not derived: too few".into())
        );
    }

    #[test]
    fn with_no_batch_left_the_header_says_so_and_blocks_have_no_position() {
        // spec [SR-4a]
        let ps = [participant(1, 0x10, 1), participant(2, 0x20, 1)];
        let (probes, own) = (BTreeMap::new(), own());
        let out = render(&report(&ps, &probes, &own, NextTm::NoneLeft));
        assert_eq!(
            out.lines().nth(2).unwrap(),
            "next TM: no batch left this epoch"
        );
        assert!(
            block(&out, 1)
                .iter()
                .any(|l| l.trim_start() == "cascade: -")
        );
    }

    #[test]
    fn excluded_pools_follow_the_blocks_with_their_reason() {
        // spec [SR-15]
        let ps = [participant(1, 0x10, 1), participant(2, 0x20, 1)];
        let (probes, own) = (BTreeMap::new(), own());
        let excluded = [Excluded {
            pool: "pool1xyz".into(),
            reason: "banned".into(),
        }];
        let mut r = report(&ps, &probes, &own, batch());
        r.excluded = &excluded;
        let out = render(&r);
        let tail: Vec<&str> = out.lines().rev().take(2).collect();
        assert_eq!(tail, ["    pool1xyz  banned", "excluded:"]);
    }
}
