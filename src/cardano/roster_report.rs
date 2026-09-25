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

/// The key the treasury is authorized under NOW (spec [SR-17]).
///
/// Distinct from the roster the rest of the report derives, which is what the
/// NEXT ceremony would run over if it ran now. The two are the same set while
/// the registry holds still; once a pool leaves or is banned mid-epoch they are
/// not, and a report that shows only the second reads as if this epoch's key
/// had already changed — "threshold 2 of 5" on an epoch whose key is 6-of-6.
#[derive(Debug, Clone)]
pub enum CurrentKey {
    /// The `treasury_info` datum could not be read, or this bridge has none.
    Unread(String),
    /// Authorized on chain, but no ceremony saved on this node made it, so its
    /// members are not known here. `why` when the state could not be looked at.
    NotHeld { key: String, why: Option<String> },
    /// Authorized on chain, and made by a ceremony saved on this node.
    Held {
        key: String,
        /// The bridge epoch whose ceremony made it.
        made_in: u64,
        threshold: u16,
        members: Vec<KeyMember>,
    },
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
}

/// Where a member of the current key stands in the registry as it reads now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// In the roster the next ceremony would run over.
    NextRoster,
    /// Registered, but not eligible: the reason the roster derivation gives.
    NotEligible(String),
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
    render_current(&mut out, r.current);
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

/// The current key and, when its ceremony is known, its members' standing and
/// what that means for its handoff (spec [SR-17]..[SR-19]).
fn render_current(out: &mut String, current: &CurrentKey) {
    match current {
        CurrentKey::Unread(why) => {
            let _ = writeln!(out, "current key: unknown — {why}");
        }
        CurrentKey::NotHeld { key, why } => {
            let _ = writeln!(
                out,
                "current key: {key} (authorized on chain) — not made by a ceremony saved on this \
                 node{}, so its members are not known here",
                why.as_ref().map_or_else(String::new, |w| format!(" ({w})"))
            );
        }
        CurrentKey::Held {
            key,
            made_in,
            threshold,
            members,
        } => {
            let _ = writeln!(
                out,
                "current key: {key} (authorized on chain) — made in bridge epoch {made_in}, \
                 threshold {threshold} of {}",
                members.len()
            );
            let name = |m: &KeyMember| {
                format!(
                    "{} ({})",
                    crate::epoch::log::pool_short(
                        &m.pool_id,
                        crate::epoch::log::id_short(m.identifier)
                    ),
                    m.bifrost_url
                )
            };
            for m in members {
                let standing = match &m.standing {
                    Standing::NextRoster => "in the next roster".to_string(),
                    Standing::NotEligible(why) => format!("registered, NOT eligible: {why}"),
                    Standing::NotRegistered => "NO LONGER REGISTERED".to_string(),
                };
                let _ = writeln!(out, "    {}  {standing}", name(m));
            }
            // [SR-19]: the handoff is signed from the NEXT epoch's roster
            // (`epoch::rotation`, WI-078), so members outside it cannot sign it.
            let staying = members
                .iter()
                .filter(|m| m.standing == Standing::NextRoster)
                .count();
            if staying >= usize::from(*threshold) {
                let _ = writeln!(
                    out,
                    "    handoff: signed from the next epoch's roster — {staying} of these {} are \
                     in it, threshold {threshold}",
                    members.len()
                );
            } else {
                let missing: Vec<String> = members
                    .iter()
                    .filter(|m| m.standing != Standing::NextRoster)
                    .map(name)
                    .collect();
                let _ = writeln!(
                    out,
                    "    handoff: signed from the next epoch's roster, so it needs {threshold} of \
                     these {} there, and only {staying} are. It cannot complete unless {} \
                     {} back in the registry's eligible set before the next boundary",
                    members.len(),
                    missing.join(", "),
                    if missing.len() == 1 { "is" } else { "are" }
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
        }
    }

    /// spec [SR-17], [SR-18], [SR-19], [SR-20]: the key in force comes first,
    /// each member placed against the registry now, then what that means for
    /// the handoff — and only then the next ceremony's projection, labelled so.
    #[test]
    fn the_current_key_comes_first_with_its_members_and_its_handoff() {
        let ps = [participant(1, 0x01, 10), participant(2, 0x02, 10)];
        let (probes, own) = (BTreeMap::new(), own());
        let current = CurrentKey::Held {
            key: "46f4e530".into(),
            made_in: 1558,
            threshold: 3,
            members: vec![
                member(1, 0x01, Standing::NextRoster),
                member(2, 0x07, Standing::NotRegistered),
                member(3, 0x08, Standing::NotEligible("banned".into())),
            ],
        };
        let mut r = report(&ps, &probes, &own, batch());
        r.current = &current;
        let out = render(&r);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("epoch 315 · stake:"), "{out}");
        assert_eq!(
            lines[1],
            "current key: 46f4e530 (authorized on chain) — made in bridge epoch 1558, threshold \
             3 of 3"
        );
        assert!(
            lines[2].ends_with("(http://key1.example:18500)  in the next roster"),
            "{out}"
        );
        assert!(lines[3].ends_with("  NO LONGER REGISTERED"), "{out}");
        assert!(
            lines[4].ends_with("  registered, NOT eligible: banned"),
            "{out}"
        );
        assert!(
            lines[5].contains("needs 3 of these 3 there, and only 1 are")
                && lines[5].contains("key7.example")
                && lines[5].contains("key8.example")
                && lines[5]
                    .ends_with("are back in the registry's eligible set before the next boundary"),
            "{out}"
        );
        assert!(lines[6].starts_with("next TM: batch B_3"), "{out}");
        assert_eq!(
            lines[7],
            "next ceremony, from the registry as it reads now: threshold 2 of 2 (20% security \
             threshold)"
        );

        // Enough members staying: the handoff line says so, and names nobody.
        let enough = CurrentKey::Held {
            key: "46f4e530".into(),
            made_in: 1558,
            threshold: 1,
            members: vec![
                member(1, 0x01, Standing::NextRoster),
                member(2, 0x07, Standing::NotRegistered),
            ],
        };
        r.current = &enough;
        let out = render(&r);
        assert!(
            out.contains(
                "handoff: signed from the next epoch's roster — 1 of these 2 are in it, \
                 threshold 1"
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
        let current = CurrentKey::Held {
            key: "k".into(),
            made_in: 1558,
            threshold: 2,
            members: members.clone(),
        };
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

    /// spec [SR-17]: a key that cannot be read, or whose ceremony is not saved
    /// here, is said to be so — and everything keyed off it falls back.
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
        let not_held = CurrentKey::NotHeld {
            key: "46f4e530".into(),
            why: None,
        };
        r.current = &not_held;
        assert_eq!(
            render(&r).lines().nth(1).unwrap(),
            "current key: 46f4e530 (authorized on chain) — not made by a ceremony saved on this \
             node, so its members are not known here"
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
