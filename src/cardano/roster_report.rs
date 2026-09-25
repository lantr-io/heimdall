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
}

/// The whole report, as printed.
#[must_use]
pub fn render(r: &RosterReport<'_>) -> String {
    let cascade = match &r.next_tm {
        NextTm::Batch { index, spends, .. } => Cascade::elect(
            r.participants
                .iter()
                .map(|p| (p.identifier, p.pool_id.as_slice())),
            &spends.to_byte_array(),
            TmSequence::Tm(*index),
        ),
        NextTm::NoneLeft | NextTm::Unavailable(_) => None,
    };
    let index_of = |id| {
        r.participants
            .iter()
            .find(|p| p.identifier == id)
            .map_or(0, |p| p.index)
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
    let _ = writeln!(
        out,
        "epoch {}{bridge} · stake: {source} · threshold {} of {} ({}% security threshold)",
        r.epoch,
        r.threshold,
        r.participants.len(),
        r.threshold_percent
    );
    // spec [SR-3]
    let _ = writeln!(
        out,
        "total stake {} ADA · bans: {} active",
        ada(r.total_stake),
        r.active_bans
    );
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
            let chain = c
                .sequence()
                .map(|id| format!("#{}", index_of(id)))
                .collect::<Vec<_>>()
                .join(" → ");
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
        let position = match cascade.as_ref().and_then(|c| c.hops_before(p.identifier)) {
            Some(0) => "leader".to_string(),
            Some(n) => format!("hop {n} (+{} slots)", n.saturating_mul(r.leader_slot_t)),
            None => "-".to_string(),
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
        }
    }

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
