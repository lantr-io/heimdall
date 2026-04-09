//! DKG phase order -- Round1 -> Round2 -> Part3

use std::collections::BTreeMap;
use std::sync::Arc;

use frost_secp256k1_tr as frost;
use frost::Identifier;

use crate::epoch::log::{id_short, short_hex};
use crate::epoch::state::{
    DkgCollected, DkgRound, EpochConfig, EpochError, EpochPhase, EpochResult, GroupKeys, Roster,
};
use crate::epoch::traits::{Clock, PeerNetwork};
use crate::frost::participant;
use crate::http::payloads::{Dkg1Payload, Dkg2Payload};

/// Drive one DKG sub-round and produce the next phase.
///
/// TODO: misbehavior detection. `dkg_part2`/`dkg_part3` return errors
/// that identify the bad peer by `Identifier`, but currently we flatten
/// them into `EpochError::Frost(String)` and abort the whole epoch.
///
/// In the real world, we're supposed to slash the misbehaving SPO via a
/// FROST-signed membership exit, restart DKG with the reduced
/// candidate set, and submit a PLONK proof of misbehavior to
/// the Cardano slashing contract. 
pub async fn dkg_phase(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    round: DkgRound,
    roster: Roster,
    mut collected: DkgCollected,
) -> EpochResult<EpochPhase> {
    let me = config.identity.identifier;
    match round {
        DkgRound::Round1 => {
            crate::epoch_log!(
                me, epoch,
                "DKG round1: generating secret polynomial and commitments \
                 (n={}, t={})",
                roster.max_signers, roster.min_signers
            );
            
            // TODO: abstract away the RNG to allow deterministic testing
            let mut rng = rand::rngs::OsRng;
            let (secret, package) = participant::dkg_part1(
                me,
                roster.max_signers,
                roster.min_signers,
                &mut rng,
            )
            .map_err(|e| EpochError::Frost(format!("dkg_part1: {e}")))?;

            let pkg_bytes = package
                .serialize()
                .map_err(|e| EpochError::Frost(format!("round1 pkg serialize: {e}")))?;
            crate::epoch_log!(
                me, epoch,
                "  -> round1 package built ({} bytes): {}",
                pkg_bytes.len(),
                short_hex(&pkg_bytes, 16)
            );

            peers
                .publish_dkg_round1(Dkg1Payload {
                    epoch,
                    identifier: me,
                    package: package.clone(),
                })
                .await?;
            crate::epoch_log!(me, epoch, "  -> round1 package published to local server");

            collected.round1_mine = Some(secret);
            collected.round1_peers.insert(me, package);

            // Poll peers until we have everyone's round 1 package.
            let peer_infos = roster.peers_of(me);
            crate::epoch_log!(
                me, epoch,
                "  waiting for round1 packages from {} peer(s)...",
                peer_infos.len()
            );
            poll_dkg_round1(
                peers,
                clock,
                config,
                epoch,
                me,
                &peer_infos,
                &mut collected.round1_peers,
            )
            .await?;
            crate::epoch_log!(
                me, epoch,
                "  <- have all {} round1 packages, advancing to round2",
                collected.round1_peers.len()
            );

            Ok(EpochPhase::Dkg {
                epoch,
                round: DkgRound::Round2,
                roster,
                collected,
            })
        }

        DkgRound::Round2 => {
            crate::epoch_log!(
                me, epoch,
                "DKG round2: computing per-peer secret shares from round1 packages"
            );

            let secret = collected
                .round1_mine
                .take()
                .ok_or_else(|| EpochError::Transition("missing round1 secret".into()))?;

            // Pass all peers' round1 packages except our own
            let peer_round1: BTreeMap<_, _> = collected
                .round1_peers
                .iter()
                .filter(|(id, _)| **id != me)
                .map(|(id, pkg)| (*id, pkg.clone()))
                .collect();

            let (round2_secret, round2_packages) = participant::dkg_part2(secret, &peer_round1)
                .map_err(|e| EpochError::Frost(format!("dkg_part2: {e}")))?;
            crate::epoch_log!(
                me, epoch,
                "  -> built {} encrypted shares (one per peer)",
                round2_packages.len()
            );
            for peer_id in round2_packages.keys() {
                crate::epoch_log!(
                    me, epoch,
                    "     - share addressed to spo={}",
                    id_short(*peer_id)
                );
            }

            peers
                .publish_dkg_round2(Dkg2Payload {
                    epoch,
                    identifier: me,
                    packages: round2_packages,
                })
                .await?;
            crate::epoch_log!(me, epoch, "  -> round2 packages published");

            collected.round2_mine = Some(round2_secret);

            let peer_infos = roster.peers_of(me);
            crate::epoch_log!(
                me, epoch,
                "  waiting for round2 shares addressed to me from {} peer(s)...",
                peer_infos.len()
            );
            poll_dkg_round2(
                peers,
                clock,
                config,
                epoch,
                me,
                &peer_infos,
                &mut collected.round2_peers,
            )
            .await?;
            crate::epoch_log!(
                me, epoch,
                "  <- have all {} round2 shares, advancing to part3",
                collected.round2_peers.len()
            );

            Ok(EpochPhase::Dkg {
                epoch,
                round: DkgRound::Part3,
                roster,
                collected,
            })
        }

        DkgRound::Part3 => {
            crate::epoch_log!(
                me, epoch,
                "DKG part3: combining shares into final KeyPackage + group key"
            );

            let round2_secret = collected
                .round2_mine
                .as_ref()
                .ok_or_else(|| EpochError::Transition("missing round2 secret".into()))?;
            let peer_round1: BTreeMap<_, _> = collected
                .round1_peers
                .iter()
                .filter(|(id, _)| **id != me)
                .map(|(id, pkg)| (*id, pkg.clone()))
                .collect();

            let (key_package, public_key_package) =
                participant::dkg_part3(round2_secret, &peer_round1, &collected.round2_peers)
                    .map_err(|e| EpochError::Frost(format!("dkg_part3: {e}")))?;

            let vk_bytes = public_key_package
                .verifying_key()
                .serialize()
                .map_err(|e| EpochError::Frost(format!("verifying_key serialize: {e}")))?;
            crate::epoch_log!(
                me, epoch,
                "  -> group verifying key (Y_51) = {}",
                hex::encode(&vk_bytes)
            );
            crate::epoch_log!(
                me, epoch,
                "  -> my signing share is bound to spo={}, threshold {}",
                id_short(*key_package.identifier()),
                key_package.min_signers()
            );

            let group_keys = GroupKeys {
                verifying_key: *public_key_package.verifying_key(),
                public_key_package,
                key_package,
            };

            Ok(EpochPhase::PublishKeys {
                epoch,
                roster,
                group_keys,
            })
        }
    }
}

async fn poll_dkg_round1(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    me: Identifier,
    peer_infos: &[&crate::epoch::state::SpoInfo],
    out: &mut BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
) -> EpochResult<()> {
    let need = peer_infos.len() + out.len(); // we already inserted self
    let deadline = clock.deadline(config.dkg_round_timeout);
    while out.len() < need {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(payload) = peers.fetch_dkg_round1(epoch, peer).await? {
                crate::epoch_log!(
                    me, epoch,
                    "     received round1 package from spo={} ({}/{})",
                    id_short(payload.identifier),
                    out.len() + 1,
                    need
                );
                out.insert(payload.identifier, payload.package);
            }
        }
        if out.len() >= need {
            break;
        }
        if clock.now() >= deadline {
            return Err(EpochError::PollTimeout {
                got: out.len(),
                need,
            });
        }
        tokio::time::sleep(config.poll_interval).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::mocks::{MockPeerHub, MockPeerNetwork, SystemClock};
    use crate::epoch::state::{EpochConfig, SpoIdentity, SpoInfo};
    use std::time::Duration;

    fn make_roster(n: u16, threshold: u16) -> Roster {
        let mut participants = BTreeMap::new();
        for i in 1..=n {
            let id = Identifier::try_from(i).unwrap();
            participants.insert(
                id,
                SpoInfo {
                    identifier: id,
                    bifrost_url: String::new(),
                    bifrost_id_pk: vec![],
                },
            );
        }
        Roster {
            epoch: 0,
            min_signers: threshold,
            max_signers: n,
            participants,
        }
    }

    async fn drive_dkg(
        peers: Arc<dyn PeerNetwork>,
        clock: Arc<dyn Clock>,
        config: EpochConfig,
        roster: Roster,
    ) -> EpochResult<GroupKeys> {
        let mut phase = EpochPhase::Dkg {
            epoch: 0,
            round: DkgRound::Round1,
            roster,
            collected: DkgCollected::default(),
        };
        loop {
            phase = match phase {
                EpochPhase::Dkg { epoch, round, roster, collected } => {
                    dkg_phase(&peers, &clock, &config, epoch, round, roster, collected).await?
                }
                EpochPhase::PublishKeys { group_keys, .. } => return Ok(group_keys),
                other => panic!("unexpected phase: {}", other.name()),
            };
        }
    }

    #[tokio::test]
    async fn dkg_3_of_3_happy_path() {
        let hub = MockPeerHub::new();
        let roster = make_roster(3, 2);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let id = Identifier::try_from(i).unwrap();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock = clock.clone();
            let config = EpochConfig::demo_default(SpoIdentity { identifier: id, port: 0 });
            let roster = roster.clone();
            handles.push(tokio::spawn(async move {
                drive_dkg(peers, clock, config, roster).await
            }));
        }

        let mut group_keys = Vec::new();
        for h in handles {
            group_keys.push(h.await.unwrap().expect("dkg ok"));
        }

        // All SPOs derive the same verifying key.
        let vk0 = group_keys[0].verifying_key;
        for gk in &group_keys[1..] {
            assert_eq!(gk.verifying_key, vk0);
        }
    }

    #[tokio::test]
    async fn dkg_round1_poll_times_out() {
        let hub = MockPeerHub::new();
        let roster = make_roster(3, 2);
        let id = Identifier::try_from(1u16).unwrap();
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut config = EpochConfig::demo_default(SpoIdentity { identifier: id, port: 0 });
        config.dkg_round_timeout = Duration::from_millis(150);
        config.poll_interval = Duration::from_millis(20);

        // Only SPO 1 runs — peers never publish, so this must time out.
        let result = drive_dkg(peers, clock, config, roster).await;
        match result {
            Err(EpochError::PollTimeout { .. }) => {}
            other => panic!("expected PollTimeout, got {:?}", other.map(|_| "ok")),
        }
    }
}

async fn poll_dkg_round2(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    me: Identifier,
    peer_infos: &[&crate::epoch::state::SpoInfo],
    out: &mut BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
) -> EpochResult<()> {
    let need = peer_infos.len();
    let deadline = clock.deadline(config.dkg_round_timeout);
    while out.len() < need {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(payload) = peers.fetch_dkg_round2(epoch, peer, me).await? {
                // FIXME: `payload.packages` is plaintext — see Dkg2Payload.
                if let Some(pkg) = payload.packages.get(&me) {
                    crate::epoch_log!(
                        me, epoch,
                        "     received round2 share from spo={} ({}/{})",
                        id_short(payload.identifier),
                        out.len() + 1,
                        need
                    );
                    out.insert(payload.identifier, pkg.clone());
                }
            }
        }
        if out.len() >= need {
            break;
        }
        if clock.now() >= deadline {
            return Err(EpochError::PollTimeout {
                got: out.len(),
                need,
            });
        }
        tokio::time::sleep(config.poll_interval).await;
    }
    Ok(())
}
