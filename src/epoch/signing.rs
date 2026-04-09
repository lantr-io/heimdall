//! Signing phase logic — Round1 (per-input commit) → Round2 (per-input
//! tweaked sign + aggregate).
//!
//! Each TM input runs an independent FROST session: sighashes differ
//! per input, and every Taproot input has its own merkle root that
//! must be folded into the signature via BIP-341 tweaking. The phase
//! therefore publishes one `Sign1Payload`/`Sign2Payload` per input and
//! polls peers with per-input keys.

use std::collections::BTreeMap;
use std::sync::Arc;

use frost_secp256k1_tr as frost;
use frost::Identifier;

use crate::epoch::log::id_short;
use crate::epoch::state::{
    CascadeLevel, EpochConfig, EpochError, EpochPhase, EpochResult, GroupKeys, Roster,
    SignCollected, SigningRound, TreasuryMovement,
};
use crate::epoch::traits::{Clock, PeerNetwork};
use crate::frost::participant;
use crate::http::payloads::{Sign1Payload, Sign2Payload};

/// Drive one sub-round of the signing phase for all TM inputs.
///
/// TODO: signing cascade is not implemented. Today `sign_phase` only
/// exercises `CascadeLevel::Quorum67`; on timeout it returns `PollTimeout`
/// and the state machine aborts. A real implementation should catch
/// `PollTimeout` from `poll_sign_round{1,2}` and transition to
/// `CascadeLevel::Quorum51`, rebuilding the signing session with the
/// lower threshold, and ultimately fall through to `Federation`
/// (script-path spend after `federation_csv_blocks`).
///
/// TODO: misbehavior detection. FROST errors here currently surface as
/// `EpochError::Frost(String)` with the identity lost. The identifiable
/// abort property means we can attribute a bad share to a specific
/// `Identifier`; the PLONK circuits in `src/circuits/` are supposed to
/// turn that into an on-chain slashing proof. None of that is wired up.
pub async fn sign_phase(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    roster: Roster,
    cascade: CascadeLevel,
    group_keys: GroupKeys,
    mut tm: TreasuryMovement,
    round: SigningRound,
    mut collected: SignCollected,
) -> EpochResult<EpochPhase> {
    let me = config.identity.identifier;
    let num_inputs = tm.num_inputs();

    match round {
        SigningRound::Round1 => {
            crate::epoch_log!(
                me, epoch,
                "Sign round1: generating nonce commitments for {} input(s)",
                num_inputs
            );
            let mut rng = rand::rngs::OsRng;

            // Generate and publish this SPO's nonce commitments for every input.
            for i in 0..num_inputs as u32 {
                let (nonces, commitments) =
                    participant::sign_round1(&group_keys.key_package, &mut rng);
                collected.nonces.insert(i, nonces);
                collected
                    .round1
                    .entry(i)
                    .or_default()
                    .insert(me, commitments);

                peers
                    .publish_sign_round1(Sign1Payload {
                        epoch,
                        identifier: me,
                        input_index: i,
                        commitments,
                    })
                    .await?;
                crate::epoch_log!(
                    me, epoch,
                    "  -> published commitments for input {i}"
                );
            }

            // Poll peers for round 1 commitments on every input.
            let peer_infos = roster.peers_of(me);
            for i in 0..num_inputs as u32 {
                crate::epoch_log!(
                    me, epoch,
                    "  waiting for round1 commitments on input {i} from {} peer(s)...",
                    peer_infos.len()
                );
                let map = collected.round1.entry(i).or_default();
                poll_sign_round1(peers, clock, config, epoch, me, i, &peer_infos, map).await?;
            }
            crate::epoch_log!(me, epoch, "  <- have all round1 commitments, advancing to round2");

            Ok(EpochPhase::Sign {
                epoch,
                roster,
                cascade,
                group_keys,
                tm,
                round: SigningRound::Round2,
                collected,
            })
        }

        SigningRound::Round2 => {
            crate::epoch_log!(
                me, epoch,
                "Sign round2: computing tweaked signature shares for {} input(s)",
                num_inputs
            );
            // For each input: build SigningPackage, compute this SPO's
            // tweaked share, publish, poll peers, then aggregate into a
            // final Schnorr signature written back to `tm.signatures`.
            for i in 0..num_inputs as u32 {
                let commitments = collected
                    .round1
                    .get(&(i))
                    .ok_or_else(|| {
                        EpochError::Transition(format!("missing round1 commitments for input {i}"))
                    })?
                    .clone();
                let nonces = collected
                    .nonces
                    .get(&i)
                    .ok_or_else(|| EpochError::Transition(format!("missing nonces for input {i}")))?;

                let sighash = tm.sighashes[i as usize];
                let signing_package = frost::SigningPackage::new(commitments, &sighash);
                let merkle = tm.merkle_root_bytes(i as usize);
                let merkle_ref = merkle.as_deref();
                crate::epoch_log!(
                    me, epoch,
                    "  input {i}: sighash={} merkle_root={}",
                    hex::encode(sighash),
                    merkle_ref
                        .map(hex::encode)
                        .unwrap_or_else(|| "<none>".to_string())
                );

                // Compute our share.
                let share = participant::sign_round2_with_tweak(
                    &signing_package,
                    nonces,
                    &group_keys.key_package,
                    merkle_ref,
                )
                .map_err(|e| EpochError::Frost(format!("sign_round2_with_tweak: {e}")))?;
                crate::epoch_log!(me, epoch, "    -> built tweaked signature share");

                collected.round2.entry(i).or_default().insert(me, share);

                peers
                    .publish_sign_round2(Sign2Payload {
                        epoch,
                        identifier: me,
                        input_index: i,
                        share,
                    })
                    .await?;
                crate::epoch_log!(me, epoch, "    -> published share for input {i}");

                // Poll peers.
                let peer_infos = roster.peers_of(me);
                crate::epoch_log!(
                    me, epoch,
                    "    waiting for round2 shares on input {i} from {} peer(s)...",
                    peer_infos.len()
                );
                let shares = collected.round2.entry(i).or_default();
                poll_sign_round2(peers, clock, config, epoch, me, i, &peer_infos, shares).await?;

                // Aggregate.
                let signature = participant::sign_aggregate_with_tweak(
                    &signing_package,
                    shares,
                    &group_keys.public_key_package,
                    merkle_ref,
                )
                .map_err(|e| EpochError::Frost(format!("aggregate_with_tweak: {e}")))?;
                let sig_bytes = signature
                    .serialize()
                    .map_err(|e| EpochError::Frost(format!("sig serialize: {e}")))?;
                crate::epoch_log!(
                    me, epoch,
                    "    <- aggregated input {i} signature: {}",
                    hex::encode(&sig_bytes)
                );

                tm.signatures[i as usize] = Some(signature);
            }

            Ok(EpochPhase::Submit {
                epoch,
                tm,
                leader_attempt: 0,
            })
        }
    }
}

// FIXME: `poll_sign_round1` (and round2) waits for commitments from
// *every* peer, not just a threshold. That means one missing SPO stalls
// the whole cycle until the timeout fires, instead of proceeding as
// soon as `min_signers` have responded. A real implementation should
// proceed once it has `roster.min_signers` commitments and record the
// absent peers so the cascade / misbehavior path can react.
async fn poll_sign_round1(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    me: Identifier,
    input_index: u32,
    peer_infos: &[&crate::epoch::state::SpoInfo],
    out: &mut BTreeMap<Identifier, frost::round1::SigningCommitments>,
) -> EpochResult<()> {
    let need = peer_infos.len() + out.len(); // self already present
    let deadline = clock.deadline(config.quorum67_timeout);
    while out.len() < need {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(payload) = peers.fetch_sign_round1(epoch, peer, input_index).await? {
                crate::epoch_log!(
                    me, epoch,
                    "     received round1 commitments for input {input_index} from spo={} ({}/{})",
                    id_short(payload.identifier),
                    out.len() + 1,
                    need
                );
                out.insert(payload.identifier, payload.commitments);
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

async fn poll_sign_round2(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    me: Identifier,
    input_index: u32,
    peer_infos: &[&crate::epoch::state::SpoInfo],
    out: &mut BTreeMap<Identifier, frost::round2::SignatureShare>,
) -> EpochResult<()> {
    let need = peer_infos.len() + out.len();
    let deadline = clock.deadline(config.quorum67_timeout);
    while out.len() < need {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(payload) = peers.fetch_sign_round2(epoch, peer, input_index).await? {
                crate::epoch_log!(
                    me, epoch,
                    "     received round2 share for input {input_index} from spo={} ({}/{})",
                    id_short(payload.identifier),
                    out.len() + 1,
                    need
                );
                out.insert(payload.identifier, payload.share);
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
    use crate::bitcoin::taproot::treasury_spend_info;
    use crate::bitcoin::tm_builder::{
        build_tm, compute_sighashes, FeeParams, PegInInput, PegOutRequest, TreasuryInput,
    };
    use crate::epoch::dkg::dkg_phase;
    use crate::epoch::mocks::{MockPeerHub, MockPeerNetwork, SystemClock};
    use crate::epoch::state::{
        DkgCollected, DkgRound, EpochConfig, SignCollected, SpoIdentity, SpoInfo,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Secp256k1, UntweakedPublicKey};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};

    fn make_roster(n: u16, t: u16) -> Roster {
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
            min_signers: t,
            max_signers: n,
            participants,
        }
    }

    async fn run_dkg(
        peers: Arc<dyn PeerNetwork>,
        clock: Arc<dyn Clock>,
        config: EpochConfig,
        roster: Roster,
    ) -> GroupKeys {
        let mut phase = EpochPhase::Dkg {
            epoch: 0,
            round: DkgRound::Round1,
            roster,
            collected: DkgCollected::default(),
        };
        loop {
            phase = match phase {
                EpochPhase::Dkg {
                    epoch,
                    round,
                    roster,
                    collected,
                } => dkg_phase(&peers, &clock, &config, epoch, round, roster, collected)
                    .await
                    .unwrap(),
                EpochPhase::PublishKeys { group_keys, .. } => return group_keys,
                other => panic!("unexpected: {}", other.name()),
            };
        }
    }

    /// Convert a FROST verifying key to bitcoin's `UntweakedPublicKey`.
    fn frost_vk_to_xonly(vk: &frost::VerifyingKey) -> UntweakedPublicKey {
        let bytes = vk.serialize().unwrap();
        // 33-byte compressed: discard parity byte, take 32-byte x-coord.
        UntweakedPublicKey::from_slice(&bytes[1..33]).unwrap()
    }

    /// Drive 3 SPOs through DKG then sign_phase for a 2-input TM; every
    /// aggregated Schnorr signature must verify under the tweaked output
    /// key of its input.
    #[tokio::test]
    async fn sign_3_of_3_two_inputs_verifies_taproot() {
        let secp = Secp256k1::new();

        // DKG so all SPOs share one group key.
        let hub = MockPeerHub::new();
        let roster = make_roster(3, 2);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut dkg_handles = Vec::new();
        for i in 1..=3u16 {
            let id = Identifier::try_from(i).unwrap();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock = clock.clone();
            let config = EpochConfig::demo_default(SpoIdentity {
                identifier: id,
                port: 0,
            });
            let roster = roster.clone();
            dkg_handles.push(tokio::spawn(async move {
                run_dkg(peers, clock, config, roster).await
            }));
        }
        let mut group_keys_all: Vec<GroupKeys> = Vec::new();
        for h in dkg_handles {
            group_keys_all.push(h.await.unwrap());
        }
        let gk0 = &group_keys_all[0];

        // Build a 2-input TM where both inputs live under the group key's
        // internal Y_51. Y_67 and Y_fed are unrelated placeholder keys.
        let y_51 = frost_vk_to_xonly(&gk0.verifying_key);
        let y_67 = UntweakedPublicKey::from_slice(
            &bitcoin::secp256k1::SecretKey::from_slice(&[7u8; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0
                .serialize(),
        )
        .unwrap();
        let y_fed = UntweakedPublicKey::from_slice(
            &bitcoin::secp256k1::SecretKey::from_slice(&[9u8; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0
                .serialize(),
        )
        .unwrap();

        let treasury_spend = treasury_spend_info(&secp, y_51, y_67, y_fed, 144);
        let pegin_spend = treasury_spend_info(&secp, y_51, y_67, y_fed, 144);

        let treasury_spk = ScriptBuf::new_p2tr_tweaked(treasury_spend.output_key());
        let unsigned = build_tm(
            TreasuryInput {
                outpoint: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                value: Amount::from_sat(10_000_000),
                spend_info: treasury_spend,
            },
            vec![PegInInput {
                outpoint: OutPoint {
                    txid: Txid::from_byte_array([2u8; 32]),
                    vout: 0,
                },
                value: Amount::from_sat(500_000),
                spend_info: pegin_spend,
            }],
            vec![PegOutRequest {
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                    [3u8; 20],
                )),
                amount: Amount::from_sat(400_000),
            }],
            treasury_spk,
            &FeeParams {
                fee_rate_sat_per_vb: 1,
                per_pegout_fee: Amount::from_sat(1_000),
            },
        )
        .unwrap();
        let sighashes = compute_sighashes(&unsigned);
        let num_inputs = unsigned.tx.input.len();
        assert_eq!(num_inputs, 2);

        let tm_template = TreasuryMovement {
            txid: unsigned.txid,
            unsigned_tx: unsigned.tx.clone(),
            prevouts: unsigned.prevouts.clone(),
            input_spend_info: unsigned.input_spend_info.clone(),
            sighashes: sighashes.clone(),
            signatures: vec![None; num_inputs],
        };

        // Drive sign_phase for every SPO in parallel.
        let mut sign_handles = Vec::new();
        for gk in group_keys_all {
            let id = *gk.key_package.identifier();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock = clock.clone();
            let config = EpochConfig::demo_default(SpoIdentity {
                identifier: id,
                port: 0,
            });
            let roster = roster.clone();
            let tm = tm_template.clone();
            sign_handles.push(tokio::spawn(async move {
                let mut phase = EpochPhase::Sign {
                    epoch: 0,
                    roster,
                    cascade: CascadeLevel::Quorum67,
                    group_keys: gk,
                    tm,
                    round: SigningRound::Round1,
                    collected: SignCollected::default(),
                };
                loop {
                    phase = match phase {
                        EpochPhase::Sign {
                            epoch,
                            roster,
                            cascade,
                            group_keys,
                            tm,
                            round,
                            collected,
                        } => sign_phase(
                            &peers,
                            &clock,
                            &config,
                            epoch,
                            roster,
                            cascade,
                            group_keys,
                            tm,
                            round,
                            collected,
                        )
                        .await
                        .unwrap(),
                        EpochPhase::Submit { tm, .. } => return tm,
                        other => panic!("unexpected: {}", other.name()),
                    };
                }
            }));
        }

        let mut signed_tms: Vec<TreasuryMovement> = Vec::new();
        for h in sign_handles {
            signed_tms.push(h.await.unwrap());
        }

        // All SPOs must have aggregated to the same signature per input.
        for i in 0..num_inputs {
            let sig0 = signed_tms[0].signatures[i].as_ref().expect("signed");
            for tm in &signed_tms[1..] {
                let sig = tm.signatures[i].as_ref().expect("signed");
                assert_eq!(sig.serialize().unwrap(), sig0.serialize().unwrap());
            }
        }

        // Each aggregated Schnorr signature verifies under that input's
        // tweaked Taproot output key — i.e. the on-chain scriptPubKey
        // key — proving BIP-341 tweaking worked end-to-end.
        let tm = &signed_tms[0];
        for (i, sig_opt) in tm.signatures.iter().enumerate() {
            let sig = sig_opt.as_ref().unwrap();
            let output_key = tm.input_spend_info[i].output_key();
            let xonly = output_key.to_x_only_public_key();

            let sig_bytes = sig.serialize().unwrap();
            let schnorr_sig =
                bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
            let msg = bitcoin::secp256k1::Message::from_digest(tm.sighashes[i]);
            secp.verify_schnorr(&schnorr_sig, &msg, &xonly)
                .expect("taproot signature must verify under output key");
        }
    }
}
