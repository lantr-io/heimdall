//! Signing phase logic — Round1 (per-input commit) → Round2 (per-input
//! tweaked sign + aggregate).
//!
//! Each TM input runs an independent FROST session: sighashes differ
//! per input, and every Taproot input has its own merkle root that
//! must be folded into the signature via BIP-341 tweaking. The phase
//! therefore publishes one commitment/share payload per input and polls
//! peers with per-input keys.
//!
//! Every payload is authenticated end to end (WI-038): the transport signs the
//! canonical bytes under this node's `bifrost_id_pk` and verifies a peer's
//! before handing anything back, binding each payload to its
//! `(epoch, input, sighash, pool_id, identifier)` domain.

use std::collections::BTreeMap;
use std::sync::Arc;

use frost::Identifier;
use frost_secp256k1_tr as frost;

use crate::epoch::log::id_short;
use crate::epoch::state::{
    CascadeLevel, EpochConfig, EpochError, EpochPhase, EpochResult, GroupKeys, Roster,
    SignCollected, SigningRound, TreasuryMovement,
};
use crate::epoch::traits::{Clock, PeerNetwork, RngSource};
use crate::frost::participant;
use crate::http::wire::SignNamespace;

/// Drive one sub-round of the signing phase for all TM inputs.
///
/// TODO: signing cascade is not implemented. Today `sign_phase` only
/// exercises `CascadeLevel::Quorum51`; on timeout it returns `PollTimeout`
/// and the state machine aborts. A real implementation should catch
/// `PollTimeout` from `poll_sign_round{1,2}` and fall through to
/// `Federation` (script-path spend after `federation_csv_blocks`).
///
/// TODO: misbehavior detection. FROST errors here currently surface as
/// `EpochError::Frost(String)` with the identity lost. The identifiable
/// abort property means we can attribute a bad share to a specific
/// `Identifier`. The on-chain fault-proof flow is currently implemented for
/// DKG faults; signing-share fault proofs are still not wired up.
pub async fn sign_phase(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    epoch: u64,
    roster: Roster,
    cascade: CascadeLevel,
    group_keys: GroupKeys,
    mut tm: TreasuryMovement,
    round: SigningRound,
    mut collected: SignCollected,
) -> EpochResult<EpochPhase> {
    // The identifier the DKG actually produced for us — authoritative for
    // signing, and consistent with the other post-DKG phases (PublishKeys,
    // BuildTm, Submit) which also key off the group key package. Using the
    // frozen `config.identity.identifier` here would drift from it after a
    // roster change, exactly as it did in `dkg_phase`.
    let me = *group_keys.key_package.identifier();
    let num_inputs = tm.num_inputs();

    match round {
        SigningRound::Round1 => {
            // --- Co-signer gate: the attested completed-peg-outs root ---
            //
            // The trie root is ATTESTED, not verified on-chain: the Confirm
            // transition copies whatever root the FROST quorum signed into the TM.
            // So the only thing standing between a wrong root and chain truth is
            // every participant recomputing it before contributing a nonce.
            //
            // A wrong root is not cosmetic. Too FEW entries and a peg-out this TM
            // pays can never be completed — its BTC is spent and its fBTC stays
            // locked. Too MANY and a peg-out nobody paid becomes provably
            // completed, burning fBTC against BTC that never moved.
            //
            // BE PRECISE ABOUT WHAT THIS BUYS TODAY. Heimdall has no
            // leader-proposes-TM wire format: each node signs the TM it built
            // itself, moments ago, from the same trie. Against that input the
            // check is very nearly a tautology. What it actually catches is the
            // narrow window it spans — the persisted trie changing on disk between
            // `build_tm_phase` and here (a concurrent `reconstruct-cpo-trie`, an
            // operator edit, a half-applied recovery), plus a corrupt or
            // unreadable trie file.
            //
            // Its real value is INTERFACE SHAPE: the check takes (tm bytes, local
            // trie) and nothing else, so the moment a TM arrives from a peer it is
            // already a genuine co-signer gate with no changes here. Wiring it now
            // means the guarantee is not bolted on after the wire format lands.
            //
            // It runs BEFORE the first nonce commitment leaves the node, because a
            // published commitment is a signing input the others can use.
            verify_cpo_root(config, me, epoch, &tm)?;

            crate::epoch_log!(
                me,
                epoch,
                "Sign round1: generating nonce commitments for {} input(s)",
                num_inputs
            );
            // Generate and publish this SPO's nonce commitments for every input.
            for i in 0..num_inputs as u32 {
                let ctx = format!("sign1:epoch={epoch}:input={i}");
                let mut sign_rng = rng.rng(ctx.as_bytes());
                let (nonces, commitments) =
                    participant::sign_round1(&group_keys.key_package, &mut sign_rng);
                collected.nonces.insert(i, nonces);
                collected
                    .round1
                    .entry(i)
                    .or_default()
                    .insert(me, commitments);

                peers
                    .publish_sign_round1(input_namespace(epoch, &tm, i), me, commitments)
                    .await?;
                crate::epoch_debug!(me, epoch, "  -> published commitments for input {i}");
            }

            // Poll peers for round 1 commitments on every input.
            let peer_infos = roster.peers_of(me);
            for i in 0..num_inputs as u32 {
                crate::epoch_log!(
                    me,
                    epoch,
                    "  waiting for round1 commitments on input {i} from {} peer(s)...",
                    peer_infos.len()
                );
                let ns = input_namespace(epoch, &tm, i);
                let map = collected.round1.entry(i).or_default();
                poll_sign_round(peers, clock, config, ns, me, &peer_infos, map).await?;
            }
            crate::epoch_log!(
                me,
                epoch,
                "  <- have all round1 commitments, advancing to round2"
            );

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
                me,
                epoch,
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
                let nonces = collected.nonces.get(&i).ok_or_else(|| {
                    EpochError::Transition(format!("missing nonces for input {i}"))
                })?;

                let sighash = tm.sighashes[i as usize];
                let signing_package = frost::SigningPackage::new(commitments, &sighash);
                let merkle = tm.merkle_root_bytes(i as usize);
                let merkle_ref = merkle.as_deref();
                crate::epoch_debug!(
                    me,
                    epoch,
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
                crate::epoch_debug!(me, epoch, "    -> built tweaked signature share");

                collected.round2.entry(i).or_default().insert(me, share);

                let ns = input_namespace(epoch, &tm, i);
                peers.publish_sign_round2(ns, me, share).await?;
                crate::epoch_debug!(me, epoch, "    -> published share for input {i}");

                // Poll peers.
                let peer_infos = roster.peers_of(me);
                crate::epoch_log!(
                    me,
                    epoch,
                    "    waiting for round2 shares on input {i} from {} peer(s)...",
                    peer_infos.len()
                );
                let shares = collected.round2.entry(i).or_default();
                poll_sign_round(peers, clock, config, ns, me, &peer_infos, shares).await?;

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
                crate::epoch_debug!(
                    me,
                    epoch,
                    "    <- aggregated input {i} signature: {}",
                    hex::encode(&sig_bytes)
                );

                tm.signatures[i as usize] = Some(signature);
            }

            Ok(EpochPhase::Submit {
                epoch,
                roster,
                tm,
                leader_attempt: 0,
            })
        }
    }
}

/// Recompute the completed-peg-outs root this TM should commit, from THIS node's
/// own persisted trie, and refuse to sign on a mismatch.
///
/// Scope, stated honestly: heimdall's TM is deterministic and there is no leader
/// proposal to inspect, so this re-reads the trie from disk and re-checks a TM the
/// same node built minutes earlier. Against a self-built TM in one uninterrupted
/// run the comparison is near-tautological. What it genuinely guards is the window
/// it spans — the on-disk trie changing between build and sign — and a trie file
/// that has become corrupt or unreadable in the meantime.
///
/// It is written as `(tm bytes, local trie)` with no dependence on who built the
/// transaction, so it becomes a real co-signer gate unchanged the moment a
/// leader-proposes-TM wire format exists (`Design.md` specifies
/// `/sign/{epoch}/tm.json`; it was never implemented).
///
/// Refusing is the safe direction. A TM nobody signs is a missed movement; a TM
/// signed with a wrong root is an unrecoverable accounting error on the peg-out
/// ledger — see the call site for what each direction of error costs.
fn verify_cpo_root(
    config: &EpochConfig,
    me: Identifier,
    epoch: u64,
    tm: &TreasuryMovement,
) -> EpochResult<()> {
    use crate::bitcoin::tm_builder::verify_committed_root;
    use crate::cardano::cpo_trie::CpoTrie;

    let trie = match config.state_dir.as_deref() {
        Some(dir) => CpoTrie::load(dir)
            .map_err(|e| EpochError::TmBuild(format!("completed-peg-outs trie: {e}")))?
            .unwrap_or_default(),
        None => CpoTrie::empty(),
    };

    let root = verify_committed_root(&tm.unsigned_tx, &tm.fulfilled, &trie).map_err(|e| {
        EpochError::TmBuild(format!(
            "REFUSING TO SIGN treasury movement {}: {e}. This node's completed-peg-outs \
             trie disagrees with the root the transaction attests; signing would make that \
             root chain truth. Reconcile with `reconstruct-cpo-trie` before signing again.",
            tm.txid
        ))
    })?;

    crate::epoch_log!(
        me,
        epoch,
        "  completed-peg-outs root {} verified against the local trie ({} fulfilled peg-out(s)) \
         — safe to sign",
        hex::encode(root),
        tm.fulfilled.len(),
    );
    Ok(())
}

// FIXME: `poll_sign_round1` (and round2) waits for commitments from
// *every* peer, not just a threshold. That means one missing SPO stalls
// the whole cycle until the timeout fires, instead of proceeding as
// soon as `min_signers` have responded. A real implementation should
// proceed once it has `roster.min_signers` commitments and record the
// absent peers so the cascade / misbehavior path can react.
/// The signing domain for TM input `i`: the epoch, the input index, and the
/// input's own BIP-341 sighash. Two TMs in one epoch share `(epoch, i)` but
/// never the sighash, which is what stops a commitment captured from one from
/// replaying into the other.
fn input_namespace(epoch: u64, tm: &TreasuryMovement, i: u32) -> SignNamespace {
    SignNamespace::new(epoch, i, tm.sighashes[i as usize])
}

/// The payload one signing round collects from each peer, and how to fetch it.
///
/// Implemented for exactly the two FROST round types so [`poll_sign_round`] can
/// be written once for both, without an async closure (whose lifetime the
/// borrow checker cannot relate to the borrowed `SpoInfo`).
pub(crate) trait SignRoundPayload: Sized {
    /// Round number, for trace output.
    const ROUND: u8;
    async fn fetch(
        peers: &Arc<dyn PeerNetwork>,
        ns: SignNamespace,
        peer: &crate::epoch::state::SpoInfo,
    ) -> EpochResult<Option<Self>>;
}

impl SignRoundPayload for frost::round1::SigningCommitments {
    const ROUND: u8 = 1;
    async fn fetch(
        peers: &Arc<dyn PeerNetwork>,
        ns: SignNamespace,
        peer: &crate::epoch::state::SpoInfo,
    ) -> EpochResult<Option<Self>> {
        peers.fetch_sign_round1(ns, peer).await
    }
}

impl SignRoundPayload for frost::round2::SignatureShare {
    const ROUND: u8 = 2;
    async fn fetch(
        peers: &Arc<dyn PeerNetwork>,
        ns: SignNamespace,
        peer: &crate::epoch::state::SpoInfo,
    ) -> EpochResult<Option<Self>> {
        peers.fetch_sign_round2(ns, peer).await
    }
}

/// Poll every peer for one signing round of `ns` until all have answered or the
/// quorum deadline fires. Shared by the TM inputs and the Update-Y rotation
/// ceremony ([`crate::epoch::rotation`]) — one session is one session, and the
/// threshold-aware version of this loop (the FIXME above) must only ever be
/// written once.
///
/// Results are filed under the ROSTER's identifier for each peer, never one a
/// payload claimed for itself: the transport has already verified the payload
/// was signed by that peer under exactly that identifier.
pub(crate) async fn poll_sign_round<T: SignRoundPayload>(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    ns: SignNamespace,
    me: Identifier,
    peer_infos: &[&crate::epoch::state::SpoInfo],
    out: &mut BTreeMap<Identifier, T>,
) -> EpochResult<()> {
    let need = peer_infos.len() + out.len(); // self already present
    let deadline = clock.deadline(config.quorum51_timeout);
    while out.len() < need {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(value) = T::fetch(peers, ns, peer).await? {
                crate::epoch_debug!(
                    me,
                    ns.epoch,
                    "     received round{} for {} from spo={} ({}/{})",
                    T::ROUND,
                    ns.session_label(),
                    id_short(peer.identifier),
                    out.len() + 1,
                    need
                );
                out.insert(peer.identifier, value);
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
        PegInInput, PegOutRequest, TmParams, TreasuryInput, build_tm, compute_sighashes,
    };
    use crate::epoch::dkg::dkg_phase;
    use crate::epoch::mocks::{
        MockCardanoChain, MockPeerHub, MockPeerNetwork, OsRngSource, SystemClock,
    };
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
                    pool_id: vec![],
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
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        let chain: Arc<dyn crate::epoch::traits::CardanoChain> = Arc::new(MockCardanoChain::demo(
            roster.min_signers,
            roster.max_signers,
            0,
        ));
        let ctx = crate::cardano::dkg_roster::DkgContext::from_roster_equal_stake(&roster, 0, 0);
        let mut phase = EpochPhase::Dkg {
            round: DkgRound::Round1,
            ctx,
            collected: DkgCollected::default(),
        };
        loop {
            phase = match phase {
                EpochPhase::Dkg {
                    round,
                    ctx,
                    collected,
                } => dkg_phase(&chain, &peers, &clock, &rng, &config, round, ctx, collected)
                    .await
                    .unwrap(),
                EpochPhase::PublishKeys { group_keys, .. } => return group_keys,
                other => panic!("unexpected: {}", other.name()),
            };
        }
    }

    /// The group key's BIP-340 x-only form — the same deliberate even-Y
    /// normalization the production path takes.
    fn frost_vk_to_xonly(vk: &frost::VerifyingKey) -> UntweakedPublicKey {
        crate::frost::xonly::group_xonly(vk).unwrap().xonly
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
                bifrost_id_pk: Vec::new(),
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
        // internal Y_51. Y_fed is an unrelated placeholder key.
        let y_51 = frost_vk_to_xonly(&gk0.verifying_key);
        let y_fed = UntweakedPublicKey::from_slice(
            &bitcoin::secp256k1::SecretKey::from_slice(&[9u8; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0
                .serialize(),
        )
        .unwrap();

        let treasury_spend = treasury_spend_info(&secp, y_51, y_fed, 144);
        let pegin_spend = treasury_spend_info(&secp, y_51, y_fed, 144);

        let treasury_spk = ScriptBuf::new_p2tr_tweaked(treasury_spend.output_key());
        let treasury_outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };
        let unsigned = build_tm(
            TreasuryInput {
                outpoint: treasury_outpoint,
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
                per_pegout_fee: Amount::from_sat(1_000),
                por_id: [7u8; 32],
                outpoint: [8u8; 36],
                created: 0,
            }],
            treasury_spk,
            &TmParams::fee_rate_only(1),
            // `created: 0` with a `now` of 0 and no margin keeps the request
            // inside the freshness window without pinning a wall-clock time.
            &crate::bitcoin::tm_builder::Freshness {
                now_ms: 0,
                margin_ms: 0,
            },
            &crate::cardano::cpo_trie::CpoTrie::empty(),
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
            fulfilled: unsigned.fulfilled.clone(),
            cpo_root: unsigned.cpo_root,
        };

        // Drive sign_phase for every SPO in parallel.
        let mut sign_handles = Vec::new();
        for gk in group_keys_all {
            let id = *gk.key_package.identifier();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock = clock.clone();
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = EpochConfig::demo_default(SpoIdentity {
                identifier: id,
                bifrost_id_pk: Vec::new(),
                port: 0,
            });
            let roster = roster.clone();
            let tm = tm_template.clone();
            sign_handles.push(tokio::spawn(async move {
                let mut phase = EpochPhase::Sign {
                    epoch: 0,
                    roster,
                    cascade: CascadeLevel::Quorum51,
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
                            &peers, &clock, &rng, &config, epoch, roster, cascade, group_keys, tm,
                            round, collected,
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
