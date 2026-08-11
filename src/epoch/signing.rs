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

            // [SPI-2]: the same gate for the swept peg-ins root. Everything the
            // honesty note above says about the CPO gate applies verbatim: the
            // TM is self-built today, so what this catches is the on-disk trie
            // moving between build and sign, and it becomes a genuine co-signer
            // gate unchanged once a leader-proposed TM arrives over the wire.
            verify_spi_root(config, me, epoch, &tm)?;

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

/// [SPI-2]: recompute the swept peg-ins root from THIS node's own persisted
/// trie plus the proposed TM's inputs, and refuse to sign on a mismatch.
///
/// The scope note on [`verify_cpo_root`] applies unchanged: heimdall's TM is
/// self-built, so against one uninterrupted run the check is near-tautological.
/// What it guards is the window between `build_tm_phase` computing `tm.spi_root`
/// and this node signing – the persisted trie changing on disk in between, or a
/// corrupt file – and it is written as `(tm, local trie)` so it becomes a real
/// co-signer gate the moment a leader-proposes-TM wire format exists.
///
/// Refusing is the safe direction: a spurious entry in the swept set mints fBTC
/// against BTC that never reached the treasury ([SPI-2]'s "Why" in the spec),
/// while a refused TM is a missed movement the next epoch retries.
fn verify_spi_root(
    config: &EpochConfig,
    me: Identifier,
    epoch: u64,
    tm: &TreasuryMovement,
) -> EpochResult<()> {
    use crate::cardano::spi_trie::SpiTrie;

    let trie = SpiTrie::load_or_empty(config.state_dir.as_deref())
        .map_err(|e| EpochError::TmBuild(format!("swept peg-ins trie: {e}")))?;

    let inputs = tm.input_outpoints();
    let root = trie.verify_proposed(&tm.spi_root, &inputs).map_err(|e| {
        EpochError::TmBuild(format!(
            "REFUSING TO SIGN treasury movement {}: {e}. This node's swept peg-ins trie \
             disagrees with the root the movement implies; signing would attest a swept set \
             this node cannot justify. Reconcile spi-trie.json with the confirmed TM chain \
             before signing again.",
            tm.txid
        ))
    })?;

    // The root the transaction ITSELF commits (BTMR1 output, script bytes
    // [7, 39)) must be the same 32 bytes — a `spi_root` field that matches
    // while the committed bytes differ would make the quorum sign an
    // attestation this node never checked. A TM with no commitment output at
    // all is not tolerated either: `verify_cpo_root` runs first and refuses it
    // (exactly one commitment, same rule as on-chain), so skipping the
    // comparison here cannot let one through.
    if let Ok(committed) = crate::bitcoin::tm_builder::committed_spi_root(&tm.unsigned_tx) {
        if committed != root {
            return Err(EpochError::TmBuild(format!(
                "REFUSING TO SIGN treasury movement {}: its BTMR1 output commits swept \
                 peg-ins root {} but this node recomputes {} from its own trie plus the \
                 movement's inputs. Signing would attest a swept set this node cannot \
                 justify.",
                tm.txid,
                hex::encode(committed),
                hex::encode(root),
            )));
        }
    }

    crate::epoch_log!(
        me,
        epoch,
        "  swept peg-ins root {} verified against the local trie ({} swept input(s)) \
         – safe to sign",
        hex::encode(root),
        inputs.len().saturating_sub(1),
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
            &crate::cardano::spi_trie::SpiTrie::empty(),
        )
        .unwrap();
        let sighashes = compute_sighashes(&unsigned);
        let num_inputs = unsigned.tx.input.len();
        assert_eq!(num_inputs, 2);

        let mut tm_template = TreasuryMovement {
            txid: unsigned.txid,
            unsigned_tx: unsigned.tx.clone(),
            prevouts: unsigned.prevouts.clone(),
            input_spend_info: unsigned.input_spend_info.clone(),
            sighashes: sighashes.clone(),
            signatures: vec![None; num_inputs],
            fulfilled: unsigned.fulfilled.clone(),
            cpo_root: unsigned.cpo_root,
            spi_root: [0u8; 32],
        };
        // The honest [SPI-2] root: no state_dir in this test, so the local trie
        // is empty and the implied root is the empty trie advanced by the TM.
        tm_template.spi_root = crate::cardano::spi_trie::SpiTrie::empty()
            .root_after(&tm_template.input_outpoints())
            .unwrap();

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

    // --- [SPI-2] co-signer gate -------------------------------------------

    /// A 36-byte outpoint: txid internal order (32 bytes of `b`) ++ vout LE.
    fn spi_op(b: u8, vout: u32) -> [u8; 36] {
        let mut o = [b; 36];
        o[32..].copy_from_slice(&vout.to_le_bytes());
        o
    }

    /// A minimal TM carrying only what `verify_spi_root` reads: inputs and the
    /// proposed `spi_root`.
    fn spi_tm(inputs: &[[u8; 36]], spi_root: [u8; 32]) -> TreasuryMovement {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|op| bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: Txid::from_byte_array(op[..32].try_into().unwrap()),
                        vout: u32::from_le_bytes(op[32..].try_into().unwrap()),
                    },
                    ..Default::default()
                })
                .collect(),
            output: vec![],
        };
        TreasuryMovement {
            txid: tx.compute_txid(),
            unsigned_tx: tx,
            prevouts: vec![],
            input_spend_info: vec![],
            sighashes: vec![],
            signatures: vec![],
            fulfilled: vec![],
            cpo_root: [0u8; 32],
            spi_root,
        }
    }

    /// [SPI-2]: before contributing any signing material, this node recomputes
    /// the swept peg-ins root from its OWN persisted trie plus the proposed
    /// TM's inputs. A matching root passes; a stale or forged root – including
    /// the on-disk trie changing between build and sign – is refused.
    #[test]
    fn verify_spi_root_refuses_a_mismatched_proposed_root() {
        use crate::cardano::spi_trie::SpiTrie;

        let dir = std::env::temp_dir().join(format!("spi-gate-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let me = Identifier::try_from(1u16).unwrap();
        let mut config = EpochConfig::demo_default(SpoIdentity {
            identifier: me,
            bifrost_id_pk: Vec::new(),
            port: 0,
        });
        config.state_dir = Some(dir.clone());

        // This node's trie already holds one earlier sweep.
        let mut local = SpiTrie::empty();
        local
            .insert_for_confirmed_tm(&[spi_op(0x10, 0), spi_op(0x11, 0)])
            .unwrap();
        local.save(&dir).unwrap();

        // The proposed TM sweeps two new deposits; its honest root is the local
        // trie advanced by its inputs.
        let inputs = [spi_op(0xaa, 0), spi_op(0x01, 0), spi_op(0x02, 3)];
        let honest = local.root_after(&inputs).unwrap();
        verify_spi_root(&config, me, 0, &spi_tm(&inputs, honest))
            .expect("the honest root must pass the gate");

        // A stale root – the trie WITHOUT this TM's entries – is refused.
        verify_spi_root(&config, me, 0, &spi_tm(&inputs, local.root()))
            .expect_err("a stale spi_root must be refused");

        // The window the gate spans: the on-disk trie changes between build and
        // sign, so the root computed at build time no longer holds.
        SpiTrie::empty().save(&dir).unwrap();
        verify_spi_root(&config, me, 0, &spi_tm(&inputs, honest))
            .expect_err("a trie that moved under the proposal must refuse the old root");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// [SPI-2] extends to the root the transaction ITSELF commits: the BTMR1
    /// output carries `spi_root` at script bytes [7, 39), and that committed
    /// root is what a Confirm makes chain truth. A TM whose `spi_root` field
    /// matches the local recompute but whose committed bytes disagree must
    /// still be refused – otherwise the quorum signs an attestation this node
    /// never checked.
    #[test]
    fn cosigner_rejects_tm_with_wrong_spi_root() {
        use crate::cardano::spi_trie::SpiTrie;

        let me = Identifier::try_from(1u16).unwrap();
        // No state_dir: the gate's local trie is `SpiTrie::empty()`.
        let config = EpochConfig::demo_default(SpoIdentity {
            identifier: me,
            bifrost_id_pk: Vec::new(),
            port: 0,
        });

        let inputs = [spi_op(0xaa, 0), spi_op(0x01, 0), spi_op(0x02, 3)];
        let honest = SpiTrie::empty().root_after(&inputs).unwrap();

        // The TM's field carries the honest root, but its transaction commits
        // a DIFFERENT spi_root inside the BTMR1 output (bytes [7, 39)).
        let mut tm = spi_tm(&inputs, honest);
        let mut spk = vec![0x6a, 0x45]; // OP_RETURN OP_PUSHBYTES_69
        spk.extend_from_slice(b"BTMR1");
        spk.extend_from_slice(&[0xffu8; 32]); // forged spi_root
        spk.extend_from_slice(&[0u8; 32]); // cpo_root, not under test here
        tm.unsigned_tx.output.push(bitcoin::TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk),
        });
        tm.txid = tm.unsigned_tx.compute_txid();

        verify_spi_root(&config, me, 0, &tm).expect_err(
            "the committed spi_root (script bytes [7, 39)) differs from the locally \
             recomputed root, so the co-signer must refuse to sign",
        );
    }
}
