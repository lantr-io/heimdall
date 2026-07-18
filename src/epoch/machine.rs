//! Epoch state machine driver.
//!
//! `run_epoch_loop` repeatedly matches on `EpochPhase` and dispatches to
//! the right phase function. Glue phases that are not big enough to
//! deserve their own module live here:
//!
//! - `idle_phase`          — block until the chain reports an epoch boundary
//! - `epoch_start_phase`   — snapshot the roster
//! - `publish_keys_phase`  — log the group key (no-op for the first cycle)
//! - `collect_pegins_phase`— poll the Cardano peg-in source over a
//!                           configured collection window, parse each
//!                           datum into a validated `ParsedPegIn`, and
//!                           freeze the set for `BuildTm`
//! - `build_tm_phase`      — pull treasury + pegouts (frozen pegins
//!                           come from `CollectPegins`) and build the
//!                           unsigned Bitcoin tx + sighashes
//! - `submit_phase`        — assemble the witnessed tx, verify each
//!                           per-input signature under the on-chain
//!                           output key, hand bytes to the chain
//! - `await_confirm_phase` — terminal for the first cycle: returns the
//!                           signed `TreasuryMovement` to the caller
//!
//! `Dkg` and `Sign` are dispatched to `dkg::dkg_phase` and
//! `signing::sign_phase` respectively.
//!
//! Note: peg-ins returned by the `CardanoPegInSource` are guaranteed
//! ≥100 Bitcoin blocks deep because they come from oracle-owned
//! UTxOs on Cardano. The SPO does NOT re-verify BTC confirmations.

use std::sync::Arc;

use bitcoin::Witness;
use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, UntweakedPublicKey};
use frost_secp256k1_tr as frost;

use crate::bitcoin::taproot::treasury_spend_info;
use crate::bitcoin::tm_builder::{
    FeeParams, PegInInput, PegOutRequest, TreasuryInput, build_tm, compute_sighashes,
};
use crate::cardano::pegin_datum::{ParsedPegIn, parse_pegin_request};
use crate::cardano::pegin_source::{CardanoOutRef, CardanoPegInSource};
use crate::epoch::dkg::dkg_phase;
use crate::epoch::signing::sign_phase;
use crate::epoch::state::{
    CascadeLevel, DkgCollected, DkgRound, EpochConfig, EpochError, EpochPhase, EpochResult,
    GroupKeys, Roster, SignCollected, SigningRound, TreasuryMovement,
};
use crate::epoch::traits::{CardanoChain, Clock, PeerNetwork, RngSource};
use std::collections::BTreeMap;

/// Run the epoch state machine for one full cycle and return the
/// witnessed `TreasuryMovement` once the cycle reaches `AwaitConfirm`.
///
/// The first-cycle scope: `await_epoch_boundary` fires once, the loop
/// runs DKG → BuildTm → Sign → Submit → AwaitConfirm and then exits.
/// Future cuts will instead loop back to `Idle` and wait for the next
/// boundary.
/// Backoff bounds for retriable phase errors (chain/peer/DKG). A persistent
/// transient failure re-enters `Idle` with an exponentially growing wait,
/// capped, so the node parks for the next boundary instead of dying or
/// hot-looping (WI-010 / WI-014 error-handling feedback).
const RETRY_BACKOFF_MIN: std::time::Duration = std::time::Duration::from_secs(2);
const RETRY_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(60);

/// One dispatch step: advance to the next phase, or finish the cycle. Both
/// variants are large but the value is constructed and consumed immediately in
/// the loop (never stored), so boxing would only add an allocation.
#[allow(clippy::large_enum_variant)]
enum Step {
    Next(EpochPhase),
    Done(TreasuryMovement),
}

pub async fn run_epoch_loop(
    chain: Arc<dyn CardanoChain>,
    pegin_source: Arc<dyn CardanoPegInSource>,
    peers: Arc<dyn PeerNetwork>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn RngSource>,
    config: &EpochConfig,
) -> EpochResult<TreasuryMovement> {
    let me = config.identity.identifier;
    let mut phase = EpochPhase::Idle;
    let mut backoff = RETRY_BACKOFF_MIN;
    loop {
        crate::epoch_log!(me, current_epoch(&phase), "==> phase = {}", phase.name());
        match step_phase(
            phase,
            &chain,
            &pegin_source,
            &peers,
            &clock,
            &rng,
            config,
            me,
        )
        .await
        {
            Ok(Step::Next(next)) => {
                phase = next;
                backoff = RETRY_BACKOFF_MIN; // progress → reset
            }
            Ok(Step::Done(tm)) => return Ok(tm),
            // Retriable (chain read, peer transport, signing timeout, fully
            // aborted DKG attempt): back off and re-enter from the boundary,
            // NEVER kill the node. A failed DKG attempt already reruns over a
            // reduced set inside `dkg_phase`; reaching here means even that
            // aborted, so wait for the next boundary and rebuild the context.
            Err(e) if e.is_retriable() => {
                crate::epoch_log!(
                    me,
                    current_epoch(&EpochPhase::Idle),
                    "retriable error: {e}; backing off {:?} then re-entering Idle",
                    backoff
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_BACKOFF_MAX);
                phase = EpochPhase::Idle;
            }
            // Fatal (logic/crypto bug, malformed tx): surface it. The caller
            // logs and exits cleanly rather than panicking.
            Err(e) => return Err(e),
        }
    }
}

/// Dispatch one phase to its handler. Pure routing — the retry/backoff policy
/// lives in [`run_epoch_loop`].
#[allow(clippy::too_many_arguments)]
async fn step_phase(
    phase: EpochPhase,
    chain: &Arc<dyn CardanoChain>,
    pegin_source: &Arc<dyn CardanoPegInSource>,
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    me: frost::Identifier,
) -> EpochResult<Step> {
    let next = match phase {
        EpochPhase::Idle => idle_phase(chain).await?,

        EpochPhase::EpochStart { epoch } => epoch_start_phase(chain, config, epoch).await?,

        EpochPhase::Dkg {
            round,
            ctx,
            collected,
        } => dkg_phase(chain, peers, clock, rng, config, round, ctx, collected).await?,

        EpochPhase::PublishKeys {
            epoch,
            roster,
            group_keys,
        } => publish_keys_phase(chain, epoch, roster, group_keys).await?,

        EpochPhase::CollectPegins {
            epoch,
            roster,
            group_keys,
        } => {
            collect_pegins_phase(
                chain,
                pegin_source,
                clock,
                config,
                epoch,
                roster,
                group_keys,
            )
            .await?
        }

        EpochPhase::BuildTm {
            epoch,
            roster,
            group_keys,
            frozen_pegins,
        } => build_tm_phase(chain, epoch, roster, group_keys, frozen_pegins).await?,

        EpochPhase::Sign {
            epoch,
            roster,
            cascade,
            group_keys,
            tm,
            round,
            collected,
        } => {
            sign_phase(
                peers, clock, rng, config, epoch, roster, cascade, group_keys, tm, round, collected,
            )
            .await?
        }

        EpochPhase::Submit {
            epoch,
            roster,
            tm,
            leader_attempt,
        } => submit_phase(chain, me, epoch, roster, tm, leader_attempt).await?,

        EpochPhase::AwaitConfirm { tm, .. } => {
            // First-cycle terminal: return the signed TM.
            //
            // TODO: in steady state this phase should poll the chain for
            // inclusion of `cardano_tx_id` (once submit actually produces one),
            // then transition back to `Idle` to wait for the next epoch
            // boundary. Today we finish the cycle unconditionally.
            return Ok(Step::Done(tm));
        }
    };
    Ok(Step::Next(next))
}

// ---------------------------------------------------------------------------
// idle / epoch_start
// ---------------------------------------------------------------------------

async fn idle_phase(chain: &Arc<dyn CardanoChain>) -> EpochResult<EpochPhase> {
    let event = chain.await_epoch_boundary().await?;
    Ok(EpochPhase::EpochStart { epoch: event.epoch })
}

async fn epoch_start_phase(
    chain: &Arc<dyn CardanoChain>,
    config: &EpochConfig,
    epoch: u64,
) -> EpochResult<EpochPhase> {
    let me = config.identity.identifier;

    // Restart recovery (WI-014 #5): if this epoch's DKG already ran and was
    // persisted, reload the share and skip straight to PublishKeys — the
    // ceremony is multi-round and expensive, and a mid-epoch crash must not
    // re-run it (or lose the share).
    if let Some(resumed) = try_resume_dkg(config, me, epoch)? {
        return Ok(resumed);
    }

    // Build the stake-aware DKG context for attempt 0. A failed attempt reruns
    // over a reduced candidate set with a bumped attempt inside `dkg_phase`
    // (DkgContext::reduced_to), so the chain is queried once at the boundary.
    let ctx = chain.query_dkg_context(epoch, 0).await?;
    Ok(EpochPhase::Dkg {
        round: DkgRound::Round1,
        ctx,
        collected: DkgCollected::default(),
    })
}

/// Reload a persisted DKG for `epoch` and turn it into a resume-to-PublishKeys
/// phase, or `None` to run a fresh ceremony. Persisted state that doesn't bind
/// this node, or is unreadable, is treated as stale (not an error) and ignored.
fn try_resume_dkg(
    config: &EpochConfig,
    me: frost::Identifier,
    epoch: u64,
) -> EpochResult<Option<EpochPhase>> {
    let Some(dir) = &config.state_dir else {
        return Ok(None);
    };
    let Some(saved) = crate::epoch::persist::read_dkg_state(dir, epoch)? else {
        return Ok(None);
    };
    match saved.to_group_keys() {
        Ok(group_keys) if *group_keys.key_package.identifier() == me => {
            crate::epoch_log!(
                me,
                epoch,
                "resuming epoch {epoch} from persisted DKG (attempt {}) — skipping the ceremony",
                saved.attempt
            );
            Ok(Some(EpochPhase::PublishKeys {
                epoch,
                roster: saved.roster,
                group_keys,
            }))
        }
        Ok(_) => {
            crate::epoch_log!(
                me,
                epoch,
                "persisted DKG for epoch {epoch} is bound to a different identity — ignoring, \
                 running a fresh ceremony"
            );
            Ok(None)
        }
        Err(e) => {
            crate::epoch_log!(
                me,
                epoch,
                "persisted DKG for epoch {epoch} is unreadable ({e}) — running a fresh ceremony"
            );
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// publish_keys
// ---------------------------------------------------------------------------

async fn publish_keys_phase(
    chain: &Arc<dyn CardanoChain>,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();
    let y_51 = frost_vk_to_xonly(&group_keys.verifying_key)?;

    crate::epoch_log!(
        me,
        epoch,
        "PublishKeys: group_key = {}",
        hex::encode(y_51.serialize())
    );

    // Finalize (WI-014 #4): derive the NEW treasury Taproot address from the
    // just-derived FROST group key (Y_51, internal key) + the federation
    // fallback key (Y_fed, script leaf) read from the treasury oracle — the
    // address the epoch's handoff will move funds into. The same derivation
    // drives the actual TM change output in `build_tm_phase`; logging it here
    // makes the handoff destination visible the moment DKG completes. Y_51 is
    // identical across all SPOs (checked in `dkg_phase`), so every SPO derives
    // this same address.
    //
    // This runs BEFORE `publish_group_key` sets the group key, so `query_treasury`
    // may not yet be able to match the current on-chain tip to our keys. That is a
    // hard error there (never sign an unmatched tip), but here it is only an
    // address preview — so treat a failure as non-fatal and continue to the actual
    // handoff, where `build_tm_phase` re-queries with the published key.
    match chain.query_treasury().await {
        Ok(treasury) => {
            let secp = Secp256k1::new();
            let new_spend = treasury_spend_info(
                &secp,
                y_51,
                treasury.y_fed,
                treasury.federation_csv_blocks as u16,
            );
            let new_spk = bitcoin::ScriptBuf::new_p2tr_tweaked(new_spend.output_key());
            crate::epoch_log!(
                me,
                epoch,
                "  -> new treasury: output_key={} scriptPubKey={}",
                hex::encode(new_spend.output_key().to_x_only_public_key().serialize()),
                hex::encode(new_spk.as_bytes())
            );
        }
        Err(e) => crate::epoch_log!(
            me,
            epoch,
            "  (new treasury address preview unavailable pre-handoff: {e})"
        ),
    }

    chain.publish_group_key(y_51).await?;

    Ok(EpochPhase::CollectPegins {
        epoch,
        roster,
        group_keys,
    })
}

// ---------------------------------------------------------------------------
// collect_pegins
// ---------------------------------------------------------------------------

/// Poll the Cardano peg-in source over `config.pegin_collection_window`,
/// parsing each observed request against the spec-derived peg-in
/// Taproot for the current Y_fed + refund_timeout + depositor_xonly.
/// Parse failures are logged and dropped. The deduped, parsed set is
/// frozen into the next `BuildTm` phase.
async fn collect_pegins_phase(
    chain: &Arc<dyn CardanoChain>,
    pegin_source: &Arc<dyn CardanoPegInSource>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();

    // Pull current Y_fed from the on-chain treasury oracle. The
    // peg-in Taproot Q is derived per-depositor inside
    // `parse_pegin_request` using the OP_RETURN beacon xonly pubkey.
    let treasury = chain.query_treasury().await?;
    let refund_timeout = config.pegin_refund_timeout_blocks;

    let deadline = clock.deadline(config.pegin_collection_window);
    let mut accepted: BTreeMap<CardanoOutRef, ParsedPegIn> = BTreeMap::new();

    crate::epoch_log!(
        me,
        epoch,
        "CollectPegins: polling source for {:?} (poll interval {:?})",
        config.pegin_collection_window,
        config.pegin_poll_interval
    );

    loop {
        let batch = pegin_source
            .query_pegin_requests(&config.pegin_policy_id)
            .await?;
        for req in batch {
            if accepted.contains_key(&req.cardano_utxo) {
                continue;
            }
            // Peg-in internal key is Y_51 (the FROST group key), not Y_fed —
            // see parse_pegin_request / commit 6af7c67.
            match parse_pegin_request(&req, treasury.y_51, refund_timeout) {
                Ok(parsed) => {
                    accepted.insert(req.cardano_utxo.clone(), parsed);
                }
                Err(e) => {
                    crate::epoch_log!(me, epoch, "  dropped peg-in {:?}: {}", req.cardano_utxo, e);
                }
            }
        }
        if clock.now() >= deadline {
            break;
        }
        tokio::time::sleep(config.pegin_poll_interval).await;
    }

    let frozen_pegins: Vec<ParsedPegIn> = accepted.into_values().collect();
    crate::epoch_log!(
        me,
        epoch,
        "  -> froze {} peg-in(s) for BuildTm",
        frozen_pegins.len()
    );

    Ok(EpochPhase::BuildTm {
        epoch,
        roster,
        group_keys,
        frozen_pegins,
    })
}

// ---------------------------------------------------------------------------
// build_tm
// ---------------------------------------------------------------------------

async fn build_tm_phase(
    chain: &Arc<dyn CardanoChain>,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
    frozen_pegins: Vec<ParsedPegIn>,
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();
    crate::epoch_log!(me, epoch, "BuildTm: querying chain for treasury / pegouts");

    // Poll until the previous treasury movement is confirmed on Bitcoin.
    let treasury = loop {
        let t = chain.query_treasury().await?;
        if t.btc_confirmed {
            break t;
        }
        crate::epoch_log!(
            me,
            epoch,
            "BuildTm: previous treasury movement not yet confirmed on Bitcoin, waiting…"
        );
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    };

    let pegouts = chain.query_pegout_requests().await?;
    crate::epoch_log!(
        me,
        epoch,
        "  chain query: treasury={} sat, {} frozen pegins, {} pegouts, fee_rate={}sat/vb",
        treasury.value.to_sat(),
        frozen_pegins.len(),
        pegouts.len(),
        treasury.fee_rate_sat_per_vb,
    );

    let secp = Secp256k1::new();

    // Treasury *input* spend info: the current treasury is locked under
    // `treasury.y_51` (at bootstrap this is Y_fed; in steady state it
    // is the previous epoch's FROST group key).
    let treasury_input_spend = treasury_spend_info(
        &secp,
        treasury.y_51,
        treasury.y_fed,
        treasury.federation_csv_blocks as u16,
    );

    // Treasury *change output*: send to the new roster's Taproot address,
    // using the just-derived FROST group key as the internal key.
    let new_y_51 = frost_vk_to_xonly(&group_keys.verifying_key)?;
    let change_spend = treasury_spend_info(
        &secp,
        new_y_51,
        treasury.y_fed,
        treasury.federation_csv_blocks as u16,
    );
    let change_script = bitcoin::ScriptBuf::new_p2tr_tweaked(change_spend.output_key());

    // Each peg-in input is locked under its own per-depositor peg-in script
    // tree (internal key Y_fed + refund leaf), NOT the treasury tree. Reuse the
    // `TaprootSpendInfo` `parse_pegin_request` already proved matches the
    // on-chain deposit scriptPubKey, so the TM sighash commits to the correct
    // prevout and the signature validates.
    let pegin_inputs: Vec<PegInInput> = frozen_pegins
        .into_iter()
        .map(|p| PegInInput {
            outpoint: bitcoin::OutPoint {
                txid: p.btc_txid,
                vout: p.btc_vout,
            },
            value: p.value,
            spend_info: p.spend_info,
        })
        .collect();

    let pegout_requests: Vec<PegOutRequest> = pegouts
        .into_iter()
        .map(|p| PegOutRequest {
            script_pubkey: p.script_pubkey,
            amount: p.amount,
        })
        .collect();

    let unsigned = build_tm(
        TreasuryInput {
            outpoint: treasury.outpoint,
            value: treasury.value,
            spend_info: treasury_input_spend,
        },
        pegin_inputs,
        pegout_requests,
        change_script,
        &FeeParams {
            fee_rate_sat_per_vb: treasury.fee_rate_sat_per_vb,
            per_pegout_fee: treasury.per_pegout_fee,
        },
    )
    .map_err(|e| EpochError::TmBuild(e.to_string()))?;

    let sighashes = compute_sighashes(&unsigned);
    let num_inputs = unsigned.tx.input.len();

    let tm = TreasuryMovement {
        txid: unsigned.txid,
        unsigned_tx: unsigned.tx,
        prevouts: unsigned.prevouts,
        input_spend_info: unsigned.input_spend_info,
        sighashes,
        signatures: vec![None; num_inputs],
    };

    crate::epoch_log!(
        me,
        epoch,
        "  -> built unsigned tx: txid={} ({num_inputs} inputs)",
        tm.txid
    );

    Ok(EpochPhase::Sign {
        epoch,
        roster,
        cascade: CascadeLevel::Quorum51,
        group_keys,
        tm,
        round: SigningRound::Round1,
        collected: SignCollected::default(),
    })
}

// ---------------------------------------------------------------------------
// submit
// ---------------------------------------------------------------------------

// All SPOs verify and assemble the witnessed transaction, but only the
// designated leader for `leader_attempt` actually broadcasts it via
// `chain.submit_signed_tm`. Today the leader is always
// `Roster::leader(0)` (lowest identifier).
//
// TODO: leader-timeout cascade. If the leader stalls, `leader_attempt`
// should increment and a new leader take over after `leader_timeout`.
// Nothing currently bumps `leader_attempt`, so a stuck leader hangs the
// cycle. The phase enum already plumbs the field for this.
async fn submit_phase(
    chain: &Arc<dyn CardanoChain>,
    me: frost_secp256k1_tr::Identifier,
    epoch: u64,
    roster: Roster,
    mut tm: TreasuryMovement,
    leader_attempt: u8,
) -> EpochResult<EpochPhase> {
    let secp = Secp256k1::new();

    // Verify each per-input signature against its tweaked output key
    // before assembling the witnesses. This catches a broken signing
    // path before we hand bytes to the chain.
    crate::epoch_log!(
        me,
        epoch,
        "Submit: verifying {} per-input signatures",
        tm.signatures.len()
    );
    for (i, sig_opt) in tm.signatures.iter().enumerate() {
        let sig = sig_opt
            .as_ref()
            .ok_or_else(|| EpochError::Transition(format!("input {i} unsigned at Submit")))?;
        let sig_bytes = sig
            .serialize()
            .map_err(|e| EpochError::Frost(format!("sig serialize: {e}")))?;
        let schnorr = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| EpochError::SignatureVerify(i, format!("from_slice: {e}")))?;
        let xonly = tm.input_spend_info[i].output_key().to_x_only_public_key();
        let msg = bitcoin::secp256k1::Message::from_digest(tm.sighashes[i]);
        secp.verify_schnorr(&schnorr, &msg, &xonly)
            .map_err(|e| EpochError::SignatureVerify(i, e.to_string()))?;
        crate::epoch_log!(
            me,
            epoch,
            "  input {i}: schnorr sig verifies under output key"
        );
    }

    // Build the final witnessed transaction (key-path spend on every input).
    let mut signed_tx = tm.unsigned_tx.clone();
    for (i, txin) in signed_tx.input.iter_mut().enumerate() {
        let sig = tm.signatures[i]
            .as_ref()
            .expect("checked above")
            .serialize()
            .map_err(|e| EpochError::Frost(format!("sig serialize: {e}")))?;
        let schnorr =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&sig).expect("verified above");
        let tap_sig = bitcoin::taproot::Signature {
            signature: schnorr,
            sighash_type: bitcoin::sighash::TapSighashType::Default,
        };
        txin.witness = Witness::p2tr_key_spend(&tap_sig);
    }

    let tx_bytes = bitcoin::consensus::encode::serialize(&signed_tx);

    // Every participant assembles the *identical* witnessed tx (same FROST
    // group signature, deterministic build), so logging the raw hex on every
    // node makes the "all SPOs saw the same signed transaction" moment visible
    // across all terminals — the point at which the epoch's signing round is
    // complete. The leader additionally submits it below.
    crate::epoch_log!(
        me,
        epoch,
        "Submit: signed treasury movement — txid={} ({} bytes)\n    raw tx: {}",
        tm.txid,
        tx_bytes.len(),
        hex::encode(&tx_bytes)
    );

    // Only the designated leader broadcasts. Everyone else assembles
    // the witnessed tx, holds it, and waits — they'd take over on a
    // future leader-timeout cascade.
    let leader = roster.leader(leader_attempt);
    if me == leader {
        crate::epoch_log!(
            me,
            epoch,
            "Submit: leader (attempt {leader_attempt}) — broadcasting signed tx; \
             txid = {} ({} bytes)",
            tm.txid,
            tx_bytes.len()
        );
        chain.submit_signed_tm(&tx_bytes).await?;
    } else {
        crate::epoch_log!(
            me,
            epoch,
            "Submit: follower (leader = {:?}, attempt {leader_attempt}); \
             holding witnessed tx ({} bytes), not broadcasting",
            leader,
            tx_bytes.len()
        );
    }

    // Persist the witnessed tx back into `tm` so callers can inspect it.
    tm.unsigned_tx = signed_tx;

    Ok(EpochPhase::AwaitConfirm {
        epoch,
        tm,
        cardano_tx_id: vec![],
    })
}

/// Convert a FROST verifying key to bitcoin's `UntweakedPublicKey` (the
/// 32-byte x-only encoding). The verifying key serializes as a 33-byte
/// compressed point — drop the parity prefix.
///
/// TODO: this silently discards the parity bit. `frost-secp256k1-tr`
/// handles BIP-341 even-Y normalization internally during signing, so
/// the tweaked `output_key` is valid, but any code that wants to
/// re-derive the *pre-tweak* point needs to remember the parity.
fn frost_vk_to_xonly(vk: &frost::VerifyingKey) -> EpochResult<UntweakedPublicKey> {
    let bytes = vk
        .serialize()
        .map_err(|e| EpochError::Frost(format!("verifying_key serialize: {e}")))?;
    if bytes.len() != 33 {
        return Err(EpochError::Frost(format!(
            "expected 33-byte compressed verifying key, got {}",
            bytes.len()
        )));
    }
    UntweakedPublicKey::from_slice(&bytes[1..33])
        .map_err(|e| EpochError::Frost(format!("xonly: {e}")))
}

/// Best-effort extraction of the epoch number from a phase, used by
/// the dispatch-line trace. `Idle` has no epoch yet.
fn current_epoch(phase: &EpochPhase) -> u64 {
    match phase {
        EpochPhase::Idle => 0,
        EpochPhase::Dkg { ctx, .. } => ctx.epoch,
        EpochPhase::EpochStart { epoch }
        | EpochPhase::PublishKeys { epoch, .. }
        | EpochPhase::CollectPegins { epoch, .. }
        | EpochPhase::BuildTm { epoch, .. }
        | EpochPhase::Sign { epoch, .. }
        | EpochPhase::Submit { epoch, .. }
        | EpochPhase::AwaitConfirm { epoch, .. } => *epoch,
    }
}

// suppress warning when no test in this module exercises the helper
#[allow(dead_code)]
fn _hash_used() -> [u8; 32] {
    bitcoin::hashes::sha256::Hash::hash(&[]).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::mock::MockCardanoPegInSource;
    use crate::epoch::fixture::demo_static_fixture;
    use crate::epoch::mocks::{
        MockCardanoChain, MockPeerHub, MockPeerNetwork, OsRngSource, SystemClock,
    };
    use crate::epoch::state::SpoIdentity;
    use frost::Identifier;
    use std::time::Duration;

    /// Tight timings so the full cycle runs in well under a second.
    fn fast_config(id: Identifier) -> EpochConfig {
        let mut config = EpochConfig::demo_default(SpoIdentity {
            identifier: id,
            port: 0,
        });
        config.dkg_round_timeout = Duration::from_millis(500);
        config.poll_interval = Duration::from_millis(10);
        config.pegin_collection_window = Duration::from_millis(40);
        config.pegin_poll_interval = Duration::from_millis(10);
        config.quorum51_timeout = Duration::from_millis(500);
        config
    }

    /// WI-014 acceptance: N instances run the FULL epoch loop (DKG → finalize →
    /// CollectPegins → BuildTm → Sign → Submit) against their own mock chains
    /// over a shared peer hub, and must complete the cycle deriving the SAME
    /// treasury movement — byte-identical unsigned TM (same txid), which embeds
    /// the new treasury address as its change output. Identical txids across all
    /// instances ⇒ identical Y_51 ⇒ identical treasury address.
    async fn multi_instance_same_treasury(n: u16, t: u16) {
        let fixture = demo_static_fixture(t, n, 18_600);
        let hub = MockPeerHub::new();

        let mut handles = Vec::new();
        for i in 1..=n {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture.clone()));
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = fast_config(id);
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }

        let mut tms = Vec::new();
        for h in handles {
            tms.push(h.await.unwrap().expect("epoch cycle completes"));
        }

        // All instances built the byte-identical treasury movement: same txid,
        // and (no pegins / no pegouts in the fixture) exactly one output — the
        // new treasury change locked under the freshly derived group key.
        let txid0 = tms[0].txid;
        for tm in &tms[1..] {
            assert_eq!(
                tm.txid, txid0,
                "all SPOs must derive the identical TM / treasury address"
            );
        }
        let change_spk = &tms[0].unsigned_tx.output[0].script_pubkey;
        assert!(
            change_spk.is_p2tr(),
            "treasury change must be a P2TR (taproot) output"
        );
        for tm in &tms[1..] {
            assert_eq!(
                &tm.unsigned_tx.output[0].script_pubkey, change_spk,
                "the new treasury scriptPubKey must be identical across SPOs"
            );
        }
    }

    #[tokio::test]
    async fn full_cycle_2_of_2_all_derive_same_treasury() {
        multi_instance_same_treasury(2, 2).await;
    }

    /// WI-014 #5 restart recovery: with a persisted DKG for the epoch,
    /// `epoch_start_phase` reloads the share and jumps to PublishKeys instead of
    /// re-running the ceremony; without it, it proceeds to a fresh DKG.
    #[tokio::test]
    async fn epoch_start_resumes_from_persisted_dkg() {
        use crate::epoch::persist::{PersistedDkg, write_dkg_state};
        use crate::epoch::state::SpoInfo;
        use crate::frost::participant;
        use std::collections::BTreeMap;

        // A real 2-of-2 DKG → node 1's KeyPackage + group package + roster.
        let id1 = Identifier::try_from(1u16).unwrap();
        let id2 = Identifier::try_from(2u16).unwrap();
        let mut rng = rand::thread_rng();
        let (s1, p1) = participant::dkg_part1(id1, 2, 2, &mut rng).unwrap();
        let (s2, p2) = participant::dkg_part1(id2, 2, 2, &mut rng).unwrap();
        let r1_1: BTreeMap<_, _> = [(id2, p2)].into_iter().collect();
        let r1_2: BTreeMap<_, _> = [(id1, p1)].into_iter().collect();
        let (s1r2, _) = participant::dkg_part2(s1, &r1_1).unwrap();
        let (_, pk2) = participant::dkg_part2(s2, &r1_2).unwrap();
        let r2_1: BTreeMap<_, _> = [(id2, pk2.get(&id1).unwrap().clone())]
            .into_iter()
            .collect();
        let (kp1, pkp1) = participant::dkg_part3(&s1r2, &r1_1, &r2_1).unwrap();
        let group_keys = GroupKeys {
            verifying_key: *pkp1.verifying_key(),
            public_key_package: pkp1,
            key_package: kp1,
        };
        let mut participants = BTreeMap::new();
        for i in 1u16..=2 {
            let id = Identifier::try_from(i).unwrap();
            participants.insert(
                id,
                SpoInfo {
                    identifier: id,
                    pool_id: vec![i as u8; 28],
                    bifrost_url: format!("http://127.0.0.1:{}", 18700 + i),
                    bifrost_id_pk: vec![i as u8; 32],
                },
            );
        }
        let roster = Roster {
            epoch: 0,
            min_signers: 2,
            max_signers: 2,
            participants,
        };

        let dir = std::env::temp_dir().join(format!("heimdall-resume-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_dkg_state(
            &dir,
            &PersistedDkg::from_output(0, 0, &roster, &group_keys).unwrap(),
        )
        .unwrap();

        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(demo_static_fixture(2, 2, 18_700)));
        let mut config = fast_config(id1);
        config.state_dir = Some(dir.clone());

        // With persisted state → resume straight to PublishKeys (no DKG).
        match epoch_start_phase(&chain, &config, 0).await.unwrap() {
            EpochPhase::PublishKeys { group_keys: gk, .. } => {
                assert_eq!(gk.verifying_key, group_keys.verifying_key);
                assert_eq!(*gk.key_package.identifier(), id1);
            }
            other => panic!("expected resume to PublishKeys, got {}", other.name()),
        }

        // No persisted state → fresh DKG (the mock chain serves the context).
        config.state_dir = None;
        assert!(matches!(
            epoch_start_phase(&chain, &config, 0).await.unwrap(),
            EpochPhase::Dkg { .. }
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn full_cycle_3_of_3_all_derive_same_treasury() {
        multi_instance_same_treasury(3, 3).await;
    }
}
