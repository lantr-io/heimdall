//! Epoch state machine driver.
//!
//! `run_epoch_loop` repeatedly matches on `EpochPhase` and dispatches to
//! the right phase function. The remaining "glue" phases that are not
//! big enough to deserve their own module live here:
//!
//! TODO: nothing in this module (or anywhere in the codebase) touches
//! the watchtower / Binocular oracle path. A real SPO must verify
//! peg-in deposits have ≥100 Bitcoin confirmations before sweeping
//! them, and produce merkle inclusion proofs for the Cardano oracle.
//! Today `BuildTm` blindly trusts whatever `query_pegin_requests`
//! returns. CLAUDE.md describes the watchtower architecture; the
//! state machine needs to grow phases (or pre-`BuildTm` checks) for
//! header validation and inclusion proof construction.
//!
//! - `idle_phase`         — block until the chain reports an epoch boundary
//! - `epoch_start_phase`  — snapshot the roster
//! - `publish_keys_phase` — log the group key (no-op for the first cycle)
//! - `build_tm_phase`     — pull treasury / pegins / pegouts and build the
//!                          unsigned Bitcoin tx + sighashes
//! - `submit_phase`       — assemble the witnessed tx, verify each
//!                          per-input signature under the on-chain
//!                          output key, hand bytes to the chain
//! - `await_confirm_phase`— terminal for the first cycle: returns the
//!                          signed `TreasuryMovement` to the caller
//!
//! `Dkg` and `Sign` are dispatched to `dkg::dkg_phase` and
//! `signing::sign_phase` respectively.

use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, UntweakedPublicKey};
use bitcoin::{Witness};
use frost_secp256k1_tr as frost;

use crate::bitcoin::taproot::treasury_spend_info;
use crate::bitcoin::tm_builder::{
    build_tm, compute_sighashes, FeeParams, PegInInput, PegOutRequest, TreasuryInput,
};
use crate::epoch::dkg::dkg_phase;
use crate::epoch::signing::sign_phase;
use crate::epoch::state::{
    CascadeLevel, DkgCollected, DkgRound, EpochConfig, EpochError, EpochPhase, EpochResult,
    GroupKeys, Roster, SignCollected, SigningRound, TreasuryMovement,
};
use crate::epoch::traits::{CardanoChain, Clock, PeerNetwork};

/// Run the epoch state machine for one full cycle and return the
/// witnessed `TreasuryMovement` once the cycle reaches `AwaitConfirm`.
///
/// The first-cycle scope: `await_epoch_boundary` fires once, the loop
/// runs DKG → BuildTm → Sign → Submit → AwaitConfirm and then exits.
/// Future cuts will instead loop back to `Idle` and wait for the next
/// boundary.
pub async fn run_epoch_loop(
    chain: Arc<dyn CardanoChain>,
    peers: Arc<dyn PeerNetwork>,
    clock: Arc<dyn Clock>,
    config: &EpochConfig,
) -> EpochResult<TreasuryMovement> {
    let me = config.identity.identifier;
    let mut phase = EpochPhase::Idle;
    loop {
        crate::epoch_log!(me, current_epoch(&phase), "==> phase = {}", phase.name());
        phase = match phase {

            EpochPhase::Idle => idle_phase(&chain).await?,

            EpochPhase::EpochStart { epoch } => epoch_start_phase(&chain, epoch).await?,

            EpochPhase::Dkg {
                epoch,
                round,
                roster,
                collected,
            } => dkg_phase(&peers, &clock, config, epoch, round, roster, collected).await?,

            EpochPhase::PublishKeys {
                epoch,
                roster,
                group_keys,
            } => publish_keys_phase(epoch, roster, group_keys).await?,

            EpochPhase::BuildTm {
                epoch,
                roster,
                group_keys,
            } => build_tm_phase(&chain, epoch, roster, group_keys).await?,

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
                    &peers, &clock, config, epoch, roster, cascade, group_keys, tm, round,
                    collected,
                )
                .await?
            }

            EpochPhase::Submit {
                epoch,
                tm,
                leader_attempt,
            } => submit_phase(&chain, me, epoch, tm, leader_attempt).await?,

            EpochPhase::AwaitConfirm { tm, .. } => {
                // First-cycle terminal: return the signed TM.
                //
                // TODO: in steady state this phase should poll the
                // chain for inclusion of `cardano_tx_id` (once submit
                // actually produces one), then transition back to
                // `Idle` to wait for the next epoch boundary. Today we
                // exit the loop unconditionally.
                return Ok(tm);
            }
        };
    }
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
    epoch: u64,
) -> EpochResult<EpochPhase> {
    let roster = chain.query_roster(epoch).await?;
    Ok(EpochPhase::Dkg {
        epoch,
        round: DkgRound::Round1,
        roster,
        collected: DkgCollected::default(),
    })
}

// ---------------------------------------------------------------------------
// publish_keys
// ---------------------------------------------------------------------------

async fn publish_keys_phase(
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
) -> EpochResult<EpochPhase> {
    // No on-chain publication in the first cycle. Just log so the demo
    // shows the derived group key, then move on.
    //
    // TODO: real PublishKeys should post the new group verifying key
    // and the derived treasury Taproot address to Cardano, atomic with
    // the epoch transition, so the next roster knows where to sweep.
    // This is the "treasury handoff" step — see `TreasuryUtxo` docs.
    let vk = group_keys
        .verifying_key
        .serialize()
        .map_err(|e| EpochError::Frost(format!("verifying_key serialize: {e}")))?;
    let me = *group_keys.key_package.identifier();
    crate::epoch_log!(
        me, epoch,
        "PublishKeys: group_key = {} (no on-chain publish in first cycle)",
        hex::encode(&vk)
    );
    Ok(EpochPhase::BuildTm {
        epoch,
        roster,
        group_keys,
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
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();
    crate::epoch_log!(me, epoch, "BuildTm: querying chain for treasury / pegins / pegouts");
    let treasury = chain.query_treasury().await?;
    let pegins = chain.query_pegin_requests().await?;
    let pegouts = chain.query_pegout_requests().await?;
    crate::epoch_log!(
        me, epoch,
        "  chain query: treasury={} sat, {} pegins, {} pegouts, fee_rate={}sat/vb",
        treasury.value.to_sat(),
        pegins.len(),
        pegouts.len(),
        treasury.fee_rate_sat_per_vb,
    );

    let secp = Secp256k1::new();
    let y_51 = frost_vk_to_xonly(&group_keys.verifying_key)?;

    // Build the spend info for the current treasury and for every peg-in
    // input. The leaf keys (`y_67`, `y_fed`) come from the chain query;
    // the internal key Y_51 is the just-derived FROST group key. Peg-ins
    // for the first cycle reuse the treasury script tree shape — there
    // is no per-depositor refund leaf yet.
    //
    // FIXME: this is bootstrap-only. In steady state the treasury
    // *input* is locked under epoch N-1's group key while the *change
    // output* uses epoch N's. We need to thread the previous epoch's
    // verifying key through `EpochPhase` (or query it from the chain)
    // and use it here for the input spend info.
    let treasury_spend = treasury_spend_info(
        &secp,
        y_51,
        treasury.y_67,
        treasury.y_fed,
        treasury.federation_csv_blocks as u16,
    );
    let change_script = bitcoin::ScriptBuf::new_p2tr_tweaked(treasury_spend.output_key());

    // TODO: real peg-ins use `pegin_spend_info(...)` with a per-depositor
    // pubkey hash + refund timeout, not the treasury script tree.
    let pegin_inputs: Vec<PegInInput> = pegins
        .into_iter()
        .map(|p| PegInInput {
            outpoint: p.outpoint,
            value: p.value,
            spend_info: treasury_spend_info(
                &secp,
                y_51,
                treasury.y_67,
                treasury.y_fed,
                treasury.federation_csv_blocks as u16,
            ),
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
            spend_info: treasury_spend,
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
        me, epoch,
        "  -> built unsigned tx: txid={} ({num_inputs} inputs)",
        tm.txid
    );

    Ok(EpochPhase::Sign {
        epoch,
        roster,
        cascade: CascadeLevel::Quorum67,
        group_keys,
        tm,
        round: SigningRound::Round1,
        collected: SignCollected::default(),
    })
}

// ---------------------------------------------------------------------------
// submit
// ---------------------------------------------------------------------------

// TODO: leader election and leader-timeout cascade. Currently, every SPO
// submits the tx from their own process (via their own chain mock);
// in production one designated SPO broadcasts the Bitcoin tx and, if
// `leader_timeout` expires without confirmation, `leader_attempt`
// increments and a new leader is selected. `_leader_attempt` is
// parked in the phase enum for exactly this purpose but ignored here.
async fn submit_phase(
    chain: &Arc<dyn CardanoChain>,
    me: frost_secp256k1_tr::Identifier,
    epoch: u64,
    mut tm: TreasuryMovement,
    _leader_attempt: u8,
) -> EpochResult<EpochPhase> {
    let secp = Secp256k1::new();

    // Verify each per-input signature against its tweaked output key
    // before assembling the witnesses. This catches a broken signing
    // path before we hand bytes to the chain.
    crate::epoch_log!(
        me, epoch,
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
        let xonly = tm.input_spend_info[i]
            .output_key()
            .to_x_only_public_key();
        let msg = bitcoin::secp256k1::Message::from_digest(tm.sighashes[i]);
        secp.verify_schnorr(&schnorr, &msg, &xonly)
            .map_err(|e| EpochError::SignatureVerify(i, e.to_string()))?;
        crate::epoch_log!(me, epoch, "  input {i}: schnorr sig verifies under output key");
    }

    // Build the final witnessed transaction (key-path spend on every input).
    let mut signed_tx = tm.unsigned_tx.clone();
    for (i, txin) in signed_tx.input.iter_mut().enumerate() {
        let sig = tm.signatures[i]
            .as_ref()
            .expect("checked above")
            .serialize()
            .map_err(|e| EpochError::Frost(format!("sig serialize: {e}")))?;
        let schnorr = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig)
            .expect("verified above");
        let tap_sig = bitcoin::taproot::Signature {
            signature: schnorr,
            sighash_type: bitcoin::sighash::TapSighashType::Default,
        };
        txin.witness = Witness::p2tr_key_spend(&tap_sig);
    }

    let tx_bytes = bitcoin::consensus::encode::serialize(&signed_tx);
    chain.submit_signed_tm(&tx_bytes).await?;

    // Persist the witnessed tx back into `tm` so callers can inspect it.
    tm.unsigned_tx = signed_tx;

    crate::epoch_log!(
        me, epoch,
        "Submit: signed tx assembled and handed to chain mock; \
         txid = {} ({} bytes)",
        tm.txid,
        tx_bytes.len()
    );

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
        EpochPhase::EpochStart { epoch }
        | EpochPhase::Dkg { epoch, .. }
        | EpochPhase::PublishKeys { epoch, .. }
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
