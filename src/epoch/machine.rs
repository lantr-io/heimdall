//! Epoch state machine driver.
//!
//! `run_epoch_loop` repeatedly matches on `EpochPhase` and dispatches to
//! the right phase function. Glue phases that are not big enough to
//! deserve their own module live here:
//!
//! - `idle_phase`          — block until the chain reports an epoch boundary
//! - `epoch_start_phase`   — snapshot the roster
//! - `publish_keys_phase`  — publish the group key: BIP-340 x-only + Update-Y handoff
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
use bitcoin::key::Secp256k1;
use frost_secp256k1_tr as frost;

use crate::bitcoin::taproot::treasury_spend_info;
use crate::bitcoin::tm_builder::{
    FeeParams, Freshness, PegInInput, PegOutRequest, TreasuryInput, build_tm, compute_sighashes,
};
use crate::cardano::pegin_datum::{ParsedPegIn, parse_pegin_request};
use crate::cardano::pegin_source::{CardanoOutRef, CardanoPegInSource};
use crate::epoch::dkg::dkg_phase;
use crate::epoch::rotation;
use crate::epoch::signing::sign_phase;
use crate::epoch::state::{
    CascadeLevel, DKG_ATTEMPTS_PER_WINDOW, DkgCollected, DkgRound, EpochConfig, EpochError,
    EpochPhase, EpochResult, GroupKeys, Roster, SignCollected, SigningRound, TreasuryMovement,
};
use crate::epoch::traits::{CardanoChain, Clock, PeerNetwork, RngSource};
use crate::frost::xonly::group_xonly;
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
            // EVERY in-loop error backs off and re-enters Idle. The loop never
            // terminates.
            //
            // It used to exit on anything outside a small retriable allowlist,
            // and that allowlist was the bug: a peer on a different candidate
            // set sent a package FROST rejected, heimdall classified the FROST
            // error as fatal, and an honest node's epoch loop died for good —
            // frozen on a stale roster while its HTTP server kept answering. It
            // could not recover, because recovering means re-deriving the roster
            // from chain and only this loop does that. One ban could take out an
            // honest node; enough of them walk the roster below quorum.
            //
            // The spec is explicit that a failed ceremony is not terminal: "no
            // Update-Y is posted... the old roster simply carries over... the
            // next epoch boundary takes fresh snapshots and retries the DKG. No
            // halt, no special state." Re-entering Idle re-derives from chain,
            // which is what makes a stale node self-heal.
            //
            // Genuinely unrecoverable conditions (missing keys, unparseable
            // config, an identity absent from the registry) are STARTUP
            // validation and must fail before the loop is entered — not here,
            // where the only correct answer is to keep trying.
            Err(e) => {
                // Post-ban recovery (chain-view reconcile): if this failure came
                // with a detected chain-view disagreement on which we are the
                // STALE side (older blockchain read-time), a blind fast retry
                // would just re-read the same unsettled tip and churn — the real
                // chain returns the current epoch immediately, so the back-off IS
                // the re-read cadence. Wait a settling interval so the next
                // re-read lands AFTER the disagreeing event settles into our
                // view; the fresher-read nodes don't wait. Otherwise the ordinary
                // capped exponential.
                let wait = if peers.is_view_stale().await {
                    crate::epoch_log!(
                        me,
                        current_epoch(&EpochPhase::Idle),
                        "error: {e}; STALE chain-view — settling back-off {:?} before re-read \
                         (reconcile), then re-entering Idle",
                        config.dkg_reconcile_backoff
                    );
                    backoff = RETRY_BACKOFF_MIN; // the settling wait replaces the ramp
                    config.dkg_reconcile_backoff
                } else {
                    crate::epoch_log!(
                        me,
                        current_epoch(&EpochPhase::Idle),
                        "error: {e}; backing off {:?} then re-entering Idle",
                        backoff
                    );
                    let w = backoff;
                    backoff = (backoff * 2).min(RETRY_BACKOFF_MAX);
                    w
                };
                tokio::time::sleep(wait).await;
                phase = EpochPhase::Idle;
            }
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

        EpochPhase::EpochStart { epoch } => epoch_start_phase(chain, peers, config, epoch).await?,

        EpochPhase::Dkg {
            round,
            ctx,
            collected,
        } => dkg_phase(chain, peers, clock, rng, config, round, ctx, collected).await?,

        EpochPhase::PublishKeys {
            epoch,
            roster,
            group_keys,
        } => {
            publish_keys_phase(chain, peers, clock, rng, config, epoch, roster, group_keys).await?
        }

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
        } => build_tm_phase(chain, config, epoch, roster, group_keys, frozen_pegins).await?,

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

        EpochPhase::AwaitConfirm { epoch, tm, .. } => {
            await_confirm_phase(chain, config, epoch, &tm).await?;
            return Ok(Step::Done(tm));
        }
    };
    Ok(Step::Next(next))
}

/// Wait for every SPO to observe this exact movement as the confirmed
/// treasury tip. The leader has already waited for Cardano oracle inclusion;
/// followers use this chain-level check to converge on the same result.
async fn await_confirm_phase(
    chain: &Arc<dyn CardanoChain>,
    config: &EpochConfig,
    epoch: u64,
    tm: &TreasuryMovement,
) -> EpochResult<()> {
    let deadline = tokio::time::Instant::now() + config.tm_confirmation_timeout;
    loop {
        if chain.is_tm_confirmed(&tm.txid).await? {
            crate::epoch_log!(
                config.identity.identifier,
                epoch,
                "AwaitConfirm: treasury movement {} is confirmed",
                tm.txid
            );
            advance_cpo_trie(config, epoch, tm)?;
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(EpochError::Chain(format!(
                "treasury movement {} was not confirmed before timeout ({:?})",
                tm.txid, config.tm_confirmation_timeout
            )));
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

/// Fold a CONFIRMED TM's peg-outs into this node's persisted completed-peg-outs
/// trie.
///
/// Only after confirmation: an in-flight TM can still be replaced (RBF) or simply
/// never mine, and a trie that recorded it would then attest a root no chain state
/// backs — every later TM this node builds would be refused by its peers.
///
/// The post-insert root MUST equal the root the TM committed. If it does not, the
/// node's view and the quorum's have diverged and the trie is NOT written: a wrong
/// trie is worse than a stale one, because the stale one fails loudly at the next
/// signing round while the wrong one signs confidently wrong roots.
///
/// A node without `state_dir` keeps no trie, so there is nothing to advance.
fn advance_cpo_trie(config: &EpochConfig, epoch: u64, tm: &TreasuryMovement) -> EpochResult<()> {
    use crate::cardano::cpo_trie::{CpoEntry, CpoTrie};

    let me = config.identity.identifier;
    let Some(dir) = config.state_dir.as_deref() else {
        return Ok(());
    };
    let mut trie = CpoTrie::load(dir)
        .map_err(|e| EpochError::TmBuild(format!("completed-peg-outs trie: {e}")))?
        .unwrap_or_default();

    let entries: Vec<CpoEntry> = tm.fulfilled.iter().map(CpoEntry::from).collect();
    let new_root = trie
        .insert_batch(&entries)
        .map_err(|e| EpochError::TmBuild(format!("completed-peg-outs trie: {e}")))?;
    if new_root != tm.cpo_root {
        return Err(EpochError::TmBuild(format!(
            "completed-peg-outs trie diverged: TM {} committed root {} but this node's trie \
             reaches {} after inserting its {} fulfilled peg-out(s) — NOT persisting; run \
             `reconstruct-cpo-trie`",
            tm.txid,
            hex::encode(tm.cpo_root),
            hex::encode(new_root),
            entries.len(),
        )));
    }
    trie.save(dir)
        .map_err(|e| EpochError::TmBuild(format!("completed-peg-outs trie: {e}")))?;
    crate::epoch_log!(
        me,
        epoch,
        "  completed-peg-outs trie advanced to root {} ({} entr(y|ies))",
        hex::encode(new_root),
        trie.len(),
    );
    Ok(())
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
    peers: &Arc<dyn PeerNetwork>,
    config: &EpochConfig,
    epoch: u64,
) -> EpochResult<EpochPhase> {
    // Build the stake-aware DKG context for attempt 0. A failed attempt reruns
    // over a reduced candidate set with a bumped attempt inside `dkg_phase`
    // (DkgContext::reduced_to), so the chain is queried once per ceremony
    // entry (which also refreshes the roster after an aborted window).
    let mut ctx = chain.query_dkg_context(epoch, 0).await?;

    // Re-derive THIS node's index from the CURRENT context, every epoch. The
    // FROST index is positional — rank in the sorted eligible set — so it
    // shifts whenever the set changes: a ban removes an earlier member and
    // everyone after it moves up by one. Reading the frozen startup value here
    // is what wedged the cluster post-ban (2026-07-22): each node kept building
    // round-1 payloads under its OLD index while peers reconstructed them under
    // the NEW one, so every honest node rejected every other with an opaque
    // `poseidon_commit mismatch`. `own_participant` looks this node up by its
    // stable bifrost key, so it always returns the correct current index.
    let me = if config.identity.bifrost_id_pk.is_empty() {
        // Fixture / --index demo: no on-chain key. Must NOT look up an empty key
        // in the roster — `own_participant(&[])` would spuriously match the first
        // participant that also has an empty key. Trust the configured index.
        config.identity.identifier
    } else {
        match ctx.own_participant(&config.identity.bifrost_id_pk) {
            Some(p) => p.identifier,
            // We hold a key but are not in this epoch's eligible set — banned,
            // deregistered, or URL-excluded. Sit the epoch out: this is
            // retriable, so the loop backs off and re-enters Idle, and a
            // temporary ban that later expires lets us rejoin automatically.
            None => {
                return Err(EpochError::DkgAborted {
                    epoch,
                    attempt: 0,
                    qualified: 0,
                    eligible: ctx.participants.len(),
                    reason:
                        "this node is not in the eligible set (banned / deregistered / excluded)"
                            .into(),
                });
            }
        }
    };

    // Restart recovery (WI-014 #5): if this epoch's DKG already ran and was
    // persisted, reload the share and skip straight to PublishKeys — the
    // ceremony is multi-round and expensive, and a mid-epoch crash must not
    // re-run it (or lose the share). Keyed by the re-derived `me`, so a resume
    // matches only the share written under this epoch's actual index.
    if let Some(resumed) = try_resume_dkg(config, me, epoch)? {
        return Ok(resumed);
    }

    // N21 health gate: bring the roster up before the ceremony. A staggered
    // process start otherwise freezes divergent live subsets — the early
    // nodes complete a reduced key without the late one, which then loops
    // forever against their stale round-1 packages. Time-bounded: a peer
    // that stays down is excluded by the normal quorum-gated reduction.
    wait_for_roster_health(peers, &ctx, config, me).await;

    // N21 ceremony window grid: with a chain-time anchor, join at the next
    // grid line so every node — however late it started, or re-entering
    // after an abort — runs the same ceremony schedule under a per-window
    // attempt namespace (stale packages from an earlier window can never be
    // fetched into this one). Without an anchor (mock / no-registry
    // fallback) the health gate alone aligns entries to within a poll
    // interval and the relative round deadlines apply as before.
    if let Some(boundary_ms) = ctx.schedule_anchor_ms {
        let now_ms = crate::epoch::dkg::wall_now_ms();
        let (window, window_start_ms) = next_window(boundary_ms, config.dkg_window, now_ms);
        let wait_ms = window_start_ms.saturating_sub(now_ms);
        ctx.attempt = window.saturating_mul(DKG_ATTEMPTS_PER_WINDOW);
        ctx.schedule_anchor_ms = Some(window_start_ms);
        crate::epoch_log!(
            me,
            epoch,
            "joining ceremony window {window} in {:.1}s (attempt base {})",
            wait_ms as f64 / 1000.0,
            ctx.attempt
        );
        // INSTRUMENTATION (2026-07-22): the derived context, printed so the SAME
        // line from every node can be diffed. A payload's poseidon_commit binds
        // (epoch, threshold=51, attempt, identifier); `t` and the candidate set
        // determine the commitment-vector length and the index assignment but
        // appear NOWHERE in the namespace — so if two nodes disagree here they
        // reject each other's honest payloads with no way to notice. This line
        // makes that disagreement visible directly instead of by inference.
        crate::epoch_log!(
            me,
            epoch,
            "ceremony ctx: t={} n={} attempt={} window={} anchor_ms={:?} candidates=[{}]",
            ctx.threshold,
            ctx.participants.len(),
            ctx.attempt,
            window,
            ctx.schedule_anchor_ms,
            ctx.participants
                .iter()
                .map(|p| format!(
                    "{}@{}",
                    hex::encode(&p.pool_id[..4.min(p.pool_id.len())]),
                    p.index
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        if wait_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(wait_ms as u64)).await;
        }
    }

    Ok(EpochPhase::Dkg {
        round: DkgRound::Round1,
        ctx,
        collected: DkgCollected::default(),
    })
}

/// Ceremony-window grid arithmetic (N21): the index and start (Unix ms) of the
/// next grid line strictly after `now_ms`, on the grid anchored at
/// `boundary_ms` with pitch `window`. A node starting before the boundary
/// joins window 0 at the boundary itself.
fn next_window(boundary_ms: i64, window: std::time::Duration, now_ms: i64) -> (u32, i64) {
    let w = i64::try_from(window.as_millis()).unwrap_or(i64::MAX).max(1);
    let elapsed = now_ms.saturating_sub(boundary_ms);
    let k = if elapsed < 0 { 0 } else { elapsed / w + 1 };
    (
        u32::try_from(k).unwrap_or(u32::MAX),
        boundary_ms.saturating_add(k.saturating_mul(w)),
    )
}

/// Poll every roster peer's `/health` until all answer or `dkg_join_wait`
/// elapses (N21). Never fails: proceeding without a peer is always legal —
/// the ceremony's quorum gate decides viability, this gate only makes the
/// happy path start complete.
async fn wait_for_roster_health(
    peers: &Arc<dyn PeerNetwork>,
    ctx: &crate::cardano::dkg_roster::DkgContext,
    config: &EpochConfig,
    me: frost::Identifier,
) {
    let roster = ctx.to_roster();
    let deadline = tokio::time::Instant::now() + config.dkg_join_wait;
    let poll = config
        .poll_interval
        .max(std::time::Duration::from_millis(200));
    loop {
        let mut down = Vec::new();
        for info in roster.participants.values() {
            if info.identifier == me {
                continue;
            }
            if !peers.check_health(info).await {
                down.push(crate::epoch::log::id_short(info.identifier));
            }
        }
        if down.is_empty() {
            crate::epoch_log!(me, ctx.epoch, "health gate: full roster reachable");
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            crate::epoch_log!(
                me,
                ctx.epoch,
                "health gate: proceeding without unreachable peer(s) {:?} after {:?}",
                down,
                config.dkg_join_wait
            );
            return;
        }
        crate::epoch_log!(
            me,
            ctx.epoch,
            "health gate: waiting for peer(s) {:?}...",
            down
        );
        tokio::time::sleep(poll).await;
    }
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

#[allow(clippy::too_many_arguments)]
async fn publish_keys_phase(
    chain: &Arc<dyn CardanoChain>,
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();
    let group = group_xonly(&group_keys.verifying_key).map_err(EpochError::Frost)?;
    let y_51 = group.xonly;

    crate::epoch_log!(
        me,
        epoch,
        "PublishKeys: group_key = {} (derived point parity 0x{:02x}; stored x-only per BIP-340)",
        hex::encode(y_51.serialize()),
        group.parity_byte()
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

    // N10c/N-b: actually hand the treasury over. Deriving Y_51 changes nothing
    // on its own — `treasury_info.current_spos_frost_key` is what the bridge
    // treats as the roster in charge, and until the Update-Y lands the OLD
    // roster still controls it. This is the step that makes a completed
    // ceremony consequential, rather than something an operator has to
    // replicate by hand with the `update-y` CLI.
    //
    // Skipping is normal, not exceptional: `plan_update_y` returns None when
    // the datum already names this key (a re-run, or an unchanged roster
    // re-deriving) and when the backend has no treasury_info state at all.
    match chain.plan_update_y(epoch, y_51).await? {
        None => crate::epoch_log!(
            me,
            epoch,
            "  no Update-Y needed (treasury_info already names this key, or no state to rotate)"
        ),
        Some(plan) => {
            crate::epoch_log!(
                me,
                epoch,
                "  Update-Y: rotating treasury_info {} from {} to {}",
                plan.state_outpoint,
                hex::encode(plan.current_key.serialize()),
                hex::encode(plan.new_key.serialize())
            );
            let (signature, authority) =
                rotation::authorize_update_y(peers, clock, rng, config, me, &plan).await?;
            crate::epoch_log!(me, epoch, "  Update-Y authorized by {authority}");

            // The signature IS the authorization, so one submission suffices and
            // a second would only burn a fee losing the race for the same input.
            // Everyone else holds a verified signature and would take over on a
            // leader cascade.
            let leader = roster.leader(0);
            if me == leader {
                let tx_id = chain.submit_update_y(&plan, &signature).await?;
                crate::epoch_log!(me, epoch, "  Update-Y submitted: cardano tx {tx_id}");
            } else {
                crate::epoch_log!(
                    me,
                    epoch,
                    "  Update-Y: follower (leader = {:?}) — signature verified, not submitting",
                    leader
                );
            }
        }
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

/// Load this node's completed-peg-outs trie from `state_dir`.
///
/// A missing file is the genesis state (empty trie, root = 32 zero bytes — the
/// same root the Aiken bootstrap mint pins), NOT an error: a bridge that has
/// completed no peg-out is exactly in that state. A file that exists but is
/// corrupt IS an error — signing a root derived from corrupt state would attest
/// something this node cannot justify.
///
/// A node that joined a bridge with existing history must run
/// `reconstruct-cpo-trie` first; starting empty there means every root it
/// proposes is wrong and every root it verifies is refused, which is loud.
///
/// Loading says nothing about whether the file still describes the deployment
/// this node is signing for — [`cross_check_cpo_root`] is what decides that, and
/// `BuildTm` runs it on the result before anything is built.
fn load_cpo_trie(
    state_dir: Option<&std::path::Path>,
    me: frost::Identifier,
    epoch: u64,
) -> EpochResult<crate::cardano::cpo_trie::CpoTrie> {
    use crate::cardano::cpo_trie::CpoTrie;
    let Some(dir) = state_dir else {
        crate::epoch_log!(
            me,
            epoch,
            "  completed-peg-outs trie: no protocol.state_dir configured — using the empty \
             (genesis) trie; set state_dir before paying peg-outs on a live bridge"
        );
        return Ok(CpoTrie::empty());
    };
    match CpoTrie::load(dir).map_err(|e| EpochError::TmBuild(e.to_string()))? {
        Some(t) => {
            crate::epoch_log!(
                me,
                epoch,
                "  completed-peg-outs trie: {} entr(y|ies), root {}",
                t.len(),
                hex::encode(t.root())
            );
            Ok(t)
        }
        None => {
            crate::epoch_log!(
                me,
                epoch,
                "  completed-peg-outs trie: no persisted state at {} — using the empty (genesis) \
                 trie; run `reconstruct-cpo-trie` if this bridge already has history",
                dir.display()
            );
            Ok(CpoTrie::empty())
        }
    }
}

/// Refuse to attest a completed-peg-outs root the chain does not hold.
///
/// [`load_cpo_trie`] trusts `cpo-trie.json` verbatim, and an ABSENT file is the
/// only path to the genesis trie — so a re-bootstrap, which mints a FRESH
/// zero-root CPO singleton while the state directory still holds the previous
/// deployment's populated trie, leaves this node ready to commit a root that
/// deployment no longer has. Peers reject that TM; a quorum of equally stale
/// nodes attests it and produces membership proofs `peg-out.ak` refuses.
///
/// The on-chain singleton is the only check that covers the whole trie — every
/// per-movement assertion in `reconstruct` is relative to the previous movement,
/// so a trie that is right about its entries and short by a movement passes them
/// all. Run before `build_tm`, so nothing is signed off a stale trie.
///
/// `None` from the chain is "not configured", not "empty": it warns and proceeds,
/// because a node with no `cardano.cpo_policy_id` cannot tell the two apart. It
/// returns [`CpoTrust::Unverified`] in that case — since WI-031 the trie is the SOLE
/// already-paid authority, so "not cross-checked" has to be a value the caller can act
/// on, not just a log line.
async fn cross_check_cpo_root(
    chain: &Arc<dyn CardanoChain>,
    cpo_trie: &crate::cardano::cpo_trie::CpoTrie,
    state_dir: Option<&std::path::Path>,
    me: frost::Identifier,
    epoch: u64,
) -> EpochResult<CpoTrust> {
    let local = cpo_trie.root();
    match chain.query_cpo_root().await? {
        Some(on_chain) if on_chain != local => Err(EpochError::TmBuild(format!(
            "completed-peg-outs trie is out of sync with the chain: local root {} ({} entries) \
             != on-chain CPO singleton root {}. Refusing to attest — a TM built on a stale trie \
             commits a root the chain does not hold. Rebuild with `reconstruct-cpo-trie` (and \
             delete the stale {}/cpo-trie.json if the bridge was re-bootstrapped).",
            hex::encode(local),
            cpo_trie.len(),
            hex::encode(on_chain),
            state_dir.map_or_else(
                || "<protocol.state_dir>".to_string(),
                |d| d.display().to_string()
            ),
        ))),
        Some(on_chain) => {
            crate::epoch_log!(
                me,
                epoch,
                "  completed-peg-outs trie: root matches the on-chain CPO singleton ({})",
                hex::encode(on_chain)
            );
            Ok(CpoTrust::Verified)
        }
        None => {
            crate::epoch_log!(
                me,
                epoch,
                "  completed-peg-outs trie: WARNING: no cpo_policy_id configured — the local root \
                 was NOT cross-checked against the on-chain CPO singleton. Set \
                 cardano.cpo_policy_id before trusting this trie to sign with."
            );
            Ok(CpoTrust::Unverified)
        }
    }
}

/// Whether this node's completed-peg-outs trie may be trusted to decide which peg-outs
/// an earlier movement already paid.
///
/// Since WI-031 the trie is the ONLY already-paid record: the `(destination, net sat)`
/// multiset that used to run in front of it could never be keyed by request identity —
/// a `Confirmed` TM datum carries `fulfilled_peg_outs: [{scriptPubKey, amount}]` and
/// nothing else, and `fulfilled_por_outpoints` lives only on `Unconfirmed` and is
/// explicitly an unverified hint — so it strands a re-created identical withdrawal
/// forever. The trie is keyed by `por_id` and cannot.
///
/// The price of removing it is that an untrustworthy trie is no longer backstopped by
/// anything, so `Unverified` must mean "pay no peg-out", never "pay unchecked".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpoTrust {
    /// Cross-checked against the on-chain CPO singleton — safe to decide payment with.
    Verified,
    /// No `cardano.cpo_policy_id`, so the local root was never checked against the
    /// chain. The trie may be stale, or belong to a previous deployment.
    Unverified,
}

async fn build_tm_phase(
    chain: &Arc<dyn CardanoChain>,
    config: &EpochConfig,
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

    // Open peg-outs on Cardano. A request UTxO survives at the `peg_out.ak` address until
    // someone completes it — which needs this TM's Bitcoin confirmation plus a membership
    // proof, hours later or never — so this set keeps returning withdrawals earlier movements
    // already paid. What filters them is the completed-peg-outs trie, keyed by `por_id`
    // (`build_tm`'s `AlreadyCompleted` skip), loaded and cross-checked below.
    //
    // WI-031 deleted the `(destination scriptPubKey, net sat)` multiset that used to run in
    // front of it. That key could never carry request identity — a `Confirmed` TM datum holds
    // `fulfilled_peg_outs: [{scriptPubKey, amount}]` and nothing more, and the
    // `fulfilled_por_outpoints` hint exists only on `Unconfirmed` and is explicitly unverified
    // — so a credit left by a long-completed withdrawal was indistinguishable from an unpaid
    // one, and a user re-requesting the same round amount to the same address was stranded
    // permanently. The window it nominally covered (paid on Bitcoin, not yet confirmed, so not
    // yet folded into the trie) is already closed above: `query_treasury` blocks until
    // `btc_confirmed`, so this node never builds a second TM while one is in flight.
    let pegouts = chain.query_pegout_requests().await?;
    crate::epoch_log!(
        me,
        epoch,
        "  chain query: treasury={} sat, {} frozen pegins, {} open pegouts, fee_rate={}sat/vb",
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
    let new_y_51 = group_xonly(&group_keys.verifying_key)
        .map_err(EpochError::Frost)?
        .xonly;
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

    // The completed-peg-outs trie: this node's own copy, which decides both which
    // requests are still owed a payment and the root this TM will commit.
    let cpo_trie = load_cpo_trie(config.state_dir.as_deref(), me, epoch)?;
    let cpo_trust =
        cross_check_cpo_root(chain, &cpo_trie, config.state_dir.as_deref(), me, epoch).await?;

    // The trie is the ONLY already-paid record (WI-031), so a trie this node cannot vouch
    // for must mean "pay no peg-out", not "pay unchecked". Unchecked payment is not a
    // degraded mode: with no dedup every open request is re-paid on EVERY movement, which
    // drains the treasury irrecoverably. Skipping instead costs only latency — the requests
    // stay open and a later movement, on a node that IS configured, pays them.
    //
    // Peg-ins are unaffected: the TM still sweeps them, so a misconfigured node degrades to
    // the peg-in-only behaviour it had before WI-030 rather than stalling the bridge.
    let pegouts = match cpo_trust {
        CpoTrust::Verified => pegouts,
        CpoTrust::Unverified if pegouts.is_empty() => pegouts,
        CpoTrust::Unverified => {
            crate::epoch_log!(
                me,
                epoch,
                "  skipping ALL {} open peg-out(s): the completed-peg-outs trie was not \
                 cross-checked against the chain (no cardano.cpo_policy_id), and it is the only \
                 record of what an earlier movement already paid — paying without it would \
                 re-pay every open request on every movement. Peg-ins are unaffected. Set \
                 cardano.cpo_policy_id (and protocol.state_dir) to pay peg-outs.",
                pegouts.len(),
            );
            Vec::new()
        }
    };

    let pegout_requests: Vec<PegOutRequest> = pegouts
        .into_iter()
        .map(|p| PegOutRequest {
            script_pubkey: p.script_pubkey,
            amount: p.amount,
            per_pegout_fee: p.per_pegout_fee,
            por_id: p.por_id,
            outpoint: p.outpoint,
            created: p.created,
        })
        .collect();

    // Chain "now" for the freshness filter. Read from the chain, not the local
    // clock: it is a skip-rule input, and every SPO must reach the same verdict or
    // the TM bytes diverge.
    let chain_now_ms = chain.chain_now_ms().await?;
    let pegout_freshness_margin_ms = config.pegout_freshness_margin.as_millis() as i64;

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
        },
        &Freshness {
            now_ms: chain_now_ms,
            margin_ms: pegout_freshness_margin_ms,
        },
        &cpo_trie,
    )
    .map_err(|e| EpochError::TmBuild(e.to_string()))?;

    // Surface peg-outs `build_tm`'s output-level skip rule dropped (non-standard
    // destination, sub-dust after the fee). Every SPO drops the same set — that is
    // what keeps the TM bytes identical — so a divergence here is the first place
    // an operator sees a chain-state disagreement. Without this the daemon drops
    // them silently, unlike the CLI sweep path.
    for s in &unsigned.skipped_pegouts {
        crate::epoch_log!(
            me,
            epoch,
            "  skipped peg-out → {} ({} sat): {}",
            hex::encode(s.script_pubkey.as_bytes()),
            s.amount.to_sat(),
            s.reason,
        );
    }

    let sighashes = compute_sighashes(&unsigned);
    let num_inputs = unsigned.tx.input.len();

    let tm = TreasuryMovement {
        txid: unsigned.txid,
        unsigned_tx: unsigned.tx,
        prevouts: unsigned.prevouts,
        input_spend_info: unsigned.input_spend_info,
        sighashes,
        signatures: vec![None; num_inputs],
        fulfilled: unsigned.fulfilled,
        cpo_root: unsigned.cpo_root,
    };

    crate::epoch_log!(
        me,
        epoch,
        "  -> built unsigned tx: txid={} ({num_inputs} inputs), commits completed-peg-outs \
         root {} over {} fulfilled peg-out(s)",
        tm.txid,
        hex::encode(tm.cpo_root),
        tm.fulfilled.len(),
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
        let hint: Vec<[u8; 36]> = tm.fulfilled.iter().map(|f| f.outpoint).collect();
        chain.submit_signed_tm(&tx_bytes, &hint).await?;
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
            bifrost_id_pk: Vec::new(),
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

    // -----------------------------------------------------------------------
    // N10c / N-b: the derived key actually reaches the chain
    // -----------------------------------------------------------------------

    /// The acceptance for N-b: a completed DKG cycle PUBLISHES Y_51 — it rotates
    /// `treasury_info.current_spos_frost_key` through the Update-Y path, with the
    /// outgoing key authorizing the succession.
    ///
    /// This is the bootstrap handoff: the treasury is still keyed to
    /// `y_federation`, so the authorization is a local BIP-340 signature under
    /// the federation seed. The mock chain applies `treasury.ak`'s actual gate —
    /// it verifies the signature under the key being replaced, over the message
    /// pinned to the spent state UTxO — so an unsigned or misdirected rotation
    /// would be rejected here exactly as on-chain.
    ///
    /// Before this wiring the ceremony ended at `publish_group_key`, which only
    /// updated the node's own in-memory view: every SPO derived a treasury the
    /// chain had never heard of.
    #[tokio::test]
    async fn a_completed_dkg_hands_the_treasury_over_via_update_y() {
        let seed = [0x42u8; 32];
        let secp = Secp256k1::new();
        let fed_kp = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&seed).unwrap(),
        );
        let fed_xonly = fed_kp.x_only_public_key().0;
        let state_txid = [0xc3u8; 32];
        let treasury_info = MockCardanoChain::treasury_info_state(fed_xonly, state_txid);

        let fixture = demo_static_fixture(2, 2, 18_900);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(
                MockCardanoChain::new(fixture.clone()).with_treasury_info(treasury_info.clone()),
            );
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let mut config = fast_config(id);
            config.y_fed_seed = Some(seed);
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }
        let mut tms = Vec::new();
        for h in handles {
            tms.push(h.await.unwrap().expect("epoch cycle completes"));
        }

        let state = treasury_info.lock().unwrap();
        // Exactly one rotation: the signature is the authorization, so only the
        // leader submits — a second would race for an already-spent input.
        assert_eq!(
            state.rotations.len(),
            1,
            "the cycle must post exactly one Update-Y"
        );
        let (rotated_epoch, new_key, signature) = state.rotations[0];
        assert_eq!(rotated_epoch, fixture.roster.epoch);
        assert_eq!(
            state.current_key, new_key,
            "the datum must now name the incoming key"
        );
        assert_ne!(
            state.current_key, fed_xonly,
            "the treasury must have left the federation key"
        );

        // The signature is over the message pinned to the SPENT state UTxO and
        // naming this successor — recomputed here rather than trusted, so a
        // rotation authorized against some other outpoint or key would fail.
        let expected_msg = crate::cardano::treasury_info::update_y_sig_msg(
            &state_txid,
            0,
            rotated_epoch,
            &new_key.serialize(),
        );
        secp.verify_schnorr(
            &bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).unwrap(),
            &bitcoin::secp256k1::Message::from_digest(expected_msg),
            &fed_xonly,
        )
        .expect("the OUTGOING key must have authorized its own succession");

        // The key that reached the chain is the one the roster actually derived:
        // rebuilding the treasury Taproot from it reproduces the TM's change
        // output byte-for-byte. That is what makes the published datum and the
        // Bitcoin address the same handoff rather than two independent guesses.
        //
        // Both keys are `new_key` because the mock collapses Y_fed onto the group
        // key once one is published (`MockCardanoChain::query_treasury`), which is
        // also what `build_tm_phase` read when it built this output.
        let expected_spk = bitcoin::ScriptBuf::new_p2tr_tweaked(
            treasury_spend_info(
                &secp,
                new_key,
                new_key,
                fixture.federation_csv_blocks as u16,
            )
            .output_key(),
        );
        assert_eq!(
            tms[0].unsigned_tx.output[0].script_pubkey, expected_spk,
            "the published key must be the internal key of the treasury the TM pays into"
        );
    }

    // -----------------------------------------------------------------------
    // WI-030: peg-outs on the DAEMON path
    // -----------------------------------------------------------------------

    /// A standard, payable destination — `build_tm` drops anything else as
    /// `NonStandardScript`, which would mask the rule under test.
    fn p2wpkh(tag: u8) -> bitcoin::ScriptBuf {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[tag; 20]);
        bitcoin::ScriptBuf::from_bytes(spk)
    }

    /// The mock's `chain_now_ms` is the local clock (the trait default), so fixture
    /// `created` values must be relative to it or every request lands outside the
    /// freshness window.
    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// The WI-030 acceptance, end to end: `run_epoch_loop` builds a TM that PAYS a pending
    /// peg-out. Before this, `query_pegout_requests` returned an empty vec on every live
    /// chain, so the daemon's TMs paid no withdrawal at all and none of the peg-out
    /// machinery below `build_tm_phase` was reachable outside the CLI.
    ///
    /// Also covers the freshness filter that replaced the treasury pin in rev 5.1: a request
    /// close to its own `created + PEG_OUT_CANCEL_TIMEOUT_MS` cancel deadline must be
    /// skipped, since paying it risks the owner cancelling for the fBTC after taking the BTC.
    #[tokio::test]
    async fn daemon_tm_pays_a_fresh_pegout_and_skips_one_near_its_cancel_deadline() {
        use crate::epoch::fixture::StaticPegOut;
        use bitcoin::Amount;

        let mut fixture = demo_static_fixture(2, 2, 18_700);
        let paid_dest = p2wpkh(0x01);
        let stale_dest = p2wpkh(0x02);
        let now = now_ms();

        // Created just now: comfortably inside the window.
        fixture.pegouts.push(StaticPegOut {
            script_pubkey: paid_dest.clone(),
            amount: Amount::from_sat(50_000),
            created: now,
        });
        // Created so long ago that its cancel deadline is within the freshness margin.
        fixture.pegouts.push(StaticPegOut {
            script_pubkey: stale_dest.clone(),
            amount: Amount::from_sat(60_000),
            created: now - crate::bitcoin::tm_builder::PEG_OUT_CANCEL_TIMEOUT_MS + 1_000,
        });

        // The trie is the sole already-paid record (WI-031), so peg-outs are paid only when
        // the local root is cross-checked. state_dir is unset here, so the local trie is the
        // empty one — report that same root as the chain's.
        let empty_root = crate::cardano::cpo_trie::CpoTrie::empty().root();

        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> =
                Arc::new(MockCardanoChain::new(fixture.clone()).with_cpo_root(empty_root));
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

        let outputs = &tms[0].unsigned_tx.output;
        // Treasury continuation, the one payable peg-out, and the CPOR1 root commitment.
        let payments: Vec<_> = outputs
            .iter()
            .filter(|o| !o.script_pubkey.is_op_return() && !o.script_pubkey.is_p2tr())
            .collect();
        assert_eq!(
            payments.len(),
            1,
            "exactly one peg-out payment expected, got {outputs:?}"
        );
        assert_eq!(payments[0].script_pubkey, paid_dest);
        // Paid NET of this request's own datum fee (rev 5.1: per-request, not a global).
        assert_eq!(
            payments[0].value,
            Amount::from_sat(50_000) - fixture.per_pegout_fee,
        );
        assert!(
            outputs.iter().all(|o| o.script_pubkey != stale_dest),
            "a peg-out inside the freshness margin of its cancel deadline must not be paid"
        );

        assert_eq!(
            tms[1].txid, tms[0].txid,
            "both SPOs must reduce identical chain state to identical TM bytes"
        );
    }

    /// The double-pay guard on the daemon path, WI-031 shape: a request an earlier movement
    /// already paid is recorded in the completed-peg-outs trie under its `por_id`, and
    /// `build_tm` skips it (`SkipReason::AlreadyCompleted`) even though its UTxO is still
    /// open — completion lags the payment by hours, or never comes.
    ///
    /// This replaces the identity-free `(destination, net sat)` multiset WI-031 deleted. The
    /// trie is keyed by request identity, so an unrelated later request to the same address
    /// for the same amount is a DIFFERENT `por_id` and stays payable — the exact case the
    /// multiset stranded forever.
    #[tokio::test]
    async fn daemon_tm_skips_a_pegout_already_in_the_trie_but_pays_an_identical_new_one() {
        use crate::cardano::cpo_trie::{CpoEntry, CpoTrie};
        use crate::epoch::fixture::StaticPegOut;
        use bitcoin::Amount;

        let mut fixture = demo_static_fixture(2, 2, 18_750);
        let dest = p2wpkh(0x03);
        let now = now_ms();
        // Two requests to the SAME destination for the SAME gross amount. Only the first has
        // been paid; the multiset guard could not tell them apart, the trie can.
        let paid_gross = Amount::from_sat(50_000);
        let fresh_gross = Amount::from_sat(70_000);
        for gross in [paid_gross, fresh_gross] {
            fixture.pegouts.push(StaticPegOut {
                script_pubkey: dest.clone(),
                amount: gross,
                created: now,
            });
        }

        // Seed a persisted trie holding only the FIRST request's por_id.
        let dir = std::env::temp_dir().join(format!("heimdall-cpo-skip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp state dir");
        let mut trie = CpoTrie::empty();
        let net = paid_gross - fixture.per_pegout_fee;
        trie.insert_batch(&[CpoEntry::new(
            crate::epoch::mocks::fixture_por_id(&dest, paid_gross),
            dest.as_bytes(),
            net.to_sat(),
        )])
        .expect("seed trie");
        trie.save(&dir).expect("persist trie");
        let seeded_root = trie.root();

        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> =
                Arc::new(MockCardanoChain::new(fixture.clone()).with_cpo_root(seeded_root));
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let mut config = fast_config(id);
            config.state_dir = Some(dir.clone());
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }
        let mut tms = Vec::new();
        for h in handles {
            tms.push(h.await.unwrap().expect("epoch cycle completes"));
        }

        let outputs = &tms[0].unsigned_tx.output;
        let payments: Vec<_> = outputs
            .iter()
            .filter(|o| !o.script_pubkey.is_op_return() && !o.script_pubkey.is_p2tr())
            .collect();
        assert_eq!(
            payments.len(),
            1,
            "the trie-recorded request must be skipped and the new one paid, got {outputs:?}"
        );
        assert_eq!(payments[0].script_pubkey, dest);
        assert_eq!(
            payments[0].value,
            fresh_gross - fixture.per_pegout_fee,
            "the PAID one must be the request absent from the trie — an identity-free filter \
             would have stranded it"
        );
    }

    /// The safety gate that makes deleting the multiset guard sound: with no
    /// `cardano.cpo_policy_id` the local trie was never cross-checked, so it cannot be trusted
    /// to say what was already paid — and paying without any dedup re-pays every open request
    /// on every movement. The daemon must skip peg-outs entirely, while still sweeping
    /// peg-ins.
    #[tokio::test]
    async fn daemon_pays_no_pegout_when_the_trie_was_not_cross_checked() {
        use crate::epoch::fixture::StaticPegOut;
        use bitcoin::Amount;

        let mut fixture = demo_static_fixture(2, 2, 18_800);
        let dest = p2wpkh(0x05);
        fixture.pegouts.push(StaticPegOut {
            script_pubkey: dest.clone(),
            amount: Amount::from_sat(50_000),
            created: now_ms(),
        });

        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            // No `with_cpo_root`: query_cpo_root returns None = "not configured".
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

        let outputs = &tms[0].unsigned_tx.output;
        assert!(
            outputs
                .iter()
                .all(|o| o.script_pubkey.is_op_return() || o.script_pubkey.is_p2tr()),
            "an uncross-checked trie must yield NO peg-out payment, got {outputs:?}"
        );
    }

    #[tokio::test]
    async fn followers_wait_in_await_confirm_until_chain_confirms() {
        let fixture = demo_static_fixture(2, 2, 18_650);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        let mut signals = Vec::new();
        let mut submitted = Vec::new();

        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain = Arc::new(MockCardanoChain::new(fixture.clone()));
            let signal = chain.confirmation_signal();
            signal.store(false, std::sync::atomic::Ordering::Release);
            submitted.push(chain.submitted_txs());
            signals.push(signal);
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = fast_config(id);
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }

        // Wait until the leader has submitted and both nodes should be parked
        // in AwaitConfirm rather than returning from the cycle.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if submitted.iter().any(|txs| !txs.lock().unwrap().is_empty()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("leader submits before confirmation test timeout");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(handles.iter().any(|h| !h.is_finished()));

        for signal in signals {
            signal.store(true, std::sync::atomic::Ordering::Release);
        }
        for handle in handles {
            handle
                .await
                .unwrap()
                .expect("cycle completes after confirmation");
        }
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
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id1, MockPeerHub::new()));
        let mut config = fast_config(id1);
        config.state_dir = Some(dir.clone());

        // With persisted state → resume straight to PublishKeys (no DKG).
        match epoch_start_phase(&chain, &peers, &config, 0).await.unwrap() {
            EpochPhase::PublishKeys { group_keys: gk, .. } => {
                assert_eq!(gk.verifying_key, group_keys.verifying_key);
                assert_eq!(*gk.key_package.identifier(), id1);
            }
            other => panic!("expected resume to PublishKeys, got {}", other.name()),
        }

        // No persisted state → fresh DKG (the mock chain serves the context).
        config.state_dir = None;
        assert!(matches!(
            epoch_start_phase(&chain, &peers, &config, 0).await.unwrap(),
            EpochPhase::Dkg { .. }
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn full_cycle_3_of_3_all_derive_same_treasury() {
        multi_instance_same_treasury(3, 3).await;
    }

    /// N21 acceptance — the reported staggered-start repro: 3 instances where
    /// the last starts late (well past the others' old round-1 deadline
    /// behavior). With the health gate the early nodes wait for the late one,
    /// and with the window grid all three then join the same ceremony window —
    /// so the cycle completes with all THREE deriving the identical TM
    /// (pre-N21: nodes 1+2 completed a reduced 2-of-2 key and node 3 looped
    /// on their stale attempt-0 packages forever).
    #[tokio::test]
    async fn full_cycle_3_of_3_staggered_start_converges() {
        let fixture = demo_static_fixture(3, 3, 18_800);
        let hub = MockPeerHub::new();
        let anchor_ms = crate::epoch::dkg::wall_now_ms();

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> =
                Arc::new(MockCardanoChain::new(fixture.clone()).with_schedule_anchor_ms(anchor_ms));
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let mut config = fast_config(id);
            // Must satisfy the self-healing inequality (see `dkg_window` docs):
            // dkg_round1_offset (2s) + retry backoff (2s) < window, so if the
            // rare entry race splits the cohorts one line apart, an aborting
            // node reaches the very next line and the cohorts merge instead of
            // cycling phase-locked (which would hang this test).
            config.dkg_window = Duration::from_secs(5);
            config.dkg_join_wait = Duration::from_secs(20);
            config.dkg_round1_offset = Duration::from_secs(2);
            config.dkg_round2_offset = Duration::from_secs(4);
            let hub = hub.clone();
            handles.push(tokio::spawn(async move {
                if i == 3 {
                    // The repro: the last instance comes up late.
                    tokio::time::sleep(Duration::from_millis(700)).await;
                }
                hub.set_online(id);
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }

        let mut tms = Vec::new();
        for h in handles {
            tms.push(h.await.unwrap().expect("epoch cycle completes"));
        }
        let txid0 = tms[0].txid;
        for tm in &tms[1..] {
            assert_eq!(
                tm.txid, txid0,
                "all SPOs (incl. the late starter) must derive the identical TM"
            );
        }
    }

    /// Grid arithmetic: the next line is strictly after `now`, snapped to
    /// `boundary + k·window`; a pre-boundary start joins window 0 at the
    /// boundary itself.
    #[test]
    fn next_window_snaps_to_the_grid() {
        let w = Duration::from_secs(60);
        // pre-boundary → window 0, at the boundary
        assert_eq!(next_window(1_000_000, w, 995_000), (0, 1_000_000));
        // at / after the boundary → the strictly-next line
        assert_eq!(next_window(1_000_000, w, 1_000_000), (1, 1_060_000));
        assert_eq!(next_window(1_000_000, w, 1_059_999), (1, 1_060_000));
        assert_eq!(next_window(1_000_000, w, 1_060_000), (2, 1_120_000));
        // attempt namespaces from consecutive windows never collide
        let (k1, _) = next_window(1_000_000, w, 1_000_000);
        let (k2, _) = next_window(1_000_000, w, 1_060_000);
        assert_ne!(k1 * DKG_ATTEMPTS_PER_WINDOW, k2 * DKG_ATTEMPTS_PER_WINDOW);
    }

    fn cpo_check_chain(on_chain_root: Option<[u8; 32]>) -> Arc<dyn CardanoChain> {
        let mock = MockCardanoChain::new(demo_static_fixture(2, 2, 18_900));
        Arc::new(match on_chain_root {
            Some(root) => mock.with_cpo_root(root),
            None => mock,
        })
    }

    /// The trie the chain agrees with is signable: the cross-check passes and
    /// `BuildTm` goes on to build.
    #[tokio::test]
    async fn cpo_cross_check_accepts_a_matching_root() {
        let trie = crate::cardano::cpo_trie::CpoTrie::empty();
        let chain = cpo_check_chain(Some(trie.root()));
        let id = Identifier::try_from(1u16).unwrap();
        cross_check_cpo_root(&chain, &trie, None, id, 0)
            .await
            .expect("a root the chain holds must be attestable");
    }

    /// The re-bootstrap case: a leftover populated trie against a fresh
    /// zero-root singleton. Nothing may be signed, and the operator must be told
    /// which command rebuilds the trie.
    #[tokio::test]
    async fn cpo_cross_check_refuses_a_stale_root() {
        let trie = crate::cardano::cpo_trie::CpoTrie::empty();
        let chain = cpo_check_chain(Some([0x11u8; 32]));
        let id = Identifier::try_from(1u16).unwrap();
        let err = cross_check_cpo_root(
            &chain,
            &trie,
            Some(std::path::Path::new("/var/lib/hd")),
            id,
            0,
        )
        .await
        .expect_err("a root the chain does not hold must not be attestable");
        let msg = err.to_string();
        assert!(
            msg.contains("reconstruct-cpo-trie"),
            "the refusal must name the command that fixes it: {msg}"
        );
        assert!(
            msg.contains(&hex::encode([0x11u8; 32])),
            "the refusal must show the on-chain root: {msg}"
        );
        assert!(
            msg.contains("/var/lib/hd/cpo-trie.json"),
            "the refusal must name the stale file: {msg}"
        );
    }

    /// An unconfigured `cardano.cpo_policy_id` reports `None`, which is "cannot
    /// check", not "empty trie" — it warns and proceeds, or every such node would
    /// refuse to sign for a bridge with any peg-out history.
    #[tokio::test]
    async fn cpo_cross_check_passes_when_the_chain_cannot_answer() {
        let mut trie = crate::cardano::cpo_trie::CpoTrie::empty();
        trie.insert_batch(&[crate::cardano::cpo_trie::CpoEntry::new(
            [7u8; 32],
            &[0x51, 0x20],
            1_000,
        )])
        .unwrap();
        let chain = cpo_check_chain(None);
        let id = Identifier::try_from(1u16).unwrap();
        cross_check_cpo_root(&chain, &trie, None, id, 0)
            .await
            .expect("an unchecked root must still be attestable");
    }
}
