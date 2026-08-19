//! Epoch state machine driver.
//!
//! `run_epoch_loop` repeatedly matches on `EpochPhase` and dispatches to
//! the right phase function. Glue phases that are not big enough to
//! deserve their own module live here:
//!
//! - `idle_phase`          — block until the chain reports an epoch boundary
//! - `epoch_start_phase`   — snapshot the roster
//! - `publish_keys_phase`  — publish the group key: BIP-340 x-only + Update-Y handoff
//! - `collect_pegins_phase`— wait for this epoch's next batch opportunity
//!                           `B_i`, then read the Cardano peg-in source
//!                           once, parse each datum into a validated
//!                           `ParsedPegIn`, and freeze the set for `BuildTm`
//! - `build_tm_phase`      — pull treasury + pegouts (frozen pegins
//!                           come from `CollectPegins`) and build the
//!                           unsigned Bitcoin tx + sighashes
//! - `submit_phase`        — assemble the witnessed tx, verify each
//!                           per-input signature under the on-chain
//!                           output key, hand bytes to the chain
//! - `record_movement_phase`— end of ONE movement: persist what it owes the
//!                           tries, return it, resume at the NEXT batch
//!                           opportunity — it does NOT await the confirmation
//!
//! `Dkg` and `Sign` are dispatched to `dkg::dkg_phase` and
//! `signing::sign_phase` respectively.
//!
//! The fold a confirmation owes the completed-peg-outs and swept-peg-ins tries is
//! NOT done by the phase that posts the movement. It is done by
//! `settle_pending_tm`, from inside `collect_pegins_phase`, the moment the chain
//! shows the treasury head has moved off the outpoint the movement spends — see
//! [`crate::epoch::pending_tm`] for why a wait cannot do that job.
//!
//! ## Two clocks, not one
//!
//! The ceremony runs once per EPOCH; treasury movements run on a slot grid
//! *within* the epoch — `B_i = epoch_start + i × tm_batch_interval`, spec §TM
//! batches and the protocol schedule. So the machine has two loops. The outer one
//! is `Idle → EpochStart → Dkg → PublishKeys`, paced by
//! [`CardanoChain::await_epoch_boundary`]. The inner one is
//! `CollectPegins → BuildTm → Sign → Submit → RecordMovement → CollectPegins`,
//! paced by the grid, and it carries the roster and group keys around so no batch
//! costs a second ceremony. It leaves for `Idle` only when the epoch's grid is
//! exhausted (`BatchWindow::Closed { next: None }`).
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
    Freshness, PegInInput, PegOutRequest, TreasuryInput, build_tm, compute_sighashes,
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
use std::collections::{BTreeMap, BTreeSet};

/// Run the epoch state machine for one full cycle and return the
/// witnessed `TreasuryMovement` once the cycle reaches `RecordMovement`.
///
/// The first-cycle scope: `await_epoch_boundary` fires once, the loop
/// runs DKG → BuildTm → Sign → Submit → RecordMovement and then exits.
/// Future cuts will instead loop back to `Idle` and wait for the next
/// boundary.
/// Backoff bounds for retriable phase errors (chain/peer/DKG). A persistent
/// transient failure re-enters `Idle` with an exponentially growing wait,
/// capped, so the node parks for the next boundary instead of dying or
/// hot-looping (WI-010 / WI-014 error-handling feedback).
const RETRY_BACKOFF_MIN: std::time::Duration = std::time::Duration::from_secs(2);

/// One dispatch step: advance to the next phase, or finish one movement. Both
/// variants are large but the value is constructed and consumed immediately in
/// the loop (never stored), so boxing would only add an allocation.
#[allow(clippy::large_enum_variant)]
enum Step {
    Next(EpochPhase),
    /// The movement is confirmed. The phase is where the machine RESUMES — the
    /// epoch's next batch opportunity, carrying this epoch's roster and group
    /// keys — so a daemon runs the grid without re-running the ceremony.
    Done(TreasuryMovement, EpochPhase),
}

/// Which batch opportunity this process has already built for, as
/// `(epoch, index)`.
///
/// The grid holds an opportunity open for a whole `tm_batch_interval`, so without
/// this marker a node that completed a movement inside the interval would
/// immediately build a second one for the SAME `B_i` — a fee per poll on a
/// treasury self-move. `run-mover` carries the identical guard as a local
/// (`built_batch`); the machine has to thread it because the movement it protects
/// completes five phases later.
///
/// Index [`BuiltBatch::NO_GRID`] marks a build on a chain with no grid at all.
/// The real grid is 1-based, so the two can never collide, and it gives the
/// no-grid case the one-movement-per-epoch bound the machine had before the grid.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct BuiltBatch(Option<(u64, u64)>);

impl BuiltBatch {
    const NO_GRID: u64 = 0;

    fn is(self, epoch: u64, index: u64) -> bool {
        self.0 == Some((epoch, index))
    }

    fn mark(&mut self, epoch: u64, index: u64) {
        self.0 = Some((epoch, index));
    }

    /// Forget the marker after a FAILED attempt: a build that produced no
    /// movement must not consume its opportunity, so the next poll retries the
    /// same `B_i` instead of waiting out the interval. (A posted-but-unconfirmed
    /// movement is caught by the in-flight gate, not by this.)
    fn clear(&mut self) {
        self.0 = None;
    }
}

/// Run the epoch machine for as long as the process lives: movement after
/// movement, for ever.
///
/// [`run_epoch_loop`] completes ONE movement and returns it — the right shape for
/// a test and for a single-shot run, and the wrong one for a daemon. A service
/// pointed at it produced exactly one Treasury Movement and exited, which under
/// `Restart=on-failure` looks like a clean shutdown: the bridge moves once and
/// then goes quiet with a green unit.
///
/// Each movement resumes where the last one ended — the epoch's next batch
/// opportunity — so the DKG runs once per epoch and the grid paces the movements.
/// Errors keep their existing treatment inside [`drive_to_movement`], which never
/// returns them.
pub async fn run_epoch_daemon(
    chain: Arc<dyn CardanoChain>,
    pegin_source: Arc<dyn CardanoPegInSource>,
    peers: Arc<dyn PeerNetwork>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn RngSource>,
    config: &EpochConfig,
    mut on_cycle: impl FnMut(&TreasuryMovement),
) -> EpochResult<std::convert::Infallible> {
    // Outlives the movements, which is the whole point: the marker says which
    // opportunity was consumed, and the next movement starts inside the same
    // interval.
    let mut built = BuiltBatch::default();
    let mut phase = EpochPhase::Idle;
    loop {
        let (tm, resume) = drive_to_movement(
            &chain,
            &pegin_source,
            &peers,
            &clock,
            &rng,
            config,
            phase,
            &mut built,
        )
        .await?;
        on_cycle(&tm);
        phase = resume;
    }
}

/// Run until ONE Treasury Movement has been built, signed and posted, and return
/// it.
///
/// Posted, not confirmed — the confirmation is hours away and nothing is gained by
/// waiting for it here (WI-032). The movement's fold into the two tries is
/// persisted, and performed by whichever later pass through `CollectPegins`
/// observes the head move; a single-shot run simply exits before that happens.
///
/// Retriable failures never surface: they back off and re-enter the loop, so this
/// returns only on a posted movement. For a long-running node use
/// [`run_epoch_daemon`], which repeats it, keeps the batch-grid position, and does
/// carry out the fold.
pub async fn run_epoch_loop(
    chain: Arc<dyn CardanoChain>,
    pegin_source: Arc<dyn CardanoPegInSource>,
    peers: Arc<dyn PeerNetwork>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn RngSource>,
    config: &EpochConfig,
) -> EpochResult<TreasuryMovement> {
    drive_to_movement(
        &chain,
        &pegin_source,
        &peers,
        &clock,
        &rng,
        config,
        EpochPhase::Idle,
        &mut BuiltBatch::default(),
    )
    .await
    .map(|(tm, _resume)| tm)
}

/// The phase driver: step from `start` until a movement completes, and report
/// both it and where to resume.
#[allow(clippy::too_many_arguments)]
async fn drive_to_movement(
    chain: &Arc<dyn CardanoChain>,
    pegin_source: &Arc<dyn CardanoPegInSource>,
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    start: EpochPhase,
    built: &mut BuiltBatch,
) -> EpochResult<(TreasuryMovement, EpochPhase)> {
    let me = config.identity.identifier;
    let mut phase = start;
    let mut backoff = RETRY_BACKOFF_MIN;
    // The opportunity this call INHERITED — the one the previous movement used,
    // when we are resuming a daemon's batch loop. It is not ours to give back; see
    // the error arm.
    let inherited = *built;
    // Where to re-enter THIS epoch after a retriable failure, carrying the
    // ceremony it already paid for. `Idle` waits for the chain epoch to ADVANCE,
    // so re-entering it mid-epoch parks the node for days — and both phases below
    // meet far more transient failures than one movement per epoch ever did.
    //
    // Two phases can be re-entered, and both are idempotent by construction:
    //
    //  - `PublishKeys` — the handoff has not landed yet. Re-running it is a no-op
    //    once it has (`plan_update_y` returns None when the datum already names
    //    the key), and a rotation that failed on a slow or absent peer deserves a
    //    retry in minutes. Falling to `Idle` here costs the epoch's ENTIRE batch
    //    grid, not just the rotation, because the batch loop sits downstream of
    //    this phase (WI-047).
    //  - `CollectPegins` — past the handoff, in the batch loop. A failure there
    //    costs one batch rather than the epoch (WI-097).
    let mut resume: Option<EpochPhase> = None;
    // How many times the handoff may be re-entered before this node accepts that
    // the failure is not transient and parks.
    //
    // Retrying is right for a slow chain read or a peer that was a moment late.
    // It is wrong for the reasons that never clear inside an epoch: a boundary
    // that dropped more than `min_signers` of the outgoing roster, or a node newly
    // registered this epoch, which holds no share of the outgoing key and gets a
    // PERMANENT `load_outgoing_dkg` error. Those used to park in `Idle`; without a
    // bound they would now re-enter every 2–60 s for the five days of an epoch,
    // achieving nothing and spending an API quota to do it. At the capped backoff
    // this spans roughly two minutes, which is far past any transient outage and
    // far short of an epoch.
    const HANDOFF_RETRIES: u32 = 6;
    let mut handoff_retries = 0u32;
    // The epoch whose rotation round this node has already SPENT (published a
    // commitment into and then failed). Set on the first such failure, which
    // re-enters `PublishKeys` once — with the ceremony disabled — purely to see
    // whether the rotation landed without this node.
    let mut rotation_spent: Option<u64> = None;
    loop {
        crate::epoch_log!(me, current_epoch(&phase), "==> phase = {}", phase.name());
        // Rebuilt rather than cloned: `EpochPhase` is not `Clone` (a `Sign` or
        // `Submit` phase carries a whole `TreasuryMovement`), and only these two
        // variants are ones we would ever want to re-enter.
        match &phase {
            EpochPhase::PublishKeys {
                epoch,
                roster,
                group_keys,
            } if handoff_retries < HANDOFF_RETRIES => {
                resume = Some(EpochPhase::PublishKeys {
                    epoch: *epoch,
                    roster: roster.clone(),
                    group_keys: group_keys.clone(),
                });
            }
            // Out of attempts: stop offering `PublishKeys` as a re-entry, so the
            // next failure falls through to `Idle` and the node waits for a
            // boundary that re-derives everything from chain.
            EpochPhase::PublishKeys { epoch, .. } => {
                crate::epoch_warn!(
                    me,
                    *epoch,
                    "the key handoff has failed {HANDOFF_RETRIES} retries running this epoch — \
                     treating it as non-transient and parking until the next boundary. The \
                     treasury stays under the OUTGOING key until a rotation completes, so this \
                     node signs no movement for this epoch."
                );
                resume = None;
            }
            // The watch is its own re-entry: a chain read that fails mid-watch
            // must resume the WATCH, not the handoff. Without this arm `resume`
            // would still hold the `PublishKeys` that entered it, so a single
            // 502 would re-run the authorization that already answered "not
            // mine" — and, because that arm is what increments the counter,
            // spend a handoff retry doing it. Six of those and the node parks,
            // which is the whole bug back again.
            EpochPhase::AwaitRotation {
                epoch,
                roster,
                group_keys,
            } => {
                resume = Some(EpochPhase::AwaitRotation {
                    epoch: *epoch,
                    roster: roster.clone(),
                    group_keys: group_keys.clone(),
                });
            }
            EpochPhase::CollectPegins {
                epoch,
                roster,
                group_keys,
            } => {
                resume = Some(EpochPhase::CollectPegins {
                    epoch: *epoch,
                    roster: roster.clone(),
                    group_keys: group_keys.clone(),
                });
            }
            _ => {}
        }
        let spent_here = rotation_spent == Some(current_epoch(&phase));
        match step_phase(
            phase,
            chain,
            pegin_source,
            peers,
            clock,
            rng,
            config,
            me,
            built,
            spent_here,
        )
        .await
        {
            Ok(Step::Next(next)) => {
                // The handoff got through, so its budget is spent and reset: a
                // later epoch on the same call must start from a full one.
                if matches!(next, EpochPhase::CollectPegins { .. }) {
                    handoff_retries = 0;
                }
                phase = next;
                backoff = RETRY_BACKOFF_MIN; // progress → reset
            }
            Ok(Step::Done(tm, resume)) => return Ok((tm, resume)),
            // EVERY in-loop error backs off and re-enters the loop, which never
            // terminates. WHERE it re-enters is `resume`'s decision above: this
            // epoch's `PublishKeys` or `CollectPegins` while its ceremony is still
            // in hand and the chain is still in that epoch, otherwise `Idle`.
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
                // A SPENT round has published commitments its peers are still
                // serving, so this node may not walk it again alone: it has to
                // rejoin them at the next SYNCHRONIZED entry. That is the next
                // grid opportunity for a movement (so its own opportunity is NOT
                // handed back below) and the next epoch boundary for a rotation
                // (so the handoff is not re-entered at all). See
                // `EpochError::RoundSpent`.
                // The negative half of the DKG answer, recorded where the loop
                // actually learns it. A node dropped from the qualified set keeps
                // running and looks fine, so this is the thing it hurts most to
                // learn late — and a warn line scrolls away where a queryable
                // field does not.
                if matches!(e, EpochError::DkgAborted { .. }) {
                    config.health.update(|h| {
                        h.dkg_qualified = Some(false);
                        h.activity = "DKG did not complete for this node".into();
                    });
                }
                let round_spent = e.round_is_spent();
                if round_spent && matches!(resume, Some(EpochPhase::PublishKeys { .. })) {
                    let ep = resume.as_ref().map_or(0, current_epoch);
                    if rotation_spent == Some(ep) {
                        // Second time round: the phase re-entered, found the
                        // treasury still naming the old key, and refused to walk
                        // the spent round again. Nothing more this node can do
                        // until the boundary re-derives everything.
                        crate::epoch_warn!(
                            me,
                            ep,
                            "Update-Y: {e} — the rotation did not land and this node's round is \
                             spent, so the epoch's handoff is over. The treasury keeps the \
                             current key and the outgoing roster carries over."
                        );
                        resume = None;
                    } else {
                        // First time: the round is spent for THIS node, but the
                        // threshold subset WI-047 exists to allow may well have
                        // aggregated and posted without it — in which case the
                        // treasury already names the key this node holds a share
                        // of, `plan_update_y` returns None, and the phase walks
                        // straight through to the batch loop. Dropping to `Idle`
                        // here would throw away the whole epoch's grid over a
                        // rotation that SUCCEEDED (machine.rs's own rule, above).
                        // So re-enter once to look, with the ceremony disabled.
                        crate::epoch_warn!(
                            me,
                            ep,
                            "Update-Y: {e} — this node's round is spent. Re-reading the treasury \
                             once in case the rotation landed without it; not re-running the \
                             ceremony."
                        );
                        rotation_spent = Some(ep);
                    }
                }
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
                    crate::epoch_warn!(
                        me,
                        current_epoch(&EpochPhase::Idle),
                        "chain read failed ({e}); STALE chain-view — settling back-off {:?} before re-read \
                         (reconcile), then re-entering {}",
                        config.dkg_reconcile_backoff,
                        resume.as_ref().map_or("Idle", EpochPhase::name)
                    );
                    backoff = RETRY_BACKOFF_MIN; // the settling wait replaces the ramp
                    config.dkg_reconcile_backoff
                } else {
                    crate::epoch_warn!(
                        me,
                        current_epoch(&EpochPhase::Idle),
                        "chain read failed ({e}); backing off {:?} then re-entering {}",
                        backoff,
                        resume.as_ref().map_or("Idle", EpochPhase::name)
                    );
                    let w = backoff;
                    backoff = (backoff * 2).min(config.retry_backoff_max);
                    w
                };
                tokio::time::sleep(wait).await;
                // A failed attempt must not consume its batch opportunity — but
                // only when the attempt was THIS call's. A failure while waiting
                // for the next opportunity leaves the marker of the movement that
                // already succeeded, and clearing that one would build a second
                // movement for a batch this node has already served.
                //
                // A SPENT round is the exception: handing the opportunity back
                // would rebuild the same frozen batch, hence the same sighashes
                // and the same namespace, and republish into a round the peers
                // have moved on from. Keeping the marker sends this node to the
                // NEXT opportunity, which every node enters together.
                if *built != inherited && !round_spent {
                    built.clear();
                }
                // Re-enter THIS epoch when its ceremony is still in hand and the
                // chain is still in that epoch; only otherwise fall back to
                // `Idle`, which re-derives everything from chain. The ceremony is
                // the expensive part and it is still valid: the spec's "no halt,
                // no special state" is about a failed DKG, not about throwing away
                // a good one because a peg-out query 502'd or one outgoing member
                // was slow to answer the rotation.
                //
                // An unreadable epoch counts as unchanged: re-entering retries and
                // backs off, whereas `Idle` would silently park for up to a full
                // epoch on what may be a five-second outage.
                // `resume` is re-set at the top of every iteration and only the
                // two ceremony-bearing phases set it, so `Some(PublishKeys)` here
                // means the failure WAS the handoff: nothing else runs between it
                // and `CollectPegins`, which overwrites it.
                if matches!(resume, Some(EpochPhase::PublishKeys { .. })) {
                    handoff_retries += 1;
                }
                phase = match resume.take() {
                    Some(p)
                        if chain
                            .current_epoch()
                            .await
                            .map_or(true, |now| now == current_epoch(&p)) =>
                    {
                        p
                    }
                    _ => EpochPhase::Idle,
                };
            }
        }
    }
}

/// Dispatch one phase to its handler. Pure routing — the retry/backoff policy
/// lives in [`drive_to_movement`].
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
    built: &mut BuiltBatch,
    // This epoch's rotation round is already spent (WI-048): re-enter to see
    // whether it landed without us, but do NOT run the ceremony again.
    rotation_spent: bool,
) -> EpochResult<Step> {
    let next = match phase {
        EpochPhase::Idle => idle_phase(chain).await?,

        // The two DKG-bearing phases share one failure route: when the ceremony
        // cannot deliver — an empty or sub-threshold registry, this node not
        // eligible, or rounds that timed out — a bridge still in Phase 1 falls
        // back to the federation rather than losing the batch. See
        // [`phase1_fallback`]; on a Phase-2 bridge it re-raises untouched, so a
        // failed ceremony stays a failed ceremony.
        EpochPhase::EpochStart { epoch } => {
            match epoch_start_phase(chain, peers, config, epoch).await {
                Ok(next) => next,
                Err(e) if dkg_unavailable(&e) => {
                    phase1_fallback(chain, peers, clock, rng, config, epoch, e).await?
                }
                Err(e) => return Err(e),
            }
        }

        EpochPhase::Dkg {
            round,
            ctx,
            collected,
        } => {
            let epoch = ctx.epoch;
            match dkg_phase(chain, peers, clock, rng, config, round, ctx, collected).await {
                Ok(next) => next,
                Err(e) if dkg_unavailable(&e) => {
                    phase1_fallback(chain, peers, clock, rng, config, epoch, e).await?
                }
                Err(e) => return Err(e),
            }
        }

        EpochPhase::PublishKeys {
            epoch,
            roster,
            group_keys,
        } => {
            publish_keys_phase(
                chain,
                peers,
                clock,
                rng,
                config,
                epoch,
                roster,
                group_keys,
                rotation_spent,
            )
            .await?
        }

        EpochPhase::AwaitRotation {
            epoch,
            roster,
            group_keys,
        } => await_rotation_phase(chain, config, epoch, roster, group_keys).await?,

        EpochPhase::CollectPegins {
            epoch,
            roster,
            group_keys,
        } => {
            collect_pegins_phase(
                chain,
                pegin_source,
                config,
                epoch,
                roster,
                group_keys,
                built,
            )
            .await?
        }

        EpochPhase::BuildTm {
            epoch,
            roster,
            group_keys,
            batch,
            frozen_pegins,
        } => {
            build_tm_phase(
                chain,
                clock,
                config,
                epoch,
                roster,
                group_keys,
                batch,
                frozen_pegins,
            )
            .await?
        }

        EpochPhase::Sign {
            epoch,
            roster,
            cascade,
            tm_sequence,
            window,
            group_keys,
            tm,
            round,
            collected,
        } => {
            sign_phase(
                peers,
                clock,
                rng,
                config,
                epoch,
                roster,
                cascade,
                group_keys,
                tm,
                round,
                collected,
                tm_sequence,
                window,
            )
            .await?
        }

        EpochPhase::Submit {
            epoch,
            roster,
            group_keys,
            tm,
            tm_sequence,
        } => submit_phase(chain, me, epoch, roster, group_keys, tm, tm_sequence).await?,

        EpochPhase::RecordMovement {
            epoch,
            roster,
            group_keys,
            tm,
        } => {
            record_movement_phase(config, epoch, &tm)?;
            // Back to the epoch's batch loop, not out of it. This movement is
            // posted; the EPOCH is not over, and the roster + keys that signed
            // this one sign every remaining batch — `CollectPegins` decides
            // whether any opportunity is left and returns `Idle` when none is.
            return Ok(Step::Done(
                tm,
                EpochPhase::CollectPegins {
                    epoch,
                    roster,
                    group_keys,
                },
            ));
        }
    };
    Ok(Step::Next(next))
}

/// Write down the movement just posted, so the fold it owes the two tries can
/// happen whenever the chain gets round to confirming it.
///
/// This phase used to BLOCK until it observed the confirmation, and then fold.
/// Both halves were wrong (WI-032). The wait was redundant — "do not build while
/// a movement is in flight" is already enforced twice and independently, by the
/// batch gate in [`collect_pegins_phase`] and again by [`build_tm_phase`], both
/// on `TreasuryUtxo::btc_confirmed` — and it could not succeed anyway: the
/// confirmation is ~100 Bitcoin blocks plus the oracle's challenge-aging window
/// away, against a 30-minute timeout. And tying the fold to it made durable state
/// depend on one process staying awake for that whole window, so a restart, a
/// crash or the timeout left the tries permanently behind the chain with no path
/// back but `reconstruct-cpo-trie`.
///
/// A node with no `state_dir` has nowhere to record it. That node cannot BUILD
/// either (`build_tm_phase` refuses), so it is here as a co-signer only — but it
/// is co-signing movements whose effects it is not tracking, and its tries fall
/// further behind with every one. This is the once-per-movement place to say so,
/// and the only one: the fold reads the record, so with no record there is
/// nothing downstream left to warn about.
fn record_movement_phase(
    config: &EpochConfig,
    epoch: u64,
    tm: &TreasuryMovement,
) -> EpochResult<()> {
    let me = config.identity.identifier;
    let Some(dir) = config.state_dir.as_deref() else {
        crate::epoch_warn!(
            me,
            epoch,
            "  treasury movement {} NOT recorded: protocol.state_dir is not configured, so this \
             node tracks neither the completed-peg-outs nor the swept-peg-ins trie and cannot \
             build or co-sign a later Treasury Movement",
            tm.txid
        );
        return Ok(());
    };
    let pending = crate::epoch::pending_tm::PendingTm::from_movement(epoch, tm)
        .map_err(|e| EpochError::TmBuild(format!("pending treasury movement: {e}")))?;
    pending
        .save(dir)
        .map_err(|e| EpochError::TmBuild(format!("pending treasury movement: {e}")))?;
    crate::epoch_log!(
        me,
        epoch,
        "RecordMovement: treasury movement {} is posted and awaiting confirmation; recorded in \
         {} — the tries advance when the chain shows it as the head, however long that takes and \
         across restarts",
        tm.txid,
        crate::epoch::pending_tm::PendingTm::state_path(dir).display(),
    );
    Ok(())
}

/// Fold a recorded movement into both tries once the chain has moved on from the
/// head it spent — the settlement half of [`record_movement_phase`].
///
/// The trigger is the HEAD, not the txid: while `treasury.outpoint` is still the
/// outpoint the pending movement spends, nothing has landed on top of it and
/// there is nothing to fold. Once the head has moved, something built on that tip
/// confirmed, and folding the record either reproduces the two roots it committed
/// — proving it was this movement — or does not, and is refused. That refusal is
/// the existing discipline in [`advance_cpo_trie`] / [`advance_spi_trie`], and
/// keying on the head rather than the txid is what lets it cover the fee-bumped
/// rebuild too (spec §Stuck-TM recovery): an RBF twin of the same frozen batch
/// has a different txid and identical roots, so it folds cleanly.
///
/// Called wherever the head is READ — which is why it takes a `TreasuryUtxo` the
/// caller already has rather than querying: this costs no extra chain traffic.
fn settle_pending_tm(
    config: &EpochConfig,
    treasury: &crate::epoch::traits::TreasuryUtxo,
) -> EpochResult<()> {
    use crate::epoch::pending_tm::PendingTm;

    let me = config.identity.identifier;
    let Some(dir) = config.state_dir.as_deref() else {
        return Ok(());
    };
    let Some(pending) = PendingTm::load(dir)
        .map_err(|e| EpochError::TmBuild(format!("pending treasury movement: {e}")))?
    else {
        return Ok(());
    };
    if treasury.outpoint == pending.spends {
        crate::epoch_debug!(
            me,
            pending.epoch,
            "  treasury movement {} is still unconfirmed (the head is still the {} it spends)",
            pending.txid,
            pending.spends
        );
        return Ok(());
    }
    crate::epoch_log!(
        me,
        pending.epoch,
        "  treasury head advanced to {} — folding the movement recorded against {} into both tries",
        treasury.outpoint,
        pending.spends,
    );
    advance_cpo_trie(config, dir, &pending)?;
    advance_spi_trie(config, dir, &pending)?;
    PendingTm::clear(dir)
        .map_err(|e| EpochError::TmBuild(format!("pending treasury movement: {e}")))?;
    Ok(())
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
/// signing round while the wrong one signs confidently wrong roots. Since WI-032
/// this is also the check that decides WHICH movement confirmed — see
/// [`settle_pending_tm`] — so a mismatch means "the chain moved on without this
/// node", and the fix it names is the same one.
///
/// `dir` is the caller's: only [`settle_pending_tm`] calls this, and it has
/// already established that this node keeps tries at all.
fn advance_cpo_trie(
    config: &EpochConfig,
    dir: &std::path::Path,
    pending: &crate::epoch::pending_tm::PendingTm,
) -> EpochResult<()> {
    use crate::cardano::cpo_trie::CpoTrie;

    let me = config.identity.identifier;
    let epoch = pending.epoch;
    let mut trie = CpoTrie::load(dir)
        .map_err(|e| EpochError::TmBuild(format!("completed-peg-outs trie: {e}")))?
        .unwrap_or_default();

    let new_root = trie
        .insert_batch(&pending.fulfilled)
        .map_err(|e| EpochError::TmBuild(format!("completed-peg-outs trie: {e}")))?;
    if new_root != pending.cpo_root {
        return Err(EpochError::TmBuild(format!(
            "completed-peg-outs trie diverged: TM {} committed root {} but this node's trie \
             reaches {} after inserting its {} fulfilled peg-out(s) — NOT persisting. Either the \
             chain confirmed a DIFFERENT movement on top of {}, or this node's trie was already \
             behind; both are repaired the same way — run `reconstruct-cpo-trie`, which rebuilds \
             from chain history and refuses any movement it cannot explain.",
            pending.txid,
            hex::encode(pending.cpo_root),
            hex::encode(new_root),
            pending.fulfilled.len(),
            pending.spends,
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

/// Fold a CONFIRMED TM's swept deposits into this node's persisted swept
/// peg-ins trie: every tx input except input 0 becomes an entry [SPI-1], all
/// valued with the TM's own input-0 outpoint [SPI-3].
///
/// Same discipline as [`advance_cpo_trie`], for the same reasons: only after
/// confirmation, and only if the post-insert root equals the movement's
/// `spi_root` – on a divergence the file is NOT written, because a wrong trie
/// signs confidently wrong roots while a stale one fails loudly at the next
/// [SPI-2] gate.
///
/// `dir` is the caller's, as in [`advance_cpo_trie`].
fn advance_spi_trie(
    config: &EpochConfig,
    dir: &std::path::Path,
    pending: &crate::epoch::pending_tm::PendingTm,
) -> EpochResult<()> {
    use crate::cardano::spi_trie::SpiTrie;

    let me = config.identity.identifier;
    let epoch = pending.epoch;
    let mut trie = SpiTrie::load(dir)
        .map_err(|e| EpochError::TmBuild(format!("swept peg-ins trie: {e}")))?
        .unwrap_or_default();

    let new_root = trie
        .insert_for_confirmed_tm(&pending.swept)
        .map_err(|e| EpochError::TmBuild(format!("swept peg-ins trie: {e}")))?;
    if new_root != pending.spi_root {
        return Err(EpochError::TmBuild(format!(
            "swept peg-ins trie diverged: TM {} carries root {} but this node's trie reaches \
             {} after inserting its {} swept input(s) – NOT persisting. Either the chain \
             confirmed a DIFFERENT movement on top of {}, or this node's trie was already \
             behind; both are repaired by `reconstruct-spi-trie`.",
            pending.txid,
            hex::encode(pending.spi_root),
            hex::encode(new_root),
            pending.swept.len().saturating_sub(1),
            pending.spends,
        )));
    }
    trie.save(dir)
        .map_err(|e| EpochError::TmBuild(format!("swept peg-ins trie: {e}")))?;
    crate::epoch_log!(
        me,
        epoch,
        "  swept peg-ins trie advanced to root {} ({} entr(y|ies))",
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

/// Wait for a handoff this node planned but cannot authorize, until it lands or
/// the epoch ends (WI-114).
///
/// Entered from `publish_keys_phase` on `EpochError::NotOursToAuthorize` — the
/// treasury's `current_spos_frost_key` is a key this node holds no share of, so
/// the rotation is real and correct but somebody else has to post it. On a
/// Phase-1 bridge that somebody is the federation: external, on a schedule this
/// node cannot know, and observed on preprod to take hours. Before this, that
/// answer was an ordinary error, so it burned the handoff retry budget (~2
/// minutes) and then parked in `Idle` — leaving the node blind to its own
/// treasury changing hands for the rest of a five-day epoch.
///
/// The exit condition is `plan_update_y` answering `None`, which is the same
/// question the cascade's stand-down already asks and means "the treasury
/// already names this key". Polling for the ANSWER rather than for a change of
/// key is what makes the resume safe: it is true exactly when this node's Y_51
/// is in charge. A rotation to some THIRD key leaves it false, and this node
/// rightly keeps waiting — it can do nothing with a key it holds no share of,
/// and the boundary re-derives everything anyway.
///
/// Cadence is `batch_poll_ceiling` (5 min), not `poll_interval` (5 s). Five days
/// of five-second reads is the API-quota problem the retry budget was introduced
/// to avoid, and this is the machine's established cadence for waiting on a
/// chain event that is hours away — the batch loop's own heartbeat.
async fn await_rotation_phase(
    chain: &Arc<dyn CardanoChain>,
    config: &EpochConfig,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();
    let y_51 = group_xonly(&group_keys.verifying_key)
        .map_err(EpochError::Frost)?
        .xonly;
    loop {
        // Asked BEFORE the first sleep, for the same reason the cascade asks
        // before its own: the rotation may well have landed while this node was
        // discovering it could not post it.
        if chain.plan_update_y(epoch, y_51).await?.is_none() {
            crate::epoch_log!(
                me,
                epoch,
                "AwaitRotation: the handoff landed — treasury_info now names {}, so this \
                 roster's key is in charge and the batch loop can start",
                hex::encode(y_51.serialize())
            );
            config.health.update(|h| {
                h.epoch = Some(epoch);
                h.activity = "handoff landed".into();
            });
            // Back into the phase this came from, NOT forward into the batch
            // loop. `plan_update_y` now answers `None`, so `PublishKeys` takes
            // its "no Update-Y needed" branch and runs its own tail — the
            // `dkg_qualified` health update and `publish_group_key`, which is
            // what tells `query_treasury` which Taproot tree the head is locked
            // under. Returning `CollectPegins` here would skip both and reach
            // `BuildTm` on a stale view of the treasury.
            //
            // Not `EpochStart` either (which is where WI-113's post-handoff fix
            // goes): that re-derives the ceremony, and on a node with no
            // `state_dir` it re-RUNS the DKG and lands on a fresh Y_51 that the
            // treasury does not name. Nothing here needs re-deriving — the key
            // just installed is the one already in hand.
            return Ok(EpochPhase::PublishKeys {
                epoch,
                roster,
                group_keys,
            });
        }
        // The only bound the watch needs. A boundary re-derives everything from
        // chain, and `await_epoch_boundary` returns at once for an epoch it has
        // not yet run, so `Idle` here costs nothing.
        let now = chain.current_epoch().await?;
        if now != epoch {
            crate::epoch_warn!(
                me,
                epoch,
                "AwaitRotation: epoch {now} began before the handoff landed — the treasury keeps \
                 the outgoing key and this roster carries over unrotated"
            );
            return Ok(EpochPhase::Idle);
        }
        config.health.update(|h| {
            h.epoch = Some(epoch);
            h.activity = "waiting for another party to post the Update-Y".into();
        });
        crate::epoch_log!(
            me,
            epoch,
            "AwaitRotation: treasury_info still names the outgoing key; re-reading in {}s",
            config.batch_poll_ceiling.as_secs()
        );
        tokio::time::sleep(config.batch_poll_ceiling).await;
    }
}

/// Did the DKG path fail in a way the federation could cover for?
///
/// `DkgAborted` is the ceremony giving up — no viable candidate set, or this node
/// outside it. `PollTimeout` is the rounds running out of time waiting for peers,
/// which on a genesis bridge is what "nobody is there" looks like. Both mean the
/// epoch will produce no group key, which is precisely when the federation should
/// be asked instead.
///
/// Everything else is deliberately excluded. A `Chain` error means we could not
/// read the registry, not that it is empty — falling back on it would take the
/// federation route every time the node's provider hiccuped. `Frost` means the
/// ceremony produced something wrong, which is a fault to investigate, not a
/// reason to route around.
fn dkg_unavailable(e: &EpochError) -> bool {
    matches!(
        e,
        EpochError::DkgAborted { .. } | EpochError::PollTimeout { .. }
    )
}

/// The Phase-1 fallback: when the DKG path cannot deliver, sign the treasury's
/// key path with the federation instead.
///
/// **Taken on failure, not on prediction.** The DKG is always attempted first —
/// a bridge whose registry can produce a roster should produce one, and that
/// ceremony's Update-Y *is* the Phase-2 transition. Only once the attempt has
/// actually failed (an empty or sub-threshold registry, this node not eligible,
/// or a ceremony that timed out) is the federation asked to sign. Predicting
/// viability up front would race the registry and take the federation route on a
/// bridge that was one late peer away from a real ceremony.
///
/// Declining returns the ORIGINAL DKG error, so a node that is not a federation
/// member keeps the diagnostic that actually applies to it.
///
/// **The phase test is a comparison, not a flag.** §Rollout Phases is explicit
/// that "there is no phase flag anywhere — the transition *is* the first
/// Update-Y", and the TreasuryDatum table says `current_spos_frost_key` holds
/// "$Y_{51}$ after the first successful DKG; **$Y_{federation}$ from K1 until
/// then**". So `authorized_key == config_y_fed` is exactly the statement that no
/// Update-Y has ever landed, and the two diverge for ever the moment one does.
/// Nothing is configured and nothing is remembered across restarts: a node that
/// joins a bridge mid-life reaches the same answer as one that watched it deploy.
///
/// Both halves come from ONE chain read — see [`TreasuryUtxo::authorized_key`]
/// for why the PHASE is that field and not `y_51`.
///
/// Phase is not the whole test, though, because phase is about AUTHORITY and
/// this function is about CAPABILITY. An Update-Y rotates the datum the instant
/// it confirms; the coins move only when a movement spends them there. In the
/// window between, the federation is the only party that can spend a head still
/// locked under `y_federation`, and the movement that does IS the handoff the
/// Update-Y is waiting for — so Phase 2 alone does not disqualify it.
///
/// [`TreasuryUtxo::authorized_key`]: crate::epoch::traits::TreasuryUtxo::authorized_key
#[allow(clippy::too_many_arguments)]
async fn phase1_fallback(
    chain: &Arc<dyn CardanoChain>,
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    epoch: u64,
    dkg_err: EpochError,
) -> EpochResult<EpochPhase> {
    let log_id = config.identity.identifier;
    let treasury = match chain.query_treasury().await {
        Ok(t) => t,
        // Could not establish the phase, so the DKG failure stands. Reported
        // rather than swallowed: "the DKG failed" and "we could not check
        // whether the federation should have covered for it" are different
        // situations for an operator.
        Err(e) => {
            crate::epoch_warn!(
                log_id,
                epoch,
                "  could not read the treasury to check for a Phase-1 fallback: {e}"
            );
            return Err(dkg_err);
        }
    };
    // Decline only when the coins have moved on TOO. Phase 2 with a head still
    // locked under `y_federation` is the handoff window, not a bridge that has
    // finished handing over: on preprod on 2026-08-18 the federation posted the
    // Update-Y, the datum rotated, and from that instant the roster could not
    // spend the treasury (wrong key) while the federation would not try (right
    // key, and it read the rotated datum as "not mine") — 299807 sat with no
    // party willing and able. `y_51` is the head's actual lock, chosen by
    // matching its scriptPubKey against the candidates.
    //
    // This widens nothing on its own: the share-versus-`y_51` check below still
    // decides whether this node can sign, and is strictly more precise than
    // either comparison here.
    if treasury.authorized_key != treasury.config_y_fed && treasury.y_51 != treasury.config_y_fed
    {
        // A roster key both authorizes AND holds the treasury, so a failed
        // ceremony is just a failed ceremony. The old roster carries over and
        // the next boundary retries — the spec's "no halt, no special state".
        return Err(dkg_err);
    }

    let Some(signer) = config.phase1_signer.as_ref() else {
        // Not a federation member. On a Phase-1 bridge that is simply idle: the
        // movements are the federation's to make, and this node has nothing to
        // contribute until the first Update-Y hands the treasury to a roster.
        crate::epoch_log!(
            log_id,
            epoch,
            "  the bridge is still in Phase 1 (treasury key == Config y_federation {}), so \
             treasury movements are the FEDERATION's to sign. This node holds no federation \
             share, so it has nothing to contribute until the first Update-Y hands the \
             treasury to an SPO roster",
            hex::encode(treasury.config_y_fed.serialize())
        );
        return Err(dkg_err);
    };

    // The share must be a share OF the key the treasury is actually locked
    // under. A federation that re-ran its ceremony produces a DIFFERENT
    // Y_federation — and therefore a different treasury address — so a stale
    // share would sign perfectly valid signatures for a key that owns nothing.
    // Checked against the group package, not against any stored label.
    let share_y = group_xonly(&signer.group_keys.verifying_key)
        .map_err(EpochError::Frost)?
        .xonly;
    if share_y != treasury.y_51 {
        return Err(EpochError::Transition(format!(
            "this node's federation share is a share of {}, but the treasury is locked under {} \
             (Config y_federation {}). A share only signs for the key its own ceremony produced, \
             so this one cannot move the treasury. Either this node holds a share from a \
             superseded ceremony, or it is configured against a different bridge",
            hex::encode(share_y.serialize()),
            hex::encode(treasury.y_51.serialize()),
            hex::encode(treasury.config_y_fed.serialize()),
        )));
    }

    // The FROST identifier the ceremony assigned is authoritative — the same
    // rule the post-DKG phases follow — and the roster must contain it, because
    // that is how peers address this node's published payloads.
    let mut roster = signer.roster.clone();
    let me = *signer.group_keys.key_package.identifier();
    let Some(own) = roster.participants.get(&me) else {
        return Err(EpochError::Transition(format!(
            "this node's federation share carries FROST identifier {} but the configured \
             [federation] roster has no member at that index ({} member(s)). The share was \
             generated for a different membership than the one configured now",
            crate::frost::identifier_u16(me),
            roster.participants.len(),
        )));
    };
    // ...and it must be THIS node's entry. The identifier is positional, so a
    // roster edited after the ceremony can leave the share pointing at a member
    // whose key is somebody else's — which would publish payloads signed by the
    // wrong identity under an index peers expect to be another member's.
    if !config.identity.bifrost_id_pk.is_empty()
        && own.bifrost_id_pk != config.identity.bifrost_id_pk
    {
        return Err(EpochError::Transition(format!(
            "this node's federation share sits at roster index {}, which the configured \
             [federation] roster says is member {} — not this node ({}). The roster changed \
             after the ceremony ran",
            crate::frost::identifier_u16(me),
            hex::encode(&own.bifrost_id_pk),
            hex::encode(&config.identity.bifrost_id_pk),
        )));
    }
    roster.epoch = epoch;

    crate::epoch_log!(
        log_id,
        epoch,
        "Phase 1: no Update-Y has landed (treasury key == Config y_federation {}), so the \
         FEDERATION signs this movement's key path — {}-of-{}, this node at index {}. Skipping \
         DKG: there is no roster to run one over and no key to rotate to",
        hex::encode(treasury.config_y_fed.serialize()),
        roster.min_signers,
        roster.max_signers,
        crate::frost::identifier_u16(me),
    );
    if roster.min_signers < roster.max_signers {
        // Honest about a limitation that is not Phase-1-specific: the signing
        // rounds poll EVERY peer rather than the first `t` to answer
        // (`poll_sign_round`'s `need = peers + 1`), so a `t`-of-`n` federation
        // still needs all `n` up to produce a movement. Worth saying out loud
        // here because `t = n - 1` is the recommended federation threshold, so
        // an operator has explicit reason to expect otherwise.
        crate::epoch_warn!(
            log_id,
            epoch,
            "  note: the federation threshold is {}-of-{}, but the signing rounds currently \
             require ALL {} members to respond — a dark member stalls the movement rather than \
             being signed around",
            roster.min_signers,
            roster.max_signers,
            roster.max_signers,
        );
    }

    // WI-113: before settling into Phase-1 operation, see whether the SPO roster
    // has produced a key worth handing custody to. Opportunistic on purpose —
    // a failure here must not cost the movement this fallback exists to make,
    // so it logs and returns rather than propagating.
    if try_succession_handoff(chain, peers, clock, rng, config, epoch, signer, log_id).await {
        // The rotation landed, so `current_spos_frost_key` is the ROSTER's key
        // now and this node's federation share no longer authorizes anything.
        // Continuing into CollectPegins would spend the rest of the epoch
        // building movements signed under a key the datum no longer names —
        // every one rejected on chain, by the node that just logged that its own
        // share "stops being the treasury's authority from here".
        //
        // Re-entering EpochStart re-reads the phase from the chain instead: the
        // node then finds `authorized_key != config_y_fed`, i.e. Phase 2, and
        // the fallback declines for the right reason rather than by accident.
        return Ok(EpochPhase::EpochStart { epoch });
    }

    Ok(EpochPhase::CollectPegins {
        epoch,
        roster,
        group_keys: signer.group_keys.clone(),
    })
}

/// Poll the roster until it advertises one agreed DKG namespace, or the budget
/// runs out.
///
/// The budget is deliberately modest: the ceremony starts within a window or two
/// of the boundary, so a few minutes covers the normal case, and a roster that
/// has not started by then has not started at all — the next epoch's attempt is
/// the right place to find out, not a longer wait here.
async fn wait_for_published_namespace(
    peers: &Arc<dyn PeerNetwork>,
    roster: &crate::epoch::state::Roster,
    config: &EpochConfig,
    epoch: u64,
    log_id: frost::Identifier,
) -> Option<crate::http::wire::DkgNamespace> {
    // Scaled from the poll interval rather than a wall-clock constant, so the
    // same code path is exercised under a test config instead of being waited
    // out by it: ~10 minutes at the production 5s cadence, milliseconds in a
    // unit test. A chain-anchored ceiling (the schedule's update_y deadline)
    // would be the more principled source and match WI-077 — noted rather than
    // done, because it is a second chain read on a path that must not fail.
    let budget = config.poll_interval.saturating_mul(120);
    let deadline = std::time::Instant::now() + budget;
    let mut announced = false;
    loop {
        if let Some(ns) = crate::epoch::succession::published_namespace(peers, roster).await {
            return Some(ns);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        if !announced {
            crate::epoch_log!(
                log_id,
                epoch,
                "  handoff: waiting up to {budget:.0?} for the roster to start its ceremony"
            );
            announced = true;
        }
        // Never past the deadline, so the wait cannot overshoot the budget.
        let nap = config
            .poll_interval
            .min(deadline.saturating_duration_since(std::time::Instant::now()));
        tokio::time::sleep(nap).await;
    }
}

/// Hand the treasury to the SPO roster, if the roster has earned it (WI-113).
///
/// This is the Phase-2 transition seen from the only party that can make it. The
/// federation is not in the registry and did not run the epoch DKG, so it does
/// not hold `Y_51` — it recomputes it from what the roster published
/// ([`crate::epoch::succession`]) and hands over only if the ceremony is
/// complete and unchallenged.
///
/// **Nothing here is fatal.** Every exit is a log line and a return: the roster
/// may not exist yet, may still be mid-ceremony, or may have failed, and all
/// three are ordinary states of a bridge waiting for its SPOs. Treating any of
/// them as an error would take down the node that is currently the only one able
/// to move the treasury at all.
#[allow(clippy::too_many_arguments)]
async fn try_succession_handoff(
    chain: &Arc<dyn CardanoChain>,
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    epoch: u64,
    signer: &crate::epoch::state::Phase1Signer,
    log_id: frost::Identifier,
) -> bool {
    use crate::epoch::succession::{SuccessionEvidence, gather, succession_key};

    let ctx = match chain.query_dkg_context(epoch, 0).await {
        Ok(c) => c,
        Err(e) => {
            crate::epoch_log!(
                log_id,
                epoch,
                "  handoff: no SPO roster to hand to yet ({e})"
            );
            return false;
        }
    };
    let spo_roster = ctx.to_roster();
    if spo_roster.participants.is_empty() {
        crate::epoch_log!(log_id, epoch, "  handoff: the SPO registry is still empty");
        return false;
    }

    // Asked for, never computed: the attempt is window*DKG_ATTEMPTS_PER_WINDOW
    // counted from whenever each SPO entered its ceremony window, so no outsider
    // can derive it — assuming 0 fetched URLs no SPO serves and reported the
    // roster as silent for ever.
    // Wait for the ceremony rather than racing it.
    //
    // This runs seconds after the epoch boundary — a federation node fails
    // `own_participant` immediately and lands here — while the SPOs are still in
    // their health gate and have not yet joined a ceremony window. The audit is
    // attempted once per epoch and the loop does not revisit EpochStart within
    // one, so probing at this instant and giving up means missing by minutes and
    // then waiting a whole epoch: five days on preprod and mainnet.
    //
    // Blocking here is affordable in a way it would not be elsewhere: this is the
    // Phase-1 path, movements are paced by `tm_batch_interval` (six hours on this
    // bridge), and a genesis bridge has no movements to delay at all.
    let Some(ns) = wait_for_published_namespace(peers, &spo_roster, config, epoch, log_id).await
    else {
        crate::epoch_log!(
            log_id,
            epoch,
            "  handoff: the roster is not advertising one agreed DKG namespace yet — either the \
             ceremony has not run, or its members are in different ones"
        );
        return false;
    };
    let (round1, round2) = gather(peers, &spo_roster, ns).await;
    // The eligible set is ALREADY ban-filtered by `query_dkg_context`, so this
    // is a belt-and-braces pass rather than the enforcement: it catches a ban
    // that is visible in `excluded` but whose member somehow survived into the
    // roster, which would be a bug upstream rather than a protocol event.
    let faulted: Vec<Vec<u8>> = ctx
        .excluded
        .iter()
        .filter(|x| {
            matches!(
                x.reason,
                crate::cardano::dkg_roster::ExclusionReason::Banned
            )
        })
        .map(|x| x.pool_id.clone())
        .collect();

    let y_51 = match succession_key(&SuccessionEvidence {
        roster: &spo_roster,
        round1: &round1,
        round2: &round2,
        faulted: &faulted,
    }) {
        Ok(k) => k,
        Err(why) => {
            crate::epoch_log!(
                log_id,
                epoch,
                "  handoff: not yet — {why}. Holding the treasury under the federation key"
            );
            return false;
        }
    };
    crate::epoch_log!(
        log_id,
        epoch,
        "  handoff: the SPO roster's ceremony is complete and unchallenged; its key is {} \
         (recomputed here from {} published round-1 commitment(s), not taken on trust)",
        hex::encode(y_51.serialize()),
        round1.len()
    );

    let plan = match chain.plan_update_y(epoch, y_51).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            crate::epoch_log!(
                log_id,
                epoch,
                "  handoff: already done (the datum names this key)"
            );
            return false;
        }
        Err(e) => {
            crate::epoch_warn!(log_id, epoch, "  handoff: cannot plan the rotation: {e}");
            return false;
        }
    };
    let window = match chain.query_batch_snapshot().await {
        Ok(snap) => rotation_window(clock, &snap),
        Err(e) => {
            crate::epoch_warn!(
                log_id,
                epoch,
                "  handoff: no schedule to bound the rounds: {e}"
            );
            return false;
        }
    };
    let me = *signer.group_keys.key_package.identifier();
    let signature = match crate::epoch::rotation::authorize_update_y(
        peers, clock, rng, config, me, &plan, window,
    )
    .await
    {
        Ok((sig, authority)) => {
            crate::epoch_log!(log_id, epoch, "  handoff authorized by {authority}");
            sig
        }
        Err(e) => {
            crate::epoch_warn!(
                log_id,
                epoch,
                "  handoff: the federation could not sign it: {e}"
            );
            return false;
        }
    };
    match chain.submit_update_y(&plan, &signature).await {
        Ok(tx) => {
            crate::epoch_log!(
                log_id,
                epoch,
                "  HANDOFF POSTED: tx {tx} — the treasury is now the SPO roster's. This node's \
                 federation share stops being the treasury's authority from here"
            );
            true
        }
        Err(e) => {
            crate::epoch_warn!(log_id, epoch, "  handoff: submission failed: {e}");
            false
        }
    }
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
    let ctx = chain.query_dkg_context(epoch, 0).await?;

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
    let incompatible = wait_for_roster_health(peers, &ctx, config, me).await;
    // WI-067: drop the reachable-but-incompatible peers from the candidate set
    // before anything is published. Nothing has been generated yet, so this is
    // simply a smaller candidate set — `t` is re-derived over it and `attempt`
    // does not move.
    //
    // It converges without any agreement protocol because the comparison is
    // symmetric: every node compares each peer against ITSELF, so a node on a
    // different minor is dropped by all of its peers and drops all of them, and
    // the two groups run (or fail to run) separately rather than corrupting one
    // ceremony. `None` means what is left cannot run at all, which is the
    // existing abort — loud, and correct: the roster really has gone below what
    // a DKG needs.
    let mut ctx = if incompatible.is_empty() {
        ctx
    } else {
        match ctx.without(&incompatible) {
            Some(narrowed) => {
                crate::epoch_warn!(
                    me,
                    epoch,
                    "  candidate set reduced to {} of {} by software mismatch; t is now {}",
                    narrowed.participants.len(),
                    ctx.participants.len(),
                    narrowed.threshold,
                );
                narrowed
            }
            None => {
                return Err(EpochError::DkgAborted {
                    epoch,
                    attempt: ctx.attempt,
                    eligible: ctx.participants.len(),
                    qualified: ctx.participants.len().saturating_sub(incompatible.len()),
                    reason: format!(
                        "{} of {} candidates run an incompatible build, leaving too few to run \
                         a ceremony — upgrade the lagging nodes",
                        incompatible.len(),
                        ctx.participants.len()
                    ),
                });
            }
        }
    };

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
/// elapses (N21), and return the peers whose BUILD is incompatible with ours
/// (WI-067).
///
/// Never fails on reachability: proceeding without a peer is always legal — the
/// ceremony's quorum gate decides viability, and this gate only makes the happy
/// path start complete.
///
/// The build check is not the same kind of thing. An unreachable peer is absent
/// and the ceremony copes; a peer on a DIFFERENT minor is present and answering,
/// and will happily produce payloads that look fine while it computes different
/// bytes than we do — different batch weights, a different leader, a different
/// policy id. That is the silent-divergence failure this whole area keeps
/// meeting, so an incompatible peer is EXCLUDED from the candidate set rather
/// than left to join.
///
/// Excluded rather than refused, deliberately: refusing would let one operator
/// who has not upgraded halt the bridge, whereas excluding costs that operator
/// its own participation and nothing else. The quorum gate still decides whether
/// what remains can run at all.
async fn wait_for_roster_health(
    peers: &Arc<dyn PeerNetwork>,
    ctx: &crate::cardano::dkg_roster::DkgContext,
    config: &EpochConfig,
    me: frost::Identifier,
) -> BTreeSet<frost::Identifier> {
    use crate::http::compat::Compatibility;

    let roster = ctx.to_roster();
    let deadline = tokio::time::Instant::now() + config.dkg_join_wait;
    let poll = config
        .poll_interval
        .max(std::time::Duration::from_millis(200));
    let mut incompatible: BTreeSet<frost::Identifier> = BTreeSet::new();
    loop {
        let mut down = Vec::new();
        for info in roster.participants.values() {
            if info.identifier == me {
                continue;
            }
            let health = peers.check_health(info).await;
            if !health.reachable {
                down.push(crate::epoch::log::id_short(info.identifier));
                continue;
            }
            // Logged ONCE per peer per gate, not per poll: the loop can turn
            // every 200 ms and this is the line an operator has to find.
            if let Compatibility::Incompatible { reason } = health.compatibility()
                && incompatible.insert(info.identifier)
            {
                crate::epoch_warn!(
                    me,
                    ctx.epoch,
                    "  ⚠ EXCLUDING spo={} from the ceremony: {reason}. It is running and \
                     reachable — this is a software mismatch, not an outage. Both sides log \
                     this, so that operator sees the same line from its own node. Upgrade the \
                     lagging node to rejoin.",
                    crate::epoch::log::id_short(info.identifier),
                );
                // Also on the operator surface: this is the one failure invisible
                // from the excluded node's chain state — registered, unbanned,
                // reachable, and simply not being talked to.
                let line = format!(
                    "spo={}: {reason}",
                    crate::epoch::log::id_short(info.identifier)
                );
                config.health.update(|h| h.excluded_peers.push(line));
            }
        }
        if down.is_empty() {
            crate::epoch_log!(me, ctx.epoch, "health gate: full roster reachable");
            return incompatible;
        }
        if tokio::time::Instant::now() >= deadline {
            crate::epoch_warn!(
                me,
                ctx.epoch,
                "health gate: proceeding without unreachable peer(s) {:?} after {:?}",
                down,
                config.dkg_join_wait
            );
            return incompatible;
        }
        // Per-poll, and `poll` can be 200ms — at info this drowns the join. Both
        // ways out of the loop log (reachable → info, deadline → warn), so the
        // operator still learns the outcome and which peers were missing.
        crate::epoch_debug!(
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
            crate::epoch_warn!(
                me,
                epoch,
                "persisted DKG for epoch {epoch} is bound to a different identity — ignoring, \
                 running a fresh ceremony"
            );
            Ok(None)
        }
        Err(e) => {
            crate::epoch_warn!(
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
    // This node already published a commitment for this epoch's rotation and
    // the round failed (WI-048). Re-entering is worth it only to LOOK: if the
    // threshold subset landed the Update-Y without us, `plan_update_y` returns
    // None and this phase walks through to the batch loop. If it did not, the
    // ceremony must not run a second time in the same namespace.
    rotation_spent: bool,
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
            let new_spend =
                treasury_spend_info(&secp, y_51, treasury.y_fed, treasury.federation_csv_blocks);
            let new_spk = bitcoin::ScriptBuf::new_p2tr_tweaked(new_spend.output_key());
            crate::epoch_log!(
                me,
                epoch,
                "  -> new treasury: output_key={} scriptPubKey={}",
                hex::encode(new_spend.output_key().to_x_only_public_key().serialize()),
                hex::encode(new_spk.as_bytes())
            );
        }
        Err(e) => crate::epoch_debug!(
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
        Some(_) if rotation_spent => {
            return Err(EpochError::RoundSpent {
                round: 1,
                cause: Box::new(EpochError::Chain(format!(
                    "the epoch-{epoch} rotation round is spent and treasury_info still names \
                     the old key, so the threshold subset did not land it either"
                ))),
            });
        }
        Some(plan) => {
            crate::epoch_log!(
                me,
                epoch,
                "  Update-Y: rotating treasury_info {} from {} to {}",
                plan.state_outpoint,
                hex::encode(plan.current_key.serialize()),
                hex::encode(plan.new_key.serialize())
            );
            // One snapshot for both chain-derived quantities this phase needs:
            // when the ceremony's rounds close, and where the submission cascade
            // starts. Read once, before the ceremony, so the deadline is fixed
            // before any nonce is published rather than after.
            let snapshot = chain.query_batch_snapshot().await?;
            let authorized = rotation::authorize_update_y(
                peers,
                clock,
                rng,
                config,
                me,
                &plan,
                rotation_window(clock, &snapshot),
            )
            .await;
            // WI-114. "Not mine to authorize" is an ANSWER, and a stable one:
            // the treasury names a key this node holds no share of, so no
            // retry can change it and no ceremony here can produce the
            // signature. Treating it as a failure is what left the node blind
            // — it spent the handoff retry budget (~2 min) on a question that
            // was already answered and then parked in `Idle` until the next
            // boundary, while on a Phase-1 bridge the federation that CAN post
            // it took hours. Hand it to the watch instead, which is the only
            // response that fits: what is being waited for is another party's
            // action.
            let (signature, authority) = match authorized {
                Ok(v) => v,
                Err(e) if matches!(e.cause(), EpochError::NotOursToAuthorize(_)) => {
                    crate::epoch_warn!(
                        me,
                        epoch,
                        "Update-Y: {e} — so this node WATCHES treasury_info for the party that \
                         can post it, rather than parking until the next boundary. It signs no \
                         movement until the handoff lands."
                    );
                    return Ok(EpochPhase::AwaitRotation {
                        epoch,
                        roster,
                        group_keys,
                    });
                }
                Err(e) => return Err(e),
            };
            crate::epoch_log!(me, epoch, "  Update-Y authorized by {authority}");

            // WI-099: the cascade runs over the roster that PRODUCED the
            // signature, which is the outgoing one — only its members hold a
            // share of the key the plan is authorized under. This used to elect
            // from the incoming roster, and the two diverge exactly when roster
            // churn makes a rotation matter: a newly registered SPO, one that
            // restarted with a wiped state_dir, or one banned and rejoined can be
            // the incoming roster's leader while holding no outgoing share at
            // all. That node failed in `authorize_update_y` before ever reaching
            // the election, while every node that COULD post saw `me != leader`
            // and stood down — so a valid Update-Y was computed and discarded,
            // including after a ban, which is the case the rotation exists for.
            //
            // On the federation path there is no roster and no cascade: whoever
            // holds the seed is the only party that can sign, so it posts.
            let electorate = match &authority {
                rotation::UpdateYAuthority::OutgoingRoster { roster, .. } => Some(roster.as_ref()),
                rotation::UpdateYAuthority::Federation => None,
            };
            let mut cascade = None;
            // `prev_tm_txid` is the same value the movement cascade uses — the
            // txid of the current treasury outpoint — and `tm_sequence` is the
            // spec's literal "dkg", which is what stops this election collapsing
            // onto the same node as the epoch's first movement.
            let wait = match electorate {
                Some(_) => {
                    let head = chain.query_treasury().await?.outpoint.txid.to_byte_array();
                    cascade = electorate
                        .and_then(|r| r.cascade(&head, crate::epoch::leader::TmSequence::Dkg));
                    cascade.as_ref().and_then(|c| {
                        cascade_wait(c, me, snapshot.slot, snapshot.slot, snapshot.leader_slot_t)
                    })
                }
                None => None,
            };
            if let Some(wait) = wait {
                let c = cascade.as_ref().expect("wait implies a cascade");
                // "Each SPO monitors the chain — if a predecessor has already
                // submitted, it does nothing." A completed rotation leaves
                // nothing to plan, so `plan_update_y` answering `None` IS that
                // check. Asked BEFORE the sleep as well as after, so a follower
                // whose leader has already posted rejoins the batch loop at once
                // instead of arriving a hop behind its peers.
                let stand_down = |me: frost::Identifier, why: &str| {
                    crate::epoch_log!(
                        me,
                        epoch,
                        "  Update-Y: {why} — standing down, as the cascade intends"
                    );
                };
                if chain.plan_update_y(epoch, y_51).await?.is_none() {
                    stand_down(me, "already on chain");
                    return Ok(EpochPhase::CollectPegins {
                        epoch,
                        roster,
                        group_keys,
                    });
                }
                crate::epoch_log!(
                    me,
                    epoch,
                    "  Update-Y: hop {} of the cascade behind {:?}, nothing posted yet — holding \
                     the signature for {}s",
                    c.hops_before(me).unwrap_or(0),
                    c.leader(),
                    wait.as_secs(),
                );
                tokio::time::sleep(wait).await;
                if chain.plan_update_y(epoch, y_51).await?.is_none() {
                    stand_down(me, "a predecessor posted while this node waited");
                    return Ok(EpochPhase::CollectPegins {
                        epoch,
                        roster,
                        group_keys,
                    });
                }
            }
            let tx_id = chain.submit_update_y(&plan, &signature).await?;
            crate::epoch_log!(me, epoch, "  Update-Y submitted: cardano tx {tx_id}");
        }
    }

    // This node finished the ceremony holding a share — the affirmative half of
    // the question an operator most wants answered, and the one a log line
    // scrolls away.
    config.health.update(|h| {
        h.epoch = Some(epoch);
        h.dkg_qualified = Some(true);
        h.activity = "keys published".into();
    });

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

/// Whether the machine may build at the opportunity it just reached.
enum BatchTurn {
    /// Freeze and build. `None` is a chain with no grid at all (a mock, or a
    /// deployment whose Config carries no `schedule`) — there is no opportunity to
    /// respect, so the machine falls back to its pre-grid cadence.
    Build(Option<crate::epoch::batch::BatchSlot>),
    /// The epoch's grid is exhausted: every remaining slot is past
    /// `final_tm_cutoff`. Wait for the next boundary.
    EpochOver,
}

/// Sleep until this epoch's next batch opportunity, and report whether to build
/// at it (spec §TM batches and the protocol schedule).
///
/// The grid is slot-anchored rather than event-driven — "freeze when the previous
/// TM confirms" would hang the freeze anchor off a Confirm transaction's inclusion
/// slot, which wavers during Cardano rollbacks and flips boundary items in and out
/// of the batch. So every SPO waits for the same absolute `B_i` and reads the same
/// chain state there.
///
/// Every wait is the EXACT hop to the opportunity being waited for, bounded by
/// `config.batch_poll_ceiling` — see [`hop_to_opportunity`]. That has to hold in
/// both waiting states, not just before `B_1`: [`GridParams::current`] reports the
/// same `B_i` for a whole interval, so a running node sees `Open` continuously and
/// a blind poll would have each node notice `B_{i+1}` at its own offset past it.
/// `collect_pegins_phase` reads the peg-in source once at that moment, so those
/// offsets are differences in what gets frozen.
///
/// [`GridParams::current`]: crate::epoch::batch::GridParams::current
async fn await_batch_opportunity(
    chain: &Arc<dyn CardanoChain>,
    config: &EpochConfig,
    me: frost::Identifier,
    epoch: u64,
    built: &mut BuiltBatch,
) -> EpochResult<BatchTurn> {
    use crate::epoch::batch::BatchWindow;
    loop {
        let snapshot = chain.query_batch_snapshot().await?;
        let wait = match snapshot.batch {
            // An opportunity is open and this process has not built for it.
            BatchWindow::Open { batch: b, .. } if !built.is(epoch, b.index) => {
                built.mark(epoch, b.index);
                config.health.update(|h| {
                    h.epoch = Some(epoch);
                    h.activity = format!("building batch B_{}", b.index);
                    h.last_progress_ms = Some(snapshot.now_ms);
                    h.grid = Some(crate::health::GridPosition {
                        slot: snapshot.slot,
                        batch: Some(b.index),
                        next_slot: snapshot.batch.next().map(|n| n.slot),
                    });
                });
                crate::epoch_log!(
                    me,
                    epoch,
                    "═══ batch B_{} @ slot {} (membership cutoff: created at or before slot {}) ═══",
                    b.index,
                    b.slot,
                    b.cutoff_slot
                );
                return Ok(BatchTurn::Build(Some(b)));
            }
            BatchWindow::NoGrid if !built.is(epoch, BuiltBatch::NO_GRID) => {
                built.mark(epoch, BuiltBatch::NO_GRID);
                // No grid to report a position on, but the loop still reached a
                // build — and "when did this node last get somewhere" is the
                // field an operator alerts on, so it must move here too.
                config.health.update(|h| {
                    h.epoch = Some(epoch);
                    h.activity = "building (no batch grid configured)".into();
                    h.last_progress_ms = Some(snapshot.now_ms);
                    h.grid = None;
                });
                return Ok(BatchTurn::Build(None));
            }
            // No grid and this epoch's movement is already made. There is no
            // schedule to follow and no local cadence to invent (a wall-clock one
            // would have two nodes freezing different sets), so this is the
            // pre-grid behaviour: one movement, then the next boundary.
            BatchWindow::NoGrid => return Ok(BatchTurn::EpochOver),
            // Waiting, in either of its two forms: an opportunity is open but this
            // node has served it, or none is open (before B_1, or past
            // `final_tm_cutoff`). Both sleep towards the SAME thing — whatever
            // follows — and both end the epoch when nothing does. Building at a
            // closed window would post a movement outside the schedule every SPO
            // agreed on, which no co-signer would reproduce.
            ref window => {
                let Some(b) = window.next() else {
                    return Ok(BatchTurn::EpochOver);
                };
                // This IS the heartbeat WI-058 asks for, and it already existed:
                // the loop re-reads the grid at most `batch_poll_ceiling` apart
                // (5 min), so a healthy idle node says where it is and what it is
                // waiting for on that cadence rather than going silent between
                // opportunities. What was missing is the same facts somewhere an
                // operator can query instead of grepping, which is the update
                // below.
                crate::epoch_log!(
                    me,
                    epoch,
                    "waiting for batch B_{} at slot {} ({} slot(s) from slot {})",
                    b.index,
                    b.slot,
                    b.slot.saturating_sub(snapshot.slot),
                    snapshot.slot,
                );
                config.health.update(|h| {
                    h.epoch = Some(epoch);
                    h.activity = format!("waiting for batch B_{}", b.index);
                    h.last_progress_ms = Some(snapshot.now_ms);
                    h.grid = Some(crate::health::GridPosition {
                        slot: snapshot.slot,
                        batch: snapshot.batch.open().map(|o| o.index),
                        next_slot: Some(b.slot),
                    });
                });
                hop_to_opportunity(b.slot, snapshot.slot, config.batch_poll_ceiling)
            }
        };
        tokio::time::sleep(wait).await;
    }
}

/// How long to sleep before re-reading the grid: the exact hop to `next_slot`,
/// bounded by `ceiling`.
///
/// One slot is one second post-Shelley — the same identity `batch_at` uses to
/// place the grid against a `(slot, time)` pair, and the reason the hop can be
/// computed at all. The ceiling only bounds how stale a waiting node's view may
/// get; because the hop shrinks as `B_i` approaches, the final sleep lands on the
/// opportunity itself whatever the ceiling is, so the ceiling never decides WHEN a
/// node freezes. The floor of one second keeps a slot arithmetic surprise (a tip
/// already past the target) from becoming a spin.
fn hop_to_opportunity(
    next_slot: u64,
    now_slot: u64,
    ceiling: std::time::Duration,
) -> std::time::Duration {
    std::time::Duration::from_secs(next_slot.saturating_sub(now_slot).max(1)).min(ceiling)
}

/// Wait for this epoch's next batch opportunity, then read the Cardano peg-in
/// source ONCE and freeze what it holds, parsing each request against the
/// spec-derived peg-in Taproot for the current Y_51 internal key, the Y_fed
/// emergency leaf and Q_auth. Parse failures are logged and dropped. The deduped,
/// parsed set is frozen into the next `BuildTm` phase.
///
/// The read used to be a poll over a local `pegin_collection_window` — a second,
/// node-local freeze rule sitting in front of the batch's. Under the grid the
/// freeze point is the opportunity and membership is the cutoff's to decide, so
/// two freeze rules could only disagree: nodes that entered the window at
/// different moments accumulated different unions of the same source.
///
/// Residual, stated rather than implied: the peg-in side of the cutoff itself is
/// WI-049. `ParsedPegIn` carries no creation slot yet, so peg-in membership here
/// is "what the source held at `B_i`" — aligned across nodes by the grid, but not
/// yet pinned to `C_i` the way peg-outs are in `freeze_pegouts`.
async fn collect_pegins_phase(
    chain: &Arc<dyn CardanoChain>,
    pegin_source: &Arc<dyn CardanoPegInSource>,
    config: &EpochConfig,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
    built: &mut BuiltBatch,
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();

    // The gate the spec states at each `B_i`: "if the TM-chain tip is
    // Binocular-confirmed and no TM is currently in flight, the batch is frozen
    // and built; otherwise the opportunity passes unused". Passing it is not a
    // failure — with a ~6 h grid pitch and ~17 h to confirm a movement, most
    // opportunities pass by design.
    let (batch, treasury) = loop {
        let BatchTurn::Build(batch) =
            await_batch_opportunity(chain, config, me, epoch, built).await?
        else {
            crate::epoch_log!(
                me,
                epoch,
                "CollectPegins: no batch opportunity remains this epoch — waiting for the next \
                 boundary"
            );
            return Ok(EpochPhase::Idle);
        };
        let treasury = chain.query_treasury().await?;
        // The one place the head is read on a regular cadence, and therefore the
        // place a movement this node posted earlier gets folded into the tries
        // (WI-032). It runs BEFORE the gate below and before every build, so
        // `build_tm_phase`'s cross-check against the on-chain singleton never
        // sees a trie that this node already had the means to advance.
        settle_pending_tm(config, &treasury)?;
        // With no grid there is no opportunity to pass, so the tip wait inside
        // `build_tm_phase` stands as it did before the grid.
        let Some(b) = batch else {
            break (None, treasury);
        };
        if treasury.btc_confirmed {
            break (Some(b), treasury);
        }
        crate::epoch_warn!(
            me,
            epoch,
            "  batch B_{} passes UNUSED: a treasury movement is still in flight against the \
             current tip {}",
            b.index,
            treasury.outpoint
        );
    };

    // The bridge's peg-in tree, straight from the oracle. `TreasuryUtxo::pegin_tree` owns
    // the field mapping — notably that the federation LEAF key is the PUBLISHED
    // `config_y_fed`, not the head-derived `y_fed` — so no call site re-decides it.
    let pegin_tree = treasury.pegin_tree().map_err(EpochError::Chain)?;

    let mut accepted: BTreeMap<CardanoOutRef, ParsedPegIn> = BTreeMap::new();
    for req in pegin_source
        .query_pegin_requests(&config.pegin_policy_id)
        .await?
    {
        if accepted.contains_key(&req.cardano_utxo) {
            continue;
        }
        // Peg-in internal key is Y_51 (the FROST group key); Y_fed is a LEAF key —
        // see parse_pegin_request / commit 6af7c67.
        match parse_pegin_request(&req, &pegin_tree) {
            Ok(parsed) => {
                accepted.insert(req.cardano_utxo.clone(), parsed);
            }
            Err(e) => {
                crate::epoch_warn!(me, epoch, "  dropped peg-in {:?}: {}", req.cardano_utxo, e);
            }
        }
    }

    let frozen_pegins = freeze_pegins(accepted.into_values().collect(), batch, me, epoch)?;
    crate::epoch_log!(
        me,
        epoch,
        "  -> froze {} peg-in(s) for BuildTm{}",
        frozen_pegins.len(),
        batch.map_or_else(String::new, |b| format!(" at batch B_{}", b.index))
    );

    Ok(EpochPhase::BuildTm {
        epoch,
        roster,
        group_keys,
        batch,
        frozen_pegins,
    })
}

/// Freeze the discovered peg-in set against this batch (spec §TM batches; WI-049).
///
/// Two of the three rules: drop anything created after the batch's stability
/// cutoff `C_i`, and order the survivors by the FIFO total order. The third —
/// capacity — is NOT applied here, because since WI-107 it is a joint byte budget
/// over the assembled movement, so it cannot be decided without the peg-out count
/// and the two classes are frozen in different phases. `build_tm_phase` applies it
/// to this list, which arrives already ordered, by truncation.
///
/// Peg-ins differ from peg-outs in one way the spec is explicit about: an unpicked
/// peg-in **rolls over freely** to the next batch, so neither the cutoff nor the
/// budget can strand one.
///
/// Until WI-049 peg-ins had none of the three. Membership was "whatever
/// `query_pegin_requests` returned at the instant this node happened to scan",
/// ordered by Cardano outpoint. That converges two SPOs only by luck — a request
/// that lands between their scans is in one node's TM and not the other's, which
/// is a different txid and a FROST round that cannot aggregate.
fn freeze_pegins(
    pegins: Vec<ParsedPegIn>,
    batch: Option<crate::epoch::batch::BatchSlot>,
    me: frost::Identifier,
    epoch: u64,
) -> EpochResult<Vec<ParsedPegIn>> {
    use crate::epoch::batch::{FifoKey, freeze};

    // WI-106: an unresolved creation slot REFUSES the batch; it is not sorted
    // last, and it is not dropped.
    //
    // Both of those were tried and both are wrong, for the same reason: batch
    // membership is a consensus decision, so a per-node HTTP outcome must not
    // change it in EITHER direction. Whether this node includes a request its
    // peers exclude, or excludes one they include, the result is a different set,
    // a different sighash and a round that cannot aggregate. Deferring is the
    // worse of the two because it looks like success — the node builds a movement
    // omitting the request, signs it, and burns the opportunity on it.
    //
    // Refusing is self-healing: `resolve_tx_slots` has already retried, and the
    // error is retriable, so the epoch loop backs off and re-queries. It costs
    // latency on a flaky provider and nothing at all on a healthy one.
    let unresolved = pegins.iter().filter(|p| p.created_slot.is_none()).count();
    if unresolved > 0 {
        return Err(EpochError::Chain(format!(
            "{unresolved} of {} peg-in request(s) have no resolved creation slot, so this node \
             cannot compute the batch its peers will compute — refusing to build. Retrying at the \
             next tick; if it persists the peg-in source cannot supply creation slots at all (the \
             N2C source never can) and the batch grid is unusable with it.",
            pegins.len()
        )));
    }

    // The CARDANO outpoint, not the Bitcoin one: this orders REQUESTS, and the
    // request is the Cardano UTxO. (The TM's input order is a separate, Bitcoin-
    // side rule — lexicographic by (txid ‖ vout) — and is unaffected by this.)
    let key = |p: &ParsedPegIn| FifoKey {
        // Every entry is resolved by the refusal above, so the fallback is
        // unreachable rather than a policy.
        created_slot: p.created_slot.unwrap_or(u64::MAX),
        tx_hash: p.cardano_utxo.tx_hash,
        output_index: p.cardano_utxo.output_index,
    };

    let Some(batch) = batch else {
        // No grid: order only. A mock chain, or a deployment whose Config carries
        // no schedule. The budget still applies in `build_tm_phase`.
        let mut ordered = pegins;
        ordered.sort_by_key(&key);
        return Ok(ordered);
    };

    // `usize::MAX` because the capacity rule is not this function's any more; the
    // cutoff is. Passing a real cap here would be a SECOND capacity bound that the
    // joint budget could not see, which is the exact defect WI-107 removed.
    let frozen = freeze(pegins, batch, usize::MAX, key);
    if frozen.deferred() > 0 {
        crate::epoch_log!(
            me,
            epoch,
            "  batch B_{} (slot {}, cutoff {}): {} peg-in(s) eligible, {} newer than the cutoff \
             — the latter roll over to a later batch",
            batch.index,
            batch.slot,
            batch.cutoff_slot,
            frozen.selected.len(),
            frozen.too_new.len(),
        );
    }
    Ok(frozen.selected)
}

/// Freeze the open peg-out set against this batch (spec §TM batches; plan N19).
///
/// Three rules, in the order the spec states them: drop anything created after the
/// batch's stability cutoff `C_i`, order the survivors by the FIFO total order
/// `(creation slot, creating txid, output index)`, and take the first `cap`.
/// Everything held back is a candidate for a later batch — since rev 5.1 retired
/// the peg-out treasury-outpoint pin, an unpicked peg-out is merely delayed, not
/// stranded.
///
/// `cap` is the peg-out half of the joint byte budget, and peg-outs get FIRST
/// claim on it (spec rev 5.6): they are the class that expires, since a peg-out
/// that keeps missing batches falls out of the fulfillment freshness filter and
/// ends at *Cancel PegOut request*, whereas a peg-in rolls over indefinitely and
/// pays only latency. Peg-ins then take what is left.
///
/// Without a grid (`batch == None`: mock chains, and deployments whose Config
/// predates the `schedule` append) the cutoff cannot be computed and is skipped,
/// which is the pre-N19 behaviour. The FIFO order and the cap are pure and apply
/// regardless — they cost nothing and remove the last dependence on the order the
/// chain query happened to answer in.
fn freeze_pegouts(
    pegouts: Vec<crate::epoch::traits::PegOutRequestUtxo>,
    batch: Option<crate::epoch::batch::BatchSlot>,
    cap: usize,
    me: frost::Identifier,
    epoch: u64,
) -> EpochResult<Vec<crate::epoch::traits::PegOutRequestUtxo>> {
    use crate::epoch::batch::{FifoKey, freeze};

    // WI-106, exactly as on the peg-in side: an unresolved creation slot refuses
    // the batch rather than being deferred into a set this node's peers would not
    // compute. See `freeze_pegins` for why neither direction is safe.
    let unresolved = pegouts.iter().filter(|p| p.created_slot.is_none()).count();
    if unresolved > 0 {
        return Err(EpochError::Chain(format!(
            "{unresolved} of {} peg-out request(s) have no resolved creation slot, so this node \
             cannot compute the batch its peers will compute — refusing to build. Retrying at \
             the next tick.",
            pegouts.len()
        )));
    }

    let key = |p: &crate::epoch::traits::PegOutRequestUtxo| FifoKey {
        // Unreachable: the refusal above leaves every entry resolved.
        created_slot: p.created_slot.unwrap_or(u64::MAX),
        tx_hash: p.outpoint[..32].try_into().unwrap_or([0u8; 32]),
        output_index: u32::from_le_bytes(p.outpoint[32..].try_into().unwrap_or([0u8; 4])),
    };

    let Some(batch) = batch else {
        // No grid: cap and order only.
        let mut ordered = pegouts;
        ordered.sort_by_key(&key);
        ordered.truncate(cap);
        return Ok(ordered);
    };

    let frozen = freeze(pegouts, batch, cap, key);
    if frozen.deferred() > 0 {
        crate::epoch_log!(
            me,
            epoch,
            "  batch B_{} (slot {}, cutoff {}): {} peg-out(s) frozen, {} newer than the cutoff, \
             {} over the {cap}-peg-out byte budget — all deferred to a later batch",
            batch.index,
            batch.slot,
            batch.cutoff_slot,
            frozen.selected.len(),
            frozen.too_new.len(),
            frozen.over_cap.len(),
        );
    }
    Ok(frozen.selected)
}

/// Take as many of the (already cutoff-filtered, already FIFO-ordered) peg-ins as
/// the byte budget still holds once `pegouts` peg-outs have claimed their share
/// (WI-107, spec rev 5.6).
///
/// Truncation is the whole operation: `freeze_pegins` established the order, and
/// dropping from the tail is what makes the survivors the OLDEST — the same rule
/// every co-signer applies to the same list.
fn fit_pegins_to_budget<T>(
    mut pegins: Vec<T>,
    budget: &crate::epoch::batch::TmBudget,
    pegouts: usize,
    me: frost::Identifier,
    epoch: u64,
) -> Vec<T> {
    let room = budget.max_pegins_with(pegouts as u64);
    if pegins.len() <= room {
        return pegins;
    }
    if room == 0 {
        // Strict peg-out priority is the spec's rule and it is the right one —
        // peg-outs expire, peg-ins do not — but a peg-out backlog large enough to
        // fill a whole movement stops peg-ins being swept entirely, and that is
        // worth seeing rather than inferring from a batch that swept nothing.
        crate::epoch_warn!(
            me,
            epoch,
            "  {} eligible peg-in(s) get NO room: {} peg-out(s) fill the movement on their own \
             ({} of {} Post-TM bytes). They roll over — nothing is stranded — but no deposit is \
             swept until the peg-out backlog drains.",
            pegins.len(),
            pegouts,
            budget.post_tm_bytes(0, pegouts as u64),
            budget.max_tx_size,
        );
    } else {
        crate::epoch_log!(
            me,
            epoch,
            "  {} of {} eligible peg-in(s) are over the byte budget left by {} peg-out(s) \
             ({} of {} Post-TM bytes) — they roll over to a later batch",
            pegins.len() - room,
            pegins.len(),
            pegouts,
            budget.post_tm_bytes(room as u64, pegouts as u64),
            budget.max_tx_size,
        );
    }
    pegins.truncate(room);
    pegins
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
        crate::epoch_warn!(
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
            crate::epoch_warn!(
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
async fn cross_check_bridge_roots(
    chain: &Arc<dyn CardanoChain>,
    cpo_trie: &crate::cardano::cpo_trie::CpoTrie,
    spi_trie: &crate::cardano::spi_trie::SpiTrie,
    state_dir: Option<&std::path::Path>,
    me: frost::Identifier,
    epoch: u64,
) -> EpochResult<CpoTrust> {
    let local_cpo = cpo_trie.root();
    let local_spi = spi_trie.root();
    let dir = || {
        state_dir.map_or_else(
            || "<protocol.state_dir>".to_string(),
            |d| d.display().to_string(),
        )
    };
    match chain.query_bridge_roots().await? {
        Some(roots) if roots.cpo_root != local_cpo => Err(EpochError::TmBuild(format!(
            "completed-peg-outs trie is out of sync with the chain: local root {} ({} entries) \
             != the bridge state singleton's cpo_root {}. Refusing to attest — a TM built on a \
             stale trie commits a root the chain does not hold. Rebuild with \
             `reconstruct-cpo-trie` (and delete the stale {}/cpo-trie.json if the bridge was \
             re-bootstrapped).",
            hex::encode(local_cpo),
            cpo_trie.len(),
            hex::encode(roots.cpo_root),
            dir(),
        ))),
        // The SPI twin of the check above, and the ONLY whole-trie guard the SPI
        // side has: [SPI-2]'s peer recomputation cannot catch a roster-wide
        // stale trie (every co-signer recomputes from the SAME restored state),
        // and a TM confirmed with a truncated spi_root strands every
        // swept-but-unminted depositor ([CPI-9] has no proof against it) and
        // makes binocular's [SPI-6] reconciliation refuse to serve at all.
        Some(roots) if roots.spi_root != local_spi => Err(EpochError::TmBuild(format!(
            "swept peg-ins trie is out of sync with the chain: local root {} ({} entries) != \
             the bridge state singleton's spi_root {}. Refusing to attest — a TM built on a \
             stale trie commits a root the chain does not hold, and a confirmed truncated \
             spi_root strands swept-but-unminted depositors. Rebuild with \
             `reconstruct-spi-trie` (and delete the stale {}/spi-trie.json if the bridge was \
             re-bootstrapped).",
            hex::encode(local_spi),
            spi_trie.len(),
            hex::encode(roots.spi_root),
            dir(),
        ))),
        Some(roots) => {
            crate::epoch_log!(
                me,
                epoch,
                "  local tries match the bridge state singleton (cpo_root {}, spi_root {})",
                hex::encode(roots.cpo_root),
                hex::encode(roots.spi_root),
            );
            Ok(CpoTrust::Verified)
        }
        None => {
            crate::epoch_warn!(
                me,
                epoch,
                "  no cpo_policy_id configured — neither local trie root was cross-checked \
                 against the bridge state singleton. Set cardano.cpo_policy_id before trusting \
                 these tries to sign with."
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

#[allow(clippy::too_many_arguments)]
async fn build_tm_phase(
    chain: &Arc<dyn CardanoChain>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
    batch: Option<crate::epoch::batch::BatchSlot>,
    frozen_pegins: Vec<ParsedPegIn>,
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();
    crate::epoch_log!(me, epoch, "BuildTm: querying chain for treasury / pegouts");

    // Both tries are CUMULATIVE state, and a TM commits the root that holds
    // AFTER it. Without somewhere to persist them, every build reloads an empty
    // trie and commits a root covering only its own movement — and neither
    // guard catches it: [SPI-2]'s peer recomputation reloads the same empty
    // trie and agrees, and `cross_check_bridge_roots` is skipped when
    // `cardano.cpo_policy_id` is unset (both keys are commented out in the
    // shipped heimdall.toml, so this is the DEFAULT configuration).
    //
    // Once such a TM confirms, the singleton's spi_root permanently omits every
    // earlier sweep: binocular's [SPI-6] replay then fails and no depositor can
    // obtain a [CPI-9] proof again. That is unrecoverable, so refuse to build
    // rather than degrade — a node that cannot track the tries must not be the
    // one proposing roots.
    if config.state_dir.is_none() {
        return Err(EpochError::TmBuild(
            "protocol.state_dir is not configured, so the completed-peg-outs and swept-peg-ins \
             tries cannot be persisted. A TM built without them commits roots covering only \
             this movement, which strands every earlier peg-in permanently once it confirms. \
             Set protocol.state_dir (and cardano.cpo_policy_id) before building Treasury \
             Movements."
                .to_string(),
        ));
    }

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

    // Freeze this batch's consensus inputs — chain "now" and the Config's
    // operational parameters — at one chain point, AFTER the wait above (the batch
    // starts where the previous movement ended, not where this phase was entered).
    // Everything downstream that must match across SPOs reads this snapshot and
    // nothing else; in particular the fee rate is the Config's, so two operators
    // with different `bitcoin.fee_rate_sat_per_vb` still build identical bytes.
    let snapshot = chain.query_batch_snapshot().await?;
    // WI-107: the batch capacity rule, and every input to it read from the same
    // snapshot as the rest of the consensus inputs. `validate` rejects a budget
    // too small to carry even a bare treasury move, which is a deployment fault
    // and not a busy batch — without it a node would produce nothing, for ever,
    // and look merely idle.
    let budget = snapshot.budget();
    budget.validate().map_err(EpochError::Chain)?;
    crate::epoch_log!(
        me,
        epoch,
        "  chain query: treasury={} sat, {} eligible pegins, {} open pegouts, fee_rate={}sat/vb \
         (params: {}); byte budget: max_tx_size={}, non-batch overhead={} → at most {} peg-outs, \
         or {} peg-ins with none",
        treasury.value.to_sat(),
        frozen_pegins.len(),
        pegouts.len(),
        snapshot.tm_params.fee_rate_sat_per_vb,
        snapshot.source,
        budget.max_tx_size,
        budget.envelope,
        budget.max_pegouts(),
        budget.max_pegins_with(0),
    );

    let secp = Secp256k1::new();

    // Treasury *input* spend info: the current treasury is locked under
    // `treasury.y_51` (at bootstrap this is Y_fed; in steady state it
    // is the previous epoch's FROST group key).
    let treasury_input_spend = treasury_spend_info(
        &secp,
        treasury.y_51,
        treasury.y_fed,
        treasury.federation_csv_blocks,
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
        treasury.federation_csv_blocks,
    );
    let change_script = bitcoin::ScriptBuf::new_p2tr_tweaked(change_spend.output_key());

    // The completed-peg-outs trie: this node's own copy, which decides both which
    // requests are still owed a payment and the root this TM will commit.
    let cpo_trie = load_cpo_trie(config.state_dir.as_deref(), me, epoch)?;
    // This node's persisted SPI trie: `build_tm` advances it by every tx input
    // except input 0 ([SPI-1]) to compute the spi_root its BTMR1 commitment
    // carries. Every co-signer recomputes that root from its own trie before
    // signing ([SPI-2], `verify_spi_root`) — but that gate cannot catch a
    // roster-wide stale trie, which is what the on-chain cross-check below is
    // for.
    let spi_trie = crate::cardano::spi_trie::SpiTrie::load_or_empty(config.state_dir.as_deref())
        .map_err(|e| EpochError::TmBuild(format!("swept peg-ins trie: {e}")))?;
    let cpo_trust = cross_check_bridge_roots(
        chain,
        &cpo_trie,
        &spi_trie,
        config.state_dir.as_deref(),
        me,
        epoch,
    )
    .await?;

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
            crate::epoch_warn!(
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

    // WI-040/WI-041: freeze the peg-out set against the batch, not against this
    // node's wall clock. `query_pegout_requests` above answers "open right now",
    // and "now" differs by seconds between SPOs — a request locked inside that skew
    // gives one node an extra output, a different txid, and an invalid aggregate.
    // The batch cutoff makes membership a function of the opportunity instead —
    // the one `CollectPegins` froze at (WI-097), not whichever one the snapshot
    // above happens to fall in.
    //
    // WI-107: capacity is one byte budget over the assembled Post-TM, and
    // peg-outs are filled FIRST because they are the class that expires. Peg-ins
    // then take whatever room is left, by truncating the already-FIFO-ordered
    // list `CollectPegins` froze.
    let pegouts = freeze_pegouts(pegouts, batch, budget.max_pegouts(), me, epoch)?;

    let frozen_pegins = fit_pegins_to_budget(frozen_pegins, &budget, pegouts.len(), me, epoch);

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
            per_pegout_fee: p.per_pegout_fee,
            por_id: p.por_id,
            outpoint: p.outpoint,
            created: p.created,
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
        &snapshot.tm_params,
        // The margin is a protocol constant, not a per-node setting (WI-071);
        // `now_ms` is the snapshot's CHAIN time, so every co-signer classifies a
        // borderline request identically.
        &Freshness::at(snapshot.now_ms),
        &cpo_trie,
        &spi_trie,
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

    // WI-107 / spec rev 5.6: "MUST NOT sign a movement whose assembled Post-TM
    // exceeds max_tx_size". The freeze above already bounds it, and `build_tm`
    // only ever DROPS peg-outs, so this can fire only if the byte model and the
    // builder disagree — which is exactly the thing worth catching, and worth
    // catching HERE. One phase later the movement is signed, the batch
    // opportunity is spent, and because membership is deterministic the identical
    // over-size set is rebuilt at the next one.
    let built_pegins = (unsigned.tx.input.len() as u64).saturating_sub(1);
    let built_pegouts = (unsigned.tx.output.len() as u64).saturating_sub(2);
    if !budget.fits(built_pegins, built_pegouts) {
        return Err(EpochError::TmBuild(format!(
            "built movement is over the byte budget: {built_pegins} peg-in(s) and \
             {built_pegouts} peg-out(s) assemble to {} Post-TM bytes against a max_tx_size of {} \
             (non-batch overhead {}). The batch was frozen inside the budget, so the size model \
             and the TM builder disagree — refusing to sign rather than burn the opportunity on a \
             movement that cannot be posted.",
            budget.post_tm_bytes(built_pegins, built_pegouts),
            budget.max_tx_size,
            budget.envelope,
        )));
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
        // Computed by `build_tm` from the same trie and committed inside the
        // tx's BTMR1 output — the two agree by construction.
        spi_root: unsigned.spi_root,
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
        // The signing windows are fixed HERE, off the same snapshot the batch was
        // frozen against, so both rounds measure from the batch opportunity every
        // SPO agrees on rather than from whenever each node reaches them.
        window: signing_window(clock, &snapshot, batch),
        // The batch grid index IS the movement's sequence within the epoch: it is
        // 1-based and every SPO derives it from the same chain state, which is
        // what the election needs. A deployment with no grid has one movement per
        // epoch, hence 0.
        tm_sequence: batch.map_or(0, |b| b.index),
    })
}

// ---------------------------------------------------------------------------
// submit
// ---------------------------------------------------------------------------

/// How long this node waits for its turn in a submission cascade, or `None` if
/// its turn is now — because it was elected, or because its slot has passed
/// while it was busy (spec §Cardano submission and leader reward).
///
/// One slot is one second post-Shelley, the same identity [`hop_to_opportunity`]
/// uses to turn a grid slot into a sleep.
///
/// `anchor_slot` is the spec's `signing_complete_slot`, observed locally. Nodes
/// finish signing within seconds of one another, so their anchors differ by
/// seconds against a hop of `leader_slot_T` — and the cost of any disagreement
/// is bounded by permissionlessness: two nodes that both post lose one fee, they
/// do not lose the movement. That is why the anchor does not have to be a value
/// they negotiate.
///
/// A node outside the cascade gets `None`, which means "post now". It should not
/// be there at all — see [`Roster::cascade`] — but if it is holding a valid
/// aggregate, withholding it would be the worse of the two mistakes.
/// Fix the ROTATION ceremony's round deadlines (WI-077).
///
/// The rotation is not per-batch and has no `B_i`, so it closes against the
/// epoch's published `update_y_deadline` instead: round 2 ends there — that being
/// the moment by which the Update-Y is meant to exist — and round 1 ends one
/// `sign_r2_window` earlier, leaving the second round its published room. Both
/// are absolute slots every SPO derives from the same Config.
///
/// The same fallback as [`signing_window`] applies where the deployment publishes
/// no schedule.
fn rotation_window(
    clock: &Arc<dyn Clock>,
    snapshot: &crate::epoch::traits::BatchSnapshot,
) -> crate::epoch::state::SigningWindow {
    let r2 = snapshot.update_y_close_slot.unwrap_or_else(|| {
        snapshot
            .slot
            .saturating_add(snapshot.sign_r1_window)
            .saturating_add(snapshot.sign_r2_window)
    });
    let r1 = r2.saturating_sub(snapshot.sign_r2_window);
    crate::epoch::state::SigningWindow::from_slots(clock.now(), snapshot.slot, r1, r2)
}

/// Fix this movement's signing windows from the chain schedule (WI-077).
///
/// With a grid, both rounds close at absolute slots off the batch opportunity:
/// `B_i + sign_r1_window` and `B_i + sign_r1_window + sign_r2_window`. Every SPO
/// computes `B_i` identically and reads the two windows from the same Config, so
/// the deadlines are one shared moment rather than each node's own stopwatch.
///
/// WITHOUT a grid — a mock, or a deployment whose Config carries no schedule —
/// there is no `B_i` to measure from, so the windows are laid off this node's own
/// snapshot slot. That is the pre-WI-077 shape and it does NOT converge across
/// nodes; it is the honest fallback for a deployment that has published no
/// schedule to converge on, and `BatchSnapshot::source` already records that the
/// parameters were local.
fn signing_window(
    clock: &Arc<dyn Clock>,
    snapshot: &crate::epoch::traits::BatchSnapshot,
    batch: Option<crate::epoch::batch::BatchSlot>,
) -> crate::epoch::state::SigningWindow {
    let anchor = batch.map_or(snapshot.slot, |b| b.slot);
    let r1 = anchor.saturating_add(snapshot.sign_r1_window);
    let r2 = r1.saturating_add(snapshot.sign_r2_window);
    crate::epoch::state::SigningWindow::from_slots(clock.now(), snapshot.slot, r1, r2)
}

/// Whether somebody has already posted a movement this node no longer needs to.
///
/// Two signals, and both are needed. `btc_confirmed = false` means an Unconfirmed
/// record already stands against this head — the ordinary case, since a posted
/// movement takes hours to confirm. The head having moved OFF the outpoint this
/// movement spends is the other: a predecessor's movement already confirmed, so
/// this one could not be mined anyway.
///
/// Keying on the HEAD rather than on a txid is the same rule the trie fold uses
/// (WI-032), and it is what makes an RBF rebuild stand down too.
async fn predecessor_posted(
    chain: &Arc<dyn CardanoChain>,
    tm: &TreasuryMovement,
) -> EpochResult<bool> {
    let treasury = chain.query_treasury().await?;
    let head_moved = treasury.outpoint != tm.unsigned_tx.input[0].previous_output;
    Ok(head_moved || !treasury.btc_confirmed)
}

fn cascade_wait(
    cascade: &crate::epoch::leader::Cascade,
    me: frost_secp256k1_tr::Identifier,
    anchor_slot: u64,
    now_slot: u64,
    leader_slot_t: u64,
) -> Option<std::time::Duration> {
    let eligible = cascade.eligible_slot(me, anchor_slot, leader_slot_t)?;
    let hop = eligible.checked_sub(now_slot).filter(|s| *s > 0)?;
    Some(std::time::Duration::from_secs(hop))
}

// All SPOs verify and assemble the witnessed transaction; the submission
// CASCADE decides who posts it first (spec §Cardano submission and leader
// reward, WI-104).
//
// Posting is PERMISSIONLESS on chain — the head check gates record validity and
// Bitcoin gates correctness, so an out-of-turn or duplicate post is inert. So
// this is a stagger, not a gate: the elected node goes at once, and every other
// holder of the aggregate becomes eligible one `leader_slot_T` hop later, in
// roster order, re-reading the chain first and standing down if a predecessor
// already posted.
//
// It used to be a gate, and always on the same node: `Roster::leader` returned
// the lowest identifier and nothing moved off it. One dark node therefore cost
// the roster its ability to post at all — and cost it every batch opportunity,
// since the election never changed.
#[allow(clippy::too_many_arguments)]
async fn submit_phase(
    chain: &Arc<dyn CardanoChain>,
    me: frost_secp256k1_tr::Identifier,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
    mut tm: TreasuryMovement,
    tm_sequence: u64,
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
        crate::epoch_debug!(
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

    // The cascade. `prev_tm_txid` is the treasury outpoint this movement SPENDS
    // — the head every SPO reads from the singleton — so all of them elect the
    // same node without exchanging anything, and the entropy is unpredictable
    // until that previous movement was mined.
    let prev_tm_txid = tm.unsigned_tx.input[0].previous_output.txid.to_byte_array();
    let snapshot = chain.query_batch_snapshot().await?;
    let cascade = roster
        .cascade(
            &prev_tm_txid,
            crate::epoch::leader::TmSequence::Tm(tm_sequence),
        )
        .ok_or_else(|| EpochError::Transition("empty roster at Submit".into()))?;

    match cascade_wait(
        &cascade,
        me,
        snapshot.slot,
        snapshot.slot,
        snapshot.leader_slot_t,
    ) {
        None => {
            crate::epoch_log!(
                me,
                epoch,
                "Submit: elected to post first (sequence {tm_sequence}, roster of {}) — \
                 broadcasting signed tx; txid = {} ({} bytes)",
                cascade.len(),
                tm.txid,
                tx_bytes.len()
            );
        }
        Some(wait) => {
            let hops = cascade.hops_before(me).unwrap_or(0);
            // Look BEFORE sleeping. "Each SPO monitors the chain — if a
            // predecessor has already submitted, it does nothing", and by the
            // time a follower gets here the leader has usually already posted:
            // sleeping first would hold this node a hop behind its peers for no
            // reason, and the next batch opportunity is what it would be late for.
            if predecessor_posted(chain, &tm).await? {
                crate::epoch_log!(
                    me,
                    epoch,
                    "Submit: hop {hops} of the cascade, and {:?} has already posted — standing \
                     down without waiting, as the cascade intends",
                    cascade.leader()
                );
                return Ok(EpochPhase::RecordMovement {
                    epoch,
                    roster,
                    group_keys,
                    tm,
                });
            }
            crate::epoch_log!(
                me,
                epoch,
                "Submit: hop {hops} of the cascade behind {:?} (T={} slots), nothing posted yet \
                 — holding the witnessed tx ({} bytes) for {}s",
                cascade.leader(),
                snapshot.leader_slot_t,
                tx_bytes.len(),
                wait.as_secs(),
            );
            tokio::time::sleep(wait).await;
            if predecessor_posted(chain, &tm).await? {
                crate::epoch_log!(
                    me,
                    epoch,
                    "Submit: a predecessor posted while this node waited — standing down"
                );
                return Ok(EpochPhase::RecordMovement {
                    epoch,
                    roster,
                    group_keys,
                    tm,
                });
            }
            crate::epoch_warn!(
                me,
                epoch,
                "Submit: nobody posted within {hops} hop(s) of the cascade — taking over and \
                 broadcasting; txid = {} ({} bytes)",
                tm.txid,
                tx_bytes.len()
            );
        }
    }
    let hint: Vec<[u8; 36]> = tm.fulfilled.iter().map(|f| f.outpoint).collect();
    chain.submit_signed_tm(&tx_bytes, &hint).await?;

    // Persist the witnessed tx back into `tm` so callers can inspect it.
    tm.unsigned_tx = signed_tx;

    Ok(EpochPhase::RecordMovement {
        epoch,
        roster,
        group_keys,
        tm,
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
        | EpochPhase::AwaitRotation { epoch, .. }
        | EpochPhase::CollectPegins { epoch, .. }
        | EpochPhase::BuildTm { epoch, .. }
        | EpochPhase::Sign { epoch, .. }
        | EpochPhase::Submit { epoch, .. }
        | EpochPhase::RecordMovement { epoch, .. } => *epoch,
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

    /// A peer transport for the Phase-1 tests, which assert the FALLBACK's own
    /// decisions. Its succession probe finds nothing (no peer serves a round-1
    /// payload), so the handoff declines and the fallback's behaviour is what is
    /// left under test — which is the point of these cases.
    fn fallback_peers() -> Arc<dyn PeerNetwork> {
        Arc::new(MockPeerNetwork::new(
            Identifier::try_from(1u16).unwrap(),
            MockPeerHub::new(),
        ))
    }

    /// Tight timings so the full cycle runs in well under a second.
    fn fast_config(id: Identifier) -> EpochConfig {
        let mut config = EpochConfig::demo_default(SpoIdentity {
            identifier: id,
            bifrost_id_pk: Vec::new(),
            port: 0,
        });
        config.dkg_round_timeout = Duration::from_millis(500);
        config.poll_interval = Duration::from_millis(10);
        // The batch loop's only sleep. Short so a test that waits out an
        // opportunity finishes in milliseconds rather than the 5-minute
        // production ceiling.
        config.batch_poll_ceiling = Duration::from_millis(20);
        // The retry ramp still starts at RETRY_BACKOFF_MIN (2 s), but every wait
        // after the first is this — enough to exhaust a bounded retry budget in a
        // test rather than in minutes.
        config.retry_backoff_max = Duration::from_millis(20);
        // BuildTm REQUIRES a state_dir: both tries are cumulative, and a node
        // that cannot persist them would commit roots covering only its own
        // movement.
        //
        // The path must be unique per CALL, not per identifier: every test
        // numbers its nodes from 1, so keying on the identifier alone makes
        // `full_cycle_2_of_2` and `full_cycle_3_of_3` share node 1's trie and
        // clobber each other under the default parallel test runner. The
        // counter gives each node in each test its own directory.
        static NEXT_STATE_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = NEXT_STATE_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        config.state_dir = Some(
            std::env::temp_dir().join(format!("heimdall-epoch-test-{}-{seq}", std::process::id(),)),
        );
        config
    }

    // ── Phase-1 federation fallback (WI-095) ────────────────────────────

    /// A federation share + the matching roster entry, keyed so the roster's
    /// `bifrost_id_pk` and the share's FROST index agree — which is what
    /// `phase1_fallback` cross-checks.
    fn phase1_signer_for(
        min_signers: u16,
        max_signers: u16,
    ) -> (crate::epoch::state::Phase1Signer, GroupKeys) {
        use crate::epoch::state::SpoInfo;
        let mut rng = rand::thread_rng();
        let (shares, pkp) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();
        let key_packages: BTreeMap<Identifier, frost::keys::KeyPackage> = shares
            .into_iter()
            .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
            .collect();
        let participants: BTreeMap<Identifier, SpoInfo> = key_packages
            .keys()
            .enumerate()
            .map(|(i, id)| {
                (
                    *id,
                    SpoInfo {
                        identifier: *id,
                        pool_id: vec![i as u8 + 1; 28],
                        bifrost_url: format!("http://127.0.0.1:{}", 9000 + i),
                        bifrost_id_pk: vec![i as u8 + 1; 32],
                    },
                )
            })
            .collect();
        let group_keys = GroupKeys {
            verifying_key: *pkp.verifying_key(),
            public_key_package: pkp,
            key_package: key_packages.into_values().next().unwrap(),
        };
        (
            crate::epoch::state::Phase1Signer {
                roster: Roster {
                    epoch: 0,
                    min_signers,
                    max_signers,
                    participants,
                },
                group_keys: group_keys.clone(),
            },
            group_keys,
        )
    }

    /// Every member's [`Phase1Signer`] for one federation key, so a test can run
    /// the whole federation rather than one seat of it. FROST has no 1-of-1, so
    /// any test that needs the federation to actually SIGN needs all of them.
    fn phase1_federation(
        min_signers: u16,
        max_signers: u16,
    ) -> (Vec<crate::epoch::state::Phase1Signer>, GroupKeys) {
        use crate::epoch::state::SpoInfo;
        let mut rng = rand::thread_rng();
        let (shares, pkp) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();
        let key_packages: BTreeMap<Identifier, frost::keys::KeyPackage> = shares
            .into_iter()
            .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
            .collect();
        let participants: BTreeMap<Identifier, SpoInfo> = key_packages
            .keys()
            .enumerate()
            .map(|(i, id)| {
                (
                    *id,
                    SpoInfo {
                        identifier: *id,
                        // Distinct from the SPO fixture's pool ids: these two
                        // rosters must never be mistaken for one another.
                        pool_id: vec![0xF0 + i as u8; 28],
                        bifrost_url: format!("http://127.0.0.1:{}", 9500 + i),
                        bifrost_id_pk: vec![0xF0 + i as u8; 32],
                    },
                )
            })
            .collect();
        let roster = Roster {
            epoch: 0,
            min_signers,
            max_signers,
            participants,
        };
        let group = GroupKeys {
            verifying_key: *pkp.verifying_key(),
            public_key_package: pkp.clone(),
            key_package: key_packages.values().next().unwrap().clone(),
        };
        let signers = key_packages
            .into_values()
            .map(|kp| crate::epoch::state::Phase1Signer {
                roster: roster.clone(),
                group_keys: GroupKeys {
                    verifying_key: *pkp.verifying_key(),
                    public_key_package: pkp.clone(),
                    key_package: kp,
                },
            })
            .collect();
        (signers, group)
    }

    fn aborted() -> EpochError {
        EpochError::DkgAborted {
            epoch: 7,
            attempt: 0,
            qualified: 0,
            eligible: 0,
            reason: "no eligible SPOs".into(),
        }
    }

    /// The classifier decides which failures the federation may cover for. A
    /// chain read that failed says nothing about whether a roster exists, so
    /// falling back on it would route around every provider hiccup.
    #[test]
    fn only_a_failed_ceremony_opens_the_phase1_route() {
        assert!(dkg_unavailable(&aborted()));
        assert!(dkg_unavailable(&EpochError::PollTimeout {
            got: 1,
            need: 3
        }));
        assert!(!dkg_unavailable(&EpochError::Chain(
            "blockfrost 502".into()
        )));
        assert!(!dkg_unavailable(&EpochError::Frost("bad share".into())));
    }

    /// WI-113 acceptance: the federation hands custody to the SPO roster, having
    /// worked out that roster's key FOR ITSELF.
    ///
    /// The two rosters are disjoint here, as they are in a real deployment: the
    /// three SPOs run the ceremony and the federation takes no part in it, so it
    /// is never handed `Y_51`. The assertion is on the rotation the chain
    /// RECORDED — specifically that its key is the one `part3` computed inside
    /// the SPOs' own ceremony, which nothing in this test ever told the
    /// federation. A 1-of-1 federation keeps the focus here; the threshold
    /// ceremony is covered by `rotation::the_federation_frost_signs_the_phase_1_handoff`.
    #[tokio::test]
    async fn the_federation_hands_the_treasury_to_a_roster_that_earned_it() {
        let epoch = 7;
        // A NON-ZERO attempt, as every chain-anchored ceremony has: the attempt
        // is `window * DKG_ATTEMPTS_PER_WINDOW`, and our preprod nodes joined
        // window 522 → 8352. An earlier version of this code probed attempt 0
        // and so could only ever have worked against a mock; publishing here
        // under a real-shaped attempt is what keeps that from coming back.
        let ns = crate::http::wire::DkgNamespace::for_attempt(epoch, 522 * 16);
        let (spo_result, round1_packages) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let spo_y51 = group_xonly(spo_result.public_key_package.verifying_key())
            .unwrap()
            .xonly;

        let fixture = demo_static_fixture(2, 3, 19300);
        let hub = MockPeerHub::new();
        let spo_roster = fixture.roster.clone();
        // Any well-formed Round 2 package: the rule reads PRESENCE and
        // authorship here, never content — the shares are addressed to
        // recipients the federation is not one of and could not decrypt.
        let marker = crate::frost::dkg::run_cheating_dkg(2, 3, 1, 2);
        let stub = marker
            .round2_packages
            .values()
            .next()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        for id in spo_roster.participants.keys() {
            let net = MockPeerNetwork::new(*id, hub.clone());
            net.publish_dkg_round1(ns, *id, &round1_packages[id])
                .await
                .unwrap();
            // Addressed to every OTHER member, as a real ceremony's Round 2 is —
            // the recipient list IS the participant set the sender ran with, and
            // the succession rule reads it as such.
            let others: Vec<(
                crate::epoch::state::SpoInfo,
                frost::keys::dkg::round2::Package,
            )> = spo_roster
                .participants
                .iter()
                .filter(|(other, _)| *other != id)
                .map(|(_, info)| (info.clone(), stub.clone()))
                .collect();
            net.publish_dkg_round2(ns, *id, &[], &others).await.unwrap();
        }

        // The federation: its own key, its own membership, in no registry.
        let (signers, group_keys) = phase1_federation(2, 2);
        let y_fed = group_xonly(&group_keys.verifying_key).unwrap().xonly;

        let mut chain_fixture = fixture.clone();
        chain_fixture.y_fed = y_fed;
        chain_fixture.y_51 = y_fed;
        let state = MockCardanoChain::treasury_info_state(y_fed, [0x5au8; 32]);
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(chain_fixture).with_treasury_info(state.clone()));

        // One hub serves both populations: the mock keeps DKG payloads (`dkg1`)
        // and signing payloads (`sign1`) in separate fields of a slot, so the
        // federation's Update-Y session cannot collide with the SPOs' published
        // ceremony even where the two rosters happen to reuse an index.
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut handles = Vec::new();
        for signer in signers {
            let me = *signer.group_keys.key_package.identifier();
            let mut config = fast_config(me);
            config.identity.bifrost_id_pk = signer.roster.participants[&me].bifrost_id_pk.clone();
            config.phase1_signer = Some(signer);
            let chain = chain.clone();
            let clock = clock.clone();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub.clone()));
            handles.push(tokio::spawn(async move {
                let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
                phase1_fallback(&chain, &peers, &clock, &rng, &config, epoch, aborted()).await
            }));
        }
        for h in handles {
            h.await
                .unwrap()
                .expect("Phase 1 with a share must continue");
        }

        let recorded = state.lock().unwrap();
        assert_eq!(
            recorded.rotations.len(),
            1,
            "the handoff should have landed"
        );
        let (rot_epoch, new_key, _sig) = recorded.rotations[0];
        assert_eq!(rot_epoch, epoch);
        assert_eq!(
            new_key, spo_y51,
            "the federation must hand over to the roster's real Y_51, which nothing told it"
        );
        assert_eq!(recorded.current_key, spo_y51);
    }

    /// The audit WAITS for the ceremony instead of racing it.
    ///
    /// A federation node reaches the Phase-1 fallback seconds after the epoch
    /// boundary, while the SPOs are still in their health gate — so a single
    /// probe finds nothing and, since the loop does not revisit EpochStart within
    /// an epoch, the handoff would then wait a whole epoch: five days here.
    /// Publishing only after the probe has begun is what pins the waiting.
    #[tokio::test]
    async fn the_audit_waits_for_a_ceremony_that_has_not_started_yet() {
        let epoch = 7;
        let ns = crate::http::wire::DkgNamespace::for_attempt(epoch, 522 * 16);
        let (spo_result, round1_packages) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let spo_y51 = group_xonly(spo_result.public_key_package.verifying_key())
            .unwrap()
            .xonly;

        let fixture = demo_static_fixture(2, 3, 19500);
        let hub = MockPeerHub::new();
        let spo_roster = fixture.roster.clone();
        let marker = crate::frost::dkg::run_cheating_dkg(2, 3, 1, 2);
        let stub = marker
            .round2_packages
            .values()
            .next()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();

        // Nothing is published yet. It appears only after the audit is already
        // polling, which is the whole point of the case.
        let publisher = {
            let hub = hub.clone();
            let roster = spo_roster.clone();
            let pkgs = round1_packages.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(120)).await;
                for id in roster.participants.keys() {
                    let net = MockPeerNetwork::new(*id, hub.clone());
                    net.publish_dkg_round1(ns, *id, &pkgs[id]).await.unwrap();
                    let others: Vec<(
                        crate::epoch::state::SpoInfo,
                        frost::keys::dkg::round2::Package,
                    )> = roster
                        .participants
                        .iter()
                        .filter(|(other, _)| *other != id)
                        .map(|(_, info)| (info.clone(), stub.clone()))
                        .collect();
                    net.publish_dkg_round2(ns, *id, &[], &others).await.unwrap();
                }
            })
        };

        let (signers, group_keys) = phase1_federation(2, 2);
        let y_fed = group_xonly(&group_keys.verifying_key).unwrap().xonly;
        let mut chain_fixture = fixture.clone();
        chain_fixture.y_fed = y_fed;
        chain_fixture.y_51 = y_fed;
        let state = MockCardanoChain::treasury_info_state(y_fed, [0x5au8; 32]);
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(chain_fixture).with_treasury_info(state.clone()));

        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut handles = Vec::new();
        for signer in signers {
            let me = *signer.group_keys.key_package.identifier();
            let mut config = fast_config(me);
            config.identity.bifrost_id_pk = signer.roster.participants[&me].bifrost_id_pk.clone();
            config.phase1_signer = Some(signer);
            let chain = chain.clone();
            let clock = clock.clone();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub.clone()));
            handles.push(tokio::spawn(async move {
                let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
                phase1_fallback(&chain, &peers, &clock, &rng, &config, epoch, aborted()).await
            }));
        }
        for h in handles {
            h.await
                .unwrap()
                .expect("Phase 1 with a share must continue");
        }
        publisher.await.unwrap();

        let recorded = state.lock().unwrap();
        assert_eq!(
            recorded.rotations.len(),
            1,
            "the audit should have waited for the ceremony and then handed over"
        );
        assert_eq!(recorded.rotations[0].1, spo_y51);
    }

    /// ...and it declines when the ceremony is not known to have finished. Same
    /// setup minus the Round 2 payloads: the key is still perfectly derivable
    /// from Round 1, which is exactly the trap — it would be a key nobody may
    /// hold a share of.
    #[tokio::test]
    async fn an_unfinished_ceremony_does_not_get_the_treasury() {
        let epoch = 7;
        let ns = crate::http::wire::DkgNamespace::for_attempt(epoch, 522 * 16);
        let (_spo_result, round1_packages) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);

        let fixture = demo_static_fixture(2, 3, 19400);
        let hub = MockPeerHub::new();
        for id in fixture.roster.participants.keys() {
            let net = MockPeerNetwork::new(*id, hub.clone());
            net.publish_dkg_round1(ns, *id, &round1_packages[id])
                .await
                .unwrap();
            // No Round 2 published.
        }

        let (signers, group_keys) = phase1_federation(2, 2);
        let signer = signers.into_iter().next().unwrap();
        let me = *signer.group_keys.key_package.identifier();
        let y_fed = group_xonly(&group_keys.verifying_key).unwrap().xonly;
        let mut chain_fixture = fixture.clone();
        chain_fixture.y_fed = y_fed;
        chain_fixture.y_51 = y_fed;
        let state = MockCardanoChain::treasury_info_state(y_fed, [0x5au8; 32]);
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(chain_fixture).with_treasury_info(state.clone()));

        let mut config = fast_config(me);
        config.identity.bifrost_id_pk = signer.roster.participants[&me].bifrost_id_pk.clone();
        config.phase1_signer = Some(signer);

        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub.clone()));
        phase1_fallback(
            &chain,
            &peers,
            &(Arc::new(SystemClock) as Arc<dyn Clock>),
            &(Arc::new(OsRngSource) as Arc<dyn RngSource>),
            &config,
            epoch,
            aborted(),
        )
        .await
        .expect("declining the handoff must not stop Phase-1 operation");

        let recorded = state.lock().unwrap();
        assert!(
            recorded.rotations.is_empty(),
            "no rotation should have landed"
        );
        assert_eq!(
            recorded.current_key, y_fed,
            "the treasury stays the federation's"
        );
    }

    /// Phase 1 + a federation share → the cycle continues at `CollectPegins`
    /// carrying the FEDERATION's roster and group keys, with no DKG in between.
    #[tokio::test]
    async fn phase1_fallback_signs_with_the_federation() {
        let (signer, group_keys) = phase1_signer_for(2, 3);
        let me = *group_keys.key_package.identifier();
        let y_fed = group_xonly(&group_keys.verifying_key).unwrap().xonly;
        // A genesis bridge: the treasury is locked under Y_federation and the
        // datum authorizes it, which is what the K1 bootstrap seeds. The mock
        // reports `authorized_key == config_y_fed` from these, so the phase test
        // says Phase 1.
        let mut fixture = demo_static_fixture(2, 2, 19100);
        fixture.y_fed = y_fed;
        fixture.y_51 = y_fed;
        let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture));
        let mut config = fast_config(Identifier::try_from(1).unwrap());
        // Adopt the roster's identity for this index, as a real member's config
        // would: the share and the configured identity must name the same member.
        config.identity.bifrost_id_pk = signer.roster.participants[&me].bifrost_id_pk.clone();
        config.phase1_signer = Some(signer.clone());

        let next = phase1_fallback(
            &chain,
            &fallback_peers(),
            &(Arc::new(SystemClock) as Arc<dyn Clock>),
            &(Arc::new(OsRngSource) as Arc<dyn RngSource>),
            &config,
            7,
            aborted(),
        )
        .await
        .expect("Phase 1 with a share must continue, not re-raise");
        match next {
            EpochPhase::CollectPegins {
                epoch,
                roster,
                group_keys: gk,
            } => {
                assert_eq!(epoch, 7);
                // The FEDERATION's membership, stamped with this epoch.
                assert_eq!(roster.epoch, 7);
                assert_eq!(roster.max_signers, 3);
                assert_eq!(roster.min_signers, 2);
                // ...and the federation's key, not a DKG one.
                assert_eq!(
                    group_xonly(&gk.verifying_key).unwrap().xonly,
                    group_xonly(&group_keys.verifying_key).unwrap().xonly
                );
            }
            other => panic!("expected CollectPegins, got {}", other.name()),
        }
    }

    /// The handoff window: the Update-Y has landed, so the datum names the
    /// incoming roster, but the treasury head is STILL locked under
    /// y_federation. The federation is the only party that can spend it and the
    /// movement that does is the handoff itself, so it must not decline.
    ///
    /// This is preprod 2026-08-18 as a test. The federation posted the Update-Y,
    /// the datum rotated, and the phase test then read Phase 2 and stood the
    /// federation down — while the roster could not spend the head at all,
    /// having a different key. 299807 sat sat still with no party both willing
    /// and able, and every batch failed `signature verification failed`.
    #[tokio::test]
    async fn a_rotated_datum_over_a_federation_locked_head_still_signs() {
        let (signer, group_keys) = phase1_signer_for(2, 3);
        let me = *group_keys.key_package.identifier();
        let y_fed = group_xonly(&group_keys.verifying_key).unwrap().xonly;
        let mut fixture = demo_static_fixture(2, 2, 19140);
        // Head locked under the federation key, as at the moment of handoff.
        fixture.y_fed = y_fed;
        fixture.y_51 = y_fed;
        // ...but the datum already authorizes the incoming roster's key.
        let incoming = {
            let (_, gk) = phase1_signer_for(2, 4);
            group_xonly(&gk.verifying_key).unwrap().xonly
        };
        assert_ne!(incoming, y_fed, "the rotated key must differ, or the test is vacuous");
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(fixture).with_authorized_key(incoming));
        let mut config = fast_config(Identifier::try_from(1).unwrap());
        config.identity.bifrost_id_pk = signer.roster.participants[&me].bifrost_id_pk.clone();
        config.phase1_signer = Some(signer.clone());

        let next = phase1_fallback(
            &chain,
            &fallback_peers(),
            &(Arc::new(SystemClock) as Arc<dyn Clock>),
            &(Arc::new(OsRngSource) as Arc<dyn RngSource>),
            &config,
            7,
            aborted(),
        )
        .await
        .expect("a head still locked under y_federation is the federation's to move");
        assert!(
            matches!(next, EpochPhase::CollectPegins { .. }),
            "expected CollectPegins, got {}",
            next.name()
        );
    }

    /// ...and the widening stops there. Once a movement has actually paid the
    /// treasury to the roster's address, the head is locked under a key this
    /// node holds no share of, and the federation is done: a failed ceremony is
    /// just a failed ceremony, and the original DKG error stands.
    #[tokio::test]
    async fn a_head_locked_under_a_roster_key_is_not_the_federations_to_move() {
        let (signer, group_keys) = phase1_signer_for(2, 3);
        let me = *group_keys.key_package.identifier();
        let y_fed = group_xonly(&group_keys.verifying_key).unwrap().xonly;
        let roster_key = {
            let (_, gk) = phase1_signer_for(2, 4);
            group_xonly(&gk.verifying_key).unwrap().xonly
        };
        assert_ne!(roster_key, y_fed);
        let mut fixture = demo_static_fixture(2, 2, 19160);
        // The published federation key, and a head that has moved past it.
        fixture.y_fed = y_fed;
        fixture.y_51 = roster_key;
        let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture));
        let mut config = fast_config(Identifier::try_from(1).unwrap());
        config.identity.bifrost_id_pk = signer.roster.participants[&me].bifrost_id_pk.clone();
        config.phase1_signer = Some(signer);

        let err = phase1_fallback(
            &chain,
            &fallback_peers(),
            &(Arc::new(SystemClock) as Arc<dyn Clock>),
            &(Arc::new(OsRngSource) as Arc<dyn RngSource>),
            &config,
            7,
            aborted(),
        )
        .await
        .expect_err("a roster-held treasury is not the federation's to move");
        assert!(
            matches!(err, EpochError::DkgAborted { .. }),
            "the ORIGINAL dkg error must stand, got {err}"
        );
    }

    /// No share → the ORIGINAL DKG error is re-raised. A node that is not a
    /// federation member must keep the diagnostic that applies to it rather than
    /// be told something about a federation it is not in.
    #[tokio::test]
    async fn a_non_member_keeps_the_dkg_error() {
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(demo_static_fixture(2, 2, 19100)));
        let config = fast_config(Identifier::try_from(1).unwrap());
        assert!(config.phase1_signer.is_none());

        let err = phase1_fallback(
            &chain,
            &fallback_peers(),
            &(Arc::new(SystemClock) as Arc<dyn Clock>),
            &(Arc::new(OsRngSource) as Arc<dyn RngSource>),
            &config,
            7,
            aborted(),
        )
        .await
        .expect_err("a non-member has nothing to fall back to");
        assert!(
            matches!(err, EpochError::DkgAborted { .. }),
            "expected the original DKG error, got {err}"
        );
    }

    /// A share of a DIFFERENT key than the treasury is locked under must not
    /// sign. It would produce perfectly valid signatures for a key that owns
    /// nothing — the failure mode a re-run ceremony creates.
    #[tokio::test]
    async fn a_share_of_the_wrong_key_is_refused() {
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(demo_static_fixture(2, 2, 19100)));
        let mut config = fast_config(Identifier::try_from(1).unwrap());
        // `phase1_signer_for` generates a fresh key, which is not the fixture's
        // y_fed — exactly the stale-share situation.
        let (signer, _) = phase1_signer_for(2, 3);
        config.phase1_signer = Some(signer);

        let err = phase1_fallback(
            &chain,
            &fallback_peers(),
            &(Arc::new(SystemClock) as Arc<dyn Clock>),
            &(Arc::new(OsRngSource) as Arc<dyn RngSource>),
            &config,
            7,
            aborted(),
        )
        .await
        .expect_err("a share of the wrong key must be refused");
        match err {
            EpochError::Transition(m) => assert!(
                m.contains("cannot move the treasury"),
                "unexpected message: {m}"
            ),
            other => panic!("expected Transition, got {other}"),
        }
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
            created_slot: 0,
            created: now,
        });
        // Created so long ago that its cancel deadline is within the freshness margin.
        fixture.pegouts.push(StaticPegOut {
            script_pubkey: stale_dest.clone(),
            amount: Amount::from_sat(60_000),
            created_slot: 0,
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
        // Treasury continuation, the one payable peg-out, and the BTMR1 root commitment.
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

    /// WI-040: the batch snapshot's Operational-params floors reach `build_tm` on the daemon
    /// path. The mock serves them where a live chain serves the Config's `params[2]`/`params[3]`, so this pins the
    /// wire `query_batch_snapshot → build_tm_phase → build_tm` — the plumbing whose absence
    /// was the reason the two skip rules could not be implemented at all.
    #[tokio::test]
    async fn daemon_tm_skips_pegouts_under_the_snapshot_floors() {
        use crate::epoch::fixture::StaticPegOut;
        use bitcoin::Amount;

        let mut fixture = demo_static_fixture(2, 2, 18_900);
        let payable = p2wpkh(0x07);
        let too_small = p2wpkh(0x08);
        let now = now_ms();

        // params[3] = 40_000 sat: the 30_000-sat request is under the protocol minimum.
        fixture.min_peg_out_fbtc = Amount::from_sat(40_000);
        // params[2] = the fee the fixture requests pin, so they all clear the floor —
        // isolating the params[3] rule under test.
        fixture.per_pegout_fee_floor = fixture.per_pegout_fee;
        fixture.pegouts.push(StaticPegOut {
            script_pubkey: payable.clone(),
            amount: Amount::from_sat(50_000),
            created_slot: 0,
            created: now,
        });
        fixture.pegouts.push(StaticPegOut {
            script_pubkey: too_small.clone(),
            amount: Amount::from_sat(30_000),
            created_slot: 0,
            created: now,
        });

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
        assert!(
            outputs.iter().any(|o| o.script_pubkey == payable),
            "a request above min_peg_out_fbtc must still be paid"
        );
        assert!(
            outputs.iter().all(|o| o.script_pubkey != too_small),
            "a request locking less than the snapshot's min_peg_out_fbtc must be skipped"
        );
        assert_eq!(tms[1].txid, tms[0].txid);
    }

    /// A `ParsedPegIn` with only the fields the freeze reads. The taproot info and
    /// the Bitcoin transaction are placeholders: `freeze_pegins` never looks at
    /// them, and pinning that is part of the point — batch membership must be a
    /// function of chain facts about the REQUEST, not of anything in the deposit.
    fn parsed_pegin(created_slot: Option<u64>, tx_hash: u8, output_index: u32) -> ParsedPegIn {
        let secp = Secp256k1::new();
        let internal = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[0x2bu8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;
        ParsedPegIn {
            btc_tx: bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            btc_txid: bitcoin::Txid::from_byte_array([tx_hash; 32]),
            btc_vout: output_index,
            value: bitcoin::Amount::from_sat(100_000),
            cardano_utxo: CardanoOutRef {
                tx_hash: [tx_hash; 32],
                output_index,
            },
            depositor_outputkey: internal,
            spend_info: bitcoin::taproot::TaprootBuilder::new()
                .finalize(&secp, internal)
                .unwrap(),
            created_slot,
        }
    }

    /// WI-049: peg-ins get the three batch rules they never had — cutoff, FIFO
    /// order, and a capacity bound.
    ///
    /// Before this, membership was whatever `query_pegin_requests` returned at the
    /// instant a node happened to scan, ordered by Cardano outpoint. Two SPOs
    /// scanning seconds apart across a new request built different transactions,
    /// which is a different txid and a FROST round that cannot aggregate — the same
    /// defect WI-041 closed on the peg-out side and left open here.
    #[test]
    fn pegins_are_frozen_at_the_cutoff_and_ordered_fifo() {
        use crate::epoch::batch::BatchSlot;

        let batch = BatchSlot {
            index: 3,
            slot: 5_000_000,
            cutoff_slot: 4_900_000,
        };
        let me = Identifier::try_from(1u16).unwrap();
        // Deliberately NOT in FIFO order, and deliberately in an outpoint order
        // that contradicts it — the old code would have kept this order.
        let pegins = vec![
            parsed_pegin(Some(batch.cutoff_slot), 0x01, 0), // at the cutoff: in, second
            parsed_pegin(Some(batch.cutoff_slot + 1), 0x02, 0), // one slot too new: out
            parsed_pegin(Some(batch.cutoff_slot - 500), 0x03, 0), // oldest: in, first
        ];

        let frozen = freeze_pegins(pegins, Some(batch), me, 42).expect("all slots resolved");

        let slots: Vec<Option<u64>> = frozen.iter().map(|p| p.created_slot).collect();
        assert_eq!(
            slots,
            vec![Some(batch.cutoff_slot - 500), Some(batch.cutoff_slot)],
            "the batch takes exactly the cutoff-eligible requests, oldest first — the request one \
             slot past the cutoff rolls over"
        );
    }

    /// WI-106: an UNRESOLVED creation slot REFUSES the batch. It is not deferred,
    /// and it is not admitted.
    ///
    /// Both of those were written here before, and both are wrong for one reason:
    /// batch membership is a consensus decision, so a per-node HTTP outcome must
    /// not move it in EITHER direction. A node that defers what its peers include
    /// builds a different set, a different sighash and a round that cannot
    /// aggregate — and deferring is the worse half, because it looks like success:
    /// the node signs a movement omitting the request and burns the opportunity on
    /// it. Refusing costs one tick of latency and is self-healing.
    #[test]
    fn a_pegin_with_no_resolved_creation_slot_refuses_the_batch() {
        use crate::epoch::batch::BatchSlot;

        let batch = BatchSlot {
            index: 1,
            slot: 5_000_000,
            cutoff_slot: 4_900_000,
        };
        let me = Identifier::try_from(1u16).unwrap();
        let err = freeze_pegins(
            vec![
                parsed_pegin(None, 0x01, 0),
                parsed_pegin(Some(batch.cutoff_slot), 0x02, 0),
            ],
            Some(batch),
            me,
            42,
        )
        .expect_err("one unresolved request must stop the batch, not shrink it");
        assert!(
            matches!(err, EpochError::Chain(ref m) if m.contains("1 of 2")),
            "the refusal must name how many could not be placed: {err}"
        );
    }

    /// The same rule with no grid. There is no cutoff to defer past, but ordering
    /// still decides membership: every unresolved key collapses to the same sort
    /// position, so once the byte budget truncates the list, two nodes with
    /// different resolution luck keep a different set.
    #[test]
    fn an_unresolved_pegin_refuses_the_batch_even_with_no_grid() {
        let me = Identifier::try_from(1u16).unwrap();
        freeze_pegins(vec![parsed_pegin(None, 0x01, 0)], None, me, 42)
            .expect_err("the no-grid path must refuse too");
    }

    // ── WI-058: the operator surface ──────────────────────────────────

    /// The loop actually WRITES the state the operator surface serves.
    ///
    /// The surface itself is tested in `crate::health`; what this pins is the
    /// wiring — that the phases call through to the handle on the config, so a
    /// running node reports something rather than an empty page. A test of the
    /// handle alone would pass with nothing connected to it.
    #[tokio::test]
    async fn the_loop_reports_its_progress_to_the_operator_surface() {
        let health = crate::health::HealthHandle::new();
        assert_eq!(
            health.snapshot(),
            crate::health::NodeState::default(),
            "nothing has run yet"
        );

        let fixture = demo_static_fixture(2, 2, 19_980);
        let hub = MockPeerHub::new();
        let head = MockCardanoChain::tm_chain_head(&fixture);
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> =
                Arc::new(MockCardanoChain::new(fixture.clone()).with_tm_chain(Arc::clone(&head)));
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let mut config = fast_config(id);
            // Only the first node reports; the second is here to co-sign.
            if i == 1 {
                config.health = health.clone();
            }
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }
        for h in handles {
            tokio::time::timeout(Duration::from_secs(30), h)
                .await
                .expect("the movement completes")
                .unwrap()
                .expect("ok");
        }

        let state = health.snapshot();
        assert!(
            state.last_progress_ms.is_some(),
            "a node that completed a movement must have recorded progress: {state:?}"
        );
        assert!(
            !state.activity.is_empty(),
            "and must say what it was doing: {state:?}"
        );
        assert_eq!(
            state.dkg_qualified,
            Some(true),
            "it published keys, so it qualified: {state:?}"
        );
    }

    // ── WI-067: the pre-ceremony build gate ───────────────────────────

    fn build_of(version: &str) -> crate::http::compat::PeerBuild {
        crate::http::compat::PeerBuild {
            version: Some(version.into()),
            blueprint_digest: Some(crate::http::compat::own_blueprint_digest()),
            threshold_percent: Some(crate::http::compat::own_threshold_percent()),
        }
    }

    async fn gate_over(builds: &[(u16, crate::http::compat::PeerBuild)]) -> Vec<u16> {
        let fixture = demo_static_fixture(2, 3, 19_990);
        let hub = crate::epoch::mocks::MockPeerHub::new();
        for (i, b) in builds {
            hub.set_build(Identifier::try_from(*i).unwrap(), b.clone());
        }
        let me = Identifier::try_from(1u16).unwrap();
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub));
        let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture));
        let ctx = chain.query_dkg_context(0, 0).await.expect("ctx");
        let mut config = fast_config(me);
        config.dkg_join_wait = Duration::from_millis(50);
        let out = wait_for_roster_health(&peers, &ctx, &config, me).await;
        out.iter()
            .map(|id| {
                ctx.participants
                    .iter()
                    .position(|p| p.identifier == *id)
                    .map(|n| n as u16 + 1)
                    .unwrap_or(0)
            })
            .collect()
    }

    /// A peer on a different `major.minor` is reported by the gate, so the
    /// caller can drop it from the candidate set. It is REACHABLE — this is a
    /// software mismatch, not an outage, and the two are not the same thing.
    #[tokio::test]
    async fn the_gate_reports_a_peer_on_a_different_minor() {
        assert_eq!(gate_over(&[(3, build_of("9.9.9"))]).await, vec![3]);
    }

    /// A patch difference is not a mismatch. Punishing one would make every
    /// rolling upgrade an outage.
    #[tokio::test]
    async fn the_gate_ignores_a_patch_difference() {
        let mine = crate::http::compat::own_version();
        let series = mine.rsplit_once('.').map(|(s, _)| s).unwrap_or(mine);
        let patched = build_of(&format!("{series}.99"));
        assert!(
            gate_over(&[(2, patched.clone()), (3, patched)])
                .await
                .is_empty()
        );
    }

    /// A peer whose `/health` predates the check reports no version, and is
    /// ALLOWED — otherwise the upgrade introducing the check is the outage. This
    /// is also the default mock build, which is why every other test is
    /// unaffected by the gate.
    #[tokio::test]
    async fn the_gate_allows_a_peer_that_reports_no_version() {
        assert!(gate_over(&[]).await.is_empty());
    }

    /// Same version, different contracts: the blueprint digest catches what the
    /// version convention cannot.
    #[tokio::test]
    async fn the_gate_reports_a_peer_carrying_a_different_blueprint() {
        let odd = crate::http::compat::PeerBuild {
            version: Some(crate::http::compat::own_version().into()),
            blueprint_digest: Some("deadbeefdeadbeef".into()),
            threshold_percent: Some(crate::http::compat::own_threshold_percent()),
        };
        assert_eq!(gate_over(&[(2, odd)]).await, vec![2]);
    }

    fn test_budget() -> crate::epoch::batch::TmBudget {
        crate::epoch::batch::TmBudget {
            max_tx_size: 16_384,
            envelope: 1_024,
            variant: crate::epoch::batch::SpendVariant::KeyPath,
        }
    }

    /// `freeze_pegins` orders and applies the cutoff; it does NOT cap. Capacity is
    /// a joint budget over the assembled movement (WI-107), so a per-class cap here
    /// would be a second bound the joint rule could not see — the exact defect the
    /// item removed.
    #[test]
    fn freezing_pegins_orders_them_and_leaves_capacity_alone() {
        use crate::epoch::batch::BatchSlot;

        let batch = BatchSlot {
            index: 1,
            slot: 5_000_000,
            cutoff_slot: 4_900_000,
        };
        let me = Identifier::try_from(1u16).unwrap();
        // Far more than any budget would take, in descending slot order so a
        // surviving cap could not accidentally agree with the input order.
        let n = 400usize;
        let pegins: Vec<ParsedPegIn> = (0..n)
            .map(|i| {
                parsed_pegin(
                    Some(batch.cutoff_slot - i as u64),
                    u8::try_from(i % 251).unwrap(),
                    i as u32,
                )
            })
            .collect();

        let frozen = freeze_pegins(pegins, Some(batch), me, 42).expect("all slots resolved");

        assert_eq!(frozen.len(), n, "every eligible peg-in survives the freeze");
        assert_eq!(
            frozen[0].created_slot,
            Some(batch.cutoff_slot - (n as u64 - 1)),
            "and they come out OLDEST first, which is what makes truncation FIFO"
        );
    }

    /// The joint rule: peg-outs are served first and peg-ins take what is left, so
    /// the same peg-in set is cut differently depending on the peg-out load.
    #[test]
    fn pegins_take_only_the_room_the_pegouts_leave() {
        let me = Identifier::try_from(1u16).unwrap();
        let budget = test_budget();
        let pegins: Vec<u32> = (0..500).collect();

        let alone = fit_pegins_to_budget(pegins.clone(), &budget, 0, me, 42);
        let crowded = fit_pegins_to_budget(pegins.clone(), &budget, 50, me, 42);
        assert!(
            crowded.len() < alone.len(),
            "50 peg-outs must cost peg-in room: {} vs {}",
            crowded.len(),
            alone.len()
        );
        // Whatever is taken, the assembled movement fits — the property that the
        // two independent caps never had.
        for (n, q) in [(alone.len(), 0), (crowded.len(), 50)] {
            assert!(budget.fits(n as u64, q as u64), "{n} peg-ins, {q} peg-outs");
        }
        // Truncation keeps the head, so the survivors are the oldest.
        assert_eq!(crowded[0], 0);
        assert_eq!(crowded.last(), Some(&(crowded.len() as u32 - 1)));
    }

    /// A peg-out backlog that fills the movement leaves peg-ins nothing. That is
    /// the spec's rule, not a bug — but it strands nothing, and the caller says so
    /// out loud rather than silently sweeping no deposits.
    #[test]
    fn a_full_pegout_batch_starves_pegins_without_stranding_them() {
        let me = Identifier::try_from(1u16).unwrap();
        let budget = test_budget();
        let all_pegouts = budget.max_pegouts();

        let kept = fit_pegins_to_budget(vec![1u32, 2, 3], &budget, all_pegouts, me, 42);
        assert!(kept.is_empty(), "no room left at all");
        // …and one fewer peg-out is not a cliff: the room returns gradually.
        let with_slack = fit_pegins_to_budget(vec![1u32, 2, 3], &budget, all_pegouts / 2, me, 42);
        assert!(!with_slack.is_empty());
    }

    /// Nothing is dropped when the budget already holds the set — the common case
    /// must not pay for the rule.
    #[test]
    fn an_undersubscribed_batch_is_untouched() {
        let me = Identifier::try_from(1u16).unwrap();
        let pegins: Vec<u32> = (0..5).collect();
        assert_eq!(
            fit_pegins_to_budget(pegins.clone(), &test_budget(), 3, me, 42),
            pegins
        );
    }

    /// WI-041's acceptance, end to end: batch membership is a function of the batch,
    /// not of the moment each node scanned. Two nodes see the SAME open peg-outs — one
    /// created after the batch's stability cutoff — and both exclude it, so their TM
    /// bytes agree. Before the freeze, a request landing in the seconds between two
    /// nodes' scans put an extra output in one node's TM and broke the aggregate.
    #[tokio::test]
    async fn daemon_freezes_pegouts_at_the_batch_cutoff() {
        use crate::epoch::batch::BatchSlot;
        use crate::epoch::fixture::StaticPegOut;
        use bitcoin::Amount;

        let batch = BatchSlot {
            index: 3,
            slot: 5_000_000,
            cutoff_slot: 4_900_000,
        };
        let mut fixture = demo_static_fixture(2, 2, 18_950);
        let payable = p2wpkh(0x11);
        let too_new = p2wpkh(0x12);
        let now = now_ms();

        fixture.pegouts.push(StaticPegOut {
            script_pubkey: payable.clone(),
            amount: Amount::from_sat(50_000),
            created_slot: batch.cutoff_slot, // exactly at the cutoff: in
            created: now,
        });
        fixture.pegouts.push(StaticPegOut {
            script_pubkey: too_new.clone(),
            amount: Amount::from_sat(60_000),
            created_slot: batch.cutoff_slot + 1, // one slot too new: out
            created: now,
        });

        let empty_root = crate::cardano::cpo_trie::CpoTrie::empty().root();
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(
                MockCardanoChain::new(fixture.clone())
                    .with_cpo_root(empty_root)
                    .with_batch(batch),
            );
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
            outputs.iter().any(|o| o.script_pubkey == payable),
            "a request at the cutoff is in the batch"
        );
        assert!(
            outputs.iter().all(|o| o.script_pubkey != too_new),
            "a request created after the cutoff must wait for a later batch"
        );
        assert_eq!(
            tms[1].txid, tms[0].txid,
            "both SPOs freeze the identical batch, so the TM bytes agree"
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
                created_slot: 0,
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
            created_slot: 0,
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

    /// WI-032, the headline: posting a movement does NOT block on its
    /// confirmation.
    ///
    /// This mock chain never advances its head, so the movement is never
    /// confirmed — which is precisely the state a real bridge is in for the ~17
    /// hours after a post. The cycle must still complete, and it must leave the
    /// fold recorded on disk rather than losing it.
    ///
    /// Before this change the machine parked in `AwaitConfirm` polling
    /// `is_tm_confirmed` and, after `tm_confirmation_timeout` (30 min by
    /// default, against a condition hours away), failed the cycle with the
    /// tries never advanced and no way back but `reconstruct-cpo-trie`.
    #[tokio::test]
    async fn a_posted_movement_completes_the_cycle_and_leaves_its_fold_recorded() {
        use crate::epoch::pending_tm::PendingTm;

        let dir = std::env::temp_dir().join(format!("wi032-record-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fixture = demo_static_fixture(2, 2, 18_650);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();

        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture.clone()));
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let mut config = fast_config(id);
            // One directory per node would be the deployment shape; here they
            // build byte-identical movements, so one is enough to assert on and
            // the last writer wins with the same bytes.
            config.state_dir = Some(dir.join(format!("node{i}")));
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }

        let mut tms = Vec::new();
        for h in handles {
            tms.push(
                tokio::time::timeout(Duration::from_secs(30), h)
                    .await
                    .expect("the cycle must not block on a confirmation that never comes")
                    .unwrap()
                    .expect("epoch cycle completes"),
            );
        }

        for i in 1..=2u16 {
            let recorded = PendingTm::load(&dir.join(format!("node{i}")))
                .unwrap()
                .expect("every node records what its posted movement owes the tries");
            assert_eq!(recorded.txid, tms[0].txid);
            assert_eq!(
                recorded.spends, fixture.treasury_outpoint,
                "the record must name the head the movement spends — that is what the fold \
                 watches for"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The settlement half: the fold is due when the chain moves off the head
    /// the recorded movement spends, and NOT before.
    ///
    /// Nothing is carried in memory between the two calls — `settle_pending_tm`
    /// reads the file — so this is also the restart case: a node that posted a
    /// movement, died, and came back folds it the first time it sees the head.
    #[test]
    fn a_recorded_movement_folds_when_the_head_moves_and_not_before() {
        use crate::cardano::spi_trie::SpiTrie;
        use crate::epoch::pending_tm::PendingTm;

        let dir = std::env::temp_dir().join(format!("wi032-settle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut config = fast_config(Identifier::try_from(1u16).unwrap());
        config.state_dir = Some(dir.clone());

        let spent = spi_op(0xaa, 0);
        let a = spi_op(0x01, 0);
        let root = SpiTrie::empty().root_after(&[spent, a]).unwrap();
        let tm = spi_tm(&[spent, a], root);
        record_movement_phase(&config, 7, &tm).expect("the movement is recorded");

        // The head is still the outpoint the movement spends: it has not
        // confirmed, so there is nothing to fold.
        let mut treasury = treasury_at(outpoint(spent));
        settle_pending_tm(&config, &treasury).expect("an unconfirmed movement is not an error");
        assert!(
            SpiTrie::load(&dir).unwrap().is_none(),
            "nothing may be folded while the movement is still in flight"
        );
        assert!(
            PendingTm::load(&dir).unwrap().is_some(),
            "the record must survive until the fold actually happens"
        );

        // The head advances to the movement's own change output.
        treasury.outpoint = bitcoin::OutPoint {
            txid: tm.txid,
            vout: 0,
        };
        settle_pending_tm(&config, &treasury).expect("the fold succeeds");
        let trie = SpiTrie::load(&dir)
            .unwrap()
            .expect("the trie is now persisted");
        assert_eq!(trie.root(), root);
        assert!(trie.contains(&a));
        assert!(
            PendingTm::load(&dir).unwrap().is_none(),
            "a folded record is cleared, so the next movement's cannot be confused with it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A head that moved to a movement this node did NOT record reaches the same
    /// root check `advance_*_trie` has always applied — the trie is not written,
    /// the record is not cleared, and the message names the repair.
    ///
    /// This is what a node that was down across someone else's movement sees,
    /// and it is the one case the fold cannot resolve by itself.
    #[test]
    fn a_head_this_node_cannot_explain_is_refused_and_names_the_repair() {
        use crate::cardano::spi_trie::SpiTrie;
        use crate::epoch::pending_tm::PendingTm;

        let dir = std::env::temp_dir().join(format!("wi032-foreign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut config = fast_config(Identifier::try_from(1u16).unwrap());
        config.state_dir = Some(dir.clone());

        let spent = spi_op(0xaa, 0);
        // A movement whose committed spi_root is not the one this node's trie
        // reaches — i.e. not the movement the chain actually confirmed.
        let tm = spi_tm(&[spent, spi_op(0x01, 0)], [9u8; 32]);
        record_movement_phase(&config, 7, &tm).expect("the movement is recorded");

        let mut treasury = treasury_at(outpoint(spent));
        treasury.outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_slice(&[0x77; 32]).unwrap(),
            vout: 0,
        };
        let err =
            settle_pending_tm(&config, &treasury).expect_err("an unexplained head is refused");
        let msg = err.to_string();
        assert!(msg.contains("reconstruct-spi-trie"), "{msg}");
        assert!(
            SpiTrie::load(&dir).unwrap().is_none(),
            "a refused fold must not write the trie"
        );
        assert!(
            PendingTm::load(&dir).unwrap().is_some(),
            "a refused fold must keep the record — dropping it would hide the divergence"
        );
        let _ = std::fs::remove_dir_all(&dir);
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
        let spi = crate::cardano::spi_trie::SpiTrie::empty();
        let chain = cpo_check_chain(Some(trie.root()));
        let id = Identifier::try_from(1u16).unwrap();
        cross_check_bridge_roots(&chain, &trie, &spi, None, id, 0)
            .await
            .expect("a root the chain holds must be attestable");
    }

    /// The SPI twin of the stale-root refusal: a roster-wide restored (empty)
    /// spi-trie.json against a singleton whose spi_root records earlier sweeps.
    /// [SPI-2] cannot catch this (every co-signer recomputes from the SAME
    /// stale trie); only the on-chain cross-check can.
    #[tokio::test]
    async fn spi_cross_check_refuses_a_stale_root() {
        let trie = crate::cardano::cpo_trie::CpoTrie::empty();
        let spi = crate::cardano::spi_trie::SpiTrie::empty();
        let mock = MockCardanoChain::new(demo_static_fixture(2, 2, 18_900))
            .with_bridge_roots([0x22u8; 32], trie.root());
        let chain: Arc<dyn CardanoChain> = Arc::new(mock);
        let id = Identifier::try_from(1u16).unwrap();
        let err = cross_check_bridge_roots(
            &chain,
            &trie,
            &spi,
            Some(std::path::Path::new("/var/lib/hd")),
            id,
            0,
        )
        .await
        .expect_err("a spi_root the chain does not hold must not be attestable");
        let msg = err.to_string();
        assert!(
            msg.contains("reconstruct-spi-trie"),
            "the refusal must name the command that fixes it: {msg}"
        );
        assert!(
            msg.contains(&hex::encode([0x22u8; 32])),
            "the refusal must show the on-chain spi_root: {msg}"
        );
        assert!(
            msg.contains("/var/lib/hd/spi-trie.json"),
            "the refusal must name the stale file: {msg}"
        );
    }

    /// The re-bootstrap case: a leftover populated trie against a fresh
    /// zero-root singleton. Nothing may be signed, and the operator must be told
    /// which command rebuilds the trie.
    #[tokio::test]
    async fn cpo_cross_check_refuses_a_stale_root() {
        let trie = crate::cardano::cpo_trie::CpoTrie::empty();
        let chain = cpo_check_chain(Some([0x11u8; 32]));
        let id = Identifier::try_from(1u16).unwrap();
        let spi = crate::cardano::spi_trie::SpiTrie::empty();
        let err = cross_check_bridge_roots(
            &chain,
            &trie,
            &spi,
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
        let spi = crate::cardano::spi_trie::SpiTrie::empty();
        cross_check_bridge_roots(&chain, &trie, &spi, None, id, 0)
            .await
            .expect("an unchecked root must still be attestable");
    }

    // --- swept peg-ins trie wiring [SPI-1] [SPI-3] -------------------------

    /// A 36-byte outpoint: txid internal order (32 bytes of `b`) ++ vout LE.
    fn spi_op(b: u8, vout: u32) -> [u8; 36] {
        let mut o = [b; 36];
        o[32..].copy_from_slice(&vout.to_le_bytes());
        o
    }

    fn outpoint(bytes: [u8; 36]) -> bitcoin::OutPoint {
        use bitcoin::hashes::Hash;
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(bytes[..32].try_into().unwrap()),
            vout: u32::from_le_bytes(bytes[32..].try_into().unwrap()),
        }
    }

    /// A minimal TM whose only meaningful content is its inputs and `spi_root`
    /// – exactly what the swept peg-ins wiring reads.
    fn spi_tm(inputs: &[[u8; 36]], spi_root: [u8; 32]) -> TreasuryMovement {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|op| bitcoin::TxIn {
                    previous_output: outpoint(*op),
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

    /// The record a posted movement leaves behind — the only thing the fold ever
    /// sees, in the machine as in these tests.
    fn pending(tm: &TreasuryMovement) -> crate::epoch::pending_tm::PendingTm {
        crate::epoch::pending_tm::PendingTm::from_movement(0, tm).expect("a movement has inputs")
    }

    /// A treasury head at `outpoint`. Only the outpoint decides whether a
    /// recorded movement is due to be folded, so the keys are the fixture's and
    /// nothing here depends on them.
    fn treasury_at(outpoint: bitcoin::OutPoint) -> crate::epoch::traits::TreasuryUtxo {
        let f = demo_static_fixture(2, 2, 19_900);
        crate::epoch::traits::TreasuryUtxo {
            outpoint,
            value: f.treasury_value,
            y_51: f.y_51,
            y_fed: f.y_fed,
            config_y_fed: f.y_fed,
            authorized_key: f.y_51,
            federation_csv_blocks: f.federation_csv_blocks,
            pegin_refund_timeout_blocks: 720,
            btc_confirmed: true,
        }
    }

    // -----------------------------------------------------------------------
    // WI-097: the batch grid paces the movements, the boundary paces the ceremony
    // -----------------------------------------------------------------------

    fn slot(index: u64) -> crate::epoch::batch::BatchSlot {
        crate::epoch::batch::BatchSlot {
            index,
            slot: 5_000_000 + index,
            cutoff_slot: 4_900_000 + index,
        }
    }

    /// WI-047, the loop half: a failed key handoff costs the ROTATION, not the
    /// epoch's treasury movements.
    ///
    /// `PublishKeys` sits upstream of the whole batch loop, and the error arm used
    /// to keep this epoch's ceremony only from `CollectPegins` onward — so any
    /// failure inside the handoff dropped to `Idle`, which waits for the chain
    /// epoch to ADVANCE. One slow Cardano read, and the node sat out every batch
    /// opportunity of a five-day epoch.
    ///
    /// The mock's `await_epoch_boundary` fires once and then parks for ever, so a
    /// machine that answers a failed rotation with `Idle` HANGS this test — which
    /// is exactly what it does to a real node, only for days rather than seconds.
    #[tokio::test]
    async fn a_failed_key_handoff_costs_the_rotation_not_the_epoch() {
        let seed = [0x21u8; 32];
        let secp = Secp256k1::new();
        let fed_xonly = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&seed).unwrap(),
        )
        .x_only_public_key()
        .0;
        let treasury_info = MockCardanoChain::treasury_info_state(fed_xonly, [0xe1u8; 32]);
        // ONE shared counter: every node fails the same read, as a real chain
        // outage would leave them, so they retry the handoff together.
        let outage = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let fixture = demo_static_fixture(2, 2, 19_700);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(
                MockCardanoChain::new(fixture.clone())
                    .with_treasury_info(treasury_info.clone())
                    .fail_next_update_y_plans(Arc::clone(&outage), 2),
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

        for h in handles {
            tokio::time::timeout(Duration::from_secs(30), h)
                .await
                .expect(
                    "a failed handoff must re-enter PublishKeys for the same epoch — falling to \
                     Idle waits for the next boundary and loses the epoch's movements",
                )
                .unwrap()
                .expect("the movement completes after the handoff retries");
        }
        // The retry was real: the handoff landed, on the epoch it belonged to.
        assert_eq!(
            treasury_info.lock().unwrap().rotations.len(),
            1,
            "the rotation must complete on the retry, not be skipped"
        );
        assert_eq!(
            outage.load(std::sync::atomic::Ordering::Acquire),
            0,
            "both injected failures must have been consumed — otherwise the phase was never \
             re-entered and this test proves nothing"
        );
    }

    /// The other side of the retry: a handoff that fails for a NON-transient
    /// reason must give up and park, not re-enter for the whole epoch.
    ///
    /// Retrying is right for a slow chain read. It is wrong for the reasons that
    /// never clear inside an epoch — a boundary that dropped more than
    /// `min_signers` of the outgoing roster, or a node registered this epoch,
    /// which holds no share of the outgoing key at all. Without a bound those
    /// re-enter every 2–60 s for five days, achieving nothing and spending an API
    /// quota to do it, where the old behaviour at least parked quietly.
    ///
    /// The mock's boundary fires once, so a node that gives up correctly parks in
    /// `Idle` for ever — which is what this asserts by NOT completing.
    #[tokio::test]
    async fn a_permanently_failing_handoff_gives_up_instead_of_looping_all_epoch() {
        let seed = [0x22u8; 32];
        let secp = Secp256k1::new();
        let fed_xonly = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&seed).unwrap(),
        )
        .x_only_public_key()
        .0;
        let treasury_info = MockCardanoChain::treasury_info_state(fed_xonly, [0xe2u8; 32]);
        // Far more failures than the budget: the outage never clears.
        let outage = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let fixture = demo_static_fixture(2, 2, 19_800);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(
                MockCardanoChain::new(fixture.clone())
                    .with_treasury_info(treasury_info.clone())
                    .fail_next_update_y_plans(Arc::clone(&outage), 10_000),
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

        // The ramp is 2 s then 20 ms (fast_config), so five seconds is several
        // times the budget's span — an unbounded retry would be well past 6.
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            handles.iter().all(|h| !h.is_finished()),
            "a node whose handoff cannot succeed must not report a completed movement"
        );
        // One run per node to discover the failure, then at most HANDOFF_RETRIES
        // re-entries each — the phase has to RUN to fail, so the budget bounds
        // re-entries rather than runs.
        let spent = 10_000 - outage.load(std::sync::atomic::Ordering::Acquire);
        assert!(
            spent <= 2 * (6 + 1),
            "the handoff must stop being re-entered after its retry budget: {spent} runs across \
             2 nodes, where 6 retries each allows at most 14"
        );
        for h in handles {
            h.abort();
        }
    }

    /// WI-114 — THE acceptance: a handoff that lands mid-epoch is picked up
    /// where it lands, not at the next boundary.
    ///
    /// The treasury is keyed to a key NOBODY in this test holds, which is the
    /// live Phase-1 shape: `current_spos_frost_key` is `Y_federation`, the
    /// federation is external, and the roster can build the Update-Y but cannot
    /// sign it. So every node plans the rotation, correctly refuses to authorize
    /// it, and has nothing left to do but watch.
    ///
    /// The rotation is landed from OUTSIDE, and deliberately late — after a wait
    /// many times the handoff retry budget, which is the whole point. Before
    /// this, "not mine to authorize" was an ordinary `EpochError::Frost`, so it
    /// was counted against `HANDOFF_RETRIES`, and about two minutes later the
    /// node parked in `Idle` until the next boundary. On preprod on 2026-08-18
    /// that left three SPOs holding a treasury they did not know was theirs; the
    /// federation posted hours after they had stopped looking. Under the old
    /// behaviour this test hangs at the final await.
    #[tokio::test]
    async fn a_handoff_landed_by_someone_else_is_picked_up_mid_epoch() {
        // Nobody's key: not the federation seed (none is configured), not any
        // roster share. There is no way for a node here to authorize a rotation
        // away from it.
        let secp = Secp256k1::new();
        let outgoing = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[0x5cu8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;
        let treasury_info = MockCardanoChain::treasury_info_state(outgoing, [0x1au8; 32]);

        let fixture = demo_static_fixture(2, 2, 19_900);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        let mut healths = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(
                MockCardanoChain::new(fixture.clone()).with_treasury_info(treasury_info.clone()),
            );
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = fast_config(id);
            healths.push(config.health.clone());
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }

        // Far past the retry ramp (2 s, then 20 ms a step, six steps): under the
        // old policy every node has long since given up by now.
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            handles.iter().all(|h| !h.is_finished()),
            "no movement is possible while the treasury is under a key no node holds"
        );
        for h in &healths {
            assert_eq!(
                h.snapshot().activity,
                "waiting for another party to post the Update-Y",
                "a node that cannot authorize the handoff must still be WATCHING for it, not \
                 parked until the next boundary"
            );
        }

        // The federation posts, hours later in wall-clock terms — long after the
        // node stopped retrying and long before the epoch ends.
        treasury_info.lock().unwrap().external_post = true;

        for h in handles {
            let tm = tokio::time::timeout(Duration::from_secs(20), h)
                .await
                .expect("the watch must pick the handoff up, not wait for the boundary")
                .unwrap()
                .expect("epoch cycle completes once the treasury is under this roster's key");
            assert!(
                !tm.sighashes.is_empty(),
                "a real movement, not an empty one"
            );
        }
        // And it was not this roster that posted it: the point of the watch is
        // that the node never gains authority it did not have.
        assert!(
            treasury_info.lock().unwrap().rotations.is_empty(),
            "no node here could authorize the rotation, so none may have submitted one"
        );
    }

    /// The other half: the watch must not mistake "nothing has happened" for
    /// success. While the outgoing key stands, it stays in the watch.
    ///
    /// Without this, a watch that returned on any poll would look identical to
    /// the fixed behaviour in the test above and would walk into `BuildTm` under
    /// a key the treasury does not name.
    #[tokio::test]
    async fn the_watch_holds_while_the_outgoing_key_stands() {
        let secp = Secp256k1::new();
        let outgoing = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[0x6du8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;
        let treasury_info = MockCardanoChain::treasury_info_state(outgoing, [0x2bu8; 32]);
        let fixture = demo_static_fixture(2, 2, 19_901);
        let epoch = fixture.roster.epoch;
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(fixture).with_treasury_info(treasury_info));
        let me = Identifier::try_from(1u16).unwrap();
        let (keys, _) = dealt_group_keys(2, 2);
        let config = fast_config(me);

        let held = tokio::time::timeout(
            Duration::from_millis(300),
            await_rotation_phase(&chain, &config, epoch, roster_of(2, 2), keys[&me].clone()),
        )
        .await;
        assert!(
            held.is_err(),
            "the watch must keep waiting while treasury_info still names the outgoing key; got \
             {:?}",
            held.map(|r| r.map(|p| p.name().to_string()))
        );
    }

    /// The resume is BACK into `PublishKeys`, not forward into the batch loop.
    ///
    /// That phase's tail is load-bearing: it calls `publish_group_key`, which is
    /// what tells `query_treasury` which Taproot tree the head is locked under.
    /// A watch that returned `CollectPegins` would skip it and reach `BuildTm`
    /// on a stale view of the treasury.
    #[tokio::test]
    async fn the_watch_resumes_into_publish_keys_so_the_phase_can_finish_its_work() {
        let me = Identifier::try_from(1u16).unwrap();
        let (keys, y_51) = dealt_group_keys(2, 2);
        // Already rotated: the handoff landed before the watch even looked.
        let treasury_info = MockCardanoChain::treasury_info_state(y_51, [0x3cu8; 32]);
        let fixture = demo_static_fixture(2, 2, 19_902);
        let epoch = fixture.roster.epoch;
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(fixture).with_treasury_info(treasury_info));
        let config = fast_config(me);

        let next = await_rotation_phase(&chain, &config, epoch, roster_of(2, 2), keys[&me].clone())
            .await
            .unwrap();
        assert!(
            matches!(next, EpochPhase::PublishKeys { .. }),
            "expected PublishKeys, got {}",
            next.name()
        );
        assert_eq!(current_epoch(&next), epoch);
    }

    /// A dealt `t`-of-`n` key set plus the group's x-only key, for phase tests
    /// that need real FROST material without running a ceremony.
    fn dealt_group_keys(
        n: u16,
        t: u16,
    ) -> (
        std::collections::BTreeMap<Identifier, GroupKeys>,
        bitcoin::key::UntweakedPublicKey,
    ) {
        let mut rng = rand::thread_rng();
        let (shares, pkp) =
            frost::keys::generate_with_dealer(n, t, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let mut out = std::collections::BTreeMap::new();
        for (id, share) in shares {
            out.insert(
                id,
                GroupKeys {
                    verifying_key: *pkp.verifying_key(),
                    public_key_package: pkp.clone(),
                    key_package: frost::keys::KeyPackage::try_from(share).unwrap(),
                },
            );
        }
        let xonly = crate::frost::xonly::group_xonly(pkp.verifying_key())
            .unwrap()
            .xonly;
        (out, xonly)
    }

    fn roster_of(n: u16, t: u16) -> Roster {
        let mut participants = std::collections::BTreeMap::new();
        for i in 1..=n {
            let id = Identifier::try_from(i).unwrap();
            participants.insert(
                id,
                crate::epoch::state::SpoInfo {
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

    /// WI-048 review: a node whose rotation round is SPENT must still discover
    /// that the handoff landed WITHOUT it, and join the epoch's batch grid.
    ///
    /// This is the case a THRESHOLD rotation creates and a full-set one could not:
    /// t of the outgoing roster aggregate and post the Update-Y while this node's
    /// own round times out. The treasury then names the very key this node
    /// completed the DKG for and holds a share of — it can co-sign every movement
    /// of the epoch, and there is nothing left to retry. Parking on the spent
    /// round throws all of that away for ~5 days over a rotation that SUCCEEDED,
    /// which is what `resume = None` alone did.
    ///
    /// So a spent rotation re-enters exactly once with the ceremony DISABLED:
    /// `plan_update_y` answering `None` is the proof it landed.
    #[tokio::test]
    async fn a_spent_rotation_that_landed_elsewhere_walks_through_to_the_batch_loop() {
        let (keys, outgoing) = dealt_group_keys(2, 2);
        let me = Identifier::try_from(1u16).unwrap();
        // The treasury already names the key this node just derived, which is what
        // a rotation posted by the threshold subset looks like from here.
        let treasury_info = MockCardanoChain::treasury_info_state(outgoing, [0xe6u8; 32]);
        let chain: Arc<dyn CardanoChain> = Arc::new(
            MockCardanoChain::new(demo_static_fixture(2, 2, 19_990))
                .with_treasury_info(treasury_info),
        );
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, MockPeerHub::new()));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        let config = fast_config(me);

        let next = publish_keys_phase(
            &chain,
            &peers,
            &clock,
            &rng,
            &config,
            7,
            roster_of(2, 2),
            keys.get(&me).unwrap().clone(),
            true, // the round is spent
        )
        .await
        .expect("a spent rotation whose handoff already landed must not fail");
        assert!(
            matches!(next, EpochPhase::CollectPegins { .. }),
            "it must walk through to the batch loop, not park: the node holds a share of the key \
             the treasury now names and can co-sign every movement of the epoch"
        );
    }

    /// The other half: a spent rotation whose handoff did NOT land must refuse to
    /// walk the round again, and say which of the two it is.
    ///
    /// Re-running the ceremony in the same namespace cannot converge — peers keep
    /// serving their first commitment and `poll_sign_round` never re-fetches a
    /// peer it already has — so the honest answer is to stop and let the boundary
    /// re-derive everything.
    #[tokio::test]
    async fn a_spent_rotation_that_did_not_land_refuses_to_walk_the_round_again() {
        let (keys, _outgoing) = dealt_group_keys(2, 2);
        let me = Identifier::try_from(1u16).unwrap();
        // A DIFFERENT key: the treasury still names the outgoing roster, so the
        // rotation is still outstanding.
        let stale = dealt_group_keys(2, 2).1;
        let treasury_info = MockCardanoChain::treasury_info_state(stale, [0xe7u8; 32]);
        let chain: Arc<dyn CardanoChain> = Arc::new(
            MockCardanoChain::new(demo_static_fixture(2, 2, 19_992))
                .with_treasury_info(treasury_info),
        );
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, MockPeerHub::new()));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        let config = fast_config(me);

        let err = publish_keys_phase(
            &chain,
            &peers,
            &clock,
            &rng,
            &config,
            7,
            roster_of(2, 2),
            keys.get(&me).unwrap().clone(),
            true,
        )
        .await
        .expect_err("a spent rotation with the handoff still outstanding must not re-run it");
        assert!(
            err.round_is_spent(),
            "the loop reads this to park instead of re-entering a third time: {err:?}"
        );
    }

    /// WI-108: a peer that answers with an ERROR during the DKG is EXCLUDED from
    /// the ceremony, not a reason to abort it.
    ///
    /// The signing half (WI-098) left this untouched, and the consequence here is
    /// worse than there. `dkg_phase`'s error is `EpochError::Peer`, which
    /// `dkg_unavailable` deliberately excludes, so no Phase-1 fallback fires; and
    /// the `Dkg` phase sets no `resume`, so `drive_to_movement` falls to `Idle`
    /// and the node sits out the whole epoch — while its peers, if they saw the
    /// same host as merely silent, went on to derive a `Y_51` it holds no share
    /// of. One unhealthy host taking the roster down was reachable through the
    /// same `fetch_raw` that the signing rounds were just taught to tolerate.
    ///
    /// Modelled SYMMETRICALLY — the dead host 502s at everyone — because that is
    /// what an unhealthy endpoint actually does. The asymmetric case does not
    /// converge even with this fix: two nodes that exclude different members
    /// derive different group keys, which is WI-105's territory, not this one's.
    #[tokio::test]
    async fn a_peer_that_errors_during_the_dkg_is_excluded_not_fatal() {
        let fixture = demo_static_fixture(2, 3, 19_960);
        let hub = MockPeerHub::new();
        let spo3 = Identifier::try_from(3u16).unwrap();
        let mut handles = Vec::new();
        // Only spo 1 and spo 2 run. spo 3 never starts, and both survivors see its
        // endpoint answering 502 rather than going quietly unanswered.
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture.clone()));
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> =
                Arc::new(MockPeerNetwork::new(id, hub.clone()).seeing_unreachable(spo3));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = fast_config(id);
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }

        let mut tms = Vec::new();
        for h in handles {
            tms.push(
                tokio::time::timeout(Duration::from_secs(60), h)
                    .await
                    .expect(
                        "one 502-ing member must not abort the ceremony — the node would \
                         otherwise fall to Idle and sit out the whole epoch",
                    )
                    .unwrap()
                    .expect("the ceremony completes on the reachable members"),
            );
        }
        assert_eq!(
            tms[0].txid, tms[1].txid,
            "both survivors must exclude the same member and derive the same key"
        );
    }

    /// WI-098: a peer that answers with an ERROR is signed around, exactly like
    /// one that stays silent — and two nodes seeing the same peer differently
    /// still close the same S1.
    ///
    /// This is the sharper half of WI-047's stall. A 404 and a refused connection
    /// already reached the poll as `Ok(None)`; a 502 from a reverse proxy or a 500
    /// from a peer mid-restart arrived as `Err` and aborted the whole round before
    /// any deadline or threshold code ran — which is precisely the peer the
    /// threshold poll exists to survive, one that is up and unhealthy rather than
    /// down.
    ///
    /// The asymmetry is what makes it worse than a race: node 2 sees spo 3 as
    /// erroring while node 1 sees the same peer as merely silent, at the same
    /// instant, with no timing skew involved at all. Before this, node 1 closed S1
    /// on {1,2} and signed while node 2 unwound into backoff — so the two could not
    /// aggregate even though nothing was wrong with either of them.
    #[tokio::test]
    async fn a_peer_that_errors_is_signed_around_like_one_that_is_silent() {
        let fixture = demo_static_fixture(2, 3, 19_950);
        let hub = MockPeerHub::new();
        let spo3 = Identifier::try_from(3u16).unwrap();
        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture.clone()));
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let net = MockPeerNetwork::new(id, hub.clone());
            // spo 3 goes dark for signing: silent to everyone. spo 2 additionally
            // gets a 502 where spo 1 gets that silence — same peer, same moment,
            // different observation.
            let net = match i {
                3 => net.muting_sign_publishes(),
                2 => net.seeing_unreachable_at_signing(spo3),
                _ => net,
            };
            let peers: Arc<dyn PeerNetwork> = Arc::new(net);
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = fast_config(id);
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }
        let spo3_handle = handles.pop().expect("three nodes");

        let mut tms = Vec::new();
        for h in handles {
            tms.push(
                tokio::time::timeout(Duration::from_secs(30), h)
                    .await
                    .expect(
                        "a peer answering 502 must be counted absent, not abort the round — the \
                         node that saw the error would otherwise never finish",
                    )
                    .unwrap()
                    .expect("the movement completes on the threshold subset"),
            );
        }
        assert_eq!(
            tms[0].txid, tms[1].txid,
            "the node that saw a 502 and the node that saw silence must close the SAME S1: a \
             different subset is a different SigningPackage, and their shares would not aggregate"
        );
        // spo 3 published nothing and cannot complete; it is the absentee, not a
        // participant.
        spo3_handle.abort();
    }

    fn snapshot_at(slot: u64) -> crate::epoch::traits::BatchSnapshot {
        let mut s = crate::epoch::traits::BatchSnapshot::local_override(
            0,
            crate::bitcoin::tm_builder::TmParams::fee_rate_only(1),
            "test",
        );
        s.slot = slot;
        s.sign_r1_window = 60;
        s.sign_r2_window = 30;
        s
    }

    /// WI-077's acceptance case at this level: the window is anchored on the
    /// BATCH OPPORTUNITY, so a node's own position only shortens its wait.
    ///
    /// A node reading 40 slots after `B_i` waits 40 fewer seconds — and because
    /// reading 40 slots later means BEING 40 seconds later, the two deadlines land
    /// on the same absolute moment. (That composition is proved directly in
    /// `epoch::state`; what is checked here is the anchor choice that feeds it,
    /// since anchoring on the reader's own slot would give every node the same
    /// wait from a different start, which is the local timeout again.)
    #[test]
    fn the_signing_window_is_anchored_on_the_batch_not_on_the_reader() {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let batch = crate::epoch::batch::BatchSlot {
            index: 1,
            slot: 5_000_000,
            cutoff_slot: 4_900_000,
        };
        let wait_of = |read_at: u64| {
            let before = clock.now();
            let w = signing_window(&clock, &snapshot_at(read_at), Some(batch));
            (w.round1_close - before, w.round2_close - before)
        };
        let (at_bi, _) = wait_of(batch.slot);
        let (later, later_r2) = wait_of(batch.slot + 40);
        assert_eq!(at_bi.as_secs(), 60, "sign_r1_window from B_i");
        assert_eq!(
            later.as_secs(),
            20,
            "40 slots later is 40 seconds less to wait"
        );
        assert_eq!(
            later_r2.as_secs(),
            50,
            "round 2 keeps its own window on top"
        );
    }

    /// Without a grid there is no `B_i` to anchor on, so every node waits the same
    /// duration from its OWN read — which does not converge across nodes. That is
    /// the honest fallback for a deployment publishing no schedule to converge on,
    /// and it is pinned here so it is never mistaken for the real rule.
    #[test]
    fn without_a_grid_the_window_falls_back_to_this_nodes_own_slot() {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let wait_of = |read_at: u64| {
            let before = clock.now();
            signing_window(&clock, &snapshot_at(read_at), None).round1_close - before
        };
        assert_eq!(wait_of(5_000_000).as_secs(), 60);
        assert_eq!(
            wait_of(5_000_040).as_secs(),
            60,
            "the same wait from a different start — no shared moment exists here"
        );
    }

    /// The rotation has no batch opportunity, so it closes against the epoch's
    /// published `update_y_deadline` — round 2 AT it, round 1 one `sign_r2_window`
    /// earlier so the second round keeps its published room.
    #[test]
    fn the_rotation_window_closes_on_the_update_y_deadline() {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut s = snapshot_at(5_000_000);
        s.update_y_close_slot = Some(5_000_300);
        let before = clock.now();
        let w = rotation_window(&clock, &s);
        assert_eq!(
            (w.round2_close - before).as_secs(),
            300,
            "ends at update_y_deadline"
        );
        assert_eq!(
            (w.round1_close - before).as_secs(),
            270,
            "round 1 leaves sign_r2_window"
        );
    }

    /// WI-104's acceptance case: the roster completes a movement when the node
    /// the election picked never runs at all.
    ///
    /// This is what the cascade is FOR. The old rule elected the lowest
    /// identifier, never moved off it, and made every other node decline to post
    /// — so one dark node cost the roster its ability to post anything. Worse
    /// after WI-048: `Quorum::requiring(leader)` turned the same absence into a
    /// `RoundSpent`, which deliberately keeps the opportunity marker, so no node
    /// retried until the next grid slot and throughput went to zero at one
    /// interval per attempt.
    ///
    /// The leader here is computed with the REAL election over the fixture's own
    /// roster, not assumed — the point is that whoever it names can be missing.
    #[tokio::test]
    async fn a_dark_leader_costs_a_cascade_hop_not_the_movement() {
        let fixture = demo_static_fixture(2, 3, 19_970);
        let head = MockCardanoChain::tm_chain_head(&fixture);
        let probe: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture.clone()));
        let roster = probe.query_roster(0).await.expect("fixture roster");
        // The movement spends the fixture's treasury outpoint, so that is the
        // election's `prev_tm_txid` — the same value every node reads.
        let prev = head.lock().unwrap().0.txid.to_byte_array();
        let elected = roster
            .cascade(&prev, crate::epoch::leader::TmSequence::Tm(0))
            .expect("a roster elects")
            .leader();

        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        // Every node runs, so the elected leader is a full participant in the
        // ceremony — this is a leader that SIGNS and then fails to post, not one
        // that was absent all epoch (an absent node is simply not in the roster
        // the election runs over, so it can never be elected).
        //
        // Its post vanishing is modelled by giving it no share of the chain head:
        // it broadcasts into its own copy, and nothing the others can see ever
        // changes. That is what a crash between signing and posting looks like to
        // the rest of the roster, and it is the case the cascade exists for.
        for (_, info) in roster.participants.iter() {
            let id = info.identifier;
            let mock = MockCardanoChain::new(fixture.clone());
            let mock = if id == elected {
                mock
            } else {
                mock.with_tm_chain(Arc::clone(&head))
            };
            let chain: Arc<dyn CardanoChain> = Arc::new(mock);
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
            tms.push(
                tokio::time::timeout(Duration::from_secs(30), h)
                    .await
                    .expect(
                        "a movement must not wait on the elected node: posting is permissionless, \
                         so an absent leader costs a cascade hop and nothing more",
                    )
                    .unwrap()
                    .expect("the threshold subset completes the movement"),
            );
        }
        assert_eq!(tms.len(), 3, "every node finished");
        assert!(
            tms.windows(2).all(|w| w[0].txid == w[1].txid),
            "all three built the same movement"
        );
        // The movement reached the shared chain — so a node that was NOT elected
        // posted it. Under the rule this replaces, every such node held its copy
        // and the head never moved.
        assert_ne!(
            head.lock().unwrap().0,
            fixture.treasury_outpoint,
            "the elected node's post vanished, so a later hop had to take over"
        );
    }

    /// The other half of the same rule: the cascade STAGGERS rather than
    /// duplicating. Once a predecessor's movement is on the chain, a later hop
    /// stands down instead of burning a fee posting the same bytes again.
    #[tokio::test]
    async fn a_later_hop_stands_down_once_a_predecessor_has_posted() {
        let fixture = demo_static_fixture(2, 2, 19_971);
        let head = MockCardanoChain::tm_chain_head(&fixture);
        let hub = MockPeerHub::new();
        // Separate chain objects so each node's submissions are counted on its
        // own, but ONE shared head — which is what lets a follower see that a
        // predecessor already posted.
        let chains: Vec<Arc<MockCardanoChain>> = (1..=2u16)
            .map(|_| {
                Arc::new(MockCardanoChain::new(fixture.clone()).with_tm_chain(Arc::clone(&head)))
            })
            .collect();
        let mut handles = Vec::new();
        for (i, mock) in chains.iter().enumerate() {
            let id = Identifier::try_from(u16::try_from(i).unwrap() + 1).unwrap();
            let chain: Arc<dyn CardanoChain> = mock.clone();
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = fast_config(id);
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }
        for h in handles {
            tokio::time::timeout(Duration::from_secs(30), h)
                .await
                .expect("both nodes finish")
                .unwrap()
                .expect("the movement completes");
        }
        let posts: usize = chains
            .iter()
            .map(|c| c.submitted_txs().lock().unwrap().len())
            .sum();
        assert_eq!(
            posts, 1,
            "exactly one node posts: the cascade is a stagger, not a race"
        );
    }

    /// WI-048: a movement whose round FAILED AFTER PUBLISHING does not rebuild
    /// at the same opportunity.
    ///
    /// The contrast is with `a_failure_gives_back_its_own_opportunity_but_never_
    /// a_served_one`, and both rules are right. A failure BEFORE any commitment
    /// leaves the node — a peg-out query, a snapshot read — should hand the
    /// opportunity back, because rebuilding is free and the batch is unchanged.
    /// A failure AFTER must not: the batch is frozen, so the rebuild produces the
    /// same sighashes and therefore the same signing namespace, and this node
    /// would publish a FRESH commitment into a round its peers have left.
    /// `poll_sign_round` never re-fetches a peer it already has, so that second
    /// pass does not race — it deterministically builds a package no peer built.
    ///
    /// Counting publications is what makes this decisive: the store only ever
    /// holds the newest value, so a node republishing into a spent round looks
    /// identical to one that published once.
    ///
    /// (The rotation half of the same rule — `resume = None` for `PublishKeys` —
    /// is pinned by `rotation::tests::a_sub_threshold_subset_does_not_authorize`,
    /// which asserts the marker the loop reads. It cannot be reached from here:
    /// `y_fed_seed` makes the first epoch's handoff a federation signature with
    /// no FROST round at all.)
    #[tokio::test]
    async fn a_spent_signing_round_does_not_rebuild_at_the_same_opportunity() {
        let seed = [0x24u8; 32];
        let secp = Secp256k1::new();
        let fed_xonly = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&seed).unwrap(),
        )
        .x_only_public_key()
        .0;
        let treasury_info = MockCardanoChain::treasury_info_state(fed_xonly, [0xe4u8; 32]);

        let fixture = demo_static_fixture(2, 2, 19_900);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(
                MockCardanoChain::new(fixture.clone()).with_treasury_info(treasury_info.clone()),
            );
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            // Node 2 completes the DKG and then goes dark for the signing rounds,
            // so node 1's round-1 poll can never reach `min_signers = 2`.
            let net = MockPeerNetwork::new(id, hub.clone());
            let peers: Arc<dyn PeerNetwork> = Arc::new(if i == 2 {
                net.muting_sign_publishes()
            } else {
                net
            });
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let mut config = fast_config(id);
            config.y_fed_seed = Some(seed);
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            handles.iter().all(|h| !h.is_finished()),
            "a movement nobody can co-sign must not be reported as completed"
        );
        // Node 2 is muted, so every publication here is node 1's, and the frozen
        // batch is ONE input: exactly one commitment. Five seconds is many times
        // the 500 ms round deadline plus the 20 ms capped backoff, so a node that
        // hands the opportunity back rebuilds and republishes repeatedly.
        let published = hub.sign1_publish_count();
        assert_eq!(
            published, 1,
            "a spent round must be published once and then left for the next \
             opportunity: {published} round-1 publications"
        );
        for h in handles {
            h.abort();
        }
    }

    /// WI-097's acceptance. Two Treasury Movements in ONE epoch, off ONE ceremony,
    /// paced by the batch grid.
    ///
    /// The mock's `await_epoch_boundary` fires once and then parks for ever, so a
    /// second movement can only complete if the machine resumed at
    /// `CollectPegins`. A machine that answered a completed movement by
    /// re-entering `Idle` hangs this test — which is precisely what it does to a
    /// real node, for the five days until the next Cardano epoch.
    ///
    /// `treasury_info` counts the ceremonies: a DKG per movement would post a
    /// second Update-Y and rotate the treasury key under a live batch.
    #[tokio::test]
    async fn a_second_movement_runs_off_the_grid_without_a_second_ceremony() {
        let seed = [0x77u8; 32];
        let secp = Secp256k1::new();
        let fed_xonly = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&seed).unwrap(),
        )
        .x_only_public_key()
        .0;
        let treasury_info = MockCardanoChain::treasury_info_state(fed_xonly, [0xd4u8; 32]);

        let fixture = demo_static_fixture(2, 2, 19_200);
        let hub = MockPeerHub::new();
        // ONE grid and ONE treasury, shared: every node stands at the same
        // opportunity, and a submitted movement moves the head and the grid on
        // together — which is what makes the second movement a different
        // transaction rather than a replay of the first.
        let grid = Arc::new(std::sync::Mutex::new(crate::epoch::mocks::open_at(slot(1))));
        let head = MockCardanoChain::tm_chain_head(&fixture);

        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(
                MockCardanoChain::new(fixture.clone())
                    .with_treasury_info(treasury_info.clone())
                    .with_batch_window(Arc::clone(&grid))
                    .with_tm_chain(Arc::clone(&head))
                    .advancing_batch_on_submit(),
            );
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let mut config = fast_config(id);
            config.y_fed_seed = Some(seed);
            handles.push(tokio::spawn(async move {
                let mut built = BuiltBatch::default();
                let (first, resume) = drive_to_movement(
                    &chain,
                    &pegin,
                    &peers,
                    &clock,
                    &rng,
                    &config,
                    EpochPhase::Idle,
                    &mut built,
                )
                .await?;
                assert!(
                    matches!(resume, EpochPhase::CollectPegins { .. }),
                    "a confirmed movement must resume in the batch loop, not at {}",
                    resume.name()
                );
                let (second, _) = drive_to_movement(
                    &chain, &pegin, &peers, &clock, &rng, &config, resume, &mut built,
                )
                .await?;
                Ok::<_, EpochError>((first, second, built))
            }));
        }

        let mut movements = Vec::new();
        for h in handles {
            movements.push(
                tokio::time::timeout(Duration::from_secs(30), h)
                    .await
                    .expect("the second movement must not wait for the next epoch boundary")
                    .unwrap()
                    .expect("both movements complete"),
            );
        }

        // Both nodes made both movements, and agreed on each.
        assert_eq!(movements[0].0.txid, movements[1].0.txid);
        assert_eq!(movements[0].1.txid, movements[1].1.txid);
        // The second is a genuine second movement: it spends the first's change.
        assert_ne!(movements[0].0.txid, movements[0].1.txid);
        assert_eq!(
            movements[0].1.unsigned_tx.input[0].previous_output.txid, movements[0].0.txid,
            "each movement's treasury input is the previous movement's output"
        );
        // Two opportunities used, so the grid stands at the third...
        assert_eq!(grid.lock().unwrap().open().unwrap().index, 3);
        // ...and the second movement was built for the SECOND of them, on both
        // nodes. Without that, "two movements" could be one opportunity served
        // twice — the treasury self-move the marker exists to prevent.
        for (_, _, built) in &movements {
            assert!(
                built.is(fixture.roster.epoch, 2),
                "the second movement must belong to B_2, not to B_1 again"
            );
        }
        // ONE ceremony for both.
        assert_eq!(
            treasury_info.lock().unwrap().rotations.len(),
            1,
            "the DKG runs once per EPOCH — a second movement must not rotate the treasury key"
        );
    }

    /// WI-032 end to end, and the reason the fold matters at all: the peg-out the
    /// FIRST movement paid must be in this node's completed-peg-outs trie by the
    /// time it builds the SECOND, or it pays the same withdrawal twice.
    ///
    /// The request UTxO is still open at the second movement — that is the normal
    /// state, since completing it needs the Bitcoin confirmation plus a membership
    /// proof, hours later or never — so the trie is the ONLY thing that can tell
    /// the two apart (WI-031). Which makes this the test that covers the whole
    /// path: `RecordMovement` persists, the batch loop's `settle_pending_tm` folds
    /// on observing the head move, and `build_tm` reads the result.
    ///
    /// Before this change the fold ran only inside a blocking wait that could not
    /// succeed, so the second movement re-paid the first's peg-out.
    #[tokio::test]
    async fn the_second_movement_does_not_re_pay_what_the_first_one_paid() {
        use crate::cardano::cpo_trie::CpoTrie;
        use crate::epoch::fixture::StaticPegOut;
        use crate::epoch::pending_tm::PendingTm;
        use bitcoin::Amount;

        let dir = std::env::temp_dir().join(format!("wi032-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut fixture = demo_static_fixture(2, 2, 19_500);
        let dest = p2wpkh(0x09);
        let gross = Amount::from_sat(50_000);
        fixture.pegouts.push(StaticPegOut {
            script_pubkey: dest.clone(),
            amount: gross,
            created_slot: 0,
            created: now_ms(),
        });

        let hub = MockPeerHub::new();
        // One grid, one treasury, one bridge-state singleton — all shared, as on
        // chain. The singleton starts at the empty roots (a bridge with no
        // history) and advances with each submitted movement.
        let grid = Arc::new(std::sync::Mutex::new(crate::epoch::mocks::open_at(slot(1))));
        let head = MockCardanoChain::tm_chain_head(&fixture);
        let roots = MockCardanoChain::bridge_roots_state(
            crate::cardano::spi_trie::SpiTrie::empty().root(),
            CpoTrie::empty().root(),
        );

        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(
                MockCardanoChain::new(fixture.clone())
                    .with_batch_window(Arc::clone(&grid))
                    .with_tm_chain(Arc::clone(&head))
                    .with_shared_bridge_roots(Arc::clone(&roots))
                    .advancing_batch_on_submit(),
            );
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let mut config = fast_config(id);
            let node_dir = dir.join(format!("node{i}"));
            config.state_dir = Some(node_dir.clone());
            handles.push(tokio::spawn(async move {
                let mut built = BuiltBatch::default();
                let (first, resume) = drive_to_movement(
                    &chain,
                    &pegin,
                    &peers,
                    &clock,
                    &rng,
                    &config,
                    EpochPhase::Idle,
                    &mut built,
                )
                .await?;
                // The first movement is posted, not yet folded: it is recorded,
                // and nothing has touched the tries.
                assert!(
                    PendingTm::load(&node_dir).unwrap().is_some(),
                    "a posted movement must be recorded before anything waits on it"
                );
                assert!(
                    CpoTrie::load(&node_dir).unwrap().is_none(),
                    "an unconfirmed movement must not advance the trie"
                );
                let (second, _) = drive_to_movement(
                    &chain, &pegin, &peers, &clock, &rng, &config, resume, &mut built,
                )
                .await?;
                Ok::<_, EpochError>((first, second, node_dir))
            }));
        }

        let mut movements = Vec::new();
        for h in handles {
            movements.push(
                tokio::time::timeout(Duration::from_secs(30), h)
                    .await
                    .expect("neither movement may block on a confirmation")
                    .unwrap()
                    .expect("both movements complete"),
            );
        }

        let payments = |tm: &TreasuryMovement| -> Vec<bitcoin::TxOut> {
            tm.unsigned_tx
                .output
                .iter()
                .filter(|o| !o.script_pubkey.is_op_return() && !o.script_pubkey.is_p2tr())
                .cloned()
                .collect()
        };
        let (first, second, node_dir) = &movements[0];
        assert_eq!(
            payments(first).len(),
            1,
            "the first movement pays the request"
        );
        assert_eq!(payments(first)[0].script_pubkey, dest);
        assert!(
            payments(second).is_empty(),
            "the second movement must not re-pay a request the first already paid — the \
             completed-peg-outs trie is the only record that can tell them apart, and it only \
             holds the payment if the fold happened: got {:?}",
            payments(second)
        );

        // ...and it holds it because the fold ran, on both nodes.
        for (_, _, node_dir) in &movements {
            let trie = CpoTrie::load(node_dir)
                .unwrap()
                .expect("the confirmed movement was folded into the trie");
            assert!(trie.contains(&crate::epoch::mocks::fixture_por_id(&dest, gross)));
        }
        // The record now names the SECOND movement: the first was cleared when it
        // was folded, so the two can never be confused.
        assert_eq!(
            PendingTm::load(node_dir).unwrap().map(|p| p.txid),
            Some(second.txid)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The gate the spec states at each `B_i`: with a movement already in flight
    /// against the tip the opportunity passes UNUSED. It must not wait inside the
    /// opportunity for the tip to free up (that would build off a stale freeze),
    /// and it must not build a second movement off a head that is already being
    /// spent.
    #[tokio::test]
    async fn an_open_opportunity_passes_unused_while_a_movement_is_in_flight() {
        let (signer, group_keys) = phase1_signer_for(2, 3);
        let config = fast_config(Identifier::try_from(1u16).unwrap());
        let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());

        let busy: Arc<dyn CardanoChain> = Arc::new(
            MockCardanoChain::new(demo_static_fixture(2, 2, 19_300))
                .with_batch(slot(4))
                .with_movement_in_flight(),
        );
        let mut built = BuiltBatch::default();
        let waited = tokio::time::timeout(
            Duration::from_millis(300),
            collect_pegins_phase(
                &busy,
                &pegin,
                &config,
                7,
                signer.roster.clone(),
                group_keys.clone(),
                &mut built,
            ),
        )
        .await;
        assert!(
            waited.is_err(),
            "a busy tip must produce no batch at this opportunity"
        );
        assert!(
            built.is(7, 4),
            "the opportunity is CONSUMED, not retried until the tip frees up"
        );

        // The same grid position with a free tip does build.
        let free: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(demo_static_fixture(2, 2, 19_300)).with_batch(slot(4)));
        let next = tokio::time::timeout(
            Duration::from_secs(5),
            collect_pegins_phase(
                &free,
                &pegin,
                &config,
                7,
                signer.roster,
                group_keys,
                &mut BuiltBatch::default(),
            ),
        )
        .await
        .expect("a free tip builds at the opportunity")
        .expect("collect_pegins");
        assert!(matches!(next, EpochPhase::BuildTm { .. }));
    }

    /// `Closed { next: None }` is the epoch's TM work being over — everything left
    /// is past `final_tm_cutoff`. `Closed { next: Some(_) }` is not: the machine
    /// waits for that opportunity rather than ending the epoch, which is the
    /// distinction WI-041 kept `Closed` separate from `NoGrid` to preserve.
    #[tokio::test]
    async fn an_exhausted_grid_ends_the_epoch_but_a_pending_one_does_not() {
        use crate::epoch::batch::BatchWindow;
        let chain = MockCardanoChain::new(demo_static_fixture(2, 2, 19_400));
        let window = chain.batch_window();
        let chain: Arc<dyn CardanoChain> = Arc::new(chain);
        let config = fast_config(Identifier::try_from(1u16).unwrap());
        let me = config.identity.identifier;

        *window.lock().unwrap() = BatchWindow::Closed { next: None };
        let turn = await_batch_opportunity(&chain, &config, me, 7, &mut BuiltBatch::default())
            .await
            .unwrap();
        assert!(matches!(turn, BatchTurn::EpochOver));

        *window.lock().unwrap() = BatchWindow::Closed {
            next: Some(slot(2)),
        };
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                await_batch_opportunity(&chain, &config, me, 7, &mut BuiltBatch::default()),
            )
            .await
            .is_err(),
            "an opportunity still to come must be waited for, not treated as the end of the epoch"
        );

        // The same question in its other form. `current()` reports the LAST
        // opportunity for its whole interval, so the end of the grid is normally
        // seen as an OPEN window this node has already served — never as `Closed`.
        // Reading only `Closed` there would poll out the rest of the epoch instead
        // of parking for the boundary.
        *window.lock().unwrap() = BatchWindow::Open {
            batch: slot(9),
            next: None,
        };
        let mut served = BuiltBatch::default();
        served.mark(7, 9);
        let turn = await_batch_opportunity(&chain, &config, me, 7, &mut served)
            .await
            .unwrap();
        assert!(
            matches!(turn, BatchTurn::EpochOver),
            "an open-but-last opportunity, once served, is the end of the epoch"
        );
    }

    /// The wait is the exact hop to the opportunity, and the ceiling only bounds
    /// it. That distinction is the whole reason `batch_poll_ceiling` is not an
    /// operator key: because the hop shrinks as `B_i` approaches, the final sleep
    /// lands on the opportunity whatever the ceiling is, so no local value decides
    /// WHEN a node freezes — and a flat poll instead of this would have each node
    /// notice `B_i` at its own offset past it and freeze a different set.
    #[test]
    fn the_hop_is_exact_below_the_ceiling_and_clamped_above_it() {
        let ceiling = Duration::from_secs(300);
        assert_eq!(
            hop_to_opportunity(5_000_100, 5_000_040, ceiling),
            Duration::from_secs(60),
            "a minute away is a minute's sleep"
        );
        assert_eq!(
            hop_to_opportunity(5_021_600, 5_000_000, ceiling),
            ceiling,
            "six hours away is capped, so the grid is re-read on the way"
        );
        assert_eq!(
            hop_to_opportunity(5_000_001, 5_000_000, ceiling),
            Duration::from_secs(1),
            "the last hop is the remaining distance, not the ceiling"
        );
        assert_eq!(
            hop_to_opportunity(5_000_000, 5_000_009, ceiling),
            Duration::from_secs(1),
            "a tip already past the target sleeps the floor rather than spinning"
        );
    }

    /// With no grid to follow there is no schedule to obey and no local cadence to
    /// invent, so the machine keeps its pre-grid bound: one movement, then the next
    /// boundary. The marker is keyed by epoch, so the next one gets its own.
    #[tokio::test]
    async fn without_a_grid_the_machine_makes_one_movement_per_epoch() {
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(demo_static_fixture(2, 2, 19_500)));
        let config = fast_config(Identifier::try_from(1u16).unwrap());
        let me = config.identity.identifier;
        let mut built = BuiltBatch::default();

        let first = await_batch_opportunity(&chain, &config, me, 7, &mut built)
            .await
            .unwrap();
        assert!(matches!(first, BatchTurn::Build(None)));
        let second = await_batch_opportunity(&chain, &config, me, 7, &mut built)
            .await
            .unwrap();
        assert!(matches!(second, BatchTurn::EpochOver));
        let next_epoch = await_batch_opportunity(&chain, &config, me, 8, &mut built)
            .await
            .unwrap();
        assert!(matches!(next_epoch, BatchTurn::Build(None)));
    }

    /// A failure decides which opportunity to retry, and the two cases differ.
    ///
    /// A failed BUILD must give its opportunity back — no movement came of it, so
    /// the next poll retries the same `B_i` rather than waiting out the interval.
    /// A failure while WAITING for the next opportunity must not: the marker then
    /// belongs to the movement that already succeeded, and handing it back builds
    /// a second movement for a batch this node has already served — a fee spent
    /// moving the treasury to itself.
    #[tokio::test]
    async fn a_failure_gives_back_its_own_opportunity_but_never_a_served_one() {
        let (signer, group_keys) = phase1_signer_for(2, 3);
        let config = fast_config(Identifier::try_from(1u16).unwrap());
        let fixture = demo_static_fixture(2, 2, 19_700);

        // Waiting: B_1 was served by a completed movement, and the grid read
        // fails. The marker must survive.
        let waiting: Arc<dyn CardanoChain> = Arc::new(
            MockCardanoChain::new(fixture.clone())
                .with_batch(slot(1))
                .fail_next_snapshots(1),
        );
        let pegin: Arc<dyn CardanoPegInSource> = Arc::new(MockCardanoPegInSource::new());
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(
            Identifier::try_from(1u16).unwrap(),
            MockPeerHub::new(),
        ));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        let mut built = BuiltBatch::default();
        built.mark(7, 1);
        let resume = EpochPhase::CollectPegins {
            epoch: 7,
            roster: signer.roster.clone(),
            group_keys: group_keys.clone(),
        };
        // It never reaches another movement (B_1 is spent and the grid does not
        // advance), so the wait is what we are timing out of.
        let _ = tokio::time::timeout(
            Duration::from_secs(4),
            drive_to_movement(
                &waiting, &pegin, &peers, &clock, &rng, &config, resume, &mut built,
            ),
        )
        .await;
        assert!(
            built.is(7, 1),
            "a served opportunity must not be handed back by an unrelated failure"
        );

        // Building: this call takes B_2 and then fails, so B_2 is retried.
        let building: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(fixture).with_batch(slot(2)));
        let failing = MockCardanoPegInSource::new();
        failing.fail_next(u32::MAX);
        let failing: Arc<dyn CardanoPegInSource> = Arc::new(failing);
        let resume = EpochPhase::CollectPegins {
            epoch: 7,
            roster: signer.roster,
            group_keys,
        };
        let _ = tokio::time::timeout(
            Duration::from_secs(4),
            drive_to_movement(
                &building, &failing, &peers, &clock, &rng, &config, resume, &mut built,
            ),
        )
        .await;
        assert!(
            !built.is(7, 2),
            "an opportunity whose build failed must be retried, not consumed"
        );
    }

    /// A transient chain failure inside the batch loop costs one batch, not the
    /// epoch. `Idle` waits for the chain epoch to ADVANCE, so answering a
    /// five-second provider outage by re-entering it parks the node for days —
    /// and a loop that cycles per batch meets far more of them than one movement
    /// per epoch ever did. Here the mock parks in `await_epoch_boundary` after the
    /// first call, so that failure mode hangs the test.
    #[tokio::test]
    async fn a_transient_failure_costs_one_batch_not_the_epoch() {
        let fixture = demo_static_fixture(2, 2, 19_600);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=2u16 {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::new(fixture.clone()));
            let source = MockCardanoPegInSource::new();
            // Both nodes fail the same query, so they stay in step; one node
            // failing alone would merely time the other out of its signing round.
            source.fail_next(1);
            let pegin: Arc<dyn CardanoPegInSource> = Arc::new(source);
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = fast_config(id);
            handles.push(tokio::spawn(async move {
                run_epoch_loop(chain, pegin, peers, clock, rng, &config).await
            }));
        }
        for h in handles {
            tokio::time::timeout(Duration::from_secs(30), h)
                .await
                .expect("a failed peg-in query must not cost the epoch")
                .unwrap()
                .expect("the movement completes after the retry");
        }
    }

    /// A CONFIRMED TM advances the persisted swept peg-ins trie: every input
    /// except input 0 becomes an entry [SPI-1], all valued with the TM's own
    /// input-0 outpoint [SPI-3]. A TM whose `spi_root` disagrees with what this
    /// node's trie reaches is refused and the trie file is NOT touched.
    #[test]
    fn a_confirmed_tm_advances_the_persisted_spi_trie() {
        use crate::cardano::spi_trie::SpiTrie;

        let dir = std::env::temp_dir().join(format!("spi-advance-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut config = fast_config(Identifier::try_from(1u16).unwrap());
        config.state_dir = Some(dir.clone());

        let t = spi_op(0xaa, 0);
        let a = spi_op(0x01, 0);
        let b = spi_op(0x02, 3);
        let root = SpiTrie::empty().root_after(&[t, a, b]).unwrap();
        let tm = pending(&spi_tm(&[t, a, b], root));
        advance_spi_trie(&config, &dir, &tm).expect("a matching root advances the trie");

        let trie = SpiTrie::load(&dir).unwrap().expect("trie persisted");
        assert_eq!(trie.root(), root);
        assert!(trie.contains(&a));
        assert!(trie.contains(&b));
        assert!(!trie.contains(&t), "input 0 must not become an entry");
        assert_eq!(trie.get(&a), Some(t.as_slice()));

        // A divergent spi_root is refused, and the persisted trie stays put.
        let tm_bad = pending(&spi_tm(&[spi_op(0xbb, 0), spi_op(0x03, 1)], [9u8; 32]));
        advance_spi_trie(&config, &dir, &tm_bad).expect_err("a divergent root must be refused");
        let untouched = SpiTrie::load(&dir).unwrap().expect("trie still present");
        assert_eq!(
            untouched.root(),
            root,
            "a refused TM must not change the file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node with no `state_dir` tracks no tries, so a movement it co-signs
    /// leaves nothing behind and neither half of the fold errors on it.
    ///
    /// It does WARN, once per movement — its tries fall further behind with each
    /// one and the divergence surfaces much later, as a refusal to build — but
    /// this asserts the state, not the log line; the warning's rationale lives in
    /// `record_movement_phase`'s doc.
    #[test]
    fn a_node_without_a_state_dir_records_nothing() {
        use crate::cardano::spi_trie::SpiTrie;
        use crate::epoch::pending_tm::PendingTm;

        let dir = std::env::temp_dir().join(format!("wi032-nostate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut config = fast_config(Identifier::try_from(1u16).unwrap());
        config.state_dir = None;

        let tm = spi_tm(&[spi_op(0xaa, 0)], SpiTrie::empty().root());
        record_movement_phase(&config, 7, &tm).expect("an untracking node is not an error");
        settle_pending_tm(&config, &treasury_at(outpoint(spi_op(0xbb, 0))))
            .expect("with no record there is nothing to fold");
        assert!(
            !dir.exists(),
            "a node with no state_dir must not write state anywhere"
        );
        // And nothing was recorded for a directory it does not have.
        config.state_dir = Some(dir.clone());
        assert_eq!(PendingTm::load(&dir).unwrap(), None);
    }
}
