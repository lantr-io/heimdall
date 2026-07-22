//! DKG phase order -- Round1 -> Round2 -> Part3, with a stake-weighted
//! abort/rerun gate (WI-014 #3).
//!
//! Each `(epoch, attempt)` runs the full FROST DKG over the attempt's
//! candidate set ([`DkgContext`]). frost-core's `dkg_part2`/`part3` require
//! the *entire* candidate set to contribute (`round1_packages.len() ==
//! max_signers - 1`), so there is no "complete with a subset" within a single
//! attempt. When a peer is absent or provably faulty:
//!
//!   - the surviving subset — `L1` (valid Round 1 publishers) after Round 1, or
//!     `Q` (valid Round 2 senders) after Round 2 — is put through the quorum
//!     gate [`DkgContext::quorum_ok`];
//!   - if it clears the gate, [`DkgContext::reduced_to`] builds the next
//!     attempt's candidate set (bumped attempt, re-based stake-weighted
//!     threshold) and the ceremony reruns from Round 1 over the reduced set;
//!   - if it fails the gate (or is too small to run FROST DKG), the epoch's DKG
//!     is dead ([`EpochError::DkgAborted`]) and the caller backs off to the next
//!     boundary rather than killing the process.
//!
//! The happy path (everyone contributes → `Q == C`, no reduction) needs no
//! rerun and is what the multi-instance acceptance test exercises.
//!
//! The transport drops invalid peer payloads (bad PoK / bad decrypted share) as
//! `Ok(None)` and retains signed evidence. When a deadline leaves peers outside
//! `L1`/`Q`, the orchestration layer asks the transport for provable evidence
//! and hands any such evidence to the chain ban flow. Plain absence is not
//! punishable; absent peers are only excluded from a reduced rerun.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use frost::Identifier;
use frost_secp256k1_tr as frost;

use crate::cardano::dkg_roster::DkgContext;
use crate::epoch::log::{id_short, short_hex};
use crate::epoch::state::SpoInfo;
use crate::epoch::state::{
    DkgCollected, DkgRound, EpochConfig, EpochError, EpochPhase, EpochResult, GroupKeys,
};
use crate::epoch::traits::{CardanoChain, Clock, DkgFaultEvidence, PeerNetwork, RngSource};
use crate::frost::participant;
use crate::http::frost_bridge;
use crate::http::wire::DkgNamespace;

/// How many times [`poll_dkg_round1`] re-fetches every peer after Round-1
/// collection finishes, spaced one poll interval apart, to catch a peer that
/// serves a second, conflicting payload. Covers a grace window of
/// `(PASSES - 1) * poll_interval` past the moment the last package arrived.
const EQUIVOCATION_SWEEP_PASSES: usize = 3;

/// Drive one DKG sub-round for `ctx` and produce the next phase: the next
/// sub-round, a reduced-set rerun at Round 1, or (at Part 3) `PublishKeys`.
pub async fn dkg_phase(
    chain: &Arc<dyn CardanoChain>,
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    round: DkgRound,
    ctx: DkgContext,
    mut collected: DkgCollected,
) -> EpochResult<EpochPhase> {
    let me = config.identity.identifier;
    let epoch = ctx.epoch;
    let attempt = ctx.attempt;
    let schedule_anchor_ms = ctx.schedule_anchor_ms;
    // Every payload (and its replay binding) is namespaced by the attempt, so a
    // stale previous-attempt package can never be replayed into a rerun.
    let ns = DkgNamespace::for_attempt(epoch, u64::from(attempt));
    let roster = ctx.to_roster();
    let eligible: BTreeSet<Identifier> = roster.participants.keys().copied().collect();

    match round {
        DkgRound::Round1 => {
            crate::epoch_log!(
                me,
                epoch,
                "DKG round1 (attempt {attempt}): generating secret polynomial and commitments \
                 (n={}, t={})",
                roster.max_signers,
                roster.min_signers
            );

            let mut dkg_rng = rng.rng(b"dkg1");
            let (secret, package) =
                participant::dkg_part1(me, roster.max_signers, roster.min_signers, &mut dkg_rng)
                    .map_err(|e| EpochError::Frost(format!("dkg_part1: {e}")))?;

            let pkg_bytes = package
                .serialize()
                .map_err(|e| EpochError::Frost(format!("round1 pkg serialize: {e}")))?;
            crate::epoch_log!(
                me,
                epoch,
                "  -> round1 package built ({} bytes): {}",
                pkg_bytes.len(),
                short_hex(&pkg_bytes, 16)
            );

            peers.publish_dkg_round1(ns, me, &package).await?;
            crate::epoch_log!(me, epoch, "  -> round1 package published to local server");

            collected.round1_mine = Some(secret);
            collected.round1_peers.insert(me, package);

            // DEMO-ONLY equivocation injection (never set in production): publish a
            // SECOND, distinct Round-1 package to our own server after peers have
            // collected the first one, so an honest peer's confirmatory re-fetch (see
            // `poll_dkg_round1`) retains BOTH and reports us for equivocation. We keep
            // using the first package's secret for the rest of the ceremony.
            if config.inject_fault == Some(crate::epoch::state::InjectFault::EquivocateRound1) {
                let mut equiv_rng = rng.rng(b"dkg1-equivocation");
                let (_discard, equiv_pkg) = participant::dkg_part1(
                    me,
                    roster.max_signers,
                    roster.min_signers,
                    &mut equiv_rng,
                )
                .map_err(|e| EpochError::Frost(format!("dkg_part1 (equivocation): {e}")))?;
                crate::epoch_log!(
                    me,
                    epoch,
                    "  ⚠ INJECT: equivocating round1 — scheduling a SECOND conflicting package"
                );
                let peers_equiv = peers.clone();
                // One and a half poll cycles: long enough that every live peer has
                // already fetched package A (so they RETAIN A and see B as a conflict,
                // rather than B being the only payload they ever saw), short enough to
                // land inside the honest nodes' anti-equivocation sweep window.
                let delay = config.poll_interval.saturating_mul(3) / 2;
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = peers_equiv.publish_dkg_round1(ns, me, &equiv_pkg).await;
                });
            }

            // Poll peers' Round 1 packages until the schedule-anchored deadline.
            // The valid publishers (plus self) form the live subset L1.
            let peer_infos = roster.peers_of(me);
            let deadline = round_deadline(
                clock,
                schedule_anchor_ms,
                config.dkg_round1_offset,
                config.dkg_round_timeout,
            );
            crate::epoch_log!(
                me,
                epoch,
                "  waiting for round1 packages from {} peer(s) until deadline (anchored={})...",
                peer_infos.len(),
                schedule_anchor_ms.is_some()
            );
            poll_dkg_round1(
                peers,
                clock,
                config,
                ns,
                me,
                &peer_infos,
                deadline,
                &mut collected.round1_peers,
            )
            .await?;

            // Drop packages built for a DIFFERENT candidate set before they can
            // reach FROST. A round-1 package carries exactly `t` commitment
            // points, so a length other than ours means the sender derived a
            // different member list — after a ban, say, which changes both `t`
            // and the index assignment. Such a peer is ABSENT for our purposes,
            // never faulty: its package is honest and correctly signed, just for
            // another ceremony. (The fault path agrees by construction —
            // building fault evidence requires reconstructing the sender's
            // poseidon_commit, which is exactly what fails across views, so a
            // cross-view peer can never be punished.)
            //
            // Without this, the mismatched vector reaches `dkg_part2`, which
            // returns "Incorrect number of commitments" — an error that used to
            // terminate the epoch loop, permanently freezing an honest node on a
            // stale view (observed 2026-07-22, spo2).
            let expected_commitments = usize::from(ctx.threshold);
            collected.round1_peers.retain(|id, pkg| {
                let got = pkg.commitment().serialize().map_or(0, |c| c.len());
                let keep = got == expected_commitments;
                if !keep {
                    crate::epoch_log!(
                        me,
                        ctx.epoch,
                        "  dropping round1 from {}: {got} commitments, we expect {expected_commitments} \
                         (peer is on a different candidate set — treating as absent, not faulty)",
                        id_short(*id)
                    );
                }
                keep
            });

            let l1: BTreeSet<Identifier> = collected.round1_peers.keys().copied().collect();
            // Report equivocation by any peer that DID publish a usable package (in L1,
            // so not covered by the exclusion path below). Catches a "smart" equivocator.
            report_round1_equivocations(chain, peers, ns, me, &ctx, &l1).await?;
            if l1 == eligible {
                crate::epoch_log!(
                    me,
                    epoch,
                    "  <- all {} round1 packages in, advancing to round2",
                    l1.len()
                );
                Ok(EpochPhase::Dkg {
                    round: DkgRound::Round2,
                    ctx,
                    collected,
                })
            } else {
                let absent: Vec<_> = eligible.difference(&l1).map(|id| id_short(*id)).collect();
                crate::epoch_log!(
                    me,
                    epoch,
                    "  round1 incomplete at deadline: {}/{} published; missing/faulty: {:?}",
                    l1.len(),
                    eligible.len(),
                    absent
                );
                report_round1_faults(chain, peers, ns, me, &ctx, &l1).await?;
                rerun_or_abort(me, &ctx, DkgRound::Round1, &l1, "round1 incomplete")
            }
        }

        DkgRound::Round2 => {
            crate::epoch_log!(
                me,
                epoch,
                "DKG round2 (attempt {attempt}): computing per-peer secret shares from round1 \
                 packages"
            );

            let secret = collected
                .round1_mine
                .take()
                .ok_or_else(|| EpochError::Transition("missing round1 secret".into()))?;

            // All peers' round1 packages except our own. We only reach Round 2
            // when L1 == the full candidate set, so this is exactly the
            // `max_signers - 1` packages dkg_part2 requires.
            let peer_round1: BTreeMap<_, _> = collected
                .round1_peers
                .iter()
                .filter(|(id, _)| **id != me)
                .map(|(id, pkg)| (*id, pkg.clone()))
                .collect();

            let (round2_secret, round2_packages) = participant::dkg_part2(secret, &peer_round1)
                .map_err(|e| EpochError::Frost(format!("dkg_part2: {e}")))?;
            crate::epoch_log!(
                me,
                epoch,
                "  -> built {} encrypted shares (one per peer)",
                round2_packages.len()
            );
            for peer_id in round2_packages.keys() {
                crate::epoch_log!(
                    me,
                    epoch,
                    "     - share addressed to spo={}",
                    id_short(*peer_id)
                );
            }

            // Pair each share with its recipient's SpoInfo so the transport can
            // encrypt under that peer's bifrost_id_pk and address it by pool_id.
            let recipients: Vec<(SpoInfo, _)> = round2_packages
                .into_iter()
                .map(|(rid, pkg)| {
                    roster
                        .participants
                        .get(&rid)
                        .cloned()
                        .map(|info| (info, pkg))
                        .ok_or_else(|| {
                            EpochError::Transition(format!(
                                "round2 recipient {} not in roster",
                                id_short(rid)
                            ))
                        })
                })
                .collect::<Result<_, _>>()?;
            let my_round1 = collected
                .round1_peers
                .get(&me)
                .ok_or_else(|| EpochError::Transition("missing own round1 package".into()))?;
            let (my_commitments, _sigma_i) = frost_bridge::round1_fields(my_round1)
                .map_err(|e| EpochError::Frost(format!("round1 fields: {e}")))?;
            peers
                .publish_dkg_round2(ns, me, &my_commitments, &recipients)
                .await?;
            crate::epoch_log!(me, epoch, "  -> round2 packages published");

            collected.round2_mine = Some(round2_secret);

            let peer_infos = roster.peers_of(me);
            let deadline = round_deadline(
                clock,
                schedule_anchor_ms,
                config.dkg_round2_offset,
                config.dkg_round_timeout,
            );
            crate::epoch_log!(
                me,
                epoch,
                "  waiting for round2 shares addressed to me from {} peer(s) until deadline \
                 (anchored={})...",
                peer_infos.len(),
                schedule_anchor_ms.is_some()
            );
            poll_dkg_round2(
                peers,
                clock,
                config,
                ns,
                me,
                &peer_infos,
                deadline,
                &collected.round1_peers,
                &mut collected.round2_peers,
            )
            .await?;

            // Q = self (always qualifies — it produced its own shares) ∪ the
            // peers whose valid Round 2 share we decrypted+verified.
            let mut q: BTreeSet<Identifier> = collected.round2_peers.keys().copied().collect();
            q.insert(me);
            if q == eligible {
                crate::epoch_log!(
                    me,
                    epoch,
                    "  <- all {} round2 shares in, advancing to part3",
                    collected.round2_peers.len()
                );
                Ok(EpochPhase::Dkg {
                    round: DkgRound::Part3,
                    ctx,
                    collected,
                })
            } else {
                let absent: Vec<_> = eligible.difference(&q).map(|id| id_short(*id)).collect();
                crate::epoch_log!(
                    me,
                    epoch,
                    "  round2 incomplete at deadline: {}/{} qualified; missing/faulty: {:?}",
                    q.len(),
                    eligible.len(),
                    absent
                );
                report_round2_faults(chain, peers, ns, me, &ctx, &q, &collected.round1_peers)
                    .await?;
                rerun_or_abort(me, &ctx, DkgRound::Round2, &q, "round2 incomplete")
            }
        }

        DkgRound::Part3 => {
            crate::epoch_log!(
                me,
                epoch,
                "DKG part3 (attempt {attempt}): combining shares into final KeyPackage + group key"
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

            // Identical-Y_51 sanity check (WI-014 #4). Y_51 is the deterministic
            // output of dkg_part3 over the qualified set's published Round 1 + 2
            // payloads, which every honest node holds identically — so every node
            // derives the SAME Y_51 (and hence the same treasury address). That
            // cross-node guarantee is asserted by the multi-instance acceptance
            // test (all SPOs' verifying_key + treasury address match). Note it is
            // NOT the naive Σ_l φ_{l,0} of the wire commitments: frost-secp256k1-tr
            // applies BIP-340 even-Y normalization per contribution inside the
            // ceremony, so the signing key differs from the raw commitment sum.
            //
            // Locally we assert part3's two outputs are coherent: the KeyPackage
            // (this node's share) and the PublicKeyPackage (the published group)
            // must carry the same group key, and the package must list this
            // node's verification share. A mismatch means a corrupt part3 output —
            // abort before locking funds under an incoherent key.
            check_dkg_output_coherent(me, &key_package, &public_key_package)?;

            let vk_bytes = public_key_package
                .verifying_key()
                .serialize()
                .map_err(|e| EpochError::Frost(format!("verifying_key serialize: {e}")))?;
            crate::epoch_log!(
                me,
                epoch,
                "  -> group verifying key (Y_51) = {}",
                hex::encode(&vk_bytes)
            );
            crate::epoch_log!(
                me,
                epoch,
                "  -> my signing share is bound to spo={}, threshold {}",
                id_short(*key_package.identifier()),
                key_package.min_signers()
            );

            let group_keys = GroupKeys {
                verifying_key: *public_key_package.verifying_key(),
                public_key_package,
                key_package,
            };

            // Persist the share so it survives a restart for the whole epoch
            // (WI-014 #5). A persist failure is logged but NOT fatal: the share
            // is valid in memory for this process, and aborting a completed DKG
            // over a transient disk error (only to re-run the expensive ceremony,
            // which may also fail to persist) is worse than running without
            // restart-survival until the next successful write.
            if let Some(dir) = &config.state_dir {
                match crate::epoch::persist::PersistedDkg::from_output(
                    epoch,
                    attempt,
                    &roster,
                    &group_keys,
                )
                .and_then(|s| crate::epoch::persist::write_dkg_state(dir, &s))
                {
                    Ok(()) => crate::epoch_log!(
                        me,
                        epoch,
                        "  -> DKG state persisted to {}",
                        crate::epoch::persist::dkg_state_path(dir, epoch).display()
                    ),
                    Err(e) => crate::epoch_log!(
                        me,
                        epoch,
                        "  WARNING: could not persist DKG state ({e}); share is in memory only \
                         and will not survive a restart this epoch"
                    ),
                }
            }

            // The roster handed to the rest of the cycle is the candidate set
            // that actually formed the key (the possibly-reduced `ctx`), so
            // signing draws from exactly the share-holders.
            Ok(EpochPhase::PublishKeys {
                epoch,
                roster,
                group_keys,
            })
        }
    }
}

/// Orchestration-layer exclusion evidence for one incomplete DKG round: the
/// eligible participants that did NOT deliver a verifiable payload by the
/// deadline. This records which participants to ask the transport about.
/// Absence alone is not punishable; only retained signed invalid-payload or
/// equivocation evidence is sent to the chain ban flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgExclusionEvidence {
    pub epoch: u64,
    pub attempt: u32,
    pub round: DkgRound,
    /// Excluded participants as `(identifier, pool_id)`, in identifier order.
    pub excluded: Vec<(Identifier, Vec<u8>)>,
}

impl DkgExclusionEvidence {
    /// The eligible participants of `ctx` not present in `survivors`.
    #[must_use]
    pub fn from_round(ctx: &DkgContext, round: DkgRound, survivors: &BTreeSet<Identifier>) -> Self {
        let excluded = ctx
            .participants
            .iter()
            .filter(|p| !survivors.contains(&p.identifier))
            .map(|p| (p.identifier, p.pool_id.clone()))
            .collect();
        Self {
            epoch: ctx.epoch,
            attempt: ctx.attempt,
            round,
            excluded,
        }
    }

    /// Human-readable `pool_id@id` list for structured logging.
    fn summary(&self) -> String {
        self.excluded
            .iter()
            .map(|(id, pool)| {
                format!(
                    "{}@{}",
                    hex::encode(&pool[..pool.len().min(4)]),
                    id_short(*id)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// After a round finished incomplete, decide between a reduced-set rerun and a
/// fatal abort. Reruns iff the `survivors` clear the quorum gate AND there are
/// still enough of them to run FROST DKG; otherwise the epoch's DKG is dead.
fn rerun_or_abort(
    me: Identifier,
    ctx: &DkgContext,
    round: DkgRound,
    survivors: &BTreeSet<Identifier>,
    why: &str,
) -> EpochResult<EpochPhase> {
    let evidence = DkgExclusionEvidence::from_round(ctx, round, survivors);
    crate::epoch_log!(
        me,
        ctx.epoch,
        "  DKG exclusions (attempt {}, {:?}): excluded [{}]",
        ctx.attempt,
        round,
        evidence.summary()
    );
    let eligible = ctx.participants.len();
    let abort = |reason: String| {
        Err(EpochError::DkgAborted {
            epoch: ctx.epoch,
            attempt: ctx.attempt,
            qualified: survivors.len(),
            eligible,
            reason,
        })
    };
    if !ctx.quorum_ok(survivors) {
        return abort(format!(
            "{why}; surviving subset fails the threshold / >51%-stake quorum gate"
        ));
    }
    // N21: a reduction chain may not spill into the next grid window's attempt
    // namespace — abort instead; the caller re-enters at the next window with a
    // freshly re-queried (full) roster, which is also how an excluded-but-alive
    // peer gets back in.
    if (ctx.attempt + 1).is_multiple_of(crate::epoch::state::DKG_ATTEMPTS_PER_WINDOW) {
        return abort(format!(
            "{why}; attempt budget for this ceremony window exhausted"
        ));
    }
    match ctx.reduced_to(survivors) {
        Some(reduced) => Ok(EpochPhase::Dkg {
            round: DkgRound::Round1,
            ctx: reduced,
            collected: DkgCollected::default(),
        }),
        // quorum_ok already implies |survivors| >= threshold >= 2, so this is a
        // defensive guard (e.g. zero survivor stake) rather than a reachable arm.
        None => abort(format!("{why}; too few survivors to rerun FROST DKG")),
    }
}

async fn report_round1_faults(
    chain: &Arc<dyn CardanoChain>,
    peers: &Arc<dyn PeerNetwork>,
    ns: DkgNamespace,
    me: Identifier,
    ctx: &DkgContext,
    survivors: &BTreeSet<Identifier>,
) -> EpochResult<()> {
    let evidence = DkgExclusionEvidence::from_round(ctx, DkgRound::Round1, survivors);
    for (peer, fault) in round1_faults_for_excluded(peers, ns, ctx, &evidence).await? {
        publish_detected_fault(chain, me, ctx.epoch, peer, fault).await?;
    }
    Ok(())
}

async fn report_round2_faults(
    chain: &Arc<dyn CardanoChain>,
    peers: &Arc<dyn PeerNetwork>,
    ns: DkgNamespace,
    me: Identifier,
    ctx: &DkgContext,
    survivors: &BTreeSet<Identifier>,
    round1_packages: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
) -> EpochResult<()> {
    let evidence = DkgExclusionEvidence::from_round(ctx, DkgRound::Round2, survivors);
    for (peer, fault) in
        round2_faults_for_excluded(peers, ns, me, ctx, &evidence, round1_packages).await?
    {
        publish_detected_fault(chain, me, ctx.epoch, peer, fault).await?;
    }
    Ok(())
}

/// Report equivocation faults for peers that DID publish a usable Round-1 package
/// (they land in L1, so the exclusion-based [`round1_faults_for_excluded`] never
/// checks them). The confirmatory re-fetch in [`poll_dkg_round1`] populates the
/// retained conflicts that back these faults.
async fn report_round1_equivocations(
    chain: &Arc<dyn CardanoChain>,
    peers: &Arc<dyn PeerNetwork>,
    ns: DkgNamespace,
    me: Identifier,
    ctx: &DkgContext,
    collected: &BTreeSet<Identifier>,
) -> EpochResult<()> {
    let roster = ctx.to_roster();
    for id in collected {
        if *id == me {
            continue;
        }
        let Some(peer) = roster.participants.get(id) else {
            continue;
        };
        for fault in peers.dkg_round1_fault_evidence(ns, peer).await? {
            publish_detected_fault(chain, me, ctx.epoch, peer.clone(), fault).await?;
        }
    }
    Ok(())
}

async fn round1_faults_for_excluded(
    peers: &Arc<dyn PeerNetwork>,
    ns: DkgNamespace,
    ctx: &DkgContext,
    evidence: &DkgExclusionEvidence,
) -> EpochResult<Vec<(SpoInfo, DkgFaultEvidence)>> {
    let roster = ctx.to_roster();
    let mut out = Vec::new();
    for (id, _) in &evidence.excluded {
        let Some(peer) = roster.participants.get(id) else {
            continue;
        };
        for fault in peers.dkg_round1_fault_evidence(ns, peer).await? {
            out.push((peer.clone(), fault));
        }
    }
    Ok(out)
}

async fn round2_faults_for_excluded(
    peers: &Arc<dyn PeerNetwork>,
    ns: DkgNamespace,
    me: Identifier,
    ctx: &DkgContext,
    evidence: &DkgExclusionEvidence,
    round1_packages: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
) -> EpochResult<Vec<(SpoInfo, DkgFaultEvidence)>> {
    let roster = ctx.to_roster();
    let mut out = Vec::new();
    for (id, _) in &evidence.excluded {
        let Some(peer) = roster.participants.get(id) else {
            continue;
        };
        let Some(sender_round1) = round1_packages.get(id) else {
            continue;
        };
        let (sender_commitments, _sigma_i) = frost_bridge::round1_fields(sender_round1)
            .map_err(|e| EpochError::Frost(format!("round1 fields: {e}")))?;
        for fault in peers
            .dkg_round2_fault_evidence(ns, peer, me, &sender_commitments)
            .await?
        {
            out.push((peer.clone(), fault));
        }
    }
    Ok(out)
}

async fn publish_detected_fault(
    chain: &Arc<dyn CardanoChain>,
    me: Identifier,
    epoch: u64,
    peer: SpoInfo,
    fault: DkgFaultEvidence,
) -> EpochResult<()> {
    crate::epoch_log!(
        me,
        epoch,
        "  -> publishing DKG fault: kind={} accused={} spo={}",
        fault.kind_label(),
        hex::encode(fault.accused_pool_id()),
        id_short(peer.identifier)
    );
    chain.publish_dkg_fault_and_apply_ban(fault).await
}

/// Assert dkg_part3's two outputs are internally coherent: the [`KeyPackage`]
/// (this node's signing share) and the [`PublicKeyPackage`] (the published
/// group) must agree on the group key, and the package must publish this node's
/// verification share. part3 builds both from the same commitments, so a
/// mismatch indicates a corrupt output and the key must not lock funds. The
/// cross-node identical-Y_51 property itself follows from part3 being a pure,
/// deterministic function of the qualified set's shared Round 1+2 payloads, and
/// is asserted end-to-end by the multi-instance acceptance test.
fn check_dkg_output_coherent(
    me: Identifier,
    key_package: &frost::keys::KeyPackage,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> EpochResult<()> {
    if key_package.verifying_key() != public_key_package.verifying_key() {
        return Err(EpochError::Frost(
            "dkg_part3 incoherent: KeyPackage and PublicKeyPackage group keys differ".into(),
        ));
    }
    match public_key_package.verifying_shares().get(&me) {
        Some(share) if share == key_package.verifying_share() => Ok(()),
        Some(_) => Err(EpochError::Frost(format!(
            "dkg_part3 incoherent: published verification share for {} != my own",
            id_short(me)
        ))),
        None => Err(EpochError::Frost(format!(
            "dkg_part3 incoherent: no verification share for {} in the group package",
            id_short(me)
        ))),
    }
}

/// The poll deadline for a DKG round (WI-014 #6). When the schedule anchor is
/// known (`schedule_anchor_ms` — the ceremony window's grid line, or the epoch
/// boundary on the pre-N21 path), the deadline is ABSOLUTE — `anchor + offset`
/// — so every node freezes its live/qualified subset at the same chain-time
/// instant regardless of when it locally entered the round; that keeps
/// `L1`/`Q` (and any reduced-set rerun) agreeing across honest nodes. Without it (mock / no-registry fallback), the fixed relative
/// `fallback` window from now is used. The absolute target is converted to a
/// monotonic [`Instant`] via the local wall clock; over the few-minute DKG
/// window the two advance together, so a clock skew between nodes only shifts
/// the freeze by that skew, not unboundedly.
fn round_deadline(
    clock: &Arc<dyn Clock>,
    schedule_anchor_ms: Option<i64>,
    offset: Duration,
    fallback: Duration,
) -> Instant {
    match schedule_anchor_ms {
        Some(boundary) => {
            let remaining = remaining_to_offset(boundary, offset, wall_now_ms());
            // A *stale* anchor — `boundary + offset` already elapsed — collapses the window to
            // zero, leaving a node no time to poll for peers' packages (every retry then fails
            // identically). This happens whenever the ceremony runs well after the epoch boundary
            // (e.g. a mid-epoch demo). Fall back to the relative window so the round still has time
            // to converge. At a real epoch-boundary DKG `remaining > 0`, so anchoring is preserved.
            if remaining.is_zero() {
                clock.deadline(fallback)
            } else {
                clock.now() + remaining
            }
        }
        None => clock.deadline(fallback),
    }
}

/// Remaining wall-clock wait from `now_ms` until `boundary + offset`, saturating
/// at zero once the deadline has passed. Pure, for testability.
fn remaining_to_offset(boundary_ms: i64, offset: Duration, now_ms: i64) -> Duration {
    let offset_ms = i64::try_from(offset.as_millis()).unwrap_or(i64::MAX);
    let remaining = boundary_ms.saturating_add(offset_ms).saturating_sub(now_ms);
    u64::try_from(remaining)
        .map(Duration::from_millis)
        .unwrap_or(Duration::ZERO)
}

/// Current wall-clock time in Unix milliseconds, for schedule anchoring. Before
/// the Unix epoch (clock badly wrong) → 0.
pub(crate) fn wall_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Poll peers' Round 1 packages until everyone has published or the round
/// deadline passes — whichever comes first. Unlike a hard timeout, an
/// incomplete deadline is NOT an error: the caller inspects `out` to form the
/// live subset L1 and decides rerun-vs-abort. A peer-network read error still
/// propagates (the transport already maps unverifiable payloads to `Ok(None)`).
#[allow(clippy::too_many_arguments)]
async fn poll_dkg_round1(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    ns: DkgNamespace,
    me: Identifier,
    peer_infos: &[&SpoInfo],
    deadline: Instant,
    out: &mut BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
) -> EpochResult<()> {
    let need = peer_infos.len() + out.len(); // out already holds self
    loop {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(pkg) = peers.fetch_dkg_round1(ns, peer).await? {
                crate::epoch_log!(
                    me,
                    ns.epoch,
                    "     received round1 package from spo={} ({}/{})",
                    id_short(peer.identifier),
                    out.len() + 1,
                    need
                );
                out.insert(peer.identifier, pkg);
            }
        }
        if out.len() >= need || clock.now() >= deadline {
            break;
        }
        tokio::time::sleep(config.poll_interval).await;
    }
    // Anti-equivocation sweep: re-fetch every peer (even those already collected)
    // so a peer that served a DIFFERENT payload after we first fetched it is
    // caught — `fetch_dkg_round1` calls `retain_evidence`, which records the
    // conflict that `report_round1_equivocations` then turns into a fault.
    //
    // Swept REPEATEDLY over a short grace window rather than once: an equivocator
    // chooses when to serve its second payload, so a single pass only catches the
    // one interleaving where the conflict happens to already be in place. Collection
    // can finish in well under a poll interval (every package arrives on the first
    // tick), which is exactly when a one-shot sweep runs too early to see anything.
    // The grace is bounded and, on the anchored path, absorbed by the Round-2
    // offset the nodes are waiting for anyway.
    for pass in 0..EQUIVOCATION_SWEEP_PASSES {
        if pass > 0 {
            tokio::time::sleep(config.poll_interval).await;
        }
        for peer in peer_infos {
            let _ = peers.fetch_dkg_round1(ns, peer).await;
        }
    }
    Ok(())
}

/// Poll peers' Round 2 shares addressed to us until all arrive or the deadline
/// passes. Same contract as [`poll_dkg_round1`]: an incomplete deadline returns
/// the partial set (→ qualified subset Q), not an error.
#[allow(clippy::too_many_arguments)]
async fn poll_dkg_round2(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    ns: DkgNamespace,
    me: Identifier,
    peer_infos: &[&SpoInfo],
    deadline: Instant,
    round1_packages: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
    out: &mut BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
) -> EpochResult<()> {
    let need = peer_infos.len();
    loop {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            let Some(sender_round1) = round1_packages.get(&peer.identifier) else {
                continue;
            };
            let (sender_commitments, _sigma_i) = frost_bridge::round1_fields(sender_round1)
                .map_err(|e| EpochError::Frost(format!("round1 fields: {e}")))?;
            if let Some(pkg) = peers
                .fetch_dkg_round2(ns, peer, me, &sender_commitments)
                .await?
            {
                crate::epoch_log!(
                    me,
                    ns.epoch,
                    "     received round2 share from spo={} ({}/{})",
                    id_short(peer.identifier),
                    out.len() + 1,
                    need
                );
                out.insert(peer.identifier, pkg);
            }
        }
        if out.len() >= need || clock.now() >= deadline {
            break;
        }
        tokio::time::sleep(config.poll_interval).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::fault_evidence::{EquivocationEvidence, NamespacePhase};
    use crate::epoch::mocks::{
        MockCardanoChain, MockPeerHub, MockPeerNetwork, OsRngSource, SystemClock,
    };
    use crate::epoch::state::{EpochConfig, Roster, SpoIdentity, SpoInfo};
    use crate::http::canonical::THRESHOLD_51;
    use std::time::Duration;

    fn make_roster(n: u16, threshold: u16) -> Roster {
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
            min_signers: threshold,
            max_signers: n,
            participants,
        }
    }

    async fn drive_dkg(
        chain: Arc<dyn CardanoChain>,
        peers: Arc<dyn PeerNetwork>,
        clock: Arc<dyn Clock>,
        config: EpochConfig,
        roster: Roster,
    ) -> EpochResult<GroupKeys> {
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        let ctx = DkgContext::from_roster_equal_stake(&roster, 0, 0);
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
                } => {
                    dkg_phase(&chain, &peers, &clock, &rng, &config, round, ctx, collected).await?
                }
                EpochPhase::PublishKeys { group_keys, .. } => return Ok(group_keys),
                other => panic!("unexpected phase: {}", other.name()),
            };
        }
    }

    /// Spawn `ids` SPOs against a shared hub and drive each through DKG.
    async fn run_ceremony(roster: Roster, ids: &[u16]) -> Vec<EpochResult<GroupKeys>> {
        let hub = MockPeerHub::new();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut handles = Vec::new();
        for &i in ids {
            let id = Identifier::try_from(i).unwrap();
            let chain: Arc<dyn CardanoChain> = Arc::new(MockCardanoChain::demo(
                roster.min_signers,
                roster.max_signers,
                0,
            ));
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock = clock.clone();
            let mut config = EpochConfig::demo_default(SpoIdentity {
                identifier: id,
                port: 0,
            });
            // Tight timing so the absent-peer reruns don't make the test slow.
            config.dkg_round_timeout = Duration::from_millis(250);
            config.poll_interval = Duration::from_millis(10);
            let roster = roster.clone();
            handles.push(tokio::spawn(async move {
                drive_dkg(chain, peers, clock, config, roster).await
            }));
        }
        let mut out = Vec::new();
        for h in handles {
            out.push(h.await.unwrap());
        }
        out
    }

    fn assert_same_group_key(results: &[EpochResult<GroupKeys>]) {
        let keys: Vec<_> = results
            .iter()
            .map(|r| r.as_ref().expect("dkg ok").verifying_key)
            .collect();
        for gk in &keys[1..] {
            assert_eq!(*gk, keys[0], "all SPOs must derive the same Y_51");
        }
    }

    fn dummy_equivocation(epoch: u64, accused_pool_id: [u8; 28]) -> DkgFaultEvidence {
        DkgFaultEvidence::Equivocation(EquivocationEvidence {
            epoch,
            threshold: THRESHOLD_51,
            attempt: 0,
            phase: NamespacePhase::Round1,
            accused_pool_id,
            bifrost_id_pk: [0x42; 32],
            payload_a: b"payload-a".to_vec(),
            signature_a: [0xA1; 64],
            payload_b: b"payload-b".to_vec(),
            signature_b: [0xB2; 64],
        })
    }

    #[tokio::test]
    async fn dkg_3_of_3_happy_path() {
        let results = run_ceremony(make_roster(3, 2), &[1, 2, 3]).await;
        assert_same_group_key(&results);
    }

    /// The smallest ceremony frost-core supports (it rejects min_signers < 2),
    /// i.e. the "solo" replacement: two instances complete and agree on Y_51.
    #[tokio::test]
    async fn dkg_2_of_2_happy_path() {
        let results = run_ceremony(make_roster(2, 2), &[1, 2]).await;
        assert_same_group_key(&results);
    }

    /// A 3-candidate ceremony where one peer never shows up. The two survivors
    /// both observe L1 = {1,2}, which clears the quorum gate (2/3 stake > 51%),
    /// so they rerun as a reduced 2-of-2 (attempt 1) and complete with the same
    /// Y_51 — exercising the poll-to-subset → gate → reduced-rerun path.
    #[tokio::test]
    async fn dkg_absent_peer_reduces_and_reruns() {
        let results = run_ceremony(make_roster(3, 2), &[1, 2]).await; // SPO 3 never spawns
        assert_same_group_key(&results);
    }

    #[tokio::test]
    async fn incomplete_round_reports_retained_fault_evidence() {
        let me = Identifier::try_from(1u16).unwrap();
        let accused = Identifier::try_from(2u16).unwrap();
        let mut roster = make_roster(3, 2);
        for (i, participant) in roster.participants.values_mut().enumerate() {
            participant.pool_id = vec![0xC0 + i as u8; 28];
        }
        let accused_pool: [u8; 28] = roster
            .participants
            .get(&accused)
            .unwrap()
            .pool_id
            .as_slice()
            .try_into()
            .unwrap();
        let ctx = DkgContext::from_roster_equal_stake(&roster, 0, 0);
        let hub = MockPeerHub::new();
        hub.push_round1_fault_evidence(
            DkgNamespace::for_attempt(0, 0),
            accused,
            dummy_equivocation(0, accused_pool),
        );
        let mock_chain = Arc::new(MockCardanoChain::demo(2, 3, 0));
        let recorded = mock_chain.dkg_faults();
        let chain: Arc<dyn CardanoChain> = mock_chain;
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        let mut config = EpochConfig::demo_default(SpoIdentity {
            identifier: me,
            port: 0,
        });
        config.dkg_round_timeout = Duration::from_millis(20);
        config.poll_interval = Duration::from_millis(5);

        let result = dkg_phase(
            &chain,
            &peers,
            &clock,
            &rng,
            &config,
            DkgRound::Round1,
            ctx,
            DkgCollected::default(),
        )
        .await;

        assert!(
            matches!(result, Err(EpochError::DkgAborted { .. })),
            "the one-survivor ceremony should still abort after reporting evidence"
        );
        let faults = recorded.lock().unwrap();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].kind_label(), "equivocation");
        assert_eq!(faults[0].accused_pool_id(), &accused_pool);
    }

    /// A "smart" equivocator publishes a usable Round-1 package (so it lands in L1
    /// and is NOT excluded) yet still equivocated. `report_round1_equivocations`
    /// must catch it — this is the path the `--inject-fault=equivocate-round1`
    /// demo exercises (the injected node stays in the ceremony but serves a second
    /// conflicting package that an honest peer's confirmatory re-fetch retains).
    #[tokio::test]
    async fn collected_peer_equivocation_is_reported() {
        let me = Identifier::try_from(1u16).unwrap();
        let accused = Identifier::try_from(2u16).unwrap();
        let mut roster = make_roster(3, 2);
        for (i, participant) in roster.participants.values_mut().enumerate() {
            participant.pool_id = vec![0xC0 + i as u8; 28];
        }
        let accused_pool: [u8; 28] = roster
            .participants
            .get(&accused)
            .unwrap()
            .pool_id
            .as_slice()
            .try_into()
            .unwrap();
        let ctx = DkgContext::from_roster_equal_stake(&roster, 0, 0);
        let ns = DkgNamespace::for_attempt(0, 0);
        let hub = MockPeerHub::new();
        hub.push_round1_fault_evidence(ns, accused, dummy_equivocation(0, accused_pool));
        let mock_chain = Arc::new(MockCardanoChain::demo(2, 3, 0));
        let recorded = mock_chain.dkg_faults();
        let chain: Arc<dyn CardanoChain> = mock_chain;
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub));

        // Accused is in the collected set L1 — it DID publish a usable package.
        let l1: BTreeSet<Identifier> = [me, accused].into_iter().collect();
        report_round1_equivocations(&chain, &peers, ns, me, &ctx, &l1)
            .await
            .expect("reporting equivocations should not error");

        let faults = recorded.lock().unwrap();
        assert_eq!(
            faults.len(),
            1,
            "the collected equivocator must be reported"
        );
        assert_eq!(faults[0].kind_label(), "equivocation");
        assert_eq!(faults[0].accused_pool_id(), &accused_pool);
    }

    /// The finalize coherence check accepts a real part3 output (group keys
    /// agree, this node's verification share is published) and rejects an
    /// output whose published share belongs to a different participant.
    #[test]
    fn dkg_output_coherence_accepts_real_rejects_wrong_share() {
        use crate::frost::participant;
        let id1 = Identifier::try_from(1u16).unwrap();
        let id2 = Identifier::try_from(2u16).unwrap();
        let mut rng = rand::thread_rng();
        let (s1, p1) = participant::dkg_part1(id1, 2, 2, &mut rng).unwrap();
        let (s2, p2) = participant::dkg_part1(id2, 2, 2, &mut rng).unwrap();

        // Each participant's "others" Round 1 set is the single other peer.
        let r1_seen_by_1: BTreeMap<_, _> = [(id2, p2)].into_iter().collect();
        let r1_seen_by_2: BTreeMap<_, _> = [(id1, p1)].into_iter().collect();
        let (s1r2, _) = participant::dkg_part2(s1, &r1_seen_by_1).unwrap();
        let (_, pkgs2) = participant::dkg_part2(s2, &r1_seen_by_2).unwrap();
        // The share participant 2 addressed to participant 1.
        let r2_seen_by_1: BTreeMap<_, _> = [(id2, pkgs2.get(&id1).unwrap().clone())]
            .into_iter()
            .collect();
        let (kp1, pkp1) = participant::dkg_part3(&s1r2, &r1_seen_by_1, &r2_seen_by_1).unwrap();

        // Real part3 output for participant 1 → coherent. (The group package is
        // shared, so it also coheres with participant 2's own KeyPackage under
        // id2 — verification shares are public and identical across nodes.)
        check_dkg_output_coherent(id1, &kp1, &pkp1).expect("real part3 output is coherent");

        // Claiming to be id2 while presenting id1's KeyPackage: the share the
        // package publishes for id2 is not id1's signing share → rejected.
        let err = check_dkg_output_coherent(id2, &kp1, &pkp1)
            .expect_err("share bound to the wrong participant must be rejected");
        assert!(matches!(err, EpochError::Frost(_)));
    }

    /// Schedule-anchored deadlines are absolute: the remaining wait is
    /// `boundary + offset − now`, saturating at zero once past — so a node that
    /// enters the round late gets a shorter window and every node freezes at the
    /// same chain-time instant.
    #[test]
    fn remaining_to_offset_anchors_to_the_boundary() {
        let boundary = 1_000_000i64;
        // 30s into the round, round-1 offset 120s → 90s left.
        assert_eq!(
            remaining_to_offset(boundary, Duration::from_secs(120), boundary + 30_000),
            Duration::from_secs(90)
        );
        // exactly at the deadline → zero.
        assert_eq!(
            remaining_to_offset(boundary, Duration::from_secs(120), boundary + 120_000),
            Duration::ZERO
        );
        // already past the deadline → zero, never negative.
        assert_eq!(
            remaining_to_offset(boundary, Duration::from_secs(120), boundary + 500_000),
            Duration::ZERO
        );
        // a node that starts before the boundary waits the full offset + lead.
        assert_eq!(
            remaining_to_offset(boundary, Duration::from_secs(120), boundary - 10_000),
            Duration::from_secs(130)
        );
    }

    /// Exclusion evidence records exactly the eligible participants missing from
    /// the survivor set, tagged with epoch/attempt/round, so DKG can ask the
    /// peer transport whether any of them produced provable fault evidence.
    #[test]
    fn exclusion_evidence_records_the_missing_participants() {
        let roster = make_roster(3, 2);
        let mut ctx = DkgContext::from_roster_equal_stake(&roster, 42, 1);
        // give participants distinct pool_ids so the evidence carries them
        for (i, p) in ctx.participants.iter_mut().enumerate() {
            p.pool_id = vec![0xC0 + i as u8; 28];
        }
        let survivors: BTreeSet<_> = [Identifier::try_from(1u16).unwrap()]
            .into_iter()
            .chain(std::iter::once(Identifier::try_from(3u16).unwrap()))
            .collect();
        let ev = DkgExclusionEvidence::from_round(&ctx, DkgRound::Round2, &survivors);
        assert_eq!(ev.epoch, 42);
        assert_eq!(ev.attempt, 1);
        assert_eq!(ev.round, DkgRound::Round2);
        // only participant 2 is missing
        assert_eq!(ev.excluded.len(), 1);
        assert_eq!(ev.excluded[0].0, Identifier::try_from(2u16).unwrap());
        assert_eq!(ev.excluded[0].1, vec![0xC1; 28]);
        // a full survivor set yields no evidence
        let all: BTreeSet<_> = ctx.participants.iter().map(|p| p.identifier).collect();
        assert!(
            DkgExclusionEvidence::from_round(&ctx, DkgRound::Round1, &all)
                .excluded
                .is_empty()
        );
    }

    /// A solo SPO in a 3-candidate set: only itself publishes Round 1, the
    /// survivor subset {self} fails the count gate (1 < t=2), so the attempt
    /// aborts fatally rather than hanging or completing under-quorum.
    #[tokio::test]
    async fn dkg_round1_incomplete_aborts_below_quorum() {
        let results = run_ceremony(make_roster(3, 2), &[1]).await;
        match &results[0] {
            Err(EpochError::DkgAborted {
                qualified,
                eligible,
                ..
            }) => {
                assert_eq!(*qualified, 1);
                assert_eq!(*eligible, 3);
            }
            other => panic!(
                "expected DkgAborted, got {:?}",
                other.as_ref().map(|_| "ok")
            ),
        }
    }
}
