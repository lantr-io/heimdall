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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use frost::Identifier;
use frost_secp256k1_tr as frost;

use crate::epoch::log::id_short;
use crate::epoch::state::{
    CascadeLevel, EpochConfig, EpochError, EpochKeys, EpochPhase, EpochResult, GroupKeys, Roster,
    SignCollected, SigningRound, TreasuryMovement,
};
use crate::epoch::traits::{Clock, PeerNetwork, RngSource};
use crate::frost::participant;
use crate::http::wire::SignNamespace;

/// Mark every failure from the first published commitment onward as
/// [`EpochError::RoundSpent`], so the epoch loop rejoins its peers at the next
/// synchronized entry instead of walking a round they have already left.
///
/// Apply it to EVERY fallible step after a commitment has actually reached the
/// store — the marker is about what this node has already told its peers, not
/// about what went wrong. It is idempotent, so wrapping an already-marked error
/// is safe.
///
/// It keeps the underlying error INTACT — `EpochError::cause()` unwraps it — so
/// `matches!(e.cause(), EpochError::PollTimeout { .. })` still works on the
/// signing path. It used to flatten it to a string, which disabled every such
/// match silently.
pub(crate) fn spent(round: u8) -> impl Fn(EpochError) -> EpochError {
    move |e| match e {
        already @ EpochError::RoundSpent { .. } => already,
        other => EpochError::RoundSpent {
            round,
            cause: Box::new(other),
        },
    }
}

/// Drive one sub-round of the signing phase for all TM inputs.
///
/// A Round-2 shortfall does not end the movement: it opens the next attempt over
/// the survivors, with fresh commitments in a fresh namespace. See
/// [`open_next_attempt`] for why that is the only safe answer and why the
/// exclusion is shaped the way it is.
///
/// It does not fall through to a FEDERATION mode, and there is nothing here to
/// add one to: per the spec the federation mode "does not use the SPO HTTP
/// endpoints" and "has no signing namespace at all" — it is an out-of-band spend
/// of the CSV leaf under `Y_federation`, posted permissionlessly like any other
/// movement, which heimdall then observes as an ordinary TM. See
/// [`CascadeLevel`], which records the same thing where the type would otherwise
/// invite a second variant.
///
/// TODO: misbehavior detection. FROST errors here currently surface as
/// `EpochError::Frost(String)` with the identity lost. The identifiable
/// abort property means we can attribute a bad share to a specific
/// `Identifier`. The on-chain fault-proof flow is currently implemented for
/// DKG faults; signing-share fault proofs are still not wired up.
// Every argument is a distinct thing the round is bound to — the roster it polls,
// the movement it signs, the round it is on, the window it closes at — and
// bundling them into a struct would only move the list, since each still has to
// be threaded here from the phase that fixed it.
#[allow(clippy::too_many_arguments)]
pub async fn sign_phase(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    epoch: u64,
    // The roster that holds the key the treasury head is locked under, chosen by
    // `build_tm_phase` — see `EpochKeys`. Not necessarily this epoch's own.
    roster: Roster,
    cascade: CascadeLevel,
    group_keys: GroupKeys,
    // Ferried, not used: this epoch's ceremony output, on its way back to
    // `CollectPegins` for the next batch.
    epoch_keys: EpochKeys,
    mut tm: TreasuryMovement,
    round: SigningRound,
    mut collected: SignCollected,
    // Which go at this opportunity this is, and who this movement will not ask
    // again — see `EpochPhase::Sign::attempt` / `::excluded` (WI-EJSVJ).
    attempt: u64,
    excluded: BTreeSet<Identifier>,
    // Carried through to `Submit`, which elects the submission cascade with it.
    tm_sequence: u64,
    // When each round closes, from the chain schedule (WI-077). Read ONCE here
    // and passed to every input, which is what stops the per-input deadlines
    // compounding down a multi-input movement.
    window: crate::epoch::state::SigningWindow,
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

            // A later attempt asks fewer members, so check the threshold is still
            // reachable BEFORE publishing a commitment. Waiting out the window
            // instead would reach the same verdict, but it spends the round to get
            // there: the nonces are published and this node then cannot join the
            // next opportunity's first attempt cleanly. The threshold itself never
            // moves across attempts — excluding a member changes who may sign,
            // never how many must (spec §Failure handling).
            let eligible = roster.participants.len().saturating_sub(excluded.len());
            if eligible < roster.min_signers as usize {
                crate::epoch_warn!(
                    me,
                    epoch,
                    "Sign attempt {attempt}: {eligible} of {} members remain after excluding {} \
                     round-2 non-publisher(s), below the {} required — the 51% mode is over for \
                     this movement.",
                    roster.participants.len(),
                    excluded.len(),
                    roster.min_signers,
                );
                return Err(EpochError::PollTimeout {
                    got: eligible,
                    need: roster.min_signers as usize,
                });
            }

            crate::epoch_log!(
                me,
                epoch,
                "Sign round1 (attempt {attempt}): generating nonce commitments for {} input(s)",
                num_inputs
            );
            // Generate and publish this SPO's nonce commitments for every input.
            let mut published_any = false;
            for i in 0..num_inputs as u32 {
                // Never `rng.rng(..)`: see `RngSource::signing_nonce_rng`. Under
                // `--deterministic` that context is constant for the epoch, so a
                // re-entered round would reuse this nonce under a different
                // signing set and leak the share.
                let mut sign_rng = rng.signing_nonce_rng();
                let (nonces, commitments) =
                    participant::sign_round1(&group_keys.key_package, &mut sign_rng);
                collected.nonces.insert(i, nonces);
                collected
                    .round1
                    .entry(i)
                    .or_default()
                    .insert(me, commitments);

                // The publish itself is only SPENT once an earlier one succeeded.
                // It can fail before anything reaches the store (canonical-bytes
                // build, serialization), and on input 0 that means no peer saw
                // anything — a plain retry at the same opportunity is then correct
                // and free, where marking it spent would skip the whole batch
                // opportunity (and, on the rotation path, park for the epoch).
                let mark = |e| if published_any { spent(1)(e) } else { e };
                peers
                    .publish_sign_round1(
                        input_namespace(epoch, tm_sequence, attempt, &tm, i),
                        me,
                        commitments,
                    )
                    .await
                    .map_err(mark)?;
                published_any = true;
                crate::epoch_debug!(me, epoch, "  -> published commitments for input {i}");
            }

            // Poll peers for round 1 commitments on every input — every peer the
            // roster has, less the ones an earlier attempt at THIS movement
            // watched commit and then withhold (WI-EJSVJ). A member that was
            // merely silent is not in `excluded` and is asked again.
            let peer_infos: Vec<&crate::epoch::state::SpoInfo> = roster
                .peers_of(me)
                .into_iter()
                .filter(|p| !excluded.contains(&p.identifier))
                .collect();
            // No member is required (WI-104). Posting is permissionless, so any
            // node holding the aggregate can post it and an absent member costs a
            // cascade hop, not the round. This used to require the leader,
            // because `submit_phase` broadcast from one hardcoded node and a
            // subset without it signed a movement nobody would post.
            //
            // Which peers missed which inputs. Each input is its own FROST
            // session with its own deadline, so a peer can be in S1 for one and
            // absent for another; the COUNT is what separates one slow answer
            // from a member that has stopped answering at all.
            let mut absent_signers: BTreeMap<Identifier, u32> = BTreeMap::new();
            for i in 0..num_inputs as u32 {
                crate::epoch_log!(
                    me,
                    epoch,
                    "  waiting for round1 commitments on input {i} from {} peer(s)...",
                    peer_infos.len()
                );
                let ns = input_namespace(epoch, tm_sequence, attempt, &tm, i);
                let map = collected.round1.entry(i).or_default();
                // S1 for this input: whoever published by the deadline, at least
                // `min_signers` of them.
                let absent = poll_sign_round(
                    peers,
                    clock,
                    config,
                    ns,
                    me,
                    Quorum::of(&peer_infos, roster.min_signers),
                    window.close_of(SigningRound::Round1, attempt),
                    map,
                )
                .await
                .map_err(spent(1))?;
                for id in absent {
                    *absent_signers.entry(id).or_insert(0u32) += 1;
                }
            }
            // Say what actually happened. This used to log "have all round1
            // commitments" unconditionally, which would now hide the member that
            // never answers from anyone reading the logs — and the absentees are
            // exactly what the cascade and the misbehaviour path need.
            if absent_signers.is_empty() {
                crate::epoch_log!(
                    me,
                    epoch,
                    "  <- have all round1 commitments, advancing to round2"
                );
            } else {
                // Logged and NOT carried into `excluded`, deliberately. Round 1
                // closes on the threshold, so an absence here costs the round
                // nothing, and the spec is explicit that it is not evidence of
                // anything: a member down at one attempt may be back at the next,
                // which is what the retry is for.
                //
                // It does mean a later attempt polls the silent member again and
                // waits out the full round-1 deadline instead of returning early —
                // and that is the design, not an oversight to optimise away. The
                // deadline is what FIXES `S1`; returning early is only safe when
                // everyone polled has answered, because "everyone" is the one
                // subset two nodes cannot disagree about. Dropping last attempt's
                // absentees from the poll is exclusion under another name, and it
                // breaks in the case it is meant to help: a member that recovers by
                // attempt 1 publishes into a namespace nobody reads, believes it is
                // in `S1`, and aggregates against a package no one else built.
                let mut listed: Vec<String> = absent_signers
                    .iter()
                    .map(|(id, missed)| format!("{} ({missed}/{num_inputs})", id_short(*id)))
                    .collect();
                listed.sort();
                crate::epoch_warn!(
                    me,
                    epoch,
                    "  <- round1 closed on a threshold subset: {} peer(s) missed inputs [{}]; \
                     advancing to round2",
                    absent_signers.len(),
                    listed.join(", ")
                );
            }

            Ok(EpochPhase::Sign {
                epoch,
                roster,
                tm_sequence,
                window,
                cascade,
                group_keys,
                epoch_keys,
                tm,
                round: SigningRound::Round2,
                collected,
                attempt,
                excluded,
            })
        }

        SigningRound::Round2 => {
            crate::epoch_log!(
                me,
                epoch,
                "Sign round2 (attempt {attempt}): computing tweaked signature shares for {} \
                 input(s)",
                num_inputs
            );
            // For each input: build SigningPackage, compute this SPO's
            // tweaked share, publish, poll peers, then aggregate into a
            // final Schnorr signature written back to `tm.signatures`.
            //
            // ROUND 1 IS ALREADY PUBLISHED by the time this arm runs, so every
            // failure below is SPENT — see `spent`. The loop is wrapped once
            // rather than each `?` tagged individually, so a fallible step added
            // later inherits the marker instead of quietly escaping it.
            // `Ok(Some(..))` is a ROUND-2 SHORTFALL: those members of `S1`
            // committed and then published no share by the deadline, so this
            // attempt cannot be aggregated — see `open_next_attempt`. It is not an
            // error at this level because the answer to it is a new attempt, not a
            // failure, and only the caller below knows whether one is left. The
            // timeout rides along so that the case with no attempt left still
            // fails with the counts the round actually saw.
            let signed: EpochResult<Option<(BTreeSet<Identifier>, EpochError)>> = async {
                for i in 0..num_inputs as u32 {
                    let commitments = collected
                        .round1
                        .get(&(i))
                        .ok_or_else(|| {
                            EpochError::Transition(format!(
                                "missing round1 commitments for input {i}"
                            ))
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

                    let ns = input_namespace(epoch, tm_sequence, attempt, &tm, i);
                    peers.publish_sign_round2(ns, me, share).await?;
                    crate::epoch_debug!(me, epoch, "    -> published share for input {i}");

                    // Poll EXACTLY the round-1 subset, and require all of it. The
                    // signing package above was built from those commitments and
                    // `aggregate` needs a share from every signer in the package, so
                    // a smaller S2 does not aggregate — it fails. Round 2 therefore
                    // carries no threshold of its own: the threshold was applied when
                    // S1 closed. (It used to poll the whole roster, including peers
                    // whose commitments are not in the package.)
                    let s1: Vec<&crate::epoch::state::SpoInfo> = roster
                        .peers_of(me)
                        .into_iter()
                        .filter(|p| {
                            signing_package
                                .signing_commitments()
                                .contains_key(&p.identifier)
                        })
                        .collect();
                    crate::epoch_log!(
                        me,
                        epoch,
                        "    waiting for round2 shares on input {i} from {} signer(s) of S1...",
                        s1.len()
                    );
                    let shares = collected.round2.entry(i).or_default();
                    let polled = poll_sign_round(
                        peers,
                        clock,
                        config,
                        ns,
                        me,
                        Quorum::all(&s1),
                        window.close_of(SigningRound::Round2, attempt),
                        shares,
                    )
                    .await;
                    if let Err(e) = polled {
                        // Only a closed deadline names a shortfall. Anything else
                        // is a genuine failure of this round and stays one.
                        if !matches!(e.cause(), EpochError::PollTimeout { .. }) {
                            return Err(e);
                        }
                        let missing: BTreeSet<Identifier> = s1
                            .iter()
                            .map(|p| p.identifier)
                            .filter(|id| !shares.contains_key(id))
                            .collect();
                        return Ok(Some((missing, e)));
                    }

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
                Ok(None)
            }
            .await;

            if let Some((missing, timeout)) = signed.map_err(spent(2))? {
                return open_next_attempt(
                    me,
                    epoch,
                    roster,
                    tm_sequence,
                    window,
                    cascade,
                    group_keys,
                    epoch_keys,
                    tm,
                    attempt,
                    excluded,
                    missing,
                    timeout,
                );
            }

            Ok(EpochPhase::Submit {
                epoch,
                roster,
                group_keys,
                epoch_keys,
                tm,
                tm_sequence,
            })
        }
    }
}

/// Answer a Round-2 shortfall: re-enter Round 1 at `attempt + 1` without the
/// members that committed and then withheld (WI-EJSVJ, spec §Round-2 shortfall
/// opens a new attempt).
///
/// ## Why a new attempt, and not aggregation over the survivors
///
/// The `SigningPackage` IS `S1`'s list of Round-1 commitments: the binding
/// factors, the group commitment `R` and the challenge are all hashes over that
/// list, and every share was computed against it. Dropping a member of `S1` from
/// the sum leaves a value that does not verify against `R` — a partial `S1` is not
/// a weaker signature, it is not a signature. Making it verify would mean asking
/// the survivors to recompute their shares against a package over the smaller set,
/// on the SAME nonce pair they already published. Two responses on one nonce
/// reveal the share, so that trades a stalled movement for the treasury key. The
/// only safe answer is fresh commitments, which need their own namespace.
///
/// ## Why the excluded set is what it is
///
/// It grows monotonically, so the eligible set strictly shrinks and this cannot
/// loop: each defector costs one attempt, once. It holds only members that reached
/// `S1` and then went quiet — a member that published nothing in Round 1 was never
/// in the package, cost the round nothing, and is asked again. And it dies with the
/// movement: this is not a ban, it mints no `FaultProof`, and the next opportunity
/// starts from the full roster.
///
/// Every honest node derives the same set from the same published payloads at the
/// same chain-anchored deadline, which is what lets them build one package. Two
/// nodes that briefly disagree — one fetched a share a moment before the deadline,
/// one did not — cost liveness, not safety: both attempts sign the same unsigned
/// transaction against the same head, and at most one movement per head can ever
/// confirm.
///
/// This needs no malice to fire. A member that CRASHES between the two deadlines
/// looks exactly like one that withholds, which on a large roster makes it the
/// expected case rather than the adversarial one.
#[allow(clippy::too_many_arguments)]
fn open_next_attempt(
    me: Identifier,
    epoch: u64,
    roster: Roster,
    tm_sequence: u64,
    window: crate::epoch::state::SigningWindow,
    cascade: CascadeLevel,
    group_keys: GroupKeys,
    epoch_keys: EpochKeys,
    tm: TreasuryMovement,
    attempt: u64,
    mut excluded: BTreeSet<Identifier>,
    missing: BTreeSet<Identifier>,
    // The round's own timeout, kept so an exhausted budget fails with the counts
    // the poll actually closed on rather than with numbers made up here.
    timeout: EpochError,
) -> EpochResult<EpochPhase> {
    let named = |set: &BTreeSet<Identifier>| {
        set.iter()
            .map(|id| id_short(*id).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let next = attempt + 1;
    // Out of room before the posting margin runs out. The movement is not signed
    // and the round is spent, so the way back in is the next opportunity — where
    // the full roster is asked again, because the exclusions were this movement's.
    if next >= window.max_attempts() {
        crate::epoch_warn!(
            me,
            epoch,
            "Sign round2 (attempt {attempt}): no round-2 share from [{}] and the opportunity has \
             room for {} attempt(s) — this movement is not signed. The next batch opportunity \
             starts again from the full roster.",
            named(&missing),
            window.max_attempts(),
        );
        return Err(spent(2)(timeout));
    }
    excluded.extend(missing.iter().copied());
    let eligible = roster.participants.len().saturating_sub(excluded.len());
    crate::epoch_warn!(
        me,
        epoch,
        "Sign round2 (attempt {attempt}): no round-2 share from [{}] after they committed in \
         round 1 — this attempt cannot aggregate (the package is S1's commitments, and a partial \
         sum does not verify). Opening attempt {next} over the remaining {eligible} member(s) \
         with fresh commitments.",
        named(&missing),
    );
    Ok(EpochPhase::Sign {
        epoch,
        roster,
        tm_sequence,
        window,
        cascade,
        group_keys,
        epoch_keys,
        tm,
        round: SigningRound::Round1,
        // Everything from the abandoned attempt goes, nonces included: the new
        // attempt is a new namespace, so its commitments must be new too. Keeping
        // a nonce across the two is the exact hazard this path exists to avoid.
        //
        // Every input is re-signed, including any that already aggregated before
        // the shortfall — and that is required, not merely simple. Which inputs a
        // node finished is a function of how far it got through a SERIAL loop
        // before the shared deadline, not of anything published, so two nodes
        // routinely differ: skipping "the ones I already have" would have them
        // publish round-1 commitments for different input ranges and build
        // different `S1`s for the overlap. It is also rarely costly — the inputs
        // share one round-2 deadline, so a member absent on every input stalls at
        // input 0 and nothing downstream ever ran.
        collected: SignCollected::default(),
        attempt: next,
        excluded,
    })
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

/// The signing domain for TM input `i`: the epoch, the input index, and the
/// input's own BIP-341 sighash. Two TMs in one epoch share `(epoch, i)` but
/// never the sighash, which is what stops a commitment captured from one from
/// replaying into the other.
/// The namespace one input's FROST session publishes under.
///
/// `tm_sequence` — the batch grid index this movement was built at — is part of
/// it, and that is what separates two OPPORTUNITIES at the same movement. A
/// rebuild at the next opportunity is byte-identical when the chain has not moved,
/// so `(epoch, session, sighash)` repeats exactly; the sequence does not, and
/// every SPO derives it from the same grid rather than from its own retry count
/// (WI-W8ZC4).
///
/// `attempt` separates two goes WITHIN one opportunity, where even the sequence
/// repeats — see [`open_next_attempt`].
fn input_namespace(
    epoch: u64,
    tm_sequence: u64,
    attempt: u64,
    tm: &TreasuryMovement,
    i: u32,
) -> SignNamespace {
    SignNamespace::new(epoch, tm_sequence, attempt, i, tm.sighashes[i as usize])
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

/// Who a signing round polls, and how many of them it needs.
///
/// The two travel together because they are one decision — "this set, at least
/// this many of it" — and splitting them is how a call site ends up polling one
/// set while thresholding against another. Round 2 is the case that makes it
/// worth a type: it must poll EXACTLY the round-1 subset and needs all of it, and
/// [`Quorum::all`] says that where a bare `s1.len() + 1` made the reader derive
/// it.
pub(crate) struct Quorum<'a> {
    peers: &'a [&'a crate::epoch::state::SpoInfo],
    /// Answers required INCLUDING this node's own, which is already in `out`.
    ///
    /// A threshold and nothing else. There used to be a second field naming a
    /// member the subset was worthless without — the node elected to post —
    /// which was a bound on heimdall's own submit gate rather than a protocol
    /// rule, and stricter than the protocol: posting is permissionless, so one
    /// absent member costs a cascade hop and never the round (WI-104).
    min: usize,
}

impl<'a> Quorum<'a> {
    /// `t` of the roster, self included — the round-1 rule.
    pub(crate) fn of(peers: &'a [&'a crate::epoch::state::SpoInfo], min_signers: u16) -> Self {
        Self {
            peers,
            min: min_signers as usize,
        }
    }

    /// Everyone in the set. Round 2 has no threshold of its own: `aggregate`
    /// needs a share from every signer in the package, so a smaller S2 does not
    /// aggregate, it fails. The threshold was applied when S1 closed.
    pub(crate) fn all(peers: &'a [&'a crate::epoch::state::SpoInfo]) -> Self {
        Self {
            peers,
            min: peers.len() + 1,
        }
    }
}

/// Poll every peer for one signing round of `ns` until all have answered, or
/// until the deadline — at which point `min` answers are enough to proceed, and
/// the absentees are returned. Shared by the TM inputs and the Update-Y rotation
/// ceremony ([`crate::epoch::rotation`]): one session is one session, and the
/// threshold rule must only ever be written once.
///
/// ## Why a deadline, and NOT "stop as soon as `min` have answered" (WI-047)
///
/// Because FROST needs every signer to build the BYTE-IDENTICAL
/// `SigningPackage`. The package IS the set of round-1 commitments, and the
/// binding factors are a hash over it. A node that stopped at `{1,2}` and one
/// that stopped at `{1,3}` compute different binding factors, so their shares do
/// not aggregate — the round fails, having looked healthy on both nodes. Stopping
/// early is precisely how you get that.
///
/// So the subset is fixed by a DEADLINE rather than by whoever answered first —
/// spec §"all honest SPOs derive the same signing state": wait until the round-1
/// deadline, let `S1` be whoever published before it, continue with EXACTLY
/// `S1`, and fail if `S1` is under threshold. This function is that rule; callers
/// pass the `min` that `S1` must clear, then pass exactly the members of `S1`
/// back in for round 2.
///
/// ## The deadline is the caller's, and it comes from the chain (WI-077)
///
/// `deadline` is an absolute moment derived from the batch opportunity and the
/// Config's `sign_r1_window` / `sign_r2_window` — see [`SigningWindow`]. This
/// function must NOT invent one, and in particular must not fall back to a local
/// timeout: the deadline decides MEMBERSHIP of `S1`, so a value each node picks
/// for itself is a value two nodes disagree about, and disagreement here is
/// shares that never aggregate rather than an error anyone can see.
///
/// It used to compute `clock.deadline(config.quorum51_timeout)` itself, from a
/// per-operator TOML key, started when this node entered the round — wrong on
/// both counts, and wrong once per input because `sign_phase` calls this in a
/// serial loop.
///
/// The early return on a FULL set is safe, and is the common case: "everyone" is
/// unambiguous, so no two nodes can disagree about it.
///
/// Results are filed under the ROSTER's identifier for each peer, never one a
/// payload claimed for itself: the transport has already verified the payload
/// was signed by that peer under exactly that identifier.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn poll_sign_round<T: SignRoundPayload>(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    ns: SignNamespace,
    me: Identifier,
    quorum: Quorum<'_>,
    // The absolute moment this round closes. Chain-derived and shared; never a
    // local timeout. See the note above.
    deadline: std::time::Instant,
    out: &mut BTreeMap<Identifier, T>,
) -> EpochResult<Vec<Identifier>> {
    let Quorum {
        peers: peer_infos,
        min,
    } = quorum;
    // Everyone = every peer plus self. NOT `out.len()`: `out` is resume state
    // (`collected.round1.entry(i).or_default()`), so a round retried after a
    // restart arrives with peers already in it, and counting them twice puts
    // `need` above the reachable maximum — the loop below can then never satisfy
    // `out.len() < need` and the round always ends in `PollTimeout`, however many
    // peers answered.
    let need = peer_infos.len() + 1;
    // A poll interval that does not fit inside the round's window means the
    // round is sampled ONCE: whoever published before this node's first fetch is
    // in `S1`, and whoever is a moment behind is not. That is not a timeout an
    // operator can read off a log — it looks exactly like peers who did not
    // answer, and it turns a healthy roster into a coin flip under load. It is
    // reachable in production whenever a bridge publishes a short window or an
    // operator raises `[protocol].poll_interval_ms`, so it is worth saying
    // rather than leaving to be re-diagnosed (WI-112).
    let window = deadline.saturating_duration_since(clock.now());
    if !window.is_zero() && window < config.poll_interval {
        crate::epoch_warn!(
            me,
            ns.epoch,
            "     round{} for {} has a {}ms window but polls every {}ms — it will be sampled \
             ONCE, so a peer that answers a moment late is excluded and the round fails as \
             though it were absent. Lower [protocol].poll_interval_ms, or the bridge's \
             sign_r{}_window is too short to co-sign under.",
            T::ROUND,
            ns.session_label(),
            window.as_millis(),
            config.poll_interval.as_millis(),
            T::ROUND,
        );
    }
    let mut unreachable = crate::epoch::log::Unreachable::default();
    loop {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            // A per-peer fetch failure is THIS PEER HAS NOT PUBLISHED, never a
            // failure of the round (WI-098). `fetch_raw` already maps a refused
            // connection and a 404 to `Ok(None)`; a 502 from a reverse proxy, a
            // 500 from a peer mid-restart and a truncated body arrive here as
            // `Err` instead, and propagating them aborted the round before any
            // deadline or threshold code ran — exactly the case the threshold
            // poll exists to survive.
            //
            // It is also the sharper divergence: node A getting a 404 from peer C
            // closes S1 without it while node B getting a 503 from the same C at
            // the same instant unwinds into backoff. Different S1, no aggregation,
            // and unlike the WI-077 race it needs no timing skew at all. The spec's
            // rule is one bucket — unreachable, unparseable and silent are all
            // "not published before the deadline" (§Failure handling).
            //
            // Scoped to the round on purpose: a fetch error in the DKG or a chain
            // read still means what it means.
            match T::fetch(peers, ns, peer).await {
                Ok(Some(value)) => {
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
                    unreachable.answered(peer.identifier);
                }
                // A clean 404 IS an answer: the peer is reachable and simply has
                // not published yet. Clearing here as well as on success is what
                // makes the deadline log's "up but erroring" list mean it — a peer
                // that 503s while restarting and then serves 404s for the rest of
                // the round has recovered, and naming it as unreachable is the
                // false positive that teaches operators to ignore the line.
                Ok(None) => unreachable.answered(peer.identifier),
                Err(e) => {
                    // Once per peer per round, not once per poll: at a 10 ms
                    // interval against a 30-minute window the second form is tens
                    // of thousands of identical lines.
                    if unreachable.record(peer.identifier, &e) {
                        crate::epoch_warn!(
                            me,
                            ns.epoch,
                            "     round{} for {}: spo={} is UNREACHABLE ({e}) — counting it \
                             absent for this round and continuing. A peer that answers with an \
                             error is not the same fault as one that stays silent; it is up and \
                             unhealthy",
                            T::ROUND,
                            ns.session_label(),
                            id_short(peer.identifier),
                        );
                    }
                }
            }
        }
        // Everyone answered, so the set is unambiguous and no deadline is needed
        // to agree on it.
        if out.len() >= need {
            return Ok(Vec::new());
        }
        if clock.now() >= deadline {
            // Who was merely silent, and who answered with an error. The absentee
            // list treats them alike — the spec requires that, or two nodes would
            // close different subsets — but the OPERATOR needs them apart: silence
            // is a peer that is down or not participating, an error is a peer that
            // is up and broken, and only the second is worth paging about. WI-103
            // carries this distinction out of the round as data; here it reaches
            // the log, which is where it is needed when a round has just failed.
            // The deadline is what FIXES the subset. Below the threshold the
            // round is simply unavailable; at or above it, proceed with exactly
            // who answered and name who did not.
            if out.len() < min {
                // Say WHY before failing. Since a fetch error no longer aborts the
                // round, an all-peers-erroring outage would otherwise surface as a
                // bare "got 1, need 2" with nothing pointing at the cause.
                crate::epoch_warn!(
                    me,
                    ns.epoch,
                    "     round{} for {} closed at the deadline with {}/{}, below the {min} \
                     required — the round is unavailable.{}",
                    T::ROUND,
                    ns.session_label(),
                    out.len(),
                    need,
                    unreachable.note(),
                );
                return Err(EpochError::PollTimeout {
                    got: out.len(),
                    need: min,
                });
            }
            let absent: Vec<Identifier> = peer_infos
                .iter()
                .map(|p| p.identifier)
                .filter(|id| !out.contains_key(id))
                .collect();
            crate::epoch_warn!(
                me,
                ns.epoch,
                "     round{} for {} closed at the deadline with {}/{} — proceeding on the \
                 threshold ({min} required). Absent: {}.{}",
                T::ROUND,
                ns.session_label(),
                out.len(),
                need,
                absent
                    .iter()
                    .map(|id| id_short(*id).to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                unreachable.note(),
            );
            return Ok(absent);
        }
        // Never sleep PAST the deadline. The deadline is what fixes `S1`, so
        // overshooting it means the round closes late on a set nobody else
        // closed at that moment — and with a window shorter than the poll
        // interval the loop would wake, find the deadline long gone, and close
        // on whoever had answered before its single fetch. That is what made
        // `integration_demo` hang under load (WI-112): not a timeout anyone
        // could read, but a subset decided by scheduling luck.
        let until_deadline = deadline.saturating_duration_since(clock.now());
        tokio::time::sleep(config.poll_interval.min(until_deadline)).await;
    }
}

#[cfg(test)]
mod tests {
    /// A signing window closing `ms` from now. Production windows are absolute
    /// slots off the chain schedule (WI-077); a unit test has no chain to read
    /// one from, and only needs the round to end.
    fn test_window(ms: u64) -> crate::epoch::state::SigningWindow {
        let now = std::time::Instant::now();
        crate::epoch::state::SigningWindow::at(
            now + std::time::Duration::from_millis(ms),
            // Strictly after round 1, as a real window is — see the twin helper
            // in `rotation`.
            now + std::time::Duration::from_millis(2 * ms),
        )
    }

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

    /// The assertion this test used to make, INVERTED by WI-104.
    ///
    /// It required the elected leader to be present or the round failed — a
    /// bound on heimdall's own submit gate, never a protocol rule, and one the
    /// spec contradicts: posting is permissionless, so every node holding the
    /// aggregate can post it. Requiring one named member made a single dark node
    /// cost the round, and after WI-048 made such a failure `RoundSpent` it cost
    /// the whole batch opportunity, every opportunity, since the elected node
    /// never changed.
    ///
    /// A threshold subset is now a threshold subset whoever is missing, and the
    /// absentee is reported so the cascade and the misbehaviour path can see it.
    #[tokio::test]
    async fn a_threshold_subset_signs_whoever_is_missing() {
        let hub = MockPeerHub::new();
        let me = Identifier::try_from(2u16).unwrap();
        let leader = Identifier::try_from(1u16).unwrap();
        let roster = make_roster(3, 2);
        let mut config = EpochConfig::demo_default(SpoIdentity {
            identifier: me,
            bifrost_id_pk: Vec::new(),
            port: 0,
        });
        config.poll_interval = std::time::Duration::from_millis(5);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let ns = SignNamespace::new(7, 1, 0, 0, [0xa1u8; 32]);

        // SPO 3 publishes; the leader (SPO 1) never does. That is a threshold
        // subset {2,3} of a 2-of-3 roster — enough signers, wrong ones.
        let three = Identifier::try_from(3u16).unwrap();
        let peers3: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(three, hub.clone()));
        let (_n3, c3) =
            crate::frost::participant::sign_round1(&dealt_package(three), &mut rand::thread_rng());
        peers3.publish_sign_round1(ns, three, c3).await.unwrap();

        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub.clone()));
        let peer_infos = roster.peers_of(me);
        let mut out: BTreeMap<Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
        let (_n2, c2) =
            crate::frost::participant::sign_round1(&dealt_package(me), &mut rand::thread_rng());
        out.insert(me, c2);

        let absent = poll_sign_round(
            &peers,
            &clock,
            &config,
            ns,
            me,
            Quorum::of(&peer_infos, roster.min_signers),
            test_window(200).round1_close,
            &mut out,
        )
        .await
        .expect("a threshold subset proceeds even without the node elected to post");
        assert_eq!(
            absent,
            vec![leader],
            "the absentee is reported, not turned into a failure"
        );
        assert!(
            out.contains_key(&three) && out.contains_key(&me),
            "S1 is the subset that answered: {out:?}"
        );
    }

    /// A key package for `id` from a throwaway 3-of-3 dealt keyset — enough to
    /// produce well-formed round-1 commitments, which is all the poll inspects.
    fn dealt_package(id: Identifier) -> frost::keys::KeyPackage {
        use frost::keys::{IdentifierList, KeyPackage, generate_with_dealer};
        let (shares, _pk) =
            generate_with_dealer(3, 3, IdentifierList::Default, rand::thread_rng()).unwrap();
        let secret = shares.get(&id).expect("dealt for this identifier").clone();
        KeyPackage::try_from(secret).unwrap()
    }

    /// A FROST signing nonce may be used once. `--deterministic` derives its
    /// stream from `hash(seed || context)` with a context that is constant within
    /// an epoch, and since WI-047 a phase can be re-entered inside that epoch — so
    /// a reproducible nonce would be signed twice under different signing sets,
    /// and the signing share recovered from the pair.
    #[test]
    fn signing_nonces_are_never_reproducible_even_under_deterministic() {
        use crate::epoch::mocks::SeededRngSource;
        use rand_core::RngCore;

        let seeded = SeededRngSource::new(*b"heimdall-demo-seed-v1-0123456789");
        // The context-keyed stream IS reproducible — that is what --deterministic
        // is for, and the DKG relies on it.
        let mut a = seeded.rng(b"dkg1");
        let mut b = seeded.rng(b"dkg1");
        assert_eq!(a.next_u64(), b.next_u64(), "the DKG stream stays seeded");

        // Signing nonces must not be.
        let mut n1 = seeded.signing_nonce_rng();
        let mut n2 = seeded.signing_nonce_rng();
        assert_ne!(
            n1.next_u64(),
            n2.next_u64(),
            "a reproducible signing nonce leaks the share when a retry signs under a different S1"
        );
    }

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
    /// WI-112: a round whose window is shorter than the poll interval is sampled
    /// ONCE, which is a coin flip rather than a threshold rule — and it says so.
    ///
    /// This is what made `integration_demo` hang under load: the demo inherited a
    /// 5-second production poll interval while the mock reported a 1-second
    /// window, so `S1` was whoever happened to have published by the first fetch.
    /// The warning exists because the symptom is indistinguishable from peers
    /// simply not answering, which is what sent me looking at the wrong thing.
    #[tokio::test]
    async fn a_window_shorter_than_the_poll_interval_closes_at_the_deadline() {
        let hub = MockPeerHub::new();
        let roster = make_roster(2, 2);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let me = Identifier::try_from(1u16).unwrap();
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub));
        let peer_infos = roster.peers_of(me);
        let mut out: BTreeMap<Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
        let (_n, c) =
            crate::frost::participant::sign_round1(&dealt_package(me), &mut rand::thread_rng());
        out.insert(me, c);

        let mut config = EpochConfig::demo_default(SpoIdentity {
            identifier: me,
            bifrost_id_pk: Vec::new(),
            port: 0,
        });
        // A 5-second poll against a 100ms window — the demo's exact shape.
        config.poll_interval = std::time::Duration::from_secs(5);
        let started = std::time::Instant::now();
        let err = poll_sign_round(
            &peers,
            &clock,
            &config,
            SignNamespace::new(7, 1, 0, 0, [0xd4u8; 32]),
            me,
            Quorum::of(&peer_infos, roster.min_signers),
            std::time::Instant::now() + std::time::Duration::from_millis(100),
            &mut out,
        )
        .await
        .expect_err("one answer is below a 2-of-2 threshold");
        assert!(matches!(err, EpochError::PollTimeout { .. }), "{err:?}");
        // It closes AT the deadline rather than sleeping to the next poll — which
        // is what makes a short window fail fast instead of hanging, and is the
        // half of this an operator can act on once the warning names it.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "the round closed at its deadline, not at the next poll"
        );
    }

    /// The plumbing test: `sign_phase` closes round 1 at the window it was HANDED,
    /// not at a deadline of its own.
    ///
    /// The window is already past and one member of a 2-of-2 roster never
    /// publishes, so the round must fail immediately. A `sign_phase` that computed
    /// its own timeout would instead sit through it — which is precisely the
    /// regression WI-077 removes, and the only part of the change that a unit test
    /// of `SigningWindow` alone cannot see.
    #[tokio::test]
    async fn sign_phase_honours_the_window_it_is_given() {
        let (roster, group_keys_all, tm, hub) = dkg_and_movement(2, 2).await;
        let me_keys = group_keys_all.into_iter().next().expect("two nodes");
        let me = *me_keys.key_package.identifier();
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        let config = EpochConfig::demo_default(SpoIdentity {
            identifier: me,
            bifrost_id_pk: Vec::new(),
            port: 0,
        });

        let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
        let expired = crate::epoch::state::SigningWindow::at(past, past);
        let started = std::time::Instant::now();
        let err = sign_phase(
            &peers,
            &clock,
            &rng,
            &config,
            0,
            roster.clone(),
            CascadeLevel::Quorum51,
            me_keys.clone(),
            EpochKeys {
                roster,
                group_keys: me_keys,
            },
            tm,
            SigningRound::Round1,
            SignCollected::default(),
            0,
            BTreeSet::new(),
            0,
            expired,
        )
        .await
        .expect_err("a closed window leaves this node alone, below a 2-of-2 threshold");
        assert!(
            matches!(err.cause(), EpochError::PollTimeout { got: 1, need: 2 }),
            "got {err:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the round must close on the window it was given, not run its own timer"
        );
    }

    /// WI-W8ZC4(b). A burned attempt leaves this node's round-1 commitments
    /// published, and the movement rebuilt at the next opportunity is
    /// BYTE-IDENTICAL when nothing on chain has changed — same head, same Config
    /// fee rate, same output — so `(epoch, session, sighash)` repeats exactly.
    /// The sequence is what keeps the two attempts apart.
    ///
    /// The second node is started late on purpose. That is not a timing hack, it
    /// is the shape of the live failure (preprod 2026-08-19): a node publishes,
    /// then polls peers that have not republished yet, and takes their PREVIOUS
    /// attempt's commitments — which verify, being correctly signed for a
    /// namespace that, without the sequence, is this one. Its package then
    /// differs from theirs and the shares cannot aggregate. With the sequence in
    /// the namespace the stale blobs are unreachable, so the poll simply waits
    /// for the real ones.
    #[tokio::test]
    async fn a_burned_attempt_does_not_poison_the_next_one() {
        let (roster, group_keys_all, tm, hub) = dkg_and_movement(2, 2).await;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

        let cfg_for = |id| {
            EpochConfig::demo_default(SpoIdentity {
                identifier: id,
                bifrost_id_pk: Vec::new(),
                port: 0,
            })
        };

        // Attempt at B_1: the window is already shut, so each node publishes its
        // round-1 commitments and then fails alone — the session is spent, and
        // the commitments outlive it.
        let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
        let expired = crate::epoch::state::SigningWindow::at(past, past);
        for gk in &group_keys_all {
            let id = *gk.key_package.identifier();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let outcome = sign_phase(
                &peers,
                &clock,
                &rng,
                &cfg_for(id),
                0,
                roster.clone(),
                CascadeLevel::Quorum51,
                gk.clone(),
                EpochKeys {
                    roster: roster.clone(),
                    group_keys: gk.clone(),
                },
                tm.clone(),
                SigningRound::Round1,
                SignCollected::default(),
                0,
                BTreeSet::new(),
                1,
                expired,
            )
            .await;
            assert!(
                !matches!(outcome, Ok(EpochPhase::Submit { .. })),
                "a shut window cannot carry a movement to Submit"
            );
        }

        // The precondition, asserted rather than assumed: both nodes' round-1
        // commitments from that attempt are still SERVED under B_1's namespace.
        // They go out before the poll, so a round that fails still leaves them —
        // and the nonces behind them are gone with the attempt.
        let observer: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(
            roster.participants.keys().copied().next().unwrap(),
            hub.clone(),
        ));
        for peer in roster.participants.values() {
            assert!(
                observer
                    .fetch_sign_round1(SignNamespace::new(0, 1, 0, 0, tm.sighashes[0]), peer)
                    .await
                    .unwrap()
                    .is_some(),
                "the burned attempt must leave commitments behind — otherwise this test proves \
                 nothing about reading them"
            );
        }

        // ...and that the next attempt cannot reach them. This is the mechanism
        // under test, stated where it can be read: same epoch, same session,
        // same message — only the sequence differs, and it is enough.
        for peer in roster.participants.values() {
            assert!(
                observer
                    .fetch_sign_round1(SignNamespace::new(0, 2, 0, 0, tm.sighashes[0]), peer)
                    .await
                    .unwrap()
                    .is_none(),
                "a commitment published for B_1 must not be readable as B_2's"
            );
        }

        // Attempt at B_2: the same movement, byte for byte.
        let mut handles = Vec::new();
        for (n, gk) in group_keys_all.into_iter().enumerate() {
            let id = *gk.key_package.identifier();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock = clock.clone();
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let config = cfg_for(id);
            let roster = roster.clone();
            let tm = tm.clone();
            handles.push(tokio::spawn(async move {
                // Stagger, so the first node polls a peer that is still serving
                // only the burned attempt's payloads.
                tokio::time::sleep(std::time::Duration::from_millis(50 * n as u64)).await;
                let mut phase = EpochPhase::Sign {
                    epoch: 0,
                    tm_sequence: 2,
                    window: test_window(60_000),
                    roster: roster.clone(),
                    cascade: CascadeLevel::Quorum51,
                    group_keys: gk.clone(),
                    epoch_keys: EpochKeys {
                        roster,
                        group_keys: gk,
                    },
                    tm,
                    round: SigningRound::Round1,
                    collected: SignCollected::default(),
                    attempt: 0,
                    excluded: BTreeSet::new(),
                };
                loop {
                    phase = match phase {
                        EpochPhase::Sign {
                            epoch,
                            roster,
                            cascade,
                            tm_sequence,
                            window,
                            group_keys,
                            epoch_keys,
                            tm,
                            round,
                            collected,
                            attempt,
                            excluded,
                        } => sign_phase(
                            &peers,
                            &clock,
                            &rng,
                            &config,
                            epoch,
                            roster,
                            cascade,
                            group_keys,
                            epoch_keys,
                            tm,
                            round,
                            collected,
                            attempt,
                            excluded,
                            tm_sequence,
                            window,
                        )
                        .await
                        .expect("the second attempt must not read the first's commitments"),
                        EpochPhase::Submit { tm, .. } => return tm,
                        other => panic!("unexpected: {}", other.name()),
                    };
                }
            }));
        }

        let mut signed = Vec::new();
        for h in handles {
            signed.push(h.await.expect("no panic"));
        }
        let secp = Secp256k1::new();
        for (i, sig) in signed[0].signatures.iter().enumerate() {
            let sig = sig.as_ref().expect("every input is signed");
            assert_eq!(
                sig.serialize().unwrap(),
                signed[1].signatures[i]
                    .as_ref()
                    .expect("every input is signed")
                    .serialize()
                    .unwrap(),
                "both nodes must aggregate the same signature for input {i}"
            );
            let xonly = signed[0].input_spend_info[i]
                .output_key()
                .to_x_only_public_key();
            secp.verify_schnorr(
                &bitcoin::secp256k1::schnorr::Signature::from_slice(&sig.serialize().unwrap())
                    .unwrap(),
                &bitcoin::secp256k1::Message::from_digest(signed[0].sighashes[i]),
                &xonly,
            )
            .expect("the retry's signature verifies under the input's output key");
        }
    }

    /// A finished DKG plus a two-input movement built against its group key —
    /// everything `sign_phase` needs, and the same setup for every test that
    /// drives it.
    ///
    /// Extracted so the happy path and the window tests share one fixture: they
    /// must exercise the SAME movement, or "the round closed differently" could
    /// be a difference in what was being signed.
    async fn dkg_and_movement(
        n: u16,
        t: u16,
    ) -> (Roster, Vec<GroupKeys>, TreasuryMovement, Arc<MockPeerHub>) {
        let secp = Secp256k1::new();

        // DKG so all SPOs share one group key.
        let hub = MockPeerHub::new();
        let roster = make_roster(n, t);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut dkg_handles = Vec::new();
        for i in 1..=n {
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
            &crate::bitcoin::tm_builder::Freshness::inert(),
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
        (roster, group_keys_all, tm_template, hub)
    }

    /// WI-077 wiring: `sign_phase` closes round 1 at the WINDOW it was given, not
    /// at a timer of its own.
    ///
    /// The window here is already past, so the round must close at once on whoever
    /// has answered — nobody — and fail below threshold. If `sign_phase` invented
    /// its own deadline instead, this would sit waiting it out; the assertion is
    /// therefore that it finishes quickly as well as that it fails, and the gap
    /// between "immediately" and any plausible invented timeout is large.
    ///
    /// A closed window is the real case a late node meets. Extending it would be
    /// the whole defect back: this node would hold a different `S1` open than its
    /// peers already closed.
    #[tokio::test]
    async fn an_expired_window_closes_round_one_at_once_instead_of_waiting() {
        let hub = MockPeerHub::new();
        let roster = make_roster(2, 2);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let me = Identifier::try_from(1u16).unwrap();
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub.clone()));
        let peer_infos = roster.peers_of(me);
        let mut out: BTreeMap<Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
        let (_n, c) =
            crate::frost::participant::sign_round1(&dealt_package(me), &mut rand::thread_rng());
        out.insert(me, c);

        // A window whose round-1 close is in the PAST.
        let expired = std::time::Instant::now() - std::time::Duration::from_secs(1);
        let config = EpochConfig::demo_default(SpoIdentity {
            identifier: me,
            bifrost_id_pk: Vec::new(),
            port: 0,
        });
        let started = std::time::Instant::now();
        let err = poll_sign_round(
            &peers,
            &clock,
            &config,
            SignNamespace::new(7, 1, 0, 0, [0xc3u8; 32]),
            me,
            Quorum::of(&peer_infos, roster.min_signers),
            expired,
            &mut out,
        )
        .await
        .expect_err("a closed window with one answer is below a 2-of-2 threshold");
        assert!(
            matches!(err, EpochError::PollTimeout { got: 1, need: 2 }),
            "got {err:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a past deadline must close the round at once, not run a timer of its own"
        );
    }

    /// A window with room for `max_attempts` goes, laid off `now`.
    ///
    /// Round 1 gets a second and round 2 a fraction of one, which is lopsided for a
    /// production schedule and right for this: `poll_sign_round` returns as soon as
    /// everyone has answered, so the only deadline a test actually WAITS OUT is the
    /// one with a member missing behind it — round 2's. Round 1 is given room to
    /// spare so three nodes doing FROST arithmetic on one runtime cannot miss it and
    /// turn a retry test into a scheduling test.
    ///
    /// Both are only reachable alongside [`fast_poll`]: at the default 5-second poll
    /// interval a 1-second window is SAMPLED ONCE (WI-112) and the round closes on
    /// whoever happened to answer before the first fetch.
    fn retryable_window(max_attempts: u64) -> crate::epoch::state::SigningWindow {
        let now = std::time::Instant::now();
        let r1 = std::time::Duration::from_secs(1);
        let r2 = r1 + std::time::Duration::from_millis(300);
        crate::epoch::state::SigningWindow::at(now + r1, now + r2).with_attempts(r2, max_attempts)
    }

    /// A demo config that polls fast enough for [`retryable_window`]'s deadlines.
    ///
    /// `demo_default` polls every 5 seconds, which is a production cadence against
    /// production windows. Left at that, each retry test spends its whole run
    /// asleep between fetches — the three of them cost ~48 s of pure waiting — and
    /// worse, round 2's window falls below one poll interval, so the round is
    /// decided by scheduling luck rather than by the deadline. Every other
    /// multi-node test in this module lowers it for the same reason.
    fn fast_poll(id: Identifier) -> EpochConfig {
        let mut config = EpochConfig::demo_default(SpoIdentity {
            identifier: id,
            bifrost_id_pk: Vec::new(),
            port: 0,
        });
        config.poll_interval = std::time::Duration::from_millis(5);
        config
    }

    /// Drive one node's `Sign` phase to a terminal state, starting at attempt 0.
    ///
    /// Returns the movement if it reached `Submit`, and the highest attempt the
    /// node opened — which is the thing under test: an attempt that never opened
    /// is a retry that did not happen, and a `Submit` at attempt 0 would mean the
    /// shortfall was never noticed.
    async fn drive_sign(
        peers: Arc<dyn PeerNetwork>,
        config: EpochConfig,
        roster: Roster,
        gk: GroupKeys,
        tm: TreasuryMovement,
        window: crate::epoch::state::SigningWindow,
    ) -> (EpochResult<TreasuryMovement>, u64) {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        let mut highest = 0;
        let mut phase = EpochPhase::Sign {
            epoch: 0,
            tm_sequence: 1,
            window,
            roster: roster.clone(),
            cascade: CascadeLevel::Quorum51,
            group_keys: gk.clone(),
            epoch_keys: EpochKeys {
                roster,
                group_keys: gk,
            },
            tm,
            round: SigningRound::Round1,
            collected: SignCollected::default(),
            attempt: 0,
            excluded: BTreeSet::new(),
        };
        loop {
            phase = match phase {
                EpochPhase::Sign {
                    epoch,
                    roster,
                    cascade,
                    tm_sequence,
                    window,
                    group_keys,
                    epoch_keys,
                    tm,
                    round,
                    collected,
                    attempt,
                    excluded,
                } => {
                    highest = highest.max(attempt);
                    match sign_phase(
                        &peers,
                        &clock,
                        &rng,
                        &config,
                        epoch,
                        roster,
                        cascade,
                        group_keys,
                        epoch_keys,
                        tm,
                        round,
                        collected,
                        attempt,
                        excluded,
                        tm_sequence,
                        window,
                    )
                    .await
                    {
                        Ok(next) => next,
                        Err(e) => return (Err(e), highest),
                    }
                }
                EpochPhase::Submit { tm, .. } => return (Ok(tm), highest),
                other => panic!("unexpected: {}", other.name()),
            };
        }
    }

    /// The denial this exists to remove: one member of a 2-of-3 roster commits in
    /// Round 1 — which puts it in `S1`, and honest nodes have no way to keep a
    /// committer out — and then publishes no share.
    ///
    /// Before WI-EJSVJ that ended the movement: Round 2 needs every member of the
    /// package, `S1` is uncapped so it is the whole roster on a healthy one, and
    /// the round was spent so the batch opportunity was gone. Now the shortfall
    /// opens attempt 1 over the survivors with fresh commitments, and the two
    /// honest members sign.
    ///
    /// The withholder does not get the signature either, and on a multi-input
    /// movement that follows without any rule aimed at it: the honest members
    /// block on input 0 until the round-2 deadline, so they never publish input
    /// 1's share, and the withholder — which raced ahead on the share it computed
    /// but did not publish — then sees THEM as the shortfall. Its own exclusion
    /// set leaves it below threshold and it stops. Withholding costs the honest
    /// majority one attempt and costs the withholder the movement.
    #[tokio::test]
    async fn a_member_that_commits_then_withholds_is_excluded_and_the_movement_still_signs() {
        let (roster, group_keys_all, tm, hub) = dkg_and_movement(3, 2).await;
        let withholder = Identifier::try_from(3u16).unwrap();

        let mut handles = Vec::new();
        for gk in group_keys_all {
            let id = *gk.key_package.identifier();
            let base = MockPeerNetwork::new(id, hub.clone());
            let peers: Arc<dyn PeerNetwork> = Arc::new(if id == withholder {
                base.withholding_sign_round2()
            } else {
                base
            });
            let config = fast_poll(id);
            let roster = roster.clone();
            let tm = tm.clone();
            handles.push(tokio::spawn(async move {
                let w = retryable_window(3);
                (id, drive_sign(peers, config, roster, gk, tm, w).await)
            }));
        }

        let mut honest = 0;
        for h in handles {
            let (id, (outcome, highest)) = h.await.unwrap();
            if id == withholder {
                assert!(
                    outcome.is_err(),
                    "the withholder must not end up holding the signature it denied everyone else"
                );
                continue;
            }
            let signed = outcome.unwrap_or_else(|e| panic!("spo {id:?} failed: {e:?}"));
            assert!(
                signed.signatures.iter().all(Option::is_some),
                "spo {id:?} must reach a fully signed movement"
            );
            assert_eq!(
                highest, 1,
                "an honest member must notice the shortfall and open exactly one more attempt"
            );
            honest += 1;
        }
        assert_eq!(honest, 2, "both honest members must have signed");
    }

    /// The same failure with no malice in it: a member publishes Round 1 and then
    /// the process is gone. Its peers cannot tell this apart from withholding —
    /// both are "in the package, no share by the deadline" — which is why the
    /// answer has to be the same one, and why on a large roster this is the
    /// EXPECTED case rather than the adversarial one.
    ///
    /// Driven without the mock knob on purpose: the crashed node runs Round 1 and
    /// is then simply never stepped again, so nothing about the recovery depends
    /// on a test double behaving in a particular way.
    #[tokio::test]
    async fn a_member_that_crashes_between_the_rounds_costs_one_attempt_not_the_movement() {
        let (roster, group_keys_all, tm, hub) = dkg_and_movement(3, 2).await;
        let crashed = Identifier::try_from(3u16).unwrap();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

        let mut handles = Vec::new();
        for gk in group_keys_all {
            let id = *gk.key_package.identifier();
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let config = fast_poll(id);
            let roster = roster.clone();
            let tm = tm.clone();
            let clock = clock.clone();
            handles.push(tokio::spawn(async move {
                let w = retryable_window(3);
                if id == crashed {
                    // Round 1 only: commitments are published, and then this node
                    // never comes back.
                    let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
                    let _ = sign_phase(
                        &peers,
                        &clock,
                        &rng,
                        &config,
                        0,
                        roster.clone(),
                        CascadeLevel::Quorum51,
                        gk.clone(),
                        EpochKeys {
                            roster,
                            group_keys: gk,
                        },
                        tm,
                        SigningRound::Round1,
                        SignCollected::default(),
                        0,
                        BTreeSet::new(),
                        1,
                        w,
                    )
                    .await
                    .expect("round 1 publishes and closes on the threshold");
                    return (id, None);
                }
                let (outcome, highest) = drive_sign(peers, config, roster, gk, tm, w).await;
                (id, Some((outcome, highest)))
            }));
        }

        let mut survivors = 0;
        for h in handles {
            let (id, result) = h.await.unwrap();
            let Some((outcome, highest)) = result else {
                continue;
            };
            let signed = outcome.unwrap_or_else(|e| panic!("spo {id:?} failed: {e:?}"));
            assert!(signed.signatures.iter().all(Option::is_some));
            assert_eq!(
                highest, 1,
                "the crash costs exactly one attempt, not the movement"
            );
            survivors += 1;
        }
        assert_eq!(survivors, 2, "both honest members must have signed");
    }

    /// A schedule with room for one attempt is the pre-WI-EJSVJ behaviour, and it
    /// must stay reachable rather than being papered over: the movement is not
    /// signed, the error is marked SPENT so the epoch loop rejoins its peers at
    /// the next synchronized entry, and the exclusions die with the movement.
    ///
    /// This is why `max_sign_attempts` is worth an operator's attention — a
    /// `tm_batch_interval` too tight for two attempts reproduces exactly the
    /// single-defector denial the retry exists to remove.
    #[tokio::test]
    async fn one_attempt_of_budget_leaves_the_movement_unsigned() {
        let (roster, group_keys_all, tm, hub) = dkg_and_movement(3, 2).await;
        let withholder = Identifier::try_from(3u16).unwrap();

        let mut handles = Vec::new();
        for gk in group_keys_all {
            let id = *gk.key_package.identifier();
            let base = MockPeerNetwork::new(id, hub.clone());
            let peers: Arc<dyn PeerNetwork> = Arc::new(if id == withholder {
                base.withholding_sign_round2()
            } else {
                base
            });
            let config = fast_poll(id);
            let roster = roster.clone();
            let tm = tm.clone();
            handles.push(tokio::spawn(async move {
                let w = retryable_window(1);
                (id, drive_sign(peers, config, roster, gk, tm, w).await)
            }));
        }

        for h in handles {
            let (id, (outcome, highest)) = h.await.unwrap();
            if id == withholder {
                assert!(outcome.is_err(), "nobody gets a signature out of this");
                continue;
            }
            let err = outcome.expect_err("no budget for a second attempt");
            assert!(
                err.round_is_spent(),
                "round 1 was published, so the way back in is the next opportunity: {err:?}"
            );
            assert!(
                matches!(err.cause(), EpochError::PollTimeout { .. }),
                "the cause must survive the spent marker: {err:?}"
            );
            assert_eq!(highest, 0, "no second attempt may open without the budget");
        }
    }

    /// aggregated Schnorr signature must verify under the tweaked output
    /// key of its input.
    #[tokio::test]
    async fn sign_3_of_3_two_inputs_verifies_taproot() {
        let (roster, group_keys_all, tm_template, hub) = dkg_and_movement(3, 2).await;
        let num_inputs = tm_template.sighashes.len();
        let secp = Secp256k1::new();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

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
                    tm_sequence: 0,
                    window: test_window(60_000),
                    roster: roster.clone(),
                    cascade: CascadeLevel::Quorum51,
                    group_keys: gk.clone(),
                    epoch_keys: EpochKeys {
                        roster,
                        group_keys: gk,
                    },
                    tm,
                    round: SigningRound::Round1,
                    collected: SignCollected::default(),
                    attempt: 0,
                    excluded: BTreeSet::new(),
                };
                loop {
                    phase = match phase {
                        EpochPhase::Sign {
                            epoch,
                            roster,
                            cascade,
                            tm_sequence,
                            window,
                            group_keys,
                            epoch_keys,
                            tm,
                            round,
                            collected,
                            attempt,
                            excluded,
                        } => sign_phase(
                            &peers,
                            &clock,
                            &rng,
                            &config,
                            epoch,
                            roster,
                            cascade,
                            group_keys,
                            epoch_keys,
                            tm,
                            round,
                            collected,
                            attempt,
                            excluded,
                            tm_sequence,
                            window,
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
