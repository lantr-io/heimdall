//! Learning the INCOMING roster's group key from what that roster published
//! (WI-113).
//!
//! ## The problem this exists for
//!
//! In Phase 1 the treasury is locked under `Y_federation`, so the first Update-Y
//! — the one that hands custody to an SPO roster — can only be authorized by the
//! federation. But the federation and the SPO roster are DISJOINT populations:
//! a federation member need not be a Cardano SPO and is not in the registry, so
//! it does not take part in the epoch DKG and never learns `Y_51` the way a
//! participant does. Every other caller of
//! [`crate::epoch::rotation::authorize_update_y`] already holds the incoming key
//! because it helped produce it. This one does not, and asking it to sign a
//! rotation to a key it was simply *told* is precisely the hazard
//! `crate::epoch::rotation`'s module doc names: "a node that signs whatever
//! `sig_msg` it is handed hands the treasury to whoever asked".
//!
//! ## So it recomputes the key instead of being told it
//!
//! A FROST DKG's group key is the sum of the participants' constant-term
//! commitments, `Y = Σᵢ φ_{i,0}` — and those commitments are exactly what round 1
//! publishes. The roster is on chain (registry, Config #9/#10) and carries each
//! member's `bifrost_url`, so the whole input is discoverable without anyone
//! being asked anything:
//!
//! 1. read the eligible roster from the registry, ban-filtered;
//! 2. fetch each member's round-1 payload from the URL IT REGISTERED;
//! 3. [`crate::http::wire::verify_round1`] it — BIP-340 under that member's
//!    REGISTERED `bifrost_id_pk`, plus the proof of knowledge, bound to
//!    `(epoch, threshold, attempt, pool_id)`;
//! 4. sum the verified `φ_{i,0}`.
//!
//! Every step is a check against something the chain already says. Nothing here
//! trusts a node's claim about what key it derived, which is the property that
//! makes it safe for the federation to sign the result.
//!
//! ## What is checked, and the one thing that is not
//!
//! Round-1 commitments fix the group key BEFORE round 2 distributes any share,
//! so round 1 alone cannot tell a completed ceremony from one that collapsed the
//! moment after the key was determined — and handing the treasury to a key
//! nobody holds a share of strands it until the recovery leaf's CSV delay
//! expires. Two further conditions close most of that, both from facts already
//! published:
//!
//! - every roster member also served a SIGNED round-2 payload, so the ceremony
//!   is known to have run past the point where the key was fixed. Presence and
//!   authorship are all an outsider can check — the shares inside are encrypted
//!   to their recipients — but that is exactly the ordinary failure: a node that
//!   crashed, went unreachable, or quietly dropped out;
//! - no fault proof stands against the ceremony on chain. That covers the half
//!   an outsider cannot check for itself, because a bad share is provable by its
//!   VICTIM, who can decrypt it, and the proof lands on chain via the
//!   identifiable-abort path.
//!
//! What remains is liveness, and it is genuinely open: all three conditions can
//! hold and the roster still be dark by the time the rotation lands. This is
//! evidence about a ceremony that happened, not a statement about who is up now.
//! Closing it needs the incoming roster to prove possession — a signature under
//! `Y_51` over the rotation's own `sig_msg` — which is a protocol addition rather
//! than a local one, so it is raised as an open question in the spec instead of
//! invented here.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::PublicKey;
use frost::Identifier;
use frost::keys::dkg::round1;
use frost_secp256k1_tr as frost;

use crate::http::frost_bridge;

/// Why a set of published round-1 payloads could not be turned into a key that
/// is safe to hand the treasury to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessionError {
    /// Not every eligible roster member published. Named, so an operator chasing
    /// a stalled handoff learns WHICH node to look at rather than that
    /// "something" is missing.
    Incomplete { missing: Vec<String>, of: usize },
    /// Two members committed to polynomials of different degree, i.e. they ran
    /// different thresholds. Their shares cannot combine, so whatever key the
    /// sum produces belongs to no coherent ceremony.
    ThresholdMismatch { expected: usize, found: usize },
    /// A commitment vector was empty or its constant term was not a point.
    Malformed(String),
    /// A member published round 1 but no signed round 2, so the ceremony that
    /// determined this key is not known to have run to completion.
    Round2Incomplete { missing: Vec<String>, of: usize },
    /// A member's Round-2 payload is addressed to a different set of
    /// participants than the roster — the signature that a ceremony ran over a
    /// NARROWED subset, or over nobody at all.
    Round2Disagrees {
        pool_id: String,
        addressed: Vec<String>,
    },
    /// A Round-1 package arrived from somebody who is not in the roster. Its
    /// commitment would change the sum, so the key would belong to no ceremony
    /// the chain describes.
    Surplus { pool_id: String },
    /// Somebody PROVED a member misbehaved in this ceremony. The proof is on
    /// chain, so this is not an opinion about liveness — the roster that
    /// produced this key contains a member the bridge can already demonstrate
    /// cheated, and custody must not move to it.
    FaultProven { pool_ids: Vec<String> },
}

impl std::fmt::Display for SuccessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete { missing, of } => write!(
                f,
                "{} of {of} roster member(s) published no round-1 commitment: {}",
                missing.len(),
                missing.join(", ")
            ),
            Self::ThresholdMismatch { expected, found } => write!(
                f,
                "a member committed to {found} coefficients where the others committed to \
                 {expected} — they are not running the same threshold, so their shares cannot \
                 combine"
            ),
            Self::Malformed(m) => write!(f, "malformed round-1 commitment: {m}"),
            Self::Round2Incomplete { missing, of } => write!(
                f,
                "{} of {of} roster member(s) published round 1 but no signed round 2, so this \
                 ceremony is not known to have completed: {}",
                missing.len(),
                missing.join(", ")
            ),
            Self::Round2Disagrees { pool_id, addressed } => write!(
                f,
                "member {pool_id} addressed its round 2 to {{{}}}, which is not the rest of the \
                 roster — this ceremony ran over a different participant set than the registry \
                 describes, so the key the commitments sum to is not the key its survivors hold",
                addressed.join(", ")
            ),
            Self::Surplus { pool_id } => write!(
                f,
                "a round-1 package came from {pool_id}, which is not in the roster — including \
                 it would change the summed key to one no ceremony produced"
            ),
            Self::FaultProven { pool_ids } => write!(
                f,
                "a fault proof is published on chain against this ceremony ({}) — the roster \
                 that produced this key contains a proven cheat",
                pool_ids.join(", ")
            ),
        }
    }
}

/// The threshold a set of round-1 commitments was generated under.
///
/// A FROST participant commits to `t` coefficients, so the commitment vector's
/// length IS the ceremony's threshold. That makes it checkable against the
/// threshold the reader derives from the chain — see [`succession_key`].
fn committed_threshold(
    packages: &BTreeMap<Identifier, round1::Package>,
) -> Result<usize, SuccessionError> {
    let mut degree: Option<usize> = None;
    for pkg in packages.values() {
        let (commitment, _sigma_i) = frost_bridge::round1_fields(pkg)
            .map_err(|e| SuccessionError::Malformed(e.to_string()))?;
        match degree {
            None => degree = Some(commitment.len()),
            Some(expected) if expected != commitment.len() => {
                return Err(SuccessionError::ThresholdMismatch {
                    expected,
                    found: commitment.len(),
                });
            }
            Some(_) => {}
        }
    }
    degree.ok_or_else(|| SuccessionError::Malformed("no round-1 packages at all".into()))
}

/// `Y = Σᵢ φ_{i,0}` over the given participants' round-1 packages.
///
/// The caller must have VERIFIED each package first
/// ([`crate::http::wire::verify_round1`]); this function is arithmetic over
/// already-authenticated inputs and deliberately re-checks neither the signature
/// nor the proof of knowledge — a second, weaker copy of that check is how the
/// two drift apart.
pub fn group_key_from_round1(
    packages: &BTreeMap<Identifier, round1::Package>,
) -> Result<UntweakedPublicKey, SuccessionError> {
    if packages.is_empty() {
        return Err(SuccessionError::Malformed(
            "no round-1 packages at all".into(),
        ));
    }
    let mut degree: Option<usize> = None;
    let mut constants = Vec::with_capacity(packages.len());
    for pkg in packages.values() {
        let (commitment, _sigma_i) = frost_bridge::round1_fields(pkg)
            .map_err(|e| SuccessionError::Malformed(e.to_string()))?;
        match degree {
            None => degree = Some(commitment.len()),
            Some(expected) if expected != commitment.len() => {
                return Err(SuccessionError::ThresholdMismatch {
                    expected,
                    found: commitment.len(),
                });
            }
            Some(_) => {}
        }
        let first = commitment.first().ok_or_else(|| {
            SuccessionError::Malformed("a member published an empty commitment vector".into())
        })?;
        constants.push(
            PublicKey::from_slice(first)
                .map_err(|e| SuccessionError::Malformed(format!("constant term: {e}")))?,
        );
    }
    let refs: Vec<&PublicKey> = constants.iter().collect();
    let sum = PublicKey::combine_keys(&refs)
        .map_err(|e| SuccessionError::Malformed(format!("summing constant terms: {e}")))?;
    // `Σ φ_{i,0}` is NOT the group key on this ciphersuite. `frost-secp256k1-tr`
    // applies the BIP-341 key-path tweak (empty merkle root) inside the DKG, so
    // what `part3` hands back — and therefore what every node calls `Y_51` — is
    // `taptweak(Σ φ_{i,0})`. Summing alone yields a well-formed key that is
    // simply a different one, which is the silent-divergence shape this whole
    // module exists to avoid; `the_summed_commitments_are_the_key_the_ceremony_produced`
    // pins the equality against a real ceremony rather than against this comment.
    let (tweaked, _parity) = bitcoin::key::TapTweak::tap_tweak(
        bitcoin::key::UntweakedPublicKey::from(sum.x_only_public_key().0),
        &bitcoin::secp256k1::Secp256k1::new(),
        None,
    );
    Ok(tweaked.to_x_only_public_key())
}

/// Everything the reliability rule is decided from, gathered by the caller.
///
/// A plain struct of already-fetched facts, deliberately: the chain reads and
/// the HTTP fetches belong to the caller, so the RULE stays pure and can be
/// tested without either. That split is why the awkward cases below are cheap to
/// pin.
pub struct SuccessionEvidence<'a> {
    /// The eligible roster at this epoch — registry, ban-filtered.
    pub roster: &'a crate::epoch::state::Roster,
    /// Round-1 packages already VERIFIED with [`crate::http::wire::verify_round1`].
    pub round1: &'a BTreeMap<Identifier, round1::Package>,
    /// For each member whose signed round-2 payload verified, the set of
    /// `pool_id`s that payload is ADDRESSED to.
    ///
    /// Not a presence flag: the recipient list is public, so it is the
    /// participant set the sender believed it was running with, and comparing
    /// those sets across members is what detects a ceremony that finished over
    /// a narrowed subset. The shares themselves are encrypted per recipient, so
    /// no third party can check they are CORRECT — that is what the fault proofs
    /// in [`Self::faulted`] cover.
    pub round2: &'a BTreeMap<Identifier, BTreeSet<Vec<u8>>>,
    /// Pool ids with a fault proof published on chain against this ceremony.
    pub faulted: &'a [Vec<u8>],
}

/// The reliability rule: what must hold before the federation hands the treasury
/// to a key it did not help produce.
///
/// Three conditions, each answering a different way the handoff goes wrong:
///
/// 1. **Every** roster member published round 1 — so the key is determined.
///    Completeness, not a threshold: `Y` is the sum over ALL participants, so a
///    missing member does not give a weaker answer, it gives a DIFFERENT key.
///    A partial set computes the group key of a ceremony that never happened.
/// 2. Every roster member published a signed round 2 — so the ceremony is known
///    to have run past the point where the key was fixed. Round-1 commitments
///    determine `Y` before any share is distributed, so round 1 alone cannot
///    distinguish a completed ceremony from one that collapsed immediately
///    after it, and the treasury would move to a key nobody holds a share of.
/// 3. No fault proof stands against it. A bad share is provable by its victim
///    and lands on chain, which is exactly the part no outside observer can
///    check for itself — the shares are encrypted to their recipients.
///
/// **Condition 3 is weaker than it reads, and the caller decides how much.**
/// What is checked is the `faulted` set the caller supplies. The natural source
/// — the eligible roster's ban list — is already applied upstream when the
/// roster is derived, so passing that makes this a no-op rather than a check;
/// and a fault proven DURING this epoch's ceremony does not become an active ban
/// until a later boundary, so it would not appear there anyway. Closing that
/// needs the fault-proof UTxOs read directly for this epoch, which is a chain
/// query this module deliberately does not make. Until a caller supplies that,
/// treat conditions 1 and 2 as the ones doing the work.
///
/// **What remains open, deliberately.** All three can hold and the roster still
/// be dark by the time the rotation lands: this is evidence about a ceremony
/// that happened, not about liveness now. Only a proof of possession — a
/// signature under `Y_51` over the rotation's own `sig_msg` — closes that, and
/// it is a protocol addition rather than a local one, so it is raised as an open
/// question in the spec instead of invented here.
pub fn succession_key(
    evidence: &SuccessionEvidence<'_>,
) -> Result<UntweakedPublicKey, SuccessionError> {
    let of = evidence.roster.participants.len();
    let pool_of = |id: &Identifier| -> Vec<u8> { evidence.roster.participants[id].pool_id.clone() };

    // Nothing may contribute a commitment that the roster does not name. The
    // completeness check below walks the ROSTER, so on its own it would let a
    // surplus package through — and a surplus phi_0 changes the sum, producing a
    // well-formed key for a ceremony that never happened.
    for id in evidence.round1.keys() {
        if !evidence.roster.participants.contains_key(id) {
            return Err(SuccessionError::Surplus {
                pool_id: format!("frost identifier {}", crate::frost::identifier_u16(*id)),
            });
        }
    }

    let missing: Vec<String> = evidence
        .roster
        .participants
        .iter()
        .filter(|(id, _)| !evidence.round1.contains_key(id))
        .map(|(_, info)| hex::encode(&info.pool_id))
        .collect();
    if !missing.is_empty() {
        return Err(SuccessionError::Incomplete { missing, of });
    }

    // Checked BEFORE the arithmetic. Deriving a key from a ceremony already
    // known to contain a proven cheat, and only then refusing it, invites a
    // caller to log the key it must not use.
    let faulted: Vec<String> = evidence
        .roster
        .participants
        .values()
        .filter(|info| evidence.faulted.contains(&info.pool_id))
        .map(|info| hex::encode(&info.pool_id))
        .collect();
    if !faulted.is_empty() {
        return Err(SuccessionError::FaultProven { pool_ids: faulted });
    }

    // The commitments must have been generated under the threshold THIS reader
    // derives from the same registry. They agree with each other by the time we
    // get here, but agreeing with each other is not agreeing with the bridge's
    // rule: a roster running a lower threshold than the chain-derived one is a
    // roster that needs fewer signers than the bridge requires, and handing it
    // custody would install exactly the weakening the rule exists to prevent.
    // In practice this is what a federation node built with a different
    // SECURITY_THRESHOLD_PERCENT than the SPOs would hit — and refusing is the
    // right answer, since it cannot tell which side is wrong.
    let committed = committed_threshold(evidence.round1)?;
    if committed != usize::from(evidence.roster.min_signers) {
        return Err(SuccessionError::ThresholdMismatch {
            expected: usize::from(evidence.roster.min_signers),
            found: committed,
        });
    }

    // Every member must have reached Round 2, AND have addressed it to exactly
    // the rest of the roster.
    //
    // The second half is what makes this more than a liveness check. Round 1
    // fixes the key before any share moves, so Round-1 evidence alone cannot
    // distinguish the ceremony that finished from one that narrowed the moment
    // after — and narrowing happens IN PLACE, inside the same attempt
    // namespace, so the abandoned member's payloads are still served and still
    // verify. A member excluded from the ceremony (round-1 absence, WI-105; a
    // build the others refused, WI-067) simply is not in its peers' recipient
    // lists, and the survivors' key is the sum over the subset — not the sum
    // this function would otherwise compute over everyone who published.
    let no_round2: Vec<String> = evidence
        .roster
        .participants
        .iter()
        .filter(|(id, _)| !evidence.round2.contains_key(id))
        .map(|(_, info)| hex::encode(&info.pool_id))
        .collect();
    if !no_round2.is_empty() {
        return Err(SuccessionError::Round2Incomplete {
            missing: no_round2,
            of,
        });
    }
    for (id, addressed) in evidence.round2 {
        let expected: BTreeSet<Vec<u8>> = evidence
            .roster
            .participants
            .keys()
            .filter(|other| *other != id)
            .map(pool_of)
            .collect();
        if *addressed != expected {
            return Err(SuccessionError::Round2Disagrees {
                pool_id: hex::encode(pool_of(id)),
                addressed: addressed.iter().map(hex::encode).collect(),
            });
        }
    }

    group_key_from_round1(evidence.round1)
}

/// How long one peer may take to answer one probe.
///
/// The transport's client has no default timeout, and this is the one code path
/// that exists so the federation can still move the treasury: a peer that
/// accepts the connection and never replies would otherwise hold the Phase-1
/// fallback open until the OS gave up, per peer, and the movements it was about
/// to make would be lost with it.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The DKG namespace the roster actually published under, if they agree on one.
///
/// **It has to be asked for, not computed.** The attempt is
/// `window * DKG_ATTEMPTS_PER_WINDOW`, where the window counts from the epoch
/// boundary to whenever that node happened to enter the ceremony — our own
/// preprod nodes joined window 522 because they were started mid-epoch. An
/// outsider cannot derive that, and the earlier version of this code assumed
/// attempt 0, which is only ever right on the mock: against a real bridge it
/// fetched URLs no SPO serves and reported the roster as silent, for ever.
///
/// Unanimity is required because disagreement is itself the answer: members
/// publishing under different namespaces are not in one ceremony, whatever each
/// of them has served.
///
/// The value is a HINT and is treated as one — every payload fetched from it is
/// verified against canonical bytes that COMMIT to the namespace, so a peer that
/// names the wrong one produces packages that fail verification rather than a
/// handoff to the wrong key.
pub async fn published_namespace(
    peers: &std::sync::Arc<dyn crate::epoch::traits::PeerNetwork>,
    roster: &crate::epoch::state::Roster,
) -> Option<crate::http::wire::DkgNamespace> {
    let mut agreed: Option<(u64, u64)> = None;
    for info in roster.participants.values() {
        let health = tokio::time::timeout(PROBE_TIMEOUT, peers.check_health(info))
            .await
            .ok()?;
        let published = health.published_dkg?;
        match agreed {
            None => agreed = Some(published),
            Some(seen) if seen != published => return None,
            Some(_) => {}
        }
    }
    let (epoch, attempt) = agreed?;
    Some(crate::http::wire::DkgNamespace::for_attempt(epoch, attempt))
}

/// Fetch what the roster published for `ns`, verifying every payload.
///
/// Returns the verified Round-1 packages and, per member, the set of `pool_id`s
/// its Round-2 payload is addressed to — the two halves [`succession_key`]
/// consumes.
///
/// **A transport error, a timeout and a missing payload are the same answer
/// here**, and deliberately so: the rule's job is to refuse on absence, so
/// "did not answer", "took too long" and "answered with rubbish" all have to
/// read as no evidence. Distinguishing them would only matter if absence were
/// ever allowed to pass, which is exactly what must not happen.
pub async fn gather(
    peers: &std::sync::Arc<dyn crate::epoch::traits::PeerNetwork>,
    roster: &crate::epoch::state::Roster,
    ns: crate::http::wire::DkgNamespace,
) -> (
    BTreeMap<Identifier, round1::Package>,
    BTreeMap<Identifier, BTreeSet<Vec<u8>>>,
) {
    let mut published = BTreeMap::new();
    let mut completed = BTreeMap::new();
    for (id, info) in &roster.participants {
        if let Ok(Ok(Some(pkg))) =
            tokio::time::timeout(PROBE_TIMEOUT, peers.fetch_dkg_round1(ns, info)).await
        {
            published.insert(*id, pkg);
        }
        if let Ok(Ok(Some(recipients))) =
            tokio::time::timeout(PROBE_TIMEOUT, peers.dkg_round2_recipients(ns, info)).await
        {
            completed.insert(*id, recipients);
        }
    }
    (published, completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::xonly::group_xonly;

    /// The load-bearing claim, proved against a REAL ceremony rather than
    /// asserted from the construction: summing the published constant terms
    /// reproduces exactly the key `part3` computed from the shares.
    ///
    /// If this ever fails, every federation-authorized handoff is rotating the
    /// treasury to the wrong key, so it is worth running a genuine DKG for.
    #[test]
    fn the_summed_commitments_are_the_key_the_ceremony_produced() {
        for (t, n) in [(2u16, 3u16), (3, 5), (2, 2)] {
            let (result, round1_packages) = crate::frost::dkg::run_dkg_single_completion(t, n, 1);
            let actual = group_xonly(result.public_key_package.verifying_key())
                .unwrap()
                .xonly;
            let derived = group_key_from_round1(&round1_packages).unwrap();
            assert_eq!(
                derived, actual,
                "{t}-of-{n}: derived key must equal the ceremony's own group key"
            );
        }
    }

    /// A ceremony run under a DIFFERENT threshold than the reader derives from
    /// the chain is refused — the case a federation node built with another
    /// `SECURITY_THRESHOLD_PERCENT` than the SPOs would hit.
    ///
    /// The commitments are internally consistent here, so this is not caught by
    /// members disagreeing with each other: it is caught by them disagreeing
    /// with the bridge's own rule, which is a weaker roster than the bridge
    /// requires and must not be handed custody.
    #[test]
    fn a_ceremony_run_under_another_threshold_is_refused() {
        let (_r, r1) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        // The reader's chain-derived threshold says 3-of-3; the published
        // ceremony was 2-of-3.
        let strict = roster_of(3, 3);
        let err = succession_key(&ev(&strict, &r1, &all_of(&strict), &[]))
            .expect_err("a lower-threshold ceremony must not take custody");
        assert!(
            matches!(
                err,
                SuccessionError::ThresholdMismatch {
                    expected: 3,
                    found: 2
                }
            ),
            "{err:?}"
        );
        // ...and the matching roster is accepted, so this is a real comparison
        // rather than a blanket refusal.
        let matching = roster_of(3, 2);
        assert!(succession_key(&ev(&matching, &r1, &all_of(&matching), &[])).is_ok());
    }

    /// A member that published nothing changes the sum, so it must be refused
    /// rather than silently yielding the group key of a smaller ceremony.
    #[test]
    fn a_missing_member_is_refused_by_name() {
        let (_r, round1_packages) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let full = group_key_from_round1(&round1_packages).unwrap();

        let mut partial = round1_packages.clone();
        let dropped = *partial.keys().next_back().unwrap();
        partial.remove(&dropped);
        let short = group_key_from_round1(&partial).unwrap();
        assert_ne!(
            short, full,
            "dropping a member must change the key — which is why completeness is required"
        );

        let roster = roster_of(3, 2);
        let err = succession_key(&ev(&roster, &partial, &all_of(&roster), &[]))
            .expect_err("an incomplete set must be refused");
        assert!(
            matches!(err, SuccessionError::Incomplete { of: 3, .. }),
            "{err:?}"
        );
        // The diagnostic names the absentee, so a stalled handoff points at a node.
        assert!(
            format!("{err}").contains("published no round-1 commitment"),
            "{err}"
        );
    }

    /// Round 1 alone cannot say the ceremony COMPLETED: the commitments fix `Y`
    /// before any share is distributed. A member that published round 1 and then
    /// vanished leaves a perfectly derivable key nobody may hold a share of, so
    /// the handoff must not proceed on round 1 alone.
    #[test]
    fn round_1_without_round_2_is_not_a_completed_ceremony() {
        let (_r, r1) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let roster = roster_of(3, 2);

        // Everything present: the key derives.
        assert!(succession_key(&ev(&roster, &r1, &all_of(&roster), &[])).is_ok());

        // One member never got to round 2.
        let mut r2 = all_of(&roster);
        let absent = *r2.keys().next_back().unwrap();
        r2.remove(&absent);
        let err = succession_key(&ev(&roster, &r1, &r2, &[]))
            .expect_err("an unfinished ceremony must be refused");
        assert!(
            matches!(err, SuccessionError::Round2Incomplete { of: 3, .. }),
            "{err:?}"
        );
        assert!(
            format!("{err}").contains("not known to have completed"),
            "{err}"
        );
    }

    /// A proven cheat in the ceremony stops the handoff — and stops it BEFORE the
    /// key is computed, so no caller can log a key it must not use.
    #[test]
    fn a_published_fault_proof_stops_the_handoff() {
        let (_r, r1) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let roster = roster_of(3, 2);
        let cheat = roster.participants.values().next().unwrap().pool_id.clone();

        let err = succession_key(&ev(
            &roster,
            &r1,
            &all_of(&roster),
            std::slice::from_ref(&cheat),
        ))
        .expect_err("a proven cheat must stop the rotation");
        let SuccessionError::FaultProven { pool_ids } = &err else {
            panic!("expected FaultProven, got {err:?}");
        };
        assert_eq!(pool_ids, &vec![hex::encode(&cheat)]);

        // A fault proof against somebody who is NOT in this roster is not this
        // ceremony's problem.
        assert!(succession_key(&ev(&roster, &r1, &all_of(&roster), &[vec![0xEE; 28]])).is_ok());
    }

    /// WI-113 review finding: a ceremony that NARROWED in place is the case the
    /// round-2 condition exists for, and presence alone could not see it.
    ///
    /// Narrowing (WI-105 round-1 absence, or a peer the others refused on build)
    /// finishes over a SUBSET inside the SAME attempt namespace, so the
    /// abandoned member's payloads are still served and still verify. Summing
    /// every published commitment then yields a key the survivors do not hold,
    /// and rotating to it strands the treasury until the recovery leaf opens.
    /// The recipient lists give it away: the survivors addressed only each
    /// other.
    #[test]
    fn a_narrowed_ceremony_is_refused() {
        let (_r, r1) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let roster = roster_of(3, 2);
        let ids: Vec<Identifier> = roster.participants.keys().copied().collect();
        let pool = |i: &Identifier| roster.participants[i].pool_id.clone();

        // A and B finished without C; C ran on regardless and published a
        // perfectly valid, correctly-signed round 2 of its own.
        let mut r2: BTreeMap<Identifier, BTreeSet<Vec<u8>>> = BTreeMap::new();
        r2.insert(ids[0], [pool(&ids[1])].into_iter().collect());
        r2.insert(ids[1], [pool(&ids[0])].into_iter().collect());
        r2.insert(ids[2], [pool(&ids[0]), pool(&ids[1])].into_iter().collect());

        let err = succession_key(&ev(&roster, &r1, &r2, &[]))
            .expect_err("a narrowed ceremony must not take custody");
        assert!(
            matches!(err, SuccessionError::Round2Disagrees { .. }),
            "{err:?}"
        );
        assert!(
            format!("{err}").contains("different participant set"),
            "{err}"
        );
    }

    /// A correctly signed round 2 addressed to NOBODY is not completion — the
    /// signature covers whatever `shares` carries, so an empty list verifies.
    #[test]
    fn a_signed_but_empty_round2_is_not_completion() {
        let (_r, r1) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let roster = roster_of(3, 2);
        let mut r2 = all_of(&roster);
        let victim = *r2.keys().next().unwrap();
        r2.insert(victim, BTreeSet::new());

        let err = succession_key(&ev(&roster, &r1, &r2, &[]))
            .expect_err("distributing nothing is not completing a ceremony");
        assert!(
            matches!(err, SuccessionError::Round2Disagrees { .. }),
            "{err:?}"
        );
    }

    /// Completeness was one-directional: it walked the roster, then summed every
    /// entry in the map. A package from outside the roster changes the key.
    #[test]
    fn a_surplus_package_is_refused() {
        let (_r, r1) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let roster = roster_of(2, 2);
        // r1 has three packages; the roster names two.
        let err = succession_key(&ev(&roster, &r1, &all_of(&roster), &[]))
            .expect_err("a package from outside the roster must be refused");
        assert!(matches!(err, SuccessionError::Surplus { .. }), "{err:?}");
    }

    /// Members running different thresholds cannot combine, and the sum of their
    /// commitments is meaningless — refused rather than returned.
    #[test]
    fn different_thresholds_do_not_combine() {
        let (_a, mut two_of_three) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let (_b, three_of_three) = crate::frost::dkg::run_dkg_single_completion(3, 3, 1);
        let id = *two_of_three.keys().next().unwrap();
        two_of_three.insert(id, three_of_three[&id].clone());

        let err = group_key_from_round1(&two_of_three)
            .expect_err("mixed thresholds must not produce a key");
        assert!(
            matches!(err, SuccessionError::ThresholdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn an_empty_set_is_not_a_key() {
        assert!(group_key_from_round1(&BTreeMap::new()).is_err());
    }

    fn ev<'a>(
        roster: &'a crate::epoch::state::Roster,
        round1: &'a BTreeMap<Identifier, round1::Package>,
        round2: &'a BTreeMap<Identifier, BTreeSet<Vec<u8>>>,
        faulted: &'a [Vec<u8>],
    ) -> SuccessionEvidence<'a> {
        SuccessionEvidence {
            roster,
            round1,
            round2,
            faulted,
        }
    }

    /// The Round-2 evidence a COMPLETE ceremony leaves: every member addressed
    /// to every other member.
    fn all_of(roster: &crate::epoch::state::Roster) -> BTreeMap<Identifier, BTreeSet<Vec<u8>>> {
        roster
            .participants
            .keys()
            .map(|me| {
                let others = roster
                    .participants
                    .iter()
                    .filter(|(id, _)| *id != me)
                    .map(|(_, i)| i.pool_id.clone())
                    .collect();
                (*me, others)
            })
            .collect()
    }

    fn roster_of(n: u16, t: u16) -> crate::epoch::state::Roster {
        use crate::epoch::state::{Roster, SpoInfo};
        let mut participants = BTreeMap::new();
        for i in 1..=n {
            let id = Identifier::try_from(i).unwrap();
            participants.insert(
                id,
                SpoInfo {
                    identifier: id,
                    pool_id: vec![i as u8; 28],
                    bifrost_url: String::new(),
                    bifrost_id_pk: vec![],
                },
            );
        }
        Roster {
            epoch: 0,
            participants,
            min_signers: t,
            max_signers: n,
        }
    }
}
