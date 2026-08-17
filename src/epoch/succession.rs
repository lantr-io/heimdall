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
            Self::FaultProven { pool_ids } => write!(
                f,
                "a fault proof is published on chain against this ceremony ({}) — the roster \
                 that produced this key contains a proven cheat",
                pool_ids.join(", ")
            ),
        }
    }
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
    /// Members whose signed round-2 payload was fetched and whose signature
    /// verified under their registered `bifrost_id_pk`.
    ///
    /// Presence and authorship only. The shares inside are encrypted per
    /// recipient, so no third party can check they are CORRECT — that is what
    /// the fault proofs in [`Self::faulted`] cover, and between them they are
    /// the strongest statement available without asking the roster for anything.
    pub round2: &'a BTreeSet<Identifier>,
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

    let no_round2: Vec<String> = evidence
        .roster
        .participants
        .iter()
        .filter(|(id, _)| !evidence.round2.contains(id))
        .map(|(_, info)| hex::encode(&info.pool_id))
        .collect();
    if !no_round2.is_empty() {
        return Err(SuccessionError::Round2Incomplete {
            missing: no_round2,
            of,
        });
    }

    group_key_from_round1(evidence.round1)
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
        let absent = *r2.iter().next_back().unwrap();
        r2.remove(&absent);
        let err = succession_key(&ev(&roster, &r1, &r2, &[]))
            .expect_err("an unfinished ceremony must be refused");
        assert!(
            matches!(err, SuccessionError::Round2Incomplete { of: 3, .. }),
            "{err:?}"
        );
        assert!(format!("{err}").contains("not known to have completed"), "{err}");
    }

    /// A proven cheat in the ceremony stops the handoff — and stops it BEFORE the
    /// key is computed, so no caller can log a key it must not use.
    #[test]
    fn a_published_fault_proof_stops_the_handoff() {
        let (_r, r1) = crate::frost::dkg::run_dkg_single_completion(2, 3, 1);
        let roster = roster_of(3, 2);
        let cheat = roster.participants.values().next().unwrap().pool_id.clone();

        let err = succession_key(&ev(&roster, &r1, &all_of(&roster), std::slice::from_ref(&cheat)))
            .expect_err("a proven cheat must stop the rotation");
        let SuccessionError::FaultProven { pool_ids } = &err else {
            panic!("expected FaultProven, got {err:?}");
        };
        assert_eq!(pool_ids, &vec![hex::encode(&cheat)]);

        // A fault proof against somebody who is NOT in this roster is not this
        // ceremony's problem.
        assert!(succession_key(&ev(&roster, &r1, &all_of(&roster), &[vec![0xEE; 28]])).is_ok());
    }

    fn ev<'a>(
        roster: &'a crate::epoch::state::Roster,
        round1: &'a BTreeMap<Identifier, round1::Package>,
        round2: &'a BTreeSet<Identifier>,
        faulted: &'a [Vec<u8>],
    ) -> SuccessionEvidence<'a> {
        SuccessionEvidence {
            roster,
            round1,
            round2,
            faulted,
        }
    }

    fn all_of(roster: &crate::epoch::state::Roster) -> BTreeSet<Identifier> {
        roster.participants.keys().copied().collect()
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

