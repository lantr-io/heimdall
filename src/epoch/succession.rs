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
//! ## What this does NOT establish, and why that is a decision not an oversight
//!
//! Round-1 commitments fix the group key BEFORE round 2 distributes the shares.
//! So a key derived here is certainly the key that ceremony *would* produce — but
//! it is not evidence that the roster can SIGN with it. A ceremony that collapsed
//! in round 2 leaves a perfectly derivable `Y_51` that nobody holds a usable
//! share of, and handing the treasury to it strands the funds until the recovery
//! leaf's CSV delay expires.
//!
//! That gap is accepted deliberately, and it is the same assurance level the
//! protocol already runs on: in steady state the OUTGOING roster likewise signs
//! a succession to a key it cannot test. Closing it needs the incoming roster to
//! prove possession — a signature under `Y_51` over the very `sig_msg` — which is
//! a protocol addition, not a local one, so it is raised as an open question in
//! the spec rather than invented here.

use std::collections::BTreeMap;

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

/// The reliability rule: every eligible roster member must have published, and
/// all must have committed to the same degree, before the sum is a key worth
/// handing the treasury to.
///
/// **All of them, not a threshold.** A threshold subset is enough to SIGN with a
/// key that already exists, but it is not enough to say which key a ceremony
/// produced: `Y` is the sum over ALL participants, so a missing member does not
/// give a weaker answer, it gives a different key. Anything less than complete
/// attendance computes the group key of a ceremony that did not happen.
pub fn succession_key(
    roster: &crate::epoch::state::Roster,
    published: &BTreeMap<Identifier, round1::Package>,
) -> Result<UntweakedPublicKey, SuccessionError> {
    let missing: Vec<String> = roster
        .participants
        .iter()
        .filter(|(id, _)| !published.contains_key(id))
        .map(|(_, info)| hex::encode(&info.pool_id))
        .collect();
    if !missing.is_empty() {
        return Err(SuccessionError::Incomplete {
            missing,
            of: roster.participants.len(),
        });
    }
    group_key_from_round1(published)
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
        let err = succession_key(&roster, &partial).expect_err("an incomplete set must be refused");
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

