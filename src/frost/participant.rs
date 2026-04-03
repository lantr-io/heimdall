/// Per-participant FROST DKG and signing functions.
///
/// These functions operate from a single SPO's perspective — exactly what
/// one process would call during the protocol.
use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost::keys::dkg;
use frost::Identifier;
use rand_core::{CryptoRng, RngCore};

// ── DKG ────────────────────────────────────────────────────────────────

/// SPO generates its Round 1 package (random polynomial + commitment + proof-of-knowledge).
pub fn dkg_part1(
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(dkg::round1::SecretPackage, dkg::round1::Package), frost::Error> {
    dkg::part1(identifier, max_signers, min_signers, rng)
}

/// SPO processes all peers' Round 1 packages, produces Round 2 secret shares.
pub fn dkg_part2(
    secret_package: dkg::round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, dkg::round1::Package>,
) -> Result<(dkg::round2::SecretPackage, BTreeMap<Identifier, dkg::round2::Package>), frost::Error>
{
    dkg::part2(secret_package, round1_packages)
}

/// SPO combines everything, derives its signing share + group key.
pub fn dkg_part3(
    round2_secret: &dkg::round2::SecretPackage,
    round1_packages: &BTreeMap<Identifier, dkg::round1::Package>,
    round2_packages: &BTreeMap<Identifier, dkg::round2::Package>,
) -> Result<(frost::keys::KeyPackage, frost::keys::PublicKeyPackage), frost::Error> {
    dkg::part3(round2_secret, round1_packages, round2_packages)
}

// ── Signing ────────────────────────────────────────────────────────────

/// SPO generates nonce commitments for signing round 1.
pub fn sign_round1(
    key_package: &frost::keys::KeyPackage,
    rng: &mut (impl RngCore + CryptoRng),
) -> (frost::round1::SigningNonces, frost::round1::SigningCommitments) {
    frost::round1::commit(key_package.signing_share(), rng)
}

/// SPO computes its signature share for signing round 2.
pub fn sign_round2(
    signing_package: &frost::SigningPackage,
    nonces: &frost::round1::SigningNonces,
    key_package: &frost::keys::KeyPackage,
) -> Result<frost::round2::SignatureShare, frost::Error> {
    frost::round2::sign(signing_package, nonces, key_package)
}

/// Aggregate signature shares into a final signature.
pub fn sign_aggregate(
    signing_package: &frost::SigningPackage,
    shares: &BTreeMap<Identifier, frost::round2::SignatureShare>,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<frost::Signature, frost::Error> {
    frost::aggregate(signing_package, shares, public_key_package)
}
