/// Per-participant FROST DKG and signing functions.
///
/// These functions operate from a single SPO's perspective — exactly what
/// one process would call during the protocol.
use std::collections::BTreeMap;

use frost::Identifier;
use frost::keys::dkg;
use frost_secp256k1_tr as frost;
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

/// Rebuild a Round 1 secret package for a SMALLER participant set, keeping the
/// polynomial — and therefore the commitment and proof of knowledge already
/// published — exactly as they are (WI-105).
///
/// This is what lets a DKG narrow to whoever published Round 1 by the deadline
/// without re-running Round 1. It is sound because `max_signers` never reaches
/// the wire: `part1`'s published `Package` is `{commitment, proof_of_knowledge}`,
/// the commitment is over the `t` polynomial coefficients, and `t` is fixed for
/// the epoch. frost-core uses `max_signers` only to check the package COUNT it is
/// handed in `part2`/`part3`, so telling it the smaller number is telling it the
/// truth about the set now being run.
///
/// Narrowing must never change `min_signers`: the published commitment carries
/// exactly `t` points, so a different `t` would invalidate the very payloads this
/// exists to reuse.
///
/// Needs frost-core's `internals` feature for the two accessors — see Cargo.toml.
pub fn dkg_narrow_round1_secret(
    secret_package: &dkg::round1::SecretPackage,
    identifier: Identifier,
    max_signers: u16,
    min_signers: u16,
) -> dkg::round1::SecretPackage {
    dkg::round1::SecretPackage::new(
        identifier,
        secret_package.coefficients(),
        secret_package.commitment().clone(),
        min_signers,
        max_signers,
    )
}

/// SPO processes all peers' Round 1 packages, produces Round 2 secret shares.
pub fn dkg_part2(
    secret_package: dkg::round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, dkg::round1::Package>,
) -> Result<
    (
        dkg::round2::SecretPackage,
        BTreeMap<Identifier, dkg::round2::Package>,
    ),
    frost::Error,
> {
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
) -> (
    frost::round1::SigningNonces,
    frost::round1::SigningCommitments,
) {
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

/// Round-2 signing with a BIP-341 Taproot tweak applied before share
/// generation. `merkle_root` is the Taproot script-tree root bytes, or
/// `None` for a key-only output. After aggregation (via
/// [`sign_aggregate_with_tweak`]) the resulting signature verifies
/// under the *tweaked* output key that the on-chain scriptPubKey uses.
pub fn sign_round2_with_tweak(
    signing_package: &frost::SigningPackage,
    nonces: &frost::round1::SigningNonces,
    key_package: &frost::keys::KeyPackage,
    merkle_root: Option<&[u8]>,
) -> Result<frost::round2::SignatureShare, frost::Error> {
    frost::round2::sign_with_tweak(signing_package, nonces, key_package, merkle_root)
}

/// Aggregate signature shares into a final signature.
pub fn sign_aggregate(
    signing_package: &frost::SigningPackage,
    shares: &BTreeMap<Identifier, frost::round2::SignatureShare>,
    public_key_package: &frost::keys::PublicKeyPackage,
) -> Result<frost::Signature, frost::Error> {
    frost::aggregate(signing_package, shares, public_key_package)
}

/// Aggregate shares produced by [`sign_round2_with_tweak`]. Must pass
/// the same `merkle_root` that each signer used for their share.
pub fn sign_aggregate_with_tweak(
    signing_package: &frost::SigningPackage,
    shares: &BTreeMap<Identifier, frost::round2::SignatureShare>,
    public_key_package: &frost::keys::PublicKeyPackage,
    merkle_root: Option<&[u8]>,
) -> Result<frost::Signature, frost::Error> {
    frost::aggregate_with_tweak(signing_package, shares, public_key_package, merkle_root)
}
