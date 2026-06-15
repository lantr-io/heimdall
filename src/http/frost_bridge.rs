//! Bridge between `frost-secp256k1-tr` DKG package types and the spec's
//! per-field wire bytes.
//!
//! The spec ships *structured* fields (the commitment points, σ_i, the
//! share scalar) — NOT frost's opaque whole-package serialization. frost
//! exposes exactly those pieces through public getters plus per-field
//! `serialize`/`deserialize` (frost-core 3.0.0-rc.0):
//!
//! - `round1::Package` → `.commitment()` (→ `t` × 33-byte points) and
//!   `.proof_of_knowledge()` (→ 64-byte σ_i)
//! - `round2::Package` → `.signing_share()` (→ 32-byte scalar)
//!
//! and rebuilds via `VerifiableSecretSharingCommitment::deserialize` /
//! `Signature::deserialize` / `SigningShare::deserialize` + `Package::new`.
//!
//! σ_i is `Signature::serialize()` verbatim = **x-only R(32) ‖ μ(32)**
//! (spec §6.1, Interpretation A — see technical_questions.md §4). This is
//! lossless because the `-tr` ciphersuite's `generate_nonce` forces R to
//! have an even Y, so dropping the parity byte in the x-only encoding
//! never loses information.

use frost_secp256k1_tr as frost;
use frost::keys::dkg::{round1, round2};
use frost::keys::{SigningShare, VerifiableSecretSharingCommitment};
use frost::Signature;

use super::canonical::{POINT_LEN, SHARE_LEN, SIG_LEN};

/// A frost field had an unexpected serialized length (should be
/// impossible for a well-formed package; treated as a malformed peer
/// payload on the receive side).
#[derive(Debug)]
pub enum BridgeError {
    Frost(frost::Error),
    BadPointLen(usize),
    BadSigLen(usize),
    BadShareLen(usize),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frost(e) => write!(f, "frost: {e}"),
            Self::BadPointLen(n) => write!(f, "commitment point is {n} bytes, want {POINT_LEN}"),
            Self::BadSigLen(n) => write!(f, "sigma_i is {n} bytes, want {SIG_LEN}"),
            Self::BadShareLen(n) => write!(f, "share scalar is {n} bytes, want {SHARE_LEN}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<frost::Error> for BridgeError {
    fn from(e: frost::Error) -> Self {
        Self::Frost(e)
    }
}

fn to_point(v: Vec<u8>) -> Result<[u8; POINT_LEN], BridgeError> {
    v.try_into().map_err(|v: Vec<u8>| BridgeError::BadPointLen(v.len()))
}

/// Decompose a Round 1 package into the spec fields: the commitment
/// vector (`t` compressed points φ_{i,0..t-1}) and σ_i (the 64-byte
/// proof of knowledge, x-only R ‖ μ).
pub fn round1_fields(
    pkg: &round1::Package,
) -> Result<(Vec<[u8; POINT_LEN]>, [u8; SIG_LEN]), BridgeError> {
    let commitment = pkg
        .commitment()
        .serialize()?
        .into_iter()
        .map(to_point)
        .collect::<Result<Vec<_>, _>>()?;
    let sig = pkg.proof_of_knowledge().serialize()?;
    let sigma_i: [u8; SIG_LEN] = sig
        .as_slice()
        .try_into()
        .map_err(|_| BridgeError::BadSigLen(sig.len()))?;
    Ok((commitment, sigma_i))
}

/// Rebuild a Round 1 package from the wire fields (receive side).
pub fn round1_from_fields(
    commitment: &[[u8; POINT_LEN]],
    sigma_i: &[u8; SIG_LEN],
) -> Result<round1::Package, BridgeError> {
    let commitment =
        VerifiableSecretSharingCommitment::deserialize(commitment.iter().map(|p| p.as_slice()))?;
    let proof_of_knowledge = Signature::deserialize(sigma_i)?;
    Ok(round1::Package::new(commitment, proof_of_knowledge))
}

/// The plaintext 32-byte share scalar `f_i(l)` carried by a Round 2
/// package — extracted before ECDH encryption (send side) or rebuilt
/// after decryption (receive side).
pub fn round2_share_bytes(pkg: &round2::Package) -> Result<[u8; SHARE_LEN], BridgeError> {
    let s = pkg.signing_share().serialize();
    s.as_slice()
        .try_into()
        .map_err(|_| BridgeError::BadShareLen(s.len()))
}

/// Rebuild a Round 2 package from a decrypted 32-byte share scalar.
pub fn round2_from_share(share: &[u8; SHARE_LEN]) -> Result<round2::Package, BridgeError> {
    let signing_share = SigningShare::deserialize(share)?;
    Ok(round2::Package::new(signing_share))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use frost::keys::dkg;
    use frost::Identifier;

    fn id(n: u16) -> Identifier {
        Identifier::try_from(n).unwrap()
    }

    #[test]
    fn round1_package_roundtrips_through_wire_fields() {
        let (_secret, pkg) = dkg::part1(id(1), 3, 2, rand::rngs::OsRng).unwrap();
        let (commitment, sigma_i) = round1_fields(&pkg).unwrap();

        // t = min_signers = 2 commitment points, each 33 bytes; σ_i 64 bytes.
        assert_eq!(commitment.len(), 2);
        let rebuilt = round1_from_fields(&commitment, &sigma_i).unwrap();
        assert_eq!(rebuilt, pkg, "round1 package must survive the wire round-trip");
    }

    #[test]
    fn round2_package_roundtrips_through_share_bytes() {
        // Two participants so part2 produces a real per-recipient package.
        let (s1, p1) = dkg::part1(id(1), 2, 2, rand::rngs::OsRng).unwrap();
        let (_s2, p2) = dkg::part1(id(2), 2, 2, rand::rngs::OsRng).unwrap();

        let mut r1_for_1 = BTreeMap::new();
        r1_for_1.insert(id(2), p2);
        let (_s1_round2, packages) = dkg::part2(s1, &r1_for_1).unwrap();
        let _ = p1; // p1 only needed to exist; id(1) is the sender here

        let pkg_for_2 = packages.get(&id(2)).expect("a package addressed to peer 2");
        let share = round2_share_bytes(pkg_for_2).unwrap();
        let rebuilt = round2_from_share(&share).unwrap();
        assert_eq!(&rebuilt, pkg_for_2, "round2 package must survive the share round-trip");
    }
}
