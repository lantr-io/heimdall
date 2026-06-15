//! Spec DKG wire payloads: the structured JSON exchanged between SPOs,
//! assembling [`canonical`](super::canonical) bytes, the
//! [`frost_bridge`](super::frost_bridge), and [`auth`](super::auth).
//!
//! These replace the ad-hoc frost-serde blobs. The JSON shape is fixed
//! by the spec (hex-encoded fields); the BIP-340 `signature` authenticates
//! the canonical bytes, not the JSON. Build on the publish side, verify +
//! parse on the fetch side.

use bitcoin::secp256k1::rand::{CryptoRng, Rng};
use bitcoin::secp256k1::{All, Keypair, Secp256k1, SecretKey};
use frost_secp256k1_tr::keys::dkg::{round1, round2};
use serde::{Deserialize, Serialize};

use super::auth::{self, AuthError};
use super::canonical::{self, ShareEntry, POINT_LEN, POOL_ID_LEN, SHARE_LEN, SIG_LEN};
use super::frost_bridge::{self, BridgeError};

#[derive(Debug)]
pub enum WireError {
    Bridge(BridgeError),
    Auth(AuthError),
    /// A hex field failed to decode or had the wrong length.
    Field(String),
    /// No share in a Round 2 payload was addressed to us.
    NoShareForUs,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bridge(e) => write!(f, "frost bridge: {e}"),
            Self::Auth(e) => write!(f, "auth: {e}"),
            Self::Field(s) => write!(f, "malformed field: {s}"),
            Self::NoShareForUs => write!(f, "no Round 2 share addressed to this pool"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<BridgeError> for WireError {
    fn from(e: BridgeError) -> Self {
        Self::Bridge(e)
    }
}
impl From<AuthError> for WireError {
    fn from(e: AuthError) -> Self {
        Self::Auth(e)
    }
}

fn hex_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N], WireError> {
    let bytes = hex::decode(s).map_err(|e| WireError::Field(format!("{what}: {e}")))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| WireError::Field(format!("{what}: got {} bytes, want {N}", v.len())))
}

// ---------------------------------------------------------------------------
// Round 1
// ---------------------------------------------------------------------------

/// Round 1 payload: commitment vector + proof of knowledge, authenticated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dkg1Wire {
    /// `t` compressed commitment points φ_{i,0..t-1}, hex (33 bytes each).
    pub commitment: Vec<String>,
    /// Proof of knowledge σ_i, hex (64 bytes).
    pub sigma_i: String,
    /// BIP-340 signature over `SHA256(canonical_bytes)`, hex (64 bytes).
    pub signature: String,
}

/// Build and sign this SPO's Round 1 payload from its frost package.
pub fn build_round1(
    secp: &Secp256k1<All>,
    keypair: &Keypair,
    epoch: u64,
    threshold: u64,
    attempt: u64,
    my_pool_id: &[u8; POOL_ID_LEN],
    package: &round1::Package,
) -> Result<Dkg1Wire, WireError> {
    let (commitment, sigma_i) = frost_bridge::round1_fields(package)?;
    let canonical_bytes =
        canonical::round1(epoch, threshold, attempt, my_pool_id, &commitment, &sigma_i);
    let signature = auth::sign_payload(secp, keypair, &canonical_bytes);
    Ok(Dkg1Wire {
        commitment: commitment.iter().map(hex::encode).collect(),
        sigma_i: hex::encode(sigma_i),
        signature: hex::encode(signature),
    })
}

/// Verify a peer's Round 1 payload against their `bifrost_id_pk` and the
/// expected namespace, then rebuild the frost package. The caller must
/// already have matched `peer_pool_id`/`bifrost_id_pk` to the polled peer.
pub fn verify_round1(
    secp: &Secp256k1<All>,
    peer_pool_id: &[u8; POOL_ID_LEN],
    peer_bifrost_id_pk: &[u8],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    wire: &Dkg1Wire,
) -> Result<round1::Package, WireError> {
    let commitment = wire
        .commitment
        .iter()
        .map(|h| hex_n::<POINT_LEN>(h, "commitment"))
        .collect::<Result<Vec<_>, _>>()?;
    let sigma_i = hex_n::<SIG_LEN>(&wire.sigma_i, "sigma_i")?;
    let signature = hex_n::<SIG_LEN>(&wire.signature, "signature")?;

    let canonical_bytes =
        canonical::round1(epoch, threshold, attempt, peer_pool_id, &commitment, &sigma_i);
    auth::verify_payload(secp, peer_bifrost_id_pk, &canonical_bytes, &signature)?;

    Ok(frost_bridge::round1_from_fields(&commitment, &sigma_i)?)
}

// ---------------------------------------------------------------------------
// Round 2
// ---------------------------------------------------------------------------

/// One encrypted share entry in the Round 2 JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareWire {
    pub recipient_pool_id: String, // hex, 28 bytes
    pub ephemeral_pk: String,      // hex, 33 bytes
    pub ciphertext: String,        // hex, 32 bytes
}

/// Round 2 payload: per-recipient encrypted shares, authenticated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dkg2Wire {
    pub shares: Vec<ShareWire>,
    /// BIP-340 signature over `SHA256(canonical_bytes)`, hex (64 bytes).
    pub signature: String,
}

/// One recipient of a Round 2 share: their `pool_id`, their identity key
/// (to encrypt under), and the frost package addressed to them.
pub struct Round2Recipient<'a> {
    pub pool_id: [u8; POOL_ID_LEN],
    pub bifrost_id_pk: &'a [u8],
    pub package: &'a round2::Package,
}

/// Build and sign this SPO's Round 2 payload: encrypt each recipient's
/// share under a fresh ephemeral key, order by `recipient_pool_id`, sign
/// the canonical bytes.
pub fn build_round2<R: Rng + CryptoRng>(
    secp: &Secp256k1<All>,
    keypair: &Keypair,
    epoch: u64,
    threshold: u64,
    attempt: u64,
    my_pool_id: &[u8; POOL_ID_LEN],
    recipients: &[Round2Recipient],
    rng: &mut R,
) -> Result<Dkg2Wire, WireError> {
    let mut entries: Vec<ShareEntry> = Vec::with_capacity(recipients.len());
    for r in recipients {
        let share = frost_bridge::round2_share_bytes(r.package)?;
        let ephemeral_sk = SecretKey::new(rng);
        let (ephemeral_pk, ciphertext) =
            auth::encrypt_share(secp, &ephemeral_sk, r.bifrost_id_pk, &share)?;
        entries.push(ShareEntry {
            recipient_pool_id: r.pool_id,
            ephemeral_pk,
            ciphertext,
        });
    }
    // Canonical ordering by recipient_pool_id; the JSON follows the same order.
    entries.sort_by(|a, b| a.recipient_pool_id.cmp(&b.recipient_pool_id));

    let canonical_bytes = canonical::round2(epoch, threshold, attempt, my_pool_id, &entries);
    let signature = auth::sign_payload(secp, keypair, &canonical_bytes);

    Ok(Dkg2Wire {
        shares: entries
            .iter()
            .map(|e| ShareWire {
                recipient_pool_id: hex::encode(e.recipient_pool_id),
                ephemeral_pk: hex::encode(e.ephemeral_pk),
                ciphertext: hex::encode(e.ciphertext),
            })
            .collect(),
        signature: hex::encode(signature),
    })
}

/// Verify a sender's Round 2 payload, decrypt the share addressed to us,
/// and rebuild the frost package.
#[allow(clippy::too_many_arguments)]
pub fn verify_round2(
    secp: &Secp256k1<All>,
    sender_pool_id: &[u8; POOL_ID_LEN],
    sender_bifrost_id_pk: &[u8],
    my_pool_id: &[u8; POOL_ID_LEN],
    my_bifrost_sk: &SecretKey,
    epoch: u64,
    threshold: u64,
    attempt: u64,
    wire: &Dkg2Wire,
) -> Result<round2::Package, WireError> {
    let mut entries: Vec<ShareEntry> = Vec::with_capacity(wire.shares.len());
    for s in &wire.shares {
        entries.push(ShareEntry {
            recipient_pool_id: hex_n::<POOL_ID_LEN>(&s.recipient_pool_id, "recipient_pool_id")?,
            ephemeral_pk: hex_n::<POINT_LEN>(&s.ephemeral_pk, "ephemeral_pk")?,
            ciphertext: hex_n::<SHARE_LEN>(&s.ciphertext, "ciphertext")?,
        });
    }
    let signature = hex_n::<SIG_LEN>(&wire.signature, "signature")?;

    // canonical::round2 sorts internally, so input order does not matter.
    let canonical_bytes = canonical::round2(epoch, threshold, attempt, sender_pool_id, &entries);
    auth::verify_payload(secp, sender_bifrost_id_pk, &canonical_bytes, &signature)?;

    let mine = entries
        .iter()
        .find(|e| &e.recipient_pool_id == my_pool_id)
        .ok_or(WireError::NoShareForUs)?;
    let share = auth::decrypt_share(secp, my_bifrost_sk, &mine.ephemeral_pk, &mine.ciphertext)?;
    Ok(frost_bridge::round2_from_share(&share)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bitcoin::secp256k1::rand::rngs::OsRng;
    use frost_secp256k1_tr as frost;
    use frost::keys::dkg;
    use frost::Identifier;

    fn id(n: u16) -> Identifier {
        Identifier::try_from(n).unwrap()
    }

    fn keypair(secp: &Secp256k1<All>) -> (SecretKey, Keypair, [u8; 32]) {
        let (sk, _pk) = secp.generate_keypair(&mut OsRng);
        let kp = Keypair::from_secret_key(secp, &sk);
        let xonly = kp.x_only_public_key().0.serialize();
        (sk, kp, xonly)
    }

    #[test]
    fn round1_build_verify_roundtrip() {
        let secp = Secp256k1::new();
        let (_sk, kp, xonly) = keypair(&secp);
        let pool = [3u8; POOL_ID_LEN];
        let (_s, pkg) = dkg::part1(id(1), 3, 2, OsRng).unwrap();

        let wire = build_round1(&secp, &kp, 9, canonical::THRESHOLD_51, 0, &pool, &pkg).unwrap();
        assert_eq!(wire.commitment.len(), 2);

        let parsed =
            verify_round1(&secp, &pool, &xonly, 9, canonical::THRESHOLD_51, 0, &wire).unwrap();
        assert_eq!(parsed, pkg);
    }

    #[test]
    fn round1_verify_rejects_wrong_namespace() {
        let secp = Secp256k1::new();
        let (_sk, kp, xonly) = keypair(&secp);
        let pool = [3u8; POOL_ID_LEN];
        let (_s, pkg) = dkg::part1(id(1), 3, 2, OsRng).unwrap();
        let wire = build_round1(&secp, &kp, 9, canonical::THRESHOLD_51, 0, &pool, &pkg).unwrap();

        // Wrong epoch -> different canonical bytes -> signature must fail.
        let err = verify_round1(&secp, &pool, &xonly, 10, canonical::THRESHOLD_51, 0, &wire);
        assert!(matches!(err, Err(WireError::Auth(_))));
    }

    #[test]
    fn round2_build_verify_roundtrip() {
        let secp = Secp256k1::new();
        // Sender = pool 1 / id 1; recipient = pool 2 / id 2.
        let (_sk1, kp1, _x1) = keypair(&secp);
        let (sk2, _kp2, x2) = keypair(&secp);
        let pool1 = [1u8; POOL_ID_LEN];
        let pool2 = [2u8; POOL_ID_LEN];

        // Real frost round2 package from sender 1, addressed to peer 2.
        let (s1, _p1) = dkg::part1(id(1), 2, 2, OsRng).unwrap();
        let (_s2, p2) = dkg::part1(id(2), 2, 2, OsRng).unwrap();
        let mut r1 = BTreeMap::new();
        r1.insert(id(2), p2);
        let (_s1r2, pkgs) = dkg::part2(s1, &r1).unwrap();
        let pkg_for_2 = pkgs.get(&id(2)).unwrap();

        let recipients = vec![Round2Recipient {
            pool_id: pool2,
            bifrost_id_pk: &x2,
            package: pkg_for_2,
        }];
        let wire =
            build_round2(&secp, &kp1, 9, canonical::THRESHOLD_51, 0, &pool1, &recipients, &mut OsRng)
                .unwrap();

        let parsed = verify_round2(
            &secp, &pool1, &keypair_xonly(&secp, &kp1), &pool2, &sk2, 9,
            canonical::THRESHOLD_51, 0, &wire,
        )
        .unwrap();
        assert_eq!(&parsed, pkg_for_2);
    }

    // Sender's x-only identity key, recomputed for the verify call.
    fn keypair_xonly(_secp: &Secp256k1<All>, kp: &Keypair) -> [u8; 32] {
        kp.x_only_public_key().0.serialize()
    }

    #[test]
    fn round2_verify_rejects_tampered_ciphertext() {
        let secp = Secp256k1::new();
        let (_sk1, kp1, _x1) = keypair(&secp);
        let (sk2, _kp2, x2) = keypair(&secp);
        let pool1 = [1u8; POOL_ID_LEN];
        let pool2 = [2u8; POOL_ID_LEN];
        let (s1, _p1) = dkg::part1(id(1), 2, 2, OsRng).unwrap();
        let (_s2, p2) = dkg::part1(id(2), 2, 2, OsRng).unwrap();
        let mut r1 = BTreeMap::new();
        r1.insert(id(2), p2);
        let (_s1r2, pkgs) = dkg::part2(s1, &r1).unwrap();
        let recipients = vec![Round2Recipient {
            pool_id: pool2,
            bifrost_id_pk: &x2,
            package: pkgs.get(&id(2)).unwrap(),
        }];
        let mut wire =
            build_round2(&secp, &kp1, 9, canonical::THRESHOLD_51, 0, &pool1, &recipients, &mut OsRng)
                .unwrap();

        // Flip a byte in the ciphertext: signature no longer matches canonical bytes.
        let mut ct = hex::decode(&wire.shares[0].ciphertext).unwrap();
        ct[0] ^= 0xff;
        wire.shares[0].ciphertext = hex::encode(ct);

        let err = verify_round2(
            &secp, &pool1, &kp1.x_only_public_key().0.serialize(), &pool2, &sk2, 9,
            canonical::THRESHOLD_51, 0, &wire,
        );
        assert!(matches!(err, Err(WireError::Auth(_))));
    }
}
