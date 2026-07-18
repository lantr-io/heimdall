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
use super::canonical::{
    self, EVIDENCE_HASH_LEN, PAD_COMMIT_LEN, POINT_LEN, POOL_ID_LEN, SHARE_LEN, SIG_LEN, ShareEntry,
};
use super::frost_bridge::{self, BridgeError};
use crate::cardano::hash::blake2b_256;
use crate::circuits::fault_evidence;
use crate::circuits::fault_evidence::{
    EquivocationEvidence, NamespacePhase, Round1PokFaultEvidence, Round2ShareFaultEvidence,
};

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

fn bifrost_pk_array(peer_bifrost_id_pk: &[u8]) -> Result<[u8; 32], WireError> {
    peer_bifrost_id_pk.try_into().map_err(|_| {
        WireError::Field(format!(
            "bifrost_id_pk is {} bytes, want 32",
            peer_bifrost_id_pk.len()
        ))
    })
}

fn fault_err(context: &str, e: fault_evidence::FaultEvidenceError) -> WireError {
    WireError::Field(format!("{context}: {e}"))
}

/// Convert a roster-held `pool_id` (`Vec<u8>`) to the fixed 28-byte array
/// the canonical-bytes/URL helpers require.
pub fn pool_id_array(pool_id: &[u8]) -> Result<[u8; POOL_ID_LEN], WireError> {
    pool_id.try_into().map_err(|_| {
        WireError::Field(format!(
            "pool_id is {} bytes, want {POOL_ID_LEN}",
            pool_id.len()
        ))
    })
}

/// The `(epoch, threshold, attempt)` namespace every DKG payload is bound
/// to, both in its URL path and inside its signed canonical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DkgNamespace {
    pub epoch: u64,
    pub threshold: u64,
    pub attempt: u64,
}

impl DkgNamespace {
    /// The normal namespace for `epoch`: the constant threshold label 51
    /// (the >51%-stake DKG) and attempt 0. Attempt only advances on an
    /// exceptional cryptographic-fault rerun (WI-014) — see [`Self::for_attempt`].
    pub fn new(epoch: u64) -> Self {
        Self::for_attempt(epoch, 0)
    }

    /// The namespace for a specific DKG `attempt` of `epoch`. A failed
    /// ceremony (a peer absent or provably faulty so the qualified set can't
    /// run `dkg_part2`/`part3`) reruns over a reduced candidate set under
    /// `attempt + 1`, which re-namespaces every payload so a stale
    /// previous-attempt package can never be replayed into the rerun. The
    /// `threshold` label stays the constant 51 (the >51%-stake DKG); the
    /// FROST signing `t` lives in the roster, not here.
    pub fn for_attempt(epoch: u64, attempt: u64) -> Self {
        Self {
            epoch,
            threshold: canonical::THRESHOLD_51,
            attempt,
        }
    }
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
    /// Circuit public input 0 for this Round 1 payload, hex (32 bytes).
    pub poseidon_commit: String,
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
    my_identifier: u16,
    package: &round1::Package,
) -> Result<Dkg1Wire, WireError> {
    let (commitment, sigma_i) = frost_bridge::round1_fields(package)?;
    let poseidon_commit = fault_evidence::round1_evidence_hash_from_fields(
        my_pool_id,
        my_identifier,
        &commitment,
        &sigma_i,
    )
    .map_err(|e| WireError::Field(format!("poseidon_commit: {e}")))?;
    let canonical_bytes = canonical::round1(
        epoch,
        threshold,
        attempt,
        my_pool_id,
        &commitment,
        &sigma_i,
        &poseidon_commit,
    );
    let signature = auth::sign_payload(secp, keypair, &canonical_bytes);
    Ok(Dkg1Wire {
        commitment: commitment.iter().map(hex::encode).collect(),
        sigma_i: hex::encode(sigma_i),
        poseidon_commit: hex::encode(poseidon_commit),
        signature: hex::encode(signature),
    })
}

/// Verify a peer's Round 1 payload against their `bifrost_id_pk` and the
/// expected namespace, then rebuild the frost package. The caller must
/// already have matched `peer_pool_id`/`bifrost_id_pk` to the polled peer.
pub fn verify_round1(
    _secp: &Secp256k1<All>,
    peer_pool_id: &[u8; POOL_ID_LEN],
    peer_bifrost_id_pk: &[u8],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    peer_identifier: u16,
    wire: &Dkg1Wire,
) -> Result<round1::Package, WireError> {
    let evidence = round1_fault_evidence(
        peer_pool_id,
        peer_bifrost_id_pk,
        epoch,
        threshold,
        attempt,
        peer_identifier,
        wire,
    )?;
    if evidence
        .is_fault()
        .map_err(|e| fault_err("round1 PoK", e))?
    {
        return Err(WireError::Field(
            "round1 proof of knowledge is invalid".into(),
        ));
    }
    Ok(frost_bridge::round1_from_fields(
        &evidence.commitments,
        &evidence.sigma_i,
    )?)
}

fn round1_signed_fields(
    wire: &Dkg1Wire,
) -> Result<
    (
        Vec<[u8; POINT_LEN]>,
        [u8; SIG_LEN],
        [u8; EVIDENCE_HASH_LEN],
        [u8; SIG_LEN],
    ),
    WireError,
> {
    let commitment = wire
        .commitment
        .iter()
        .map(|h| hex_n::<POINT_LEN>(h, "commitment"))
        .collect::<Result<Vec<_>, _>>()?;
    let sigma_i = hex_n::<SIG_LEN>(&wire.sigma_i, "sigma_i")?;
    let poseidon_commit = hex_n::<EVIDENCE_HASH_LEN>(&wire.poseidon_commit, "poseidon_commit")?;
    let signature = hex_n::<SIG_LEN>(&wire.signature, "signature")?;
    Ok((commitment, sigma_i, poseidon_commit, signature))
}

/// Rebuild the signed Round 1 evidence envelope from a JSON payload.
///
/// This verifies the accused's BIP-340 signature and the payload's advertised
/// `poseidon_commit`, but does not require the PoK to be bad. Call
/// [`Round1PokFaultEvidence::is_fault`] to distinguish a punishable invalid
/// payload from an honest one.
pub fn round1_fault_evidence(
    peer_pool_id: &[u8; POOL_ID_LEN],
    peer_bifrost_id_pk: &[u8],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    peer_identifier: u16,
    wire: &Dkg1Wire,
) -> Result<Round1PokFaultEvidence, WireError> {
    let (commitment, sigma_i, poseidon_commit, signature) = round1_signed_fields(wire)?;
    let ev = Round1PokFaultEvidence {
        epoch,
        threshold,
        attempt,
        accused_pool_id: *peer_pool_id,
        bifrost_id_pk: bifrost_pk_array(peer_bifrost_id_pk)?,
        identifier: peer_identifier,
        commitments: commitment,
        sigma_i,
        payload_signature: signature,
    };
    if poseidon_commit
        != ev
            .evidence_hash()
            .map_err(|e| fault_err("poseidon_commit", e))?
    {
        return Err(WireError::Field("poseidon_commit mismatch".into()));
    }
    let canonical_bytes = ev
        .canonical_bytes()
        .map_err(|e| fault_err("round1 canonical bytes", e))?;
    auth::verify_payload(
        &Secp256k1::new(),
        peer_bifrost_id_pk,
        &canonical_bytes,
        &signature,
    )?;
    Ok(ev)
}

/// The canonical bytes and signature from a Round 1 payload, suitable for an
/// equivocation proof.
pub fn round1_signed_payload(
    peer_pool_id: &[u8; POOL_ID_LEN],
    peer_bifrost_id_pk: &[u8],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    wire: &Dkg1Wire,
) -> Result<(Vec<u8>, [u8; SIG_LEN]), WireError> {
    let (commitment, sigma_i, poseidon_commit, signature) = round1_signed_fields(wire)?;
    let canonical_bytes = canonical::round1(
        epoch,
        threshold,
        attempt,
        peer_pool_id,
        &commitment,
        &sigma_i,
        &poseidon_commit,
    );
    auth::verify_payload(
        &Secp256k1::new(),
        peer_bifrost_id_pk,
        &canonical_bytes,
        &signature,
    )?;
    Ok((canonical_bytes, signature))
}

// ---------------------------------------------------------------------------
// Round 2
// ---------------------------------------------------------------------------

/// One encrypted share entry in the Round 2 JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareWire {
    pub recipient_pool_id: String, // hex, 28 bytes
    pub recipient_frost_identifier: u16,
    pub ephemeral_pk: String,  // hex, 33 bytes
    pub ciphertext: String,    // hex, 32 bytes
    pub pad_commit: String,    // hex, 32 bytes
    pub evidence_hash: String, // hex, 32 bytes
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
    pub identifier: u16,
    pub bifrost_id_pk: &'a [u8],
    pub package: &'a round2::Package,
}

/// Build and sign this SPO's Round 2 payload: encrypt each recipient's
/// share under a fresh ephemeral key, order by `recipient_pool_id`, sign
/// the canonical bytes.
#[allow(clippy::too_many_arguments)]
pub fn build_round2<R: Rng + CryptoRng>(
    secp: &Secp256k1<All>,
    keypair: &Keypair,
    epoch: u64,
    threshold: u64,
    attempt: u64,
    my_pool_id: &[u8; POOL_ID_LEN],
    sender_commitments: &[[u8; POINT_LEN]],
    recipients: &[Round2Recipient],
    rng: &mut R,
) -> Result<Dkg2Wire, WireError> {
    let mut entries: Vec<ShareEntry> = Vec::with_capacity(recipients.len());
    for r in recipients {
        let share = frost_bridge::round2_share_bytes(r.package)?;
        let ephemeral_sk = SecretKey::new(rng);
        let (ephemeral_pk, ciphertext, pad) =
            auth::encrypt_share_with_pad(secp, &ephemeral_sk, r.bifrost_id_pk, &share)?;
        let evidence_hash = fault_evidence::round2_evidence_hash_from_fields_dyn(
            my_pool_id,
            r.identifier,
            sender_commitments,
            &share,
        )
        .map_err(|e| WireError::Field(format!("evidence_hash: {e}")))?;
        entries.push(ShareEntry {
            recipient_pool_id: r.pool_id,
            recipient_identifier: u64::from(r.identifier),
            ephemeral_pk,
            ciphertext,
            pad_commit: blake2b_256(&pad),
            evidence_hash,
        });
    }
    // Canonical ordering by recipient_pool_id; the JSON follows the same order.
    entries.sort_by_key(|e| e.recipient_pool_id);

    let canonical_bytes = canonical::round2(epoch, threshold, attempt, my_pool_id, &entries);
    let signature = auth::sign_payload(secp, keypair, &canonical_bytes);

    Ok(Dkg2Wire {
        shares: entries
            .iter()
            .map(|e| ShareWire {
                recipient_pool_id: hex::encode(e.recipient_pool_id),
                recipient_frost_identifier: u16::try_from(e.recipient_identifier)
                    .expect("recipient identifier came from u16"),
                ephemeral_pk: hex::encode(e.ephemeral_pk),
                ciphertext: hex::encode(e.ciphertext),
                pad_commit: hex::encode(e.pad_commit),
                evidence_hash: hex::encode(e.evidence_hash),
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
    my_identifier: u16,
    my_bifrost_sk: &SecretKey,
    sender_commitments: &[[u8; POINT_LEN]],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    wire: &Dkg2Wire,
) -> Result<round2::Package, WireError> {
    let evidence = round2_fault_evidence(
        secp,
        sender_pool_id,
        sender_bifrost_id_pk,
        my_pool_id,
        my_identifier,
        my_bifrost_sk,
        sender_commitments,
        epoch,
        threshold,
        attempt,
        wire,
    )?;
    if evidence
        .is_fault()
        .map_err(|e| fault_err("round2 share", e))?
    {
        return Err(WireError::Field(
            "round2 share is inconsistent with sender commitments".into(),
        ));
    }
    Ok(frost_bridge::round2_from_share(&evidence.share)?)
}

fn round2_entries(wire: &Dkg2Wire) -> Result<Vec<ShareEntry>, WireError> {
    let mut entries = Vec::with_capacity(wire.shares.len());
    for s in &wire.shares {
        entries.push(ShareEntry {
            recipient_pool_id: hex_n::<POOL_ID_LEN>(&s.recipient_pool_id, "recipient_pool_id")?,
            recipient_identifier: u64::from(s.recipient_frost_identifier),
            ephemeral_pk: hex_n::<POINT_LEN>(&s.ephemeral_pk, "ephemeral_pk")?,
            ciphertext: hex_n::<SHARE_LEN>(&s.ciphertext, "ciphertext")?,
            pad_commit: hex_n::<PAD_COMMIT_LEN>(&s.pad_commit, "pad_commit")?,
            evidence_hash: hex_n::<EVIDENCE_HASH_LEN>(&s.evidence_hash, "evidence_hash")?,
        });
    }
    Ok(entries)
}

/// Rebuild the signed Round 2 evidence envelope from a JSON payload addressed
/// to this SPO. This verifies the sender signature, decrypts this recipient's
/// share, checks the pad commitment and advertised `evidence_hash`, but does
/// not require the share to be bad. Call [`Round2ShareFaultEvidence::is_fault`]
/// before treating it as punishable.
#[allow(clippy::too_many_arguments)]
pub fn round2_fault_evidence(
    secp: &Secp256k1<All>,
    sender_pool_id: &[u8; POOL_ID_LEN],
    sender_bifrost_id_pk: &[u8],
    my_pool_id: &[u8; POOL_ID_LEN],
    my_identifier: u16,
    my_bifrost_sk: &SecretKey,
    sender_commitments: &[[u8; POINT_LEN]],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    wire: &Dkg2Wire,
) -> Result<Round2ShareFaultEvidence, WireError> {
    let entries = round2_entries(wire)?;
    let signature = hex_n::<SIG_LEN>(&wire.signature, "signature")?;
    let canonical_bytes = canonical::round2(epoch, threshold, attempt, sender_pool_id, &entries);
    auth::verify_payload(secp, sender_bifrost_id_pk, &canonical_bytes, &signature)?;

    let mine = entries
        .iter()
        .find(|e| &e.recipient_pool_id == my_pool_id)
        .ok_or(WireError::NoShareForUs)?;
    if mine.recipient_identifier != u64::from(my_identifier) {
        return Err(WireError::Field(
            "recipient_frost_identifier mismatch".into(),
        ));
    }
    let (share, pad) =
        auth::decrypt_share_with_pad(secp, my_bifrost_sk, &mine.ephemeral_pk, &mine.ciphertext)?;
    if blake2b_256(&pad) != mine.pad_commit {
        return Err(WireError::Field("pad_commit mismatch".into()));
    }

    let ev = Round2ShareFaultEvidence {
        epoch,
        threshold,
        attempt,
        accused_pool_id: *sender_pool_id,
        bifrost_id_pk: bifrost_pk_array(sender_bifrost_id_pk)?,
        recipient_index: my_identifier,
        sender_commitments: sender_commitments.to_vec(),
        share,
        round2_canonical_bytes: canonical_bytes,
        payload_signature: signature,
    };
    if fault_evidence::round2_evidence_hash_dyn(&ev).map_err(|e| fault_err("evidence_hash", e))?
        != mine.evidence_hash
    {
        return Err(WireError::Field("evidence_hash mismatch".into()));
    }
    Ok(ev)
}

/// The canonical bytes and signature from a Round 2 payload, suitable for an
/// equivocation proof.
pub fn round2_signed_payload(
    secp: &Secp256k1<All>,
    sender_pool_id: &[u8; POOL_ID_LEN],
    sender_bifrost_id_pk: &[u8],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    wire: &Dkg2Wire,
) -> Result<(Vec<u8>, [u8; SIG_LEN]), WireError> {
    let entries = round2_entries(wire)?;
    let signature = hex_n::<SIG_LEN>(&wire.signature, "signature")?;
    let canonical_bytes = canonical::round2(epoch, threshold, attempt, sender_pool_id, &entries);
    auth::verify_payload(secp, sender_bifrost_id_pk, &canonical_bytes, &signature)?;
    Ok((canonical_bytes, signature))
}

/// Build equivocation evidence from two already-fetched same-namespace Round 1
/// JSON payloads.
#[allow(clippy::too_many_arguments)]
pub fn round1_equivocation_evidence(
    peer_pool_id: &[u8; POOL_ID_LEN],
    peer_bifrost_id_pk: &[u8],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    a: &Dkg1Wire,
    b: &Dkg1Wire,
) -> Result<EquivocationEvidence, WireError> {
    let (payload_a, signature_a) = round1_signed_payload(
        peer_pool_id,
        peer_bifrost_id_pk,
        epoch,
        threshold,
        attempt,
        a,
    )?;
    let (payload_b, signature_b) = round1_signed_payload(
        peer_pool_id,
        peer_bifrost_id_pk,
        epoch,
        threshold,
        attempt,
        b,
    )?;
    let ev = EquivocationEvidence {
        epoch,
        threshold,
        attempt,
        phase: NamespacePhase::Round1,
        accused_pool_id: *peer_pool_id,
        bifrost_id_pk: bifrost_pk_array(peer_bifrost_id_pk)?,
        payload_a,
        signature_a,
        payload_b,
        signature_b,
    };
    ev.verify()
        .map_err(|e| fault_err("round1 equivocation", e))?;
    Ok(ev)
}

/// Build equivocation evidence from two already-fetched same-namespace Round 2
/// JSON payloads.
#[allow(clippy::too_many_arguments)]
pub fn round2_equivocation_evidence(
    secp: &Secp256k1<All>,
    sender_pool_id: &[u8; POOL_ID_LEN],
    sender_bifrost_id_pk: &[u8],
    epoch: u64,
    threshold: u64,
    attempt: u64,
    a: &Dkg2Wire,
    b: &Dkg2Wire,
) -> Result<EquivocationEvidence, WireError> {
    let (payload_a, signature_a) = round2_signed_payload(
        secp,
        sender_pool_id,
        sender_bifrost_id_pk,
        epoch,
        threshold,
        attempt,
        a,
    )?;
    let (payload_b, signature_b) = round2_signed_payload(
        secp,
        sender_pool_id,
        sender_bifrost_id_pk,
        epoch,
        threshold,
        attempt,
        b,
    )?;
    let ev = EquivocationEvidence {
        epoch,
        threshold,
        attempt,
        phase: NamespacePhase::Round2,
        accused_pool_id: *sender_pool_id,
        bifrost_id_pk: bifrost_pk_array(sender_bifrost_id_pk)?,
        payload_a,
        signature_a,
        payload_b,
        signature_b,
    };
    ev.verify()
        .map_err(|e| fault_err("round2 equivocation", e))?;
    Ok(ev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use bitcoin::secp256k1::rand::rngs::OsRng;
    use frost::Identifier;
    use frost::keys::dkg;
    use frost_secp256k1_tr as frost;

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

        let wire = build_round1(&secp, &kp, 9, canonical::THRESHOLD_51, 0, &pool, 1, &pkg).unwrap();
        assert_eq!(wire.commitment.len(), 2);
        assert_eq!(
            hex::decode(&wire.poseidon_commit).unwrap().len(),
            EVIDENCE_HASH_LEN
        );

        let parsed = verify_round1(
            &secp,
            &pool,
            &xonly,
            9,
            canonical::THRESHOLD_51,
            0,
            1,
            &wire,
        )
        .unwrap();
        assert_eq!(parsed, pkg);
    }

    #[test]
    fn round1_verify_rejects_wrong_namespace() {
        let secp = Secp256k1::new();
        let (_sk, kp, xonly) = keypair(&secp);
        let pool = [3u8; POOL_ID_LEN];
        let (_s, pkg) = dkg::part1(id(1), 3, 2, OsRng).unwrap();
        let wire = build_round1(&secp, &kp, 9, canonical::THRESHOLD_51, 0, &pool, 1, &pkg).unwrap();

        // Wrong epoch -> different canonical bytes -> signature must fail.
        let err = verify_round1(
            &secp,
            &pool,
            &xonly,
            10,
            canonical::THRESHOLD_51,
            0,
            1,
            &wire,
        );
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
        let (s1, p1) = dkg::part1(id(1), 2, 2, OsRng).unwrap();
        let (_s2, p2) = dkg::part1(id(2), 2, 2, OsRng).unwrap();
        let (sender_commitments, _sigma_i) = frost_bridge::round1_fields(&p1).unwrap();
        let mut r1 = BTreeMap::new();
        r1.insert(id(2), p2);
        let (_s1r2, pkgs) = dkg::part2(s1, &r1).unwrap();
        let pkg_for_2 = pkgs.get(&id(2)).unwrap();

        let recipients = vec![Round2Recipient {
            pool_id: pool2,
            identifier: 2,
            bifrost_id_pk: &x2,
            package: pkg_for_2,
        }];
        let wire = build_round2(
            &secp,
            &kp1,
            9,
            canonical::THRESHOLD_51,
            0,
            &pool1,
            &sender_commitments,
            &recipients,
            &mut OsRng,
        )
        .unwrap();

        let parsed = verify_round2(
            &secp,
            &pool1,
            &keypair_xonly(&secp, &kp1),
            &pool2,
            2,
            &sk2,
            &sender_commitments,
            9,
            canonical::THRESHOLD_51,
            0,
            &wire,
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
        let (s1, p1) = dkg::part1(id(1), 2, 2, OsRng).unwrap();
        let (_s2, p2) = dkg::part1(id(2), 2, 2, OsRng).unwrap();
        let (sender_commitments, _sigma_i) = frost_bridge::round1_fields(&p1).unwrap();
        let mut r1 = BTreeMap::new();
        r1.insert(id(2), p2);
        let (_s1r2, pkgs) = dkg::part2(s1, &r1).unwrap();
        let recipients = vec![Round2Recipient {
            pool_id: pool2,
            identifier: 2,
            bifrost_id_pk: &x2,
            package: pkgs.get(&id(2)).unwrap(),
        }];
        let mut wire = build_round2(
            &secp,
            &kp1,
            9,
            canonical::THRESHOLD_51,
            0,
            &pool1,
            &sender_commitments,
            &recipients,
            &mut OsRng,
        )
        .unwrap();

        // Flip a byte in the ciphertext: signature no longer matches canonical bytes.
        let mut ct = hex::decode(&wire.shares[0].ciphertext).unwrap();
        ct[0] ^= 0xff;
        wire.shares[0].ciphertext = hex::encode(ct);

        let err = verify_round2(
            &secp,
            &pool1,
            &kp1.x_only_public_key().0.serialize(),
            &pool2,
            2,
            &sk2,
            &sender_commitments,
            9,
            canonical::THRESHOLD_51,
            0,
            &wire,
        );
        assert!(matches!(err, Err(WireError::Auth(_))));
    }
}
