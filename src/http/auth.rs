//! Payload authentication and per-recipient share encryption.
//!
//! Two independent crypto primitives the spec layers on the DKG wire
//! format, both keyed by the SPO's **bifrost identity key** (the x-only
//! secp256k1 key bound on-chain at registration):
//!
//! 1. **Authentication** — every payload carries a BIP-340 Schnorr
//!    signature over `SHA256(canonical_bytes)` (see [`super::canonical`]).
//!    The same hash+signature is what a Cardano validator checks for
//!    misbehavior proofs, so we sign the canonical bytes, never the JSON.
//!
//! 2. **Share encryption** — Round 2 shares are encrypted per recipient:
//!    `ss = ECDH(ephemeral_sk, bifrost_id_pk_l)`,
//!    `k  = HKDF-SHA256(ss, info = "bifrost-dkg-share")`,
//!    `ciphertext = f_i(l) XOR k`.
//!
//! All crypto uses `bitcoin::secp256k1` (libsecp256k1) — the same crate
//! that generated the bifrost keys at registration.
//!
//! ## ECDH detail (parity-robust)
//!
//! `bifrost_id_pk` is stored x-only (the even-Y point, BIP-340
//! convention), but a peer's actual secret may correspond to an odd-Y
//! point. We therefore take **only the x-coordinate** of the shared
//! point as `ss`: the sender computes `x(e · lift_even(pk_l))` and the
//! recipient `x(s_l · E)`, which are negatives of each other exactly
//! when `s_l·G` is odd-Y — and negation preserves the x-coordinate. So
//! both sides derive the same `ss` regardless of key parity. (This is
//! why we cannot use `secp256k1`'s default `SharedSecret`, which hashes
//! the *compressed* point including its parity byte.)
//!
//! Note: the exact `ss`/HKDF construction has no upstream reference
//! implementation yet (FluidTokens' offchain DKG is a placeholder); it
//! is defined here pending confirmation — see `technical_questions.md`.

use bitcoin::secp256k1::{
    All, Keypair, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey, schnorr,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use super::canonical::{POINT_LEN, SHARE_LEN, SIG_LEN};

/// HKDF `info` tag binding the derived key to this protocol + purpose.
const SHARE_INFO: &[u8] = b"bifrost-dkg-share";

#[derive(Debug)]
pub enum AuthError {
    /// The BIP-340 signature did not verify against the expected key.
    VerifyFailed,
    /// A public key (x-only or compressed) was malformed.
    BadKey(String),
    /// A signature was not 64 well-formed bytes.
    BadSig(String),
    /// ECDH failed (secret out of range / point at infinity — negligible).
    Ecdh(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifyFailed => write!(f, "BIP-340 signature verification failed"),
            Self::BadKey(s) => write!(f, "bad public key: {s}"),
            Self::BadSig(s) => write!(f, "bad signature: {s}"),
            Self::Ecdh(s) => write!(f, "ECDH failed: {s}"),
        }
    }
}

impl std::error::Error for AuthError {}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// BIP-340 sign `SHA256(canonical_bytes)` with this SPO's bifrost
/// identity keypair. Returns the 64-byte signature for the payload's
/// `signature` field.
pub fn sign_payload(
    secp: &Secp256k1<All>,
    keypair: &Keypair,
    canonical_bytes: &[u8],
) -> [u8; SIG_LEN] {
    let msg = Message::from_digest(sha256(canonical_bytes));
    secp.sign_schnorr_no_aux_rand(&msg, keypair).serialize()
}

/// Verify a payload's BIP-340 signature against a peer's x-only
/// `bifrost_id_pk`. The caller must additionally confirm the key belongs
/// to the peer it expected (the registry binds `pool_id → bifrost_id_pk`).
pub fn verify_payload(
    secp: &Secp256k1<All>,
    bifrost_id_pk: &[u8],
    canonical_bytes: &[u8],
    signature: &[u8; SIG_LEN],
) -> Result<(), AuthError> {
    let xonly =
        XOnlyPublicKey::from_slice(bifrost_id_pk).map_err(|e| AuthError::BadKey(e.to_string()))?;
    let sig =
        schnorr::Signature::from_slice(signature).map_err(|e| AuthError::BadSig(e.to_string()))?;
    let msg = Message::from_digest(sha256(canonical_bytes));
    secp.verify_schnorr(&sig, &msg, &xonly)
        .map_err(|_| AuthError::VerifyFailed)
}

// ---------------------------------------------------------------------------
// Share encryption (ECDH + HKDF)
// ---------------------------------------------------------------------------

/// x-coordinate of `sk · point` — the parity-robust ECDH output.
fn ecdh_x(secp: &Secp256k1<All>, sk: &SecretKey, point: &PublicKey) -> Result<[u8; 32], AuthError> {
    let scalar = Scalar::from_be_bytes(sk.secret_bytes())
        .map_err(|_| AuthError::Ecdh("secret scalar out of range".into()))?;
    let shared = point
        .mul_tweak(secp, &scalar)
        .map_err(|e| AuthError::Ecdh(e.to_string()))?;
    Ok(shared.x_only_public_key().0.serialize())
}

/// HKDF-SHA256 expand the shared secret to a 32-byte one-time pad.
fn share_key(ss: &[u8; 32]) -> [u8; SHARE_LEN] {
    let hk = Hkdf::<Sha256>::new(None, ss);
    let mut okm = [0u8; SHARE_LEN];
    hk.expand(SHARE_INFO, &mut okm)
        .expect("SHARE_LEN is a valid HKDF-SHA256 output length");
    okm
}

fn xor32(a: &[u8; SHARE_LEN], b: &[u8; SHARE_LEN]) -> [u8; SHARE_LEN] {
    let mut out = [0u8; SHARE_LEN];
    for i in 0..SHARE_LEN {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Encrypt one share `f_i(l)` for recipient `l`, given a freshly
/// generated ephemeral secret. Returns `(ephemeral_pk, ciphertext)` —
/// the 33-byte compressed `E_i` and the 32-byte XOR ciphertext.
pub fn encrypt_share(
    secp: &Secp256k1<All>,
    ephemeral_sk: &SecretKey,
    recipient_bifrost_id_pk: &[u8],
    share: &[u8; SHARE_LEN],
) -> Result<([u8; POINT_LEN], [u8; SHARE_LEN]), AuthError> {
    let recipient_point = XOnlyPublicKey::from_slice(recipient_bifrost_id_pk)
        .map_err(|e| AuthError::BadKey(e.to_string()))?
        .public_key(Parity::Even);
    let ss = ecdh_x(secp, ephemeral_sk, &recipient_point)?;
    let ciphertext = xor32(share, &share_key(&ss));
    let ephemeral_pk = PublicKey::from_secret_key(secp, ephemeral_sk).serialize();
    Ok((ephemeral_pk, ciphertext))
}

/// Decrypt a share addressed to us, using our bifrost identity secret
/// and the sender's ephemeral public key.
pub fn decrypt_share(
    secp: &Secp256k1<All>,
    my_bifrost_sk: &SecretKey,
    ephemeral_pk: &[u8; POINT_LEN],
    ciphertext: &[u8; SHARE_LEN],
) -> Result<[u8; SHARE_LEN], AuthError> {
    let e = PublicKey::from_slice(ephemeral_pk).map_err(|e| AuthError::BadKey(e.to_string()))?;
    let ss = ecdh_x(secp, my_bifrost_sk, &e)?;
    Ok(xor32(ciphertext, &share_key(&ss)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;

    fn keypair(secp: &Secp256k1<All>) -> (SecretKey, Keypair, [u8; 32]) {
        let (sk, _pk) = secp.generate_keypair(&mut OsRng);
        let kp = Keypair::from_secret_key(secp, &sk);
        let xonly = kp.x_only_public_key().0.serialize();
        (sk, kp, xonly)
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let secp = Secp256k1::new();
        let (_sk, kp, xonly) = keypair(&secp);
        let canonical = b"some-canonical-bytes-to-authenticate".to_vec();
        let sig = sign_payload(&secp, &kp, &canonical);
        assert!(verify_payload(&secp, &xonly, &canonical, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let secp = Secp256k1::new();
        let (_sk, kp, _xonly) = keypair(&secp);
        let (_sk2, _kp2, other_xonly) = keypair(&secp);
        let canonical = b"payload".to_vec();
        let sig = sign_payload(&secp, &kp, &canonical);
        assert!(matches!(
            verify_payload(&secp, &other_xonly, &canonical, &sig),
            Err(AuthError::VerifyFailed)
        ));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let secp = Secp256k1::new();
        let (_sk, kp, xonly) = keypair(&secp);
        let sig = sign_payload(&secp, &kp, b"original");
        assert!(verify_payload(&secp, &xonly, b"tampered", &sig).is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secp = Secp256k1::new();
        // Recipient identity key (x-only, as stored in the registry).
        let (recipient_sk, _recipient_kp, recipient_xonly) = keypair(&secp);
        // Sender's fresh ephemeral key for this share.
        let (ephemeral_sk, _e_kp, _e_xonly) = keypair(&secp);

        let share = [42u8; SHARE_LEN];
        let (ephemeral_pk, ciphertext) =
            encrypt_share(&secp, &ephemeral_sk, &recipient_xonly, &share).unwrap();
        let recovered = decrypt_share(&secp, &recipient_sk, &ephemeral_pk, &ciphertext).unwrap();
        assert_eq!(recovered, share, "decrypt must recover the original share");
        assert_ne!(ciphertext, share, "ciphertext must differ from plaintext");
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        let secp = Secp256k1::new();
        let (_recipient_sk, _kp, recipient_xonly) = keypair(&secp);
        let (attacker_sk, _akp, _axonly) = keypair(&secp);
        let (ephemeral_sk, _ekp, _exonly) = keypair(&secp);

        let share = [7u8; SHARE_LEN];
        let (ephemeral_pk, ciphertext) =
            encrypt_share(&secp, &ephemeral_sk, &recipient_xonly, &share).unwrap();
        let wrong = decrypt_share(&secp, &attacker_sk, &ephemeral_pk, &ciphertext).unwrap();
        assert_ne!(
            wrong, share,
            "a different secret must not recover the share"
        );
    }
}
