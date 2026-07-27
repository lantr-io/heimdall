//! Canonical byte layouts for DKG payload authentication.
//!
//! The spec authenticates each DKG payload with a BIP-340 Schnorr
//! signature over `SHA256(canonical_bytes)`, **not** over the JSON. The
//! same bytes are what a Cardano validator reconstructs to verify
//! misbehavior proofs (`verifySchnorrSecp256k1Signature` on the hash),
//! so the layout is fixed and every party — publisher, peers, on-chain
//! verifier — must reproduce it byte-for-byte. JSON is transport only.
//!
//! Layouts (FluidTokens `technical_documentation.md` §6.1, §7.3):
//!
//! ```text
//! r1: "bifrost-dkg-r1" || epoch(8 BE) || threshold(8 BE) || attempt(8 BE)
//!       || pool_id(28) || φ_0(33) || … || φ_{t-1}(33) || σ_i(64)
//!       || evidence_hash(32)
//! r2: "bifrost-dkg-r2" || epoch(8 BE) || threshold(8 BE) || attempt(8 BE)
//!       || pool_id(28)
//!       || [recipient(28) || recipient_id(8 BE) || ephemeral_pk(33)
//!           || ciphertext(32) || pad_commit(32) || evidence_hash(32)] × m
//! ```
//!
//! Round 2 share entries are ordered by `recipient_pool_id`
//! (lexicographic) for determinism.

/// `blake2b_224(cold_vkey)` membership id — the spec `pool_id`.
pub const POOL_ID_LEN: usize = 28;
/// Compressed secp256k1 point (commitment coefficient / ephemeral key).
pub const POINT_LEN: usize = 33;
/// BIP-340 signature, and the FROST proof-of-knowledge σ_i.
pub const SIG_LEN: usize = 64;
/// Encrypted share — a 32-byte secp256k1 scalar XOR the HKDF key.
pub const SHARE_LEN: usize = 32;
/// Circuit public input 0 and token-name evidence component.
pub const EVIDENCE_HASH_LEN: usize = 32;
/// Blake2b-256 commitment to the one-time pad that opens a Round 2 ciphertext.
pub const PAD_COMMIT_LEN: usize = 32;

/// The fixed DKG threshold *label* in URLs and canonical bytes — the
/// ">51% stake" DKG, one per epoch. This is NOT the computed
/// `min_signers` `t`; it is a constant namespace tag.
pub const THRESHOLD_51: u64 = 51;

const TAG_R1: &[u8] = b"bifrost-dkg-r1";
const TAG_R2: &[u8] = b"bifrost-dkg-r2";

/// `epoch || threshold || attempt || pool_id` — the namespace header
/// shared by both round layouts (each integer 8-byte big-endian).
fn push_header(
    out: &mut Vec<u8>,
    epoch: u64,
    threshold: u64,
    attempt: u64,
    pool_id: &[u8; POOL_ID_LEN],
) {
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&threshold.to_be_bytes());
    out.extend_from_slice(&attempt.to_be_bytes());
    out.extend_from_slice(pool_id);
}

/// Round 1 canonical bytes: the publisher's commitment vector and PoK
/// bound to the `(epoch, threshold, attempt, pool_id)` namespace.
pub fn round1(
    epoch: u64,
    threshold: u64,
    attempt: u64,
    pool_id: &[u8; POOL_ID_LEN],
    commitment: &[[u8; POINT_LEN]],
    sigma_i: &[u8; SIG_LEN],
    evidence_hash: &[u8; EVIDENCE_HASH_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        TAG_R1.len()
            + 24
            + POOL_ID_LEN
            + commitment.len() * POINT_LEN
            + SIG_LEN
            + EVIDENCE_HASH_LEN,
    );
    out.extend_from_slice(TAG_R1);
    push_header(&mut out, epoch, threshold, attempt, pool_id);
    for phi in commitment {
        out.extend_from_slice(phi);
    }
    out.extend_from_slice(sigma_i);
    out.extend_from_slice(evidence_hash);
    out
}

/// One encrypted-share entry, addressed to a single recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEntry {
    pub recipient_pool_id: [u8; POOL_ID_LEN],
    pub recipient_identifier: u64,
    pub ephemeral_pk: [u8; POINT_LEN],
    pub ciphertext: [u8; SHARE_LEN],
    pub pad_commit: [u8; PAD_COMMIT_LEN],
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
}

/// Round 2 canonical bytes. `shares` may be in any order — this sorts a
/// copy by `recipient_pool_id` so the output is deterministic regardless
/// of caller ordering (the same rule the JSON wire form follows).
pub fn round2(
    epoch: u64,
    threshold: u64,
    attempt: u64,
    pool_id: &[u8; POOL_ID_LEN],
    shares: &[ShareEntry],
) -> Vec<u8> {
    let mut sorted: Vec<&ShareEntry> = shares.iter().collect();
    sorted.sort_by_key(|e| e.recipient_pool_id);
    let entry_len = POOL_ID_LEN + 8 + POINT_LEN + SHARE_LEN + PAD_COMMIT_LEN + EVIDENCE_HASH_LEN;
    let mut out = Vec::with_capacity(TAG_R2.len() + 24 + POOL_ID_LEN + sorted.len() * entry_len);
    out.extend_from_slice(TAG_R2);
    push_header(&mut out, epoch, threshold, attempt, pool_id);
    for s in sorted {
        out.extend_from_slice(&s.recipient_pool_id);
        out.extend_from_slice(&s.recipient_identifier.to_be_bytes());
        out.extend_from_slice(&s.ephemeral_pk);
        out.extend_from_slice(&s.ciphertext);
        out.extend_from_slice(&s.pad_commit);
        out.extend_from_slice(&s.evidence_hash);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG_LEN: usize = 14; // "bifrost-dkg-rN"
    const HEADER_LEN: usize = TAG_LEN + 24 + POOL_ID_LEN;

    fn pid(b: u8) -> [u8; POOL_ID_LEN] {
        [b; POOL_ID_LEN]
    }

    #[test]
    fn round1_length_and_prefix() {
        let t = 3;
        let commitment = vec![[7u8; POINT_LEN]; t];
        let sigma = [9u8; SIG_LEN];
        let evidence_hash = [8u8; EVIDENCE_HASH_LEN];
        let bytes = round1(
            42,
            THRESHOLD_51,
            0,
            &pid(1),
            &commitment,
            &sigma,
            &evidence_hash,
        );

        assert_eq!(&bytes[..TAG_LEN], TAG_R1);
        assert_eq!(
            bytes.len(),
            HEADER_LEN + t * POINT_LEN + SIG_LEN + EVIDENCE_HASH_LEN
        );
        // epoch big-endian right after the tag
        assert_eq!(&bytes[TAG_LEN..TAG_LEN + 8], &42u64.to_be_bytes());
        // threshold == 51
        assert_eq!(
            &bytes[TAG_LEN + 8..TAG_LEN + 16],
            &THRESHOLD_51.to_be_bytes()
        );
        assert_eq!(
            &bytes[bytes.len() - SIG_LEN - EVIDENCE_HASH_LEN..bytes.len() - EVIDENCE_HASH_LEN],
            &sigma
        );
        assert_eq!(&bytes[bytes.len() - EVIDENCE_HASH_LEN..], &evidence_hash);
    }

    #[test]
    fn round2_length_and_sorted() {
        let shares = vec![
            ShareEntry {
                recipient_pool_id: pid(3),
                recipient_identifier: 3,
                ephemeral_pk: [1; POINT_LEN],
                ciphertext: [1; SHARE_LEN],
                pad_commit: [4; PAD_COMMIT_LEN],
                evidence_hash: [5; EVIDENCE_HASH_LEN],
            },
            ShareEntry {
                recipient_pool_id: pid(1),
                recipient_identifier: 1,
                ephemeral_pk: [2; POINT_LEN],
                ciphertext: [2; SHARE_LEN],
                pad_commit: [6; PAD_COMMIT_LEN],
                evidence_hash: [7; EVIDENCE_HASH_LEN],
            },
            ShareEntry {
                recipient_pool_id: pid(2),
                recipient_identifier: 2,
                ephemeral_pk: [3; POINT_LEN],
                ciphertext: [3; SHARE_LEN],
                pad_commit: [8; PAD_COMMIT_LEN],
                evidence_hash: [9; EVIDENCE_HASH_LEN],
            },
        ];
        let bytes = round2(7, THRESHOLD_51, 1, &pid(9), &shares);
        let entry_len =
            POOL_ID_LEN + 8 + POINT_LEN + SHARE_LEN + PAD_COMMIT_LEN + EVIDENCE_HASH_LEN;

        assert_eq!(&bytes[..TAG_LEN], TAG_R2);
        assert_eq!(bytes.len(), HEADER_LEN + shares.len() * entry_len);
        // attempt == 1
        assert_eq!(&bytes[TAG_LEN + 16..TAG_LEN + 24], &1u64.to_be_bytes());
        // first entry's recipient must be the lexicographically smallest (pid 1)
        let first_recipient = &bytes[HEADER_LEN..HEADER_LEN + POOL_ID_LEN];
        assert_eq!(first_recipient, &pid(1));
    }

    #[test]
    fn round2_independent_of_input_order() {
        let a = ShareEntry {
            recipient_pool_id: pid(1),
            recipient_identifier: 1,
            ephemeral_pk: [2; POINT_LEN],
            ciphertext: [2; SHARE_LEN],
            pad_commit: [3; PAD_COMMIT_LEN],
            evidence_hash: [4; EVIDENCE_HASH_LEN],
        };
        let b = ShareEntry {
            recipient_pool_id: pid(2),
            recipient_identifier: 2,
            ephemeral_pk: [3; POINT_LEN],
            ciphertext: [3; SHARE_LEN],
            pad_commit: [4; PAD_COMMIT_LEN],
            evidence_hash: [5; EVIDENCE_HASH_LEN],
        };
        let forward = round2(1, THRESHOLD_51, 0, &pid(0), &[a.clone(), b.clone()]);
        let reversed = round2(1, THRESHOLD_51, 0, &pid(0), &[b, a]);
        assert_eq!(forward, reversed);
    }
}
