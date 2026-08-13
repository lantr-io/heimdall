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
//!
//! The signing ceremony's two rounds are authenticated the same way (WI-038).
//! They are NOT in the upstream spec document — the spec covers DKG payloads
//! only — so the layouts below are heimdall's, deliberately built to the same
//! shape so one verifier idiom covers both:
//!
//! ```text
//! s1: "bifrost-sign-r1" || epoch(8 BE) || session(8 BE) || pool_id(28)
//!       || identifier(8 BE) || message(32) || hiding(33) || binding(33)
//! s2: "bifrost-sign-r2" || epoch(8 BE) || session(8 BE) || pool_id(28)
//!       || identifier(8 BE) || message(32) || share(32)
//! ```
//!
//! `session` is the FROST session within the epoch (a TM input index, or the
//! reserved rotation session). `message` is the exact 32 bytes the session
//! signs — the input's BIP-341 sighash, or the Update-Y preimage hash.
//!
//! **Why `message` is in the layout.** `(epoch, session)` alone does not pin a
//! payload to a ceremony: an epoch runs many treasury movements, each with an
//! input 0, so a commitment captured from one TM would replay into the next
//! under the same namespace. Binding the message makes every signing session
//! its own domain. Both sides already hold it — a verifier only ever checks a
//! session it is itself participating in — so this costs nothing.
//!
//! `identifier` is bound because aggregation keys shares by it. A roster
//! change renumbers participants (indices are positional), and without this a
//! payload could be accepted into the wrong signer slot.

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

/// The namespace label of the FEDERATION key ceremony (WI-087) — the
/// genesis-time DKG that produces `Y_federation`.
///
/// A second label rather than a second epoch number, because the federation
/// ceremony has no epoch to number: it runs *before* the bridge exists. Zero
/// says what it is — the epoch DKG's label is the stake share it needs, and
/// this ceremony is weighted by nothing at all.
///
/// It sits inside the signed canonical bytes, not only in the URL path, so a
/// Round-1 package from an epoch ceremony can never be replayed into a
/// federation one however the two are scheduled — a real risk, since the two use
/// the same transport, the same routes and (for an SPO that is also a federation
/// member) the same identity key.
pub const THRESHOLD_FEDERATION: u64 = 0;

/// The 32-byte message one FROST signing session signs.
pub const SIGN_MESSAGE_LEN: usize = 32;

const TAG_R1: &[u8] = b"bifrost-dkg-r1";
const TAG_R2: &[u8] = b"bifrost-dkg-r2";
const TAG_S1: &[u8] = b"bifrost-sign-r1";
const TAG_S2: &[u8] = b"bifrost-sign-r2";

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

// ---------------------------------------------------------------------------
// Signing rounds
// ---------------------------------------------------------------------------

/// `epoch || session || pool_id || identifier || message` — the header shared
/// by both signing-round layouts (integers 8-byte big-endian).
fn push_sign_header(
    out: &mut Vec<u8>,
    epoch: u64,
    session: u32,
    pool_id: &[u8; POOL_ID_LEN],
    identifier: u64,
    message: &[u8; SIGN_MESSAGE_LEN],
) {
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&u64::from(session).to_be_bytes());
    out.extend_from_slice(pool_id);
    out.extend_from_slice(&identifier.to_be_bytes());
    out.extend_from_slice(message);
}

const SIGN_HEADER_LEN: usize = 8 + 8 + POOL_ID_LEN + 8 + SIGN_MESSAGE_LEN;

/// Signing Round 1 canonical bytes: this signer's two nonce commitments,
/// bound to the `(epoch, session, pool_id, identifier, message)` domain.
pub fn sign_round1(
    epoch: u64,
    session: u32,
    pool_id: &[u8; POOL_ID_LEN],
    identifier: u64,
    message: &[u8; SIGN_MESSAGE_LEN],
    hiding: &[u8; POINT_LEN],
    binding: &[u8; POINT_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_S1.len() + SIGN_HEADER_LEN + 2 * POINT_LEN);
    out.extend_from_slice(TAG_S1);
    push_sign_header(&mut out, epoch, session, pool_id, identifier, message);
    out.extend_from_slice(hiding);
    out.extend_from_slice(binding);
    out
}

/// Signing Round 2 canonical bytes: this signer's signature share, bound to
/// the same domain as its Round 1 commitments.
pub fn sign_round2(
    epoch: u64,
    session: u32,
    pool_id: &[u8; POOL_ID_LEN],
    identifier: u64,
    message: &[u8; SIGN_MESSAGE_LEN],
    share: &[u8; SHARE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TAG_S2.len() + SIGN_HEADER_LEN + SHARE_LEN);
    out.extend_from_slice(TAG_S2);
    push_sign_header(&mut out, epoch, session, pool_id, identifier, message);
    out.extend_from_slice(share);
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

    // -- signing rounds (WI-038) -------------------------------------------

    const SIGN_TAG_LEN: usize = 15; // "bifrost-sign-rN"

    fn s1(epoch: u64, session: u32, id: u64, msg: [u8; 32]) -> Vec<u8> {
        sign_round1(
            epoch,
            session,
            &pid(1),
            id,
            &msg,
            &[0xaa; POINT_LEN],
            &[0xbb; POINT_LEN],
        )
    }

    #[test]
    fn sign_round1_length_and_prefix() {
        let bytes = s1(9, 2, 5, [0x11; 32]);
        assert_eq!(&bytes[..SIGN_TAG_LEN], TAG_S1);
        assert_eq!(bytes.len(), SIGN_TAG_LEN + SIGN_HEADER_LEN + 2 * POINT_LEN);
        assert_eq!(
            &bytes[SIGN_TAG_LEN..SIGN_TAG_LEN + 8],
            &9u64.to_be_bytes(),
            "epoch big-endian right after the tag"
        );
        assert_eq!(
            &bytes[SIGN_TAG_LEN + 8..SIGN_TAG_LEN + 16],
            &2u64.to_be_bytes(),
            "session next"
        );
        assert_eq!(
            &bytes[bytes.len() - 2 * POINT_LEN..bytes.len() - POINT_LEN],
            &[0xaa; POINT_LEN],
            "hiding then binding"
        );
    }

    /// The whole point of the layout: every field that identifies a signing
    /// session changes the bytes, so a signature over one session's payload
    /// cannot be replayed into another.
    #[test]
    fn every_sign_round1_domain_field_changes_the_bytes() {
        let base = s1(9, 2, 5, [0x11; 32]);
        assert_ne!(base, s1(10, 2, 5, [0x11; 32]), "epoch");
        assert_ne!(base, s1(9, 3, 5, [0x11; 32]), "session");
        assert_ne!(base, s1(9, 2, 6, [0x11; 32]), "identifier");
        assert_ne!(base, s1(9, 2, 5, [0x12; 32]), "message");
        assert_ne!(
            base,
            sign_round1(
                9,
                2,
                &pid(2),
                5,
                &[0x11; 32],
                &[0xaa; POINT_LEN],
                &[0xbb; POINT_LEN]
            ),
            "pool_id"
        );
    }

    #[test]
    fn sign_round2_length_and_prefix() {
        let bytes = sign_round2(9, 2, &pid(1), 5, &[0x11; 32], &[0xcc; SHARE_LEN]);
        assert_eq!(&bytes[..SIGN_TAG_LEN], TAG_S2);
        assert_eq!(bytes.len(), SIGN_TAG_LEN + SIGN_HEADER_LEN + SHARE_LEN);
        assert_eq!(&bytes[bytes.len() - SHARE_LEN..], &[0xcc; SHARE_LEN]);
    }

    /// Namespace separation across all four round tags: no two rounds can ever
    /// produce identical canonical bytes, so a signature is only ever valid for
    /// the round it was made in.
    #[test]
    fn round_tags_are_mutually_distinct() {
        let tags = [TAG_R1, TAG_R2, TAG_S1, TAG_S2];
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b);
                // No tag may prefix another, or the remaining fields could be
                // shifted to forge a match across rounds.
                assert!(!a.starts_with(b) && !b.starts_with(a));
            }
        }
    }
}
