//! Signing-round payload authentication (WI-038).
//!
//! The DKG rounds have been authenticated since WI-013; the signing rounds were
//! plain JSON that anyone could produce or alter in flight. These tests pin the
//! guarantees the authenticated wire now provides: a payload is bound to its
//! signer AND to the exact session it was made for, so it can be attributed and
//! cannot be moved anywhere else.

use std::collections::BTreeMap;

use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{All, Keypair, Secp256k1};
use frost_secp256k1_tr::{self as frost, Identifier};
use heimdall::frost::participant;
use heimdall::http::canonical::POOL_ID_LEN;
use heimdall::http::wire::{
    SignNamespace, build_sign_round1, build_sign_round2, verify_sign_round1, verify_sign_round2,
};

/// A 2-of-3 group. These tests exercise payload authentication, not the DKG, so
/// the dealer is used — the key material only has to be well-formed.
fn key_packages() -> BTreeMap<Identifier, frost::keys::KeyPackage> {
    let mut rng = rand::thread_rng();
    let (shares, _pkp) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
            .unwrap();
    shares
        .into_iter()
        .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
        .collect()
}

/// A signer's bifrost identity: the keypair it authenticates payloads with, its
/// registry-bound x-only key, and its pool id.
struct Identity {
    keypair: Keypair,
    xonly: [u8; 32],
    pool_id: [u8; POOL_ID_LEN],
}

fn identity(secp: &Secp256k1<All>, tag: u8) -> Identity {
    let (sk, _) = secp.generate_keypair(&mut OsRng);
    let keypair = Keypair::from_secret_key(secp, &sk);
    Identity {
        xonly: keypair.x_only_public_key().0.serialize(),
        keypair,
        pool_id: [tag; POOL_ID_LEN],
    }
}

/// A namespace at the first batch opportunity — what almost every case here
/// needs, since the sequence only matters where two ATTEMPTS are compared.
fn ns(epoch: u64, session: u32, msg: u8) -> SignNamespace {
    ns_at(epoch, 1, session, msg)
}

/// A namespace at a named batch sequence.
fn ns_at(epoch: u64, sequence: u64, session: u32, msg: u8) -> SignNamespace {
    SignNamespace::new(epoch, sequence, session, [msg; 32])
}

/// One signer's commitments for a session.
fn commitments(
    kps: &BTreeMap<Identifier, frost::keys::KeyPackage>,
    id: Identifier,
) -> frost::round1::SigningCommitments {
    let mut rng = rand::thread_rng();
    participant::sign_round1(&kps[&id], &mut rng).1
}

/// A real signature share over `message` from a 2-signer session.
fn signature_share(
    kps: &BTreeMap<Identifier, frost::keys::KeyPackage>,
    signer: Identifier,
    message: &[u8],
) -> frost::round2::SignatureShare {
    let mut rng = rand::thread_rng();
    let signers: Vec<Identifier> = kps.keys().take(2).copied().collect();
    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for &id in &signers {
        let (n, c) = participant::sign_round1(&kps[&id], &mut rng);
        nonces.insert(id, n);
        comms.insert(id, c);
    }
    let package = frost::SigningPackage::new(comms, message);
    participant::sign_round2(&package, &nonces[&signer], &kps[&signer]).unwrap()
}

// ---------------------------------------------------------------------------
// Round 1
// ---------------------------------------------------------------------------

#[test]
fn round1_survives_json_and_verifies_under_the_signers_key() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xA1);
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let c = commitments(&kps, id);
    let namespace = ns(42, 0, 0x11);

    let wire = build_sign_round1(&secp, &me.keypair, namespace, &me.pool_id, 1, &c).unwrap();
    // The signature travels as JSON; verification must survive the round trip.
    let json = serde_json::to_string(&wire).unwrap();
    let back: heimdall::http::wire::Sign1Wire = serde_json::from_str(&json).unwrap();
    assert_eq!(wire, back);

    let verified = verify_sign_round1(&secp, &me.pool_id, &me.xonly, namespace, 1, &back).unwrap();
    assert_eq!(verified, c, "the commitments must survive the wire form");
}

#[test]
fn round1_from_a_different_key_is_rejected() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xA1);
    let impostor = identity(&secp, 0xA1); // same pool_id, different key
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let namespace = ns(42, 0, 0x11);

    let wire = build_sign_round1(
        &secp,
        &impostor.keypair,
        namespace,
        &me.pool_id,
        1,
        &commitments(&kps, id),
    )
    .unwrap();
    assert!(
        verify_sign_round1(&secp, &me.pool_id, &me.xonly, namespace, 1, &wire).is_err(),
        "a payload signed by a key the registry does not bind to this pool must be rejected"
    );
}

#[test]
fn round1_tampered_commitment_is_rejected() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xA1);
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let namespace = ns(42, 0, 0x11);

    let mut wire = build_sign_round1(
        &secp,
        &me.keypair,
        namespace,
        &me.pool_id,
        1,
        &commitments(&kps, id),
    )
    .unwrap();
    // Swap in another signer's commitments, keeping the original signature.
    let other = build_sign_round1(
        &secp,
        &me.keypair,
        namespace,
        &me.pool_id,
        1,
        &commitments(&kps, Identifier::try_from(2u16).unwrap()),
    )
    .unwrap();
    wire.hiding = other.hiding;
    assert!(
        verify_sign_round1(&secp, &me.pool_id, &me.xonly, namespace, 1, &wire).is_err(),
        "altering a commitment must invalidate the signature"
    );
}

/// The replay guarantee. A genuine, correctly-signed payload must not verify in
/// ANY other session — a different epoch, a different input index within the
/// epoch, or (critically) the same epoch and index for a different message,
/// which is what a second treasury movement in the same epoch looks like.
#[test]
fn round1_does_not_replay_into_another_session() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xA1);
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let original = ns(42, 0, 0x11);

    let wire = build_sign_round1(
        &secp,
        &me.keypair,
        original,
        &me.pool_id,
        1,
        &commitments(&kps, id),
    )
    .unwrap();

    for (label, other) in [
        ("different epoch", ns(43, 0, 0x11)),
        ("different session", ns(42, 1, 0x11)),
        ("different message, same epoch+session", ns(42, 0, 0x12)),
        // The one the message cannot catch: a movement rebuilt at the next
        // opportunity when nothing on chain has changed is byte-identical, so
        // its sighash — and therefore `message` — is the SAME. Only the
        // sequence separates the two attempts (WI-W8ZC4).
        (
            "the next attempt at the same movement",
            ns_at(42, 2, 0, 0x11),
        ),
    ] {
        assert!(
            verify_sign_round1(&secp, &me.pool_id, &me.xonly, other, 1, &wire).is_err(),
            "a round1 payload must not replay into a {label}"
        );
    }
    // Sanity: it does still verify in its own session.
    assert!(verify_sign_round1(&secp, &me.pool_id, &me.xonly, original, 1, &wire).is_ok());
}

/// Aggregation keys shares by FROST identifier, and a roster change renumbers
/// participants. A payload must be accepted only into the slot the roster
/// assigns its publisher.
#[test]
fn round1_claiming_a_foreign_identifier_is_rejected() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xA1);
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let namespace = ns(42, 0, 0x11);

    let wire = build_sign_round1(
        &secp,
        &me.keypair,
        namespace,
        &me.pool_id,
        1,
        &commitments(&kps, id),
    )
    .unwrap();
    let err = verify_sign_round1(&secp, &me.pool_id, &me.xonly, namespace, 2, &wire).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("identifier 1") && msg.contains('2'),
        "the rejection must name both identifiers so it is attributable, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Round 2
// ---------------------------------------------------------------------------

#[test]
fn round2_survives_json_and_verifies_under_the_signers_key() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xB2);
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let share = signature_share(&kps, id, b"treasury movement sighash");
    let namespace = ns(7, 3, 0x22);

    let wire = build_sign_round2(&secp, &me.keypair, namespace, &me.pool_id, 1, &share).unwrap();
    let json = serde_json::to_string(&wire).unwrap();
    let back: heimdall::http::wire::Sign2Wire = serde_json::from_str(&json).unwrap();

    let verified = verify_sign_round2(&secp, &me.pool_id, &me.xonly, namespace, 1, &back).unwrap();
    assert_eq!(verified, share, "the share must survive the wire form");
}

#[test]
fn round2_tampered_share_is_rejected() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xB2);
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let namespace = ns(7, 3, 0x22);

    let mut wire = build_sign_round2(
        &secp,
        &me.keypair,
        namespace,
        &me.pool_id,
        1,
        &signature_share(&kps, id, b"m"),
    )
    .unwrap();
    // Flip one hex nibble of the share.
    let mut chars: Vec<char> = wire.share.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    wire.share = chars.into_iter().collect();
    assert!(
        verify_sign_round2(&secp, &me.pool_id, &me.xonly, namespace, 1, &wire).is_err(),
        "altering the share must invalidate the signature"
    );
}

#[test]
fn round2_does_not_replay_into_another_session() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xB2);
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let original = ns(7, 3, 0x22);

    let wire = build_sign_round2(
        &secp,
        &me.keypair,
        original,
        &me.pool_id,
        1,
        &signature_share(&kps, id, b"m"),
    )
    .unwrap();
    for other in [
        ns(8, 3, 0x22),
        ns(7, 4, 0x22),
        ns(7, 3, 0x23),
        ns_at(7, 2, 3, 0x22),
    ] {
        assert!(
            verify_sign_round2(&secp, &me.pool_id, &me.xonly, other, 1, &wire).is_err(),
            "a round2 payload must not replay into another session"
        );
    }
    assert!(verify_sign_round2(&secp, &me.pool_id, &me.xonly, original, 1, &wire).is_ok());
}

/// Namespace separation between the rounds themselves: the two layouts carry
/// distinct tags, so a Round 1 signature is meaningless as a Round 2 one even
/// with everything else identical.
#[test]
fn a_round1_signature_does_not_authenticate_a_round2_payload() {
    let secp = Secp256k1::new();
    let me = identity(&secp, 0xC3);
    let kps = key_packages();
    let id = Identifier::try_from(1u16).unwrap();
    let namespace = ns(5, 0, 0x33);

    let r1 = build_sign_round1(
        &secp,
        &me.keypair,
        namespace,
        &me.pool_id,
        1,
        &commitments(&kps, id),
    )
    .unwrap();
    let mut r2 = build_sign_round2(
        &secp,
        &me.keypair,
        namespace,
        &me.pool_id,
        1,
        &signature_share(&kps, id, b"m"),
    )
    .unwrap();
    r2.signature = r1.signature;
    assert!(
        verify_sign_round2(&secp, &me.pool_id, &me.xonly, namespace, 1, &r2).is_err(),
        "a Round 1 signature must not authenticate a Round 2 payload"
    );
}
