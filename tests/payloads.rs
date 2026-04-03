use std::collections::BTreeMap;

use frost_secp256k1_tr::{self as frost, Identifier};
use heimdall::frost::participant;
use heimdall::http::payloads::*;

/// Helper: run a 2-of-3 DKG, return everything needed to build payloads.
struct TestData {
    round1_packages: BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
    round2_packages_per_sender:
        BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>>,
    key_packages: BTreeMap<Identifier, frost::keys::KeyPackage>,
    pubkey_package: frost::keys::PublicKeyPackage,
}

fn setup() -> TestData {
    let mut rng = rand::thread_rng();
    let ids: Vec<Identifier> = (1..=3u16)
        .map(|i| Identifier::try_from(i).unwrap())
        .collect();

    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for &id in &ids {
        let (secret, package) = participant::dkg_part1(id, 3, 2, &mut rng).unwrap();
        round1_secrets.insert(id, secret);
        round1_packages.insert(id, package);
    }

    let mut round2_secrets = BTreeMap::new();
    let mut round2_packages_per_sender = BTreeMap::new();
    for &id in &ids {
        let others: BTreeMap<_, _> = round1_packages
            .iter()
            .filter(|&(&k, _)| k != id)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let secret = round1_secrets.remove(&id).unwrap();
        let (secret2, packages2) = participant::dkg_part2(secret, &others).unwrap();
        round2_secrets.insert(id, secret2);
        round2_packages_per_sender.insert(id, packages2);
    }

    let mut key_packages = BTreeMap::new();
    let mut pubkey_pkg = None;
    for &id in &ids {
        let round1_others: BTreeMap<_, _> = round1_packages
            .iter()
            .filter(|&(&k, _)| k != id)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let round2_for_me: BTreeMap<_, _> = round2_packages_per_sender
            .iter()
            .filter(|&(&sender, _)| sender != id)
            .map(|(&sender, pkgs)| (sender, pkgs[&id].clone()))
            .collect();
        let (kp, pp) =
            participant::dkg_part3(&round2_secrets[&id], &round1_others, &round2_for_me).unwrap();
        key_packages.insert(id, kp);
        pubkey_pkg = Some(pp);
    }

    TestData {
        round1_packages,
        round2_packages_per_sender,
        key_packages,
        pubkey_package: pubkey_pkg.unwrap(),
    }
}

#[test]
fn test_dkg1_payload_json_roundtrip() {
    let data = setup();
    let id = Identifier::try_from(1u16).unwrap();
    let payload = Dkg1Payload {
        epoch: 42,
        identifier: id,
        package: data.round1_packages[&id].clone(),
    };
    let json = serde_json::to_string(&payload).unwrap();
    let back: Dkg1Payload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload.epoch, back.epoch);
    assert_eq!(payload.identifier, back.identifier);
    assert_eq!(payload.package, back.package);
}

#[test]
fn test_dkg2_payload_json_roundtrip() {
    let data = setup();
    let id = Identifier::try_from(1u16).unwrap();
    let payload = Dkg2Payload {
        epoch: 42,
        identifier: id,
        packages: data.round2_packages_per_sender[&id].clone(),
    };
    let json = serde_json::to_string(&payload).unwrap();
    let back: Dkg2Payload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload.epoch, back.epoch);
    assert_eq!(payload.identifier, back.identifier);
    assert_eq!(payload.packages, back.packages);
}

#[test]
fn test_sign1_payload_json_roundtrip() {
    let mut rng = rand::thread_rng();
    let data = setup();
    let id = Identifier::try_from(1u16).unwrap();
    let (_, commitments) = participant::sign_round1(&data.key_packages[&id], &mut rng);
    let payload = Sign1Payload {
        epoch: 42,
        identifier: id,
        commitments,
    };
    let json = serde_json::to_string(&payload).unwrap();
    let back: Sign1Payload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload.epoch, back.epoch);
    assert_eq!(payload.identifier, back.identifier);
    assert_eq!(payload.commitments, back.commitments);
}

#[test]
fn test_sign2_payload_json_roundtrip() {
    let mut rng = rand::thread_rng();
    let data = setup();
    let message = b"test";
    let signer_ids: Vec<Identifier> = data.key_packages.keys().take(2).copied().collect();

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for &id in &signer_ids {
        let (nonces, commitments) = participant::sign_round1(&data.key_packages[&id], &mut rng);
        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    let id = signer_ids[0];
    let share =
        participant::sign_round2(&signing_package, &nonces_map[&id], &data.key_packages[&id])
            .unwrap();
    let payload = Sign2Payload {
        epoch: 42,
        identifier: id,
        share,
    };
    let json = serde_json::to_string(&payload).unwrap();
    let back: Sign2Payload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload.epoch, back.epoch);
    assert_eq!(payload.identifier, back.identifier);
    assert_eq!(payload.share, back.share);
}
