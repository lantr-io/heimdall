use std::collections::BTreeMap;

use frost_secp256k1_tr::{self as frost, Identifier};
use heimdall::frost::participant;

/// Helper: run a 2-of-3 DKG and return (key_packages, pubkey_package).
fn run_2_of_3_dkg() -> (
    BTreeMap<Identifier, frost::keys::KeyPackage>,
    frost::keys::PublicKeyPackage,
) {
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
    let mut round2_packages_per_sender: BTreeMap<Identifier, BTreeMap<Identifier, _>> =
        BTreeMap::new();
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

    (key_packages, pubkey_pkg.unwrap())
}

#[test]
fn test_2_of_3_signing_per_participant() {
    let mut rng = rand::thread_rng();
    let (key_packages, pubkey_package) = run_2_of_3_dkg();
    let message = b"bifrost treasury tx";

    // Pick signers 1 and 2
    let signer_ids: Vec<Identifier> = key_packages.keys().take(2).copied().collect();

    // Round 1: each signer generates nonce commitments
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for &id in &signer_ids {
        let (nonces, commitments) = participant::sign_round1(&key_packages[&id], &mut rng);
        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }

    // Build signing package
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    // Round 2: each signer computes its signature share
    let mut shares = BTreeMap::new();
    for &id in &signer_ids {
        let share =
            participant::sign_round2(&signing_package, &nonces_map[&id], &key_packages[&id])
                .unwrap();
        shares.insert(id, share);
    }

    // Aggregate
    let signature =
        participant::sign_aggregate(&signing_package, &shares, &pubkey_package).unwrap();

    // Verify with the group public key
    pubkey_package
        .verifying_key()
        .verify(message, &signature)
        .expect("signature must verify against group public key");
}

#[test]
fn test_3_of_3_signing_per_participant() {
    let mut rng = rand::thread_rng();

    // Run a 3-of-3 DKG
    let ids: Vec<Identifier> = (1..=3u16)
        .map(|i| Identifier::try_from(i).unwrap())
        .collect();

    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for &id in &ids {
        let (secret, package) = participant::dkg_part1(id, 3, 3, &mut rng).unwrap();
        round1_secrets.insert(id, secret);
        round1_packages.insert(id, package);
    }

    let mut round2_secrets = BTreeMap::new();
    let mut round2_packages_per_sender: BTreeMap<Identifier, BTreeMap<Identifier, _>> =
        BTreeMap::new();
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
    let pubkey_package = pubkey_pkg.unwrap();

    let message = b"all three signers";

    // All 3 sign
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for &id in &ids {
        let (nonces, commitments) = participant::sign_round1(&key_packages[&id], &mut rng);
        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }

    let signing_package = frost::SigningPackage::new(commitments_map, message);

    let mut shares = BTreeMap::new();
    for &id in &ids {
        let share =
            participant::sign_round2(&signing_package, &nonces_map[&id], &key_packages[&id])
                .unwrap();
        shares.insert(id, share);
    }

    let signature =
        participant::sign_aggregate(&signing_package, &shares, &pubkey_package).unwrap();

    pubkey_package
        .verifying_key()
        .verify(message, &signature)
        .expect("3-of-3 signature must verify");
}
