use std::collections::BTreeMap;

use frost_secp256k1_tr::Identifier;
use heimdall::frost::participant;

#[test]
fn test_3_of_3_dkg_per_participant() {
    let mut rng = rand::thread_rng();

    let ids: Vec<Identifier> = (1..=3u16)
        .map(|i| Identifier::try_from(i).unwrap())
        .collect();

    // Each SPO calls dkg_part1 independently
    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for &id in &ids {
        let (secret, package) = participant::dkg_part1(id, 3, 3, &mut rng).unwrap();
        round1_secrets.insert(id, secret);
        round1_packages.insert(id, package);
    }

    // Each SPO calls dkg_part2 with others' round1 packages
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

    // Each SPO calls dkg_part3 — gets only packages addressed to them
    let mut key_packages = BTreeMap::new();
    let mut pubkey_packages = Vec::new();
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

        let (key_pkg, pubkey_pkg) =
            participant::dkg_part3(&round2_secrets[&id], &round1_others, &round2_for_me).unwrap();
        key_packages.insert(id, key_pkg);
        pubkey_packages.push(pubkey_pkg);
    }

    // All 3 derive the same group public key
    let group_key = pubkey_packages[0].verifying_key();
    for pkg in &pubkey_packages[1..] {
        assert_eq!(
            group_key, pkg.verifying_key(),
            "all participants must derive the same group public key"
        );
    }

    // Each has a different signing share
    let shares: Vec<_> = key_packages
        .values()
        .map(|kp| kp.signing_share().clone())
        .collect();
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            assert_ne!(
                shares[i], shares[j],
                "signing shares must be distinct"
            );
        }
    }

    // Verification shares are consistent (each participant's pubkey pkg has them)
    let vs0 = pubkey_packages[0].verifying_shares();
    for pkg in &pubkey_packages[1..] {
        assert_eq!(vs0, pkg.verifying_shares());
    }
}

#[test]
fn test_2_of_3_dkg_per_participant() {
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
    let mut pubkey_packages = Vec::new();
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

        let (key_pkg, pubkey_pkg) =
            participant::dkg_part3(&round2_secrets[&id], &round1_others, &round2_for_me).unwrap();
        key_packages.insert(id, key_pkg);
        pubkey_packages.push(pubkey_pkg);
    }

    // Same group key
    let group_key = pubkey_packages[0].verifying_key();
    for pkg in &pubkey_packages[1..] {
        assert_eq!(group_key, pkg.verifying_key());
    }

    // Different shares
    let shares: Vec<_> = key_packages.values().map(|kp| kp.signing_share().clone()).collect();
    assert_ne!(shares[0], shares[1]);
    assert_ne!(shares[1], shares[2]);
}
