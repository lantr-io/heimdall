use std::collections::BTreeMap;

use frost_secp256k1_tr::{self as frost, Identifier};
use heimdall::frost::participant;

/// Helper: run a 2-of-3 DKG returning all intermediate data for serialization testing.
struct DkgData {
    round1_packages: BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
    round2_packages_per_sender: BTreeMap<Identifier, BTreeMap<Identifier, frost::keys::dkg::round2::Package>>,
    key_packages: BTreeMap<Identifier, frost::keys::KeyPackage>,
    pubkey_package: frost::keys::PublicKeyPackage,
}

fn run_2_of_3_dkg() -> DkgData {
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

    DkgData {
        round1_packages,
        round2_packages_per_sender,
        key_packages,
        pubkey_package: pubkey_pkg.unwrap(),
    }
}

#[test]
fn test_identifier_json_roundtrip() {
    let id = Identifier::try_from(42u16).unwrap();
    let json = serde_json::to_string(&id).unwrap();
    let back: Identifier = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn test_dkg_round1_package_json_roundtrip() {
    let data = run_2_of_3_dkg();
    for (id, pkg) in &data.round1_packages {
        let json = serde_json::to_string(pkg).unwrap();
        let back: frost::keys::dkg::round1::Package = serde_json::from_str(&json).unwrap();
        assert_eq!(*pkg, back, "round1 package roundtrip failed for {id:?}");
    }
}

#[test]
fn test_dkg_round2_package_json_roundtrip() {
    let data = run_2_of_3_dkg();
    for (_sender, pkgs) in &data.round2_packages_per_sender {
        for (recipient, pkg) in pkgs {
            let json = serde_json::to_string(pkg).unwrap();
            let back: frost::keys::dkg::round2::Package = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *pkg, back,
                "round2 package roundtrip failed for recipient {recipient:?}"
            );
        }
    }
}

#[test]
fn test_signing_commitments_and_shares_json_roundtrip() {
    let mut rng = rand::thread_rng();
    let data = run_2_of_3_dkg();
    let message = b"test message";

    let signer_ids: Vec<Identifier> = data.key_packages.keys().take(2).copied().collect();

    // Round 1 commitments
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for &id in &signer_ids {
        let (nonces, commitments) = participant::sign_round1(&data.key_packages[&id], &mut rng);
        // Test commitments roundtrip
        let json = serde_json::to_string(&commitments).unwrap();
        let back: frost::round1::SigningCommitments = serde_json::from_str(&json).unwrap();
        assert_eq!(commitments, back, "commitments roundtrip failed for {id:?}");

        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }

    let signing_package = frost::SigningPackage::new(commitments_map, message);

    // Test SigningPackage roundtrip
    let sp_json = serde_json::to_string(&signing_package).unwrap();
    let sp_back: frost::SigningPackage = serde_json::from_str(&sp_json).unwrap();
    assert_eq!(signing_package, sp_back, "signing package roundtrip failed");

    // Round 2 shares
    let mut shares = BTreeMap::new();
    for &id in &signer_ids {
        let share =
            participant::sign_round2(&signing_package, &nonces_map[&id], &data.key_packages[&id])
                .unwrap();
        // Test share roundtrip
        let json = serde_json::to_string(&share).unwrap();
        let back: frost::round2::SignatureShare = serde_json::from_str(&json).unwrap();
        assert_eq!(share, back, "signature share roundtrip failed for {id:?}");

        shares.insert(id, share);
    }

    // Aggregate and test signature roundtrip
    let signature =
        participant::sign_aggregate(&signing_package, &shares, &data.pubkey_package).unwrap();
    let sig_json = serde_json::to_string(&signature).unwrap();
    let sig_back: frost::Signature = serde_json::from_str(&sig_json).unwrap();

    // Verify both the original and deserialized signatures work
    data.pubkey_package
        .verifying_key()
        .verify(message, &signature)
        .expect("original signature must verify");
    data.pubkey_package
        .verifying_key()
        .verify(message, &sig_back)
        .expect("deserialized signature must verify");

    // Verify the serialized bytes are identical (the canonical form)
    assert_eq!(
        signature.serialize().unwrap(),
        sig_back.serialize().unwrap(),
        "signature serialize bytes must match after roundtrip"
    );
}

#[test]
fn test_public_key_package_json_roundtrip() {
    let data = run_2_of_3_dkg();
    let json = serde_json::to_string(&data.pubkey_package).unwrap();
    let back: frost::keys::PublicKeyPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(data.pubkey_package, back);
}
