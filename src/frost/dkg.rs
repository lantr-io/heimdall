/// Wrapper around frost-secp256k1-tr for DKG operations.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use frost_secp256k1_tr as frost;
use frost::{Identifier, keys::dkg};
use rayon::prelude::*;

/// Result of a completed DKG for one participant.
pub struct DkgResult {
    pub key_package: frost::keys::KeyPackage,
    pub public_key_package: frost::keys::PublicKeyPackage,
}

/// Part 1 — parallel. Returns (secrets_map, packages_map).
fn run_part1(
    identifiers: &[Identifier],
    max_signers: u16,
    min_signers: u16,
) -> (
    BTreeMap<Identifier, dkg::round1::SecretPackage>,
    BTreeMap<Identifier, dkg::round1::Package>,
) {
    let t0 = Instant::now();
    let results: Vec<_> = identifiers
        .par_iter()
        .map(|&id| {
            let mut rng = rand::thread_rng();
            let (secret, package) = dkg::part1(id, max_signers, min_signers, &mut rng).unwrap();
            (id, secret, package)
        })
        .collect();

    let mut secrets = BTreeMap::new();
    let mut packages = BTreeMap::new();
    for (id, secret, package) in results {
        secrets.insert(id, secret);
        packages.insert(id, package);
    }
    println!(
        "    part1: {}/{} ({:.2?}) [parallel]",
        max_signers, max_signers, t0.elapsed()
    );
    (secrets, packages)
}

/// Part 2 — parallel. Each participant's part2 is independent once round1 is done.
/// Consumes secrets, returns (round2_secrets, round2_packages_per_sender).
fn run_part2(
    identifiers: &[Identifier],
    mut round1_secrets: BTreeMap<Identifier, dkg::round1::SecretPackage>,
    round1_packages: &BTreeMap<Identifier, dkg::round1::Package>,
    max_signers: u16,
) -> (
    BTreeMap<Identifier, dkg::round2::SecretPackage>,
    BTreeMap<Identifier, BTreeMap<Identifier, dkg::round2::Package>>,
) {
    let t1 = Instant::now();

    // Pre-extract secrets into a vec so we can consume them in parallel
    let secrets_vec: Vec<_> = identifiers
        .iter()
        .map(|id| (*id, round1_secrets.remove(id).unwrap()))
        .collect();

    let counter = AtomicUsize::new(0);
    let n = max_signers as usize;

    let results: Vec<_> = secrets_vec
        .into_par_iter()
        .map(|(id, secret)| {
            let others: BTreeMap<Identifier, dkg::round1::Package> = round1_packages
                .iter()
                .filter(|&(k, _)| *k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();

            let (secret2, packages2) = dkg::part2(secret, &others).unwrap();

            let c = counter.fetch_add(1, Ordering::Relaxed) + 1;
            if c % 50 == 0 || c == n {
                println!("    part2: {}/{} ({:.2?}) [parallel]", c, n, t1.elapsed());
            }

            (id, secret2, packages2)
        })
        .collect();

    let mut round2_secrets = BTreeMap::new();
    let mut round2_packages = BTreeMap::new();
    for (id, secret2, packages2) in results {
        round2_secrets.insert(id, secret2);
        round2_packages.insert(id, packages2);
    }
    println!(
        "    part2: done ({:.2?}) [parallel]",
        t1.elapsed()
    );
    (round2_secrets, round2_packages)
}

/// Result of a completed DKG for all participants.
pub struct FullDkgResult {
    pub key_packages: BTreeMap<Identifier, frost::keys::KeyPackage>,
    pub public_key_package: frost::keys::PublicKeyPackage,
}

/// Run DKG rounds 1+2+3 (parallelized) for all N participants.
/// Returns key packages for every participant and the shared public key package.
pub fn run_dkg_all_completions(min_signers: u16, max_signers: u16) -> FullDkgResult {
    let identifiers: Vec<Identifier> = (1..=max_signers)
        .map(|i| Identifier::try_from(i).unwrap())
        .collect();

    let (round1_secrets, round1_packages) = run_part1(&identifiers, max_signers, min_signers);
    let (mut round2_secrets, round2_all_packages) =
        run_part2(&identifiers, round1_secrets, &round1_packages, max_signers);

    // Part 3: parallel for all participants
    let t2 = Instant::now();
    let n = max_signers as usize;
    let counter = AtomicUsize::new(0);

    let secrets_vec: Vec<_> = identifiers
        .iter()
        .map(|id| (*id, round2_secrets.remove(id).unwrap()))
        .collect();

    let results: Vec<_> = secrets_vec
        .into_par_iter()
        .map(|(id, secret2)| {
            let round1_others: BTreeMap<_, _> = round1_packages
                .iter()
                .filter(|&(k, _)| *k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();

            let round2_for_me: BTreeMap<_, _> = round2_all_packages
                .iter()
                .filter(|&(k, _)| *k != id)
                .map(|(sender_id, packages)| (*sender_id, packages[&id].clone()))
                .collect();

            let (key_package, public_key_package) =
                dkg::part3(&secret2, &round1_others, &round2_for_me).unwrap();

            let c = counter.fetch_add(1, Ordering::Relaxed) + 1;
            if c % 50 == 0 || c == n {
                println!("    part3: {}/{} ({:.2?}) [parallel]", c, n, t2.elapsed());
            }

            (id, key_package, public_key_package)
        })
        .collect();

    let mut key_packages = BTreeMap::new();
    let mut last_pubkey_pkg = None;
    for (id, kp, pkp) in results {
        key_packages.insert(id, kp);
        last_pubkey_pkg = Some(pkp);
    }
    println!("    part3: done ({:.2?}) [parallel]", t2.elapsed());

    FullDkgResult {
        key_packages,
        public_key_package: last_pubkey_pkg.unwrap(),
    }
}

/// Run DKG rounds 1+2 (parallelized) then part3 for a single participant.
pub fn run_dkg_single_completion(
    min_signers: u16,
    max_signers: u16,
    complete_for: u16,
) -> (DkgResult, BTreeMap<Identifier, dkg::round1::Package>) {
    let identifiers: Vec<Identifier> = (1..=max_signers)
        .map(|i| Identifier::try_from(i).unwrap())
        .collect();
    let target_id = Identifier::try_from(complete_for).unwrap();

    let (round1_secrets, round1_packages) = run_part1(&identifiers, max_signers, min_signers);
    let (mut round2_secrets, round2_all_packages) =
        run_part2(&identifiers, round1_secrets, &round1_packages, max_signers);

    // Part 3: only for the target participant
    let t2 = Instant::now();
    let round1_others: BTreeMap<_, _> = round1_packages
        .iter()
        .filter(|&(k, _)| *k != target_id)
        .map(|(k, v)| (*k, v.clone()))
        .collect();

    let round2_for_me: BTreeMap<_, _> = round2_all_packages
        .iter()
        .filter(|&(k, _)| *k != target_id)
        .map(|(sender_id, packages)| (*sender_id, packages[&target_id].clone()))
        .collect();

    let (key_package, public_key_package) = dkg::part3(
        &round2_secrets.remove(&target_id).unwrap(),
        &round1_others,
        &round2_for_me,
    )
    .unwrap();
    println!("    part3 for SPO #{complete_for}: ({:.2?})", t2.elapsed());

    (
        DkgResult {
            key_package,
            public_key_package,
        },
        round1_packages,
    )
}

/// Run a DKG where one participant sends a corrupted share to another.
pub struct CheatingDkgResult {
    pub round1_packages: BTreeMap<Identifier, dkg::round1::Package>,
    pub round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round2::Package>>,
    pub cheater_id: Identifier,
    pub victim_id: Identifier,
}

pub fn run_cheating_dkg(
    min_signers: u16,
    max_signers: u16,
    cheater_idx: u16,
    victim_idx: u16,
) -> CheatingDkgResult {
    let identifiers: Vec<Identifier> = (1..=max_signers)
        .map(|i| Identifier::try_from(i).unwrap())
        .collect();

    let (round1_secrets, round1_packages) = run_part1(&identifiers, max_signers, min_signers);
    let (_round2_secrets, mut round2_all_packages) =
        run_part2(&identifiers, round1_secrets, &round1_packages, max_signers);

    let cheater_id = Identifier::try_from(cheater_idx).unwrap();
    let victim_id = Identifier::try_from(victim_idx).unwrap();

    // Tamper: generate fresh polynomial for cheater, swap the share to victim
    println!("    Tampering with SPO #{cheater_idx}'s share to SPO #{victim_idx}...");
    let mut rng = rand::thread_rng();
    let (fake_secret, _) = dkg::part1(cheater_id, max_signers, min_signers, &mut rng).unwrap();
    let fake_others: BTreeMap<_, _> = round1_packages
        .iter()
        .filter(|&(k, _)| *k != cheater_id)
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let (_, fake_packages2) = dkg::part2(fake_secret, &fake_others).unwrap();

    round2_all_packages
        .get_mut(&cheater_id)
        .unwrap()
        .insert(victim_id, fake_packages2[&victim_id].clone());

    CheatingDkgResult {
        round1_packages,
        round2_packages: round2_all_packages,
        cheater_id,
        victim_id,
    }
}
