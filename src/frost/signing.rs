/// FROST two-round signing protocol helpers.
///
/// Provides:
/// - `run_signing()`: successful threshold signing (t-of-n)
/// - `run_cheating_signing()`: one SPO submits a bad signature share
/// - `compute_misbehavior_witness()`: EC witness for the PLONK misbehavior circuit
use std::collections::BTreeMap;
use std::time::Instant;

use frost_secp256k1_tr as frost;
use frost::Identifier;
use rayon::prelude::*;

/// Result of a successful signing session.
pub struct SigningResult {
    pub signature: frost::Signature,
    pub signing_package: frost::SigningPackage,
    pub signature_shares: BTreeMap<Identifier, frost::round2::SignatureShare>,
}

/// Run a successful FROST signing session with `num_signers` out of the full set.
pub fn run_signing(
    key_packages: &BTreeMap<Identifier, frost::keys::KeyPackage>,
    public_key_package: &frost::keys::PublicKeyPackage,
    message: &[u8],
    num_signers: u16,
) -> SigningResult {
    // Select first num_signers participants
    let signer_ids: Vec<Identifier> = key_packages.keys().take(num_signers as usize).copied().collect();

    // Round 1: commitments (parallel)
    println!("    Round 1: each signer generates a nonce pair (d,e) and publishes curve points (D,E)");
    let t0 = Instant::now();
    let round1_results: Vec<_> = signer_ids
        .par_iter()
        .map(|id| {
            let kp = &key_packages[id];
            let mut rng = rand::thread_rng();
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            (*id, nonces, commitments)
        })
        .collect();

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for (id, nonces, commitments) in round1_results {
        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }
    println!("    Round 1: {num_signers} signers done ({:.2?}) [parallel]", t0.elapsed());

    // Build signing package
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    // Round 2: signature shares (parallel)
    println!("    Round 2: each signer computes z_p = d_p + rho_p*e_p + lambda_p*s_p*c (signature share)");
    let t1 = Instant::now();
    let nonces_vec: Vec<_> = nonces_map.into_iter().collect();
    let sign_results: Vec<_> = nonces_vec
        .into_par_iter()
        .map(|(id, nonces)| {
            let kp = &key_packages[&id];
            let share = frost::round2::sign(&signing_package, &nonces, kp).unwrap();
            (id, share)
        })
        .collect();

    let mut signature_shares = BTreeMap::new();
    for (id, share) in sign_results {
        signature_shares.insert(id, share);
    }
    println!("    Round 2: {num_signers} signers done ({:.2?}) [parallel]", t1.elapsed());

    // Aggregate
    println!("    Aggregate: coordinator sums z = Σz_p, verifies each share against verification shares Y_p");
    let t2 = Instant::now();
    let signature = frost::aggregate(&signing_package, &signature_shares, public_key_package).unwrap();
    println!("    Aggregate: done ({:.2?})", t2.elapsed());

    // Verify
    println!("    Verify: check (R, z) is a valid Schnorr/BIP-340 signature under the group public key");
    let t3 = Instant::now();
    public_key_package
        .verifying_key()
        .verify(message, &signature)
        .unwrap();
    println!("    Verify: done ({:.2?})", t3.elapsed());

    SigningResult {
        signature,
        signing_package,
        signature_shares,
    }
}

/// Result of a cheating signing session.
pub struct CheatingSigningResult {
    pub signing_package: frost::SigningPackage,
    pub signature_shares: BTreeMap<Identifier, frost::round2::SignatureShare>,
    pub cheater_id: Identifier,
    pub honest_share_bytes: [u8; 32],
    pub corrupted_share_bytes: [u8; 32],
}

/// Run a FROST signing session where one SPO submits a corrupted signature share.
/// `cheater_idx` is 1-based participant index (will be clamped to signer set).
pub fn run_cheating_signing(
    key_packages: &BTreeMap<Identifier, frost::keys::KeyPackage>,
    public_key_package: &frost::keys::PublicKeyPackage,
    message: &[u8],
    num_signers: u16,
    cheater_idx: u16,
) -> CheatingSigningResult {
    let signer_ids: Vec<Identifier> = key_packages.keys().take(num_signers as usize).copied().collect();
    let cheater_id = Identifier::try_from(cheater_idx).unwrap();
    assert!(signer_ids.contains(&cheater_id), "cheater must be in signer set");

    // Round 1
    let t0 = Instant::now();
    let round1_results: Vec<_> = signer_ids
        .par_iter()
        .map(|id| {
            let kp = &key_packages[id];
            let mut rng = rand::thread_rng();
            let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
            (*id, nonces, commitments)
        })
        .collect();

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for (id, nonces, commitments) in round1_results {
        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }
    println!("    Round 1 (commitments): {num_signers} signers ({:.2?}) [parallel]", t0.elapsed());

    let signing_package = frost::SigningPackage::new(commitments_map, message);

    // Round 2: honest shares
    let t1 = Instant::now();
    let nonces_vec: Vec<_> = nonces_map.into_iter().collect();
    let sign_results: Vec<_> = nonces_vec
        .into_par_iter()
        .map(|(id, nonces)| {
            let kp = &key_packages[&id];
            let share = frost::round2::sign(&signing_package, &nonces, kp).unwrap();
            (id, share)
        })
        .collect();

    let mut signature_shares = BTreeMap::new();
    for (id, share) in sign_results {
        signature_shares.insert(id, share);
    }
    println!("    Round 2 (sign shares): {num_signers} signers ({:.2?}) [parallel]", t1.elapsed());

    // Corrupt the cheater's share
    let honest_share = &signature_shares[&cheater_id];
    let honest_bytes_vec = honest_share.serialize();
    let mut honest_share_bytes = [0u8; 32];
    honest_share_bytes.copy_from_slice(&honest_bytes_vec);

    // Add 1 to the scalar (as big-endian bytes)
    let mut corrupted_share_bytes = honest_share_bytes;
    // Increment the least significant byte (last byte in big-endian)
    let mut carry = 1u16;
    for byte in corrupted_share_bytes.iter_mut().rev() {
        let sum = *byte as u16 + carry;
        *byte = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }

    let corrupted_share = frost::round2::SignatureShare::deserialize(&corrupted_share_bytes).unwrap();
    signature_shares.insert(cheater_id, corrupted_share);

    println!("    Corrupted SPO #{cheater_idx}'s signature share");
    println!("      honest:    {}", hex::encode(honest_share_bytes));
    println!("      corrupted: {}", hex::encode(corrupted_share_bytes));

    // Try to aggregate — should fail
    let t2 = Instant::now();
    match frost::aggregate(&signing_package, &signature_shares, public_key_package) {
        Ok(_) => println!("    Aggregation unexpectedly succeeded"),
        Err(e) => println!("    Aggregation detected misbehavior: {e} ({:.2?})", t2.elapsed()),
    }

    CheatingSigningResult {
        signing_package,
        signature_shares,
        cheater_id,
        honest_share_bytes,
        corrupted_share_bytes,
    }
}

/// Compute the EC points for the signature misbehavior witness.
///
/// For a valid share z_good: z_good * G == R_p + lambda_p * c * Y_p
/// For a corrupted share z_bad: z_bad * G != R_p + lambda_p * c * Y_p
///
/// We compute:
///   LHS = z_bad * G  (the corrupted point)
///   RHS = z_good * G (the expected point, since the honest share satisfies the equation)
///
/// Returns (lhs_x, lhs_y, rhs_x, rhs_y) as [u64; 4] limbs.
pub fn compute_misbehavior_witness(
    honest_share_bytes: &[u8; 32],
    corrupted_share_bytes: &[u8; 32],
) -> ([u64; 4], [u64; 4], [u64; 4], [u64; 4]) {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::elliptic_curve::PrimeField;
    use k256::{ProjectivePoint, Scalar};

    let honest_scalar = Scalar::from_repr((*honest_share_bytes).into()).unwrap();
    let corrupted_scalar = Scalar::from_repr((*corrupted_share_bytes).into()).unwrap();

    let rhs_point = ProjectivePoint::GENERATOR * honest_scalar;
    let lhs_point = ProjectivePoint::GENERATOR * corrupted_scalar;

    let rhs_affine = rhs_point.to_affine();
    let lhs_affine = lhs_point.to_affine();

    let rhs_encoded = rhs_affine.to_encoded_point(false);
    let lhs_encoded = lhs_affine.to_encoded_point(false);

    let rhs_x_bytes: [u8; 32] = <[u8; 32]>::try_from(&rhs_encoded.x().unwrap()[..]).unwrap();
    let lhs_x_bytes: [u8; 32] = <[u8; 32]>::try_from(&lhs_encoded.x().unwrap()[..]).unwrap();
    let rhs_y_bytes: [u8; 32] = <[u8; 32]>::try_from(&rhs_encoded.y().unwrap()[..]).unwrap();
    let lhs_y_bytes: [u8; 32] = <[u8; 32]>::try_from(&lhs_encoded.y().unwrap()[..]).unwrap();

    fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = 24 - i * 8;
            limbs[i] = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        }
        limbs
    }

    (
        bytes_to_limbs(&lhs_x_bytes),
        bytes_to_limbs(&lhs_y_bytes),
        bytes_to_limbs(&rhs_x_bytes),
        bytes_to_limbs(&rhs_y_bytes),
    )
}
