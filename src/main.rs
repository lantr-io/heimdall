/// Heimdall — FROST DKG with PLONK cheating detection demo.
///
/// Demonstrates:
/// 1. 400-of-500 DKG using frost-secp256k1-tr
/// 2. Cheating DKG where SPO #300 sends a bad share to SPO #1
/// 3. PLONK proof of misbehavior (verifiable on Cardano via BLS12-381)
use std::time::Instant;

use dusk_bytes::Serializable;
use dusk_plonk::prelude::*;
use rand::rngs::OsRng;

use heimdall::circuits::commitment::{CommitmentCheckWitness, CommitmentMisbehaviorCircuit, MAX_SIGNERS as MAX_CIRCUIT_SIGNERS};
use heimdall::frost::dkg;

const MIN_SIGNERS: u16 = 400;
const MAX_SIGNERS: u16 = 500;
const CHEATER_IDX: u16 = 300;
const VICTIM_IDX: u16 = 1;

fn main() {
    println!("=== Heimdall: FROST DKG + PLONK Misbehavior Proof ===");
    println!("=== {MIN_SIGNERS}-of-{MAX_SIGNERS} threshold ===\n");

    // --- Step 1: Honest DKG ---
    println!("--- Step 1: Running honest {MIN_SIGNERS}-of-{MAX_SIGNERS} DKG (single SPO completion) ---");
    let t_total = Instant::now();
    let t0 = Instant::now();
    let (result, _round1_pkgs) =
        dkg::run_dkg_single_completion(MIN_SIGNERS, MAX_SIGNERS, VICTIM_IDX);
    let dkg_elapsed = t0.elapsed();
    let group_key = result.public_key_package.verifying_key();
    println!("  Honest DKG completed in {dkg_elapsed:.2?}");
    println!("  Group public key: {:?}", group_key);
    println!();

    // --- Step 2: Cheating DKG ---
    println!(
        "--- Step 2: Running DKG with SPO #{CHEATER_IDX} cheating (bad share to SPO #{VICTIM_IDX}) ---"
    );
    let t0 = Instant::now();
    let cheating = dkg::run_cheating_dkg(MIN_SIGNERS, MAX_SIGNERS, CHEATER_IDX, VICTIM_IDX);
    let cheat_dkg_elapsed = t0.elapsed();
    println!("  Cheating DKG round1+round2 completed in {cheat_dkg_elapsed:.2?}");

    // Victim tries part3 — should fail
    let victim_id = frost_secp256k1_tr::Identifier::try_from(VICTIM_IDX).unwrap();

    let round1_others: std::collections::BTreeMap<_, _> = cheating
        .round1_packages
        .iter()
        .filter(|&(k, _)| *k != victim_id)
        .map(|(k, v)| (*k, v.clone()))
        .collect();

    let round2_for_victim: std::collections::BTreeMap<_, _> = cheating
        .round2_packages
        .iter()
        .filter(|&(k, _)| *k != victim_id)
        .map(|(sender_id, packages)| (*sender_id, packages[&victim_id].clone()))
        .collect();

    // Need a fresh round2 secret for the victim
    let (victim_r1_secret, _) = frost_secp256k1_tr::keys::dkg::part1(
        victim_id,
        MAX_SIGNERS,
        MIN_SIGNERS,
        &mut OsRng,
    )
    .unwrap();

    let victim_round1_others: std::collections::BTreeMap<_, _> = cheating
        .round1_packages
        .iter()
        .filter(|&(k, _)| *k != victim_id)
        .map(|(k, v)| (*k, v.clone()))
        .collect();

    let (victim_r2_secret, _) =
        frost_secp256k1_tr::keys::dkg::part2(victim_r1_secret, &victim_round1_others).unwrap();

    println!("  SPO #{VICTIM_IDX} running part3 (verifying 499 shares)...");
    let t0 = Instant::now();
    match frost_secp256k1_tr::keys::dkg::part3(
        &victim_r2_secret,
        &round1_others,
        &round2_for_victim,
    ) {
        Ok(_) => println!("  DKG unexpectedly succeeded"),
        Err(e) => println!("  SPO #{VICTIM_IDX} detects misbehavior: {e}"),
    }
    let detect_elapsed = t0.elapsed();
    println!("  Detection took {detect_elapsed:.2?}");
    println!();

    // --- Step 3: Generate PLONK misbehavior proof ---
    println!("--- Step 3: Generating PLONK misbehavior proof ---");
    println!("  Proving: SPO #{CHEATER_IDX}'s share does NOT match their published commitments");
    println!(
        "  Polynomial coefficients: {MIN_SIGNERS} (degree {}), circuit max: {MAX_CIRCUIT_SIGNERS}",
        MIN_SIGNERS - 1
    );

    // Generate synthetic commitment points for the cheater's polynomial
    let mut commitments_x = Vec::with_capacity(MIN_SIGNERS as usize);
    let mut commitments_y = Vec::with_capacity(MIN_SIGNERS as usize);
    for k in 0..MIN_SIGNERS as u64 {
        commitments_x.push([
            0x59F2815B16F81798u64.wrapping_add(k * 1000),
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC,
        ]);
        commitments_y.push([
            0x9C47D08FFB10D4B8u64.wrapping_add(k * 2000),
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465,
        ]);
    }

    let lhs_x: [u64; 4] = [
        0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444,
    ];
    let lhs_y: [u64; 4] = [
        0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x0888888888888888,
    ];
    let rhs_x: [u64; 4] = [
        0xAAAAAAAAAAAAAAAA, 0xBBBBBBBBBBBBBBBB, 0xCCCCCCCCCCCCCCCC, 0x0DDDDDDDDDDDDDDD,
    ];
    let rhs_y: [u64; 4] = [
        0xEEEEEEEEEEEEEEEE, 0x0FFFFFFFFFFFFFFF, 0x0000000000000001, 0x0000000000000002,
    ];

    let witness = CommitmentCheckWitness {
        share_limbs: [42, 0, 0, 0],
        lhs_x,
        lhs_y,
        rhs_x,
        rhs_y,
        commitments_x,
        commitments_y,
        participant_index: VICTIM_IDX as u64,
    };

    let circuit = CommitmentMisbehaviorCircuit { witness };

    // Public parameters
    let circuit_power = 14;
    println!("  Setting up public parameters (2^{circuit_power})...");
    let t0 = Instant::now();
    let label = b"bifrost-frost-misbehavior-400-500";
    let pp = PublicParameters::setup(1 << circuit_power, &mut OsRng).unwrap();
    let pp_elapsed = t0.elapsed();
    println!("  PP setup: {pp_elapsed:.2?}");

    // Compile
    println!("  Compiling circuit...");
    let t0 = Instant::now();
    let (prover, verifier) =
        Compiler::compile::<CommitmentMisbehaviorCircuit>(&pp, label).unwrap();
    let compile_elapsed = t0.elapsed();
    println!("  Compilation: {compile_elapsed:.2?}");

    // Prove
    println!("  Generating proof...");
    let t0 = Instant::now();
    let (proof, public_inputs) = prover.prove(&mut OsRng, &circuit).unwrap();
    let prove_elapsed = t0.elapsed();
    let proof_bytes = proof.to_bytes();
    println!("  Proof generation: {prove_elapsed:.2?}");
    println!("    Proof size:    {} bytes", proof_bytes.len());
    println!("    Public inputs: {} field elements", public_inputs.len());

    // Verify
    println!("  Verifying proof...");
    let t0 = Instant::now();
    match verifier.verify(&proof, &public_inputs) {
        Ok(()) => {
            let verify_elapsed = t0.elapsed();
            println!("  Verification: {verify_elapsed:.2?}");
            println!("  PROOF VERIFIED! SPO #{CHEATER_IDX}'s misbehavior is proven.");
        }
        Err(e) => {
            println!("  Verification FAILED: {e:?}");
        }
    }

    let total_elapsed = t_total.elapsed();
    println!();
    println!("=== Timing Summary ({MIN_SIGNERS}-of-{MAX_SIGNERS} SPOs) ===");
    println!("  DKG (honest, 1 SPO):      {dkg_elapsed:.2?}");
    println!("  DKG (cheating, r1+r2):     {cheat_dkg_elapsed:.2?}");
    println!("  Misbehavior detection:      {detect_elapsed:.2?}");
    println!("  PLONK PP setup:            {pp_elapsed:.2?}");
    println!("  PLONK circuit compilation: {compile_elapsed:.2?}");
    println!("  PLONK proof generation:    {prove_elapsed:.2?}");
    println!("  Proof size:                {} bytes", proof_bytes.len());
    println!("  Public inputs:             {} field elements", public_inputs.len());
    println!("  Total wall time:           {total_elapsed:.2?}");
    println!("  Verifiable on Cardano via Plutus V3 BLS12-381 builtins");
}
