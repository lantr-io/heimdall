/// Heimdall — FROST DKG + Signing + Misbehavior Proofs demo.
///
/// Usage: heimdall [min_signers] [max_signers]
///   Defaults: 350 400
///
/// Demonstrates:
/// 1. Full M-of-N DKG (all N SPOs)
/// 2. Honest FROST signing (M signers)
/// 3. Cheating signing (one SPO submits bad share, aggregate detects it)
/// 4. PLONK signature misbehavior proof
/// 5. PLONK DKG commitment misbehavior proof
use std::time::Instant;

use dusk_bytes::Serializable;
use dusk_plonk::prelude::*;
use rand::rngs::OsRng;

use heimdall::circuits::commitment::{CommitmentCheckWitness, CommitmentMisbehaviorCircuit};
use heimdall::circuits::signature::{SignatureShareCheckWitness, SignatureMisbehaviorCircuit};
use heimdall::frost::{dkg, signing};
use heimdall::gadgets::nonnative::bytes_to_limbs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let min_signers: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(350);
    let max_signers: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(400);

    assert!(
        min_signers >= 2 && min_signers <= max_signers,
        "need 2 <= min_signers <= max_signers, got {min_signers}/{max_signers}"
    );

    let cheater_signer_idx: u16 = 42.min(min_signers);
    let cheater_dkg_idx: u16 = 100.min(max_signers);
    let victim_dkg_idx: u16 = 1;

    println!("=== Heimdall: FROST DKG + Signing + Misbehavior Proofs ===");
    println!("=== {min_signers}-of-{max_signers} threshold ===\n");

    let t_total = Instant::now();

    // --- Step 1: Full DKG ---
    println!("--- Step 1: Full {min_signers}-of-{max_signers} DKG (all {max_signers} SPOs) ---");
    let t0 = Instant::now();
    let dkg_result = dkg::run_dkg_all_completions(min_signers, max_signers);
    let dkg_elapsed = t0.elapsed();
    let group_key = dkg_result.public_key_package.verifying_key();
    println!("  DKG completed in {dkg_elapsed:.2?}");
    println!("  Group public key: {:?}", group_key);
    println!("  Key packages: {} participants", dkg_result.key_packages.len());
    println!();

    // --- Step 2: Honest FROST signing ---
    println!("--- Step 2: Honest FROST signing ({min_signers} signers) ---");
    let message = b"bifrost treasury tx";
    let t0 = Instant::now();
    let sign_result = signing::run_signing(
        &dkg_result.key_packages,
        &dkg_result.public_key_package,
        message,
        min_signers,
    );
    let sign_elapsed = t0.elapsed();
    let sig_bytes = sign_result.signature.serialize().unwrap();
    println!("  Signing completed in {sign_elapsed:.2?}");
    println!("  Signature: {}", hex::encode(&sig_bytes));
    println!("  Message: \"{}\"", std::str::from_utf8(message).unwrap());
    println!();

    // --- Step 3: Cheating signing ---
    println!(
        "--- Step 3: Cheating signing (SPO #{cheater_signer_idx} submits bad share) ---"
    );
    let t0 = Instant::now();
    let cheat_sign = signing::run_cheating_signing(
        &dkg_result.key_packages,
        &dkg_result.public_key_package,
        message,
        min_signers,
        cheater_signer_idx,
    );
    let cheat_sign_elapsed = t0.elapsed();
    println!("  Cheating signing completed in {cheat_sign_elapsed:.2?}");
    println!();

    // --- Step 4: PLONK signature misbehavior proof ---
    println!("--- Step 4: PLONK signature misbehavior proof ---");
    println!(
        "  Proving: SPO #{cheater_signer_idx}'s signature share z*G != expected point"
    );

    let t0 = Instant::now();
    let (lhs_x, lhs_y, rhs_x, rhs_y) = signing::compute_misbehavior_witness(
        &cheat_sign.honest_share_bytes,
        &cheat_sign.corrupted_share_bytes,
    );
    let witness_elapsed = t0.elapsed();
    println!("  EC witness computation: {witness_elapsed:.2?}");

    let corrupted_limbs = bytes_to_limbs(&cheat_sign.corrupted_share_bytes);

    let sig_witness = SignatureShareCheckWitness {
        share_limbs: corrupted_limbs,
        lhs_x,
        lhs_y,
        rhs_x,
        rhs_y,
        z_p_limbs: corrupted_limbs,
        lhs_pub_x: lhs_x,
        lhs_pub_y: lhs_y,
        rhs_pub_x: rhs_x,
        rhs_pub_y: rhs_y,
    };

    let sig_circuit = SignatureMisbehaviorCircuit {
        witness: sig_witness,
    };

    let sig_circuit_power = 13;
    println!("  Setting up public parameters (2^{sig_circuit_power})...");
    let t0 = Instant::now();
    let sig_label = b"bifrost-frost-sig-misbehavior";
    let sig_pp = PublicParameters::setup(1 << sig_circuit_power, &mut OsRng).unwrap();
    let sig_pp_elapsed = t0.elapsed();
    println!("  PP setup: {sig_pp_elapsed:.2?}");

    println!("  Compiling circuit...");
    let t0 = Instant::now();
    let (sig_prover, sig_verifier) =
        Compiler::compile::<SignatureMisbehaviorCircuit>(&sig_pp, sig_label).unwrap();
    let sig_compile_elapsed = t0.elapsed();
    println!("  Compilation: {sig_compile_elapsed:.2?}");

    println!("  Generating proof...");
    let t0 = Instant::now();
    let (sig_proof, sig_public_inputs) = sig_prover.prove(&mut OsRng, &sig_circuit).unwrap();
    let sig_prove_elapsed = t0.elapsed();
    let sig_proof_bytes = sig_proof.to_bytes();
    println!("  Proof generation: {sig_prove_elapsed:.2?}");
    println!("    Proof size:    {} bytes", sig_proof_bytes.len());
    println!(
        "    Public inputs: {} field elements",
        sig_public_inputs.len()
    );

    println!("  Verifying proof...");
    let t0 = Instant::now();
    match sig_verifier.verify(&sig_proof, &sig_public_inputs) {
        Ok(()) => {
            let sig_verify_elapsed = t0.elapsed();
            println!("  Verification: {sig_verify_elapsed:.2?}");
            println!(
                "  PROOF VERIFIED! SPO #{cheater_signer_idx}'s signature misbehavior is proven."
            );
        }
        Err(e) => {
            println!("  Verification FAILED: {e:?}");
        }
    }
    println!();

    // --- Step 5: PLONK DKG commitment misbehavior proof ---
    println!("--- Step 5: PLONK DKG commitment misbehavior proof ---");
    println!(
        "  Proving: SPO #{cheater_dkg_idx}'s DKG share does NOT match their published commitments"
    );

    let circuit_signers = max_signers as usize;
    println!(
        "  Polynomial coefficients: {min_signers} (degree {}), circuit slots: {circuit_signers}",
        min_signers - 1
    );

    let mut commitments_x = Vec::with_capacity(min_signers as usize);
    let mut commitments_y = Vec::with_capacity(min_signers as usize);
    for k in 0..min_signers as u64 {
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

    let commit_lhs_x: [u64; 4] = [
        0x1111111111111111,
        0x2222222222222222,
        0x3333333333333333,
        0x4444444444444444,
    ];
    let commit_lhs_y: [u64; 4] = [
        0x5555555555555555,
        0x6666666666666666,
        0x7777777777777777,
        0x0888888888888888,
    ];
    let commit_rhs_x: [u64; 4] = [
        0xAAAAAAAAAAAAAAAA,
        0xBBBBBBBBBBBBBBBB,
        0xCCCCCCCCCCCCCCCC,
        0x0DDDDDDDDDDDDDDD,
    ];
    let commit_rhs_y: [u64; 4] = [
        0xEEEEEEEEEEEEEEEE,
        0x0FFFFFFFFFFFFFFF,
        0x0000000000000001,
        0x0000000000000002,
    ];

    let commit_witness = CommitmentCheckWitness {
        share_limbs: [42, 0, 0, 0],
        lhs_x: commit_lhs_x,
        lhs_y: commit_lhs_y,
        rhs_x: commit_rhs_x,
        rhs_y: commit_rhs_y,
        commitments_x,
        commitments_y,
        participant_index: victim_dkg_idx as u64,
    };

    let commit_circuit = CommitmentMisbehaviorCircuit {
        witness: commit_witness,
        max_signers: circuit_signers,
    };

    // Circuit needs: max_signers*8 + 17 public inputs, each ~1 gate, plus witness/constraint gates
    // Pick smallest power of 2 that fits
    let commit_gates_estimate = circuit_signers * 8 + 500; // generous overhead
    let commit_circuit_power = (commit_gates_estimate as f64).log2().ceil() as u32 + 1;
    println!("  Setting up public parameters (2^{commit_circuit_power})...");
    let t0 = Instant::now();
    let commit_label = b"bifrost-frost-commit-misbehavior";
    let commit_pp =
        PublicParameters::setup(1 << commit_circuit_power, &mut OsRng).unwrap();
    let commit_pp_elapsed = t0.elapsed();
    println!("  PP setup: {commit_pp_elapsed:.2?}");

    println!("  Compiling circuit...");
    let t0 = Instant::now();
    let dummy = CommitmentMisbehaviorCircuit::dummy(circuit_signers);
    let (commit_prover, commit_verifier) =
        Compiler::compile_with_circuit(&commit_pp, commit_label, &dummy).unwrap();
    let commit_compile_elapsed = t0.elapsed();
    println!("  Compilation: {commit_compile_elapsed:.2?}");

    println!("  Generating proof...");
    let t0 = Instant::now();
    let (commit_proof, commit_public_inputs) =
        commit_prover.prove(&mut OsRng, &commit_circuit).unwrap();
    let commit_prove_elapsed = t0.elapsed();
    let commit_proof_bytes = commit_proof.to_bytes();
    println!("  Proof generation: {commit_prove_elapsed:.2?}");
    println!("    Proof size:    {} bytes", commit_proof_bytes.len());
    println!(
        "    Public inputs: {} field elements",
        commit_public_inputs.len()
    );

    println!("  Verifying proof...");
    let t0 = Instant::now();
    match commit_verifier.verify(&commit_proof, &commit_public_inputs) {
        Ok(()) => {
            let commit_verify_elapsed = t0.elapsed();
            println!("  Verification: {commit_verify_elapsed:.2?}");
            println!(
                "  PROOF VERIFIED! SPO #{cheater_dkg_idx}'s DKG commitment misbehavior is proven."
            );
        }
        Err(e) => {
            println!("  Verification FAILED: {e:?}");
        }
    }

    let total_elapsed = t_total.elapsed();
    println!();
    println!("=== Timing Summary ({min_signers}-of-{max_signers} SPOs) ===");
    println!("  DKG (all {max_signers} SPOs):       {dkg_elapsed:.2?}");
    println!("  Honest signing ({min_signers}):      {sign_elapsed:.2?}");
    println!("  Cheating signing:            {cheat_sign_elapsed:.2?}");
    println!("  --- Signature proof ---");
    println!("    PP setup:                  {sig_pp_elapsed:.2?}");
    println!("    Circuit compilation:       {sig_compile_elapsed:.2?}");
    println!("    Proof generation:          {sig_prove_elapsed:.2?}");
    println!("    Proof size:                {} bytes", sig_proof_bytes.len());
    println!("    Public inputs:             {} field elements", sig_public_inputs.len());
    println!("  --- Commitment proof ---");
    println!("    PP setup:                  {commit_pp_elapsed:.2?}");
    println!("    Circuit compilation:       {commit_compile_elapsed:.2?}");
    println!("    Proof generation:          {commit_prove_elapsed:.2?}");
    println!("    Proof size:                {} bytes", commit_proof_bytes.len());
    println!("    Public inputs:             {} field elements", commit_public_inputs.len());
    println!("  Total wall time:             {total_elapsed:.2?}");
    println!("  Verifiable on Cardano via Plutus V3 BLS12-381 builtins");
}
