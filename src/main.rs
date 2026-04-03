use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use frost_secp256k1_tr::Identifier;

use heimdall::demo::orchestrator::SpoOrchestrator;
use heimdall::http::client::PeerInfo;

#[derive(Parser)]
#[command(name = "heimdall", about = "Bifrost Bridge SPO program")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run one SPO instance (use 3 terminals for a full demo)
    Demo {
        /// This SPO's 1-based index
        #[arg(long)]
        index: u16,
        /// Minimum signers (threshold)
        #[arg(long, default_value = "2")]
        min_signers: u16,
        /// Maximum signers (total SPOs)
        #[arg(long, default_value = "3")]
        max_signers: u16,
        /// Comma-separated peer URLs (e.g. http://localhost:8471,http://localhost:8472)
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,
        /// Port to listen on
        #[arg(long)]
        port: u16,
    },
    /// Run all SPOs in a single process (for easy testing)
    DemoLocal {
        /// Minimum signers (threshold)
        #[arg(long, default_value = "2")]
        min_signers: u16,
        /// Maximum signers (total SPOs)
        #[arg(long, default_value = "3")]
        max_signers: u16,
    },
    /// Run the original PLONK misbehavior proof demo
    ProofDemo {
        /// Minimum signers
        #[arg(default_value = "350")]
        min_signers: u16,
        /// Maximum signers
        #[arg(default_value = "400")]
        max_signers: u16,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Demo {
            index,
            min_signers,
            max_signers,
            peers,
            port,
        } => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_demo(index, min_signers, max_signers, peers, port));
        }
        Commands::DemoLocal {
            min_signers,
            max_signers,
        } => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_demo_local(min_signers, max_signers));
        }
        Commands::ProofDemo {
            min_signers,
            max_signers,
        } => {
            run_proof_demo(min_signers, max_signers);
        }
    }
}

async fn run_demo(
    index: u16,
    min_signers: u16,
    max_signers: u16,
    peer_urls: Vec<String>,
    port: u16,
) {
    assert!(
        index >= 1 && index <= max_signers,
        "index must be in 1..={max_signers}"
    );
    assert!(
        peer_urls.len() == (max_signers - 1) as usize,
        "need exactly {} peer URLs, got {}",
        max_signers - 1,
        peer_urls.len()
    );

    // Build peer list: assign identifiers 1..=max_signers, skipping our own index
    let mut peers = Vec::new();
    let mut peer_idx = 0;
    for i in 1..=max_signers {
        if i == index {
            continue;
        }
        peers.push(PeerInfo {
            identifier: Identifier::try_from(i).unwrap(),
            base_url: peer_urls[peer_idx].clone(),
        });
        peer_idx += 1;
    }

    let mut spo = SpoOrchestrator::new(
        Identifier::try_from(index).unwrap(),
        port,
        peers,
    );

    let _server = spo.start_server().await;
    println!("SPO #{index} listening on port {port}");

    let timeout = Duration::from_secs(60);

    // DKG
    println!("--- DKG ({min_signers}-of-{max_signers}) ---");
    let t0 = Instant::now();
    spo.run_dkg(min_signers, max_signers, timeout).await.unwrap();
    println!(
        "DKG complete ({:.2?}). Group public key: {:?}",
        t0.elapsed(),
        spo.group_public_key().unwrap()
    );

    // Sign
    let message = b"bifrost treasury handoff tx";
    println!("--- Signing message: \"{}\" ---", std::str::from_utf8(message).unwrap());
    let t0 = Instant::now();
    let signature = spo.run_signing(message, timeout).await.unwrap();
    let sig_bytes = signature.serialize().unwrap();
    println!(
        "Signing complete ({:.2?}). Signature: {}",
        t0.elapsed(),
        hex::encode(&sig_bytes)
    );

    // Verify
    spo.group_public_key()
        .unwrap()
        .verify(message, &signature)
        .expect("signature verification failed");
    println!("Signature verified successfully.");
}

async fn run_demo_local(min_signers: u16, max_signers: u16) {
    assert!(
        min_signers >= 2 && min_signers <= max_signers,
        "need 2 <= min_signers <= max_signers"
    );

    let base_port = 18500u16;
    let n = max_signers as usize;

    println!("=== Heimdall: {min_signers}-of-{max_signers} Local Demo ===");
    println!("Spawning {n} SPOs on ports {base_port}..{}", base_port + max_signers - 1);

    // Build all orchestrators
    let ports: Vec<(u16, u16)> = (1..=max_signers)
        .map(|i| (i, base_port + i - 1))
        .collect();

    let mut spos: Vec<SpoOrchestrator> = ports
        .iter()
        .map(|&(idx, port)| {
            let peers: Vec<PeerInfo> = ports
                .iter()
                .filter(|(i, _)| *i != idx)
                .map(|&(i, p)| PeerInfo {
                    identifier: Identifier::try_from(i).unwrap(),
                    base_url: format!("http://127.0.0.1:{p}"),
                })
                .collect();
            SpoOrchestrator::new(Identifier::try_from(idx).unwrap(), port, peers)
        })
        .collect();

    // Start all servers
    for spo in &spos {
        spo.start_server().await;
    }
    println!("All servers started.");

    let timeout = Duration::from_secs(30);

    // Run DKG concurrently
    println!("\n--- DKG ---");
    let t0 = Instant::now();
    let mut dkg_handles = Vec::new();
    // We need to move each spo into its own task. Use channels to get them back.
    let (tx, mut rx) = tokio::sync::mpsc::channel(n);
    for mut spo in spos.drain(..) {
        let tx = tx.clone();
        dkg_handles.push(tokio::spawn(async move {
            spo.run_dkg(min_signers, max_signers, timeout)
                .await
                .unwrap();
            tx.send(spo).await.unwrap();
        }));
    }
    drop(tx);
    while let Some(spo) = rx.recv().await {
        spos.push(spo);
    }
    // Sort by identifier for deterministic output
    spos.sort_by_key(|s| {
        let bytes = s.identifier.serialize();
        bytes
    });

    println!("DKG complete ({:.2?})", t0.elapsed());
    let group_key = spos[0].group_public_key().unwrap();
    println!("Group public key: {:?}", group_key);

    // Verify all SPOs got the same key
    for spo in &spos[1..] {
        assert_eq!(group_key, spo.group_public_key().unwrap());
    }
    println!("All {n} SPOs derived the same group public key.");

    // Sign with all SPOs
    let message = b"bifrost treasury handoff tx";
    println!(
        "\n--- Signing: \"{}\" ---",
        std::str::from_utf8(message).unwrap()
    );
    let t0 = Instant::now();
    let (tx, mut rx) = tokio::sync::mpsc::channel(n);
    let mut sign_handles = Vec::new();
    for mut spo in spos.drain(..) {
        let tx = tx.clone();
        let msg = message.to_vec();
        sign_handles.push(tokio::spawn(async move {
            let sig = spo.run_signing(&msg, timeout).await.unwrap();
            tx.send((spo, sig)).await.unwrap();
        }));
    }
    drop(tx);
    let mut signatures = Vec::new();
    while let Some((spo, sig)) = rx.recv().await {
        signatures.push(sig);
        spos.push(spo);
    }

    let signature = &signatures[0];
    for sig in &signatures[1..] {
        assert_eq!(signature, sig);
    }

    let sig_bytes = signature.serialize().unwrap();
    println!("Signing complete ({:.2?})", t0.elapsed());
    println!("Signature: {}", hex::encode(&sig_bytes));

    group_key
        .verify(message, signature)
        .expect("verification failed");
    println!("Signature verified successfully.");
    println!("\n=== Demo complete ===");
}

fn run_proof_demo(min_signers: u16, max_signers: u16) {
    use dusk_bytes::Serializable;
    use dusk_plonk::prelude::*;
    use rand::rngs::OsRng;

    use heimdall::circuits::commitment::{CommitmentCheckWitness, CommitmentMisbehaviorCircuit};
    use heimdall::circuits::signature::{SignatureShareCheckWitness, SignatureMisbehaviorCircuit};
    use heimdall::frost::{dkg, signing};
    use heimdall::gadgets::nonnative::bytes_to_limbs;

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
    println!(
        "  Key packages: {} participants",
        dkg_result.key_packages.len()
    );
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
    println!(
        "  Message: \"{}\"",
        std::str::from_utf8(message).unwrap()
    );
    println!();

    // --- Step 3: Cheating signing ---
    println!("--- Step 3: Cheating signing (SPO #{cheater_signer_idx} submits bad share) ---");
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
    println!("  Proving: SPO #{cheater_signer_idx}'s signature share z*G != expected point");

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

    let commit_gates_estimate = circuit_signers * 8 + 500;
    let commit_circuit_power = (commit_gates_estimate as f64).log2().ceil() as u32 + 1;
    println!("  Setting up public parameters (2^{commit_circuit_power})...");
    let t0 = Instant::now();
    let commit_label = b"bifrost-frost-commit-misbehavior";
    let commit_pp = PublicParameters::setup(1 << commit_circuit_power, &mut OsRng).unwrap();
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
    println!(
        "    Public inputs:             {} field elements",
        sig_public_inputs.len()
    );
    println!("  --- Commitment proof ---");
    println!("    PP setup:                  {commit_pp_elapsed:.2?}");
    println!("    Circuit compilation:       {commit_compile_elapsed:.2?}");
    println!("    Proof generation:          {commit_prove_elapsed:.2?}");
    println!(
        "    Proof size:                {} bytes",
        commit_proof_bytes.len()
    );
    println!(
        "    Public inputs:             {} field elements",
        commit_public_inputs.len()
    );
    println!("  Total wall time:             {total_elapsed:.2?}");
    println!("  Verifiable on Cardano via Plutus V3 BLS12-381 builtins");
}
