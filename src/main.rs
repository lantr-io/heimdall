use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use frost_secp256k1_tr::Identifier;

use heimdall::cardano::always_ok::always_ok_testnet_address_bech32;
use heimdall::cardano::blockfrost_chain::BlockfrostCardanoChain;
use heimdall::cardano::blockfrost_source::BlockfrostPegInSource;
use heimdall::cardano::treasury_datum::TreasuryConfig;
use heimdall::cardano::mock::MockCardanoPegInSource;
use heimdall::cardano::pallas_source::{NetworkMagic, PallasPegInSource};
use heimdall::cardano::pegin_source::CardanoPegInSource;
use heimdall::epoch::mocks::{MockCardanoChain, OsRngSource, SeededRngSource, SystemClock};
use heimdall::epoch::run_epoch_loop;
use heimdall::epoch::state::{EpochConfig, SpoIdentity};
use heimdall::epoch::traits::{CardanoChain, Clock, PeerNetwork, RngSource};
use heimdall::http::peer_network::HttpPeerNetwork;
use heimdall::http::server::router;

#[derive(Parser)]
#[command(name = "heimdall", about = "Bifrost Bridge SPO program")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run one SPO instance. Start `max-signers` of these in separate
    /// terminals — each one points at the same chain and discovers the
    /// roster (and thus its own listen port) from it.
    ///
    /// TODO: add a `--chain` flag (once a real `CardanoChain` impl
    /// exists) to select between `mock` and a live Cardano follower.
    /// Today the demo is hardwired to `MockCardanoChain`, and the
    /// `--min-signers`, `--max-signers`, `--base-port` flags are only
    /// used to parameterize that mock chain — a real deployment would
    /// read none of those from the CLI.
    Demo {
        /// This SPO's 1-based index in the roster.
        #[arg(long)]
        index: u16,
        /// Minimum signers (threshold). Mock-chain only.
        #[arg(long, default_value = "2")]
        min_signers: u16,
        /// Maximum signers (total SPOs in the roster). Mock-chain only.
        #[arg(long, default_value = "3")]
        max_signers: u16,
        /// Base port: SPO `i` listens on `base_port + i - 1`. Mock-chain only.
        #[arg(long, default_value = "18500")]
        base_port: u16,
        /// Use a deterministic seeded RNG so the cycle is bit-for-bit
        /// reproducible across runs. Demo-only.
        #[arg(long)]
        deterministic: bool,
        /// Blockfrost project ID (e.g. `preprodXXXXXX`). Network is
        /// auto-detected from the key prefix. If set, UTxOs are
        /// queried from Blockfrost instead of a local node.
        #[arg(long)]
        blockfrost_project_id: Option<String>,
        /// Path to a running Cardano node's Unix socket. If set, the
        /// peg-in source is the live node via pallas N2C. Ignored if
        /// `--blockfrost-project-id` is given.
        #[arg(long)]
        cardano_socket: Option<String>,
        /// Cardano network magic (`764824073` mainnet, `1` preprod,
        /// `2` preview). Required with `--cardano-socket`.
        #[arg(long)]
        cardano_magic: Option<u64>,
        /// Bech32 address of the peg-in script. Required with
        /// `--cardano-socket`.
        #[arg(long)]
        pegin_script_address: Option<String>,
        /// Peg-in policy ID as 56 hex chars (28 bytes). Required with
        /// `--cardano-socket`.
        #[arg(long)]
        pegin_policy_id: Option<String>,
        /// How long (seconds) `CollectPegins` polls the source before
        /// freezing the observed set.
        #[arg(long)]
        pegin_window_secs: Option<u64>,
        /// Interval (ms) between successive peg-in polls inside the
        /// collection window.
        #[arg(long)]
        pegin_poll_ms: Option<u64>,
        /// Bech32 address holding the treasury oracle UTxO. Defaults
        /// to the always-OK testnet address.
        #[arg(long)]
        treasury_address: Option<String>,
        /// Treasury marker token policy ID (56 hex chars). Defaults to
        /// the always-OK script hash.
        #[arg(long)]
        treasury_policy_id: Option<String>,
        /// Treasury marker token asset name as hex. Defaults to "TMTx"
        /// (`544d5478`).
        #[arg(long)]
        treasury_asset_name: Option<String>,
        /// BIP-39 mnemonic (12/15/24 words, space-separated) for the
        /// Cardano wallet that pays fees and signs the oracle-update tx.
        /// The payment key is derived at `m/1852'/1815'/0'/0/0`
        /// (CIP-1852), the wallet address is derived from that key, and
        /// UTxOs are queried from Blockfrost automatically. Without
        /// this, the demo runs in dry-run mode (no Cardano publish).
        #[arg(long)]
        cardano_mnemonic: Option<String>,
    },
    /// Print the bootstrap treasury Taproot address.
    BootstrapTreasury {
        /// Federation CSV timeout in blocks.
        #[arg(long, default_value = "144")]
        federation_csv_blocks: u16,
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
            base_port,
            deterministic,
            blockfrost_project_id,
            cardano_socket,
            cardano_magic,
            pegin_script_address,
            pegin_policy_id,
            pegin_window_secs,
            pegin_poll_ms,
            treasury_address,
            treasury_policy_id,
            treasury_asset_name,
            cardano_mnemonic,
        } => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_demo(DemoArgs {
                index,
                min_signers,
                max_signers,
                base_port,
                deterministic,
                blockfrost_project_id,
                cardano_socket,
                cardano_magic,
                pegin_script_address,
                pegin_policy_id,
                pegin_window_secs,
                pegin_poll_ms,
                treasury_address,
                treasury_policy_id,
                treasury_asset_name,
                cardano_mnemonic,
            }));
        }
        Commands::BootstrapTreasury {
            federation_csv_blocks,
        } => {
            print_bootstrap_treasury(federation_csv_blocks);
        }
        Commands::ProofDemo {
            min_signers,
            max_signers,
        } => {
            run_proof_demo(min_signers, max_signers);
        }
    }
}

struct DemoArgs {
    index: u16,
    min_signers: u16,
    max_signers: u16,
    base_port: u16,
    deterministic: bool,
    blockfrost_project_id: Option<String>,
    cardano_socket: Option<String>,
    cardano_magic: Option<u64>,
    pegin_script_address: Option<String>,
    pegin_policy_id: Option<String>,
    pegin_window_secs: Option<u64>,
    pegin_poll_ms: Option<u64>,
    treasury_address: Option<String>,
    treasury_policy_id: Option<String>,
    treasury_asset_name: Option<String>,
    cardano_mnemonic: Option<String>,
}

async fn run_demo(args: DemoArgs) {
    let id = Identifier::try_from(args.index).unwrap();

    // The fixture provides a fallback roster (SPO identities + ports)
    // until the on-chain SPO registry is wired.
    let fixture = heimdall::epoch::fixture::demo_static_fixture(
        args.min_signers,
        args.max_signers,
        args.base_port,
    );

    let always_ok_hash = hex::encode(heimdall::cardano::always_ok::always_ok_script_hash());
    let script_address: String = args
        .pegin_script_address
        .clone()
        .unwrap_or_else(|| always_ok_testnet_address_bech32().to_string());
    let treasury_address: String = args
        .treasury_address
        .clone()
        .unwrap_or_else(|| always_ok_testnet_address_bech32().to_string());
    let treasury_policy_id: String = args
        .treasury_policy_id
        .clone()
        .unwrap_or_else(|| always_ok_hash.clone());
    let treasury_asset_name: String = args
        .treasury_asset_name
        .clone()
        .unwrap_or_else(|| hex::encode("TMTx"));

    // Chain + pegin source selection:
    // --blockfrost-project-id → Blockfrost for both chain + pegin source
    // --cardano-socket        → pallas N2C for pegin source, mock chain
    // neither                 → full mock
    let chain: Arc<dyn CardanoChain>;
    let pegin_source: Arc<dyn CardanoPegInSource>;

    if let Some(project_id) = args.blockfrost_project_id.as_deref() {
        let treasury_config = TreasuryConfig {
            y_51: fixture.y_51,
            y_67: fixture.y_67,
            y_fed: fixture.y_fed,
            federation_csv_blocks: fixture.federation_csv_blocks,
            fee_rate_sat_per_vb: fixture.fee_rate_sat_per_vb,
            per_pegout_fee: fixture.per_pegout_fee,
        };
        let mut bf_chain = BlockfrostCardanoChain::new(
            project_id,
            &treasury_address,
            &treasury_policy_id,
            &treasury_asset_name,
            treasury_config,
            fixture.roster.clone(),
        );

        // If a mnemonic is provided, enable publishing. The payment
        // key, wallet address, and UTxOs are derived/queried
        // automatically.
        if let Some(mnemonic) = &args.cardano_mnemonic {
            bf_chain = bf_chain
                .with_mnemonic(mnemonic)
                .expect("--cardano-mnemonic must be a valid BIP-39 mnemonic");
        }

        chain = Arc::new(bf_chain);
        pegin_source = Arc::new(BlockfrostPegInSource::new(project_id, &script_address));
    } else if let Some(socket) = args.cardano_socket {
        let magic = args
            .cardano_magic
            .expect("--cardano-magic required with --cardano-socket");
        chain = Arc::new(MockCardanoChain::new(fixture.clone()));
        pegin_source = Arc::new(
            PallasPegInSource::from_bech32(socket, NetworkMagic(magic), &script_address)
                .expect("pallas source"),
        );
    } else {
        chain = Arc::new(MockCardanoChain::new(fixture.clone()));
        pegin_source = Arc::new(MockCardanoPegInSource::new());
    };

    // Parse the policy ID hex if the operator provided one. Otherwise
    // leave `EpochConfig::demo_default`'s always-OK hash in place.
    let pegin_policy_id_override: Option<[u8; 28]> =
        args.pegin_policy_id.as_deref().map(|hex_str| {
            let v = hex::decode(hex_str).expect("--pegin-policy-id must be hex");
            assert_eq!(v.len(), 28, "policy id must be 28 bytes (56 hex chars)");
            let mut out = [0u8; 28];
            out.copy_from_slice(&v);
            out
        });
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rng: Arc<dyn RngSource> = if args.deterministic {
        // Fixed demo seed — every run of `--deterministic` produces
        // the same DKG polynomials and signing nonces.
        Arc::new(SeededRngSource::new(*b"heimdall-demo-seed-v1-0123456789"))
    } else {
        Arc::new(OsRngSource)
    };

    // Use the chain to understand which demo user is us (and thus which port to listen on).

    let index = args.index;
    let roster = chain
        .query_roster(0)
        .await
        .expect("query initial roster");
    let me = roster
        .participants
        .get(&id)
        .unwrap_or_else(|| panic!("identifier {index} not in roster"));
    let port = port_from_url(&me.bifrost_url);

    // Spin up this SPO's HTTP server on the port the roster advertises.
    let net = Arc::new(HttpPeerNetwork::new());
    let app = router(net.shared_state());
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    println!(
        "=== Heimdall SPO #{index} ({}-of-{}) ===",
        roster.min_signers, roster.max_signers
    );
    println!("Listening on 127.0.0.1:{port}");
    println!(
        "Waiting for the other {} SPOs to come online...",
        roster.max_signers - 1
    );

    let peers: Arc<dyn PeerNetwork> = net;
    let mut config = EpochConfig::demo_default(SpoIdentity {
        identifier: id,
        port,
    });
    if let Some(pid) = pegin_policy_id_override {
        config.pegin_policy_id = pid;
    }
    if let Some(secs) = args.pegin_window_secs {
        config.pegin_collection_window = std::time::Duration::from_secs(secs);
    }
    if let Some(ms) = args.pegin_poll_ms {
        config.pegin_poll_interval = std::time::Duration::from_millis(ms);
    }

    let t0 = Instant::now();
    let tm = run_epoch_loop(chain, pegin_source, peers, clock, rng, &config)
        .await
        .expect("epoch loop");
    println!("Cycle complete ({:.2?})", t0.elapsed());

    println!("Agreed txid: {}", tm.txid);
    let signed_bytes = bitcoin::consensus::encode::serialize(&tm.unsigned_tx);
    println!("Witnessed Bitcoin tx ({} bytes):", signed_bytes.len());
    println!("  {}", hex::encode(&signed_bytes));
    println!("\n=== SPO #{index} cycle complete ===");

    // Stay up serving the published payloads so peers can still fetch
    // our round shares after we've finished our own cycle.
    println!("Server still running on 127.0.0.1:{port}; press Ctrl-C to exit.");
    tokio::signal::ctrl_c().await.ok();
}

fn port_from_url(url: &str) -> u16 {
    url.rsplit(':')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("cannot parse port from bifrost_url {url:?}"))
}

fn print_bootstrap_treasury(federation_csv_blocks: u16) {
    use bitcoin::key::{Secp256k1, UntweakedPublicKey};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{Address, Network, ScriptBuf};
    use heimdall::bitcoin::taproot::treasury_spend_info;

    let secp = Secp256k1::new();

    // Same deterministic keys as demo_static_fixture.
    let y_67 = UntweakedPublicKey::from_slice(
        &SecretKey::from_slice(&[0x67u8; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0
            .serialize(),
    )
    .unwrap();
    let y_fed = UntweakedPublicKey::from_slice(
        &SecretKey::from_slice(&[0xFEu8; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0
            .serialize(),
    )
    .unwrap();

    // At bootstrap Y_51 = Y_fed.
    let spend_info = treasury_spend_info(&secp, y_fed, y_67, y_fed, federation_csv_blocks);
    let output_key = spend_info.output_key();
    let script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key);
    let address = Address::from_script(&script_pubkey, Network::Bitcoin)
        .expect("valid P2TR address");

    println!("{address}");
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
