use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use frost_secp256k1_tr::Identifier;

use heimdall::cardano::blockfrost_chain::BlockfrostCardanoChain;
use heimdall::cardano::blockfrost_source::BlockfrostPegInSource;
use heimdall::cardano::treasury_datum::TreasuryConfig;
use heimdall::cardano::mock::MockCardanoPegInSource;
use heimdall::cardano::pallas_source::{NetworkMagic, PallasPegInSource};
use heimdall::cardano::pegin_source::CardanoPegInSource;
use heimdall::config::HeimdallConfig;
use heimdall::epoch::mocks::{MockCardanoChain, OsRngSource, SeededRngSource, SystemClock};
use heimdall::epoch::run_epoch_loop;
use heimdall::epoch::state::SpoIdentity;
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
        /// Path to a TOML configuration file. Omitted fields use
        /// compiled defaults. CLI flags override TOML values.
        #[arg(long)]
        config: Option<String>,
        /// This SPO's 1-based index in the roster.
        #[arg(long)]
        index: u16,
        /// Minimum signers (threshold). Mock-chain only.
        #[arg(long)]
        min_signers: Option<u16>,
        /// Maximum signers (total SPOs in the roster). Mock-chain only.
        #[arg(long)]
        max_signers: Option<u16>,
        /// Base port: SPO `i` listens on `base_port + i - 1`. Mock-chain only.
        #[arg(long)]
        base_port: Option<u16>,
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
    /// Print the bootstrap treasury Taproot address (Bitcoin side; the Cardano
    /// state UTxO is created by bootstrap-treasury-info).
    BootstrapTreasury {
        /// Path to a TOML configuration file.
        #[arg(long)]
        config: Option<String>,
        /// Federation CSV timeout in blocks (overrides TOML).
        #[arg(long)]
        federation_csv_blocks: Option<u16>,
    },
    /// Print the FROST group treasury address (Y_fed = Y_51 = FROST key).
    /// Runs a deterministic DKG to derive the group key, then prints the P2TR address.
    FrostTreasury {
        /// Path to a TOML configuration file.
        #[arg(long)]
        config: Option<String>,
        /// 32-byte FROST group key as hex (skips DKG if provided).
        #[arg(long)]
        frost_key: Option<String>,
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
    /// Self-send the bootstrap treasury UTXO so the treasury becomes output[0]
    /// (normalises a faucet funding tx; see internal-docs decisions D1).
    /// Key-path spend signed with the single y_fed key. Prints the signed tx;
    /// broadcasts only with --broadcast.
    TreasurySelfSend {
        #[arg(long)]
        config: Option<String>,
        /// Funding outpoint to spend, as <txid>:<vout>.
        #[arg(long)]
        outpoint: String,
        /// Input amount in satoshis.
        #[arg(long)]
        amount_sat: u64,
        /// Actually broadcast via bitcoin.rpc_url (default: build + print only).
        #[arg(long)]
        broadcast: bool,
    },
    /// Print the Cardano wallet base address + payment key hash (the TM-NFT mint
    /// authority) derived from the configured mnemonic / $HEIMDALL_MNEMONIC.
    WalletAddress {
        #[arg(long)]
        config: Option<String>,
    },
    /// Bootstrap (K1 / init) the Cardano `treasury_info` state UTxO: one-shot mint
    /// of the treasury NFT plus the initial TreasuryDatum (empty MPF identity root,
    /// BTC treasury P2TR scriptPubKey, BTC treasury outpoint, FROST group key).
    /// Spends a wallet UTxO as the one-shot; prints the signed tx, submits only
    /// with --submit. (Cardano side; bootstrap-treasury prints the BTC-side
    /// Taproot address.)
    BootstrapTreasuryInfo {
        #[arg(long)]
        config: Option<String>,
        /// Path to the bifrost Aiken blueprint (plutus.json) holding the compiled
        /// spos_registry + treasury_info validators.
        #[arg(long)]
        blueprint: String,
        /// The spos_registry one-shot bootstrap output ref, as
        /// <cardano_tx_hash>:<index>. Parameterizes the registry policy (and through
        /// it treasury_info). It must still be unspent when the registry linked list
        /// itself is bootstrapped later — pick a wallet UTxO that will be left alone
        /// until then.
        #[arg(long)]
        registry_bootstrap: String,
        /// Bootstrap BTC treasury P2TR scriptPubKey, hex (5120 || x-only key).
        #[arg(long)]
        btc_treasury_spk: String,
        /// Bootstrap BTC treasury outpoint, as <btc_txid>:<vout>. Stored in the
        /// datum in Bitcoin consensus form (txid little-endian || u32-LE vout).
        #[arg(long)]
        btc_outpoint: String,
        /// 32-byte FROST group key (y_fed, x-only), hex.
        #[arg(long)]
        frost_key: String,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
    },
    /// Scan binocular's on-chain peg-in requests over N2C, then build → sign →
    /// (optionally) broadcast the Treasury Movement sweeping the treasury + all
    /// discovered deposits into a new treasury output[0]. Key-path spend signed
    /// with the single y_fed key. See internal-docs sweep-pegins-handoff.md.
    SweepPegins {
        #[arg(long)]
        config: Option<String>,
        /// Path to a running Cardano node's Unix socket (e.g. /tmp/yaci-node.socket).
        #[arg(long)]
        cardano_socket: String,
        /// Cardano network magic (`42` for the yaci devnet).
        #[arg(long)]
        cardano_magic: u64,
        /// Bech32 address of the peg-in script holding the PegInRequest UTxOs.
        #[arg(long)]
        pegin_script_address: String,
        /// Peg-in policy ID as 56 hex chars (28 bytes).
        #[arg(long)]
        pegin_policy_id: String,
        /// Current treasury outpoint to sweep, as <txid>:<vout>.
        #[arg(long)]
        treasury_outpoint: String,
        /// Treasury input amount in satoshis.
        #[arg(long)]
        treasury_amount_sat: u64,
        /// Bech32 address of the `peg_out.ak` script holding PegOut UTxOs. A Treasury Movement
        /// collects EVERY pending peg-out here (technical_documentation §"Treasury Movement
        /// (Bitcoin)": "pay every pending peg-out") alongside every confirmed peg-in. Destination +
        /// amount come from each on-chain PegOut UTxO, never from the CLI.
        #[arg(long)]
        pegout_script_address: String,
        /// The bridged-token (fBTC) unit `<policy_hex><asset_name_hex>` used to read each PegOut
        /// UTxO's locked amount from its value.
        #[arg(long)]
        bridged_token_unit: String,
        /// Actually broadcast via bitcoin.rpc_url (default: build + print only).
        #[arg(long)]
        broadcast: bool,
        /// Override the locally-built signed TM with these raw BTC tx bytes (hex). Use when
        /// the on-chain TM bytes are fixed (already confirmed on Bitcoin) but the local builder
        /// would produce different bytes (e.g. different PIR set). Cardano TM datum will contain
        /// these bytes; Bitcoin broadcast is skipped regardless of `bitcoin.submit`.
        #[arg(long)]
        existing_tm_hex: Option<String>,
    },
}

fn load_config(path: Option<&str>) -> HeimdallConfig {
    match path {
        Some(p) => HeimdallConfig::from_file(std::path::Path::new(p)).unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }),
        None => HeimdallConfig::default(),
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Demo {
            config,
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
            let mut cfg = load_config(config.as_deref());

            // CLI flags override TOML values.
            if let Some(v) = min_signers { cfg.demo.min_signers = v; }
            if let Some(v) = max_signers { cfg.demo.max_signers = v; }
            if let Some(v) = base_port { cfg.http.base_port = v; }
            if let Some(ref v) = blockfrost_project_id {
                cfg.cardano.blockfrost_project_id = Some(v.clone());
            }
            if let Some(ref v) = cardano_socket {
                cfg.cardano.socket_path = Some(v.clone());
            }
            if let Some(v) = cardano_magic {
                cfg.cardano.network_magic = Some(v);
            }
            if let Some(ref v) = pegin_script_address {
                cfg.cardano.pegin_script_address = Some(v.clone());
            }
            if let Some(ref v) = pegin_policy_id {
                cfg.cardano.pegin_policy_id = Some(v.clone());
            }
            if let Some(v) = pegin_window_secs {
                cfg.protocol.pegin_collection_window_secs = v;
            }
            if let Some(v) = pegin_poll_ms {
                cfg.protocol.pegin_poll_interval_ms = v;
            }
            if let Some(ref v) = treasury_address {
                cfg.cardano.treasury_address = Some(v.clone());
            }
            if let Some(ref v) = treasury_policy_id {
                cfg.cardano.treasury_policy_id = Some(v.clone());
            }
            if let Some(ref v) = treasury_asset_name {
                cfg.cardano.treasury_asset_name = Some(v.clone());
            }
            if let Some(ref v) = cardano_mnemonic {
                cfg.cardano.mnemonic = Some(v.clone());
            }
            // Env var fallback: keep the real seed out of heimdall.toml
            // and the repo. Precedence: CLI --cardano-mnemonic > TOML
            // cardano.mnemonic > $HEIMDALL_MNEMONIC.
            if cfg.cardano.mnemonic.is_none() {
                if let Ok(v) = std::env::var("HEIMDALL_MNEMONIC") {
                    if !v.trim().is_empty() {
                        cfg.cardano.mnemonic = Some(v);
                    }
                }
            }

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(run_demo(cfg, index, deterministic));
        }
        Commands::BootstrapTreasury {
            config,
            federation_csv_blocks,
        } => {
            let mut cfg = load_config(config.as_deref());
            if let Some(v) = federation_csv_blocks {
                cfg.bitcoin.federation_csv_blocks = v as u32;
            }
            print_bootstrap_treasury(&cfg);
        }
        Commands::FrostTreasury { config, frost_key } => {
            let cfg = load_config(config.as_deref());
            print_frost_treasury(&cfg, frost_key.as_deref());
        }
        Commands::ProofDemo {
            min_signers,
            max_signers,
        } => {
            run_proof_demo(min_signers, max_signers);
        }
        Commands::TreasurySelfSend {
            config,
            outpoint,
            amount_sat,
            broadcast,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_treasury_self_send(&cfg, &outpoint, amount_sat, broadcast) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::WalletAddress { config } => {
            let cfg = load_config(config.as_deref());
            let mnemonic = resolve_mnemonic(&cfg).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                std::process::exit(1);
            });
            match (
                heimdall::cardano::wallet::wallet_address_from_mnemonic(&mnemonic),
                heimdall::cardano::wallet::derive_payment_key(&mnemonic),
            ) {
                (Ok(addr), Ok(key)) => {
                    println!("wallet base address: {addr}");
                    println!(
                        "payment key hash:    {}",
                        heimdall::cardano::wallet::pub_key_hash_hex(&key)
                    );
                }
                (Err(e), _) | (_, Err(e)) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::BootstrapTreasuryInfo {
            config,
            blueprint,
            registry_bootstrap,
            btc_treasury_spk,
            btc_outpoint,
            frost_key,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_bootstrap_treasury_info(
                &cfg,
                &blueprint,
                &registry_bootstrap,
                &btc_treasury_spk,
                &btc_outpoint,
                &frost_key,
                submit,
            ) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::SweepPegins {
            config,
            cardano_socket,
            cardano_magic,
            pegin_script_address,
            pegin_policy_id,
            treasury_outpoint,
            treasury_amount_sat,
            pegout_script_address,
            bridged_token_unit,
            broadcast,
            existing_tm_hex,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_sweep_pegins(
                &cfg,
                &cardano_socket,
                cardano_magic,
                &pegin_script_address,
                &pegin_policy_id,
                &treasury_outpoint,
                treasury_amount_sat,
                &pegout_script_address,
                &bridged_token_unit,
                broadcast,
                existing_tm_hex.as_deref(),
            ) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Apply the real TM-NFT minting policy to the chain when both `cardano.tm_script_cbor` and
/// `cardano.tm_control_ref` are configured (else leave it on the always-ok scaffold). Errors on a
/// half-configured pair or a malformed control ref (`<tx_hash>#<index>`).
fn apply_tm_policy(
    chain: BlockfrostCardanoChain,
    cfg: &HeimdallConfig,
) -> Result<BlockfrostCardanoChain, String> {
    match (&cfg.cardano.tm_script_cbor, &cfg.cardano.tm_control_ref) {
        (Some(cbor), Some(r)) => {
            let (h, i) = r
                .split_once('#')
                .and_then(|(h, i)| i.parse::<u32>().ok().map(|i| (h, i)))
                .ok_or_else(|| {
                    format!("cardano.tm_control_ref must be <tx_hash>#<index>, got '{r}'")
                })?;
            Ok(chain.with_tm_policy(cbor, h, i))
        }
        (None, None) => Ok(chain),
        _ => Err("set both cardano.tm_script_cbor and cardano.tm_control_ref (or neither)".into()),
    }
}

async fn run_demo(cfg: HeimdallConfig, index: u16, deterministic: bool) {
    let id = Identifier::try_from(index).unwrap();

    // The fixture provides a fallback roster (SPO identities + ports)
    // until the on-chain SPO registry is wired.
    let fixture = heimdall::epoch::fixture::demo_static_fixture_from_config(&cfg);

    let script_address: String = cfg
        .cardano
        .pegin_script_address
        .clone()
        .unwrap_or_default();
    let treasury_address: String = cfg
        .cardano
        .treasury_address
        .clone()
        .unwrap_or_default();
    let treasury_policy_id: String = cfg
        .cardano
        .treasury_policy_id
        .clone()
        .unwrap_or_default();
    let treasury_asset_name_hex: String = cfg
        .cardano
        .treasury_asset_name
        .clone()
        .unwrap_or_else(|| hex::encode("TMTx"));

    // Chain + pegin source selection:
    // blockfrost_project_id → Blockfrost for both chain + pegin source
    // socket_path           → pallas N2C for pegin source, mock chain
    // neither               → full mock
    let chain: Arc<dyn CardanoChain>;
    let pegin_source: Arc<dyn CardanoPegInSource>;

    if let Some(project_id) = cfg.cardano.blockfrost_project_id.as_deref() {
        let treasury_config = TreasuryConfig {
            y_51: fixture.y_51,
            y_fed: fixture.y_fed,
            federation_csv_blocks: fixture.federation_csv_blocks,
            fee_rate_sat_per_vb: fixture.fee_rate_sat_per_vb,
            per_pegout_fee: fixture.per_pegout_fee,
        };
        let mut bf_chain = BlockfrostCardanoChain::new(
            project_id,
            &treasury_address,
            &treasury_policy_id,
            &treasury_asset_name_hex,
            treasury_config,
            fixture.roster.clone(),
            cfg.cardano.blockfrost_url.as_deref(),
        );

        if let Some(mnemonic) = &cfg.cardano.mnemonic {
            let wallet_addr = heimdall::cardano::wallet::wallet_address_from_mnemonic(mnemonic)
                .expect("cardano.mnemonic must be a valid BIP-39 mnemonic");
            println!("Cardano wallet address: {wallet_addr}");
            bf_chain = bf_chain
                .with_mnemonic(mnemonic)
                .expect("cardano.mnemonic must be a valid BIP-39 mnemonic");
        }

        if let Some(rpc_url) = &cfg.bitcoin.rpc_url {
            bf_chain = bf_chain.with_btc_rpc(
                rpc_url,
                cfg.bitcoin.rpc_user.clone(),
                cfg.bitcoin.rpc_pass.clone(),
            );
        }

        bf_chain = bf_chain.with_submit_config(
            cfg.bitcoin.submit,
            cfg.cardano.submit_oracle,
            cfg.cardano.oracle_constructor,
        );
        let bf_chain = apply_tm_policy(bf_chain, &cfg).expect("invalid TM policy config");

        chain = Arc::new(bf_chain);
        pegin_source = Arc::new(BlockfrostPegInSource::new(
            project_id,
            &script_address,
            cfg.cardano.blockfrost_url.as_deref(),
        ));
    } else if let Some(socket) = cfg.cardano.socket_path.clone() {
        let magic = cfg
            .cardano
            .network_magic
            .expect("cardano.network_magic required with cardano.socket_path");
        chain = Arc::new(mock_chain_with_rpc(&cfg, fixture.clone()));
        pegin_source = Arc::new(
            PallasPegInSource::from_bech32(socket, NetworkMagic(magic), &script_address)
                .expect("pallas source"),
        );
    } else {
        chain = Arc::new(mock_chain_with_rpc(&cfg, fixture.clone()));
        pegin_source = Arc::new(MockCardanoPegInSource::new());
    };

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rng: Arc<dyn RngSource> = if deterministic {
        Arc::new(SeededRngSource::new(*b"heimdall-demo-seed-v1-0123456789"))
    } else {
        Arc::new(OsRngSource)
    };

    let roster = chain
        .query_roster(0)
        .await
        .expect("query initial roster");
    let me = roster
        .participants
        .get(&id)
        .unwrap_or_else(|| panic!("identifier {index} not in roster"));
    let port = port_from_url(&me.bifrost_url);

    let net = Arc::new(HttpPeerNetwork::new());
    let app = router(net.shared_state());
    let bind_addr = &cfg.http.bind_address;
    let listener = tokio::net::TcpListener::bind(format!("{bind_addr}:{port}"))
        .await
        .expect("bind");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    println!(
        "=== Heimdall SPO #{index} ({}-of-{}) ===",
        roster.min_signers, roster.max_signers
    );
    println!("Listening on {bind_addr}:{port}");
    println!(
        "Waiting for the other {} SPOs to come online...",
        roster.max_signers - 1
    );

    let peers: Arc<dyn PeerNetwork> = net;
    let config = cfg.to_epoch_config(SpoIdentity {
        identifier: id,
        port,
    });

    let t0 = Instant::now();
    let tm = run_epoch_loop(chain, pegin_source, peers, clock, rng, &config)
        .await
        .expect("epoch loop");
    println!("Cycle complete ({:.2?})", t0.elapsed());

    // ── Bitcoin TM transaction summary ──────────────────────────────────────
    println!("\n── Bitcoin Treasury Movement ──");
    println!("  txid:    {}", tm.txid);
    println!("  inputs:  {}", tm.unsigned_tx.input.len());
    for (i, (inp, prevout)) in tm.unsigned_tx.input.iter().zip(tm.prevouts.iter()).enumerate() {
        println!(
            "    [{}] {}:{} — {} sat  script={}",
            i,
            inp.previous_output.txid,
            inp.previous_output.vout,
            prevout.value.to_sat(),
            hex::encode(prevout.script_pubkey.as_bytes()),
        );
    }
    println!("  outputs: {}", tm.unsigned_tx.output.len());
    for (i, out) in tm.unsigned_tx.output.iter().enumerate() {
        println!(
            "    [{}] {} sat  script={}",
            i,
            out.value.to_sat(),
            hex::encode(out.script_pubkey.as_bytes()),
        );
    }
    let signed_bytes = bitcoin::consensus::encode::serialize(&tm.unsigned_tx);
    println!("  size:    {} bytes", signed_bytes.len());
    println!("  hex:     {}", hex::encode(&signed_bytes));

    println!("\n=== SPO #{index} cycle complete ===");

    println!("Server still running on {bind_addr}:{port}; press Ctrl-C to exit.");
    tokio::signal::ctrl_c().await.ok();
}

/// Build a `MockCardanoChain` from the fixture, wiring up the Bitcoin
/// RPC if `bitcoin.rpc_url` is set in the config.
fn mock_chain_with_rpc(
    cfg: &HeimdallConfig,
    fixture: heimdall::epoch::fixture::StaticFixture,
) -> MockCardanoChain {
    let mut chain = MockCardanoChain::new(fixture);
    if let Some(rpc_url) = &cfg.bitcoin.rpc_url {
        chain = chain.with_btc_rpc(
            rpc_url,
            cfg.bitcoin.rpc_user.clone(),
            cfg.bitcoin.rpc_pass.clone(),
        );
    }
    chain
}

fn port_from_url(url: &str) -> u16 {
    url.rsplit(':')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("cannot parse port from bifrost_url {url:?}"))
}

/// Derive the bootstrap federation keypair from `bitcoin.y_fed_seed_hex`.
/// At bootstrap Y_51 = Y_fed, so the seed's secret key signs every TM input
/// and its x-only pubkey is both the treasury and peg-in internal key.
fn y_fed_keypair(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    cfg: &HeimdallConfig,
) -> Result<(bitcoin::secp256k1::SecretKey, bitcoin::key::UntweakedPublicKey), String> {
    let seed: [u8; 32] = hex::decode(&cfg.bitcoin.y_fed_seed_hex)
        .map_err(|e| format!("y_fed_seed_hex: {e}"))?
        .try_into()
        .map_err(|_| "y_fed_seed_hex must be 32 bytes".to_string())?;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&seed)
        .map_err(|e| format!("seed -> sk: {e}"))?;
    let y_fed = sk.x_only_public_key(secp).0;
    Ok((sk, y_fed))
}

/// Parse a `<txid>:<vout>` outpoint.
fn parse_outpoint(s: &str) -> Result<bitcoin::OutPoint, String> {
    use std::str::FromStr;
    bitcoin::OutPoint::from_str(s)
        .map_err(|e| format!("outpoint must be <txid>:<vout>, got '{s}': {e}"))
}

/// Narrow the configured federation CSV timelock to `u16` (the width required
/// by the relative-timelock encoding). Errors if the value exceeds `u16::MAX`,
/// since a silent truncation would change the Taproot spend path and produce an
/// invalid scriptPubKey / signatures.
fn csv_blocks_u16(cfg: &HeimdallConfig) -> Result<u16, String> {
    u16::try_from(cfg.bitcoin.federation_csv_blocks).map_err(|_| {
        format!(
            "federation_csv_blocks ({}) exceeds u16::MAX ({})",
            cfg.bitcoin.federation_csv_blocks,
            u16::MAX
        )
    })
}

/// Build `FeeParams` from the Bitcoin config section.
fn fee_params_from_cfg(cfg: &HeimdallConfig) -> heimdall::bitcoin::tm_builder::FeeParams {
    heimdall::bitcoin::tm_builder::FeeParams {
        fee_rate_sat_per_vb: cfg.bitcoin.fee_rate_sat_per_vb,
        per_pegout_fee: bitcoin::Amount::from_sat(cfg.bitcoin.per_pegout_fee_sat),
    }
}

/// Build the Bitcoin RPC config; errors if `bitcoin.rpc_url` is unset.
fn btc_rpc_config(cfg: &HeimdallConfig) -> Result<heimdall::cardano::btc_rpc::BtcRpcConfig, String> {
    let url = cfg
        .bitcoin
        .rpc_url
        .clone()
        .ok_or_else(|| "bitcoin.rpc_url not set in config".to_string())?;
    Ok(heimdall::cardano::btc_rpc::BtcRpcConfig {
        url,
        user: cfg.bitcoin.rpc_user.clone(),
        pass: cfg.bitcoin.rpc_pass.clone(),
    })
}

/// Build (and optionally broadcast) a self-send of the bootstrap treasury UTXO
/// to a tx whose output[0] is the treasury — so `query_treasury` (which reads
/// vout 0) sees it. Key-path spend with the single `y_fed` key.
fn run_treasury_self_send(
    cfg: &HeimdallConfig,
    outpoint: &str,
    amount_sat: u64,
    broadcast: bool,
) -> Result<(), String> {
    use bitcoin::key::Secp256k1;
    use bitcoin::{Amount, ScriptBuf};
    use heimdall::bitcoin::taproot::treasury_spend_info;
    use heimdall::bitcoin::tm_builder::{build_tm, sign_tm_single_key, TreasuryInput};
    use heimdall::cardano::btc_rpc::broadcast_btc_tx;

    let secp = Secp256k1::new();
    let outpoint = parse_outpoint(outpoint)?;
    let (sk, y_fed) = y_fed_keypair(&secp, cfg)?;
    let csv = csv_blocks_u16(cfg)?;

    let spend_info = treasury_spend_info(&secp, y_fed, y_fed, csv);
    let treasury_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    // Only the treasury input, no peg-ins/peg-outs => single output[0] = treasury.
    let unsigned = build_tm(
        TreasuryInput {
            outpoint,
            value: Amount::from_sat(amount_sat),
            spend_info,
        },
        vec![],
        vec![],
        treasury_spk,
        &fee_params_from_cfg(cfg),
    )
    .map_err(|e| format!("build self-send: {e}"))?;

    let signed = sign_tm_single_key(&secp, &unsigned, &sk)
        .map_err(|e| format!("sign self-send: {e}"))?;
    let raw = bitcoin::consensus::encode::serialize(&signed);

    println!("self-send txid : {}", signed.compute_txid());
    println!("output[0]      : {} sat (treasury)", signed.output[0].value.to_sat());
    println!("raw tx         : {}", hex::encode(&raw));

    if !broadcast {
        println!("(not broadcast — pass --broadcast to send)");
        return Ok(());
    }
    let rpc = btc_rpc_config(cfg)?;
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(broadcast_btc_tx(&rpc, &raw))
        .map_err(|e| format!("broadcast: {e}"))?;
    println!("broadcast OK");
    Ok(())
}

/// The Cardano wallet mnemonic: `cardano.mnemonic` from config, else
/// `$HEIMDALL_MNEMONIC`.
fn resolve_mnemonic(cfg: &HeimdallConfig) -> Result<String, String> {
    cfg.cardano
        .mnemonic
        .clone()
        .or_else(|| {
            std::env::var("HEIMDALL_MNEMONIC")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .ok_or_else(|| "no mnemonic (set cardano.mnemonic or $HEIMDALL_MNEMONIC)".to_string())
}

/// Parse `<cardano_tx_hash>:<index>` into a 32-byte tx id + output index.
/// The index is bounded to `u32` (the ledger's output-index width) so a typo
/// can never silently wrap into a negative Plutus Int downstream.
fn parse_cardano_outref(s: &str) -> Result<([u8; 32], u32), String> {
    let (h, i) = s
        .split_once(':')
        .ok_or_else(|| format!("expected <tx_hash>:<index>, got '{s}'"))?;
    let tx_id: [u8; 32] = hex::decode(h)
        .map_err(|e| format!("tx hash hex: {e}"))?
        .try_into()
        .map_err(|_| "tx hash must be 32 bytes".to_string())?;
    let index: u32 = i.parse().map_err(|e| format!("output index: {e}"))?;
    Ok((tx_id, index))
}

/// Build (and with `submit`, broadcast) the K1 `treasury_info` bootstrap mint.
/// See `heimdall::cardano::treasury_bootstrap` for the on-chain contract.
fn run_bootstrap_treasury_info(
    cfg: &HeimdallConfig,
    blueprint_path: &str,
    registry_bootstrap: &str,
    btc_treasury_spk: &str,
    btc_outpoint: &str,
    frost_key: &str,
    submit: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{spos_registry_script, treasury_info_script};
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::treasury_bootstrap::{bootstrap_datum, build_treasury_bootstrap_tx};
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = std::fs::read_to_string(blueprint_path)
        .map_err(|e| format!("read blueprint {blueprint_path}: {e}"))?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let registry = spos_registry_script(&blueprint_json, &reg_tx_id, u64::from(reg_index))
        .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let treasury = treasury_info_script(&blueprint_json, &registry.hash)
        .map_err(|e| format!("parameterize treasury_info: {e}"))?;
    println!("registry policy id:   {}", registry.hash_hex());
    println!("treasury_info policy: {}", treasury.hash_hex());

    let spk = hex::decode(btc_treasury_spk).map_err(|e| format!("--btc-treasury-spk: {e}"))?;
    if spk.len() != 34 || spk[..2] != [0x51, 0x20] {
        return Err(format!(
            "--btc-treasury-spk must be a P2TR scriptPubKey (34 bytes, 5120 || x-only key), \
             got {} bytes",
            spk.len()
        ));
    }
    let outpoint = parse_outpoint(btc_outpoint)?;
    let utxo_id = bitcoin::consensus::encode::serialize(&outpoint);
    let frost = hex::decode(frost_key).map_err(|e| format!("--frost-key: {e}"))?;
    bitcoin::XOnlyPublicKey::from_slice(&frost)
        .map_err(|e| format!("--frost-key is not a valid x-only secp256k1 point: {e}"))?;
    let datum = bootstrap_datum(spk, utxo_id, frost);

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    let raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    // Never let coin selection consume the registry one-shot outref: spending
    // it would make the spos_registry bootstrap impossible, and treasury.ak's
    // spend path requires a registry-policy mint — the state UTxO created here
    // would be frozen at bootstrap forever.
    let reg_tx_hash_hex = hex::encode(reg_tx_id);
    let wallet_utxos: Vec<WalletUtxo> = raw
        .iter()
        .map(WalletUtxo::from_bf)
        .filter(|u| !(u.tx_hash == reg_tx_hash_hex && u.output_index == reg_index))
        .collect();
    if wallet_utxos.is_empty() {
        return Err(format!(
            "wallet has no spendable UTxOs besides the registry bootstrap outref — \
             fund it first (address: {wallet_addr})"
        ));
    }
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let built = build_treasury_bootstrap_tx(
        &treasury,
        &wallet_addr,
        &wallet_utxos,
        &datum,
        &key,
        Some(cost_models),
    )
    .map_err(|e| format!("build bootstrap tx: {e}"))?;

    println!(
        "one-shot input_ref:   {}#{}",
        built.input_ref.0, built.input_ref.1
    );
    println!(
        "treasury NFT:         {}.{}",
        built.policy_id_hex, built.asset_name_hex
    );
    println!("state UTxO address:   {}", built.script_address);
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    if !submit {
        println!("(dry run — pass --submit to broadcast via Blockfrost)");
        return Ok(());
    }
    let cbor = hex::decode(&built.signed_tx_hex).map_err(|e| e.to_string())?;
    let mut settings = blockfrost::BlockFrostSettings::new();
    if let Some(url) = cfg.cardano.blockfrost_url.as_deref() {
        settings.base_url = Some(url.to_string());
    }
    let api = blockfrost::BlockfrostAPI::new(pid, settings);
    let tx_hash = rt
        .block_on(api.transactions_submit(cbor))
        .map_err(|e| format!("blockfrost submit: {e}"))?;
    println!("submitted: tx_hash={tx_hash}");
    Ok(())
}

/// Scan binocular's on-chain `PegInRequest` UTxOs over N2C, then build, sign and
/// (optionally) broadcast the Treasury Movement sweeping the current treasury +
/// all discovered deposits into a new treasury `output[0]`.
///
/// The deposits are *discovered* from Cardano (not hand-typed): each PIR is
/// validated by `parse_pegin_request`, which reconstructs the peg-in P2TR from
/// `(y_fed, depositor_xonly, refund_timeout)` and requires a matching output —
/// so a successful parse is itself proof the spend-info matches the on-chain
/// scriptPubKey. The treasury input is passed by arg (its Cardano oracle UTxO is
/// not required for the pure-Bitcoin sweep).
#[allow(clippy::too_many_arguments)]
fn run_sweep_pegins(
    cfg: &HeimdallConfig,
    cardano_socket: &str,
    cardano_magic: u64,
    pegin_script_address: &str,
    pegin_policy_id: &str,
    treasury_outpoint: &str,
    treasury_amount_sat: u64,
    pegout_script_address: &str,
    bridged_token_unit: &str,
    broadcast: bool,
    existing_tm_hex: Option<&str>,
) -> Result<(), String> {
    use bitcoin::key::Secp256k1;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction};
    use heimdall::bitcoin::taproot::treasury_spend_info;
    use heimdall::bitcoin::tm_builder::{
        build_tm, sign_tm_single_key, PegInInput, PegOutRequest, TreasuryInput,
    };
    use heimdall::cardano::bf_http;
    use heimdall::cardano::pegout_datum::fetch_pegout_requests;
    use heimdall::cardano::blockfrost_source::BlockfrostPegInSource;
    use heimdall::cardano::btc_rpc::broadcast_btc_tx;
    use heimdall::cardano::pallas_source::{NetworkMagic, PallasPegInSource};
    use heimdall::cardano::pegin_datum::parse_pegin_request;
    use heimdall::cardano::pegin_source::CardanoPegInSource;

    let secp = Secp256k1::new();
    let (sk, y_fed) = y_fed_keypair(&secp, cfg)?;
    let csv = csv_blocks_u16(cfg)?;
    let refund_timeout = cfg.bitcoin.pegin_refund_timeout_blocks;

    let policy_id: [u8; 28] = hex::decode(pegin_policy_id)
        .map_err(|e| format!("pegin_policy_id: {e}"))?
        .try_into()
        .map_err(|_| "pegin_policy_id must be 28 bytes (56 hex chars)".to_string())?;

    // One runtime for both the peg-in scan and the (optional) broadcast.
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    // Scan PegInRequests: via Blockfrost (incl. yaci-devkit's blockfrost_url) when configured,
    // else via the N2C socket.
    let source: Box<dyn CardanoPegInSource> =
        if let Some(pid) = cfg.cardano.blockfrost_project_id.as_deref() {
            Box::new(BlockfrostPegInSource::new(
                pid,
                pegin_script_address,
                cfg.cardano.blockfrost_url.as_deref(),
            ))
        } else {
            Box::new(
                PallasPegInSource::from_bech32(
                    cardano_socket,
                    NetworkMagic(cardano_magic),
                    pegin_script_address,
                )
                .map_err(|e| format!("pallas source: {e}"))?,
            )
        };
    let reqs = rt
        .block_on(source.query_pegin_requests(&policy_id))
        .map_err(|e| format!("query_pegin_requests: {e}"))?;
    println!("scanned {} peg-in request(s) at {pegin_script_address}", reqs.len());

    // Each parse reconstructs and matches the peg-in P2TR, so the returned
    // `spend_info` is itself proof the spend info matches the on-chain
    // scriptPubKey — reuse it directly rather than re-deriving.
    let mut pegin_inputs = Vec::with_capacity(reqs.len());
    for req in &reqs {
        let parsed = parse_pegin_request(req, y_fed, refund_timeout)
            .map_err(|e| format!("parse_pegin_request: {e}"))?;
        println!(
            "  peg-in {}:{} — {} sat (depositor {})",
            parsed.btc_txid,
            parsed.btc_vout,
            parsed.value.to_sat(),
            hex::encode(parsed.depositor_xonly_pubkey.serialize()),
        );
        pegin_inputs.push(PegInInput {
            outpoint: OutPoint {
                txid: parsed.btc_txid,
                vout: parsed.btc_vout,
            },
            value: parsed.value,
            spend_info: parsed.spend_info,
        });
    }

    // Collect EVERY pending peg-out at the peg_out.ak address (the SPO's spec job — a TM pays every
    // pending peg-out alongside sweeping every peg-in). Destination scriptPubKey + amount come from
    // each on-chain PegOut UTxO. Blockfrost-backed (the demo path); the pallas N2C path is peg-in only.
    // Peg-out collection is Blockfrost-only (the N2C path is peg-in only). When no Blockfrost is
    // configured, skip it with a loud warning rather than hard-failing — an N2C-only sweep that
    // previously worked must still build a TM (it just can't include peg-outs over N2C).
    let pegout_data = match cfg.cardano.blockfrost_project_id.as_deref() {
        Some(pid) => {
            let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
            rt.block_on(fetch_pegout_requests(
                &base_url,
                pid,
                pegout_script_address,
                bridged_token_unit,
            ))
            .map_err(|e| format!("fetch_pegout_requests: {e}"))?
        }
        None => {
            eprintln!(
                "[sweep] no cardano.blockfrost_project_id — peg-out collection is Blockfrost-only \
                 (N2C is peg-in only); building TM without peg-outs"
            );
            Vec::new()
        }
    };
    println!(
        "scanned {} peg-out request(s) at {pegout_script_address}",
        pegout_data.len()
    );
    let mut pegout_requests = Vec::with_capacity(pegout_data.len());
    for po in &pegout_data {
        println!(
            "  peg-out → {} — {} sat",
            hex::encode(&po.destination_script_pubkey),
            po.amount_sat
        );
        pegout_requests.push(PegOutRequest {
            script_pubkey: ScriptBuf::from_bytes(po.destination_script_pubkey.clone()),
            amount: Amount::from_sat(po.amount_sat),
        });
    }

    let treasury_outpoint = parse_outpoint(treasury_outpoint)?;
    let treasury_spend_info = treasury_spend_info(&secp, y_fed, y_fed, csv);
    let treasury_spk = ScriptBuf::new_p2tr_tweaked(treasury_spend_info.output_key());

    // Treasury self-funds the fee; output[0] = new treasury = sum(inputs) − fee; outputs[1..] = one
    // payment per peg-out (sorted by scriptPubKey inside build_tm).
    let unsigned = build_tm(
        TreasuryInput {
            outpoint: treasury_outpoint,
            value: Amount::from_sat(treasury_amount_sat),
            spend_info: treasury_spend_info,
        },
        pegin_inputs,
        pegout_requests,
        treasury_spk.clone(),
        &fee_params_from_cfg(cfg),
    )
    .map_err(|e| format!("build sweep: {e}"))?;

    // Surface any peg-outs the TM dropped as unpayable (non-standard destination
    // or sub-dust after fee) so the operator sees them — the TM still pays the
    // rest rather than aborting.
    for s in &unsigned.skipped_pegouts {
        eprintln!(
            "[sweep] skipped peg-out → {} ({} sat): {}",
            hex::encode(s.script_pubkey.as_bytes()),
            s.amount.to_sat(),
            s.reason
        );
    }

    // output[0] is the new treasury; if it doesn't carry the treasury
    // scriptPubKey the whole balance would move to the wrong address, so
    // refuse before signing rather than broadcast a misdirected sweep.
    if unsigned.tx.output[0].script_pubkey != treasury_spk {
        return Err(format!(
            "output[0] scriptPubKey {} does not match treasury spk {}",
            hex::encode(unsigned.tx.output[0].script_pubkey.as_bytes()),
            hex::encode(treasury_spk.as_bytes()),
        ));
    }

    let signed = sign_tm_single_key(&secp, &unsigned, &sk)
        .map_err(|e| format!("sign sweep: {e}"))?;
    let local_raw = bitcoin::consensus::encode::serialize(&signed);
    // If an existing-on-Bitcoin TM is provided, the effective tx posted to Cardano is THAT one,
    // not the locally-built one. Deserialize it so every subsequent print (txid, inputs, outputs)
    // reflects the bytes Cardano will actually see — operators would otherwise copy-paste the
    // wrong txid from the locally-signed value.
    let (effective_tx, raw, override_in_effect): (Transaction, Vec<u8>, bool) =
        if let Some(hex_str) = existing_tm_hex {
            let trimmed = hex_str.trim();
            let bytes = hex::decode(trimmed)
                .map_err(|e| format!("existing_tm_hex: {e}"))?;
            let tx: Transaction = bitcoin::consensus::deserialize(&bytes).map_err(|e| {
                format!("existing_tm_hex: not a valid Bitcoin transaction: {e}")
            })?;
            // Slice into `trimmed` (not the un-trimmed `hex_str`) — otherwise leading/trailing
            // whitespace makes `hex_str.len()` bigger than `trimmed.len()` and the slice panics.
            let preview_end = trimmed.len().min(20);
            println!(
                "  [override] using existing TM bytes ({} bytes hex={}…)",
                bytes.len(),
                &trimmed[..preview_end]
            );
            (tx, bytes, true)
        } else {
            (signed, local_raw, false)
        };

    println!("\n── Treasury Movement (sweep peg-ins) ──");
    println!("  txid:    {}", effective_tx.compute_txid());
    println!("  inputs:  {}", effective_tx.input.len());
    for (i, (inp, prevout)) in effective_tx.input.iter().zip(unsigned.prevouts.iter()).enumerate() {
        println!(
            "    [{}] {}:{} — {} sat  script={}",
            i,
            inp.previous_output.txid,
            inp.previous_output.vout,
            prevout.value.to_sat(),
            hex::encode(prevout.script_pubkey.as_bytes()),
        );
    }
    println!("  outputs: {}", effective_tx.output.len());
    for (i, out) in effective_tx.output.iter().enumerate() {
        println!(
            "    [{}] {} sat  script={}",
            i,
            out.value.to_sat(),
            hex::encode(out.script_pubkey.as_bytes()),
        );
    }
    println!(
        "  output[0] (new treasury): {} sat",
        effective_tx.output[0].value.to_sat()
    );
    println!("  size:    {} bytes", raw.len());
    println!("  hex:     {}", hex::encode(&raw));

    // `--broadcast` is the master "execute side effects" gate. Without it, sweep-pegins only
    // builds, signs, and prints the TM (no Cardano post, no Bitcoin broadcast) — a safe dry run.
    if !broadcast {
        println!("\n(not broadcast — pass --broadcast to post the TM / send)");
        return Ok(());
    }

    // Protocol path (technical_documentation.md §"Post signed TM as Unconfirmed TM tx"): when
    // Blockfrost is configured, hand the signed TM to the shared Cardano chain, which POSTS the
    // Unconfirmed TM UTxO to Cardano (Constr(0, [signed_btc_tx]) at treasury_address) when
    // `cardano.submit_oracle` is set, and broadcasts to Bitcoin when `bitcoin.submit` is set. A
    // watchtower (binocular) then relays to Bitcoin and runs the validated Confirm. NOTE: whether
    // the BTC tx is broadcast is governed by config (`bitcoin.submit`), NOT by --broadcast — on
    // this setup heimdall posts to Cardano while binocular `relay` carries it to Bitcoin.
    if let Some(project_id) = cfg.cardano.blockfrost_project_id.as_deref() {
        let fixture = heimdall::epoch::fixture::demo_static_fixture_from_config(cfg);
        let treasury_address = cfg
            .cardano
            .treasury_address
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "cardano.treasury_address must be set (the TM validator address)".to_string())?;
        let treasury_policy_id = cfg.cardano.treasury_policy_id.clone().unwrap_or_default();
        let treasury_asset_name_hex = cfg
            .cardano
            .treasury_asset_name
            .clone()
            .unwrap_or_else(|| hex::encode("TMTx"));
        let treasury_config = TreasuryConfig {
            y_51: fixture.y_51,
            y_fed: fixture.y_fed,
            federation_csv_blocks: fixture.federation_csv_blocks,
            fee_rate_sat_per_vb: fixture.fee_rate_sat_per_vb,
            per_pegout_fee: fixture.per_pegout_fee,
        };
        let mut chain = BlockfrostCardanoChain::new(
            project_id,
            &treasury_address,
            &treasury_policy_id,
            &treasury_asset_name_hex,
            treasury_config,
            fixture.roster.clone(),
            cfg.cardano.blockfrost_url.as_deref(),
        );
        if let Some(mnemonic) = &cfg.cardano.mnemonic {
            chain = chain
                .with_mnemonic(mnemonic)
                .map_err(|e| format!("with_mnemonic: {e}"))?;
        }
        if let Some(rpc_url) = &cfg.bitcoin.rpc_url {
            chain = chain.with_btc_rpc(
                rpc_url,
                cfg.bitcoin.rpc_user.clone(),
                cfg.bitcoin.rpc_pass.clone(),
            );
        }
        // Honor the documented contract: when the BTC TM bytes come from `--existing-tm-hex`,
        // the tx is already on Bitcoin (and would be a double-spend), so DON'T let the chain
        // re-broadcast it regardless of how `bitcoin.submit` is set in the config.
        let bitcoin_submit = if override_in_effect {
            false
        } else {
            cfg.bitcoin.submit
        };
        chain = chain.with_submit_config(
            bitcoin_submit,
            cfg.cardano.submit_oracle,
            cfg.cardano.oracle_constructor,
        );
        let chain = apply_tm_policy(chain, cfg)?;
        rt.block_on(chain.submit_signed_tm(&raw))
            .map_err(|e| format!("submit_signed_tm: {e}"))?;
        return Ok(());
    }

    // Legacy fallback: no Blockfrost configured → direct Bitcoin broadcast only (pre-protocol
    // shortcut; the TM never lands on Cardano, so binocular confirm-tmtx has nothing to confirm).
    let rpc = btc_rpc_config(cfg)?;
    rt.block_on(broadcast_btc_tx(&rpc, &raw))
        .map_err(|e| format!("broadcast: {e}"))?;
    println!("broadcast OK");
    Ok(())
}

fn print_bootstrap_treasury(cfg: &HeimdallConfig) {
    use bitcoin::key::{Secp256k1, UntweakedPublicKey};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{Address, ScriptBuf};
    use heimdall::bitcoin::taproot::treasury_spend_info;

    let secp = Secp256k1::new();

    let y_fed_seed: [u8; 32] = hex::decode(&cfg.bitcoin.y_fed_seed_hex)
        .expect("bitcoin.y_fed_seed_hex must be valid hex")
        .try_into()
        .expect("bitcoin.y_fed_seed_hex must be 32 bytes");

    let y_fed = UntweakedPublicKey::from_slice(
        &SecretKey::from_slice(&y_fed_seed)
            .unwrap()
            .x_only_public_key(&secp)
            .0
            .serialize(),
    )
    .unwrap();

    let network = cfg.bitcoin.parsed_network();
    let csv_blocks = csv_blocks_u16(cfg).unwrap_or_else(|e| panic!("{e}"));

    // At bootstrap Y_51 = Y_fed.
    let spend_info = treasury_spend_info(&secp, y_fed, y_fed, csv_blocks);
    let output_key = spend_info.output_key();
    let script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key);
    let address = Address::from_script(&script_pubkey, network)
        .expect("valid P2TR address");

    println!("{address}");
}

/// Print the treasury Taproot address when Y_fed = Y_51 = FROST group key.
///
/// `frost_key_hex` must be the 32-byte x-only FROST group key as hex.
fn print_frost_treasury(cfg: &HeimdallConfig, frost_key_hex: Option<&str>) {
    use bitcoin::key::{Secp256k1, UntweakedPublicKey};
    use bitcoin::{Address, ScriptBuf};
    use heimdall::bitcoin::taproot::treasury_spend_info;

    let secp = Secp256k1::new();
    let network = cfg.bitcoin.parsed_network();
    let csv_blocks = csv_blocks_u16(cfg).unwrap_or_else(|e| panic!("{e}"));

    let hex_str = frost_key_hex.expect("--frost-key <32-byte-hex> is required");
    let bytes: Vec<u8> = hex::decode(hex_str).expect("--frost-key must be valid hex");
    assert_eq!(bytes.len(), 32, "--frost-key must be 32 bytes (x-only pubkey)");
    let group_key = UntweakedPublicKey::from_slice(&bytes)
        .expect("--frost-key must be a valid secp256k1 x-only pubkey");

    println!("FROST group key (x-only): {}", hex::encode(group_key.serialize()));

    // Y_fed = Y_51 = FROST group key
    let spend_info = treasury_spend_info(&secp, group_key, group_key, csv_blocks);
    let output_key = spend_info.output_key();
    let script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key);
    let address = Address::from_script(&script_pubkey, network).expect("valid P2TR address");

    println!("Treasury address (Y_fed=Y_51=FROST): {address}");
    println!("Script pubkey: {}", hex::encode(script_pubkey.as_bytes()));
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

#[cfg(test)]
mod tests {
    use super::parse_cardano_outref;

    #[test]
    fn parse_cardano_outref_ok() {
        let (tx_id, index) = parse_cardano_outref(&format!("{}:7", "ab".repeat(32))).unwrap();
        assert_eq!(tx_id, [0xab; 32]);
        assert_eq!(index, 7);
    }

    #[test]
    fn parse_cardano_outref_rejects_malformed() {
        // no separator
        assert!(parse_cardano_outref("aabb").is_err());
        // hash not 32 bytes
        assert!(parse_cardano_outref("aabb:0").is_err());
        // non-hex hash
        assert!(parse_cardano_outref(&format!("{}:0", "zz".repeat(32))).is_err());
        // non-numeric / out-of-u32-range index
        assert!(parse_cardano_outref(&format!("{}:x", "ab".repeat(32))).is_err());
        assert!(parse_cardano_outref(&format!("{}:4294967296", "ab".repeat(32))).is_err());
    }
}
