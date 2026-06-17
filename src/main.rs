use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use frost_secp256k1_tr::Identifier;

use heimdall::cardano::blockfrost_chain::BlockfrostCardanoChain;
use heimdall::cardano::blockfrost_source::BlockfrostPegInSource;
use heimdall::cardano::mock::MockCardanoPegInSource;
use heimdall::cardano::pallas_source::{NetworkMagic, PallasPegInSource};
use heimdall::cardano::pegin_source::CardanoPegInSource;
use heimdall::cardano::treasury_datum::TreasuryConfig;
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
        /// Legacy fallback: this SPO's 1-based roster index, used only for the
        /// config/mock fixture demo (whose roster carries no bifrost_id_pk). With
        /// a real on-chain roster the node identifies itself by its bifrost key.
        #[arg(long)]
        index: Option<u16>,
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
    /// Bootstrap the spos_registry linked list: spend the one-shot outref that
    /// parameterizes the registry policy and mint the "reg-root" anchor NFT to
    /// the registry script address. Prints the signed tx, submits only with
    /// --submit. Must confirm before any register-spo can be built.
    BootstrapRegistry {
        #[arg(long)]
        config: Option<String>,
        /// Path to the bifrost Aiken blueprint (plutus.json).
        #[arg(long)]
        blueprint: String,
        /// The spos_registry one-shot bootstrap output ref, as
        /// <cardano_tx_hash>:<index>. Must still be an unspent wallet UTxO,
        /// and the same value that parameterized bootstrap-treasury-info.
        #[arg(long)]
        registry_bootstrap: String,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
    },
    /// Deploy the spos_registry script as a reference script (output #0 at the
    /// wallet's own address, reclaimable). register_spo references it instead
    /// of embedding the ~12 KB script twice, which would not fit in the 16 KB
    /// tx-size limit.
    DeployRegistryRef {
        #[arg(long)]
        config: Option<String>,
        /// Path to the bifrost Aiken blueprint (plutus.json).
        #[arg(long)]
        blueprint: String,
        /// The spos_registry one-shot bootstrap output ref (<tx_hash>:<index>).
        #[arg(long)]
        registry_bootstrap: String,
        /// Actually submit via Blockfrost (default: build + print only).
        #[arg(long)]
        submit: bool,
    },
    /// Build (and with --submit, broadcast) the register_spo tx: bind this
    /// pool's cold-key identity to a Bifrost identity (secp256k1 key + URL),
    /// mint the membership token, insert the registration node into the
    /// on-chain linked list and advance the treasury bifrost_identity_root.
    /// Submission is gated on the R2 min-stake check
    /// (cardano.min_stake_lovelace vs the pool's epoch-snapshot active stake).
    RegisterSpo {
        #[arg(long)]
        config: Option<String>,
        /// Path to the bifrost Aiken blueprint (plutus.json).
        #[arg(long)]
        blueprint: String,
        /// The spos_registry one-shot bootstrap output ref (<tx_hash>:<index>)
        /// that parameterizes the registry policy (and through it treasury_info).
        #[arg(long)]
        registry_bootstrap: String,
        /// Treasury NFT asset name (hex), as printed by bootstrap-treasury-info.
        #[arg(long)]
        treasury_nft_name: String,
        /// Pool cold signing key: 32-byte hex, or a path to a file holding that
        /// hex or a cardano-cli TextEnvelope (cborHex "5820" || 32 bytes).
        /// Omit for the air-gapped flow (--cold-vkey + --cold-sig).
        #[arg(long)]
        cold_skey: Option<String>,
        /// Air-gapped: 32-byte cold verification key, hex.
        #[arg(long)]
        cold_vkey: Option<String>,
        /// Air-gapped: 64-byte Ed25519 signature (hex) over the registration
        /// message. Run without it first to print the exact message to sign.
        #[arg(long)]
        cold_sig: Option<String>,
        /// Bifrost identity secret key: 32-byte hex or a path to a file with
        /// it. Omit for the air-gapped flow (--bifrost-id-pk + --bifrost-sig).
        #[arg(long)]
        bifrost_skey: Option<String>,
        /// Air-gapped: 32-byte x-only bifrost public key, hex.
        #[arg(long)]
        bifrost_id_pk: Option<String>,
        /// Air-gapped: 64-byte BIP340 Schnorr signature (hex) over
        /// sha2_256(registration message).
        #[arg(long)]
        bifrost_sig: Option<String>,
        /// This SPO's Bifrost endpoint URL (where DKG data is published).
        #[arg(long)]
        bifrost_url: String,
        /// The registry reference-script UTxO (<tx_hash>:<index>), from
        /// deploy-registry-ref. Without it the ~12 KB registry script is
        /// embedded twice and the tx exceeds the 16 KB size limit.
        #[arg(long)]
        registry_ref: Option<String>,
        /// Actually submit via Blockfrost (requires passing the min-stake gate).
        #[arg(long)]
        submit: bool,
    },
    /// Build (and with --submit, broadcast) the spo_bans.ApplyBan tx: consume a
    /// published FaultProof and write the ban-list node (WI-018). The
    /// fault-policy set + ban-schedule params come from [cardano] config.
    ApplyBan {
        #[arg(long)]
        config: Option<String>,
        /// Path to the bifrost Aiken blueprint (plutus.json).
        #[arg(long)]
        blueprint: String,
        /// The spos_registry one-shot bootstrap output ref (<tx_hash>:<index>).
        #[arg(long)]
        registry_bootstrap: String,
        /// The accused pool id (28-byte hex).
        #[arg(long)]
        accused_pool_id: String,
        /// The fault evidence hash (32-byte hex) that binds the FaultProof token.
        #[arg(long)]
        evidence_hash: String,
        /// The spo_bans reference-script UTxO (<tx_hash>:<index>): the script is
        /// used three times in the tx and would not fit embedded.
        #[arg(long)]
        spo_bans_ref: String,
        /// Actually submit via Blockfrost.
        #[arg(long)]
        submit: bool,
    },
    /// Build (and with --submit, broadcast) the fault_verifier.PublishProof tx:
    /// mint the FaultProof token and park it at the wallet for a later
    /// apply-ban to consume (WI-018).
    FaultProofMint {
        #[arg(long)]
        config: Option<String>,
        /// Path to the bifrost Aiken blueprint (plutus.json).
        #[arg(long)]
        blueprint: String,
        /// Fault kind: `invalid-payload` or `equivocation`.
        #[arg(long)]
        kind: String,
        /// The accused pool id (28-byte hex).
        #[arg(long)]
        accused_pool_id: String,
        /// The protocol namespace hash (32-byte hex) — descriptive datum field.
        #[arg(long)]
        namespace_hash: String,
        /// The fault evidence hash (32-byte hex) — binds the FaultProof token.
        #[arg(long)]
        evidence_hash: String,
        /// Actually submit via Blockfrost.
        #[arg(long)]
        submit: bool,
    },
    /// Read + verify the on-chain SPO registry and print the DKG roster:
    /// reconstructs the spos_registry linked list, cross-checks the rebuilt
    /// identity-trie root against the treasury_info datum, and orders
    /// participants by bifrost_id_pk. Read-only.
    ShowRoster {
        #[arg(long)]
        config: Option<String>,
        /// Path to the bifrost Aiken blueprint (plutus.json). Falls back to
        /// cardano.registry_blueprint.
        #[arg(long)]
        blueprint: Option<String>,
        /// The spos_registry one-shot bootstrap outref (<tx_hash>:<index>).
        /// Falls back to cardano.registry_bootstrap.
        #[arg(long)]
        registry_bootstrap: Option<String>,
        /// Treasury NFT asset name (hex), as printed by bootstrap-treasury-info.
        /// Falls back to cardano.treasury_info_asset_name.
        #[arg(long)]
        treasury_nft_name: Option<String>,
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
            if let Some(v) = min_signers {
                cfg.demo.min_signers = v;
            }
            if let Some(v) = max_signers {
                cfg.demo.max_signers = v;
            }
            if let Some(v) = base_port {
                cfg.http.base_port = v;
            }
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
        Commands::BootstrapRegistry {
            config,
            blueprint,
            registry_bootstrap,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_bootstrap_registry(&cfg, &blueprint, &registry_bootstrap, submit) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::DeployRegistryRef {
            config,
            blueprint,
            registry_bootstrap,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_deploy_registry_ref(&cfg, &blueprint, &registry_bootstrap, submit) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::RegisterSpo {
            config,
            blueprint,
            registry_bootstrap,
            treasury_nft_name,
            cold_skey,
            cold_vkey,
            cold_sig,
            bifrost_skey,
            bifrost_id_pk,
            bifrost_sig,
            bifrost_url,
            registry_ref,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            let args = RegisterSpoArgs {
                blueprint,
                registry_bootstrap,
                treasury_nft_name,
                cold_skey,
                cold_vkey,
                cold_sig,
                bifrost_skey,
                bifrost_id_pk,
                bifrost_sig,
                bifrost_url,
                registry_ref,
                submit,
            };
            if let Err(e) = run_register_spo(&cfg, &args) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ApplyBan {
            config,
            blueprint,
            registry_bootstrap,
            accused_pool_id,
            evidence_hash,
            spo_bans_ref,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            let args = ApplyBanArgs {
                blueprint,
                registry_bootstrap,
                accused_pool_id,
                evidence_hash,
                spo_bans_ref,
                submit,
            };
            if let Err(e) = run_apply_ban(&cfg, &args) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::FaultProofMint {
            config,
            blueprint,
            kind,
            accused_pool_id,
            namespace_hash,
            evidence_hash,
            submit,
        } => {
            let cfg = load_config(config.as_deref());
            let args = FaultProofMintArgs {
                blueprint,
                kind,
                accused_pool_id,
                namespace_hash,
                evidence_hash,
                submit,
            };
            if let Err(e) = run_fault_proof_mint(&cfg, &args) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::ShowRoster {
            config,
            blueprint,
            registry_bootstrap,
            treasury_nft_name,
        } => {
            let cfg = load_config(config.as_deref());
            if let Err(e) = run_show_roster(&cfg, blueprint, registry_bootstrap, treasury_nft_name)
            {
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

async fn run_demo(cfg: HeimdallConfig, index: Option<u16>, deterministic: bool) {
    // The fixture provides a fallback roster (SPO identities + ports)
    // until the on-chain SPO registry is wired.
    let fixture = heimdall::epoch::fixture::demo_static_fixture_from_config(&cfg);

    let script_address: String = cfg.cardano.pegin_script_address.clone().unwrap_or_default();
    let treasury_address: String = cfg.cardano.treasury_address.clone().unwrap_or_default();
    let treasury_policy_id: String = cfg.cardano.treasury_policy_id.clone().unwrap_or_default();
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

        // On-chain SPO registry roster (WI-010): configured via
        // cardano.{registry_blueprint, registry_bootstrap, treasury_info_asset_name}.
        // Without it query_roster serves the fixture roster.
        match heimdall::cardano::roster::RegistryRosterSource::from_config(&cfg.cardano) {
            Ok(Some(source)) => {
                println!("on-chain SPO registry: {}", source.registry_address);
                println!(
                    "note: eligible roster = registry − active bans; FROST threshold is \
                     stake-weighted (WI-012) — demo.min_signers is ignored on this path"
                );
                bf_chain = bf_chain.with_registry_roster(source);
                // Ban filtering (WI-011/012): only if cardano.ban_bootstrap is set.
                match heimdall::cardano::ban_list::BanListSource::from_config(&cfg.cardano) {
                    Ok(Some(bans)) => {
                        println!("on-chain ban list:     {}", bans.ban_address);
                        bf_chain = bf_chain.with_ban_source(bans);
                    }
                    Ok(None) => println!(
                        "note: no ban list configured (cardano.ban_bootstrap) — roster not \
                         ban-filtered"
                    ),
                    // Fail fast with a clear message — NOT a degrade-to-unfiltered:
                    // an unread ban list would admit banned SPOs to the roster. A
                    // misconfig (e.g. ban_bootstrap set but the fault-policy set /
                    // ban-schedule params missing) must stop startup, not silently
                    // disable ban filtering.
                    Err(e) => {
                        eprintln!("fatal: ban list config: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("fatal: registry roster config: {e}");
                std::process::exit(1);
            }
        }

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

    // Identity (WI-014): this node's bifrost key locates its own roster entry
    // (own_participant). The positional --index is a legacy fallback only for
    // the config/mock fixture, whose SpoInfos carry no bifrost_id_pk.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let keypair = cfg
        .load_bifrost_keypair(&secp)
        .unwrap_or_else(|e| panic!("bifrost identity key required for the HTTP transport: {e}"));
    let bifrost_id_pk = keypair.x_only_public_key().0.serialize();

    // WI-014: query the roster at the REAL current epoch (was hardcoded 0).
    let epoch = chain
        .current_epoch()
        .await
        .expect("query current chain epoch");
    let roster = chain
        .query_roster(epoch)
        .await
        .expect("query initial roster");

    let (id, me) = match roster.own_participant(&bifrost_id_pk) {
        Some((id, info)) => (id, info),
        None => {
            // Not in the roster by bifrost key. Against a real registry roster
            // this is fatal (not registered / banned / bifrost_url excluded). Fall
            // back to --index ONLY for the fixture demo (empty bifrost_id_pks).
            let ix = index.unwrap_or_else(|| {
                panic!(
                    "this node's bifrost_id_pk ({}) is not in the eligible roster for epoch \
                     {epoch} (not registered / banned / URL-excluded) and no --index fallback \
                     was given — refusing to run DKG under an unknown identity",
                    hex::encode(bifrost_id_pk)
                )
            });
            let id = Identifier::try_from(ix).unwrap();
            let info = roster
                .participants
                .get(&id)
                .unwrap_or_else(|| panic!("--index {ix} is not in the roster"));
            eprintln!(
                "[demo] WARNING: bifrost_id_pk not found in roster; falling back to --index {ix} \
                 (fixture/legacy demo only)"
            );
            (id, info)
        }
    };
    let port = port_from_url(&me.bifrost_url).unwrap_or_else(|e| panic!("{e}"));
    let my_pool_id: [u8; 28] = me.pool_id.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "this node's roster entry has no 28-byte pool_id (got {} bytes) — the \
             authenticated DKG transport needs a registered on-chain roster",
            me.pool_id.len()
        )
    });
    let spo_label = hex::encode(&my_pool_id[..4]);
    let net = Arc::new(HttpPeerNetwork::new(secp, keypair, my_pool_id));
    let app = router(net.shared_state());
    let bind_addr = &cfg.http.bind_address;
    let listener = tokio::net::TcpListener::bind(format!("{bind_addr}:{port}"))
        .await
        .expect("bind");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    println!(
        "=== Heimdall SPO {spo_label} ({}-of-{}) ===",
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
    for (i, (inp, prevout)) in tm
        .unsigned_tx
        .input
        .iter()
        .zip(tm.prevouts.iter())
        .enumerate()
    {
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

    println!("\n=== SPO {spo_label} cycle complete ===");

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

/// The local HTTP bind port, from this node's OWN registered bifrost_url.
/// Parses the URL properly (a naive `rsplit(':')` mishandles paths, IPv6
/// hosts, and userinfo that the roster's URL validation accepts) and
/// requires an explicit `:<port>` — peers fetching FROM a URL can rely on
/// scheme defaults, but the node cannot guess which local port to serve on.
fn port_from_url(url: &str) -> Result<u16, String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.port())
        .ok_or_else(|| {
            format!(
                "this node's bifrost_url {url:?} has no explicit ':<port>' — the demo binds its \
                 local HTTP server to that port, so register a URL ending in ':<port>'"
            )
        })
}

/// Derive the bootstrap federation keypair from `bitcoin.y_fed_seed_hex`.
/// At bootstrap Y_51 = Y_fed, so the seed's secret key signs every TM input
/// and its x-only pubkey is both the treasury and peg-in internal key.
fn y_fed_keypair(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    cfg: &HeimdallConfig,
) -> Result<
    (
        bitcoin::secp256k1::SecretKey,
        bitcoin::key::UntweakedPublicKey,
    ),
    String,
> {
    let seed: [u8; 32] = hex::decode(&cfg.bitcoin.y_fed_seed_hex)
        .map_err(|e| format!("y_fed_seed_hex: {e}"))?
        .try_into()
        .map_err(|_| "y_fed_seed_hex must be 32 bytes".to_string())?;
    let sk =
        bitcoin::secp256k1::SecretKey::from_slice(&seed).map_err(|e| format!("seed -> sk: {e}"))?;
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
fn btc_rpc_config(
    cfg: &HeimdallConfig,
) -> Result<heimdall::cardano::btc_rpc::BtcRpcConfig, String> {
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
    use heimdall::bitcoin::tm_builder::{TreasuryInput, build_tm, sign_tm_single_key};
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

    let signed =
        sign_tm_single_key(&secp, &unsigned, &sk).map_err(|e| format!("sign self-send: {e}"))?;
    let raw = bitcoin::consensus::encode::serialize(&signed);

    println!("self-send txid : {}", signed.compute_txid());
    println!(
        "output[0]      : {} sat (treasury)",
        signed.output[0].value.to_sat()
    );
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

/// Submit a signed tx (hex) via Blockfrost; returns the tx hash.
fn submit_tx_blockfrost(
    cfg: &HeimdallConfig,
    project_id: &str,
    signed_tx_hex: &str,
    rt: &tokio::runtime::Runtime,
) -> Result<String, String> {
    let cbor = hex::decode(signed_tx_hex).map_err(|e| e.to_string())?;
    let mut settings = blockfrost::BlockFrostSettings::new();
    if let Some(url) = cfg.cardano.blockfrost_url.as_deref() {
        settings.base_url = Some(url.to_string());
    }
    let api = blockfrost::BlockfrostAPI::new(project_id, settings);
    rt.block_on(api.transactions_submit(cbor))
        .map_err(|e| format!("blockfrost submit: {e}"))
}

/// The Cardano network of a bech32 address — testnet iff the `addr_test` HRP.
/// Single source of truth for the on-chain command handlers (they previously
/// open-coded this with inverted branch order, an easy place to drift).
fn network_of(addr: &str) -> pallas_addresses::Network {
    if addr.starts_with("addr_test") {
        pallas_addresses::Network::Testnet
    } else {
        pallas_addresses::Network::Mainnet
    }
}

/// The shared dry-run / `--submit` tail of the on-chain tx commands: on a dry
/// run print the notice and stop; otherwise broadcast via Blockfrost and print
/// the tx hash. Centralizes the user-facing wording so the copies can't drift.
fn finish_tx(
    cfg: &HeimdallConfig,
    project_id: &str,
    rt: &tokio::runtime::Runtime,
    submit: bool,
    signed_tx_hex: &str,
) -> Result<(), String> {
    if !submit {
        println!("(dry run — pass --submit to broadcast via Blockfrost)");
        return Ok(());
    }
    let tx_hash = submit_tx_blockfrost(cfg, project_id, signed_tx_hex, rt)?;
    println!("submitted: tx_hash={tx_hash}");
    Ok(())
}

/// Build (and with `submit`, broadcast) the registry-list bootstrap: the
/// one-shot `Bootstrap` mint creating the `"reg-root"` anchor element.
/// See `heimdall::cardano::register_spo`.
fn run_bootstrap_registry(
    cfg: &HeimdallConfig,
    blueprint_path: &str,
    registry_bootstrap: &str,
    submit: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::spos_registry_script;
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::register_spo::build_registry_bootstrap_tx;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = std::fs::read_to_string(blueprint_path)
        .map_err(|e| format!("read blueprint {blueprint_path}: {e}"))?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let registry = spos_registry_script(&blueprint_json, &reg_tx_id, u64::from(reg_index))
        .map_err(|e| format!("parameterize spos_registry: {e}"))?;

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
    let wallet_utxos: Vec<WalletUtxo> = raw.iter().map(WalletUtxo::from_bf).collect();
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    // The one-shot outref cannot be swapped (it parameterizes the policy). If
    // it carries a reference script, the ledger charges the per-byte
    // ref-script fee on spending it — fetch the size so the builder prices it
    // in explicitly (whisky's estimate cannot see it).
    let reg_tx_hash_hex = hex::encode(reg_tx_id);
    let one_shot_ref_script_size = match raw
        .iter()
        .find(|u| u.tx_hash == reg_tx_hash_hex && u.output_index == reg_index)
        .and_then(|u| u.reference_script_hash.as_deref())
    {
        Some(h) => {
            let size = rt
                .block_on(bf_http::fetch_script_size(&base_url, pid, h))
                .map_err(|e| format!("one-shot ref script size: {e}"))?;
            eprintln!(
                "[bootstrap-registry] note: the one-shot outref carries reference script \
                 {h} ({size} bytes) — adding the Conway ref-script fee"
            );
            Some(size)
        }
        None => None,
    };

    let built = build_registry_bootstrap_tx(
        &registry,
        &reg_tx_hash_hex,
        reg_index,
        &wallet_addr,
        &wallet_utxos,
        &key,
        one_shot_ref_script_size,
        Some(cost_models),
    )
    .map_err(|e| format!("build registry bootstrap tx: {e}"))?;

    println!("registry policy id:   {}", built.policy_id_hex);
    println!("registry address:     {}", built.script_address);
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, submit, &built.signed_tx_hex)
}

/// Build (and with `submit`, broadcast) the registry reference-script deploy.
fn run_deploy_registry_ref(
    cfg: &HeimdallConfig,
    blueprint_path: &str,
    registry_bootstrap: &str,
    submit: bool,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::spos_registry_script;
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::register_spo::build_ref_script_deploy_tx;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = std::fs::read_to_string(blueprint_path)
        .map_err(|e| format!("read blueprint {blueprint_path}: {e}"))?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(registry_bootstrap)?;
    let registry = spos_registry_script(&blueprint_json, &reg_tx_id, u64::from(reg_index))
        .map_err(|e| format!("parameterize spos_registry: {e}"))?;

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
    let wallet_utxos: Vec<WalletUtxo> = raw.iter().map(WalletUtxo::from_bf).collect();
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let built = build_ref_script_deploy_tx(
        &registry,
        &wallet_addr,
        &wallet_utxos,
        &key,
        Some(cost_models),
    )
    .map_err(|e| format!("build ref-script deploy tx: {e}"))?;

    println!("registry script hash: {}", built.script_hash_hex);
    println!(
        "locked with the ref:  {} lovelace (reclaimable: key-locked at the wallet)",
        built.lovelace
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    if !submit {
        println!("(dry run — pass --submit to broadcast via Blockfrost)");
        return Ok(());
    }
    let tx_hash = submit_tx_blockfrost(cfg, pid, &built.signed_tx_hex, &rt)?;
    println!("submitted: tx_hash={tx_hash}");
    println!("registry ref UTxO:    {tx_hash}:0  (pass as --registry-ref to register-spo)");
    Ok(())
}

/// register-spo CLI inputs, bundled (clap hands us a dozen options).
struct RegisterSpoArgs {
    blueprint: String,
    registry_bootstrap: String,
    treasury_nft_name: String,
    cold_skey: Option<String>,
    cold_vkey: Option<String>,
    cold_sig: Option<String>,
    bifrost_skey: Option<String>,
    bifrost_id_pk: Option<String>,
    bifrost_sig: Option<String>,
    bifrost_url: String,
    registry_ref: Option<String>,
    submit: bool,
}

/// apply-ban CLI inputs.
struct ApplyBanArgs {
    blueprint: String,
    registry_bootstrap: String,
    accused_pool_id: String,
    evidence_hash: String,
    spo_bans_ref: String,
    submit: bool,
}

/// fault-proof-mint CLI inputs.
struct FaultProofMintArgs {
    blueprint: String,
    kind: String,
    accused_pool_id: String,
    namespace_hash: String,
    evidence_hash: String,
    submit: bool,
}

/// Parse a 32-byte secret-key argument: inline hex, a file containing hex, or
/// a cardano-cli TextEnvelope file (`cborHex` = `"5820" || 32 bytes`).
fn parse_key32(arg: &str, what: &str) -> Result<[u8; 32], String> {
    let content = if std::path::Path::new(arg).is_file() {
        std::fs::read_to_string(arg).map_err(|e| format!("{what}: read {arg}: {e}"))?
    } else {
        arg.to_string()
    };
    let trimmed = content.trim();
    let hex_str = if trimmed.starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| format!("{what}: TextEnvelope JSON: {e}"))?;
        v.get("cborHex")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("{what}: TextEnvelope has no cborHex"))?
            .strip_prefix("5820")
            .ok_or_else(|| format!("{what}: cborHex is not a 32-byte key (5820…)"))?
            .to_string()
    } else {
        trimmed.to_string()
    };
    parse_hex_n(&hex_str, what)
}

/// Parse an inline hex argument of exactly `N` bytes.
fn parse_hex_n<const N: usize>(arg: &str, what: &str) -> Result<[u8; N], String> {
    hex::decode(arg.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("{what}: expected {N} bytes of hex"))
}

/// Bech32 (`pool1…`) form of the 28-byte pool key hash, as Blockfrost expects.
use heimdall::cardano::hash::pool_id_bech32;

/// Build (and with `--submit`, broadcast) the register_spo tx. Identities come
/// from local secret keys or from the air-gapped (vkey + signature) flow; the
/// R2 min-stake gate must pass before anything is submitted.
fn run_register_spo(cfg: &HeimdallConfig, args: &RegisterSpoArgs) -> Result<(), String> {
    use bitcoin::hashes::{Hash as _, sha256};
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::{Keypair, Message};
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{spos_registry_script, treasury_info_script};
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::register_spo::{
        RegisterSpoRequest, RegistrationSignatures, build_register_spo_tx, pool_id_from_cold_vkey,
        registration_message, verify_registration,
    };
    use heimdall::cardano::registry::REGISTRATION_ROOT_KEY;
    use heimdall::cardano::stake::{check_min_stake, fetch_pool_stake};
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
    use pallas_crypto::key::ed25519;

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = std::fs::read_to_string(&args.blueprint)
        .map_err(|e| format!("read blueprint {}: {e}", args.blueprint))?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(&args.registry_bootstrap)?;
    let registry = spos_registry_script(&blueprint_json, &reg_tx_id, u64::from(reg_index))
        .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let treasury = treasury_info_script(&blueprint_json, &registry.hash)
        .map_err(|e| format!("parameterize treasury_info: {e}"))?;

    // ── identities: local secret keys, or the air-gapped halves ──
    let cold_skey: Option<ed25519::SecretKey> = args
        .cold_skey
        .as_deref()
        .map(|arg| parse_key32(arg, "--cold-skey").map(ed25519::SecretKey::from))
        .transpose()?;
    let cold_vkey: [u8; 32] = match (&cold_skey, args.cold_vkey.as_deref()) {
        (Some(sk), None) => sk.public_key().into(),
        (None, Some(vk)) => parse_hex_n(vk, "--cold-vkey")?,
        (Some(sk), Some(vk)) => {
            let derived: [u8; 32] = sk.public_key().into();
            if parse_hex_n::<32>(vk, "--cold-vkey")? != derived {
                return Err("--cold-vkey does not match --cold-skey".into());
            }
            derived
        }
        (None, None) => {
            return Err(
                "provide --cold-skey, or --cold-vkey (+ --cold-sig) for the air-gapped flow".into(),
            );
        }
    };

    let secp = Secp256k1::new();
    let bifrost_keypair: Option<Keypair> = match args.bifrost_skey.as_deref() {
        Some(arg) => Some(
            Keypair::from_seckey_slice(&secp, &parse_key32(arg, "--bifrost-skey")?)
                .map_err(|e| format!("--bifrost-skey: {e}"))?,
        ),
        None => None,
    };
    let bifrost_id_pk: [u8; 32] = match (&bifrost_keypair, args.bifrost_id_pk.as_deref()) {
        (Some(kp), None) => kp.x_only_public_key().0.serialize(),
        (None, Some(pk)) => parse_hex_n(pk, "--bifrost-id-pk")?,
        (Some(kp), Some(pk)) => {
            let derived = kp.x_only_public_key().0.serialize();
            if parse_hex_n::<32>(pk, "--bifrost-id-pk")? != derived {
                return Err("--bifrost-id-pk does not match --bifrost-skey".into());
            }
            derived
        }
        (None, None) => {
            return Err(
                "provide --bifrost-skey, or --bifrost-id-pk (+ --bifrost-sig) for the \
                 air-gapped flow"
                    .into(),
            );
        }
    };

    let pool_id = pool_id_from_cold_vkey(&cold_vkey);
    let message = registration_message(&pool_id, &bifrost_id_pk, args.bifrost_url.as_bytes());
    let digest = sha256::Hash::hash(&message).to_byte_array();

    let cold_sig: [u8; 64] = match (&cold_skey, args.cold_sig.as_deref()) {
        (Some(sk), _) => sk
            .sign(&message)
            .as_ref()
            .try_into()
            .expect("ed25519 signature is 64 bytes"),
        (None, Some(sig)) => parse_hex_n(sig, "--cold-sig")?,
        (None, None) => {
            return Err(format!(
                "no --cold-skey/--cold-sig. Air-gapped: Ed25519-sign this message with the \
                 pool cold key and re-run with --cold-sig:\n  message (hex): {}",
                hex::encode(&message)
            ));
        }
    };
    let bifrost_sig: [u8; 64] = match (&bifrost_keypair, args.bifrost_sig.as_deref()) {
        (Some(kp), _) => secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), kp)
            .serialize(),
        (None, Some(sig)) => parse_hex_n(sig, "--bifrost-sig")?,
        (None, None) => {
            return Err(format!(
                "no --bifrost-skey/--bifrost-sig. Air-gapped: BIP340-sign this 32-byte digest \
                 with the bifrost identity key and re-run with --bifrost-sig:\n  \
                 sha2_256(message): {}",
                hex::encode(digest)
            ));
        }
    };
    let sigs = RegistrationSignatures {
        cold_vkey,
        cold_sig,
        bifrost_sig,
    };
    verify_registration(&sigs, &bifrost_id_pk, args.bifrost_url.as_bytes())
        .map_err(|e| format!("registration signatures: {e}"))?;

    println!(
        "pool id:           {} ({})",
        hex::encode(pool_id),
        pool_id_bech32(&pool_id)
    );
    println!("bifrost_id_pk:     {}", hex::encode(bifrost_id_pk));
    println!("bifrost_url:       {}", args.bifrost_url);
    println!("registry policy:   {}", registry.hash_hex());
    println!("treasury policy:   {}", treasury.hash_hex());

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    // ── R2 min-stake gate: gates submission; a dry run only warns ──
    match cfg.cardano.min_stake_lovelace {
        Some(threshold) => {
            let stake = rt
                .block_on(fetch_pool_stake(&base_url, pid, &pool_id_bech32(&pool_id)))
                .map_err(|e| format!("min-stake gate: {e}"))?;
            let chk = check_min_stake(&stake, threshold);
            println!(
                "min-stake gate:    active_stake={} threshold={} → {}",
                chk.active_stake,
                chk.threshold,
                if chk.meets { "PASS" } else { "FAIL" }
            );
            if !chk.meets {
                if args.submit {
                    return Err(
                        "min-stake gate failed (R2) — refusing to submit register_spo".into(),
                    );
                }
                eprintln!(
                    "[register-spo] WARNING: min-stake gate failed; printing the dry-run tx, \
                     but submission would be refused"
                );
            }
        }
        None => {
            if args.submit {
                return Err(
                    "cardano.min_stake_lovelace is not configured — the R2 gate cannot run; \
                     set it (the protocol min_stake) before submitting"
                        .into(),
                );
            }
            eprintln!(
                "[register-spo] WARNING: cardano.min_stake_lovelace not configured; \
                 dry run only — submission would be refused"
            );
        }
    }

    // ── chain state ──
    let network = network_of(&wallet_addr);
    let registry_addr = registry.enterprise_address(network);
    let treasury_addr = treasury.enterprise_address(network);
    let wallet_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
    let registry_utxos = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &registry_addr))
        .map_err(|e| format!("registry UTxO query: {e}"))?;
    let treasury_utxos = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &treasury_addr))
        .map_err(|e| format!("treasury UTxO query: {e}"))?;
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;
    // Epoch-boundary validity window: the tx may not land in a later epoch
    // than the one it was built (and its candidate snapshot computed) in.
    let window = rt
        .block_on(bf_http::fetch_epoch_window(&base_url, pid))
        .map_err(|e| format!("epoch window: {e}"))?;
    println!(
        "validity window:   [{}, {}) — current epoch only",
        window.current_slot, window.epoch_end_slot
    );

    let registry_ref = args
        .registry_ref
        .as_deref()
        .map(|s| {
            let (tx_id, index) = parse_cardano_outref(s)?;
            Ok::<_, String>((hex::encode(tx_id), index))
        })
        .transpose()
        .map_err(|e| format!("--registry-ref: {e}"))?;

    let req = RegisterSpoRequest {
        registry_script: &registry,
        treasury_script: &treasury,
        treasury_asset_name_hex: &args.treasury_nft_name,
        registry_utxos: &registry_utxos,
        treasury_utxos: &treasury_utxos,
        wallet_address: &wallet_addr,
        wallet_utxos: &wallet_utxos,
        key: &key,
        sigs: &sigs,
        bifrost_id_pk,
        bifrost_url: args.bifrost_url.as_bytes().to_vec(),
        invalid_before: Some(window.current_slot),
        invalid_hereafter: Some(window.epoch_end_slot),
        registry_ref,
        cost_models: Some(cost_models),
    };
    let built = build_register_spo_tx(&req).map_err(|e| format!("build register_spo tx: {e}"))?;

    let anchor = if built.anchor_asset_name == REGISTRATION_ROOT_KEY {
        "reg-root (registry root)".to_string()
    } else {
        hex::encode(&built.anchor_asset_name)
    };
    println!("anchor element:    {anchor}");
    println!(
        "new identity root: {}",
        hex::encode(built.new_bifrost_identity_root)
    );
    println!(
        "membership token:  {}.{}",
        registry.hash_hex(),
        hex::encode(built.pool_id)
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, args.submit, &built.signed_tx_hex)
}

/// Build (and with `--submit`, broadcast) the `spo_bans.ApplyBan` tx: consume a
/// published FaultProof and write the ban-list node (WI-018 pt4b). The
/// fault-policy set + ban-schedule params come from `[cardano]` config (they
/// are baked into the ban policy id).
fn run_apply_ban(cfg: &HeimdallConfig, args: &ApplyBanArgs) -> Result<(), String> {
    use heimdall::cardano::apply_ban::{ApplyBanRequest, FaultProofUtxo, build_apply_ban_tx};
    use heimdall::cardano::ban_list::{BanPolicyParams, fault_token_name};
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::{
        fault_verifier_script, spo_bans_script, spos_registry_script,
    };
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = std::fs::read_to_string(&args.blueprint)
        .map_err(|e| format!("read blueprint {}: {e}", args.blueprint))?;
    let (reg_tx_id, reg_index) = parse_cardano_outref(&args.registry_bootstrap)?;
    let registry = spos_registry_script(&blueprint_json, &reg_tx_id, u64::from(reg_index))
        .map_err(|e| format!("parameterize spos_registry: {e}"))?;
    let fault = fault_verifier_script(&blueprint_json)
        .map_err(|e| format!("parameterize fault_verifier: {e}"))?;

    // The ban policy is config-pinned (ban bootstrap + fault-policy set + schedule).
    let ban_bootstrap = cfg
        .cardano
        .ban_bootstrap
        .as_deref()
        .ok_or("cardano.ban_bootstrap required")?;
    let (ban_tx_id, ban_index) = parse_cardano_outref(ban_bootstrap)?;
    let params = BanPolicyParams::from_config(&cfg.cardano).map_err(|e| e.to_string())?;
    let spo_bans = spo_bans_script(
        &blueprint_json,
        &registry.hash,
        &params.fault_proof_policies,
        params.base_ban_duration_ms,
        params.max_faults_before_permanent,
        params.max_validity_window_ms,
        &ban_tx_id,
        u64::from(ban_index),
    )
    .map_err(|e| format!("parameterize spo_bans: {e}"))?;

    let accused_pool_id: [u8; 28] = parse_hex_n(&args.accused_pool_id, "--accused-pool-id")?;
    let evidence_hash: [u8; 32] = parse_hex_n(&args.evidence_hash, "--evidence-hash")?;
    let (sb_tx, sb_ix) = parse_cardano_outref(&args.spo_bans_ref)?;

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    let network = network_of(&wallet_addr);
    let mainnet = matches!(network, pallas_addresses::Network::Mainnet);
    let ban_addr = spo_bans.enterprise_address(network);
    let registry_addr = registry.enterprise_address(network);

    println!("ban policy:        {}", spo_bans.hash_hex());
    println!("ban address:       {ban_addr}");
    println!(
        "accused pool:      {} ({})",
        hex::encode(accused_pool_id),
        pool_id_bech32(&accused_pool_id)
    );

    let wallet_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let registry_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &registry_addr))
        .map_err(|e| format!("registry UTxO query: {e}"))?;
    let ban_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &ban_addr))
        .map_err(|e| format!("ban UTxO query: {e}"))?;
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;
    let window = rt
        .block_on(bf_http::fetch_epoch_window(&base_url, pid))
        .map_err(|e| format!("epoch window: {e}"))?;

    // Locate the parked FaultProof UTxO at the wallet (Part 3b output).
    let token_name = fault_token_name(&accused_pool_id, &evidence_hash);
    let fault_unit = format!("{}{}", fault.hash_hex(), hex::encode(token_name));
    let lovelace_of = |u: &bf_http::BfUtxo| -> u64 {
        u.amount
            .iter()
            .find(|a| a.unit == "lovelace")
            .and_then(|a| a.quantity.parse().ok())
            .unwrap_or(0)
    };
    let fault_bf = wallet_raw
        .iter()
        .find(|u| u.amount.iter().any(|a| a.unit == fault_unit))
        .ok_or_else(|| {
            format!(
                "no FaultProof UTxO for this (pool, evidence) at the wallet — publish it first \
                 (token {})",
                hex::encode(token_name)
            )
        })?;
    let fault_utxo = FaultProofUtxo {
        tx_hash: fault_bf.tx_hash.clone(),
        output_index: fault_bf.output_index,
        lovelace: lovelace_of(fault_bf),
    };

    // Locate the accused pool's registry node — the read-only reference input.
    let reg_unit = format!("{}{}", registry.hash_hex(), hex::encode(accused_pool_id));
    let reg_node = registry_raw
        .iter()
        .find(|u| u.amount.iter().any(|a| a.unit == reg_unit))
        .ok_or_else(|| {
            format!(
                "accused pool {} is not in the on-chain registry — cannot reference it",
                hex::encode(accused_pool_id)
            )
        })?;

    // Validity interval: [current_slot, current_slot + W), W*1s within both the
    // ban validator's max_validity_window_ms and the epoch horizon. start_time
    // is the POSIX-ms upper bound the validator resolves (drives BanNodeData).
    // NOTE: the exact inclusivity of the resolved upper bound is ledger-defined;
    // verify start_time against a real node on a devnet before relying on it.
    let max_window_slots = (params.max_validity_window_ms / 1000).max(1) as u64;
    let avail = window.epoch_end_slot.saturating_sub(window.current_slot);
    let w = max_window_slots.min(avail);
    let invalid_before = window.current_slot;
    let invalid_hereafter = window.current_slot + w;
    let start_time_ms = window.block_time_ms + (w as i64) * 1000;

    let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
    let req = ApplyBanRequest {
        spo_bans_script: &spo_bans,
        fault_verifier_script: &fault,
        ban_params: &params,
        accused_pool_id,
        evidence_hash,
        ban_utxos: &ban_raw,
        fault_utxo: &fault_utxo,
        registration_ref: (reg_node.tx_hash.clone(), reg_node.output_index),
        spo_bans_ref: (hex::encode(sb_tx), sb_ix),
        mainnet,
        start_time_ms,
        invalid_before,
        invalid_hereafter,
        wallet_address: &wallet_addr,
        wallet_utxos: &wallet_utxos,
        key: &key,
        cost_models: Some(cost_models),
    };
    let built = build_apply_ban_tx(&req).map_err(|e| format!("build apply_ban tx: {e}"))?;

    println!(
        "action:            {}",
        if built.first_ban {
            "first ban (mint + insert)"
        } else {
            "reban (in-place update)"
        }
    );
    println!(
        "ban node:          {}.{} (counter {}, until {})",
        spo_bans.hash_hex(),
        hex::encode(&built.ban_node_asset_name),
        built.ban_node.ban_counter,
        built.ban_node.ban_until_time
    );
    println!(
        "burned FaultProof: {}.{}",
        fault.hash_hex(),
        hex::encode(built.burned_fault_token)
    );
    println!(
        "validity:          slots [{invalid_before}, {invalid_hereafter}), start_time_ms {start_time_ms}"
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, args.submit, &built.signed_tx_hex)
}

/// Build (and with `--submit`, broadcast) the `fault_verifier.PublishProof` tx:
/// mint the FaultProof token `blake2b_256(accused_pool_id || evidence_hash)` and
/// park it at the wallet with the inline FaultProofDatum (WI-018 pt3b). A later
/// `apply-ban` consumes + burns it.
fn run_fault_proof_mint(cfg: &HeimdallConfig, args: &FaultProofMintArgs) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blueprint::fault_verifier_script;
    use heimdall::cardano::fault_proof::{
        FaultKind, FaultProofDatum, FaultProofMintRequest, build_fault_proof_mint_tx,
    };
    use heimdall::cardano::publish::WalletUtxo;
    use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};

    let mnemonic = resolve_mnemonic(cfg)?;
    let key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;

    let blueprint_json = std::fs::read_to_string(&args.blueprint)
        .map_err(|e| format!("read blueprint {}: {e}", args.blueprint))?;
    let fault_vscript = fault_verifier_script(&blueprint_json)
        .map_err(|e| format!("parameterize fault_verifier: {e}"))?;

    let kind = match args.kind.as_str() {
        "invalid-payload" => FaultKind::InvalidPayload,
        "equivocation" => FaultKind::Equivocation,
        other => {
            return Err(format!(
                "--kind must be `invalid-payload` or `equivocation`, got `{other}`"
            ));
        }
    };
    let accused_pool_id: [u8; 28] = parse_hex_n(&args.accused_pool_id, "--accused-pool-id")?;
    let namespace_hash: [u8; 32] = parse_hex_n(&args.namespace_hash, "--namespace-hash")?;
    let evidence_hash: [u8; 32] = parse_hex_n(&args.evidence_hash, "--evidence-hash")?;
    let fault = FaultProofDatum {
        kind,
        accused_pool_id: accused_pool_id.to_vec(),
        namespace_hash: namespace_hash.to_vec(),
        evidence_hash: evidence_hash.to_vec(),
    };

    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    let wallet_raw = rt
        .block_on(bf_http::fetch_address_utxos(&base_url, pid, &wallet_addr))
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, pid))
        .map_err(|e| format!("fetch cost models: {e}"))?;

    let req = FaultProofMintRequest {
        fault_verifier_script: &fault_vscript,
        fault: &fault,
        wallet_address: &wallet_addr,
        wallet_utxos: &wallet_utxos,
        key: &key,
        cost_models: Some(cost_models),
    };
    let built =
        build_fault_proof_mint_tx(&req).map_err(|e| format!("build fault-proof mint tx: {e}"))?;

    println!("fault policy:      {}", built.policy_id_hex);
    println!(
        "FaultProof token:  {}.{}",
        built.policy_id_hex,
        hex::encode(built.token_name)
    );
    println!(
        "parked at:         {} ({} lovelace) — spend with `apply-ban`",
        built.proof_address, built.lovelace
    );
    println!(
        "nonce input_ref:   {}:{}",
        built.input_ref.0, built.input_ref.1
    );
    println!("signed tx hex:\n{}", built.signed_tx_hex);

    finish_tx(cfg, pid, &rt, args.submit, &built.signed_tx_hex)
}

/// Read + verify the on-chain SPO registry and print the DKG roster (WI-010).
fn run_show_roster(
    cfg: &HeimdallConfig,
    blueprint: Option<String>,
    registry_bootstrap: Option<String>,
    treasury_nft_name: Option<String>,
) -> Result<(), String> {
    use heimdall::cardano::bf_http;
    use heimdall::cardano::roster::RegistryRosterSource;

    let blueprint = blueprint
        .or_else(|| cfg.cardano.registry_blueprint.clone())
        .ok_or("--blueprint (or cardano.registry_blueprint) required")?;
    let bootstrap = registry_bootstrap
        .or_else(|| cfg.cardano.registry_bootstrap.clone())
        .ok_or("--registry-bootstrap (or cardano.registry_bootstrap) required")?;
    let nft_name = treasury_nft_name
        .or_else(|| cfg.cardano.treasury_info_asset_name.clone())
        .ok_or("--treasury-nft-name (or cardano.treasury_info_asset_name) required")?;
    let pid = cfg
        .cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or("cardano.blockfrost_project_id required")?;

    let source = RegistryRosterSource::from_blueprint(
        &blueprint,
        &bootstrap,
        &nft_name,
        pid.starts_with("mainnet"),
    )
    .map_err(|e| e.to_string())?;
    println!("registry policy:   {}", source.registry_policy_hex);
    println!("registry address:  {}", source.registry_address);
    println!("treasury_info:     {}", source.treasury_info_address);

    let base_url = bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let epoch = rt.block_on(bf_http::fetch_current_epoch(&base_url, pid))?;
    let snapshot = rt
        .block_on(source.fetch_snapshot(&base_url, pid))
        .map_err(|e| e.to_string())?;

    println!("current epoch:     {epoch}");
    println!(
        "identity root:     {} (verified against treasury_info)",
        hex::encode(snapshot.identity_root)
    );
    println!("registered SPOs:   {}", snapshot.spos.len());
    for spo in &snapshot.spos {
        let pool: [u8; 28] = spo
            .pool_id
            .as_slice()
            .try_into()
            .map_err(|_| format!("pool_id not 28 bytes: {}", hex::encode(&spo.pool_id)))?;
        println!("  pool {} ({})", hex::encode(pool), pool_id_bech32(&pool));
        println!("    bifrost_id_pk: {}", hex::encode(&spo.bifrost_id_pk));
        println!(
            "    bifrost_url:   {}",
            String::from_utf8_lossy(&spo.bifrost_url)
        );
        println!("    element UTxO:  {}:{}", spo.tx_hash, spo.output_index);
    }

    // ── ban list (WI-011) ── list entries AND capture the active-ban set the
    // Round-0 derivation below subtracts. Derive from the SAME resolved
    // blueprint/registry-bootstrap (the ban policy is parameterized by the
    // registry policy) so a --blueprint/--registry-bootstrap override can't
    // make the sections describe different deployments. ban_bootstrap is
    // config-only.
    use heimdall::cardano::ban_list::{BanListError, BanListSource, BanPolicyParams};
    let mut active_bans: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    match cfg.cardano.ban_bootstrap.as_deref() {
        None => {
            println!("ban list:          (not configured — set cardano.ban_bootstrap)");
        }
        Some(ban_bootstrap) => {
            // The fault-policy set + ban-schedule params are config-only (they
            // are baked into the ban policy id), unlike --blueprint/--registry-
            // bootstrap which may be CLI overrides.
            let ban_params =
                BanPolicyParams::from_config(&cfg.cardano).map_err(|e| e.to_string())?;
            let source = BanListSource::from_blueprint(
                &blueprint,
                &bootstrap,
                ban_bootstrap,
                &ban_params,
                pid.starts_with("mainnet"),
            )
            .map_err(|e| e.to_string())?;
            println!("ban policy:        {}", source.ban_policy_hex);
            println!("ban address:       {}", source.ban_address);
            // Ban activity is evaluated at the epoch boundary (chain-derived),
            // the same deterministic time the live roster path uses.
            let epoch_start_ms =
                rt.block_on(bf_http::fetch_epoch_start_ms(&base_url, pid, epoch))?;
            match rt.block_on(source.fetch_ban_list(&base_url, pid)) {
                Ok(bans) => {
                    active_bans = bans.active_bans(epoch_start_ms);
                    println!(
                        "ban entries:       {} ({} active at epoch {epoch} boundary)",
                        bans.len(),
                        active_bans.len()
                    );
                    for (pool_id, data) in bans.iter() {
                        let state = if data.active_at(epoch_start_ms) {
                            "ACTIVE"
                        } else {
                            "expired"
                        };
                        println!(
                            "  pool {}  counter={} until_time={} permanent={} [{state}]",
                            hex::encode(pool_id),
                            data.ban_counter,
                            data.ban_until_time,
                            data.permanent
                        );
                    }
                }
                // Expected until the ban root is minted (WI-015) — report,
                // don't fail the read-only diagnostic.
                Err(e @ BanListError::NotBootstrapped) => println!("ban list:          {e}"),
                Err(e) => return Err(format!("ban list: {e}")),
            }
        }
    }

    // ── DKG Round 0 (WI-012): eligible roster (registry − active bans −
    // unusable/duplicate URLs) + stake-weighted FROST threshold ──
    use heimdall::cardano::dkg_roster::{
        derive_dkg_context, eligible_pool_ids, fetch_eligible_stakes,
    };
    let eligible = eligible_pool_ids(&snapshot, &active_bans);
    match rt.block_on(fetch_eligible_stakes(&base_url, pid, &eligible)) {
        Ok(stakes) => match derive_dkg_context(&snapshot, &active_bans, &stakes, epoch, 0) {
            Ok(ctx) => {
                println!(
                    "DKG roster (epoch {epoch}; threshold {} of {}, total stake {}):",
                    ctx.threshold,
                    ctx.participants.len(),
                    ctx.total_stake
                );
                for p in &ctx.participants {
                    println!(
                        "  #{:<3} pk {}  stake={} {}",
                        p.index,
                        hex::encode(&p.bifrost_id_pk),
                        p.active_stake,
                        p.bifrost_url
                    );
                }
                for ex in &ctx.excluded {
                    println!(
                        "  excluded pool {}: {}",
                        hex::encode(&ex.pool_id),
                        ex.reason
                    );
                }
            }
            Err(e) => println!("DKG roster:        cannot derive ({e})"),
        },
        // A stake query failure is fatal for a real ceremony (the threshold
        // can't be computed), but tolerated in this read-only diagnostic so
        // the registry + ban sections above still print — synthetic preprod
        // pools aren't registered Cardano SPOs, so /pools/{id} returns 404.
        Err(e) => println!(
            "DKG roster:        stake unavailable ({e}) — {} eligible pool(s) before threshold",
            eligible.len()
        ),
    }
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
        PegInInput, PegOutRequest, TreasuryInput, build_tm, sign_tm_single_key,
    };
    use heimdall::cardano::bf_http;
    use heimdall::cardano::blockfrost_source::BlockfrostPegInSource;
    use heimdall::cardano::btc_rpc::broadcast_btc_tx;
    use heimdall::cardano::pallas_source::{NetworkMagic, PallasPegInSource};
    use heimdall::cardano::pegin_datum::parse_pegin_request;
    use heimdall::cardano::pegin_source::CardanoPegInSource;
    use heimdall::cardano::pegout_datum::fetch_pegout_requests;

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
    println!(
        "scanned {} peg-in request(s) at {pegin_script_address}",
        reqs.len()
    );

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

    let signed =
        sign_tm_single_key(&secp, &unsigned, &sk).map_err(|e| format!("sign sweep: {e}"))?;
    let local_raw = bitcoin::consensus::encode::serialize(&signed);
    // If an existing-on-Bitcoin TM is provided, the effective tx posted to Cardano is THAT one,
    // not the locally-built one. Deserialize it so every subsequent print (txid, inputs, outputs)
    // reflects the bytes Cardano will actually see — operators would otherwise copy-paste the
    // wrong txid from the locally-signed value.
    let (effective_tx, raw, override_in_effect): (Transaction, Vec<u8>, bool) =
        if let Some(hex_str) = existing_tm_hex {
            let trimmed = hex_str.trim();
            let bytes = hex::decode(trimmed).map_err(|e| format!("existing_tm_hex: {e}"))?;
            let tx: Transaction = bitcoin::consensus::deserialize(&bytes)
                .map_err(|e| format!("existing_tm_hex: not a valid Bitcoin transaction: {e}"))?;
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

    // With an override, the bytes posted to Cardano are the supplied TM, NOT the locally-built
    // one (heimdall's real output is the Cardano post; the BTC broadcast path is debug/demo).
    // Warn about any peg-out the local build would pay that the supplied TM does NOT — typically
    // a peg-out created/scanned AFTER the supplied TM was built, which this movement cannot
    // fulfil (it rolls to the next TM). Surfacing it prevents silently recording a TM that skips
    // a pending withdrawal. (Compared by destination scriptPubKey: local peg-out outputs are
    // `unsigned.tx.output[1..]`; output[0] is the treasury change.)
    if override_in_effect {
        let override_out_spks: std::collections::HashSet<&[u8]> = effective_tx
            .output
            .iter()
            .map(|o| o.script_pubkey.as_bytes())
            .collect();
        for out in unsigned.tx.output.iter().skip(1) {
            if !override_out_spks.contains(out.script_pubkey.as_bytes()) {
                eprintln!(
                    "[override] WARNING: supplied TM does not pay pending peg-out → {} ({} sat) \
                     — likely recorded after the supplied TM was built; it will NOT be fulfilled \
                     by this movement",
                    hex::encode(out.script_pubkey.as_bytes()),
                    out.value.to_sat(),
                );
            }
        }
    }

    println!("\n── Treasury Movement (sweep peg-ins) ──");
    println!("  txid:    {}", effective_tx.compute_txid());
    println!("  inputs:  {}", effective_tx.input.len());
    if override_in_effect {
        // The override is a different tx than the local build, so its inputs do NOT correspond
        // to the locally-computed `unsigned.prevouts` — print outpoints only (we don't have the
        // override's prevout values/scripts) rather than mispair them.
        for (i, inp) in effective_tx.input.iter().enumerate() {
            println!(
                "    [{}] {}:{}",
                i, inp.previous_output.txid, inp.previous_output.vout
            );
        }
    } else {
        for (i, (inp, prevout)) in effective_tx
            .input
            .iter()
            .zip(unsigned.prevouts.iter())
            .enumerate()
        {
            println!(
                "    [{}] {}:{} — {} sat  script={}",
                i,
                inp.previous_output.txid,
                inp.previous_output.vout,
                prevout.value.to_sat(),
                hex::encode(prevout.script_pubkey.as_bytes()),
            );
        }
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
            .ok_or_else(|| {
                "cardano.treasury_address must be set (the TM validator address)".to_string()
            })?;
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
    let address = Address::from_script(&script_pubkey, network).expect("valid P2TR address");

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
    assert_eq!(
        bytes.len(),
        32,
        "--frost-key must be 32 bytes (x-only pubkey)"
    );
    let group_key = UntweakedPublicKey::from_slice(&bytes)
        .expect("--frost-key must be a valid secp256k1 x-only pubkey");

    println!(
        "FROST group key (x-only): {}",
        hex::encode(group_key.serialize())
    );

    // Y_fed = Y_51 = FROST group key
    let spend_info = treasury_spend_info(&secp, group_key, group_key, csv_blocks);
    let output_key = spend_info.output_key();
    let script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key);
    let address = Address::from_script(&script_pubkey, network).expect("valid P2TR address");

    println!("Treasury address (Y_fed=Y_51=FROST): {address}");
    println!("Script pubkey: {}", hex::encode(script_pubkey.as_bytes()));
}

#[cfg(test)]
mod tests {
    use super::{parse_cardano_outref, parse_hex_n, parse_key32, pool_id_bech32};

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

    #[test]
    fn parse_hex_n_checks_length() {
        assert_eq!(parse_hex_n::<2>("a1b2", "x").unwrap(), [0xa1, 0xb2]);
        assert!(parse_hex_n::<2>("a1", "x").is_err());
        assert!(parse_hex_n::<2>("zz", "x").is_err());
    }

    #[test]
    fn parse_key32_accepts_hex_and_textenvelope() {
        let hexkey = "11".repeat(32);
        assert_eq!(parse_key32(&hexkey, "k").unwrap(), [0x11; 32]);

        // cardano-cli TextEnvelope from a file.
        let dir = std::env::temp_dir().join(format!("heimdall-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cold.skey");
        std::fs::write(
            &path,
            format!(
                r#"{{"type": "StakePoolSigningKey_ed25519", "description": "", "cborHex": "5820{}"}}"#,
                "22".repeat(32)
            ),
        )
        .unwrap();
        assert_eq!(
            parse_key32(path.to_str().unwrap(), "k").unwrap(),
            [0x22; 32]
        );
        // TextEnvelope whose cborHex is not a 32-byte key
        std::fs::write(&path, r#"{"type": "x", "cborHex": "5840aabb"}"#).unwrap();
        assert!(parse_key32(path.to_str().unwrap(), "k").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    // The bech32 form must round-trip back to the same 28 bytes under the
    // `pool` HRP (the id Blockfrost's /pools endpoint expects).
    #[test]
    fn pool_id_bech32_roundtrip() {
        let id = [0x5Au8; 28];
        let s = pool_id_bech32(&id);
        assert!(s.starts_with("pool1"), "{s}");
        let (hrp, data) = bitcoin::bech32::decode(&s).unwrap();
        assert_eq!(hrp.as_str(), "pool");
        assert_eq!(data, id);
    }
}
