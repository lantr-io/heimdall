//! Test-utility: register a Cardano stake pool and self-delegate a small,
//! wallet-controlled stake to it (WI-024). Mirrors the `depositor` binary's
//! shape — build + sign, print the tx, broadcast only with `--submit`.
//!
//! Purpose: give the demo SPOs non-zero `active_stake` so `heimdall demo` can
//! run a stake-weighted DKG off the REAL on-chain registry (instead of the
//! WI-023 local equal-stake fixture). Intended for a local **yaci devnet**
//! (short epochs → stake goes active in seconds), pointed at via
//! `cardano.blockfrost_url`; works against any Blockfrost-compatible endpoint.
//!
//! One tx carries a `PoolRegistration` + `StakeRegistrationAndDelegation`, and
//! funds a `base(wallet_payment, pool_stake)` output with `--delegated-stake-
//! lovelace` — that ADA is what counts as the pool's active stake (the funds
//! stay spendable by the fee wallet's payment key). Register the 3 demo pools
//! with roughly EQUAL amounts so the stake-weighted threshold lands on 2-of-3.
//!
//! See `docs/local/instructions/run-dkz.md`.

use std::path::PathBuf;

use clap::Parser;

use heimdall::cardano::bf_http;
use heimdall::cardano::publish::WalletUtxo;
use heimdall::cardano::register_pool::{
    BuiltRegisterPoolTx, RegisterPoolRequest, build_register_pool_tx, key_hash,
    normal_key_from_seed, synthetic_vrf_key_hash,
};
use heimdall::cardano::tx_common::network_from_address;
use heimdall::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
use heimdall::config::HeimdallConfig;

#[derive(Parser)]
#[command(
    name = "heimdall-register-pool",
    about = "Register a Cardano stake pool + self-delegate stake (devnet demo helper)"
)]
struct Cli {
    /// Path to a Heimdall TOML config (Blockfrost project id / url + mnemonic).
    #[arg(long)]
    config: PathBuf,
    /// Pool cold signing key: 32-byte hex, or a path to a file holding that hex
    /// or a cardano-cli TextEnvelope (cborHex "5820" || 32 bytes). The operator
    /// id = blake2b_224(cold_vkey).
    #[arg(long)]
    cold_skey: String,
    /// Pool stake signing key (same formats). Omit to derive it deterministically
    /// from the cold key, so each pool gets a distinct stake key automatically.
    #[arg(long)]
    stake_skey: Option<String>,
    /// Synthetic VRF key hash (32-byte hex). Omit to derive from the cold key —
    /// the pool produces no blocks, so any well-formed hash is accepted.
    #[arg(long)]
    vrf_key_hash: Option<String>,
    /// Pool pledge (lovelace).
    #[arg(long, default_value_t = 0)]
    pledge: u64,
    /// Pool cost (lovelace); must be >= the network's minPoolCost.
    #[arg(long, default_value_t = 340_000_000)]
    cost: u64,
    /// Margin numerator / denominator (default 0/1 = 0%).
    #[arg(long, default_value_t = 0)]
    margin_numerator: u64,
    #[arg(long, default_value_t = 1)]
    margin_denominator: u64,
    /// ADA routed to base(wallet_payment, pool_stake) — the pool's active stake.
    /// Keep equal across the demo pools for a 2-of-3 threshold.
    #[arg(long, default_value_t = 10_000_000)]
    delegated_stake_lovelace: u64,
    /// Pool registration deposit (lovelace). Must match the network param.
    #[arg(long, default_value_t = 500_000_000)]
    pool_deposit: u64,
    /// Stake-key registration deposit (lovelace). Must match the network param.
    #[arg(long, default_value_t = 2_000_000)]
    key_deposit: u64,
    /// Actually broadcast via Blockfrost (default: build + print only).
    #[arg(long)]
    submit: bool,
}

/// Parse a 32-byte key from raw hex, or from a file containing hex / a
/// cardano-cli TextEnvelope (`cborHex` of `5820` || 32 bytes).
fn parse_key32(arg: &str) -> Result<[u8; 32], String> {
    let raw = arg.trim();
    // Direct 32-byte hex?
    if let Ok(bytes) = hex::decode(raw)
        && bytes.len() == 32
    {
        return Ok(bytes.try_into().unwrap());
    }
    // Otherwise treat as a file path.
    let content = std::fs::read_to_string(raw)
        .map_err(|e| format!("key is neither 32-byte hex nor a readable file ({raw}): {e}"))?;
    let trimmed = content.trim();
    // TextEnvelope JSON with a cborHex field?
    if let Some(idx) = trimmed.find("cborHex") {
        let rest = &trimmed[idx..];
        if let (Some(s), Some(e)) = (
            rest.find(':'),
            rest[rest.find(':').unwrap_or(0)..].find('"'),
        ) {
            let after = &rest[s + e + 1..];
            if let Some(end) = after.find('"') {
                let cbor = &after[..end];
                let bytes = hex::decode(cbor).map_err(|e| format!("bad cborHex: {e}"))?;
                // Strip the CBOR bytestring prefix 0x5820 (32-byte string).
                let key = if bytes.len() == 34 && bytes[0] == 0x58 && bytes[1] == 0x20 {
                    &bytes[2..]
                } else {
                    &bytes[..]
                };
                if key.len() == 32 {
                    return Ok(key.try_into().unwrap());
                }
                return Err(format!(
                    "TextEnvelope cborHex is not a 32-byte key ({} bytes)",
                    key.len()
                ));
            }
        }
        return Err("could not parse cborHex from TextEnvelope".into());
    }
    // Plain hex in a file.
    let bytes = hex::decode(trimmed).map_err(|e| format!("file is not hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "key file is not a 32-byte key ({} bytes)",
            bytes.len()
        ));
    }
    Ok(bytes.try_into().unwrap())
}

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

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let cfg = HeimdallConfig::from_file(&cli.config).map_err(|e| e.to_string())?;

    let mnemonic = resolve_mnemonic(&cfg)?;
    let payment_key = derive_payment_key(&mnemonic)?;
    let wallet_addr = wallet_address_from_mnemonic(&mnemonic)?;
    let wallet_payment_pkh = key_hash(&payment_key);

    let cold_seed = parse_key32(&cli.cold_skey)?;
    let stake_seed = match &cli.stake_skey {
        Some(s) => parse_key32(s)?,
        None => {
            // Distinct-but-deterministic stake key per pool.
            let mut p = b"heimdall-demo-stake".to_vec();
            p.extend_from_slice(&cold_seed);
            heimdall::cardano::hash::blake2b_256(&p)
        }
    };
    let vrf_key_hash = match &cli.vrf_key_hash {
        Some(h) => {
            let b = hex::decode(h.trim()).map_err(|e| format!("--vrf-key-hash not hex: {e}"))?;
            b.try_into()
                .map_err(|_| "--vrf-key-hash must be 32 bytes".to_string())?
        }
        None => synthetic_vrf_key_hash(&cold_seed),
    };

    let cold_key = normal_key_from_seed(cold_seed);
    let stake_key = normal_key_from_seed(stake_seed);

    let project_id = cfg
        .cardano
        .blockfrost_project_id
        .clone()
        .ok_or("cardano.blockfrost_project_id required")?;
    let base_url = bf_http::base_url(&project_id, cfg.cardano.blockfrost_url.as_deref());
    let network = network_from_address(&wallet_addr);

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    let wallet_raw = rt
        .block_on(bf_http::fetch_address_utxos(
            &base_url,
            &project_id,
            &wallet_addr,
        ))
        .map_err(|e| format!("fetch wallet utxos: {e}"))?;
    let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
    let cost_models = rt
        .block_on(bf_http::fetch_cost_models(&base_url, &project_id))
        .ok();

    let req = RegisterPoolRequest {
        wallet_address: &wallet_addr,
        wallet_payment_pkh,
        wallet_utxos: &wallet_utxos,
        payment_key: &payment_key,
        cold_key: &cold_key,
        stake_key: &stake_key,
        vrf_key_hash,
        pledge: cli.pledge,
        cost: cli.cost,
        margin: (cli.margin_numerator, cli.margin_denominator),
        delegated_lovelace: cli.delegated_stake_lovelace,
        pool_deposit: cli.pool_deposit,
        key_deposit: cli.key_deposit,
        cost_models,
        network,
    };
    let built: BuiltRegisterPoolTx =
        build_register_pool_tx(req).map_err(|e| format!("build register-pool tx: {e}"))?;

    eprintln!("fee wallet:        {wallet_addr}");
    eprintln!("pool id (hex):     {}", built.pool_id_hex);
    eprintln!("pool id (bech32):  {}", built.pool_id_bech32);
    eprintln!("stake address:     {}", built.stake_address);
    eprintln!(
        "delegated stake:   {} lovelace at {}",
        cli.delegated_stake_lovelace, built.stake_base_address
    );
    println!("{}", built.signed_tx_hex);

    if !cli.submit {
        eprintln!("(dry run — pass --submit to broadcast via Blockfrost)");
        return Ok(());
    }
    let cbor = hex::decode(&built.signed_tx_hex).map_err(|e| e.to_string())?;
    let mut settings = blockfrost::BlockFrostSettings::new();
    if let Some(url) = cfg.cardano.blockfrost_url.as_deref() {
        settings.base_url = Some(url.to_string());
    }
    let api = blockfrost::BlockfrostAPI::new(&project_id, settings);
    let tx_hash = rt
        .block_on(api.transactions_submit(cbor))
        .map_err(|e| format!("blockfrost submit: {e}"))?;
    eprintln!("submitted: tx_hash={tx_hash}");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
