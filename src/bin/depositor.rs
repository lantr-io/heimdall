//! Test-utility: build, sign, and (optionally) broadcast a Bifrost peg-in
//! Bitcoin transaction from a depositor's funding UTXO(s).
//!
//! Heimdall the daemon is an SPO program; the depositor is a different actor.
//! This binary lives next to it for convenient reuse of `pegin_spend_info`,
//! `Y_federation` derivation, and the Bitcoin RPC client — it is NOT part of
//! the SPO control plane.
//!
//! Tx layout produced (demo-simplified peg-in, per
//! `ft-bifrost-bridge/documentation/demo_simplifications.md`):
//!
//! ```text
//! Input  0..N : funding UTXO(s) (P2WPKH controlled by depositor WIF) — signed
//! Output 0    : peg-in P2TR (internal key Y_fed, single leaf = depositor refund)
//! Output 1    : OP_RETURN "BFR" || depositor_auth_outputkey (32 bytes)  [Bifrost beacon]
//!               (depositor's key-path Taproot output key = the BIP-322 completion key)
//! Output 2    : P2WPKH change back to depositor
//! ```
//!
//! UTXO selection: if `--funding-*` flags are not given, the tool queries the
//! Bitcoin node for spendable UTXOs at the depositor's P2WPKH address — first
//! via `listunspent`, falling back to `scantxoutset` if the wallet doesn't
//! track the key. Selection prefers the smallest single UTXO ≥ required;
//! falls back to greedy largest-first if no single UTXO is big enough.
//!
//! Limitations (intentional for a first cut):
//! - Funding inputs must be P2WPKH controlled by the same WIF used to derive
//!   the depositor x-only pubkey.
//! - Fee is taken as a flat `--fee-sat`; tool auto-bumps by 200 sat per extra
//!   input when multi-input selection is used.
//! - No Cardano-side PegInRequest minting — watchtowers handle that in the
//!   real protocol; for demos do it via the Cardano-side tooling.

use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::hashes::Hash as _;
use bitcoin::key::{PrivateKey, UntweakedPublicKey};
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, ecdsa};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, absolute, script, transaction,
};
use clap::Parser;

use heimdall::bitcoin::taproot::pegin_spend_info;
use heimdall::cardano::btc_rpc::{BtcRpcConfig, broadcast_btc_tx};
use heimdall::config::HeimdallConfig;

/// Extra fee allowance per additional P2WPKH input (sats).
const EXTRA_INPUT_FEE_SAT: u64 = 200;

#[derive(Parser)]
#[command(
    name = "heimdall-depositor",
    about = "Build/sign/broadcast a Bifrost peg-in Bitcoin transaction"
)]
struct Cli {
    /// Path to a Heimdall TOML config. Y_federation, refund timeout, network,
    /// and Bitcoin RPC settings are read from here.
    #[arg(long, default_value = "heimdall.toml")]
    config: PathBuf,

    /// Depositor's funding key in Bitcoin WIF format. The same key derives
    /// the depositor x-only pubkey used in the OP_RETURN beacon and the
    /// peg-in P2TR refund leaf. Mutually exclusive with --depositor-wif-file.
    #[arg(
        long,
        conflicts_with = "depositor_wif_file",
        required_unless_present = "depositor_wif_file"
    )]
    depositor_wif: Option<String>,

    /// Path to a file containing the depositor WIF (whitespace trimmed).
    /// Safer than --depositor-wif because the key doesn't appear in shell history.
    #[arg(long)]
    depositor_wif_file: Option<PathBuf>,

    /// Manual funding override (all three required together). If unset, the
    /// tool auto-selects UTXOs via Bitcoin RPC.
    #[arg(long, requires_all = ["funding_vout", "funding_amount_sat"])]
    funding_txid: Option<String>,
    #[arg(long)]
    funding_vout: Option<u32>,
    #[arg(long)]
    funding_amount_sat: Option<u64>,

    /// Amount to lock in the peg-in P2TR output (sats).
    #[arg(long)]
    deposit_amount_sat: u64,

    /// Base fee in sats (auto-bumped by 200 sat per extra input for multi-input txs).
    #[arg(long, default_value_t = 1000)]
    fee_sat: u64,

    /// Broadcast the signed tx to `bitcoin.rpc_url`. Opt-in: without this flag
    /// the depositor only prints the raw tx / txid (dry run). This is a demo
    /// tool, so it does NOT inherit the daemon's `bitcoin.submit` setting —
    /// broadcasting a live peg-in requires explicit intent here.
    #[arg(long)]
    submit: bool,
}

#[derive(Debug, Clone)]
struct Utxo {
    txid: Txid,
    vout: u32,
    amount: Amount,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    let cfg = HeimdallConfig::from_file(&cli.config).map_err(|e| e.to_string())?;
    let network = cfg.bitcoin.parsed_network();
    let refund_timeout = cfg.bitcoin.pegin_refund_timeout_blocks;

    let secp = Secp256k1::new();

    let y_fed = derive_y_fed(&cfg.bitcoin.y_fed_seed_hex, &secp)?;

    let wif = read_wif(&cli)?;
    let depositor_priv =
        PrivateKey::from_wif(wif.trim()).map_err(|e| format!("invalid depositor WIF: {e}"))?;
    if depositor_priv.network != network.into() {
        return Err(format!(
            "WIF network ({:?}) differs from config network ({:?}); the derived \
             funding address would not match the key on the configured network",
            depositor_priv.network, network
        ));
    }
    let depositor_sk = depositor_priv.inner;
    let depositor_compressed = CompressedPublicKey::from_private_key(&secp, &depositor_priv)
        .map_err(|e| format!("uncompressed WIF not supported: {e}"))?;
    let depositor_xonly = depositor_sk.x_only_public_key(&secp).0;

    let depositor_p2wpkh = Address::p2wpkh(&depositor_compressed, network);

    let pegin_addr = pegin_address(&secp, y_fed, depositor_xonly, refund_timeout, network);
    eprintln!("peg-in P2TR address: {pegin_addr}");
    eprintln!(
        "depositor x-only:    {}",
        hex::encode(depositor_xonly.serialize())
    );
    eprintln!(
        "depositor auth P2TR: {}  (sign the BIP-322 completion here)",
        Address::p2tr(&secp, depositor_xonly, None, network)
    );
    eprintln!("depositor P2WPKH:    {depositor_p2wpkh}");

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;

    let deposit_amount = Amount::from_sat(cli.deposit_amount_sat);
    // The federation rejects peg-in outputs below its 330-sat dust threshold
    // (see parse_pegin_request); building one would strand the BTC until the
    // refund timelock, so reject it up front.
    const PEGIN_DUST_SAT: u64 = 330;
    if cli.deposit_amount_sat < PEGIN_DUST_SAT {
        return Err(format!(
            "--deposit-amount-sat {} is below the {}-sat peg-in dust threshold the \
             federation enforces; the deposit would be unprocessable",
            cli.deposit_amount_sat, PEGIN_DUST_SAT
        ));
    }

    let (selected, fee) = match cli.funding_txid.as_deref() {
        Some(txid_hex) => {
            let utxo = Utxo {
                txid: Txid::from_str(txid_hex).map_err(|e| format!("invalid funding txid: {e}"))?,
                vout: cli.funding_vout.expect("clap requires_all guarantees this"),
                amount: Amount::from_sat(
                    cli.funding_amount_sat
                        .expect("clap requires_all guarantees this"),
                ),
            };
            eprintln!(
                "manual UTXO: {}:{} ({} sat)",
                utxo.txid,
                utxo.vout,
                utxo.amount.to_sat()
            );
            (vec![utxo], Amount::from_sat(cli.fee_sat))
        }
        None => {
            let rpc = build_rpc(&cfg)?;
            // One `Client` for the whole discovery + broadcast chain so reqwest pools the
            // bitcoind RPC connection across `listunspent` / `scantxoutset` / `sendrawtransaction`.
            let http = reqwest::Client::new();
            let utxos = rt.block_on(discover_utxos(&http, &rpc, &depositor_p2wpkh.to_string()))?;
            if utxos.is_empty() {
                return Err(format!(
                    "no UTXOs found at {depositor_p2wpkh}. Fund the address and retry."
                ));
            }
            let required = deposit_amount
                .checked_add(Amount::from_sat(cli.fee_sat))
                .ok_or_else(|| "deposit + fee overflows".to_string())?;
            let selected = select_utxos(&utxos, required)?;
            let extra = selected.len().saturating_sub(1) as u64;
            let fee = Amount::from_sat(cli.fee_sat + extra * EXTRA_INPUT_FEE_SAT);
            for u in &selected {
                eprintln!(
                    "selected UTXO: {}:{} ({} sat)",
                    u.txid,
                    u.vout,
                    u.amount.to_sat()
                );
            }
            if extra > 0 {
                eprintln!(
                    "multi-input ({} inputs): fee bumped to {} sat",
                    selected.len(),
                    fee.to_sat()
                );
            }
            (selected, fee)
        }
    };

    let total_in: Amount = selected.iter().map(|u| u.amount).sum();
    let change = total_in
        .checked_sub(deposit_amount)
        .and_then(|v| v.checked_sub(fee))
        .ok_or_else(|| {
            format!(
                "selected {} sat < deposit {} sat + fee {} sat",
                total_in.to_sat(),
                deposit_amount.to_sat(),
                fee.to_sat()
            )
        })?;

    // A zero or sub-dust P2WPKH change output is non-standard and bitcoind
    // rejects it on broadcast. Demo tooling: rather than silently absorbing the
    // remainder into the fee, fail loudly so the operator picks a different
    // amount / funding UTXO.
    const P2WPKH_DUST_SAT: u64 = 294;
    if change > Amount::ZERO && change < Amount::from_sat(P2WPKH_DUST_SAT) {
        return Err(format!(
            "change {} sat is below the P2WPKH dust threshold ({} sat); \
             adjust --deposit-amount-sat / --fee-sat or fund a larger UTXO",
            change.to_sat(),
            P2WPKH_DUST_SAT
        ));
    }

    let pegin_spk = pegin_addr.script_pubkey();
    // Beacon carries the depositor's key-path Taproot output key — the key the completion's
    // BIP-322 signature verifies against — NOT the raw internal x-only.
    let depositor_auth_spk = ScriptBuf::new_p2tr(&secp, depositor_xonly, None);
    let depositor_auth_outputkey: [u8; 32] = depositor_auth_spk.as_bytes()[2..34]
        .try_into()
        .expect("p2tr scriptPubKey is OP_1 PUSH32 <32-byte key>");
    let beacon_spk = build_beacon_spk(depositor_auth_outputkey);
    let change_spk = ScriptBuf::new_p2wpkh(&depositor_compressed.wpubkey_hash());
    let funding_spk = change_spk.clone();

    let inputs: Vec<TxIn> = selected
        .iter()
        .map(|u| TxIn {
            previous_output: OutPoint {
                txid: u.txid,
                vout: u.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        })
        .collect();

    let mut outputs = vec![
        TxOut {
            value: deposit_amount,
            script_pubkey: pegin_spk,
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: beacon_spk,
        },
    ];
    // Omit the change output entirely when the remainder is zero (a zero-value
    // P2WPKH output is non-standard); sub-dust positive change was already
    // rejected above.
    if change > Amount::ZERO {
        outputs.push(TxOut {
            value: change,
            script_pubkey: change_spk,
        });
    }

    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    for (idx, utxo) in selected.iter().enumerate() {
        sign_p2wpkh_input(&mut tx, idx, &funding_spk, utxo.amount, depositor_sk, &secp)?;
    }

    let raw = bitcoin::consensus::encode::serialize(&tx);
    println!("{}", hex::encode(&raw));
    eprintln!("txid: {}", tx.compute_txid());

    if cli.submit {
        let rpc = build_rpc(&cfg)?;
        rt.block_on(broadcast_btc_tx(&rpc, &raw))
            .map_err(|e| format!("broadcast failed: {e}"))?;
    } else {
        eprintln!("(dry run — pass --submit to broadcast)");
    }

    Ok(())
}

fn read_wif(cli: &Cli) -> Result<String, String> {
    if let Some(s) = &cli.depositor_wif {
        return Ok(s.clone());
    }
    if let Some(path) = &cli.depositor_wif_file {
        return std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()));
    }
    Err("must pass --depositor-wif or --depositor-wif-file".to_string())
}

fn derive_y_fed(
    seed_hex: &str,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<UntweakedPublicKey, String> {
    let seed: [u8; 32] = hex::decode(seed_hex)
        .map_err(|e| format!("y_fed_seed_hex not valid hex: {e}"))?
        .try_into()
        .map_err(|_| "y_fed_seed_hex must be 32 bytes".to_string())?;
    let sk = SecretKey::from_slice(&seed).map_err(|e| format!("y_fed seed → sk: {e}"))?;
    Ok(sk.x_only_public_key(secp).0)
}

fn pegin_address(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    y_fed: UntweakedPublicKey,
    depositor_xonly: UntweakedPublicKey,
    refund_timeout: u16,
    network: bitcoin::Network,
) -> Address {
    let spend_info = pegin_spend_info(secp, y_fed, depositor_xonly, refund_timeout);
    let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    Address::from_script(&spk, network).expect("P2TR script always has a valid address")
}

fn build_beacon_spk(depositor_xonly_bytes: [u8; 32]) -> ScriptBuf {
    let mut payload = Vec::with_capacity(35);
    payload.extend_from_slice(b"BFR");
    payload.extend_from_slice(&depositor_xonly_bytes);
    script::Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(<&bitcoin::script::PushBytes>::try_from(payload.as_slice()).unwrap())
        .into_script()
}

fn sign_p2wpkh_input(
    tx: &mut Transaction,
    input_index: usize,
    funding_spk: &ScriptBuf,
    funding_amount: Amount,
    sk: SecretKey,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<(), String> {
    let mut cache = SighashCache::new(&*tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            input_index,
            funding_spk,
            funding_amount,
            EcdsaSighashType::All,
        )
        .map_err(|e| format!("p2wpkh sighash: {e}"))?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let sig: ecdsa::Signature = secp.sign_ecdsa(&msg, &sk);

    let pk = sk.public_key(secp).serialize();
    let mut sig_der = sig.serialize_der().to_vec();
    sig_der.push(EcdsaSighashType::All as u8);

    let mut witness = Witness::new();
    witness.push(sig_der);
    witness.push(pk);
    tx.input[input_index].witness = witness;
    Ok(())
}

fn build_rpc(cfg: &HeimdallConfig) -> Result<BtcRpcConfig, String> {
    let url = cfg
        .bitcoin
        .rpc_url
        .clone()
        .ok_or_else(|| "bitcoin.rpc_url not set in config".to_string())?;
    Ok(BtcRpcConfig {
        url,
        user: cfg.bitcoin.rpc_user.clone(),
        pass: cfg.bitcoin.rpc_pass.clone(),
    })
}

// ──────────────────────────────────────────────────────────────────────
// UTXO discovery + selection
// ──────────────────────────────────────────────────────────────────────

/// Try `listunspent` filtered by address; if it returns empty or the
/// wallet isn't usable (no wallet loaded / multiple wallets unselected),
/// fall back to `scantxoutset addr(...)`. Returns owned, spendable UTXOs.
async fn discover_utxos(
    client: &reqwest::Client,
    rpc: &BtcRpcConfig,
    address: &str,
) -> Result<Vec<Utxo>, String> {
    let via_wallet = list_unspent(client, rpc, address).await?;
    if !via_wallet.is_empty() {
        eprintln!("discovered {} UTXO(s) via listunspent", via_wallet.len());
        return Ok(via_wallet);
    }
    eprintln!("listunspent unavailable or empty; falling back to scantxoutset (slower)");
    let via_scan = scan_utxos(client, rpc, address).await?;
    eprintln!("discovered {} UTXO(s) via scantxoutset", via_scan.len());
    Ok(via_scan)
}

/// Extract the `error.code` field from a Bitcoin Core JSON-RPC response,
/// returning `None` if there is no structured error.
fn rpc_error_code(json: &serde_json::Value) -> Option<i64> {
    json.get("error")
        .filter(|e| !e.is_null())
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64())
}

async fn list_unspent(
    client: &reqwest::Client,
    rpc: &BtcRpcConfig,
    address: &str,
) -> Result<Vec<Utxo>, String> {
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "depositor",
        "method": "listunspent",
        "params": [1, 9999999, [address]]
    });
    let json = rpc_call(client, rpc, body).await?;

    // -18 RPC_WALLET_NOT_FOUND  (no wallet is loaded)
    // -19 RPC_WALLET_NOT_SPECIFIED (multiple wallets, none selected)
    // Neither is fatal: scantxoutset doesn't need a wallet, so let the
    // caller fall back. Other error codes still surface as failures.
    if let Some(code) = rpc_error_code(&json) {
        if code == -18 || code == -19 {
            eprintln!(
                "listunspent: rpc error {code} ({}); skipping wallet path",
                json["error"]
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("?")
            );
            return Ok(Vec::new());
        }
        return Err(format!("listunspent rpc error: {}", json["error"]));
    }

    let arr = json
        .get("result")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "listunspent: missing result array".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let txid_str = item
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "listunspent: entry missing txid".to_string())?;
        let vout =
            item.get("vout")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "listunspent: entry missing vout".to_string())? as u32;
        let amount_btc = item
            .get("amount")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| "listunspent: entry missing amount".to_string())?;
        out.push(Utxo {
            txid: Txid::from_str(txid_str).map_err(|e| format!("listunspent txid: {e}"))?,
            vout,
            amount: btc_to_amount(amount_btc)?,
        });
    }
    Ok(out)
}

async fn scan_utxos(
    client: &reqwest::Client,
    rpc: &BtcRpcConfig,
    address: &str,
) -> Result<Vec<Utxo>, String> {
    let descriptor = format!("addr({address})");
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "depositor",
        "method": "scantxoutset",
        "params": ["start", [descriptor]]
    });
    let json = rpc_call(client, rpc, body).await?;
    if rpc_error_code(&json).is_some() {
        return Err(format!("scantxoutset rpc error: {}", json["error"]));
    }
    let arr = json
        .get("result")
        .and_then(|v| v.get("unspents"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| "scantxoutset: missing unspents array".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let txid_str = item
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "scantxoutset: entry missing txid".to_string())?;
        let vout =
            item.get("vout")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "scantxoutset: entry missing vout".to_string())? as u32;
        let amount_btc = item
            .get("amount")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| "scantxoutset: entry missing amount".to_string())?;
        out.push(Utxo {
            txid: Txid::from_str(txid_str).map_err(|e| format!("scantxoutset txid: {e}"))?,
            vout,
            amount: btc_to_amount(amount_btc)?,
        });
    }
    Ok(out)
}

/// Send a JSON-RPC body and return the parsed response. Bitcoin Core
/// returns HTTP 500 with a structured `error` body for RPC-level failures
/// (e.g. -18 "No wallet is loaded"), so this helper does NOT treat a
/// JSON-level error as fatal — callers inspect `json["error"]` to decide
/// whether a given code is recoverable (see `list_unspent`). For 4xx /
/// non-500 5xx (e.g. 401 from missing/incorrect auth), Bitcoin Core returns
/// a non-JSON body; we short-circuit before the JSON parse so the caller
/// sees a precise status code instead of a generic `rpc parse` error.
///
/// The `client` is shared across calls so reqwest can pool the connection —
/// `discover_utxos` does back-to-back `listunspent` + `scantxoutset`, and
/// `run` chains a broadcast on top.
async fn rpc_call(
    client: &reqwest::Client,
    rpc: &BtcRpcConfig,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut req = client.post(&rpc.url).json(&body);
    if let (Some(user), Some(pass)) = (&rpc.user, &rpc.pass) {
        req = req.basic_auth(user, Some(pass));
    }
    let resp = req.send().await.map_err(|e| format!("rpc send: {e}"))?;
    let status = resp.status();
    // Only HTTP 200 and HTTP 500 (Bitcoin Core's structured RPC-error path) carry JSON. Anything
    // else (401/403 from auth, 404 from a bad URL, etc.) returns plain text or HTML; surface the
    // status so the operator sees the cause directly instead of chasing a "rpc parse" error.
    if status != reqwest::StatusCode::OK && status != reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(200).collect();
        return Err(format!("rpc http {status}: {snippet}"));
    }
    let json: serde_json::Value = resp.json().await.map_err(|e| format!("rpc parse: {e}"))?;
    Ok(json)
}

fn btc_to_amount(btc: f64) -> Result<Amount, String> {
    Amount::from_btc(btc).map_err(|e| format!("amount {btc} BTC: {e}"))
}

/// Prefer the smallest single UTXO ≥ required; fall back to greedy
/// largest-first when no single UTXO covers it.
fn select_utxos(utxos: &[Utxo], required: Amount) -> Result<Vec<Utxo>, String> {
    let mut by_size_asc: Vec<&Utxo> = utxos.iter().collect();
    by_size_asc.sort_by_key(|u| u.amount);

    if let Some(u) = by_size_asc.iter().find(|u| u.amount >= required) {
        return Ok(vec![(*u).clone()]);
    }

    let mut acc = Amount::ZERO;
    let mut picked = Vec::new();
    for u in by_size_asc.iter().rev() {
        acc += u.amount;
        picked.push((*u).clone());
        let fee_budget =
            Amount::from_sat(EXTRA_INPUT_FEE_SAT * (picked.len().saturating_sub(1) as u64));
        if acc >= required + fee_budget {
            return Ok(picked);
        }
    }
    Err(format!(
        "insufficient funds: have {} sat, need {} sat (+ ~{} sat/extra-input)",
        acc.to_sat(),
        required.to_sat(),
        EXTRA_INPUT_FEE_SAT
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_utxo(amount_sat: u64, seed: u8) -> Utxo {
        Utxo {
            txid: Txid::from_byte_array([seed; 32]),
            vout: 0,
            amount: Amount::from_sat(amount_sat),
        }
    }

    #[test]
    fn picks_smallest_sufficient_single_utxo() {
        let utxos = vec![
            fake_utxo(100_000, 1),
            fake_utxo(50_000, 2),
            fake_utxo(200_000, 3),
            fake_utxo(75_000, 4),
        ];
        let sel = select_utxos(&utxos, Amount::from_sat(60_000)).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].amount.to_sat(), 75_000);
    }

    #[test]
    fn falls_back_to_multi_input_largest_first() {
        let utxos = vec![
            fake_utxo(40_000, 1),
            fake_utxo(30_000, 2),
            fake_utxo(20_000, 3),
        ];
        let sel = select_utxos(&utxos, Amount::from_sat(60_000)).unwrap();
        assert!(sel.len() >= 2);
        let total: u64 = sel.iter().map(|u| u.amount.to_sat()).sum();
        assert!(total >= 60_000 + EXTRA_INPUT_FEE_SAT);
    }

    #[test]
    fn errors_on_insufficient_funds() {
        let utxos = vec![fake_utxo(10_000, 1), fake_utxo(20_000, 2)];
        let err = select_utxos(&utxos, Amount::from_sat(100_000)).unwrap_err();
        assert!(err.contains("insufficient"));
    }
}
