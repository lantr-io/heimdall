//! Test-utility: build, sign, and (optionally) broadcast a Bifrost peg-in
//! Bitcoin transaction from a depositor's funding UTXO(s).
//!
//! Heimdall the daemon is an SPO program; the depositor is a different actor.
//! This binary lives next to it for convenient reuse of `pegin_spend_info` and the Bitcoin
//! RPC client — it is NOT part of the SPO control plane. It derives no bridge key of its
//! own: every value that decides the deposit address is a required argument.
//!
//! Tx layout produced (spec § Peg-in Taproot tree; the one-leaf demo simplification this
//! used to follow was retired by WI-081):
//!
//! ```text
//! Input  0..N : funding UTXO(s) (P2WPKH controlled by depositor WIF) — signed
//! Output 0    : peg-in P2TR — internal key Y_51 (the 51% quorum's key-path sweep), and
//!               TWO leaves (spec § Peg-in Taproot tree):
//!                 <federation_csv_blocks> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG
//!                 <refund_timeout>        OP_CSV OP_DROP <Q_auth>       OP_CHECKSIG
//! Output 1    : OP_RETURN "BFR" || Q_auth (35 bytes)  [Bifrost one-key beacon]
//!               Q_auth = the depositor's BIP-86 Taproot OUTPUT key, derived from
//!               the WIF. One key does both jobs: the refund leaf above commits it,
//!               and the BIP-322 peg-in completion is signed under it.
//! Output 2    : P2WPKH change back to depositor
//! ```
//!
//! The refund leaf holds the OUTPUT key rather than the WIF's raw internal key, so
//! taking the refund path after the timeout means signing with the BIP-86 *tweaked*
//! key — which is what an ordinary Taproot wallet signs with by default. That is the
//! whole reason for this form (WI-045/WI-072): no wallet would produce an untweaked
//! BIP-322 signature, so the protocol asks for the key they can all sign under.
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
use bitcoin::key::{PrivateKey, TapTweak, UntweakedPublicKey};
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, ecdsa};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, absolute, script, transaction,
};
use clap::Parser;

use heimdall::bitcoin::taproot::{PeginTreeParams, pegin_spend_info};
use heimdall::cardano::btc_rpc::{BtcRpcConfig, broadcast_btc_tx};
use heimdall::config::HeimdallConfig;
use tracing::{error, info, warn};

/// Extra fee allowance per additional P2WPKH input (sats).
const EXTRA_INPUT_FEE_SAT: u64 = 200;

#[derive(Parser)]
#[command(
    name = "heimdall-depositor",
    about = "Build/sign/broadcast a Bifrost peg-in Bitcoin transaction"
)]
struct Cli {
    /// Path to a Heimdall TOML config. Refund timeout, network, and Bitcoin
    /// RPC settings are read from here.
    #[arg(long, default_value = "heimdall.toml")]
    config: PathBuf,

    /// The peg-in Taproot INTERNAL key: the 32-byte x-only FROST group key
    /// `Y_51`, as hex. Get it from `heimdall show-treasury` ("our Y_51: …").
    ///
    /// Required, and deliberately not derivable here. Both sweep paths reconstruct the
    /// deposit address as `Taproot(Y_51; federation leaf + refund leaf)` — this is the
    /// INTERNAL key of that tree, so a deposit built under any other one is unsweepable and
    /// the BTC sits there until the refund timeout. A tool that guessed it would produce a
    /// well-formed address no federation will ever touch, which is worse than refusing to
    /// run. The other two tree inputs are `--y-federation` and `--federation-csv-blocks`.
    #[arg(long)]
    frost_key: String,

    /// The federation fallback key `Y_federation`, 32-byte x-only hex — the key in the
    /// deposit tree's EMERGENCY-SWEEP leaf, not the internal key. Published as the
    /// bridge's Config `y_federation`.
    ///
    /// Required for the same reason as `--frost-key`: it is an input to the deposit
    /// ADDRESS (spec § Peg-in Taproot tree gives the tree two leaves), so a wrong or
    /// absent value builds a well-formed P2TR that neither the federation can sweep nor
    /// this depositor can refund.
    #[arg(long)]
    y_federation: String,

    /// The CSV delay of the deposit tree's DEPOSITOR REFUND leaf, in blocks — the
    /// bridge's Config `params.pegin_refund_timeout_blocks` ([CFG-9]).
    ///
    /// A flag for the same reason as the rest: it is hashed into the deposit address.
    /// It must exceed `--federation-csv-blocks`.
    #[arg(long)]
    refund_timeout_blocks: u16,

    /// The CSV delay of the deposit tree's federation leaf, in blocks — the bridge's
    /// Config `params.federation_csv_blocks`.
    ///
    /// A flag and not a config key, for the same reason as the two above: it is an input
    /// to the deposit ADDRESS. `bitcoin.federation_csv_blocks` is deliberately unset on a
    /// correctly configured node (WI-069 moved it on chain), so reading it from there would
    /// either refuse to run or silently use a value the bridge does not publish.
    #[arg(long)]
    federation_csv_blocks: u16,

    /// Depositor's funding key in Bitcoin WIF format. Its BIP-86 Taproot
    /// output key is what the OP_RETURN beacon carries and what the peg-in
    /// P2TR refund leaf commits. Mutually exclusive with --depositor-wif-file.
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
    /// the depositor only prints the raw tx / txid (dry run). The depositor is the
    /// ONE component that talks to bitcoind (WI-086) — heimdall proper never sends
    /// a transaction to Bitcoin — and even here it takes explicit intent.
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
    // Before anything else: the config-load failure below has to be levelled too.
    heimdall::logging::init_tool();
    if let Err(e) = run() {
        error!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    let cfg = HeimdallConfig::from_file(&cli.config).map_err(|e| e.to_string())?;
    let network = cfg.bitcoin.parsed_network();
    let refund_timeout = cli.refund_timeout_blocks;

    let secp = Secp256k1::new();

    // The peg-in Taproot internal key is the FROST group key Y_51 — NOT the federation
    // key Y_fed, which sits in the emergency-sweep LEAF. Both have to be passed in: they
    // are consensus values the daemon reconstructs every deposit address from
    // (`parse_pegin_request`), so getting either from anywhere else silently produces
    // deposits no federation can sweep.
    let y_51 = parse_xonly("--frost-key", &cli.frost_key)?;
    let y_federation = parse_xonly("--y-federation", &cli.y_federation)?;
    let federation_csv_blocks = cli.federation_csv_blocks;
    let pegin_tree = PeginTreeParams {
        y_51,
        y_federation,
        federation_csv_blocks,
        refund_timeout,
    };
    // One rule, one message, shared with every other deriver.
    pegin_tree.validate()?;

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
    // Q_auth — the WIF's BIP-86 Taproot output key (key-path only, no script tree).
    // This is the single depositor key the protocol knows: the beacon carries it,
    // the peg-in refund leaf commits it, and the BIP-322 completion signs under it.
    let depositor_outputkey = depositor_xonly
        .tap_tweak(&secp, None)
        .0
        .to_x_only_public_key();

    let depositor_p2wpkh = Address::p2wpkh(&depositor_compressed, network);

    let pegin_addr = pegin_address(&secp, &pegin_tree, depositor_outputkey, network);
    info!("peg-in P2TR address: {pegin_addr}");
    info!(
        "peg-in internal key: {}  (Y_51, key path)",
        hex::encode(y_51.serialize())
    );
    info!(
        "federation leaf:     {}  (Y_fed, after {federation_csv_blocks} blocks)",
        hex::encode(y_federation.serialize())
    );
    info!(
        "depositor Q_auth:    {}  (beacon payload + refund-leaf key)",
        hex::encode(depositor_outputkey.serialize())
    );
    info!(
        "depositor auth P2TR: {}  (sign the BIP-322 completion here)",
        Address::p2tr(&secp, depositor_xonly, None, network)
    );
    info!("depositor P2WPKH:    {depositor_p2wpkh}");

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
            info!(
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
                info!(
                    "selected UTXO: {}:{} ({} sat)",
                    u.txid,
                    u.vout,
                    u.amount.to_sat()
                );
            }
            if extra > 0 {
                info!(
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
    let beacon_spk = build_beacon_spk(depositor_outputkey.serialize());
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
    info!("txid: {}", tx.compute_txid());

    if cli.submit {
        let rpc = build_rpc(&cfg)?;
        rt.block_on(broadcast_btc_tx(&rpc, &raw))
            .map_err(|e| format!("broadcast failed: {e}"))?;
    } else {
        info!("(dry run — pass --submit to broadcast)");
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

/// Parse a 32-byte x-only key argument, naming the flag in every failure.
fn parse_xonly(flag: &str, hex_str: &str) -> Result<UntweakedPublicKey, String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("{flag}: {e}"))?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{flag} must be 32 bytes (x-only), got {}", bytes.len()))?;
    UntweakedPublicKey::from_slice(&bytes)
        .map_err(|e| format!("{flag} is not a valid x-only pubkey: {e}"))
}

fn pegin_address(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    tree: &PeginTreeParams,
    depositor_outputkey: UntweakedPublicKey,
    network: bitcoin::Network,
) -> Address {
    let spend_info = pegin_spend_info(secp, tree, depositor_outputkey);
    let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    Address::from_script(&spk, network).expect("P2TR script always has a valid address")
}

/// The 35-byte one-key beacon: `"BFR" || Q_auth`.
///
/// `Q_auth` is the depositor's Taproot output key. It is the key committed in the
/// peg-in Taproot refund leaf, so a sweeper reads the refund key here instead of
/// recovering it by trying candidate outputs against the reconstructed peg-in
/// address; and it is the key the BIP-322 completion signature verifies against.
fn build_beacon_spk(depositor_outputkey: [u8; 32]) -> ScriptBuf {
    let mut payload = Vec::with_capacity(35);
    payload.extend_from_slice(b"BFR");
    payload.extend_from_slice(&depositor_outputkey);
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
        info!("discovered {} UTXO(s) via listunspent", via_wallet.len());
        return Ok(via_wallet);
    }
    warn!("listunspent unavailable or empty; falling back to scantxoutset (slower)");
    let via_scan = scan_utxos(client, rpc, address).await?;
    info!("discovered {} UTXO(s) via scantxoutset", via_scan.len());
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
            warn!(
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
    fn frost_key_round_trips_and_tolerates_whitespace() {
        // A real Y_51: the live deployment's FROST group key.
        let hex_str = "b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854";
        let key = parse_xonly("--frost-key", &format!("  {hex_str}\n")).unwrap();
        assert_eq!(hex::encode(key.serialize()), hex_str);
    }

    #[test]
    fn frost_key_rejects_wrong_length_and_off_curve() {
        // Truncated: caught before it can be mistaken for a valid point.
        let err = parse_xonly("--frost-key", "b1e15a53").unwrap_err();
        assert!(err.contains("32 bytes"), "{err}");
        // Right length, not a curve point — a deposit built under it would be
        // unspendable, so it must not reach the address derivation.
        let err = parse_xonly("--frost-key", &"ff".repeat(32)).unwrap_err();
        assert!(err.contains("x-only pubkey"), "{err}");
    }

    /// The peg-in address must be keyed to Y_51, not to some other internal key:
    /// this is the mismatch that made every depositor-built deposit unsweepable
    /// while the tool derived the internal key from `y_fed_seed_hex`.
    #[test]
    fn pegin_address_follows_the_internal_key() {
        let secp = Secp256k1::new();
        let network = bitcoin::Network::Regtest;
        let depositor = SecretKey::from_slice(&[0xAB; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0;
        let y_51 = parse_xonly(
            "--frost-key",
            "b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854",
        )
        .unwrap();
        let other = SecretKey::from_slice(&[0xFE; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0;

        let tree = PeginTreeParams {
            y_51,
            y_federation: other,
            federation_csv_blocks: 144,
            refund_timeout: 720,
        };
        let a = pegin_address(&secp, &tree, depositor, network);
        let b = pegin_address(
            &secp,
            &PeginTreeParams {
                y_51: other,
                ..tree
            },
            depositor,
            network,
        );
        assert_ne!(a, b);
    }

    /// The beacon is the 35-byte one-key form, and the key it carries is the one
    /// the refund leaf commits — the two are derived from the same value, so a
    /// sweeper reading the beacon reconstructs the address the tool just built.
    #[test]
    fn beacon_is_35_bytes_and_names_the_refund_leaf_key() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let outputkey = sk
            .x_only_public_key(&secp)
            .0
            .tap_tweak(&secp, None)
            .0
            .to_x_only_public_key();

        let spk = build_beacon_spk(outputkey.serialize());
        let bytes = spk.as_bytes();
        assert_eq!(bytes.len(), 37, "OP_RETURN + push + 35-byte payload");
        assert_eq!(bytes[0], 0x6a);
        assert_eq!(bytes[1], 0x23, "OP_PUSHBYTES_35");
        assert_eq!(&bytes[2..5], b"BFR");
        assert_eq!(&bytes[5..37], &outputkey.serialize());

        // …and that is exactly the key the peg-in refund leaf holds.
        let y_51 = parse_xonly(
            "--frost-key",
            "b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854",
        )
        .unwrap();
        let si = pegin_spend_info(
            &secp,
            &PeginTreeParams {
                y_51,
                y_federation: y_51,
                federation_csv_blocks: 144,
                refund_timeout: 720,
            },
            outputkey,
        );
        let leaf = heimdall::bitcoin::taproot::build_csv_checksig_script(720, outputkey);
        assert!(si.script_map().keys().any(|(s, _)| *s == leaf));
    }

    #[test]
    fn errors_on_insufficient_funds() {
        let utxos = vec![fake_utxo(10_000, 1), fake_utxo(20_000, 2)];
        let err = select_utxos(&utxos, Amount::from_sat(100_000)).unwrap_err();
        assert!(err.contains("insufficient"));
    }
}
