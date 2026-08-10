//! Thin bitcoind JSON-RPC client for broadcasting raw transactions.
//!
//! Shared by `MockCardanoChain` and `BlockfrostCardanoChain` so both
//! can send signed BTC transactions directly to a regtest/testnet node.

use crate::epoch::state::{EpochError, EpochResult};
use tracing::info;

#[derive(Clone)]
pub struct BtcRpcConfig {
    pub url: String,
    pub user: Option<String>,
    pub pass: Option<String>,
}

/// Broadcast a raw Bitcoin transaction to a bitcoind node via JSON-RPC
/// (`sendrawtransaction`).
pub async fn broadcast_btc_tx(rpc: &BtcRpcConfig, tx_bytes: &[u8]) -> EpochResult<()> {
    let tx_hex = hex::encode(tx_bytes);
    info!(
        "[btc-rpc] broadcasting tx ({} bytes) to {}",
        tx_bytes.len(),
        rpc.url
    );

    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "heimdall",
        "method": "sendrawtransaction",
        "params": [tx_hex]
    });

    let mut req = reqwest::Client::new().post(&rpc.url).json(&body);
    if let (Some(user), Some(pass)) = (&rpc.user, &rpc.pass) {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| EpochError::Chain(format!("btc rpc request: {e}")))?;

    let status = resp.status();
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| EpochError::Chain(format!("btc rpc response parse: {e}")))?;

    if let Some(err) = json.get("error").filter(|e| !e.is_null()) {
        return Err(EpochError::Chain(format!("btc rpc error: {err}")));
    }

    if !status.is_success() {
        return Err(EpochError::Chain(format!("btc rpc HTTP {status}: {json}")));
    }

    let txid = json.get("result").and_then(|r| r.as_str()).unwrap_or("?");
    info!("[btc-rpc] broadcast accepted: txid = {txid}");
    Ok(())
}

/// Value in satoshis of an unspent outpoint via `gettxout` (mempool included).
/// Errors when the outpoint is unknown or already spent — used only to price
/// the genesis treasury anchor, which must be unspent until the first TM.
pub async fn get_txout_value_sat(rpc: &BtcRpcConfig, txid: &str, vout: u32) -> EpochResult<u64> {
    let result = get_txout(rpc, txid, vout).await?;
    let btc = result
        .get("value")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| EpochError::Chain("gettxout result has no numeric value".into()))?;
    bitcoin::Amount::from_btc(btc)
        .map(bitcoin::Amount::to_sat)
        .map_err(|e| EpochError::Chain(format!("gettxout value parse: {e}")))
}

/// Hex scriptPubKey of an unspent outpoint via `gettxout` (mempool included).
/// Used to select which candidate taproot tree the singleton's head is locked
/// under — the BridgeState datum records outpoint and amount, not the script.
pub async fn get_txout_script_pub_key_hex(
    rpc: &BtcRpcConfig,
    txid: &str,
    vout: u32,
) -> EpochResult<String> {
    let result = get_txout(rpc, txid, vout).await?;
    result
        .get("scriptPubKey")
        .and_then(|s| s.get("hex"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| EpochError::Chain("gettxout result has no scriptPubKey.hex".into()))
}

/// The non-null `gettxout` result for an UNSPENT outpoint (mempool included).
async fn get_txout(rpc: &BtcRpcConfig, txid: &str, vout: u32) -> EpochResult<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "heimdall",
        "method": "gettxout",
        "params": [txid, vout, true]
    });

    let mut req = reqwest::Client::new().post(&rpc.url).json(&body);
    if let (Some(user), Some(pass)) = (&rpc.user, &rpc.pass) {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| EpochError::Chain(format!("btc rpc request: {e}")))?;
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| EpochError::Chain(format!("btc rpc response parse: {e}")))?;

    if let Some(err) = json.get("error").filter(|e| !e.is_null()) {
        return Err(EpochError::Chain(format!("btc rpc error: {err}")));
    }

    json.get("result")
        .filter(|r| !r.is_null())
        .cloned()
        .ok_or_else(|| {
            EpochError::Chain(format!(
                "gettxout {txid}:{vout} returned null — outpoint unknown or already spent"
            ))
        })
}
