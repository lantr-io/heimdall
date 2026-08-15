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

/// How deep a transaction is in the chain, via `getrawtransaction <txid> true`.
///
/// `Ok(None)` means the node has no confirmation count for it: unconfirmed, or
/// outside the node's index (a pruned node, or `txindex=0` with the tx not in the
/// wallet). Both are "we cannot say", which the caller must not read as zero —
/// a relative-timelock check that treats unknown as shallow would block a
/// perfectly valid recovery spend.
///
/// Exists for the CSV gate on `federation-spend`: the recovery leaf is a relative
/// timelock, so the treasury UTxO has to be `federation_csv_blocks` deep before
/// the spend is even relayable. Without this the check could not be made at all,
/// and a too-early attempt burned a whole `t`-of-`n` FROST session before the
/// network rejected the result.
pub async fn fetch_tx_confirmations(
    rpc: &BtcRpcConfig,
    txid: &bitcoin::Txid,
) -> EpochResult<Option<u64>> {
    let json = rpc_call(
        rpc,
        "getrawtransaction",
        serde_json::json!([txid.to_string(), true]),
    )
    .await?;
    Ok(json
        .get("result")
        .and_then(|r| r.get("confirmations"))
        .and_then(serde_json::Value::as_u64))
}

/// One JSON-RPC round trip, returning the whole envelope so callers can read
/// `result` themselves. Errors carry the node's own message: a `getrawtransaction`
/// refusal is usually "No such mempool or blockchain transaction… use -txindex",
/// which tells the operator exactly what to change.
async fn rpc_call(
    rpc: &BtcRpcConfig,
    method: &str,
    params: serde_json::Value,
) -> EpochResult<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "heimdall",
        "method": method,
        "params": params,
    });
    let mut req = reqwest::Client::new().post(&rpc.url).json(&body);
    if let (Some(user), Some(pass)) = (&rpc.user, &rpc.pass) {
        req = req.basic_auth(user, Some(pass));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| EpochError::Chain(format!("btc rpc request ({method}): {e}")))?;
    let status = resp.status();
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| EpochError::Chain(format!("btc rpc response parse ({method}): {e}")))?;
    if let Some(err) = json.get("error").filter(|e| !e.is_null()) {
        return Err(EpochError::Chain(format!(
            "btc rpc error ({method}): {err}"
        )));
    }
    if !status.is_success() {
        return Err(EpochError::Chain(format!(
            "btc rpc HTTP {status} ({method}): {json}"
        )));
    }
    Ok(json)
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
