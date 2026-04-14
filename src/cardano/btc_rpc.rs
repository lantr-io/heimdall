//! Thin bitcoind JSON-RPC client for broadcasting raw transactions.
//!
//! Shared by `MockCardanoChain` and `BlockfrostCardanoChain` so both
//! can send signed BTC transactions directly to a regtest/testnet node.

use crate::epoch::state::{EpochError, EpochResult};

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
    eprintln!(
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
    eprintln!("[btc-rpc] broadcast accepted: txid = {txid}");
    Ok(())
}
