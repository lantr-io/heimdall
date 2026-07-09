//! Minimal raw-HTTP fetch of a Blockfrost-compatible `/addresses/{addr}/utxos`, tolerant of
//! backends (e.g. yaci-devkit) whose response omits fields the `blockfrost` crate's typed
//! `AddressUtxo` requires (notably `tx_index`). Only the fields heimdall actually uses are parsed.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BfAmount {
    pub unit: String,
    pub quantity: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BfUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub amount: Vec<BfAmount>,
    #[serde(default)]
    pub inline_datum: Option<String>,
    /// Hash of a reference script attached to the UTxO. Spending such a UTxO
    /// incurs the Conway per-byte ref-script fee, which generic fee
    /// estimation cannot see — coin selection must avoid these.
    #[serde(default)]
    pub reference_script_hash: Option<String>,
}

/// Resolve the Blockfrost base URL: explicit `custom` (e.g. yaci's http://localhost:8080/api/v1),
/// else the public blockfrost.io URL implied by the project-id prefix.
pub fn base_url(project_id: &str, custom: Option<&str>) -> String {
    if let Some(u) = custom {
        return u.trim_end_matches('/').to_string();
    }
    if project_id.starts_with("mainnet") {
        "https://cardano-mainnet.blockfrost.io/api/v0".into()
    } else if project_id.starts_with("preview") {
        "https://cardano-preview.blockfrost.io/api/v0".into()
    } else {
        "https://cardano-preprod.blockfrost.io/api/v0".into()
    }
}

/// Fetch all UTxOs at `address` (paginated), leniently parsed.
pub async fn fetch_address_utxos(
    base_url: &str,
    project_id: &str,
    address: &str,
) -> Result<Vec<BfUtxo>, String> {
    let client = reqwest::Client::new();
    let mut all = Vec::new();
    let mut page = 1usize;
    loop {
        let url = format!("{base_url}/addresses/{address}/utxos?page={page}&count=100&order=asc");
        let resp = client
            .get(&url)
            .header("project_id", project_id)
            .send()
            .await
            .map_err(|e| format!("utxos request: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            break; // no UTxOs at this address
        }
        if !status.is_success() {
            return Err(format!(
                "utxos http {}: {}",
                status,
                resp.text().await.unwrap_or_default()
            ));
        }
        let batch: Vec<BfUtxo> = resp.json().await.map_err(|e| format!("utxos json: {e}"))?;
        let n = batch.len();
        all.extend(batch);
        if n < 100 {
            break;
        }
        page += 1;
    }
    Ok(all)
}

/// `serialised_size` (bytes) of an on-chain script, from `/scripts/{hash}` —
/// the input to the Conway ref-script fee when a ref-script UTxO must be spent.
pub async fn fetch_script_size(
    base_url: &str,
    project_id: &str,
    script_hash: &str,
) -> Result<u64, String> {
    let url = format!("{base_url}/scripts/{script_hash}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("script request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "script http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("script json: {e}"))?;
    v.get("serialised_size")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "script: missing serialised_size".to_string())
}

/// Current epoch number from `/epochs/latest`. Roster snapshots and ban
/// activity are epoch-scoped, so callers must use the chain's epoch, never a
/// local clock.
pub async fn fetch_current_epoch(base_url: &str, project_id: &str) -> Result<u64, String> {
    let url = format!("{base_url}/epochs/latest");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("epochs/latest request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "epochs/latest http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("epochs/latest json: {e}"))?;
    v.get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "epochs/latest: missing/non-numeric `epoch`".to_string())
}

/// Chain "now" — the latest block's POSIX time (seconds), from `/blocks/latest`.
/// Used as the reference clock for the in-flight staleness deadline (chain time,
/// never a local node clock).
pub async fn fetch_latest_block_time(base_url: &str, project_id: &str) -> Result<i64, String> {
    let url = format!("{base_url}/blocks/latest");
    let v: serde_json::Value = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("blocks/latest request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("blocks/latest json: {e}"))?;
    v.get("time")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| "blocks/latest: missing/non-numeric `time`".to_string())
}

/// The POSIX block-time (seconds) of the Cardano tx `tx_hash`, from `/txs/{hash}`.
/// The age of an Unconfirmed TM UTxO = chain-now − this.
pub async fn fetch_tx_block_time(
    base_url: &str,
    project_id: &str,
    tx_hash: &str,
) -> Result<i64, String> {
    let url = format!("{base_url}/txs/{tx_hash}");
    let v: serde_json::Value = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("txs/{tx_hash} request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("txs/{tx_hash} json: {e}"))?;
    v.get("block_time")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| format!("txs/{tx_hash}: missing/non-numeric `block_time`"))
}

/// POSIX start time (ms) of `epoch`, from `/epochs/{epoch}`. This is the
/// epoch-boundary time the eligible-roster ban check compares against — using a
/// chain-derived boundary (not a node clock) so every SPO derives the same
/// roster even when a ban's `ban_until_time` is expiring around the boundary.
pub async fn fetch_epoch_start_ms(
    base_url: &str,
    project_id: &str,
    epoch: u64,
) -> Result<i64, String> {
    let url = format!("{base_url}/epochs/{epoch}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("epochs/{epoch} request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "epochs/{epoch} http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("epochs/{epoch} json: {e}"))?;
    let secs = v
        .get("start_time")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| format!("epochs/{epoch}: missing/non-numeric `start_time`"))?;
    // Blockfrost `start_time` is Unix SECONDS. Reject values outside a sane
    // window (~2001..2286): a negative/zero, or an already-milliseconds value
    // (~1.7e12), would otherwise yield a wrong boundary time that silently marks
    // every temporary ban expired — re-admitting banned pools to the roster.
    if !(1_000_000_000..10_000_000_000).contains(&secs) {
        return Err(format!(
            "epochs/{epoch}: implausible start_time {secs} (want Unix seconds)"
        ));
    }
    Ok(secs * 1000)
}

/// The current slot and the upper validity bound at the epoch boundary, for
/// the register_spo validity window (`invalid_before` / `invalid_hereafter`).
#[derive(Debug, Clone, Copy)]
pub struct EpochWindow {
    pub current_slot: u64,
    /// One slot BEFORE the next epoch boundary (`current_slot + (epoch
    /// end_time − block time) − 1`; 1 slot = 1 second post-Shelley). The
    /// boundary slot itself sits at the ledger's time-translation horizon —
    /// a Plutus tx with `invalid_hereafter` exactly there is rejected with
    /// `TimeTranslationPastHorizon` when the script context is built.
    pub epoch_end_slot: u64,
    /// POSIX time (ms) of `current_slot` (the latest block's wall time). With
    /// 1-second post-Shelley slots, `posix_ms(slot) = block_time_ms + (slot −
    /// current_slot) * 1000` — used to derive an ApplyBan validity interval's
    /// POSIX upper bound (the `start_time` the `spo_bans` validator resolves).
    pub block_time_ms: i64,
}

/// Fetch the epoch-boundary window from `/blocks/latest` (slot + wall time)
/// and `/epochs/latest` (end time). A tx with `invalid_hereafter =
/// epoch_end_slot` cannot land in a later epoch than the one it was built in.
pub async fn fetch_epoch_window(base_url: &str, project_id: &str) -> Result<EpochWindow, String> {
    let client = reqwest::Client::new();
    let get = |path: &str| {
        let url = format!("{base_url}/{path}");
        let client = client.clone();
        let project_id = project_id.to_string();
        async move {
            let resp = client
                .get(&url)
                .header("project_id", project_id)
                .send()
                .await
                .map_err(|e| format!("{url}: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!(
                    "{url}: http {}: {}",
                    resp.status(),
                    resp.text().await.unwrap_or_default()
                ));
            }
            resp.json::<serde_json::Value>()
                .await
                .map_err(|e| format!("{url}: json: {e}"))
        }
    };
    let block = get("blocks/latest").await?;
    let epoch = get("epochs/latest").await?;
    let field = |v: &serde_json::Value, name: &str, what: &str| -> Result<u64, String> {
        v.get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("{what}: missing/non-numeric `{name}`"))
    };
    let current_slot = field(&block, "slot", "blocks/latest")?;
    let block_time = field(&block, "time", "blocks/latest")?;
    let end_time = field(&epoch, "end_time", "epochs/latest")?;
    let remaining = end_time.saturating_sub(block_time);
    Ok(EpochWindow {
        current_slot,
        epoch_end_slot: (current_slot + remaining).saturating_sub(1),
        block_time_ms: (block_time as i64) * 1000,
    })
}

/// Fetch the network's live Plutus cost models (ordered int arrays) from
/// `/epochs/latest/parameters`, returned as `[PlutusV1, PlutusV2, PlutusV3]`.
///
/// whisky-common's hardcoded per-network cost models go stale (e.g. preprod's PlutusV3 grew
/// from 298 to 350 params), which makes the tx's script-integrity hash mismatch the ledger's
/// (`PPViewHashesDontMatch`). Passing these live arrays via `Network::Custom` fixes that.
pub async fn fetch_cost_models(base_url: &str, project_id: &str) -> Result<Vec<Vec<i64>>, String> {
    let url = format!("{base_url}/epochs/latest/parameters");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("parameters request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "parameters http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parameters json: {e}"))?;
    // `cost_models_raw` gives each language as an ordered array of ints (the canonical order the
    // ledger hashes); `cost_models` is the named-map form. Prefer the raw arrays.
    let raw = v
        .get("cost_models_raw")
        .or_else(|| v.get("cost_models"))
        .ok_or_else(|| "parameters: no cost_models_raw/cost_models".to_string())?;
    let mut out = Vec::with_capacity(3);
    for lang in ["PlutusV1", "PlutusV2", "PlutusV3"] {
        let arr = raw
            .get(lang)
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("parameters: cost_models[{lang}] not an array"))?;
        let nums: Vec<i64> = arr
            .iter()
            .map(|n| {
                n.as_i64()
                    .ok_or_else(|| format!("cost_models[{lang}]: non-int entry"))
            })
            .collect::<Result<_, _>>()?;
        out.push(nums);
    }
    Ok(out)
}
