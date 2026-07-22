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

/// The latest block's `(slot, posix_time_secs)` from `/blocks/latest`. The slot anchors
/// tx validity bounds (`invalid_hereafter`); the time seeds the TM datum's `created` field
/// (the TM mint policy requires `created` within 1h of the tx's validity upper bound).
pub async fn fetch_latest_block_slot_time(
    base_url: &str,
    project_id: &str,
) -> Result<(u64, i64), String> {
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
    let slot = v
        .get("slot")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "blocks/latest: missing/non-numeric `slot`".to_string())?;
    let time = v
        .get("time")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| "blocks/latest: missing/non-numeric `time`".to_string())?;
    Ok((slot, time))
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
    // yaci-store serves no per-number /epochs/{n} route (404 "Epoch not
    // found") — only /epochs/latest. Fall back to it when the direct route
    // fails, but ONLY accept its start_time when it is for the requested
    // epoch: an epoch mismatch (turnover race) must stay an error, since a
    // wrong boundary time silently mis-evaluates ban expiry.
    let fetch = |path: String| async move {
        let resp = reqwest::Client::new()
            .get(format!("{base_url}/{path}"))
            .header("project_id", project_id)
            .send()
            .await
            .map_err(|e| format!("{path} request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "{path} http {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| format!("{path} json: {e}"))
    };
    let v = match fetch(format!("epochs/{epoch}")).await {
        Ok(v) => v,
        Err(direct_err) => {
            let latest = fetch("epochs/latest".to_string())
                .await
                .map_err(|e| format!("{direct_err}; epochs/latest fallback: {e}"))?;
            match latest.get("epoch").and_then(serde_json::Value::as_u64) {
                Some(e) if e == epoch => latest,
                other => {
                    return Err(format!(
                        "{direct_err}; epochs/latest is epoch {other:?}, want {epoch}"
                    ));
                }
            }
        }
    };
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
    /// 1-second post-Shelley slots, `posix_ms(slot) = block_time_ms + (slot -
    /// current_slot) * 1000`. ApplyBan uses `posix_ms(invalid_hereafter) - 1`
    /// because Plutus exposes finite upper bounds as exclusive.
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

/// Fetch the protocol's stake-key deposit (lovelace) from
/// `/epochs/latest/parameters`.
///
/// A stake registration locks this per certificate, refundable only by
/// deregistration, so `init-scripts` must know it to balance the transaction.
/// Blockfrost serves the amount as a string; yaci-store as a number — accept
/// both.
pub async fn fetch_key_deposit(base_url: &str, project_id: &str) -> Result<u64, String> {
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
    let d = v
        .get("key_deposit")
        .ok_or_else(|| "parameters: no key_deposit".to_string())?;
    d.as_u64()
        .or_else(|| d.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| format!("parameters: key_deposit not a number: {d}"))
}

/// Whether a reward account is currently registered, via `/accounts/{addr}`.
///
/// `Ok(Some(true|false))` is a definite answer; **`Ok(None)` means unknown** —
/// the backend does not serve this route (yaci-store implements only part of
/// the Blockfrost surface, as the `/epochs/{n}` and `/pools/{id}` workarounds
/// elsewhere in this module attest). A 404 is reported as `Some(false)`, since
/// that is how Blockfrost says "never registered"; callers must treat the
/// unknown case optimistically and let the ledger arbitrate, because
/// re-registering is rejected in phase 1 at no cost.
pub async fn fetch_account_registered(
    base_url: &str,
    project_id: &str,
    stake_address: &str,
) -> Result<Option<bool>, String> {
    let url = format!("{base_url}/accounts/{stake_address}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("account request: {e}"))?;
    if resp.status().as_u16() == 404 {
        return Ok(Some(false));
    }
    if !resp.status().is_success() {
        return Ok(None);
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("account json: {e}"))?;
    Ok(v.get("active").and_then(serde_json::Value::as_bool))
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
        let entry = raw
            .get(lang)
            .ok_or_else(|| format!("parameters: no cost_models[{lang}]"))?;
        let nums: Vec<i64> = if let Some(arr) = entry.as_array() {
            arr.iter()
                .map(|n| {
                    n.as_i64()
                        .ok_or_else(|| format!("cost_models[{lang}]: non-int entry"))
                })
                .collect::<Result<_, _>>()?
        } else if let Some(map) = entry.as_object() {
            // yaci-store serves ONLY the named-map form (no cost_models_raw).
            // The ledger's canonical array order for cost models is the
            // alphabetical order of the parameter names, so a key-sorted
            // flatten reproduces it — and any deviation is self-checking: a
            // wrong order breaks the script integrity hash and the chain
            // rejects the tx.
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            entries
                .into_iter()
                .map(|(k, n)| {
                    n.as_i64()
                        .ok_or_else(|| format!("cost_models[{lang}].{k}: non-int entry"))
                })
                .collect::<Result<_, _>>()?
        } else {
            return Err(format!(
                "parameters: cost_models[{lang}] is neither an array nor a map"
            ));
        };
        out.push(nums);
    }
    Ok(out)
}
