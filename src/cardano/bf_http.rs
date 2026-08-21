//! Minimal raw-HTTP fetch of a Blockfrost-compatible `/addresses/{addr}/utxos`, tolerant of
//! backends (e.g. yaci-devkit) whose response omits fields the `blockfrost` crate's typed
//! `AddressUtxo` requires (notably `tx_index`). Only the fields heimdall actually uses are parsed.

use serde::Deserialize;
use tracing::warn;

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

/// The Plutus V3 script bytes for `script_hash`, from `/scripts/{hash}/cbor`,
/// **verified against the hash that asked for them**.
///
/// This is what lets a script the node cannot compile be sourced from the chain
/// instead of pasted into a config file (WI-HJ1N5). The verification is not a
/// nicety, it is the entire safety argument: `script_hash_v3` digests
/// `0x03 || bytes`, so a matching digest proves both that these are the bytes
/// the bridge named AND that they are Plutus V3 — there is nothing left for a
/// provider to get wrong, and nothing an operator has to be trusted to type.
///
/// `Ok(None)` means the provider does not know the script — on a bridge whose
/// deployment published it as a reference script that means the wrong hash or
/// the wrong network, and it is distinguished from a transport failure because
/// only one of the two is repaired by editing a config file.
pub async fn fetch_script_cbor(
    base_url: &str,
    project_id: &str,
    script_hash: &str,
) -> Result<Option<String>, String> {
    let url = format!("{base_url}/scripts/{script_hash}/cbor");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("script cbor request: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!(
            "script cbor http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("script cbor json: {e}"))?;
    // Blockfrost answers `{"cbor": null}` for a native script, which has no
    // Plutus bytes at all — the same shape as a missing field, and neither is an
    // answer we can use.
    let cbor = v
        .get("cbor")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("script {script_hash}: no cbor in the provider's answer"))?
        .to_string();
    verified_script_cbor(script_hash, cbor).map(Some)
}

/// The safety property of [`fetch_script_cbor`], separated from the transport so
/// it can be tested without one: bytes are only ever returned when they hash
/// back to the identifier that asked for them.
fn verified_script_cbor(script_hash: &str, cbor: String) -> Result<String, String> {
    let bytes =
        hex::decode(&cbor).map_err(|e| format!("script {script_hash}: cbor is not hex: {e}"))?;
    let got = hex::encode(crate::cardano::blueprint::script_hash_v3(&bytes));
    if !got.eq_ignore_ascii_case(script_hash) {
        return Err(format!(
            "script {script_hash}: the provider returned {} bytes hashing to {got} — refusing \
             them. blake2b224(0x03 || cbor) must equal the hash they were fetched by",
            bytes.len()
        ));
    }
    Ok(cbor)
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
/// tx validity bounds (`invalid_hereafter`); the time derives the TM datum's `created` field
/// (the TM mint policy requires `created` to EQUAL the validity upper bound's POSIX ms).
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

/// The address that OWNED output `index` of `tx_hash`, from `/txs/{hash}/utxos`.
///
/// Used to find the wallet a bridge was deployed from (WI-091). The federation
/// one-shot is `<txid>:<ix>`, and the deploy transaction SPENT that outpoint —
/// so output `ix` of `txid` sat at the deployer's own address, which is also
/// where `deploy-script-refs` parks the shared reference scripts. There is no
/// by-script-hash location query, so this is how a node finds them without being
/// told an outpoint by a human.
pub async fn fetch_tx_output_address(
    base_url: &str,
    project_id: &str,
    tx_hash: &str,
    index: u32,
) -> Result<String, String> {
    let url = format!("{base_url}/txs/{tx_hash}/utxos");
    let v: serde_json::Value = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("txs/{tx_hash}/utxos request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("txs/{tx_hash}/utxos json: {e}"))?;
    let outputs = v
        .get("outputs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("txs/{tx_hash}/utxos: no `outputs` array"))?;
    // Match on the reported output_index rather than trusting array order: the
    // wrong output yields a well-formed address holding no reference script,
    // which reads as "nothing deployed" instead of as an error.
    outputs
        .iter()
        .find(|o| {
            o.get("output_index")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|i| i == u64::from(index))
        })
        .and_then(|o| o.get("address"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "txs/{tx_hash}/utxos: no output #{index} (tx has {})",
                outputs.len()
            )
        })
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

/// Where a transaction sits on the chain: its absolute slot when the backend
/// reports one, and its block time.
///
/// The slot is what the TM batch grid needs (spec §TM batches: membership is
/// "created at or before `C_i`", and `C_i` is a slot). Blockfrost reports `slot`
/// directly; a Blockfrost-compatible backend that omits it leaves `slot: None`
/// and the caller derives it with [`slot_at_time`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxPoint {
    pub slot: Option<u64>,
    pub block_time_secs: i64,
}

/// `/txs/{hash}` → the transaction's chain position.
pub async fn fetch_tx_point(
    base_url: &str,
    project_id: &str,
    tx_hash: &str,
) -> Result<TxPoint, String> {
    let url = format!("{base_url}/txs/{tx_hash}");
    // Bounded, unlike most of this module: `resolve_tx_slots` calls this once per
    // distinct creating transaction, SEQUENTIALLY, on the movement's critical
    // path, and nothing above it applies a timeout of its own. reqwest has no
    // default, so one half-open connection (a NAT timeout, a load-balancer black
    // hole) would hang `query_pegin_requests` — and with it the whole epoch loop —
    // producing no error for the back-off policy to see and no log line.
    let v: serde_json::Value = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("txs/{tx_hash} request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("txs/{tx_hash} json: {e}"))?;
    let block_time_secs = v
        .get("block_time")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| format!("txs/{tx_hash}: missing/non-numeric `block_time`"))?;
    Ok(TxPoint {
        slot: v.get("slot").and_then(serde_json::Value::as_u64),
        block_time_secs,
    })
}

/// The slot of a block at `block_time_ms`, derived from a known `(slot, time)`
/// pair on the same chain.
///
/// Post-Shelley slots are exactly one second, so this is an exact identity rather
/// than an estimate — which is what makes it safe for a consensus input: two SPOs
/// holding DIFFERENT reference pairs still derive the same slot for the same
/// block. Only used when the backend omits `slot` (yaci-devkit); Blockfrost
/// reports it and this is not consulted.
#[must_use]
pub fn slot_at_time(ref_slot: u64, ref_time_ms: i64, block_time_ms: i64) -> u64 {
    let delta_secs = (block_time_ms - ref_time_ms) / 1000;
    if delta_secs >= 0 {
        ref_slot.saturating_add(delta_secs as u64)
    } else {
        ref_slot.saturating_sub(delta_secs.unsigned_abs())
    }
}

/// Resolve the CREATION SLOT of each named transaction, one `/txs/{hash}` per
/// DISTINCT hash.
///
/// The shared half of batch membership: the creation slot is the chain fact both
/// the stability cutoff and the FIFO total order key off, for peg-outs (whose
/// datum `created` is requester-set and backdatable) and for peg-ins alike.
/// Several requests minted in one transaction cost one lookup, and batches are
/// hours apart, so this is a handful of reads per movement.
///
/// `tip` is a known `(slot, time_ms)` pair on the same chain, consulted only when
/// the backend omits `slot` (yaci-devkit).
///
/// # An unresolved hash is not safe in EITHER direction (WI-106)
///
/// A hash that cannot be resolved maps to `None`. This used to be documented as
/// the safe outcome — "a flaky lookup costs latency rather than a batch two SPOs
/// disagree about" — and that was wrong in a way worth recording, because it is
/// the natural sentence to write again. Batch membership is a CONSENSUS decision,
/// so a per-node HTTP outcome must not change it either way: node A resolving a
/// request that node B does not gives them different sets, different sighashes
/// and no aggregate, whether B's answer is "include" or "defer".
///
/// Deferring is in fact the worse of the two, because it looks like success. The
/// nodes that resolved nothing build a movement that omits the request, sign it,
/// and burn the batch opportunity on it. So: this function retries, and callers
/// MUST REFUSE to build a batch that still holds an unresolved request rather
/// than quietly building a smaller one (`machine::freeze_pegins`). Refusing is
/// self-healing — the epoch loop backs off, re-queries, and the transient clears.
///
/// `what` names the caller in the warnings.
pub async fn resolve_tx_slots(
    base_url: &str,
    project_id: &str,
    tx_hashes: impl IntoIterator<Item = String>,
    tip: Option<(u64, i64)>,
    what: &str,
) -> std::collections::HashMap<String, Option<u64>> {
    let mut seen: std::collections::HashMap<String, Option<u64>> = std::collections::HashMap::new();
    for tx_hash in tx_hashes {
        if seen.contains_key(&tx_hash) {
            continue;
        }
        let resolved = resolve_one(base_url, project_id, &tx_hash, tip, what).await;
        seen.insert(tx_hash, resolved);
    }
    seen
}

/// One hash, with a bounded retry.
///
/// A 429 or a 502 from a shared endpoint is the common failure and clears in
/// milliseconds; it is not worth refusing a whole batch over. The attempts are
/// few and the pause short because the caller sits on the movement's critical
/// path — a failure that survives them is handed back for the epoch loop's own
/// back-off, which re-queries everything from scratch.
async fn resolve_one(
    base_url: &str,
    project_id: &str,
    tx_hash: &str,
    tip: Option<(u64, i64)>,
    what: &str,
) -> Option<u64> {
    const ATTEMPTS: u32 = 3;
    const PAUSE: std::time::Duration = std::time::Duration::from_millis(200);

    for attempt in 1..=ATTEMPTS {
        match fetch_tx_point(base_url, project_id, tx_hash).await {
            Ok(point) => {
                let slot = point.slot.or_else(|| {
                    tip.map(|(ref_slot, ref_time_ms)| {
                        slot_at_time(
                            ref_slot,
                            ref_time_ms,
                            point.block_time_secs.saturating_mul(1000),
                        )
                    })
                });
                // The other way to end up unresolved, and retrying cannot help it:
                // the backend omits `slot` (yaci-devkit) AND the caller's tip read
                // failed, so there is nothing to derive one from. The lookup itself
                // succeeded, so answer now rather than spending the attempts.
                if slot.is_none() {
                    tracing::warn!(
                        "[{what}] {tx_hash} has no `slot` and no chain tip to derive one from. \
                         The tip read failed; without it this backend cannot place any request \
                         in a batch, so no batch will be built."
                    );
                }
                return slot;
            }
            Err(e) if attempt < ATTEMPTS => {
                tracing::debug!(
                    "[{what}] creation slot of {tx_hash} unresolved ({e}), \
                     attempt {attempt}/{ATTEMPTS} — retrying"
                );
                tokio::time::sleep(PAUSE).await;
            }
            Err(e) => {
                tracing::warn!(
                    "[{what}] could not resolve the creation slot of {tx_hash} after {ATTEMPTS} \
                     attempts ({e}). No batch will be built at this opportunity: a request one \
                     node can place and another cannot is what breaks a FROST round, so this \
                     node refuses rather than building a set its peers would not."
                );
            }
        }
    }
    None
}

/// Return whether a Cardano transaction is included in the indexed chain.
/// Blockfrost returns 404 while a submitted transaction is still pending (or
/// has expired from the mempool), so callers can distinguish pending from an
/// HTTP/API failure.
pub async fn fetch_tx_inclusion(
    base_url: &str,
    project_id: &str,
    tx_hash: &str,
) -> Result<Option<i64>, String> {
    let url = format!("{base_url}/txs/{tx_hash}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("txs/{tx_hash} request: {e}"))?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!(
            "txs/{tx_hash} http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("txs/{tx_hash} json: {e}"))?;
    let block_time = v
        .get("block_time")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| format!("txs/{tx_hash}: missing/non-numeric `block_time`"))?;
    Ok(Some(block_time))
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
/// both, and accept the camelCase key too, in the spirit of this module's other
/// yaci-store accommodations.
///
/// Falls back to the protocol-standard 2 ADA when the field is absent entirely,
/// rather than failing the run: a wrong deposit unbalances the tx and the node
/// rejects it loudly, whereas a hard error here blocks a devnet whose parameters
/// endpoint is merely incomplete. `--key-deposit` overrides.
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
    let Some(d) = v.get("key_deposit").or_else(|| v.get("keyDeposit")) else {
        warn!(
            "/epochs/latest/parameters carries no key_deposit — \
             assuming the protocol-standard {DEFAULT_KEY_DEPOSIT} lovelace \
             (override with --key-deposit)"
        );
        return Ok(DEFAULT_KEY_DEPOSIT);
    };
    d.as_u64()
        .or_else(|| d.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| format!("parameters: key_deposit not a number: {d}"))
}

/// The protocol-standard stake-key deposit, used only when the parameters
/// endpoint omits the field.
pub const DEFAULT_KEY_DEPOSIT: u64 = 2_000_000;

/// Registration state of a reward account, as far as the backend can tell us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    Registered,
    NotRegistered,
    /// No usable answer. Carries the HTTP status so the operator can see *why*
    /// rather than guessing between an unimplemented route and an outage.
    Unknown {
        http_status: u16,
    },
}

/// Registration state of a reward account, via `/accounts/{addr}`.
///
/// Only a 200 carrying `active` is treated as an answer. **A 404 is
/// deliberately `Unknown`, not `NotRegistered`**: Blockfrost 404s an account it
/// has never seen, but a backend that does not implement the route 404s
/// identically (yaci-store serves only part of the Blockfrost surface — see the
/// `/epochs/{n}` and named-map `cost_models` workarounds elsewhere in this
/// module). Reporting "not registered" off an unimplemented route would state a
/// falsehood about the chain, so the ambiguity is surfaced instead.
///
/// This costs nothing in practice: callers treat `Unknown` optimistically and
/// let the ledger arbitrate, since re-registering is rejected in phase 1 at no
/// cost, and the positive case — which is what post-registration assertions
/// check — stays exact.
pub async fn fetch_account_registered(
    base_url: &str,
    project_id: &str,
    stake_address: &str,
) -> Result<RegistrationState, String> {
    let url = format!("{base_url}/accounts/{stake_address}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("account request: {e}"))?;
    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        return Ok(RegistrationState::Unknown {
            http_status: status,
        });
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("account json: {e}"))?;
    match v.get("active").and_then(serde_json::Value::as_bool) {
        Some(true) => Ok(RegistrationState::Registered),
        Some(false) => Ok(RegistrationState::NotRegistered),
        // 200 without `active` — a backend serving a different schema.
        None => Ok(RegistrationState::Unknown {
            http_status: status,
        }),
    }
}

/// Cardano's `max_tx_size` **for a named epoch** — the bound the TM batch byte
/// budget is measured against (WI-107, spec §TM batches rev 5.6).
///
/// Named, not `latest`, and the difference is the point. Protocol-parameter
/// changes take effect only at epoch boundaries, so the value for a given epoch
/// is a chain fact every SPO derives identically; two SPOs reading `latest`
/// either side of a boundary would get two budgets, freeze two different batches
/// and produce no signature at all — the FROST binding factors commit to the
/// signing package, so a membership disagreement is not a bad signature but the
/// absence of one.
///
/// Same direct-then-fallback shape as [`fetch_epoch_start_ms`], and for the same
/// reason: yaci-store serves no per-number `/epochs/{n}/parameters` route, and a
/// `latest` that turns out to be a different epoch stays an error rather than
/// silently answering for the wrong one.
pub async fn fetch_max_tx_size(
    base_url: &str,
    project_id: &str,
    epoch: u64,
) -> Result<u64, String> {
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
    let v = match fetch(format!("epochs/{epoch}/parameters")).await {
        Ok(v) => v,
        Err(direct_err) => {
            let latest = fetch("epochs/latest/parameters".to_string())
                .await
                .map_err(|e| format!("{direct_err}; epochs/latest/parameters fallback: {e}"))?;
            match latest.get("epoch").and_then(serde_json::Value::as_u64) {
                Some(e) if e == epoch => latest,
                other => {
                    return Err(format!(
                        "{direct_err}; epochs/latest/parameters is epoch {other:?}, want {epoch}"
                    ));
                }
            }
        }
    };
    // Blockfrost spells it `max_tx_size`; some yaci-store builds echo the ledger's
    // `maxTxSize`. Accept either rather than fail on a spelling.
    let n = v
        .get("max_tx_size")
        .or_else(|| v.get("maxTxSize"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("epochs/{epoch}/parameters: missing/non-numeric `max_tx_size`"))?;
    // A zero or absurd value would silently empty every batch (or overflow one).
    // The floor is well under any real network's; the ceiling is 1 MB.
    if !(1_024..=1_048_576).contains(&n) {
        return Err(format!(
            "epochs/{epoch}/parameters: max_tx_size {n} is outside any plausible range — \
             refusing to size TM batches against it"
        ));
    }
    Ok(n)
}

/// Fetch the network's live Plutus cost models (ordered int arrays) from
/// `/epochs/latest/parameters`, returned as `[PlutusV1, PlutusV2, PlutusV3]`.
///
/// whisky-common's hardcoded per-network cost models go stale (e.g. preprod's PlutusV3 grew
/// from 298 to 350 params), which makes the tx's script-integrity hash mismatch the ledger's
/// (`PPViewHashesDontMatch`). Passing these live arrays via `Network::Custom` fixes that.
///
/// The three slots are POSITIONS, not requirements: a chain that publishes no V1/V2
/// model gets an empty array in that slot, because whisky indexes this list by
/// language and heimdall's transactions are PlutusV3 only. See the loop.
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
        // A chain need not publish a cost model for every language, and heimdall
        // does not need every language: it builds PlutusV3 transactions only, and
        // the script-integrity hash covers just the language views of the
        // languages a transaction actually uses. So a missing V1/V2 becomes an
        // empty SPACER rather than a refusal.
        //
        // The spacer is the point. whisky takes these positionally —
        // `Network::Custom(v)` is indexed `v[0]=V1, v[1]=V2, v[2]=V3` — and its
        // evaluator rejects a list shorter than 3 outright. Dropping a missing
        // language instead of holding its slot would slide V3 down to index 1,
        // hash the wrong model into the script-integrity hash, and the chain
        // would answer PPViewHashesDontMatch with nothing pointing here.
        //
        // PlutusV3 is not optional: heimdall's transactions carry V3 scripts, so
        // its model does reach the hash and a placeholder would be a wrong one.
        let Some(entry) = raw.get(lang) else {
            if lang == "PlutusV3" {
                return Err(format!(
                    "parameters: no cost_models[{lang}] — heimdall's scripts are PlutusV3, so \
                     this chain cannot execute them"
                ));
            }
            out.push(Vec::new());
            continue;
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A Plutus script the node cannot compile is only usable if the bytes can be
    /// checked, and the check is the whole reason `cardano.tm_script_cbor` could
    /// be deleted rather than merely validated (WI-HJ1N5). `script_hash_v3`
    /// digests `0x03 || bytes`, so a matching digest proves the bytes AND the
    /// language version at once — there is nothing left for a provider to get
    /// wrong and nothing an operator has to be trusted to paste.
    #[test]
    fn script_bytes_are_only_accepted_under_the_hash_that_asked_for_them() {
        let bytes = [0x59u8, 0x01, 0x02, 0xde, 0xad, 0xbe, 0xef];
        let hash = hex::encode(crate::cardano::blueprint::script_hash_v3(&bytes));
        let cbor = hex::encode(bytes);

        assert_eq!(
            verified_script_cbor(&hash, cbor.clone()).unwrap(),
            cbor,
            "the bytes that hash to the identifier are the ones to use"
        );

        // One flipped byte is a different script — and it is the case that
        // matters, because a wrong-but-well-formed validator mints under a policy
        // nothing on this bridge scans, discovered only after a ceremony is spent.
        let mut tampered = bytes;
        tampered[4] ^= 0x01;
        let err = verified_script_cbor(&hash, hex::encode(tampered))
            .expect_err("bytes that hash elsewhere must be refused");
        assert!(err.contains(&hash), "{err}");

        // The hash cannot vouch for something that is not bytes at all.
        assert!(
            verified_script_cbor(&hash, "not hex".into()).is_err(),
            "unparseable cbor must be refused, not hashed"
        );

        // Upper-case is the same identifier: Blockfrost and the Config datum
        // render hex differently, and refusing on case alone would read to an
        // operator exactly like a wrong bridge.
        assert!(verified_script_cbor(&hash.to_uppercase(), cbor).is_ok());
    }
}
