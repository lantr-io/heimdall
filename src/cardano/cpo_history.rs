//! The chain-history FETCH layer behind completed-peg-outs trie reconstruction.
//!
//! ## Why this module exists
//!
//! [`crate::cardano::cpo_trie::reconstruct`] rebuilds the trie from Cardano
//! history alone. The algorithm it runs — chain-order the Confirmed Treasury
//! Movements, try every published data-availability hint, fall back to matching
//! payments against peg-out requests, assert the running root after every
//! movement, cross-check the finished trie against the on-chain CPO singleton —
//! is the security-critical part, and it is IDENTICAL whatever serves the bytes.
//!
//! Only the reads differ. This module is that seam: one trait,
//! [`CpoHistorySource`], with two implementations.
//!
//! | | [`KupoHistory`] | [`BlockfrostHistory`] |
//! |---|---|---|
//! | reads | `GET /matches/{pattern}`, `GET /datums/{hash}` | `GET /addresses/{addr}/transactions`, `GET /txs/{hash}/utxos`, `GET /scripts/datum/{hash}` |
//! | requests for an address with *T* transactions and *D* hash-only datums | 1 + *D* | ⌈*T*/100⌉ + *T* + *D* |
//! | production status | **recommended for SPOs** | tests, demos, non-SPO tooling |
//!
//! ## Which one to run
//!
//! A production SPO SHOULD run Kupo. Reconstruction then costs a handful of
//! requests regardless of history length, and Kupo is a self-hosted index — the
//! infrastructure rule in the spec (§Infrastructure assumptions) is that no
//! consensus-relevant read may depend on a centralized query service.
//!
//! The Blockfrost path exists because requiring Kupo makes a test environment, a
//! demo, or a read-only tool need a second indexer for one rare command. It is
//! deliberately heavier: it walks the address's whole transaction history and
//! fetches every transaction's outputs, so it issues roughly one request per
//! transaction that ever touched the address.
//!
//! ## What both backends must guarantee
//!
//! The algorithm's invariants depend on the fetch layer answering honestly:
//!
//! - [`CpoHistorySource::address_history`] MUST return EVERY output ever created
//!   at the address, spent ones included. A Confirm transition spends the
//!   `Unconfirmed` record, and that spent record is where the hint lives.
//! - A datum the backend cannot resolve MUST come back as `datum: None`, never as
//!   a silently dropped output. `reconstruct` turns a missing datum at the TM
//!   address into a hard error, and it can only do that if it sees the output.
//! - Asset quantities MUST be keyed by the Blockfrost UNIT form
//!   (`<policy_hex><asset_name_hex>`), so the algorithm's asset lookups are
//!   backend-independent. [`KupoHistory`] converts Kupo's dotted keys.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use async_trait::async_trait;
use pallas_primitives::PlutusData;
use serde::Deserialize;

use crate::cardano::bf_http;
use crate::cardano::kupo::{KupoClient, KupoMatch, MatchFilter};
use crate::cardano::retry;

// ---------------------------------------------------------------------------
// The backend-independent output shape
// ---------------------------------------------------------------------------

/// One transaction output as chain history remembers it — spent or unspent —
/// with its datum already resolved.
///
/// This is the ONLY shape the reconstruction algorithm sees, so nothing in it may
/// be backend-flavoured: asset keys are normalized to the Blockfrost unit form and
/// the datum is decoded `PlutusData` rather than either backend's wire encoding.
#[derive(Debug, Clone)]
pub struct HistoricalOutput {
    /// Cardano transaction hash, lowercase hex.
    pub tx_hash: String,
    pub output_index: u32,
    /// Native assets, keyed `<policy_hex><asset_name_hex>` (lowercase) — the
    /// Blockfrost `unit`. Lovelace is not included; no caller needs it.
    pub assets: BTreeMap<String, u64>,
    /// `None` when the output carries no datum at all, AND when the backend
    /// cannot supply the preimage of a datum hash it knows. The two are
    /// distinguished by [`Self::datum_note`], never by dropping the output.
    pub datum: Option<PlutusData>,
    /// What the backend reported about the datum, verbatim enough to diagnose a
    /// gap ("no datum", "inline", "hash=… (unresolved)"). Only ever used to build
    /// an error message.
    pub datum_note: String,
}

impl HistoricalOutput {
    /// Quantity of `policy_hex` / `asset_name_hex` held by this output.
    #[must_use]
    pub fn asset_quantity(&self, policy_hex: &str, asset_name_hex: &str) -> u64 {
        let unit = format!(
            "{}{}",
            policy_hex.to_ascii_lowercase(),
            asset_name_hex.to_ascii_lowercase()
        );
        self.assets.get(&unit).copied().unwrap_or(0)
    }
}

/// Decode datum CBOR into `PlutusData`.
///
/// Bytes that are present but do not decode are an ERROR, not a `None`: the
/// backend told us there is a datum, so treating it as absent would let a
/// malformed TM record pass as "no datum here".
fn decode_datum(bytes: &[u8], at: &str) -> Result<PlutusData, String> {
    pallas_codec::minicbor::decode(bytes).map_err(|e| format!("datum cbor ({at}): {e}"))
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// The reads [`crate::cardano::cpo_trie::reconstruct`] needs from a chain index.
///
/// Implementations are pure fetch: no filtering, no interpretation, no skipping.
/// Every judgement about what an output MEANS belongs to the algorithm, which is
/// why it stays identical across backends.
#[async_trait]
pub trait CpoHistorySource: Send + Sync {
    /// Short backend name for the log line: `"kupo"` or `"blockfrost"`.
    fn backend(&self) -> &'static str;

    /// The base URL this backend reads, for the log line.
    fn endpoint(&self) -> &str;

    /// Backend-specific remediation for an output whose datum could not be
    /// resolved. Reconstruction hard-errors on such an output at the TM address,
    /// and a generic message would leave the operator guessing which knob to
    /// turn.
    fn datum_gap_advice(&self) -> &'static str;

    /// EVERY output ever created at `address`, spent ones INCLUDED, with datums
    /// resolved.
    ///
    /// Order is unspecified: the algorithm sorts the TM records by treasury
    /// linkage and indexes the peg-out requests by outpoint, so neither depends
    /// on the backend's ordering.
    async fn address_history(&self, address: &str) -> Result<Vec<HistoricalOutput>, String>;

    /// Every UNSPENT output holding at least one unit of
    /// `policy_hex`.`asset_name_hex`, with datums resolved.
    ///
    /// Used only to locate the on-chain completed-peg-outs singleton. The caller
    /// enforces the singleton rule (exactly one output holding quantity 1); this
    /// method just reports what the index has.
    async fn unspent_with_asset(
        &self,
        policy_hex: &str,
        asset_name_hex: &str,
    ) -> Result<Vec<HistoricalOutput>, String>;
}

// ---------------------------------------------------------------------------
// Kupo backend
// ---------------------------------------------------------------------------

/// The production backend: a Kupo index of the bridge script addresses.
///
/// One `/matches` request answers a whole address history, so reconstruction cost
/// is independent of how long the bridge has been running.
pub struct KupoHistory {
    client: KupoClient,
}

impl KupoHistory {
    /// `base_url` is the Kupo root, e.g. `http://localhost:1442`.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        Self {
            client: KupoClient::new(base_url),
        }
    }

    /// Convert one match, resolving its datum.
    async fn convert(&self, m: &KupoMatch) -> Result<HistoricalOutput, String> {
        let datum = self.client.resolve_datum(m).await?;
        let datum_note = match (&datum, &m.datum_hash) {
            (Some(_), _) => format!(
                "resolved, datum_type={}",
                m.datum_type.as_deref().unwrap_or("<none>")
            ),
            (None, Some(h)) => format!(
                "datum_hash={h}, datum_type={} — Kupo has no preimage",
                m.datum_type.as_deref().unwrap_or("<none>")
            ),
            (None, None) => "no datum".to_string(),
        };
        Ok(HistoricalOutput {
            tx_hash: m.transaction_id.to_ascii_lowercase(),
            output_index: m.output_index,
            assets: kupo_assets(m),
            datum,
            datum_note,
        })
    }

    async fn convert_all(&self, matches: &[KupoMatch]) -> Result<Vec<HistoricalOutput>, String> {
        let mut out = Vec::with_capacity(matches.len());
        for m in matches {
            out.push(self.convert(m).await?);
        }
        Ok(out)
    }
}

/// Kupo keys assets `"<policy>.<name>"`, and omits the dot for an empty asset
/// name. Both spellings normalize to the Blockfrost unit `"<policy><name>"`.
fn kupo_assets(m: &KupoMatch) -> BTreeMap<String, u64> {
    m.value
        .assets
        .iter()
        .map(|(k, v)| (k.replacen('.', "", 1).to_ascii_lowercase(), *v))
        .collect()
}

/// Kupo's asset pattern for an NFT. An empty asset name has no dot.
fn kupo_asset_pattern(policy_hex: &str, asset_name_hex: &str) -> String {
    let policy = policy_hex.trim().to_ascii_lowercase();
    let name = asset_name_hex.trim().to_ascii_lowercase();
    if name.is_empty() {
        policy
    } else {
        format!("{policy}.{name}")
    }
}

#[async_trait]
impl CpoHistorySource for KupoHistory {
    fn backend(&self) -> &'static str {
        "kupo"
    }

    fn endpoint(&self) -> &str {
        self.client.base_url()
    }

    fn datum_gap_advice(&self) -> &'static str {
        "Re-index Kupo over the full history (no --prune-utxo) and retry."
    }

    async fn address_history(&self, address: &str) -> Result<Vec<HistoricalOutput>, String> {
        let matches = self.client.matches(address, MatchFilter::All).await?;
        self.convert_all(&matches).await
    }

    async fn unspent_with_asset(
        &self,
        policy_hex: &str,
        asset_name_hex: &str,
    ) -> Result<Vec<HistoricalOutput>, String> {
        let pattern = kupo_asset_pattern(policy_hex, asset_name_hex);
        let matches = self.client.matches(&pattern, MatchFilter::Unspent).await?;
        // Datums are resolved for every match, not just the one the caller picks.
        // An exact asset pattern returns a singleton (or a handful when the NFT is
        // not unique, which is itself an error the caller reports), so the extra
        // lookups are bounded and the code stays a plain fetch.
        self.convert_all(&matches).await
    }
}

// ---------------------------------------------------------------------------
// Blockfrost backend
// ---------------------------------------------------------------------------

/// How many items per page. 100 is the Blockfrost maximum.
const PAGE: usize = 100;

/// The Kupo-free backend: a plain Blockfrost-compatible API.
///
/// **Not the recommended production configuration.** It reconstructs the same
/// trie with the same checks, but it must WALK history rather than query it:
/// `GET /addresses/{addr}/transactions` gives every transaction that touched the
/// address, and each one costs a `GET /txs/{hash}/utxos` to learn which outputs it
/// created there. Budget roughly one request per transaction.
///
/// It exists so a test environment, a demo, or a non-SPO tool can rebuild the trie
/// with the API it already has.
pub struct BlockfrostHistory {
    base_url: String,
    project_id: String,
    /// One client for the whole run. Reconstruction issues one request per
    /// transaction, and a per-request client would open a socket for each.
    client: reqwest::Client,
}

/// One attempt's failure, classified so the retry wrapper can tell a blip from a
/// definite answer.
#[derive(Debug)]
enum Fail {
    /// Network error, 429, or 5xx — worth retrying.
    Transient(String),
    /// A 4xx other than 429, or a body that does not parse. Retrying repeats it.
    Permanent(String),
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient(m) | Self::Permanent(m) => write!(f, "{m}"),
        }
    }
}

impl From<Fail> for String {
    fn from(f: Fail) -> Self {
        f.to_string()
    }
}

/// One transaction output, as `GET /txs/{hash}/utxos` reports it.
///
/// Lenient in the same spirit as `bf_http::BfUtxo`: only the fields heimdall reads
/// are declared, and `output_index` is optional because some Blockfrost-compatible
/// backends omit index fields (`bf_http` already works around a missing
/// `tx_index`).
#[derive(Debug, Clone, Deserialize)]
struct BfTxOutput {
    #[serde(default)]
    address: String,
    #[serde(default)]
    amount: Vec<bf_http::BfAmount>,
    #[serde(default)]
    output_index: Option<u32>,
    #[serde(default)]
    inline_datum: Option<String>,
    #[serde(default)]
    data_hash: Option<String>,
}

/// `GET /txs/{hash}/utxos`.
#[derive(Debug, Clone, Deserialize)]
struct BfTxUtxos {
    #[serde(default)]
    outputs: Vec<BfTxOutput>,
}

/// One UTxO, as `GET /addresses/{addr}/utxos/{unit}` reports it.
#[derive(Debug, Clone, Deserialize)]
struct BfAssetUtxo {
    tx_hash: String,
    #[serde(default)]
    output_index: u32,
    #[serde(default)]
    amount: Vec<bf_http::BfAmount>,
    #[serde(default)]
    inline_datum: Option<String>,
    #[serde(default)]
    data_hash: Option<String>,
}

impl BlockfrostHistory {
    /// `project_id` is the Blockfrost API key; `custom_url` overrides the network
    /// URL implied by its prefix (e.g. a Dolos or yaci-devkit base URL).
    #[must_use]
    pub fn new(project_id: &str, custom_url: Option<&str>) -> Self {
        Self {
            base_url: bf_http::base_url(project_id, custom_url),
            project_id: project_id.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// `GET {base_url}/{path}`, retried through transient failures.
    ///
    /// `Ok(None)` on 404 — every route here 404s for "nothing there" (an address
    /// with no history, an asset nobody holds, a datum the backend never saw), and
    /// that is a normal answer, not an error.
    async fn get_json(&self, path: &str) -> Result<Option<serde_json::Value>, String> {
        let url = format!("{}/{path}", self.base_url);
        let attempt = || async {
            let resp = self
                .client
                .get(&url)
                .header("project_id", &self.project_id)
                .send()
                .await
                .map_err(|e| Fail::Transient(format!("{path}: {e}")))?;
            let status = resp.status();
            if status.as_u16() == 404 {
                return Ok(None);
            }
            if status.as_u16() == 429 || status.is_server_error() {
                return Err(Fail::Transient(format!(
                    "{path} http {status}: {}",
                    resp.text().await.unwrap_or_default()
                )));
            }
            if !status.is_success() {
                return Err(Fail::Permanent(format!(
                    "{path} http {status}: {}",
                    resp.text().await.unwrap_or_default()
                )));
            }
            resp.json::<serde_json::Value>()
                .await
                .map(Some)
                .map_err(|e| Fail::Permanent(format!("{path} json: {e}")))
        };
        retry::retry_transient(
            &retry::DEFAULT_DELAYS,
            "cpo-history",
            |e| matches!(e, Fail::Transient(_)),
            attempt,
        )
        .await
        .map_err(String::from)
    }

    /// Every transaction hash that ever touched `address`, oldest first, without
    /// duplicates.
    async fn address_tx_hashes(&self, address: &str) -> Result<Vec<String>, String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        let mut page = 1usize;
        loop {
            let path =
                format!("addresses/{address}/transactions?page={page}&count={PAGE}&order=asc");
            let Some(v) = self.get_json(&path).await? else {
                break; // 404: the address has no history
            };
            let items = v
                .as_array()
                .ok_or_else(|| format!("{path}: expected a JSON array"))?;
            let n = items.len();
            for item in items {
                let hash = item
                    .get("tx_hash")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| format!("{path}: entry without a string `tx_hash`"))?
                    .trim()
                    .to_ascii_lowercase();
                if seen.insert(hash.clone()) {
                    out.push(hash);
                }
            }
            if n < PAGE {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// The outputs `tx_hash` created AT `address`, with datums resolved.
    ///
    /// A transaction reached through the address history may only have SPENT an
    /// output there, so an empty result is normal.
    ///
    /// Every output the endpoint reports at the address is kept, including one
    /// flagged `collateral`. A phase-2 failure is the only case where the two
    /// backends could then disagree — Kupo indexes what the ledger created, this
    /// endpoint reports what the transaction declared — and the disagreement
    /// cannot corrupt a trie: an extra "movement" fails the running-root assertion
    /// or the singleton cross-check, both of which abort the run by name.
    async fn outputs_of_tx_at(
        &self,
        tx_hash: &str,
        address: &str,
    ) -> Result<Vec<HistoricalOutput>, String> {
        let path = format!("txs/{tx_hash}/utxos");
        let Some(v) = self.get_json(&path).await? else {
            // The transactions listing named this hash, so a 404 here means the
            // backend contradicts itself. Reporting it beats inventing an empty
            // transaction: a Confirmed TM record silently missing from the scan is
            // exactly the gap reconstruction refuses to tolerate.
            return Err(format!(
                "{path}: 404, but the address history of {address} lists {tx_hash} — \
                 the backend's transaction index and its transaction store disagree"
            ));
        };
        let parsed: BfTxUtxos =
            serde_json::from_value(v).map_err(|e| format!("{path} decode: {e}"))?;
        let mut out = Vec::new();
        for (position, o) in parsed.outputs.iter().enumerate() {
            if o.address != address {
                continue;
            }
            // `output_index` is what every real backend sends. Falling back to the
            // position in the outputs array is correct because the endpoint returns
            // the transaction's outputs in ledger order, complete.
            let index = o
                .output_index
                .unwrap_or_else(|| u32::try_from(position).unwrap_or(u32::MAX));
            let at = format!("{tx_hash}#{index}");
            let (datum, datum_note) = self
                .resolve_datum(o.inline_datum.as_deref(), o.data_hash.as_deref(), &at)
                .await?;
            out.push(HistoricalOutput {
                tx_hash: tx_hash.to_ascii_lowercase(),
                output_index: index,
                assets: bf_assets(&o.amount),
                datum,
                datum_note,
            });
        }
        Ok(out)
    }

    /// Resolve an output's datum: inline bytes when present, else the preimage of
    /// `data_hash` from `GET /scripts/datum/{hash}`.
    async fn resolve_datum(
        &self,
        inline: Option<&str>,
        data_hash: Option<&str>,
        at: &str,
    ) -> Result<(Option<PlutusData>, String), String> {
        if let Some(hex_str) = inline {
            let bytes =
                hex::decode(hex_str.trim()).map_err(|e| format!("inline datum hex ({at}): {e}"))?;
            return Ok((Some(decode_datum(&bytes, at)?), "inline".to_string()));
        }
        let Some(hash) = data_hash else {
            return Ok((None, "no datum".to_string()));
        };
        match self.datum_by_hash(hash).await? {
            Some(bytes) => Ok((
                Some(decode_datum(&bytes, at)?),
                format!("data_hash={hash}, resolved"),
            )),
            None => Ok((
                None,
                format!("data_hash={hash} — the backend serves no CBOR preimage"),
            )),
        }
    }

    /// The CBOR behind a datum hash.
    ///
    /// `/scripts/datum/{hash}/cbor` is the route that returns CBOR; the plain
    /// `/scripts/datum/{hash}` returns the JSON-value form, which cannot be
    /// re-serialized to the exact bytes a datum hash commits to. Both are tried,
    /// and only a `cbor` field is accepted — a backend that offers the JSON form
    /// alone is reported as "no preimage" rather than guessed at.
    ///
    /// Every Bifrost datum is INLINE, so this path is a compatibility fallback
    /// that a healthy bridge never takes.
    async fn datum_by_hash(&self, hash: &str) -> Result<Option<Vec<u8>>, String> {
        for path in [
            format!("scripts/datum/{hash}/cbor"),
            format!("scripts/datum/{hash}"),
        ] {
            let Some(v) = self.get_json(&path).await? else {
                continue;
            };
            let Some(cbor) = v.get("cbor").and_then(serde_json::Value::as_str) else {
                continue;
            };
            return hex::decode(cbor.trim())
                .map(Some)
                .map_err(|e| format!("{path}: cbor hex: {e}"));
        }
        Ok(None)
    }
}

/// Blockfrost `amount` entries → the unit-keyed asset map. Lovelace is dropped;
/// a quantity that is not a number is dropped rather than failing the read, since
/// no caller here can act on a malformed foreign asset anyway.
fn bf_assets(amount: &[bf_http::BfAmount]) -> BTreeMap<String, u64> {
    amount
        .iter()
        .filter(|a| a.unit != "lovelace")
        .filter_map(|a| {
            a.quantity
                .parse::<u64>()
                .ok()
                .map(|q| (a.unit.to_ascii_lowercase(), q))
        })
        .collect()
}

#[async_trait]
impl CpoHistorySource for BlockfrostHistory {
    fn backend(&self) -> &'static str {
        "blockfrost"
    }

    fn endpoint(&self) -> &str {
        &self.base_url
    }

    fn datum_gap_advice(&self) -> &'static str {
        "The backend served the output but no datum preimage. Point cardano.kupo_url at a \
         full Kupo index (the recommended SPO configuration), or use a Blockfrost-compatible \
         API that serves /scripts/datum/{hash}/cbor."
    }

    async fn address_history(&self, address: &str) -> Result<Vec<HistoricalOutput>, String> {
        let hashes = self.address_tx_hashes(address).await?;
        let mut out = Vec::new();
        for h in &hashes {
            out.extend(self.outputs_of_tx_at(h, address).await?);
        }
        Ok(out)
    }

    async fn unspent_with_asset(
        &self,
        policy_hex: &str,
        asset_name_hex: &str,
    ) -> Result<Vec<HistoricalOutput>, String> {
        let unit = format!(
            "{}{}",
            policy_hex.trim().to_ascii_lowercase(),
            asset_name_hex.trim().to_ascii_lowercase()
        );
        // `/assets/{unit}/addresses` names the holders; `/addresses/{addr}/utxos/{unit}`
        // turns a holder into the actual UTxO. Two hops, because a Blockfrost-
        // compatible API indexes the UTxO set by ADDRESS, not by asset.
        //
        // One page of each is read on purpose. A singleton NFT has ONE holder
        // holding ONE output; a chain state that needs a second page of either is
        // already the "not a singleton" case the caller rejects, and truncating it
        // at 100 changes nothing about that verdict.
        let path = format!("assets/{unit}/addresses?page=1&count={PAGE}");
        let Some(v) = self.get_json(&path).await? else {
            return Ok(Vec::new()); // 404: nobody holds it
        };
        let holders: Vec<String> = v
            .as_array()
            .ok_or_else(|| format!("{path}: expected a JSON array"))?
            .iter()
            .filter_map(|e| e.get("address").and_then(serde_json::Value::as_str))
            .map(str::to_string)
            .collect();

        let mut out = Vec::new();
        for holder in holders {
            let path = format!("addresses/{holder}/utxos/{unit}?page=1&count={PAGE}&order=asc");
            let Some(v) = self.get_json(&path).await? else {
                continue;
            };
            let utxos: Vec<BfAssetUtxo> =
                serde_json::from_value(v).map_err(|e| format!("{path} decode: {e}"))?;
            for u in &utxos {
                let at = format!("{}#{}", u.tx_hash, u.output_index);
                let (datum, datum_note) = self
                    .resolve_datum(u.inline_datum.as_deref(), u.data_hash.as_deref(), &at)
                    .await?;
                out.push(HistoricalOutput {
                    tx_hash: u.tx_hash.to_ascii_lowercase(),
                    output_index: u.output_index,
                    assets: bf_assets(&u.amount),
                    datum,
                    datum_note,
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::cpo_trie::{
        CPO_ASSET_NAME_HEX, CpoTrie, CpoTrieError, ReconstructConfig, hint_bytes, por_id,
        reconstruct, trie_value,
    };
    use crate::cardano::plutus::{array, bytes, constr, int, int_from_u64};
    use bitcoin::hashes::Hash as _;

    // -- the synthetic world both fake servers serve ------------------------
    //
    // One description of a chain, rendered into Kupo's wire shape and into
    // Blockfrost's. Everything the equivalence test asserts rests on the two
    // servers being fed from THIS, so neither backend can be quietly tailored to
    // its own fixture.

    const TM_ADDR: &str = "addr_test1_tm";
    const PEGOUT_ADDR: &str = "addr_test1_pegout";
    const CPO_ADDR: &str = "addr_test1_cpo";
    const FBTC_POLICY: &str = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
    /// `"fBTC"` in hex.
    const FBTC_NAME: &str = "66425443";
    const CPO_POLICY: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

    /// One output in the synthetic world.
    #[derive(Clone)]
    struct FxOut {
        address: String,
        tx_hash: String,
        output_index: u32,
        /// unit -> quantity, Blockfrost form.
        assets: BTreeMap<String, u64>,
        /// Inline datum CBOR. `None` = an output with no datum at all.
        datum: Option<Vec<u8>>,
        spent: bool,
    }

    fn pd_hex(d: &PlutusData) -> Vec<u8> {
        pallas_codec::minicbor::to_vec(d).expect("plutus data encodes")
    }

    fn unit(policy: &str, name: &str) -> String {
        format!("{policy}{name}")
    }

    fn assets_of(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(u, q)| ((*u).to_string(), *q)).collect()
    }

    // --- Kupo-shaped fake server ------------------------------------------

    async fn spawn_kupo(world: Vec<FxOut>) -> String {
        use axum::extract::{Path, Query, State};
        use axum::routing::get;
        use std::collections::HashMap as Map;
        use std::sync::Arc;

        type W = Arc<Vec<FxOut>>;

        async fn matches(
            Path(pattern): Path<String>,
            Query(q): Query<Map<String, String>>,
            State(world): State<W>,
        ) -> axum::Json<serde_json::Value> {
            let unspent_only = q.contains_key("unspent");
            let out: Vec<serde_json::Value> = world
                .iter()
                .filter(|o| {
                    if unspent_only && o.spent {
                        return false;
                    }
                    if o.address == pattern {
                        return true;
                    }
                    // Asset pattern "<policy>.<name>".
                    o.assets.keys().any(|u| {
                        pattern
                            .split_once('.')
                            .map(|(p, n)| *u == format!("{p}{n}"))
                            .unwrap_or(false)
                    })
                })
                .map(|o| {
                    // Kupo's dotted asset keys, and a datum HASH (real Kupo does
                    // not inline the datum in a match; the client fetches it).
                    let assets: serde_json::Map<String, serde_json::Value> = o
                        .assets
                        .iter()
                        .map(|(u, q)| {
                            let (p, n) = u.split_at(56);
                            (format!("{p}.{n}"), serde_json::json!(q))
                        })
                        .collect();
                    serde_json::json!({
                        "transaction_id": o.tx_hash,
                        "output_index": o.output_index,
                        "address": o.address,
                        "value": { "coins": 2_000_000, "assets": assets },
                        "datum_hash": o.datum.as_ref().map(|d| hex::encode(crate::cardano::hash::blake2b_256(d))),
                        "datum_type": o.datum.as_ref().map(|_| "inline"),
                        "created_at": { "slot_no": 1 },
                        "spent_at": o.spent.then(|| serde_json::json!({ "slot_no": 2 })),
                    })
                })
                .collect();
            axum::Json(serde_json::json!(out))
        }

        async fn datums(
            Path(hash): Path<String>,
            State(world): State<W>,
        ) -> axum::Json<serde_json::Value> {
            let found = world.iter().find_map(|o| {
                o.datum
                    .as_ref()
                    .filter(|d| hex::encode(crate::cardano::hash::blake2b_256(d)) == hash)
                    .map(hex::encode)
            });
            axum::Json(serde_json::json!({ "datum": found }))
        }

        let app = axum::Router::new()
            .route("/matches/{pattern}", get(matches))
            .route("/datums/{hash}", get(datums))
            .with_state(Arc::new(world));
        serve(app).await
    }

    // --- Blockfrost-shaped fake server ------------------------------------

    async fn spawn_blockfrost(world: Vec<FxOut>) -> String {
        use axum::extract::{Path, State};
        use axum::routing::get;
        use std::sync::Arc;

        type W = Arc<Vec<FxOut>>;

        // Every distinct tx hash that created an output at `address`. The real
        // endpoint also lists transactions that only SPENT there; the fake adds
        // one such phantom hash below so the client's "outputs may be empty"
        // handling is exercised.
        async fn address_txs(
            Path(address): Path<String>,
            State(world): State<W>,
        ) -> axum::Json<serde_json::Value> {
            let mut hashes: Vec<String> = Vec::new();
            for o in world.iter().filter(|o| o.address == address) {
                if !hashes.contains(&o.tx_hash) {
                    hashes.push(o.tx_hash.clone());
                }
            }
            // A transaction that touched the address without creating an output
            // there — the endpoint really does return these.
            hashes.push("de".repeat(32));
            let items: Vec<serde_json::Value> = hashes
                .iter()
                .map(|h| serde_json::json!({ "tx_hash": h }))
                .collect();
            axum::Json(serde_json::json!(items))
        }

        async fn tx_utxos(
            Path(hash): Path<String>,
            State(world): State<W>,
        ) -> axum::Json<serde_json::Value> {
            let outputs: Vec<serde_json::Value> = world
                .iter()
                .filter(|o| o.tx_hash == hash)
                .map(|o| {
                    let mut amount = vec![serde_json::json!({
                        "unit": "lovelace", "quantity": "2000000"
                    })];
                    for (u, q) in &o.assets {
                        amount.push(serde_json::json!({
                            "unit": u, "quantity": q.to_string()
                        }));
                    }
                    serde_json::json!({
                        "address": o.address,
                        "output_index": o.output_index,
                        "amount": amount,
                        "inline_datum": o.datum.as_ref().map(hex::encode),
                        "data_hash": o.datum.as_ref().map(|d| hex::encode(crate::cardano::hash::blake2b_256(d))),
                    })
                })
                .collect();
            axum::Json(serde_json::json!({ "hash": hash, "inputs": [], "outputs": outputs }))
        }

        async fn asset_addresses(
            Path(unit): Path<String>,
            State(world): State<W>,
        ) -> axum::Json<serde_json::Value> {
            let mut addrs: Vec<String> = Vec::new();
            for o in world
                .iter()
                .filter(|o| !o.spent && o.assets.contains_key(&unit))
            {
                if !addrs.contains(&o.address) {
                    addrs.push(o.address.clone());
                }
            }
            let items: Vec<serde_json::Value> = addrs
                .iter()
                .map(|a| serde_json::json!({ "address": a, "quantity": "1" }))
                .collect();
            axum::Json(serde_json::json!(items))
        }

        async fn address_asset_utxos(
            Path((address, unit)): Path<(String, String)>,
            State(world): State<W>,
        ) -> axum::Json<serde_json::Value> {
            let items: Vec<serde_json::Value> = world
                .iter()
                .filter(|o| !o.spent && o.address == address && o.assets.contains_key(&unit))
                .map(|o| {
                    let mut amount = vec![serde_json::json!({
                        "unit": "lovelace", "quantity": "2000000"
                    })];
                    for (u, q) in &o.assets {
                        amount.push(serde_json::json!({
                            "unit": u, "quantity": q.to_string()
                        }));
                    }
                    serde_json::json!({
                        "tx_hash": o.tx_hash,
                        "output_index": o.output_index,
                        "amount": amount,
                        "inline_datum": o.datum.as_ref().map(hex::encode),
                    })
                })
                .collect();
            axum::Json(serde_json::json!(items))
        }

        let app = axum::Router::new()
            .route("/addresses/{address}/transactions", get(address_txs))
            .route("/txs/{hash}/utxos", get(tx_utxos))
            .route("/assets/{unit}/addresses", get(asset_addresses))
            .route(
                "/addresses/{address}/utxos/{unit}",
                get(address_asset_utxos),
            )
            .with_state(Arc::new(world));
        serve(app).await
    }

    async fn serve(app: axum::Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    // -- the world ---------------------------------------------------------

    /// A chain with two peg-out requests, one Treasury Movement paying both, its
    /// spent `Unconfirmed` record carrying the hint, and the CPO singleton holding
    /// the resulting root.
    fn world() -> (Vec<FxOut>, [u8; 32]) {
        let por_tx_a = [0x11u8; 32];
        let por_tx_b = [0x22u8; 32];
        let spk_a = vec![0xaau8; 22];
        let spk_b = vec![0xbbu8; 22];
        let (gross_a, gross_b, fee) = (100_000u64, 250_000u64, 1_000u64);

        let entries = [
            (por_id(&por_tx_a, 0), trie_value(&spk_a, gross_a - fee)),
            (por_id(&por_tx_b, 1), trie_value(&spk_b, gross_b - fee)),
        ];
        let mut trie = CpoTrie::empty();
        let root = trie
            .insert_batch(
                &entries
                    .iter()
                    .map(|(k, v)| crate::cardano::cpo_trie::CpoEntry {
                        por_id: *k,
                        value: v.clone(),
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        // The Bitcoin TM: output 0 treasury, then the two payments, then the
        // "CPOR1" commitment. The Unconfirmed record embeds this tx, so its txid
        // must be the one the Confirmed record reports.
        let commitment_spk = {
            let mut s = crate::bitcoin::tm_builder::CPO_COMMITMENT_PREFIX.to_vec();
            s.extend_from_slice(&root);
            s
        };
        let btc_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(900_000),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51; 34]),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(gross_a - fee),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(spk_a.clone()),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(gross_b - fee),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(spk_b.clone()),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::ZERO,
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(commitment_spk.clone()),
                },
            ],
        };
        let btc_txid = btc_tx.compute_txid().to_byte_array();
        let btc_tx_bytes = bitcoin::consensus::serialize(&btc_tx);

        let tm_output = |spk: &[u8], amount: u64| constr(0, vec![bytes(spk), int_from_u64(amount)]);
        let confirmed = constr(
            1,
            vec![
                bytes(&btc_txid),
                array(vec![]),
                array(vec![
                    tm_output(&[0x51; 34], 900_000),
                    tm_output(&spk_a, gross_a - fee),
                    tm_output(&spk_b, gross_b - fee),
                    tm_output(&commitment_spk, 0),
                ]),
                crate::cardano::plutus::bool_data(false),
                bytes(&[0x7a; 28]),
                int(1_700_000_000_000),
            ],
        );
        let unconfirmed = constr(
            0,
            vec![
                bytes(&btc_tx_bytes),
                bytes(&[0x7a; 28]),
                int(1_700_000_000_000),
                int(0),
                int(0),
                array(vec![
                    bytes(&hint_bytes(&por_tx_a, 0)),
                    bytes(&hint_bytes(&por_tx_b, 1)),
                ]),
            ],
        );
        let pegout_datum = |spk: &[u8]| {
            constr(
                0,
                vec![
                    constr(0, vec![bytes(&[0x01; 28])]),
                    bytes(spk),
                    int_from_u64(fee),
                    int(1_700_000_000_000),
                ],
            )
        };
        let cpo_datum = constr(0, vec![bytes(&root)]);

        let fbtc = unit(FBTC_POLICY, FBTC_NAME);
        let cpo_unit = unit(CPO_POLICY, CPO_ASSET_NAME_HEX);

        let world = vec![
            // The Unconfirmed record, SPENT by its own Confirm transition — the
            // whole reason reconstruction needs spent outputs.
            FxOut {
                address: TM_ADDR.into(),
                tx_hash: "a1".repeat(32),
                output_index: 0,
                assets: BTreeMap::new(),
                datum: Some(pd_hex(&unconfirmed)),
                spent: true,
            },
            FxOut {
                address: TM_ADDR.into(),
                tx_hash: "b2".repeat(32),
                output_index: 0,
                assets: BTreeMap::new(),
                datum: Some(pd_hex(&confirmed)),
                spent: false,
            },
            // A junk UTxO at the permissionlessly-payable TM address: its datum
            // resolves, it just is not a TM record.
            FxOut {
                address: TM_ADDR.into(),
                tx_hash: "c3".repeat(32),
                output_index: 7,
                assets: BTreeMap::new(),
                datum: Some(pd_hex(&bytes(b"junk"))),
                spent: false,
            },
            FxOut {
                address: PEGOUT_ADDR.into(),
                tx_hash: hex::encode(por_tx_a),
                output_index: 0,
                assets: assets_of(&[(&fbtc, gross_a)]),
                datum: Some(pd_hex(&pegout_datum(&spk_a))),
                spent: true,
            },
            FxOut {
                address: PEGOUT_ADDR.into(),
                tx_hash: hex::encode(por_tx_b),
                output_index: 1,
                assets: assets_of(&[(&fbtc, gross_b)]),
                datum: Some(pd_hex(&pegout_datum(&spk_b))),
                spent: true,
            },
            // Value sent to the peg-out address that is not a request (no fBTC).
            FxOut {
                address: PEGOUT_ADDR.into(),
                tx_hash: "ee".repeat(32),
                output_index: 0,
                assets: BTreeMap::new(),
                datum: None,
                spent: false,
            },
            FxOut {
                address: CPO_ADDR.into(),
                tx_hash: "cf".repeat(32),
                output_index: 0,
                assets: assets_of(&[(&cpo_unit, 1)]),
                datum: Some(pd_hex(&cpo_datum)),
                spent: false,
            },
        ];
        (world, root)
    }

    fn recon_cfg() -> ReconstructConfig {
        ReconstructConfig {
            tm_address: TM_ADDR.into(),
            pegout_address: PEGOUT_ADDR.into(),
            fbtc_policy_id: FBTC_POLICY.into(),
            fbtc_asset_name_hex: FBTC_NAME.into(),
            cpo_policy_id: Some(CPO_POLICY.into()),
        }
    }

    // -- tests -------------------------------------------------------------

    /// THE test this whole abstraction exists for: the same chain, read through
    /// Kupo and through a plain Blockfrost-compatible API, must reconstruct the
    /// SAME trie. If the two ever diverge, one of them makes a node sign roots the
    /// quorum refuses.
    #[tokio::test]
    async fn both_backends_reconstruct_the_same_trie() {
        let (w, expected_root) = world();
        let kupo_url = spawn_kupo(w.clone()).await;
        let bf_url = spawn_blockfrost(w).await;

        let via_kupo = reconstruct(&KupoHistory::new(&kupo_url), &recon_cfg())
            .await
            .expect("kupo reconstruction");
        let via_bf = reconstruct(
            &BlockfrostHistory::new("preprodtest", Some(&bf_url)),
            &recon_cfg(),
        )
        .await
        .expect("blockfrost reconstruction");

        assert_eq!(via_kupo.root(), expected_root, "kupo root");
        assert_eq!(via_bf.root(), expected_root, "blockfrost root");
        assert_eq!(via_kupo.len(), 2);
        let a: Vec<_> = via_kupo.entries().map(|(k, v)| (*k, v.to_vec())).collect();
        let b: Vec<_> = via_bf.entries().map(|(k, v)| (*k, v.to_vec())).collect();
        assert_eq!(a, b, "the two backends must produce identical entries");
    }

    /// The fetch layer itself, compared backend against backend: same outputs,
    /// same asset keys, same resolved datums. This is what makes the equivalence
    /// above a property of the DATA rather than a coincidence of the algorithm.
    #[tokio::test]
    async fn both_backends_report_the_same_address_history() {
        let (w, _) = world();
        let kupo = KupoHistory::new(&spawn_kupo(w.clone()).await);
        let bf = BlockfrostHistory::new("preprodtest", Some(&spawn_blockfrost(w).await));

        for address in [TM_ADDR, PEGOUT_ADDR] {
            let mut k = kupo.address_history(address).await.unwrap();
            let mut b = bf.address_history(address).await.unwrap();
            assert_eq!(k.len(), b.len(), "{address}: output count");
            let key = |o: &HistoricalOutput| (o.tx_hash.clone(), o.output_index);
            k.sort_by_key(key);
            b.sort_by_key(key);
            for (k, b) in k.iter().zip(b.iter()) {
                assert_eq!(k.tx_hash, b.tx_hash);
                assert_eq!(k.output_index, b.output_index);
                assert_eq!(k.assets, b.assets, "{}#{}", k.tx_hash, k.output_index);
                assert_eq!(
                    k.datum.as_ref().map(pd_hex),
                    b.datum.as_ref().map(pd_hex),
                    "{}#{} datum",
                    k.tx_hash,
                    k.output_index
                );
            }
        }
    }

    #[tokio::test]
    async fn both_backends_find_the_cpo_singleton() {
        let (w, root) = world();
        let kupo = KupoHistory::new(&spawn_kupo(w.clone()).await);
        let bf = BlockfrostHistory::new("preprodtest", Some(&spawn_blockfrost(w).await));

        for (name, found) in [
            (
                "kupo",
                kupo.unspent_with_asset(CPO_POLICY, CPO_ASSET_NAME_HEX)
                    .await
                    .unwrap(),
            ),
            (
                "blockfrost",
                bf.unspent_with_asset(CPO_POLICY, CPO_ASSET_NAME_HEX)
                    .await
                    .unwrap(),
            ),
        ] {
            assert_eq!(found.len(), 1, "{name}: expected the singleton alone");
            assert_eq!(found[0].asset_quantity(CPO_POLICY, CPO_ASSET_NAME_HEX), 1);
            assert_eq!(
                crate::cardano::cpo_trie::parse_cpo_trie_datum(
                    found[0].datum.as_ref().expect("singleton datum")
                )
                .unwrap(),
                root,
                "{name}: singleton root"
            );
        }
    }

    /// A spent output must be visible to BOTH backends: the hint lives in the
    /// `Unconfirmed` record, which its own Confirm transition consumes.
    #[tokio::test]
    async fn both_backends_return_spent_outputs() {
        let (w, _) = world();
        let kupo = KupoHistory::new(&spawn_kupo(w.clone()).await);
        let bf = BlockfrostHistory::new("preprodtest", Some(&spawn_blockfrost(w).await));
        let spent_tx = "a1".repeat(32);
        for (name, hist) in [
            ("kupo", kupo.address_history(TM_ADDR).await.unwrap()),
            ("blockfrost", bf.address_history(TM_ADDR).await.unwrap()),
        ] {
            assert!(
                hist.iter().any(|o| o.tx_hash == spent_tx),
                "{name}: the spent Unconfirmed record must still be returned"
            );
        }
    }

    /// A datum the backend cannot resolve must arrive as an OUTPUT with
    /// `datum: None`, so `reconstruct` can hard-error on it. A backend that
    /// dropped the output instead would produce a trie that silently omits a
    /// movement.
    #[tokio::test]
    async fn an_unresolvable_datum_is_surfaced_not_dropped() {
        // Kupo that knows the hash but has no preimage (a --prune-utxo index).
        let world = vec![FxOut {
            address: TM_ADDR.into(),
            tx_hash: "a1".repeat(32),
            output_index: 0,
            assets: BTreeMap::new(),
            datum: Some(pd_hex(&bytes(b"whatever"))),
            spent: true,
        }];
        let url = spawn_pruned_kupo(world).await;
        let hist = KupoHistory::new(&url)
            .address_history(TM_ADDR)
            .await
            .unwrap();
        assert_eq!(hist.len(), 1);
        assert!(hist[0].datum.is_none());
        assert!(
            hist[0].datum_note.contains("no preimage"),
            "{}",
            hist[0].datum_note
        );

        // And reconstruction refuses to continue past it.
        let err = reconstruct(&KupoHistory::new(&url), &recon_cfg())
            .await
            .unwrap_err();
        assert!(
            matches!(err, CpoTrieError::Source(_)) && format!("{err}").contains("unexplained gap"),
            "{err}"
        );
    }

    /// A Kupo whose `/datums/{hash}` always answers `{"datum": null}`.
    async fn spawn_pruned_kupo(world: Vec<FxOut>) -> String {
        use axum::extract::{Path, State};
        use axum::routing::get;
        use std::sync::Arc;

        async fn matches(
            Path(pattern): Path<String>,
            State(world): State<Arc<Vec<FxOut>>>,
        ) -> axum::Json<serde_json::Value> {
            let out: Vec<serde_json::Value> = world
                .iter()
                .filter(|o| o.address == pattern)
                .map(|o| {
                    serde_json::json!({
                        "transaction_id": o.tx_hash,
                        "output_index": o.output_index,
                        "address": o.address,
                        "value": { "coins": 2_000_000, "assets": {} },
                        "datum_hash": o.datum.as_ref().map(|d| hex::encode(crate::cardano::hash::blake2b_256(d))),
                        "datum_type": "inline",
                        "created_at": { "slot_no": 1 },
                        "spent_at": null,
                    })
                })
                .collect();
            axum::Json(serde_json::json!(out))
        }

        async fn datums() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({ "datum": null }))
        }

        let app = axum::Router::new()
            .route("/matches/{pattern}", get(matches))
            .route("/datums/{hash}", get(datums))
            .with_state(Arc::new(world));
        serve(app).await
    }

    /// The Blockfrost walk must survive a transaction that only SPENT at the
    /// address (the transactions endpoint lists those too) and must not mistake
    /// another address's outputs in the same transaction for its own.
    #[tokio::test]
    async fn blockfrost_ignores_foreign_outputs_and_spend_only_transactions() {
        let world = vec![
            FxOut {
                address: TM_ADDR.into(),
                tx_hash: "aa".repeat(32),
                output_index: 1,
                assets: BTreeMap::new(),
                datum: Some(pd_hex(&bytes(b"mine"))),
                spent: false,
            },
            FxOut {
                address: "someone_else".into(),
                tx_hash: "aa".repeat(32),
                output_index: 0,
                assets: BTreeMap::new(),
                datum: Some(pd_hex(&bytes(b"theirs"))),
                spent: false,
            },
        ];
        let bf = BlockfrostHistory::new("preprodtest", Some(&spawn_blockfrost(world).await));
        let hist = bf.address_history(TM_ADDR).await.unwrap();
        assert_eq!(hist.len(), 1, "only the output AT the address");
        assert_eq!(hist[0].output_index, 1);
    }

    // -- pure unit tests ---------------------------------------------------

    #[test]
    fn kupo_asset_keys_normalize_to_the_blockfrost_unit() {
        let m: KupoMatch = serde_json::from_str(
            r#"{
              "transaction_id": "aa", "output_index": 0, "address": "x",
              "value": { "coins": 1, "assets": { "C0FFEE.43504F": 3, "deadbeef": 7 } },
              "created_at": { "slot_no": 1 }
            }"#,
        )
        .unwrap();
        let assets = kupo_assets(&m);
        assert_eq!(assets.get("c0ffee43504f"), Some(&3));
        // A dotless Kupo key is a policy with an EMPTY asset name — the unit is
        // the policy alone.
        assert_eq!(assets.get("deadbeef"), Some(&7));
    }

    #[test]
    fn kupo_asset_pattern_omits_the_dot_for_an_empty_name() {
        assert_eq!(kupo_asset_pattern("C0FFEE", "43504F"), "c0ffee.43504f");
        assert_eq!(kupo_asset_pattern("c0ffee", ""), "c0ffee");
    }

    #[test]
    fn asset_quantity_is_case_insensitive_and_zero_when_absent() {
        let o = HistoricalOutput {
            tx_hash: "aa".into(),
            output_index: 0,
            assets: assets_of(&[("c0ffee43504f", 1)]),
            datum: None,
            datum_note: "no datum".into(),
        };
        assert_eq!(o.asset_quantity("C0FFEE", "43504F"), 1);
        assert_eq!(o.asset_quantity("c0ffee", "00"), 0);
    }

    #[test]
    fn bf_assets_drops_lovelace() {
        let amount = vec![
            bf_http::BfAmount {
                unit: "lovelace".into(),
                quantity: "2000000".into(),
            },
            bf_http::BfAmount {
                unit: "C0FFEE43504F".into(),
                quantity: "1".into(),
            },
        ];
        let a = bf_assets(&amount);
        assert_eq!(a.len(), 1);
        assert_eq!(a.get("c0ffee43504f"), Some(&1));
    }
}
