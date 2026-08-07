//! The chain-history FETCH layer behind completed-peg-outs trie reconstruction.
//!
//! ## Why this module exists
//!
//! [`crate::cardano::cpo_trie::reconstruct`] rebuilds the trie from Cardano
//! history alone. The algorithm it runs — chain-order the Confirmed Treasury
//! Movements, try every published data-availability hint, fall back to matching
//! payments against peg-out requests, assert the running root after every
//! movement, cross-check the finished trie against the bridge state singleton —
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
//! - [`HistoricalOutput::datum`] MUST distinguish an output with NO datum at all
//!   ([`DatumState::Absent`]) from one whose datum hash is known but whose
//!   preimage the backend could not supply ([`DatumState::Unresolved`]), never as
//!   a silently dropped output. `reconstruct` SKIPS the former even at the TM
//!   address — no protocol record is ever written without an inline datum, so a
//!   bare payment provably is not one — and HARD-ERRORS on the latter, because an
//!   unread datum there might be a `Confirmed` record. Collapsing the two into
//!   one `None` is exactly what let a single datum-less payment to the TM address
//!   block every SPO's reconstruction forever; see `cpo_trie`'s module doc.
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

/// What chain history reports about one output's datum — a THREE-way reading,
/// not a two-way one.
///
/// [`Self::Absent`] and [`Self::Unresolved`] must never collapse into a single
/// `None`: [`crate::cardano::cpo_trie::reconstruct`] treats them oppositely at the
/// TM address. An output with NO datum at all is skipped even there, because
/// every genuine `Unconfirmed`/`Confirmed` record is written with an inline
/// datum, so a bare payment provably is not one — the TM address is
/// permissionlessly payable, and treating a bare payment as fatal let a single
/// junk UTxO block every reconstruction forever. An output whose datum EXISTS but
/// could not be read is a hard error: it might be an unread `Confirmed` record,
/// and dropping one yields a trie that silently omits a whole movement.
#[derive(Debug, Clone)]
pub enum DatumState {
    /// The output carries no datum at all — no hash, no inline bytes.
    Absent,
    /// A datum hash is known, but the backend could not produce its preimage
    /// (Kupo run with `--prune-utxo`, or a Blockfrost-compatible API that does
    /// not serve `/scripts/datum/{hash}`).
    Unresolved {
        /// The datum hash, for naming the offending output in an error message.
        datum_hash: String,
    },
    /// The datum resolved to `PlutusData`, however it was carried on the wire
    /// (inline bytes, or a hash the backend could supply the preimage of).
    Resolved(PlutusData),
}

impl DatumState {
    /// The resolved data, if any. `None` for both [`Self::Absent`] and
    /// [`Self::Unresolved`] — a caller that only needs "is there usable data
    /// here" (the peg-out address's skip-on-either case) can stay agnostic to
    /// which.
    #[must_use]
    pub fn resolved(&self) -> Option<&PlutusData> {
        match self {
            Self::Resolved(d) => Some(d),
            Self::Absent | Self::Unresolved { .. } => None,
        }
    }

    /// Is this output entirely without a datum?
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

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
    /// See [`DatumState`]: absent, present-but-unresolved, or resolved. The
    /// first two MUST NOT collapse into one value — that collapse is exactly
    /// what let a datum-less junk payment block reconstruction forever.
    pub datum: DatumState,
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
    /// Used only to locate the on-chain bridge state singleton. The caller
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
    ///
    /// Kupo's match ALWAYS carries `datum_hash` when the output has a datum at
    /// all — even one whose preimage Kupo lacks — so that field alone is what
    /// tells [`DatumState::Absent`] apart from [`DatumState::Unresolved`].
    async fn convert(&self, m: &KupoMatch) -> Result<HistoricalOutput, String> {
        let resolved = self.client.resolve_datum(m).await?;
        let (datum, datum_note) = match (resolved, &m.datum_hash) {
            (Some(pd), _) => (
                DatumState::Resolved(pd),
                format!(
                    "resolved, datum_type={}",
                    m.datum_type.as_deref().unwrap_or("<none>")
                ),
            ),
            (None, Some(h)) => (
                DatumState::Unresolved {
                    datum_hash: h.clone(),
                },
                format!(
                    "datum_hash={h}, datum_type={} — Kupo has no preimage",
                    m.datum_type.as_deref().unwrap_or("<none>")
                ),
            ),
            (None, None) => (DatumState::Absent, "no datum".to_string()),
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
    /// Backoff schedule for transient failures ([`retry::DEFAULT_DELAYS`]). A
    /// field rather than a constant so a test can assert the retry BEHAVIOUR in
    /// milliseconds instead of the seconds production wants.
    delays: Vec<std::time::Duration>,
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
            delays: retry::DEFAULT_DELAYS.to_vec(),
        }
    }

    /// Shorten the backoff so a retry test runs in milliseconds.
    #[cfg(test)]
    fn with_delays(mut self, delays: Vec<std::time::Duration>) -> Self {
        self.delays = delays;
        self
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
            &self.delays,
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
    ///
    /// `data_hash` being absent (with no inline bytes either) is
    /// [`DatumState::Absent`] — the output has no datum at all. `data_hash`
    /// present but the preimage unavailable is [`DatumState::Unresolved`], never
    /// the same value: `reconstruct` treats the two oppositely at the TM address.
    async fn resolve_datum(
        &self,
        inline: Option<&str>,
        data_hash: Option<&str>,
        at: &str,
    ) -> Result<(DatumState, String), String> {
        if let Some(hex_str) = inline {
            let bytes =
                hex::decode(hex_str.trim()).map_err(|e| format!("inline datum hex ({at}): {e}"))?;
            return Ok((
                DatumState::Resolved(decode_datum(&bytes, at)?),
                "inline".to_string(),
            ));
        }
        let Some(hash) = data_hash else {
            return Ok((DatumState::Absent, "no datum".to_string()));
        };
        match self.datum_by_hash(hash).await? {
            Some(bytes) => Ok((
                DatumState::Resolved(decode_datum(&bytes, at)?),
                format!("data_hash={hash}, resolved"),
            )),
            None => Ok((
                DatumState::Unresolved {
                    datum_hash: hash.to_string(),
                },
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
    use crate::cardano::bridge_state::{BSS_ASSET_NAME_HEX, parse_bridge_state};
    use crate::cardano::cpo_trie::{
        CpoTrie, CpoTrieError, ReconstructConfig, hint_bytes, por_id, reconstruct, trie_value,
    };
    use crate::cardano::plutus::{array, bytes, constr, int, int_from_u64};
    use bitcoin::hashes::Hash as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        /// Datum CBOR. `None` = an output with no datum at all.
        datum: Option<Vec<u8>>,
        /// Is the datum stored INLINE in the output?
        ///
        /// Only the Blockfrost rendering cares. `true` puts the bytes in
        /// `inline_datum`; `false` sends `data_hash` alone, so the client must go
        /// to `/scripts/datum/{hash}/cbor` for the preimage. Kupo always reports a
        /// hash and a separate `/datums/{hash}` fetch either way, which is exactly
        /// why the two backends must still agree.
        inline: bool,
        spent: bool,
    }

    /// A `FxOut` with an inline datum — the common case.
    fn fx(
        address: &str,
        tx_hash: String,
        output_index: u32,
        assets: BTreeMap<String, u64>,
        datum: Option<Vec<u8>>,
        spent: bool,
    ) -> FxOut {
        FxOut {
            address: address.to_string(),
            tx_hash,
            output_index,
            assets,
            datum,
            inline: true,
            spent,
        }
    }

    fn datum_hash_hex(d: &[u8]) -> String {
        hex::encode(crate::cardano::hash::blake2b_256(d))
    }

    fn pd_hex(d: &PlutusData) -> Vec<u8> {
        pallas_codec::minicbor::to_vec(d).expect("plutus data encodes")
    }

    /// Which of the three [`DatumState`] variants `d` is, for an equality
    /// assertion between backends — `DatumState` itself does not derive
    /// `PartialEq` ([`PlutusData`] does not either).
    fn datum_kind(d: &DatumState) -> &'static str {
        match d {
            DatumState::Absent => "absent",
            DatumState::Unresolved { .. } => "unresolved",
            DatumState::Resolved(_) => "resolved",
        }
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
                        "datum_hash": o.datum.as_deref().map(datum_hash_hex),
                        "datum_type": o.datum.as_ref().map(|_| if o.inline { "inline" } else { "hash" }),
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
                    .as_deref()
                    .filter(|d| datum_hash_hex(d) == hash)
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

    /// How the fake serves `/scripts/datum/{hash}` — the branchy part of
    /// [`BlockfrostHistory::datum_by_hash`].
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DatumRoute {
        /// `/scripts/datum/{hash}/cbor` returns `{"cbor": ...}`. What Blockfrost does.
        Cbor,
        /// Only the non-`/cbor` route exists, and it carries a `cbor` field.
        NonCborRouteOnly,
        /// Both routes exist but serve only `json_value` — no recoverable bytes.
        JsonValueOnly,
        /// Neither route knows the hash. The preimage is gone.
        Missing,
    }

    async fn spawn_blockfrost(world: Vec<FxOut>) -> String {
        spawn_blockfrost_with(world, DatumRoute::Cbor).await
    }

    async fn spawn_blockfrost_with(world: Vec<FxOut>, mode: DatumRoute) -> String {
        use axum::extract::{Path, State};
        use axum::routing::get;
        use std::sync::Arc;

        type W = Arc<Vec<FxOut>>;
        type S = (W, DatumRoute);

        // Every distinct tx hash that created an output at `address`. The real
        // endpoint also lists transactions that only SPENT there; the fake adds
        // one such phantom hash below so the client's "outputs may be empty"
        // handling is exercised.
        async fn address_txs(
            Path(address): Path<String>,
            State((world, _)): State<S>,
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

        /// An output's datum as `/txs/{hash}/utxos` reports it: bytes in
        /// `inline_datum` for an inline datum, `data_hash` ALONE otherwise.
        fn datum_fields(o: &FxOut) -> (Option<String>, Option<String>) {
            match (&o.datum, o.inline) {
                (None, _) => (None, None),
                (Some(d), true) => (Some(hex::encode(d)), Some(datum_hash_hex(d))),
                (Some(d), false) => (None, Some(datum_hash_hex(d))),
            }
        }

        async fn tx_utxos(
            Path(hash): Path<String>,
            State((world, _)): State<S>,
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
                    let (inline_datum, data_hash) = datum_fields(o);
                    serde_json::json!({
                        "address": o.address,
                        "output_index": o.output_index,
                        "amount": amount,
                        "inline_datum": inline_datum,
                        "data_hash": data_hash,
                    })
                })
                .collect();
            axum::Json(serde_json::json!({ "hash": hash, "inputs": [], "outputs": outputs }))
        }

        /// `/scripts/datum/{hash}` and `/scripts/datum/{hash}/cbor`, behaving as
        /// `mode` says. A 404 means "this route does not serve that hash".
        async fn scripts_datum(
            Path(hash): Path<String>,
            State((world, mode)): State<S>,
        ) -> axum::response::Response {
            scripts_datum_inner(&hash, &world, mode, true)
        }

        async fn scripts_datum_cbor(
            Path(hash): Path<String>,
            State((world, mode)): State<S>,
        ) -> axum::response::Response {
            scripts_datum_inner(&hash, &world, mode, false)
        }

        fn scripts_datum_inner(
            hash: &str,
            world: &[FxOut],
            mode: DatumRoute,
            plain_route: bool,
        ) -> axum::response::Response {
            use axum::response::IntoResponse as _;
            let not_found = || axum::http::StatusCode::NOT_FOUND.into_response();
            let Some(d) = world
                .iter()
                .filter_map(|o| o.datum.as_deref())
                .find(|d| datum_hash_hex(d) == hash)
            else {
                return not_found();
            };
            let body = match (mode, plain_route) {
                (DatumRoute::Missing, _) => return not_found(),
                (DatumRoute::Cbor, true) | (DatumRoute::NonCborRouteOnly, false) => {
                    return not_found();
                }
                (DatumRoute::JsonValueOnly, _) => serde_json::json!({ "json_value": { "int": 1 } }),
                _ => serde_json::json!({ "cbor": hex::encode(d) }),
            };
            axum::Json(body).into_response()
        }

        async fn asset_addresses(
            Path(unit): Path<String>,
            State((world, _)): State<S>,
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
            State((world, _)): State<S>,
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
                    let (inline_datum, data_hash) = datum_fields(o);
                    serde_json::json!({
                        "tx_hash": o.tx_hash,
                        "output_index": o.output_index,
                        "amount": amount,
                        "inline_datum": inline_datum,
                        "data_hash": data_hash,
                    })
                })
                .collect();
            axum::Json(serde_json::json!(items))
        }

        let app = axum::Router::new()
            .route("/addresses/{address}/transactions", get(address_txs))
            .route("/txs/{hash}/utxos", get(tx_utxos))
            .route("/scripts/datum/{hash}", get(scripts_datum))
            .route("/scripts/datum/{hash}/cbor", get(scripts_datum_cbor))
            .route("/assets/{unit}/addresses", get(asset_addresses))
            .route(
                "/addresses/{address}/utxos/{unit}",
                get(address_asset_utxos),
            )
            .with_state((Arc::new(world) as W, mode));
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
    /// spent `Unconfirmed` record carrying the hint, and the bridge state singleton holding
    /// the resulting root. Also carries, at the TM address, a resolvable
    /// hash-only Confirmed datum AND a genuinely datum-less junk output — the two
    /// cases [`DatumState`] exists to keep apart — so the equivalence tests below
    /// prove both backends agree on the distinction, not just on the happy path.
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
        // BTMR1 commitment. The Unconfirmed record embeds this tx, so its txid
        // must be the one the Confirmed record reports.
        let commitment_spk = {
            let mut s = crate::bitcoin::tm_builder::BTMR1_COMMITMENT_PREFIX.to_vec();
            s.extend_from_slice(&[0x99u8; 32]); // spi_root placeholder
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
        // The bridge state singleton. `spi_root` is a distinct placeholder, so a
        // positional read of field 0 cannot pass for `cpo_root`.
        let cpo_datum = constr(
            0,
            vec![
                bytes(&[0x5b; 32]),
                bytes(&root),
                bytes(&[0x7c; 36]),
                int_from_u64(1_000_000),
            ],
        );

        let fbtc = unit(FBTC_POLICY, FBTC_NAME);
        let cpo_unit = unit(CPO_POLICY, BSS_ASSET_NAME_HEX);

        let world = vec![
            // The Unconfirmed record, SPENT by its own Confirm transition — the
            // whole reason reconstruction needs spent outputs. Inline datum.
            fx(
                TM_ADDR,
                "a1".repeat(32),
                0,
                BTreeMap::new(),
                Some(pd_hex(&unconfirmed)),
                true,
            ),
            // The Confirmed record, deliberately NOT inline.
            //
            // On the Blockfrost path this is the only output whose datum the walk
            // cannot read from `/txs/{hash}/utxos`; it must go to
            // `/scripts/datum/{hash}/cbor`. Reconstruction hard-errors on an
            // unresolvable datum at the TM address, so this fixture succeeding is
            // proof the hash-only path resolved — and the equivalence test then
            // proves it resolved to the same bytes Kupo serves.
            FxOut {
                address: TM_ADDR.into(),
                tx_hash: "b2".repeat(32),
                output_index: 0,
                assets: BTreeMap::new(),
                datum: Some(pd_hex(&confirmed)),
                inline: false,
                spent: false,
            },
            // A junk UTxO at the permissionlessly-payable TM address: its datum
            // resolves, it just is not a TM record.
            fx(
                TM_ADDR,
                "c3".repeat(32),
                7,
                BTreeMap::new(),
                Some(pd_hex(&bytes(b"junk"))),
                false,
            ),
            // A datum-LESS junk payment at the TM address: no datum at all, so it
            // is provably not a TM record (every genuine Unconfirmed/Confirmed
            // record carries an inline datum) and MUST be skipped rather than
            // aborting reconstruction. This is the case the 2026-08 fix exists
            // for: before it, this single output would have blocked every
            // reconstruction.
            fx(TM_ADDR, "d4".repeat(32), 0, BTreeMap::new(), None, false),
            fx(
                PEGOUT_ADDR,
                hex::encode(por_tx_a),
                0,
                assets_of(&[(&fbtc, gross_a)]),
                Some(pd_hex(&pegout_datum(&spk_a))),
                true,
            ),
            fx(
                PEGOUT_ADDR,
                hex::encode(por_tx_b),
                1,
                assets_of(&[(&fbtc, gross_b)]),
                Some(pd_hex(&pegout_datum(&spk_b))),
                true,
            ),
            // Value sent to the peg-out address that is not a request (no fBTC).
            fx(
                PEGOUT_ADDR,
                "ee".repeat(32),
                0,
                BTreeMap::new(),
                None,
                false,
            ),
            fx(
                CPO_ADDR,
                "cf".repeat(32),
                0,
                assets_of(&[(&cpo_unit, 1)]),
                Some(pd_hex(&cpo_datum)),
                false,
            ),
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
                // The DatumState kind must agree (Absent stays Absent, Resolved
                // stays Resolved) — the whole point of the shared fixture is that
                // "no datum" and "hash-only, resolved" are not confused by either
                // backend.
                assert_eq!(
                    datum_kind(&k.datum),
                    datum_kind(&b.datum),
                    "{}#{} datum state",
                    k.tx_hash,
                    k.output_index
                );
                assert_eq!(
                    k.datum.resolved().map(pd_hex),
                    b.datum.resolved().map(pd_hex),
                    "{}#{} datum",
                    k.tx_hash,
                    k.output_index
                );
            }
        }
    }

    #[tokio::test]
    async fn both_backends_find_the_bridge_state_singleton() {
        let (w, root) = world();
        let kupo = KupoHistory::new(&spawn_kupo(w.clone()).await);
        let bf = BlockfrostHistory::new("preprodtest", Some(&spawn_blockfrost(w).await));

        for (name, found) in [
            (
                "kupo",
                kupo.unspent_with_asset(CPO_POLICY, BSS_ASSET_NAME_HEX)
                    .await
                    .unwrap(),
            ),
            (
                "blockfrost",
                bf.unspent_with_asset(CPO_POLICY, BSS_ASSET_NAME_HEX)
                    .await
                    .unwrap(),
            ),
        ] {
            assert_eq!(found.len(), 1, "{name}: expected the singleton alone");
            assert_eq!(found[0].asset_quantity(CPO_POLICY, BSS_ASSET_NAME_HEX), 1);
            // `cpo_root` BY NAME, per [LIB-1].
            assert_eq!(
                parse_bridge_state(found[0].datum.resolved().expect("singleton datum"))
                    .unwrap()
                    .cpo_root,
                root,
                "{name}: singleton cpo_root"
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
    /// `datum: DatumState::Unresolved { .. }` — never as `Absent`, and never
    /// dropped — so `reconstruct` can hard-error on it by name. A backend that
    /// dropped the output, or reported it `Absent`, would produce a trie that
    /// silently omits a movement.
    ///
    /// Both backends must fail the SAME way. Kupo loses a preimage by being run
    /// with `--prune-utxo`; a Blockfrost-compatible API loses one by not serving
    /// `/scripts/datum/{hash}`. Different causes, identical verdict.
    #[tokio::test]
    async fn an_unresolvable_datum_hard_errors_the_same_way_on_both_backends() {
        // Kupo that knows the hash but answers `{"datum": null}`.
        let kupo_url = spawn_pruned_kupo(vec![fx(
            TM_ADDR,
            "a1".repeat(32),
            0,
            BTreeMap::new(),
            Some(pd_hex(&bytes(b"whatever"))),
            true,
        )])
        .await;
        // Blockfrost serving the SHARED world, whose Confirmed TM record is
        // hash-only, with both datum routes 404ing.
        let (w, _) = world();
        let bf_url = spawn_blockfrost_with(w, DatumRoute::Missing).await;

        let kupo = KupoHistory::new(&kupo_url);
        let bf = BlockfrostHistory::new("preprodtest", Some(&bf_url));

        // 1. The output is SURFACED, not dropped, by both.
        for (name, hist) in [
            ("kupo", kupo.address_history(TM_ADDR).await.unwrap()),
            ("blockfrost", bf.address_history(TM_ADDR).await.unwrap()),
        ] {
            let gap = hist
                .iter()
                .find(|o| matches!(o.datum, DatumState::Unresolved { .. }))
                .unwrap_or_else(|| panic!("{name}: the unresolvable output must still be listed"));
            assert!(
                gap.datum_note.contains("preimage"),
                "{name}: {}",
                gap.datum_note
            );
        }

        // 2. Reconstruction refuses to continue past it, on both.
        for (name, source) in [
            ("kupo", &kupo as &dyn CpoHistorySource),
            ("blockfrost", &bf as &dyn CpoHistorySource),
        ] {
            let err = reconstruct(source, &recon_cfg()).await.unwrap_err();
            assert!(matches!(err, CpoTrieError::Source(_)), "{name}: {err}");
            let msg = format!("{err}");
            assert!(msg.contains("unexplained gap"), "{name}: {msg}");
            assert!(
                msg.contains(source.datum_gap_advice()),
                "{name} must carry its OWN remediation: {msg}"
            );
        }
    }

    /// The hash-only path, end to end and on the shared fixture: the Confirmed TM
    /// record's datum lives behind `/scripts/datum/{hash}/cbor`, so a trie only
    /// comes out if that fetch worked. Kupo reads the same record through
    /// `/datums/{hash}` and must land on the same root.
    #[tokio::test]
    async fn blockfrost_resolves_a_hash_only_datum() {
        let (w, expected_root) = world();
        assert!(
            w.iter().any(|o| o.datum.is_some() && !o.inline),
            "the shared fixture must contain a hash-only datum"
        );
        let bf_url = spawn_blockfrost(w).await;
        let trie = reconstruct(
            &BlockfrostHistory::new("preprodtest", Some(&bf_url)),
            &recon_cfg(),
        )
        .await
        .expect("the hash-only datum must resolve through /scripts/datum/{hash}/cbor");
        assert_eq!(trie.root(), expected_root);
        assert_eq!(trie.len(), 2);
    }

    /// Some backends serve the CBOR on the plain `/scripts/datum/{hash}` route
    /// instead of the `/cbor` one. The client tries both before giving up.
    #[tokio::test]
    async fn blockfrost_falls_back_to_the_non_cbor_datum_route() {
        let (w, expected_root) = world();
        let bf_url = spawn_blockfrost_with(w, DatumRoute::NonCborRouteOnly).await;
        let trie = reconstruct(
            &BlockfrostHistory::new("preprodtest", Some(&bf_url)),
            &recon_cfg(),
        )
        .await
        .expect("the plain /scripts/datum/{hash} route must be tried too");
        assert_eq!(trie.root(), expected_root);
    }

    /// A backend that offers only the JSON-value form of a datum is "no preimage",
    /// never a guess. The JSON form cannot be re-serialized to the exact bytes the
    /// datum hash commits to, so accepting it would put unverifiable data into a
    /// trie this node signs with.
    #[tokio::test]
    async fn blockfrost_treats_a_json_only_datum_as_no_preimage() {
        let (w, _) = world();
        let bf_url = spawn_blockfrost_with(w, DatumRoute::JsonValueOnly).await;
        let err = reconstruct(
            &BlockfrostHistory::new("preprodtest", Some(&bf_url)),
            &recon_cfg(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CpoTrieError::Source(_)), "{err}");
        assert!(format!("{err}").contains("unexplained gap"), "{err}");
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
                        "datum_hash": o.datum.as_deref().map(datum_hash_hex),
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
            fx(
                TM_ADDR,
                "aa".repeat(32),
                1,
                BTreeMap::new(),
                Some(pd_hex(&bytes(b"mine"))),
                false,
            ),
            fx(
                "someone_else",
                "aa".repeat(32),
                0,
                BTreeMap::new(),
                Some(pd_hex(&bytes(b"theirs"))),
                false,
            ),
        ];
        let bf = BlockfrostHistory::new("preprodtest", Some(&spawn_blockfrost(world).await));
        let hist = bf.address_history(TM_ADDR).await.unwrap();
        assert_eq!(hist.len(), 1, "only the output AT the address");
        assert_eq!(hist[0].output_index, 1);
    }

    // -- retry classification ----------------------------------------------
    //
    // The Blockfrost path issues one request per transaction, so it WILL meet a
    // 429 on a long history. Misclassifying one costs the whole reconstruction:
    // giving up on a transient failure aborts a rare, expensive command, and
    // retrying a permanent one just repeats it. Each class is pinned separately.

    /// A server that replies with `codes[n]` to the nth request, then 200.
    ///
    /// Returns the URL and the request counter, so a test can assert HOW MANY
    /// attempts happened, not merely that the call eventually succeeded.
    async fn spawn_flaky(codes: Vec<u16>) -> (String, std::sync::Arc<AtomicUsize>) {
        use axum::extract::State;
        use axum::response::IntoResponse as _;
        use axum::routing::get;
        use std::sync::Arc;

        let hits = Arc::new(AtomicUsize::new(0));
        type S = (Arc<Vec<u16>>, Arc<AtomicUsize>);

        async fn handler(State((codes, hits)): State<S>) -> axum::response::Response {
            let n = hits.fetch_add(1, Ordering::SeqCst);
            match codes.get(n) {
                Some(&code) => (
                    axum::http::StatusCode::from_u16(code).unwrap(),
                    "backend says no",
                )
                    .into_response(),
                None => axum::Json(serde_json::json!([])).into_response(),
            }
        }

        let app = axum::Router::new()
            .route("/addresses/{address}/transactions", get(handler))
            .with_state((Arc::new(codes), Arc::clone(&hits)));
        (serve(app).await, hits)
    }

    /// Millisecond backoff so a retry assertion is not a seven-second test.
    fn fast_delays() -> Vec<std::time::Duration> {
        vec![
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(1),
        ]
    }

    #[tokio::test]
    async fn a_429_is_retried_until_it_succeeds() {
        let (url, hits) = spawn_flaky(vec![429]).await;
        let bf = BlockfrostHistory::new("preprodtest", Some(&url)).with_delays(fast_delays());
        bf.address_history("addr").await.expect("retried past 429");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "one retry, then success");
    }

    #[tokio::test]
    async fn a_5xx_is_retried_and_gives_up_after_the_schedule() {
        let (url, hits) = spawn_flaky(vec![503, 500, 502, 500]).await;
        let bf = BlockfrostHistory::new("preprodtest", Some(&url)).with_delays(fast_delays());
        let err = bf.address_history("addr").await.unwrap_err();
        assert!(
            err.contains("503") || err.contains("500") || err.contains("502"),
            "{err}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "attempts = delays + 1, then the error surfaces"
        );
    }

    #[tokio::test]
    async fn a_4xx_is_permanent_and_not_retried() {
        let (url, hits) = spawn_flaky(vec![400, 400, 400, 400]).await;
        let bf = BlockfrostHistory::new("preprodtest", Some(&url)).with_delays(fast_delays());
        let err = bf.address_history("addr").await.unwrap_err();
        assert!(err.contains("400"), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no retry for a 4xx");
    }

    /// 404 is an ANSWER — "no history at this address" — not a failure. Conflating
    /// it with an error would make a cold-start reconstruction of a fresh bridge
    /// fail instead of returning an empty trie.
    #[tokio::test]
    async fn a_404_is_an_empty_answer_not_an_error() {
        let (url, hits) = spawn_flaky(vec![404, 404, 404]).await;
        let bf = BlockfrostHistory::new("preprodtest", Some(&url)).with_delays(fast_delays());
        assert!(bf.address_history("addr").await.unwrap().is_empty());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no retry for a 404");
    }

    /// A 200 whose body is not JSON is the backend's final word, not a blip.
    #[tokio::test]
    async fn an_unparsable_body_is_permanent() {
        use axum::routing::get;
        use std::sync::Arc;
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/addresses/{address}/transactions",
            get(move || {
                let counted = Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, Ordering::SeqCst);
                    "not json at all"
                }
            }),
        );
        let url = serve(app).await;
        let bf = BlockfrostHistory::new("preprodtest", Some(&url)).with_delays(fast_delays());
        let err = bf.address_history("addr").await.unwrap_err();
        assert!(err.contains("json"), "{err}");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "no retry for a parse failure"
        );
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
            datum: DatumState::Absent,
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
