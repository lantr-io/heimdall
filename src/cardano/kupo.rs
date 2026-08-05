//! Minimal Kupo client — the chain-history reader the completed-peg-outs trie
//! reconstruction needs.
//!
//! ## Why Kupo and not Blockfrost
//!
//! Reconstruction (cold start, disaster recovery, a newly joined SPO) has to read
//! the inline datums of **spent** outputs: every Treasury Movement's `Unconfirmed`
//! record is spent by its own Confirm transition, and that spent record is where
//! the rev-5.1 data-availability hint (`fulfilled_por_outpoints`) lives. A
//! Blockfrost-compatible API indexes the *current* UTxO set by address; it cannot
//! answer "every output ever created at this address, spent ones included".
//! Kupo can: `GET /matches/{pattern}` returns created-and-since-spent matches with
//! their datum hashes, and `GET /datums/{hash}` returns the datum bytes.
//!
//! So Kupo is used ONLY on the reconstruction path. Steady-state operation stays
//! on the Blockfrost-compatible subset a Dolos node serves — see the endpoint list
//! in `cardano::cpo_trie`.
//!
//! ## Scope
//!
//! Two endpoints, no pagination (Kupo returns the full match list), no
//! authentication (Kupo is an unauthenticated local/edge service). Errors are
//! `String`, matching the convention in `cardano::bf_http`.

use std::collections::BTreeMap;

use pallas_primitives::PlutusData;
use serde::Deserialize;

/// Which matches to return: Kupo's `?spent` / `?unspent` query flags, or neither
/// (both).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchFilter {
    /// Every match ever created at the pattern, spent or not. Required for the
    /// TM-record scan — a Confirm transition spends the `Unconfirmed` record.
    All,
    /// Only outputs already consumed.
    Spent,
    /// Only outputs still in the UTxO set.
    Unspent,
}

impl MatchFilter {
    fn query(self) -> &'static str {
        match self {
            Self::All => "",
            Self::Spent => "?spent",
            Self::Unspent => "?unspent",
        }
    }
}

/// A point on the chain, as Kupo reports it.
#[derive(Debug, Clone, Deserialize)]
pub struct KupoPoint {
    pub slot_no: u64,
    #[serde(default)]
    pub header_hash: Option<String>,
    /// Present on `spent_at`: the transaction that consumed the output.
    #[serde(default)]
    pub transaction_id: Option<String>,
}

/// One Kupo match = one transaction output.
///
/// Deliberately lenient: only the fields heimdall reads are declared, so a Kupo
/// version that adds or renames anything else still parses.
#[derive(Debug, Clone, Deserialize)]
pub struct KupoMatch {
    pub transaction_id: String,
    pub output_index: u32,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub value: KupoValue,
    /// `None` for an output with no datum at all.
    #[serde(default)]
    pub datum_hash: Option<String>,
    /// `"inline"` or `"hash"`. Only `"inline"` datums are protocol-meaningful
    /// here — every Bifrost datum is inline — but the bytes are fetched the same
    /// way either.
    #[serde(default)]
    pub datum_type: Option<String>,
    /// Some Kupo deployments (and the test fixtures) inline the resolved datum in
    /// the match payload. When present it saves a `/datums/{hash}` round trip.
    #[serde(default)]
    pub datum: Option<String>,
    pub created_at: KupoPoint,
    /// `None` while the output is unspent.
    #[serde(default)]
    pub spent_at: Option<KupoPoint>,
}

/// The value of an output: lovelace plus native assets keyed `policy.name`
/// (Kupo's separator) — note this is NOT the Blockfrost `policy||name` unit.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct KupoValue {
    #[serde(default)]
    pub coins: u64,
    #[serde(default)]
    pub assets: BTreeMap<String, u64>,
}

impl KupoMatch {
    /// Is this output still unspent?
    #[must_use]
    pub fn is_unspent(&self) -> bool {
        self.spent_at.is_none()
    }

    /// Quantity of `policy_hex` / `asset_name_hex` in this output.
    ///
    /// Kupo keys assets `"<policy>.<name>"` and OMITS the dot for an empty asset
    /// name, so both spellings are accepted.
    #[must_use]
    pub fn asset_quantity(&self, policy_hex: &str, asset_name_hex: &str) -> u64 {
        let policy = policy_hex.to_ascii_lowercase();
        let name = asset_name_hex.to_ascii_lowercase();
        let dotted = format!("{policy}.{name}");
        self.value
            .assets
            .get(&dotted)
            .or_else(|| {
                if name.is_empty() {
                    self.value.assets.get(&policy)
                } else {
                    None
                }
            })
            .copied()
            .unwrap_or(0)
    }
}

/// A Kupo HTTP client.
///
/// Holds one `reqwest::Client` so reconstruction's many datum lookups reuse
/// connections (the `bf_http` per-call-client style would open a socket per
/// datum, and a long chain has thousands).
pub struct KupoClient {
    base_url: String,
    client: reqwest::Client,
}

impl KupoClient {
    /// `base_url` is the Kupo root, e.g. `http://localhost:1442`. A trailing
    /// slash is trimmed so URL joins never double it.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// `GET /matches/{pattern}` — every output matching `pattern` (an address, a
    /// policy id, `*`, …), filtered by `filter`.
    pub async fn matches(
        &self,
        pattern: &str,
        filter: MatchFilter,
    ) -> Result<Vec<KupoMatch>, String> {
        let url = format!("{}/matches/{}{}", self.base_url, pattern, filter.query());
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("kupo GET /matches/{pattern}: {e}"))?;
        let status = resp.status();
        // 404 means "the pattern matched nothing", not an error: an address with
        // no history is the normal cold-start state.
        if status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(format!(
                "kupo GET /matches/{pattern} http {status}: {}",
                resp.text().await.unwrap_or_default()
            ));
        }
        resp.json::<Vec<KupoMatch>>()
            .await
            .map_err(|e| format!("kupo /matches/{pattern} decode: {e}"))
    }

    /// `GET /datums/{hash}` — the datum bytes behind a datum hash. `Ok(None)` when
    /// Kupo does not have them (it only stores datums it has seen witnessed, and
    /// `--prune-utxo` deployments drop some).
    pub async fn datum_bytes(&self, datum_hash: &str) -> Result<Option<Vec<u8>>, String> {
        let url = format!("{}/datums/{datum_hash}", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("kupo GET /datums/{datum_hash}: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(format!(
                "kupo GET /datums/{datum_hash} http {status}: {}",
                resp.text().await.unwrap_or_default()
            ));
        }
        #[derive(Deserialize)]
        struct DatumResp {
            #[serde(default)]
            datum: Option<String>,
        }
        let body: DatumResp = resp
            .json()
            .await
            .map_err(|e| format!("kupo /datums/{datum_hash} decode: {e}"))?;
        // Kupo answers 200 with `{"datum": null}` for a hash it knows but whose
        // preimage it never witnessed — same meaning as 404 for our purposes.
        match body.datum {
            Some(hex_str) => hex::decode(hex_str.trim())
                .map(Some)
                .map_err(|e| format!("kupo /datums/{datum_hash} hex: {e}")),
            None => Ok(None),
        }
    }

    /// The inline datum of `m`, decoded as `PlutusData`.
    ///
    /// `Ok(None)` for an output with no datum, or one whose preimage Kupo cannot
    /// supply. A datum that IS present but does not decode is an error, not a
    /// `None` — silently dropping it would make reconstruction quietly incomplete.
    pub async fn resolve_datum(&self, m: &KupoMatch) -> Result<Option<PlutusData>, String> {
        let raw = match &m.datum {
            Some(hex_str) => Some(hex::decode(hex_str.trim()).map_err(|e| {
                format!(
                    "inline datum hex ({}#{}): {e}",
                    m.transaction_id, m.output_index
                )
            })?),
            None => match &m.datum_hash {
                Some(h) => self.datum_bytes(h).await?,
                None => None,
            },
        };
        let Some(bytes) = raw else { return Ok(None) };
        let pd: PlutusData = pallas_codec::minicbor::decode(&bytes)
            .map_err(|e| format!("datum cbor ({}#{}): {e}", m.transaction_id, m.output_index))?;
        Ok(Some(pd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
      {
        "transaction_index": 0,
        "transaction_id": "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44",
        "output_index": 1,
        "address": "addr_test1wq...",
        "value": { "coins": 2000000, "assets": { "c0ffee.43504f": 1 } },
        "datum_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "datum_type": "inline",
        "script_hash": null,
        "created_at": { "slot_no": 100, "header_hash": "abc" },
        "spent_at": { "slot_no": 200, "header_hash": "def", "transaction_id": "ff00" }
      },
      {
        "transaction_id": "bb11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44",
        "output_index": 0,
        "address": "addr_test1wq...",
        "value": { "coins": 5000000, "assets": {} },
        "datum_hash": null,
        "datum_type": null,
        "created_at": { "slot_no": 300, "header_hash": "ghi" },
        "spent_at": null
      }
    ]"#;

    #[test]
    fn parses_a_kupo_match_list() {
        let ms: Vec<KupoMatch> = serde_json::from_str(SAMPLE).unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].output_index, 1);
        assert!(!ms[0].is_unspent());
        assert_eq!(ms[0].spent_at.as_ref().unwrap().slot_no, 200);
        assert_eq!(ms[0].datum_type.as_deref(), Some("inline"));
        assert!(ms[1].is_unspent());
        assert_eq!(ms[1].created_at.slot_no, 300);
    }

    #[test]
    fn asset_quantity_reads_the_dotted_kupo_key() {
        let ms: Vec<KupoMatch> = serde_json::from_str(SAMPLE).unwrap();
        // "CPO" = 43504f
        assert_eq!(ms[0].asset_quantity("c0ffee", "43504f"), 1);
        assert_eq!(
            ms[0].asset_quantity("C0FFEE", "43504F"),
            1,
            "case-insensitive"
        );
        assert_eq!(ms[0].asset_quantity("c0ffee", "00"), 0);
        assert_eq!(ms[1].asset_quantity("c0ffee", "43504f"), 0);
    }

    #[test]
    fn asset_quantity_accepts_the_dotless_empty_name_key() {
        let json = r#"[{
          "transaction_id": "aa", "output_index": 0, "address": "x",
          "value": { "coins": 1, "assets": { "deadbeef": 1 } },
          "created_at": { "slot_no": 1 }
        }]"#;
        let ms: Vec<KupoMatch> = serde_json::from_str(json).unwrap();
        assert_eq!(ms[0].asset_quantity("deadbeef", ""), 1);
        assert_eq!(ms[0].asset_quantity("deadbeef", "43504f"), 0);
    }

    #[test]
    fn base_url_trailing_slash_is_trimmed() {
        assert_eq!(
            KupoClient::new("  http://localhost:1442/ ").base_url(),
            "http://localhost:1442"
        );
    }

    #[test]
    fn match_filter_query_strings() {
        assert_eq!(MatchFilter::All.query(), "");
        assert_eq!(MatchFilter::Spent.query(), "?spent");
        assert_eq!(MatchFilter::Unspent.query(), "?unspent");
    }
}
