//! register_spo R2: off-chain minimum-stake enforcement.
//!
//! The registry contract cannot read a pool's delegated stake (not
//! script-accessible), so SPOs enforce the threshold OFF-CHAIN: query the
//! pool's active stake and require it `>=` the protocol `min_stake` before
//! (a) building a register_spo tx and (b) admitting the SPO to the DKG
//! candidate set.
//!
//! `min_stake` is a protocol parameter — canonically the on-chain
//! `ConfigDatum.min_stake` ("Variables used offchain that must be
//! unquestionable"). Until heimdall reads the Config UTxO (WI-009-adjacent),
//! the threshold is supplied by the caller (`cardano.min_stake_lovelace`).
//!
//! The gate uses the epoch-snapshot `active_stake` (stable within an epoch),
//! NOT `live_stake`: every SPO checking the same candidate at the same epoch
//! boundary must reach the same verdict, and `live_stake` drifts intra-epoch.

use serde_json::Value;

/// A pool's stake (lovelace), from Blockfrost `/pools/{pool_id}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStake {
    /// Stake active for the current epoch (the epoch-boundary snapshot) — the
    /// value the min-stake gate compares against.
    pub active_stake: u64,
    /// Current live delegation (informational; drifts within an epoch).
    pub live_stake: u64,
}

/// Outcome of a min-stake check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinStakeCheck {
    /// `active_stake >= threshold`.
    pub meets: bool,
    pub active_stake: u64,
    pub threshold: u64,
}

/// Whether a pool's active stake meets the `min_stake` threshold (both
/// lovelace). At-threshold passes (`>=`).
#[must_use]
pub fn check_min_stake(stake: &PoolStake, min_stake_lovelace: u64) -> MinStakeCheck {
    MinStakeCheck {
        meets: stake.active_stake >= min_stake_lovelace,
        active_stake: stake.active_stake,
        threshold: min_stake_lovelace,
    }
}

/// Parse a Blockfrost `/pools/{pool_id}` JSON body into [`PoolStake`]. Stake
/// fields are decimal-string lovelace.
fn parse_pool_stake(v: &Value) -> Result<PoolStake, String> {
    let field = |name: &str| -> Result<u64, String> {
        v.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("pool: missing/non-string `{name}`"))?
            .parse::<u64>()
            .map_err(|e| format!("pool: bad `{name}`: {e}"))
    };
    Ok(PoolStake {
        active_stake: field("active_stake")?,
        live_stake: field("live_stake")?,
    })
}

/// Fetch a pool's stake from Blockfrost `/pools/{pool_id}`.
///
/// `pool_id` is the **bech32** pool id (`pool1…`); register_spo's 28-byte pool
/// key hash (`blake2b_224(cold_vkey)`) must be bech32-encoded with the `pool`
/// HRP before calling. A 404 means the pool is not registered (or retired).
pub async fn fetch_pool_stake(
    base_url: &str,
    project_id: &str,
    pool_id: &str,
) -> Result<PoolStake, String> {
    let url = format!("{base_url}/pools/{pool_id}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("pool request: {e}"))?;
    if resp.status().as_u16() == 404 {
        return Err(format!(
            "pool {pool_id} not found (not registered / retired?)"
        ));
    }
    if !resp.status().is_success() {
        return Err(format!(
            "pool http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: Value = resp.json().await.map_err(|e| format!("pool json: {e}"))?;
    parse_pool_stake(&v)
}

/// Where per-pool active stake is read from. The default keeps the
/// preprod/mainnet path (Blockfrost `/pools/{id}`) byte-for-byte unchanged;
/// `YaciStore` is opt-in for a local yaci-devkit devnet, which does not
/// implement `/pools/{id}` and instead exposes per-epoch per-pool stake at
/// `/epochs/{epoch}/pools/{id}/stake`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StakeSource {
    #[default]
    Blockfrost,
    YaciStore,
}

impl StakeSource {
    /// Parse `cardano.stake_source`. `None`/`"blockfrost"` → [`Self::Blockfrost`];
    /// `"yaci_store"`/`"yaci-store"`/`"yaci"` → [`Self::YaciStore`].
    pub fn from_config(s: Option<&str>) -> Result<Self, String> {
        match s.map(|x| x.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("blockfrost") => Ok(Self::Blockfrost),
            Some("yaci_store") | Some("yaci-store") | Some("yaci") => Ok(Self::YaciStore),
            Some(other) => Err(format!(
                "unknown cardano.stake_source {other:?} (use \"blockfrost\" or \"yaci_store\")"
            )),
        }
    }
}

/// Lenient lovelace parse: yaci-store returns numbers, Blockfrost decimal
/// strings.
fn lovelace_field(v: &Value, name: &str) -> Result<u64, String> {
    match v.get(name) {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("`{name}` is not a u64: {n}")),
        Some(Value::String(s)) => s.parse::<u64>().map_err(|e| format!("bad `{name}`: {e}")),
        _ => Err(format!("missing/invalid `{name}`")),
    }
}

/// A pool's active stake from a yaci-devkit devnet:
/// `GET /epochs/{epoch}/pools/{pool_id}/stake` → `{ active_stake }`. `pool_id`
/// may be bech32 (`pool1…`) or hex. yaci-store reports no `live_stake`, so it
/// mirrors `active_stake` (the gate keys on active stake anyway).
pub async fn fetch_pool_stake_yaci(
    base_url: &str,
    project_id: &str,
    epoch: u64,
    pool_id: &str,
) -> Result<PoolStake, String> {
    let url = format!("{base_url}/epochs/{epoch}/pools/{pool_id}/stake");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("pool stake request: {e}"))?;
    if resp.status().as_u16() == 404 {
        // No snapshot row for this pool at this epoch → not yet active.
        return Ok(PoolStake {
            active_stake: 0,
            live_stake: 0,
        });
    }
    if !resp.status().is_success() {
        return Err(format!(
            "pool stake http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: Value = resp
        .json()
        .await
        .map_err(|e| format!("pool stake json: {e}"))?;
    let active = lovelace_field(&v, "active_stake")?;
    Ok(PoolStake {
        active_stake: active,
        live_stake: active,
    })
}

/// Fetch a pool's stake from the configured [`StakeSource`]. `epoch` is used
/// only by [`StakeSource::YaciStore`]; the Blockfrost path ignores it and is
/// unchanged.
pub async fn fetch_pool_stake_src(
    source: StakeSource,
    base_url: &str,
    project_id: &str,
    epoch: u64,
    pool_id_bech32: &str,
) -> Result<PoolStake, String> {
    match source {
        StakeSource::Blockfrost => fetch_pool_stake(base_url, project_id, pool_id_bech32).await,
        StakeSource::YaciStore => {
            fetch_pool_stake_yaci(base_url, project_id, epoch, pool_id_bech32).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_min_stake_uses_active_and_is_inclusive() {
        let stake = PoolStake {
            active_stake: 1_000_000,
            live_stake: 1_200_000,
        };
        assert!(check_min_stake(&stake, 1_000_000).meets); // at threshold → passes
        assert!(check_min_stake(&stake, 999_999).meets);
        assert!(!check_min_stake(&stake, 1_000_001).meets);

        // The gate keys on ACTIVE stake, never live (which can be inflated
        // intra-epoch); a low active stake fails regardless of live.
        let below = PoolStake {
            active_stake: 500,
            live_stake: u64::MAX,
        };
        let c = check_min_stake(&below, 1_000);
        assert!(!c.meets);
        assert_eq!(c.active_stake, 500);
        assert_eq!(c.threshold, 1_000);
    }

    #[test]
    fn parse_pool_stake_ok_and_rejects_bad() {
        let good = serde_json::json!({
            "pool_id": "pool1abc",
            "active_stake": "123456789",
            "live_stake": "200000000",
        });
        let s = parse_pool_stake(&good).unwrap();
        assert_eq!(s.active_stake, 123_456_789);
        assert_eq!(s.live_stake, 200_000_000);

        // missing field
        assert!(parse_pool_stake(&serde_json::json!({ "active_stake": "1" })).is_err());
        // non-numeric
        assert!(
            parse_pool_stake(&serde_json::json!({ "active_stake": "x", "live_stake": "1" }))
                .is_err()
        );
        // number instead of string (Blockfrost sends strings)
        assert!(
            parse_pool_stake(&serde_json::json!({ "active_stake": 1, "live_stake": 2 })).is_err()
        );
    }

    #[test]
    fn stake_source_from_config_defaults_to_blockfrost() {
        // Default (preprod path) is preserved: unset / "blockfrost" → Blockfrost.
        assert_eq!(
            StakeSource::from_config(None).unwrap(),
            StakeSource::Blockfrost
        );
        assert_eq!(
            StakeSource::from_config(Some("")).unwrap(),
            StakeSource::Blockfrost
        );
        assert_eq!(
            StakeSource::from_config(Some("Blockfrost")).unwrap(),
            StakeSource::Blockfrost
        );
        // Opt-in devnet aliases.
        for s in ["yaci_store", "yaci-store", "YACI", "yaci"] {
            assert_eq!(
                StakeSource::from_config(Some(s)).unwrap(),
                StakeSource::YaciStore
            );
        }
        assert!(StakeSource::from_config(Some("nope")).is_err());
    }

    #[test]
    fn yaci_lovelace_field_accepts_number_and_string() {
        // yaci-store sends a JSON number; tolerate a string too.
        assert_eq!(
            lovelace_field(
                &serde_json::json!({ "active_stake": 300000000000u64 }),
                "active_stake"
            )
            .unwrap(),
            300_000_000_000
        );
        assert_eq!(
            lovelace_field(&serde_json::json!({ "active_stake": "42" }), "active_stake").unwrap(),
            42
        );
        assert!(lovelace_field(&serde_json::json!({}), "active_stake").is_err());
    }
}
