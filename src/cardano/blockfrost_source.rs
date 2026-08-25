//! `CardanoPegInSource` backed by the Blockfrost REST API.
//!
//! Uses the `blockfrost` crate's `BlockfrostAPI` client and OpenAPI
//! types. Server-side asset filtering via `addresses_utxos_asset`
//! keeps bandwidth low. The source does NOT decode the inline datum —
//! it hands the raw CBOR bytes to `parse_pegin_request`, which knows
//! the `PegInDatum` Constr shape.

use async_trait::async_trait;

use crate::cardano::bf_http;
use crate::cardano::pegin_source::{CardanoOutRef, CardanoPegInRequest, CardanoPegInSource};
use crate::epoch::state::{EpochError, EpochResult};

pub struct BlockfrostPegInSource {
    base_url: String,
    project_id: String,
    address: String,
    /// Where to re-read Config #6 from. `None` → the pinned `address` stands, which
    /// is what every non-Config deployment (fixtures, devnets) wants.
    refresh: Option<PegInRefresh>,
    /// The chain's per-batch pin, when this source was given it. Preferred over
    /// `refresh`: it is the ConfigView the batch was snapshotted from, so the
    /// address scanned here and the addresses the movement is built against cannot
    /// come from two reads that straddle a governance Update.
    shared: Option<crate::cardano::config_params::SharedContracts>,
}

/// Enough to locate the bridge Config and derive an address from it.
struct PegInRefresh {
    config_address: String,
    config_nft_unit: String,
    /// Decides only the bech32 network tag of the derived address; the hash is the
    /// datum's. Same single local input `ConfigParams::bridge_contracts` documents.
    mainnet: bool,
}

impl BlockfrostPegInSource {
    /// `project_id` is the Blockfrost API key (e.g. `preprodXXXXXX`).
    /// The network is auto-detected from the key prefix unless `blockfrost_url` overrides it.
    /// `address` is the bech32 script address carrying peg-in UTxOs.
    pub fn new(project_id: &str, address: impl Into<String>, blockfrost_url: Option<&str>) -> Self {
        Self {
            base_url: bf_http::base_url(project_id, blockfrost_url),
            project_id: project_id.to_string(),
            address: address.into(),
            refresh: None,
            shared: None,
        }
    }

    /// Scan the address the current batch was snapshotted against.
    ///
    /// Pass [`crate::cardano::blockfrost_chain::BlockfrostCardanoChain::contracts_cache`]
    /// so both objects answer from one Config read. Without it this source would
    /// take its own, and two reads are two chances to pair a new peg-in address
    /// with an old request policy — which filters every deposit out and reports an
    /// empty bridge.
    #[must_use]
    pub fn with_shared_contracts(
        mut self,
        shared: crate::cardano::config_params::SharedContracts,
    ) -> Self {
        self.shared = Some(shared);
        self
    }

    /// Re-read Config #6 on every scan instead of running forever on the boot read.
    ///
    /// This is the case that motivated the whole refresh: a governance Update moves
    /// `peg_in_script_hash`, and a node still scanning the retired address reports
    /// `0 eligible peg-ins` — indistinguishable from a bridge nobody is depositing
    /// to. Restarting does not fix it, it just moves the node to the other side of
    /// the disagreement. See `BlockfrostCardanoChain::current_contracts` for what
    /// this bounds and what it does not (the adoption point remains WI-2AHGZ).
    #[must_use]
    pub fn with_config_refresh(
        mut self,
        config_address: impl Into<String>,
        config_nft_unit: impl Into<String>,
        mainnet: bool,
    ) -> Self {
        self.refresh = Some(PegInRefresh {
            config_address: config_address.into(),
            config_nft_unit: config_nft_unit.into(),
            mainnet,
        });
        self
    }

    /// The peg-in address AND the request-NFT policy AS OF NOW, from ONE Config read.
    ///
    /// Both are Config #6. Taking them from a single read is the point: an Update
    /// landing between two reads would otherwise pair the new address with the old
    /// policy, and the scan would filter everything out and call it empty — the
    /// same silence, arrived at by a different route.
    ///
    /// `Ok(None)` → nothing to refresh from; the pinned pair stands.
    async fn current_pegin_contract(&self) -> EpochResult<Option<(String, String)>> {
        // The batch's own answer first — same Config read the movement is built
        // from, so the scan cannot disagree with it.
        let pinned_by_batch = self.shared.as_ref().and_then(|shared| {
            let slot = shared.lock().ok()?;
            let entry = slot.as_ref()?;
            Some((
                entry.contracts.pegin_script_address.clone(),
                entry.contracts.pegin_policy_id.clone(),
            ))
        });
        if pinned_by_batch.is_some() {
            return Ok(pinned_by_batch);
        }
        let Some(r) = &self.refresh else {
            return Ok(None);
        };
        // Retried rather than allowed to fall back: silently keeping the pinned copy
        // on a 502 is the same divergence with a network blip as its trigger.
        let view = crate::cardano::retry::retry_transient(
            &crate::cardano::retry::DEFAULT_DELAYS,
            "pegin-config",
            |_: &String| true,
            || {
                crate::cardano::config_params::fetch_config(
                    &self.base_url,
                    &self.project_id,
                    &r.config_address,
                    &r.config_nft_unit,
                )
            },
        )
        .await
        .map_err(|e| EpochError::Chain(format!("bridge Config (peg-in identity #6): {e}")))?;

        let contracts = view
            .params
            .bridge_contracts(r.mainnet)
            .map_err(|e| EpochError::Chain(format!("peg-in identity: {e}")))?;

        if contracts.pegin_script_address != self.address {
            tracing::warn!(
                "[pegin] the bridge Config now publishes a different peg-in address: {} -> {} \
                 (Config UTxO {}). This node follows the chain, not its startup snapshot",
                self.address,
                contracts.pegin_script_address,
                view.utxo
            );
        }
        Ok(Some((
            contracts.pegin_script_address,
            contracts.pegin_policy_id,
        )))
    }
}

#[async_trait]
impl CardanoPegInSource for BlockfrostPegInSource {
    async fn query_pegin_requests(
        &self,
        policy_id: &[u8; 28],
    ) -> EpochResult<Vec<CardanoPegInRequest>> {
        // Config #6, re-read when there is a Config to read it from. `policy_id` is
        // the caller's boot-time copy (EpochConfig::pegin_policy_id, pinned since
        // WI-070) and stands only when nothing can be refreshed.
        let refreshed = self.current_pegin_contract().await?;
        let (address, policy_hex) = refreshed.map_or_else(
            || (self.address.clone(), hex::encode(policy_id)),
            |(addr, pol)| (addr, pol),
        );

        // Fetch all UTxOs at the address (raw HTTP, lenient parse — tolerates backends like
        // yaci-devkit that omit `tx_index`) and filter by policy locally. (The asset-filtered
        // endpoint wants the FULL `<policy><name>` unit on some backends, so we don't rely on it.)
        let utxos = bf_http::fetch_address_utxos(&self.base_url, &self.project_id, &address)
            .await
            .map_err(EpochError::Chain)?;

        let mut out = Vec::new();
        for utxo in utxos {
            // Keep only UTxOs carrying a token under the peg-in policy.
            if !utxo.amount.iter().any(|a| a.unit.starts_with(&policy_hex)) {
                continue;
            }
            // Inline datum: Blockfrost returns the CBOR as a hex string.
            // We pass the raw bytes through — the parser decodes the
            // Constr shape.
            let Some(datum_hex) = &utxo.inline_datum else {
                continue;
            };
            let datum_cbor = match hex::decode(datum_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let tx_hash_bytes = match hex::decode(&utxo.tx_hash) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => continue,
            };

            out.push(CardanoPegInRequest {
                cardano_utxo: CardanoOutRef {
                    tx_hash: tx_hash_bytes,
                    output_index: utxo.output_index as u32,
                },
                datum_cbor,
                // Filled in below, once per DISTINCT creating transaction.
                created_slot: None,
            });
        }

        // Batch membership needs the CREATION SLOT of each request (WI-049), and
        // it is not in the UTxO listing. One `/txs/{hash}` per distinct creating
        // transaction, hours apart — the cost the peg-out side already pays.
        //
        // The tip is this source's own read rather than the caller's: it is only
        // consulted when the backend omits `slot` (yaci-devkit), and `slot_at_time`
        // is exact for post-Shelley one-second slots, so two SPOs holding different
        // reference pairs still derive the same slot for the same block. A tip we
        // cannot read leaves the slots unresolved, which defers rather than admits.
        //
        // NOTE THE UNIT: `fetch_latest_block_slot_time` reports POSIX **seconds**
        // and `slot_at_time` takes **milliseconds**. Passing it through unscaled
        // is silent — every request lands thousands of slots in the future and is
        // deferred for ever.
        let tip = bf_http::fetch_latest_block_slot_time(&self.base_url, &self.project_id)
            .await
            .ok()
            .map(|(slot, time_secs)| (slot, time_secs.saturating_mul(1000)));
        // Collected rather than passed as a borrowing iterator: a `.iter().map(..)`
        // held across the await makes the closure's lifetime not general enough for
        // the async trait method.
        let hashes: Vec<String> = out
            .iter()
            .map(|r| hex::encode(r.cardano_utxo.tx_hash))
            .collect();
        let resolved =
            bf_http::resolve_tx_slots(&self.base_url, &self.project_id, hashes, tip, "pegin").await;
        for req in &mut out {
            req.created_slot = resolved
                .get(&hex::encode(req.cardano_utxo.tx_hash))
                .copied()
                .flatten();
        }

        out.sort_by(|a, b| a.cardano_utxo.cmp(&b.cardano_utxo));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WI-2AHGZ: peg-in identity follows the chain when there is a chain to follow,
    /// and otherwise stays exactly where it was. The fallback arm is what every
    /// fixture and devnet runs on, so it must not become a fetch against nothing.
    #[tokio::test]
    async fn without_a_config_the_pinned_pegin_address_stands() {
        let src = BlockfrostPegInSource::new("preprodXXX", "addr_test1_pegin", None);
        assert!(src.current_pegin_contract().await.unwrap().is_none());
        assert_eq!(src.address, "addr_test1_pegin");
    }

    /// WI-2AHGZ: the batch's pin wins over this source's own read, and it is the
    /// SAME cell the chain writes — that is what stops the scan from pairing a
    /// peg-in address out of one Config read with a request policy out of another.
    #[tokio::test]
    async fn the_batch_pin_beats_this_source_s_own_read() {
        use crate::cardano::config_params::{BatchContracts, BridgeContracts};

        let shared: crate::cardano::config_params::SharedContracts = Default::default();
        let src = BlockfrostPegInSource::new("preprodXXX", "addr_test1_boot", None)
            // A locator IS present, so without the shared pin this would go to the
            // network. The pin has to take precedence over it, not merely over the
            // boot value.
            .with_config_refresh("addr_test1_config", "beef424946434647", false)
            .with_shared_contracts(std::sync::Arc::clone(&shared));

        *shared.lock().unwrap() = Some(BatchContracts {
            batch_key: Some(1_000),
            contracts: BridgeContracts {
                pegin_policy_id: "aa".repeat(28),
                pegin_script_address: "addr_test1_batch_pegin".into(),
                pegout_script_address: "addr_test1_batch_pegout".into(),
                bridged_token_unit: "bb".repeat(28),
                bridge_state_policy_id: "cc".repeat(28),
                tm_policy_id: "dd".repeat(28),
                tm_address: "addr_test1_tm".into(),
            },
            config_utxo: format!("{}#0", "ee".repeat(32)),
        });

        let (address, policy) = src
            .current_pegin_contract()
            .await
            .unwrap()
            .expect("the pin");
        assert_eq!(address, "addr_test1_batch_pegin");
        // And the POLICY comes from the same entry, not from the caller's boot copy.
        assert_eq!(policy, "aa".repeat(28));
    }

    /// The locator is recorded, not resolved eagerly: construction must stay free
    /// of I/O so a misconfigured backend fails at the first scan with a named
    /// error, not inside a constructor nobody is awaiting.
    #[test]
    fn the_refresh_locator_is_recorded_without_touching_the_network() {
        let src = BlockfrostPegInSource::new("preprodXXX", "addr_test1_pegin", None)
            .with_config_refresh("addr_test1_config", "beef424946434647", false);
        let r = src.refresh.as_ref().expect("locator recorded");
        assert_eq!(r.config_address, "addr_test1_config");
        assert_eq!(r.config_nft_unit, "beef424946434647");
        assert!(!r.mainnet);
        // Still pinned until something actually scans.
        assert_eq!(src.address, "addr_test1_pegin");
    }
}
