//! `CardanoChain` backed by Blockfrost.
//!
//! Finds the treasury oracle UTxO by looking for a specific policy ID +
//! asset name, then fetches its datum via the `/scripts/datum/{hash}`
//! JSON endpoint to avoid CBOR chunked-bytestring issues. The datum is
//! `Constr(0, [BoundedBytes(raw_btc_tx)])` — we extract the BTC tx hex
//! from the JSON, deserialize, and take output 0 as the treasury.
//!
//! `submit_signed_tm` builds a Cardano transaction (via whisky) that
//! spends the current oracle UTxO and creates a new one with the signed
//! BTC tx as the updated datum, then submits it via Blockfrost.

use std::sync::Mutex;

use async_trait::async_trait;
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use blockfrost::{BlockFrostSettings, BlockfrostAPI, Pagination};

use pallas_wallet::PrivateKey;

use crate::cardano::publish::{build_oracle_update_tx, OracleUtxoInfo, WalletUtxo};
use crate::cardano::wallet::{derive_payment_key, wallet_address};
use crate::cardano::treasury_datum::TreasuryConfig;
use crate::epoch::state::{EpochError, EpochResult, Roster};
use crate::epoch::traits::{
    CardanoChain, EpochBoundaryEvent, PegOutRequestUtxo, TreasuryUtxo,
};

pub struct BlockfrostCardanoChain {
    api: BlockfrostAPI,
    /// Bech32 address holding the treasury oracle UTxO.
    treasury_address: String,
    /// Policy ID portion of the treasury marker (28 bytes hex).
    treasury_policy_id: String,
    /// Asset name portion of the treasury marker (hex).
    treasury_asset_name_hex: String,
    /// Concatenated hex `<policy_id><asset_name_hex>`.
    treasury_asset: String,
    /// Off-chain treasury parameters (leaf keys, CSV, fees).
    treasury_config: TreasuryConfig,
    /// Fallback roster.
    fallback_roster: Roster,
    /// Always-succeeds script CBOR hex (for the witness set).
    script_cbor_hex: String,
    /// Mnemonic-derived payment key for the Cardano wallet that pays
    /// fees. `None` means publishing is disabled (dry run).
    payment_key: Option<PrivateKey>,
    /// Cached oracle UTxO info from the last `query_treasury` call.
    cached_oracle: Mutex<Option<OracleUtxoInfo>>,
}

impl BlockfrostCardanoChain {
    pub fn new(
        project_id: &str,
        treasury_address: impl Into<String>,
        treasury_policy_id: &str,
        treasury_asset_name_hex: &str,
        treasury_config: TreasuryConfig,
        fallback_roster: Roster,
    ) -> Self {
        let api = BlockfrostAPI::new(project_id, BlockFrostSettings::new());
        let script_cbor = crate::cardano::always_ok::always_ok_script_cbor();
        Self {
            api,
            treasury_address: treasury_address.into(),
            treasury_policy_id: treasury_policy_id.to_string(),
            treasury_asset_name_hex: treasury_asset_name_hex.to_string(),
            treasury_asset: format!("{treasury_policy_id}{treasury_asset_name_hex}"),
            treasury_config,
            fallback_roster,
            script_cbor_hex: hex::encode(script_cbor),
            payment_key: None,
            cached_oracle: Mutex::new(None),
        }
    }

    /// Configure publishing from a BIP-39 mnemonic. The payment key is
    /// derived at `m/1852'/1815'/0'/0/0` (CIP-1852), the wallet address
    /// is derived from that key, and UTxOs are queried from Blockfrost
    /// automatically — no manual collateral needed.
    pub fn with_mnemonic(mut self, mnemonic: &str) -> EpochResult<Self> {
        let key = derive_payment_key(mnemonic)
            .map_err(|e| EpochError::Chain(format!("derive payment key: {e}")))?;
        self.payment_key = Some(key);
        Ok(self)
    }

    /// Fetch all UTxOs at the wallet address (derived from the payment key).
    async fn query_wallet_utxos(&self, key: &PrivateKey) -> EpochResult<Vec<WalletUtxo>> {
        let wallet_addr = wallet_address(key);
        let utxos = match self
            .api
            .addresses_utxos(&wallet_addr, Pagination::all())
            .await
        {
            Ok(u) => u,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("404") || msg.contains("Not Found") {
                    return Ok(vec![]);
                }
                return Err(EpochError::Chain(format!(
                    "blockfrost wallet UTxO query: {e}"
                )));
            }
        };

        Ok(utxos
            .iter()
            .map(|u| {
                let lovelace: u64 = u
                    .amount
                    .iter()
                    .find(|a| a.unit == "lovelace")
                    .map(|a| a.quantity.parse().unwrap_or(0))
                    .unwrap_or(0);
                WalletUtxo {
                    tx_hash: u.tx_hash.clone(),
                    output_index: u.output_index as u32,
                    lovelace,
                }
            })
            .collect())
    }
}

#[async_trait]
impl CardanoChain for BlockfrostCardanoChain {
    async fn await_epoch_boundary(&self) -> EpochResult<EpochBoundaryEvent> {
        Ok(EpochBoundaryEvent { epoch: 0 })
    }

    async fn query_roster(&self, _epoch: u64) -> EpochResult<Roster> {
        Ok(self.fallback_roster.clone())
    }

    async fn query_treasury(&self) -> EpochResult<TreasuryUtxo> {
        let utxos = self
            .api
            .addresses_utxos_asset(
                &self.treasury_address,
                &self.treasury_asset,
                Pagination::all(),
            )
            .await
            .map_err(|e| EpochError::Chain(format!("blockfrost treasury query: {e}")))?;

        let utxo = utxos.first().ok_or_else(|| {
            EpochError::Chain(format!(
                "no UTxO carrying asset {} at {}",
                self.treasury_asset, self.treasury_address
            ))
        })?;

        // Cache the oracle UTxO details for submit_signed_tm.
        let tx_hash_bytes = hex::decode(&utxo.tx_hash)
            .map_err(|e| EpochError::Chain(format!("tx_hash hex: {e}")))?;
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&tx_hash_bytes);

        let lovelace: u64 = utxo
            .amount
            .iter()
            .find(|a| a.unit == "lovelace")
            .map(|a| a.quantity.parse().unwrap_or(0))
            .unwrap_or(0);

        {
            let mut cached = self.cached_oracle.lock().unwrap();
            *cached = Some(OracleUtxoInfo {
                tx_hash,
                tx_index: utxo.output_index as u64,
                lovelace,
            });
        }

        // Use the datum hash to fetch via the JSON endpoint.
        let datum_hash = utxo.data_hash.as_deref().ok_or_else(|| {
            EpochError::Chain("treasury UTxO has no data_hash".into())
        })?;

        let datum_json = self
            .api
            .scripts_datum_hash(datum_hash)
            .await
            .map_err(|e| EpochError::Chain(format!("blockfrost datum fetch: {e}")))?;

        let btc_tx_hex = datum_json
            .get("json_value")
            .and_then(|jv| jv.get("fields"))
            .and_then(|f| f.as_array())
            .and_then(|arr| arr.first())
            .and_then(|field| field.get("bytes"))
            .and_then(|b| b.as_str())
            .ok_or_else(|| {
                EpochError::Chain(format!(
                    "unexpected datum JSON shape: {}",
                    serde_json::to_string_pretty(&datum_json).unwrap_or_default()
                ))
            })?;

        let tx_bytes = hex::decode(btc_tx_hex)
            .map_err(|e| EpochError::Chain(format!("datum BTC tx hex: {e}")))?;
        let tx: Transaction = deserialize(&tx_bytes)
            .map_err(|e| EpochError::Chain(format!("BTC tx deserialize: {e}")))?;

        let out = tx.output.first().ok_or_else(|| {
            EpochError::Chain("BTC tx in treasury datum has no outputs".into())
        })?;
        let txid = tx.compute_txid();

        Ok(TreasuryUtxo {
            outpoint: bitcoin::OutPoint { txid, vout: 0 },
            value: out.value,
            y_67: self.treasury_config.y_67,
            y_fed: self.treasury_config.y_fed,
            federation_csv_blocks: self.treasury_config.federation_csv_blocks,
            fee_rate_sat_per_vb: self.treasury_config.fee_rate_sat_per_vb,
            per_pegout_fee: self.treasury_config.per_pegout_fee,
        })
    }

    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>> {
        Ok(vec![])
    }

    async fn submit_signed_tm(&self, tx_bytes: &[u8]) -> EpochResult<()> {
        let key = match &self.payment_key {
            Some(k) => k,
            None => {
                eprintln!(
                    "[blockfrost] submit_signed_tm: no mnemonic configured, \
                     skipping Cardano publish (dry run)"
                );
                return Ok(());
            }
        };

        let oracle = self
            .cached_oracle
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| {
                EpochError::Chain(
                    "no cached oracle UTxO — was query_treasury called?".into(),
                )
            })?;

        // Query wallet UTxOs from Blockfrost for coin selection.
        let wallet_utxos = self.query_wallet_utxos(key).await?;
        if wallet_utxos.is_empty() {
            return Err(EpochError::Chain(
                "wallet has no UTxOs — fund it before publishing".into(),
            ));
        }

        let total_lovelace: u64 = wallet_utxos.iter().map(|u| u.lovelace).sum();
        eprintln!(
            "[blockfrost] wallet has {} UTxOs ({} lovelace total)",
            wallet_utxos.len(),
            total_lovelace,
        );

        let signed_tx_hex = build_oracle_update_tx(
            &oracle,
            &self.treasury_address,
            &self.treasury_policy_id,
            &self.treasury_asset_name_hex,
            &self.script_cbor_hex,
            tx_bytes,
            &wallet_utxos,
            key,
        )?;

        let cardano_tx_cbor = hex::decode(&signed_tx_hex)
            .map_err(|e| EpochError::Chain(format!("tx hex decode: {e}")))?;

        eprintln!(
            "[blockfrost] submitting oracle update tx ({} bytes CBOR)",
            cardano_tx_cbor.len()
        );

        let tx_hash = self
            .api
            .transactions_submit(cardano_tx_cbor)
            .await
            .map_err(|e| EpochError::Chain(format!("blockfrost tx submit: {e}")))?;

        eprintln!("[blockfrost] oracle update submitted: {tx_hash}");

        Ok(())
    }
}
