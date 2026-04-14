//! `CardanoChain` backed by Blockfrost.
//!
//! Finds the treasury oracle UTxO by scanning all UTxOs at the
//! treasury address and picking the most recent one that carries a
//! datum. The datum is `Constr(X, [BoundedBytes(raw_btc_tx)])` —
//! we extract the BTC tx hex from the JSON, deserialize, and take
//! output 0 as the treasury.
//!
//! `submit_signed_tm` builds a Cardano transaction that **creates a
//! new UTxO** at the treasury address with the signed BTC tx as an
//! inline datum. The old oracle UTxO is NOT spent — old confirmed
//! UTxOs are kept on-chain for minting proofs.

use std::sync::Mutex;

use async_trait::async_trait;
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use blockfrost::{BlockFrostSettings, BlockfrostAPI, Pagination};

use pallas_wallet::PrivateKey;

use crate::cardano::btc_rpc::{broadcast_btc_tx, BtcRpcConfig};
use crate::cardano::publish::{build_oracle_update_tx, WalletUtxo};
use crate::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
use crate::cardano::treasury_datum::TreasuryConfig;
use crate::epoch::state::{EpochError, EpochResult, Roster};
use crate::epoch::traits::{
    CardanoChain, EpochBoundaryEvent, PegOutRequestUtxo, TreasuryUtxo,
};

pub struct BlockfrostCardanoChain {
    api: BlockfrostAPI,
    /// Bech32 address holding the treasury oracle UTxOs.
    treasury_address: String,
    /// Policy ID of the treasury marker token (28 bytes hex).
    treasury_policy_id: String,
    /// Asset name of the treasury marker token (hex).
    treasury_asset_name_hex: String,
    /// Off-chain treasury parameters (leaf keys, CSV, fees).
    treasury_config: TreasuryConfig,
    /// Fallback roster.
    fallback_roster: Roster,
    /// Mnemonic-derived payment key for the Cardano wallet that pays
    /// fees. `None` means publishing is disabled (dry run).
    payment_key: Option<PrivateKey>,
    /// Full CIP-1852 base address (`payment_pkh + staking_pkh`) derived
    /// from the mnemonic. Used for Blockfrost UTxO queries so funds at
    /// the user's normal wallet address are found.
    wallet_base_address: Option<String>,
    /// After DKG, `publish_group_key` stores the FROST group key here.
    /// `query_treasury` returns this as Y_51 so the FROST group can
    /// sign the treasury input (same pattern as MockCardanoChain).
    treasury_y_51: Mutex<Option<bitcoin::key::UntweakedPublicKey>>,
    /// Optional bitcoind JSON-RPC config for direct BTC tx broadcast.
    btc_rpc: Option<BtcRpcConfig>,
    /// Whether to broadcast the signed BTC tx to Bitcoin (requires btc_rpc).
    submit_btc: bool,
    /// Whether to publish an oracle-update UTxO to Cardano after signing.
    submit_oracle: bool,
    /// Constructor tag used in the oracle datum (0 = unconfirmed, 1 = confirmed).
    oracle_constructor: u8,
}

impl BlockfrostCardanoChain {
    pub fn new(
        project_id: &str,
        treasury_address: impl Into<String>,
        treasury_policy_id: impl Into<String>,
        treasury_asset_name_hex: impl Into<String>,
        treasury_config: TreasuryConfig,
        fallback_roster: Roster,
    ) -> Self {
        let api = BlockfrostAPI::new(project_id, BlockFrostSettings::new());
        Self {
            api,
            treasury_address: treasury_address.into(),
            treasury_policy_id: treasury_policy_id.into(),
            treasury_asset_name_hex: treasury_asset_name_hex.into(),
            treasury_config,
            fallback_roster,
            payment_key: None,
            wallet_base_address: None,
            treasury_y_51: Mutex::new(None),
            btc_rpc: None,
            submit_btc: true,
            submit_oracle: true,
            oracle_constructor: 0,
        }
    }

    /// Override submission flags from config.
    pub fn with_submit_config(mut self, submit_btc: bool, submit_oracle: bool, oracle_constructor: u8) -> Self {
        self.submit_btc = submit_btc;
        self.submit_oracle = submit_oracle;
        self.oracle_constructor = oracle_constructor;
        self
    }

    /// Configure direct Bitcoin RPC broadcast. When set,
    /// `submit_signed_tm` sends the signed BTC tx to bitcoind via
    /// `sendrawtransaction` instead of posting to the Cardano oracle.
    pub fn with_btc_rpc(
        mut self,
        url: impl Into<String>,
        user: Option<String>,
        pass: Option<String>,
    ) -> Self {
        self.btc_rpc = Some(BtcRpcConfig {
            url: url.into(),
            user,
            pass,
        });
        self
    }

    /// Configure publishing from a BIP-39 mnemonic. The payment key is
    /// derived at `m/1852'/1815'/0'/0/0` (CIP-1852). The wallet base
    /// address (payment_pkh + staking_pkh) is derived for UTxO queries.
    pub fn with_mnemonic(mut self, mnemonic: &str) -> EpochResult<Self> {
        let key = derive_payment_key(mnemonic)
            .map_err(|e| EpochError::Chain(format!("derive payment key: {e}")))?;
        let base_addr = wallet_address_from_mnemonic(mnemonic)
            .map_err(|e| EpochError::Chain(format!("derive wallet address: {e}")))?;
        self.payment_key = Some(key);
        self.wallet_base_address = Some(base_addr);
        Ok(self)
    }

    /// Fetch all UTxOs at the wallet base address.
    async fn query_wallet_utxos(&self) -> EpochResult<Vec<WalletUtxo>> {
        let wallet_addr = self
            .wallet_base_address
            .as_deref()
            .ok_or_else(|| EpochError::Chain("no wallet address — was with_mnemonic called?".into()))?;

        let utxos = match self
            .api
            .addresses_utxos(wallet_addr, Pagination::all())
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
            .addresses_utxos(&self.treasury_address, Pagination::all())
            .await
            .map_err(|e| EpochError::Chain(format!("blockfrost treasury query: {e}")))?;

        let asset_unit = format!(
            "{}{}",
            self.treasury_policy_id, self.treasury_asset_name_hex
        );
        let utxo = utxos
            .iter()
            .rev()
            .find(|u| {
                u.inline_datum.is_some()
                    && u.amount.iter().any(|a| a.unit == asset_unit)
            })
            .ok_or_else(|| {
                EpochError::Chain(format!(
                    "no UTxO with an inline datum and marker token ({asset_unit}) at treasury address {}",
                    self.treasury_address
                ))
            })?;

        let inline_datum_str = utxo.inline_datum.as_deref().unwrap();
        let json_value: serde_json::Value = serde_json::from_str(inline_datum_str)
            .map_err(|e| EpochError::Chain(format!("inline datum JSON parse: {e}")))?;

        eprintln!(
            "[blockfrost] treasury datum JSON:\n{}",
            serde_json::to_string_pretty(&json_value).unwrap_or_default()
        );

        // constructor 0 = unsigned/unconfirmed, constructor 1 = confirmed.
        let constructor = json_value
            .get("constructor")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);
        let btc_confirmed = constructor == 1;

        let btc_tx_hex = json_value
            .get("fields")
            .and_then(|f| f.as_array())
            .and_then(|arr| arr.first())
            .and_then(|field| field.get("bytes"))
            .and_then(|b| b.as_str())
            .ok_or_else(|| {
                EpochError::Chain(format!(
                    "unexpected datum JSON shape: {}",
                    serde_json::to_string_pretty(&json_value).unwrap_or_default()
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

        let maybe_key = *self.treasury_y_51.lock().unwrap();
        let y_51 = maybe_key.unwrap_or(self.treasury_config.y_51);
        // After DKG: Y_fed = Y_67 = Y_51 = FROST group key (same key everywhere).
        let (y_67, y_fed) = match maybe_key {
            Some(k) => (k, k),
            None => (self.treasury_config.y_67, self.treasury_config.y_fed),
        };

        Ok(TreasuryUtxo {
            outpoint: bitcoin::OutPoint { txid, vout: 0 },
            value: out.value,
            y_51,
            y_67,
            y_fed,
            federation_csv_blocks: self.treasury_config.federation_csv_blocks,
            fee_rate_sat_per_vb: self.treasury_config.fee_rate_sat_per_vb,
            per_pegout_fee: self.treasury_config.per_pegout_fee,
            btc_confirmed,
        })
    }

    async fn publish_group_key(&self, y_51: bitcoin::key::UntweakedPublicKey) -> EpochResult<()> {
        *self.treasury_y_51.lock().unwrap() = Some(y_51);
        Ok(())
    }

    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>> {
        Ok(vec![])
    }

    async fn submit_signed_tm(&self, tx_bytes: &[u8]) -> EpochResult<()> {
        eprintln!(
            "[submit] signed BTC tx: {} bytes, hex: {}",
            tx_bytes.len(),
            hex::encode(tx_bytes)
        );

        // Broadcast the signed BTC tx to Bitcoin if configured and enabled.
        if self.submit_btc {
            match &self.btc_rpc {
                Some(rpc) => broadcast_btc_tx(rpc, tx_bytes).await?,
                None => eprintln!("[submit] bitcoin.submit=true but rpc_url not set — skipping BTC broadcast"),
            }
        } else {
            eprintln!("[submit] bitcoin.submit=false — skipping BTC broadcast");
        }

        // Publish the oracle update to Cardano if enabled.
        if !self.submit_oracle {
            eprintln!("[submit] cardano.submit_oracle=false — skipping Cardano oracle publish");
            return Ok(());
        }

        let key = match &self.payment_key {
            Some(k) => k,
            None => {
                eprintln!("[submit] no mnemonic configured — skipping Cardano oracle publish (dry run)");
                return Ok(());
            }
        };

        let wallet_addr = self
            .wallet_base_address
            .as_deref()
            .ok_or_else(|| EpochError::Chain("no wallet base address".into()))?;

        eprintln!("[submit] querying wallet UTxOs at {wallet_addr}");
        let wallet_utxos = self.query_wallet_utxos().await?;
        if wallet_utxos.is_empty() {
            return Err(EpochError::Chain(format!(
                "wallet has no UTxOs — fund it before publishing (address: {wallet_addr})"
            )));
        }

        let total_lovelace: u64 = wallet_utxos.iter().map(|u| u.lovelace).sum();
        eprintln!(
            "[submit] wallet: {} UTxO(s), {} lovelace total",
            wallet_utxos.len(), total_lovelace,
        );
        eprintln!(
            "[submit] building Cardano oracle-update tx: treasury={} constructor={} policy={}",
            self.treasury_address, self.oracle_constructor, self.treasury_policy_id
        );

        let signed_tx_hex = build_oracle_update_tx(
            &self.treasury_address,
            wallet_addr,
            &self.treasury_policy_id,
            &self.treasury_asset_name_hex,
            tx_bytes,
            self.oracle_constructor,
            &wallet_utxos,
            key,
        )?;

        let cardano_tx_cbor = hex::decode(&signed_tx_hex)
            .map_err(|e| EpochError::Chain(format!("tx hex decode: {e}")))?;

        eprintln!(
            "[submit] submitting Cardano oracle-update tx ({} bytes CBOR) via Blockfrost",
            cardano_tx_cbor.len()
        );

        let tx_hash = self
            .api
            .transactions_submit(cardano_tx_cbor)
            .await
            .map_err(|e| EpochError::Chain(format!("blockfrost tx submit: {e}")))?;

        eprintln!("[submit] Cardano oracle-update submitted: tx_hash={tx_hash}");

        Ok(())
    }
}

