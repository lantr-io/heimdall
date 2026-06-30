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
use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use blockfrost::{BlockFrostSettings, BlockfrostAPI, Pagination};
use pallas_codec::minicbor;
use pallas_primitives::conway::PlutusData;
use pallas_wallet::PrivateKey;

use crate::cardano::btc_rpc::{BtcRpcConfig, broadcast_btc_tx};
use crate::cardano::publish::{WalletUtxo, build_oracle_update_tx};
use crate::cardano::treasury_datum::TreasuryConfig;
use crate::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
use crate::epoch::state::{EpochError, EpochResult, Roster};
use crate::epoch::traits::{CardanoChain, EpochBoundaryEvent, PegOutRequestUtxo, TreasuryUtxo};

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
    /// On-chain SPO registry source. When set, `query_roster` reads the
    /// real registry (verified against the `treasury_info` identity root)
    /// and any failure is a hard error — it never silently falls back to
    /// `fallback_roster`, which would let SPOs run DKG on divergent rosters.
    registry_roster: Option<crate::cardano::roster::RegistryRosterSource>,
    /// On-chain ban-list source. When set (alongside `registry_roster`),
    /// `query_roster` subtracts pools actively banned for the epoch before
    /// computing the threshold (WI-012). `None` → no ban filtering (e.g.
    /// before the ban list is bootstrapped, WI-015).
    ban_source: Option<crate::cardano::ban_list::BanListSource>,
    /// Where per-pool active stake is read for the DKG threshold. Defaults to
    /// Blockfrost (`/pools/{id}`); set to `YaciStore` for a local devnet.
    stake_source: crate::cardano::stake::StakeSource,
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
    /// Resolved Blockfrost base URL + project id, for raw-HTTP UTxO queries (lenient parsing).
    bf_base_url: String,
    bf_project_id: String,
    /// TreasuryMovementValidator CBOR (`binocular tm-script`). When set, the TM NFT is minted under
    /// this policy (and `treasury_policy_id` must be its hash, `treasury_asset_name_hex` empty); else
    /// the always-ok scaffold is used.
    tm_script_cbor: Option<String>,
    /// The TM-control UTxO `(tx_hash, index)` to reference so the validator can read the authorized
    /// minter. Required alongside `tm_script_cbor`.
    tm_control_ref: Option<(String, u32)>,
}

impl BlockfrostCardanoChain {
    pub fn new(
        project_id: &str,
        treasury_address: impl Into<String>,
        treasury_policy_id: impl Into<String>,
        treasury_asset_name_hex: impl Into<String>,
        treasury_config: TreasuryConfig,
        fallback_roster: Roster,
        // Custom Blockfrost-compatible base URL (e.g. yaci-devkit's http://localhost:8080/api/v1).
        // None → the public blockfrost.io URL derived from the project_id prefix.
        blockfrost_url: Option<&str>,
    ) -> Self {
        let mut settings = BlockFrostSettings::new();
        if let Some(url) = blockfrost_url {
            settings.base_url = Some(url.to_string());
        }
        let api = BlockfrostAPI::new(project_id, settings);
        Self {
            api,
            bf_base_url: crate::cardano::bf_http::base_url(project_id, blockfrost_url),
            bf_project_id: project_id.to_string(),
            treasury_address: treasury_address.into(),
            treasury_policy_id: treasury_policy_id.into(),
            treasury_asset_name_hex: treasury_asset_name_hex.into(),
            treasury_config,
            fallback_roster,
            registry_roster: None,
            ban_source: None,
            stake_source: crate::cardano::stake::StakeSource::Blockfrost,
            payment_key: None,
            wallet_base_address: None,
            treasury_y_51: Mutex::new(None),
            btc_rpc: None,
            submit_btc: true,
            submit_oracle: true,
            oracle_constructor: 0,
            tm_script_cbor: None,
            tm_control_ref: None,
        }
    }

    /// Mint the TM NFT under the real TreasuryMovementValidator policy (CBOR from
    /// `binocular tm-script`), referencing the TM-control UTxO `(tx_hash, index)`. Without this the
    /// always-ok scaffold policy is used.
    pub fn with_tm_policy(
        mut self,
        script_cbor: &str,
        control_tx_hash: &str,
        control_index: u32,
    ) -> Self {
        self.tm_script_cbor = Some(script_cbor.to_string());
        self.tm_control_ref = Some((control_tx_hash.to_string(), control_index));
        self
    }

    /// Read the roster from the on-chain SPO registry instead of the
    /// fallback fixture (WI-010).
    pub fn with_registry_roster(
        mut self,
        source: crate::cardano::roster::RegistryRosterSource,
    ) -> Self {
        self.registry_roster = Some(source);
        self
    }

    /// Subtract the on-chain ban list when deriving the eligible roster
    /// (WI-012). Only meaningful alongside [`Self::with_registry_roster`].
    pub fn with_ban_source(mut self, source: crate::cardano::ban_list::BanListSource) -> Self {
        self.ban_source = Some(source);
        self
    }

    /// Select where per-pool active stake is read (Blockfrost vs a local
    /// yaci-devkit devnet). Only meaningful alongside [`Self::with_registry_roster`].
    pub fn with_stake_source(mut self, source: crate::cardano::stake::StakeSource) -> Self {
        self.stake_source = source;
        self
    }

    /// Override submission flags from config.
    pub fn with_submit_config(
        mut self,
        submit_btc: bool,
        submit_oracle: bool,
        oracle_constructor: u8,
    ) -> Self {
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
        let wallet_addr = self.wallet_base_address.as_deref().ok_or_else(|| {
            EpochError::Chain("no wallet address — was with_mnemonic called?".into())
        })?;

        // Raw HTTP + lenient parse (tolerates backends like yaci-devkit that omit `tx_index`).
        let utxos = crate::cardano::bf_http::fetch_address_utxos(
            &self.bf_base_url,
            &self.bf_project_id,
            wallet_addr,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("blockfrost wallet UTxO query: {e}")))?;

        // The oracle-update tx only needs ADA (fee + new-UTxO min-ADA + script collateral) and runs a
        // minting script — feed coin-selection only PURE-ADA UTxOs. A token-bearing fee input drops
        // those tokens from the change (ValueNotConservedUTxO) and a token-bearing collateral fails
        // (CollateralContainsNonADA); the wallet's token UTxOs are irrelevant to this tx.
        Ok(utxos
            .iter()
            .map(WalletUtxo::from_bf)
            .filter(|u| u.pure_ada)
            .collect())
    }
}

#[async_trait]
impl CardanoChain for BlockfrostCardanoChain {
    async fn await_epoch_boundary(&self) -> EpochResult<EpochBoundaryEvent> {
        // WI-014: deliver the REAL chain epoch — DKG payload namespaces and
        // replay protection bind to (epoch, threshold, attempt), so a hardcoded
        // 0 made every SPO publish under the wrong namespace. A chain-read
        // failure is a retriable Chain error (the idle phase backs off and
        // re-enters), never process death.
        // TODO(WI-014): this returns the CURRENT epoch immediately rather than
        // blocking until the next boundary; true boundary-waiting (poll until
        // the epoch advances past the last-seen) lands with the loop hardening.
        Ok(EpochBoundaryEvent {
            epoch: self.current_epoch().await?,
        })
    }

    async fn current_epoch(&self) -> EpochResult<u64> {
        crate::cardano::bf_http::fetch_current_epoch(&self.bf_base_url, &self.bf_project_id)
            .await
            .map_err(|e| EpochError::Chain(format!("fetch current epoch: {e}")))
    }

    async fn query_roster(&self, epoch: u64) -> EpochResult<Roster> {
        let Some(registry) = &self.registry_roster else {
            return Ok(self.fallback_roster.clone());
        };
        // WI-012: eligible roster = registry − active bans, FROST threshold
        // stake-weighted. Any failure is hard — never silently fall back to
        // the fixture, which would let SPOs run DKG on divergent rosters.
        // `attempt` is 0 here; the orchestration layer (WI-014) bumps it on
        // a failed ceremony.
        let ctx = crate::cardano::dkg_roster::fetch_dkg_context(
            registry,
            self.ban_source.as_ref(),
            &self.bf_base_url,
            &self.bf_project_id,
            self.stake_source,
            epoch,
            0,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("eligible roster: {e}")))?;
        Ok(ctx.to_roster())
    }

    async fn query_dkg_context(
        &self,
        epoch: u64,
        attempt: u32,
    ) -> EpochResult<crate::cardano::dkg_roster::DkgContext> {
        match &self.registry_roster {
            // Real eligible set + chain stake (registry − active bans).
            Some(registry) => crate::cardano::dkg_roster::fetch_dkg_context(
                registry,
                self.ban_source.as_ref(),
                &self.bf_base_url,
                &self.bf_project_id,
                self.stake_source,
                epoch,
                attempt,
            )
            .await
            .map_err(|e| EpochError::Chain(format!("eligible roster: {e}"))),
            // No registry configured → fall back to the static roster with equal
            // stake (the quorum gate degrades to a >51%-by-count majority).
            None => Ok(
                crate::cardano::dkg_roster::DkgContext::from_roster_equal_stake(
                    &self.fallback_roster,
                    epoch,
                    attempt,
                ),
            ),
        }
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

        let inline_datum_hex = utxo.inline_datum.as_deref().unwrap();
        let datum_cbor = hex::decode(inline_datum_hex)
            .map_err(|e| EpochError::Chain(format!("inline datum hex decode: {e}")))?;
        let datum: PlutusData = minicbor::decode(&datum_cbor)
            .map_err(|e| EpochError::Chain(format!("inline datum CBOR decode: {e}")))?;

        let constr = match &datum {
            PlutusData::Constr(c) => c,
            _ => return Err(EpochError::Chain("treasury datum is not a Constr".into())),
        };

        // tag 121 = constructor 0 (unconfirmed), tag 122 = constructor 1 (confirmed).
        let constructor = constr.tag.saturating_sub(121);
        let btc_confirmed = constructor == 1;
        eprintln!(
            "[blockfrost] treasury datum: constructor={constructor} btc_confirmed={btc_confirmed}"
        );

        let tx_bytes = match constr.fields.first() {
            Some(PlutusData::BoundedBytes(bb)) => {
                let v: Vec<u8> = bb.clone().into();
                v
            }
            _ => {
                return Err(EpochError::Chain(
                    "treasury datum Constr has no BoundedBytes field".into(),
                ));
            }
        };
        let tx: Transaction = deserialize(&tx_bytes)
            .map_err(|e| EpochError::Chain(format!("BTC tx deserialize: {e}")))?;

        let out = tx
            .output
            .first()
            .ok_or_else(|| EpochError::Chain("BTC tx in treasury datum has no outputs".into()))?;
        let txid = tx.compute_txid();

        let maybe_key = *self.treasury_y_51.lock().unwrap();
        let y_51 = maybe_key.unwrap_or(self.treasury_config.y_51);
        // After DKG: Y_fed = Y_51 = FROST group key (same key everywhere).
        let y_fed = maybe_key.unwrap_or(self.treasury_config.y_fed);

        Ok(TreasuryUtxo {
            outpoint: bitcoin::OutPoint { txid, vout: 0 },
            value: out.value,
            y_51,
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

    async fn query_pool_stake(
        &self,
        pool_id: &str,
    ) -> EpochResult<crate::cardano::stake::PoolStake> {
        crate::cardano::stake::fetch_pool_stake(&self.bf_base_url, &self.bf_project_id, pool_id)
            .await
            .map_err(EpochError::Chain)
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
                None => eprintln!(
                    "[submit] bitcoin.submit=true but rpc_url not set — skipping BTC broadcast"
                ),
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
                eprintln!(
                    "[submit] no mnemonic configured — skipping Cardano oracle publish (dry run)"
                );
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
            wallet_utxos.len(),
            total_lovelace,
        );
        eprintln!(
            "[submit] building Cardano oracle-update tx: treasury={} constructor={} policy={}",
            self.treasury_address, self.oracle_constructor, self.treasury_policy_id
        );

        // Fetch the network's live cost models so the script-integrity hash matches the ledger's
        // (whisky's hardcoded preprod models are stale — see bf_http::fetch_cost_models).
        let cost_models =
            crate::cardano::bf_http::fetch_cost_models(&self.bf_base_url, &self.bf_project_id)
                .await
                .map_err(|e| EpochError::Chain(format!("fetch cost models: {e}")))?;
        eprintln!(
            "[submit] live cost models: V1={} V2={} V3={} params",
            cost_models[0].len(),
            cost_models[1].len(),
            cost_models[2].len()
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
            self.tm_script_cbor.as_deref(),
            self.tm_control_ref.as_ref().map(|(h, i)| (h.as_str(), *i)),
            Some(cost_models),
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
