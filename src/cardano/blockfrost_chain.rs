//! `CardanoChain` backed by Blockfrost.
//!
//! Derives the current Bitcoin treasury UTxO from Cardano chain state (WI-028):
//! `query_treasury` scans every TM UTxO at the treasury address, parses the
//! Confirmed (Constr 1) datums, and chain-follows them to the tip — the TM whose
//! own treasury output nobody has swept. Outpoint `(btc_txid, 0)`, value, and
//! scriptPubKey all come from the tip datum; the tip's SPK must match the current
//! treasury keys (both selecting among divergent lineages and proving we can sign
//! it). The local `bitcoin.treasury_txid/vout/amount` config is now only a
//! bootstrap fallback for before the first TM confirms. Unconfirmed (Constr 0)
//! datums are inspected only to detect a movement already in flight against the
//! tip, so heimdall waits instead of double-posting.
//!
//! `submit_signed_tm` builds a Cardano transaction that **creates a
//! new UTxO** at the treasury address with the signed BTC tx as an
//! inline datum. The old oracle UTxO is NOT spent — old confirmed
//! UTxOs are kept on-chain for minting proofs.

use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use blockfrost::{BlockFrostSettings, BlockfrostAPI};
use pallas_codec::minicbor;
use pallas_primitives::conway::PlutusData;
use pallas_wallet::PrivateKey;

use crate::bitcoin::taproot::treasury_spend_info;
use crate::cardano::btc_rpc::{BtcRpcConfig, broadcast_btc_tx};
use crate::cardano::publish::{WalletUtxo, build_oracle_update_tx};
use crate::cardano::treasury_datum::{
    ConfirmedTm, TreasuryConfig, TreasuryDatumError, UnconfirmedTm, parse_confirmed_tm_datum,
    parse_unconfirmed_tm, select_spendable_tip,
};
use crate::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
use crate::epoch::state::{EpochError, EpochResult, Roster};
use crate::epoch::traits::{CardanoChain, EpochBoundaryEvent, PegOutRequestUtxo, TreasuryUtxo};

pub struct BlockfrostCardanoChain {
    /// Pooled Blockfrost client — used ONLY for `transactions_submit` (the leader's
    /// oracle-update POST). Reads go through fresh `bf_http` clients instead: the
    /// pooled keep-alive connection goes stale during the staggered-start DKG wait.
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
    /// DEMO-ONLY: when true, eligible pools whose Cardano stake can't be
    /// resolved are excluded from the roster instead of failing the whole
    /// stake-weighted derivation. Default false.
    demo_exclude_unstaked: bool,
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
            demo_exclude_unstaked: false,
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

    /// DEMO-ONLY: exclude eligible pools whose Cardano stake can't be resolved
    /// from the roster (instead of failing the stake-weighted derivation).
    pub fn with_demo_exclude_unstaked(mut self, v: bool) -> Self {
        self.demo_exclude_unstaked = v;
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
            self.demo_exclude_unstaked,
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
                self.demo_exclude_unstaked,
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
        let asset_unit = format!(
            "{}{}",
            self.treasury_policy_id, self.treasury_asset_name_hex
        );

        // Scan every marker-token TM UTxO at the validator address (fresh HTTP
        // client per call — the pooled keep-alive goes stale across the DKG wait).
        let TmScan {
            confirmed,
            in_flight_spends,
            parse_failures,
            opaque_unconfirmed,
            ..
        } = scan_tm_utxos(
            &self.bf_base_url,
            &self.bf_project_id,
            &self.treasury_address,
            &asset_unit,
            // Staleness deadline is applied on the mover/sweep path (run_sweep_pegins);
            // the epoch-machine daemon does not thread it through TreasuryConfig yet.
            None,
        )
        .await
        .map_err(EpochError::Chain)?;

        // A marker-token TM UTxO is NFT-mint-gated, so a datum we cannot parse is a
        // REAL TM we dropped — chain-following an incomplete set can promote an
        // already-spent parent to a false tip. Refuse rather than mis-root/misdirect.
        if parse_failures > 0 {
            return Err(EpochError::Chain(format!(
                "{parse_failures} marker-token TM datum(s) failed to parse — refusing to \
                 chain-source the treasury (would risk mis-rooting the movement chain)"
            )));
        }

        // The treasury's Taproot internal key (Y_51). After DKG, publish_group_key
        // stores the FROST group key here; at bootstrap it is the config Y_51.
        let maybe_key = *self.treasury_y_51.lock().unwrap();
        let y_51 = maybe_key.unwrap_or(self.treasury_config.y_51);
        let csv = self.treasury_config.federation_csv_blocks;

        // Bootstrap: before the first TM confirms there is no Confirmed datum to
        // follow, so fall back to the config outpoint/value.
        if confirmed.is_empty() {
            let cfg_out = self.treasury_config.treasury_outpoint;
            if cfg_out == bitcoin::OutPoint::null() {
                return Err(EpochError::Chain(
                    "no Confirmed TM on-chain and no bootstrap bitcoin.treasury_txid configured"
                        .into(),
                ));
            }
            // An unreadable in-flight movement could be spending this outpoint; be
            // conservative and treat it as not-yet-free.
            let btc_confirmed = !in_flight_spends.contains(&cfg_out) && opaque_unconfirmed == 0;
            eprintln!(
                "[blockfrost] no Confirmed TM yet — bootstrap treasury from config {cfg_out} \
                 (btc_confirmed={btc_confirmed})"
            );
            return Ok(TreasuryUtxo {
                outpoint: cfg_out,
                value: self.treasury_config.treasury_value,
                y_51,
                y_fed: self.treasury_config.y_fed,
                federation_csv_blocks: csv,
                fee_rate_sat_per_vb: self.treasury_config.fee_rate_sat_per_vb,
                per_pegout_fee: self.treasury_config.per_pegout_fee,
                btc_confirmed,
            });
        }

        // Chain-follow to the tip we can spend. The treasury tree's key-path key is
        // Y_51; the script-path (federation-CSV) leaf is the federation key, which
        // does NOT rotate with DKG. Try each candidate leaf — the federation seed
        // (production) and, defensively, Y_51 itself (the demo's collapsed
        // Y_fed=Y_51 convention) — through the SAME `select_spendable_tip` the CLI /
        // mover path uses, keeping whichever matched so the input spend rebuilds the
        // exact tree. No candidate matches -> hard error (never sign an outpoint whose
        // on-chain scriptPubKey we cannot reconstruct).
        let secp = bitcoin::key::Secp256k1::new();
        let csv_u16 = csv_to_u16(csv)?;
        let mut leaf_candidates = vec![self.treasury_config.y_fed];
        if y_51 != self.treasury_config.y_fed {
            leaf_candidates.push(y_51);
        }
        let mut selected: Option<(&ConfirmedTm, bitcoin::key::UntweakedPublicKey)> = None;
        let mut last_err: Option<String> = None;
        for &y_fed in &leaf_candidates {
            let spk = bitcoin::ScriptBuf::new_p2tr_tweaked(
                treasury_spend_info(&secp, y_51, y_fed, csv_u16).output_key(),
            );
            match select_spendable_tip(&confirmed, spk.as_bytes()) {
                Ok(tip) => {
                    selected = Some((tip, y_fed));
                    break;
                }
                Err(e) => last_err = Some(e.to_string()),
            }
        }
        let (tip, y_fed) = selected.ok_or_else(|| {
            EpochError::Chain(format!(
                "no Confirmed TM tip is spendable under the current treasury keys \
                 ({} confirmed TM(s)): {}",
                confirmed.len(),
                last_err.unwrap_or_else(|| "no candidate keys".into()),
            ))
        })?;

        let outpoint = tip.treasury_outpoint();
        let value = tip
            .treasury_value()
            .ok_or_else(|| EpochError::Chain("treasury tip datum has no outputs".into()))?;
        // A movement already in flight against this tip — or an in-flight movement we
        // could not read — means it is not yet safe to build the next TM; report
        // btc_confirmed=false so BuildTm waits for confirmation.
        let btc_confirmed = !in_flight_spends.contains(&outpoint) && opaque_unconfirmed == 0;
        eprintln!(
            "[blockfrost] treasury tip {}:{} = {} sat ({} confirmed TM(s), in_flight={}, btc_confirmed={})",
            outpoint.txid,
            outpoint.vout,
            value.to_sat(),
            confirmed.len(),
            !btc_confirmed,
            btc_confirmed,
        );

        Ok(TreasuryUtxo {
            outpoint,
            value,
            y_51,
            y_fed,
            federation_csv_blocks: csv,
            fee_rate_sat_per_vb: self.treasury_config.fee_rate_sat_per_vb,
            per_pegout_fee: self.treasury_config.per_pegout_fee,
            btc_confirmed,
        })
    }

    async fn publish_group_key(&self, y_51: bitcoin::key::UntweakedPublicKey) -> EpochResult<()> {
        *self.treasury_y_51.lock().unwrap() = Some(y_51);
        Ok(())
    }

    async fn publish_dkg_fault_and_apply_ban(
        &self,
        evidence: crate::epoch::traits::DkgFaultEvidence,
    ) -> EpochResult<()> {
        Err(EpochError::Chain(format!(
            "automatic DKG fault publication is not wired for live Cardano yet \
             (kind={}, accused_pool_id={})",
            evidence.kind_label(),
            hex::encode(evidence.accused_pool_id())
        )))
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

// ---------------------------------------------------------------------------
// Shared TM-UTxO scan (WI-028) — used by `query_treasury` and the sweep CLI.
// ---------------------------------------------------------------------------

/// Convert the u32 federation CSV to the u16 the Taproot leaf timelock needs,
/// erroring (never silently truncating) on overflow — so every treasury-sourcing
/// path derives the same scriptPubKey from the same config.
pub fn csv_to_u16(csv: u32) -> EpochResult<u16> {
    u16::try_from(csv).map_err(|_| {
        EpochError::Chain(format!(
            "federation_csv_blocks {csv} exceeds the 16-bit CSV limit"
        ))
    })
}

/// Result of scanning the TM validator address for treasury movements.
pub struct TmScan {
    /// Every Confirmed (Constr 1) TM datum found — the chain-follow input.
    pub confirmed: Vec<ConfirmedTm>,
    /// Outpoints spent by Unconfirmed (Constr 0) TMs — a movement already in
    /// flight. If the selected tip's outpoint is in here, a new TM must NOT be
    /// built off it yet (wait for confirmation).
    pub in_flight_spends: HashSet<bitcoin::OutPoint>,
    /// Count of marker-token UTxOs whose datum failed to hex/CBOR-decode or parse
    /// as a Confirmed TM. Because the marker token is NFT-mint-gated, each is a
    /// REAL TM we could not read — a non-zero count makes the chain-follow
    /// untrustworthy (a dropped tip promotes an already-spent parent).
    pub parse_failures: usize,
    /// Count of Unconfirmed (Constr 0) TMs whose raw BTC tx would not deserialize,
    /// so we could not learn which outpoint they spend. Treated as a possible
    /// in-flight movement against the tip (fail closed, never double-post).
    pub opaque_unconfirmed: usize,
    /// Every readable Unconfirmed (Constr 0) TM — its BTC txid, inputs, outputs.
    /// Kept separately (all of them, dead or live) so callers can diagnose WHICH
    /// movement blocks the tip and what it references.
    pub unconfirmed: Vec<UnconfirmedTm>,
    /// Every outpoint spent by a Confirmed TM — DEFINITIVELY spent on Bitcoin
    /// (Confirmed = oracle-verified mined). heimdall's Bitcoin-spent view, sourced
    /// purely from Cardano. Used to skip already-swept peg-ins and to detect dead
    /// (never-confirmable) in-flight movements without ever querying Bitcoin.
    pub consumed: HashSet<bitcoin::OutPoint>,
}

/// Scan every marker-token (`asset_unit`) TM UTxO at `address` via Blockfrost and
/// parse the datums. Uses a fresh HTTP client per call (the pooled keep-alive
/// goes stale across the staggered-start DKG wait). Unparseable datums are logged
/// and COUNTED (`parse_failures` / `opaque_unconfirmed`) rather than aborting the
/// scan — the caller decides whether the counts make the result untrustworthy
/// (they do for chain-following, since a marker token is NFT-mint-gated).
///
/// `deadline_secs` (opt-in): an Unconfirmed TM still on-chain longer than this
/// (chain-now − its Cardano block time) is treated as DEAD/stale and excluded
/// from `in_flight_spends` — the time-based catch for a never-confirmable movement
/// heimdall can't detect otherwise (e.g. a peg-in refunded outside a Confirmed
/// TM). Costs one `/blocks/latest` + one `/txs/{hash}` per viable in-flight TM;
/// `None` skips all of that.
pub async fn scan_tm_utxos(
    base_url: &str,
    project_id: &str,
    address: &str,
    asset_unit: &str,
    deadline_secs: Option<u64>,
) -> Result<TmScan, String> {
    let utxos = crate::cardano::bf_http::fetch_address_utxos(base_url, project_id, address)
        .await
        .map_err(|e| format!("blockfrost treasury query: {e}"))?;

    let mut confirmed: Vec<ConfirmedTm> = Vec::new();
    let mut parse_failures: usize = 0;
    let mut opaque_unconfirmed: usize = 0;
    let mut unconfirmed: Vec<UnconfirmedTm> = Vec::new();
    for u in &utxos {
        let Some(datum_hex) = u.inline_datum.as_deref() else {
            continue;
        };
        if !u.amount.iter().any(|a| a.unit == asset_unit) {
            continue;
        }
        let datum_cbor = match hex::decode(datum_hex) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[tm-scan] marker-token TM datum failed hex decode: {e}");
                parse_failures += 1;
                continue;
            }
        };
        let datum: PlutusData = match minicbor::decode(&datum_cbor) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[tm-scan] marker-token TM datum failed CBOR decode: {e}");
                parse_failures += 1;
                continue;
            }
        };
        match parse_confirmed_tm_datum(&datum) {
            Ok(tm) => confirmed.push(tm),
            Err(TreasuryDatumError::NotConfirmed) => match parse_unconfirmed_tm(&datum) {
                Some(mut tm) => {
                    tm.cardano_tx_hash = u.tx_hash.clone();
                    unconfirmed.push(tm);
                }
                None => {
                    eprintln!(
                        "[tm-scan] Unconfirmed TM datum's BTC tx did not deserialize — \
                         treating as a possible in-flight movement"
                    );
                    opaque_unconfirmed += 1;
                }
            },
            Err(e) => {
                eprintln!("[tm-scan] marker-token Confirmed TM datum failed to parse: {e}");
                parse_failures += 1;
            }
        }
    }

    // `consumed` = every outpoint spent by a Confirmed TM. Because Confirmed means
    // the oracle verified the BTC tx is mined, these are DEFINITIVELY spent on
    // Bitcoin — heimdall's Bitcoin-spent view sourced purely from Cardano.
    let consumed: HashSet<bitcoin::OutPoint> = confirmed
        .iter()
        .flat_map(|tm| tm.swept_outpoints())
        .collect();

    // Staleness pass (opt-in): a viable-by-inputs Unconfirmed TM that has been
    // on-chain longer than `deadline_secs` (chain-now − its Cardano block time)
    // never confirmed, so treat it as DEAD too — the time-based catch for a
    // movement heimdall can't otherwise see is doomed (e.g. a peg-in refunded
    // outside a TM). Fetch chain time once, then each candidate's block time.
    let now: Option<i64> = match deadline_secs {
        Some(_) => {
            match crate::cardano::bf_http::fetch_latest_block_time(base_url, project_id).await {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("[tm-scan] could not read chain time for staleness deadline: {e}");
                    None
                }
            }
        }
        None => None,
    };
    let mut stale: HashSet<bitcoin::Txid> = HashSet::new();
    if let (Some(deadline), Some(now)) = (deadline_secs, now) {
        for tm in &mut unconfirmed {
            // Consumed-dead ones are excluded by `viable_in_flight_spends` anyway.
            if tm.inputs.iter().any(|i| consumed.contains(i)) {
                continue;
            }
            match crate::cardano::bf_http::fetch_tx_block_time(
                base_url,
                project_id,
                &tm.cardano_tx_hash,
            )
            .await
            {
                Ok(bt) => {
                    tm.block_time = Some(bt);
                    let age = now.saturating_sub(bt);
                    if age > deadline as i64 {
                        eprintln!(
                            "[tm-scan] Unconfirmed TM {} unconfirmed for {age}s (> {deadline}s \
                             deadline) — treating as dead/stale, ignoring",
                            tm.btc_txid
                        );
                        stale.insert(tm.btc_txid);
                    }
                }
                Err(e) => eprintln!(
                    "[tm-scan] could not read block time for TM {} ({e}) — not applying staleness",
                    tm.btc_txid
                ),
            }
        }
    }

    // `viable_in_flight_spends` drops consumed-dead TMs; also drop the stale set
    // (cloning only when there is something to drop, i.e. the deadline fired).
    let in_flight_spends = if stale.is_empty() {
        viable_in_flight_spends(&consumed, &unconfirmed)
    } else {
        let live: Vec<UnconfirmedTm> = unconfirmed
            .iter()
            .filter(|t| !stale.contains(&t.btc_txid))
            .cloned()
            .collect();
        viable_in_flight_spends(&consumed, &live)
    };

    Ok(TmScan {
        confirmed,
        in_flight_spends,
        parse_failures,
        opaque_unconfirmed,
        unconfirmed,
        consumed,
    })
}

/// The VIABLE in-flight spends: the union of the inputs of every Unconfirmed TM
/// that is NOT dead. An Unconfirmed TM is **dead** when its BTC tx spends an
/// already-`consumed` outpoint — one a Confirmed (hence oracle-verified, mined) TM
/// already spent — because that is a double-spend which can never confirm. A dead
/// TM must therefore neither block the treasury tip nor reserve a peg-in (the
/// auto-unblock). Only the returned outpoints gate the tip / peg-in guards.
fn viable_in_flight_spends(
    consumed: &HashSet<bitcoin::OutPoint>,
    unconfirmed: &[UnconfirmedTm],
) -> HashSet<bitcoin::OutPoint> {
    let mut in_flight_spends: HashSet<bitcoin::OutPoint> = HashSet::new();
    for tm in unconfirmed {
        let dead = tm.inputs.iter().any(|i| consumed.contains(i));
        if dead {
            eprintln!(
                "[tm-scan] Unconfirmed TM {} spends an already-swept input — dead, ignoring \
                 (will never confirm)",
                tm.btc_txid
            );
            continue;
        }
        in_flight_spends.extend(tm.inputs.iter().copied());
    }
    in_flight_spends
}

#[cfg(test)]
mod tests {
    use super::viable_in_flight_spends;
    use crate::cardano::treasury_datum::UnconfirmedTm;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
    use std::collections::HashSet;

    fn op(txid: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([txid; 32]),
            vout,
        }
    }

    fn unconf(txid: u8, inputs: &[OutPoint]) -> UnconfirmedTm {
        UnconfirmedTm {
            btc_txid: Txid::from_byte_array([txid; 32]),
            inputs: inputs.to_vec(),
            outputs: vec![(Amount::from_sat(1), ScriptBuf::new())],
            cardano_tx_hash: String::new(),
            block_time: None,
        }
    }

    /// A viable in-flight TM (no input already swept) contributes all its inputs —
    /// the tip guard must treat the treasury it spends as in-flight and wait.
    #[test]
    fn viable_tm_reserves_its_inputs() {
        let consumed = HashSet::new(); // nothing swept yet
        let tip = op(0xAB, 0);
        let deposit = op(0xCD, 1);
        let spends = viable_in_flight_spends(&consumed, &[unconf(0x01, &[tip, deposit])]);
        assert!(spends.contains(&tip));
        assert!(spends.contains(&deposit));
    }

    /// A dead in-flight TM (spends an already-`consumed` outpoint) contributes
    /// NOTHING — the auto-unblock: it must not block the tip or reserve a peg-in.
    #[test]
    fn dead_tm_reserves_nothing() {
        let swept_deposit = op(0xCD, 1);
        let consumed = HashSet::from([swept_deposit]); // a Confirmed TM already spent it
        let tip = op(0xAB, 0);
        // Re-spends the live tip + the already-swept deposit → double-spend → dead.
        let spends = viable_in_flight_spends(&consumed, &[unconf(0x02, &[tip, swept_deposit])]);
        assert!(
            spends.is_empty(),
            "dead TM must reserve nothing, got {spends:?}"
        );
    }

    /// Mixed set: only the viable movement's inputs survive; the dead one on the
    /// same tip is dropped, so the tip is NOT considered in-flight by the dead TM.
    #[test]
    fn dead_and_viable_are_separated() {
        let swept = op(0xCD, 1);
        let consumed = HashSet::from([swept]);
        let tip = op(0xAB, 0);
        let fresh_deposit = op(0xEF, 2);
        let dead = unconf(0x02, &[tip, swept]);
        let viable = unconf(0x03, &[fresh_deposit]);
        let spends = viable_in_flight_spends(&consumed, &[dead, viable]);
        assert_eq!(spends, HashSet::from([fresh_deposit]));
        assert!(!spends.contains(&tip));
    }
}
