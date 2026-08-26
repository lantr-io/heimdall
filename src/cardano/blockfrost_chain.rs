//! `CardanoChain` backed by Blockfrost.
//!
//! Derives the current Bitcoin treasury UTxO from Cardano chain state (rev 5.4,
//! DEC-030/DEC-034): `query_treasury` reads the bridge-state singleton — the
//! head outpoint (`treasury_utxo_id`) and satoshi amount come straight from its
//! `BridgeState` datum, bootstrap anchor included. The head's scriptPubKey is
//! reconstructed from the candidate treasury trees and checked against the
//! spent `UnconfirmedTm` record whose RECOMPUTED txid equals the head's (the
//! [SPI-7] discipline), so no Bitcoin node is needed. Unconfirmed (Constr 0)
//! datums are also inspected to detect a movement already in flight against the
//! head, so heimdall waits instead of double-posting.
//!
//! `submit_signed_tm` builds a Cardano transaction that **creates a new
//! UTxO** at the treasury address with the signed BTC tx as an inline datum,
//! minting the TM NFT with the `TmMintRedeemer(bss_ref_index)` redeemer, which
//! names the bridge-state singleton reference input the mint's head check
//! ([PTM-6]/[PTM-7]) reads. The singleton is NOT spent by posting — only the
//! Confirm transition advances it.

use std::{
    collections::HashSet,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use async_trait::async_trait;
use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use blockfrost::{BlockFrostSettings, BlockfrostAPI};
use halo2_base::halo2_proofs::{
    SerdeFormat,
    halo2curves::{
        bls12_381::{Bls12, Fr as BlsFr},
        ff::PrimeField,
    },
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use pallas_codec::minicbor;
use pallas_primitives::conway::PlutusData;
use pallas_wallet::PrivateKey;

use crate::bitcoin::taproot::treasury_spend_info;
use crate::bitcoin::tm_builder::TmParams;
use crate::cardano::config_params;
use crate::cardano::fault_proof::FaultProofKind;
use crate::cardano::publish::{WalletUtxo, build_oracle_update_tx};
use crate::cardano::treasury_datum::{
    ConfirmedTm, TreasuryConfig, TreasuryDatumError, UnconfirmedTm, parse_confirmed_tm_datum,
    parse_unconfirmed_tm,
};
use crate::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
use crate::epoch::state::{EpochError, EpochResult, Roster};
use crate::epoch::traits::{
    BatchSnapshot, CardanoChain, EpochBoundaryEvent, PegOutRequestUtxo, TreasuryUtxo,
};
use tracing::{debug, info, warn};

/// How often to re-read the chain epoch while waiting for the next boundary.
///
/// Cardano epochs are days long, so this only decides how promptly a node joins
/// a new one — a minute of lag against a five-day epoch costs nothing, and the
/// ceremony window grid realigns late joiners anyway. Kept short enough that a
/// devnet with minute-long epochs still works.
const EPOCH_BOUNDARY_POLL: std::time::Duration = std::time::Duration::from_secs(30);

const FAULT_TOKEN_CONFIRM_POLL_SECS: u64 = 5;
const FAULT_TOKEN_CONFIRM_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct DkgFaultScriptRef {
    pub tx_hash: String,
    pub output_index: u32,
}

#[derive(Debug, Clone)]
pub struct DkgFaultBanFlow {
    blueprint_path: String,
    registry: crate::cardano::blueprint::ParameterizedScript,
    round1_fault: crate::cardano::blueprint::ParameterizedScript,
    round2_fault: crate::cardano::blueprint::ParameterizedScript,
    equivocation_fault: crate::cardano::blueprint::ParameterizedScript,
    spo_bans: crate::cardano::blueprint::ParameterizedScript,
    ban_params: crate::cardano::ban_list::BanPolicyParams,
    spo_bans_ref: DkgFaultScriptRef,
    round1_fault_ref: DkgFaultScriptRef,
    round2_fault_ref: DkgFaultScriptRef,
    equivocation_fault_ref: DkgFaultScriptRef,
    srs_path: PathBuf,
}

impl DkgFaultBanFlow {
    /// Build the automatic DKG fault-ban configuration — the *enforcement*
    /// half: proving a fault on chain and applying the ban.
    ///
    /// This is deliberately separate from reading the ban list (WI-060).
    /// Reading it is consensus-relevant and mandatory once the registry roster
    /// is configured, because it decides who is in the DKG; enforcement only
    /// decides whether cheating costs anything, and detection already works
    /// without it — `dkg_part3` verifies every share against the published
    /// commitments, so a bad round 1 package is dropped and the offender
    /// excluded whether or not this flow exists.
    ///
    /// So: absent the whole enforcement key set, this returns `None` and the
    /// node still filters its roster. Present *any* of it, every field is
    /// required — a half-configured publish path must fail at startup, not
    /// after a fault is detected.
    ///
    /// `config` is the decoded bridge Config: it supplies the ban schedule
    /// (params[4..6]) when the bridge publishes one, and its ban policy id (#8) is
    /// what the locally derived `spo_bans` is checked against (WI-065).
    /// ASYNC since WI-091: the four reference-script locations are discovered on
    /// chain when they are not configured, so this reads. It used to demand all
    /// four as hand-typed outrefs — the last hand-copied values in an operator's
    /// config, and the same missing lookup `register-spo` had.
    pub async fn from_config(
        cardano: &crate::config::CardanoConfig,
        config: Option<&crate::cardano::config_params::ConfigParams>,
    ) -> Result<Option<Self>, String> {
        let enforcement_keys = [
            &cardano.fault_proof_srs_path,
            &cardano.spo_bans_ref,
            &cardano.fault_verifier_round1_ref,
            &cardano.fault_verifier_round2_ref,
            &cardano.fault_verifier_equivocation_ref,
        ];
        if enforcement_keys.iter().all(|k| k.is_none()) {
            return Ok(None);
        }
        let Some(one_shot) = cardano.federation_one_shot.as_deref() else {
            return Err(
                "the federation one-shot has not been read from the chain: publishing a fault \
                 proof and applying a ban both need it, because spo_bans and the three fault \
                 verifiers are all parameterized by it. It is Config #12 since WI-090, so set \
                 cardano.config_address and cardano.config_nft_policy_id"
                    .to_string(),
            );
        };
        // One outpoint parameterizes the registry, the ban list and the three
        // fault verifiers alike — see `CardanoConfig::federation_one_shot`.
        let (ban_bootstrap, registry_bootstrap) = (one_shot, one_shot);
        let blueprint_path = req_fault_config(&cardano.registry_blueprint, "registry_blueprint")?;
        let srs_path = PathBuf::from(req_fault_config(
            &cardano.fault_proof_srs_path,
            "fault_proof_srs_path",
        )?);

        // The round 1 / round 2 verifiers are generated from this SRS, so an
        // untrustworthy setup is a forged-ban vector, not a slow proof. Check
        // it here rather than at fault time: a mainnet node that could mint
        // forgeable fault proofs must refuse to start, not discover it months
        // later when the first fault happens. Costs two small reads — see
        // `read_srs_header`.
        let mainnet = cardano.is_mainnet()?;
        crate::circuits::srs_provenance::check_fault_srs(
            &srs_path,
            crate::circuits::fault_evidence::round1_params().degree,
            mainnet,
        )?;

        let blueprint_json = std::fs::read_to_string(blueprint_path)
            .map_err(|e| format!("read blueprint {blueprint_path}: {e}"))?;
        let (reg_tx_id, reg_index) = crate::cardano::roster::parse_outref(registry_bootstrap)
            .map_err(|e| format!("registry bootstrap outref: {e}"))?;
        let (ban_tx_id, ban_index) = crate::cardano::roster::parse_outref(ban_bootstrap)
            .map_err(|e| format!("ban bootstrap outref: {e}"))?;
        // Rev 5.5: the registry policy is downstream of the treasury policy, which
        // is downstream of the Config identity.
        let (treasury_bootstrap, config_policy_id) =
            crate::cardano::roster::treasury_derivation_inputs(cardano)?;
        let (tsy_tx_id, tsy_index) = crate::cardano::roster::parse_outref(&treasury_bootstrap)
            .map_err(|e| format!("treasury bootstrap outref: {e}"))?;
        let registry = crate::cardano::blueprint::registry_policy_from_bootstraps(
            &blueprint_json,
            (&reg_tx_id, u64::from(reg_index)),
            (&tsy_tx_id, u64::from(tsy_index)),
            &config_policy_id,
        )
        .map_err(|e| format!("parameterize spos_registry: {e}"))?;
        let round1_fault = crate::cardano::blueprint::fault_verifier_round1_script(
            &blueprint_json,
            &registry.hash,
        )
        .map_err(|e| format!("parameterize fault_verifier_round1: {e}"))?;
        let round2_fault = crate::cardano::blueprint::fault_verifier_round2_script(
            &blueprint_json,
            &registry.hash,
        )
        .map_err(|e| format!("parameterize fault_verifier_round2: {e}"))?;
        let equivocation_fault = crate::cardano::blueprint::fault_verifier_equivocation_script(
            &blueprint_json,
            &registry.hash,
        )
        .map_err(|e| format!("parameterize fault_verifier_equivocation: {e}"))?;
        let ban_params = crate::cardano::ban_list::BanPolicyParams::resolve(cardano, config)
            .map_err(|e| e.to_string())?;
        let own_fault_policies = [
            round1_fault.hash,
            round2_fault.hash,
            equivocation_fault.hash,
        ];
        if own_fault_policies
            .iter()
            .any(|policy| !ban_params.fault_proof_policies.contains(policy))
        {
            return Err(format!(
                "cardano.fault_proof_policies must include Heimdall's Round 1, Round 2, and \
                 equivocation fault policies: {}, {}, {}",
                hex::encode(own_fault_policies[0]),
                hex::encode(own_fault_policies[1]),
                hex::encode(own_fault_policies[2])
            ));
        }
        let spo_bans = crate::cardano::blueprint::spo_bans_script(
            &blueprint_json,
            &registry.hash,
            &ban_params.fault_proof_policies,
            ban_params.base_ban_duration_ms,
            ban_params.max_faults_before_permanent,
            ban_params.max_validity_window_ms,
            &ban_tx_id,
            u64::from(ban_index),
        )
        .map_err(|e| format!("parameterize spo_bans: {e}"))?;

        // The enforcement half derives the policy from seven local parameters,
        // so it can land on an address the bridge does not use — an ApplyBan
        // that confirms into a list nobody reads. Where the Config publishes the
        // policy id there is a right answer to compare against, so compare.
        if let Some(published) = config.map(|c| &c.bans)
            && published.spo_bans_policy_id != spo_bans.hash
        {
            return Err(format!(
                "the fault-enforcement keys derive spo_bans policy {} but the bridge Config \
                 publishes {} (field #8) — an ApplyBan built here would confirm into a ban \
                 list no other SPO reads. Check cardano.ban_bootstrap, \
                 cardano.fault_proof_policies against this bridge — the schedule half comes \
                 from the Config itself (params[4..6]), so it cannot be what disagrees",
                spo_bans.hash_hex(),
                hex::encode(published.spo_bans_policy_id),
            ));
        }

        // Locations, resolved last because discovery needs the script HASHES the
        // derivation above produces. A configured value still wins; unset means
        // "find it", which is what removes the last typed outrefs from an
        // operator's config (WI-091).
        let spo_bans_ref = resolve_script_ref(
            cardano,
            one_shot,
            &cardano.spo_bans_ref,
            &spo_bans,
            "spo_bans",
        )
        .await?;
        let round1_fault_ref = resolve_script_ref(
            cardano,
            one_shot,
            &cardano.fault_verifier_round1_ref,
            &round1_fault,
            "fault_verifier_round1",
        )
        .await?;
        let round2_fault_ref = resolve_script_ref(
            cardano,
            one_shot,
            &cardano.fault_verifier_round2_ref,
            &round2_fault,
            "fault_verifier_round2",
        )
        .await?;
        let equivocation_fault_ref = resolve_script_ref(
            cardano,
            one_shot,
            &cardano.fault_verifier_equivocation_ref,
            &equivocation_fault,
            "fault_verifier_equivocation",
        )
        .await?;

        Ok(Some(Self {
            blueprint_path: blueprint_path.to_string(),
            registry,
            round1_fault,
            round2_fault,
            equivocation_fault,
            spo_bans,
            ban_params,
            spo_bans_ref,
            round1_fault_ref,
            round2_fault_ref,
            equivocation_fault_ref,
            srs_path,
        }))
    }

    fn fault_script(
        &self,
        kind: FaultProofKind,
    ) -> (
        &crate::cardano::blueprint::ParameterizedScript,
        &DkgFaultScriptRef,
    ) {
        match kind {
            FaultProofKind::Round1InvalidPayload => (&self.round1_fault, &self.round1_fault_ref),
            FaultProofKind::Round2InvalidPayload => (&self.round2_fault, &self.round2_fault_ref),
            FaultProofKind::Equivocation => {
                (&self.equivocation_fault, &self.equivocation_fault_ref)
            }
        }
    }
}

fn req_fault_config<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str, String> {
    value.as_deref().ok_or_else(|| {
        format!(
            "cardano.{name} is required once any DKG fault-enforcement key is set; automatic \
             fault banning needs the full publish-and-apply path. Set it, or remove every \
             enforcement key (fault_proof_srs_path, spo_bans_ref, fault_verifier_*_ref) to \
             read and filter the ban list without publishing fault proofs"
        )
    })
}

/// One reference-script location: the configured outref, or the one found on
/// chain (WI-091).
///
/// The four `*_ref` keys were the last hand-typed outrefs in an operator's
/// config, and they were typed for a script that `binocular deploy-script-refs`
/// had usually already published — there is simply no by-script-hash location
/// query, so heimdall could not see it. It can now: the federation one-shot the
/// Config publishes at #12 identifies the deploy transaction, whose spent output
/// sat at the deployer's own wallet, which is where those scripts are parked.
///
/// A configured value WINS and is not cross-checked against discovery: the two
/// are not required to agree — a valid reason to set one is to pin a copy other
/// than the one that would be found — and refusing a deliberate override because
/// the chain also offers a candidate would be worse than either.
async fn resolve_script_ref(
    cardano: &crate::config::CardanoConfig,
    one_shot: &str,
    configured: &Option<String>,
    script: &crate::cardano::blueprint::ParameterizedScript,
    what: &str,
) -> Result<DkgFaultScriptRef, String> {
    if let Some(raw) = configured.as_deref() {
        return parse_script_ref(raw);
    }
    let pid = cardano
        .blockfrost_project_id
        .as_deref()
        .ok_or_else(|| format!("{what} reference script is unset and there is no chain to find it on: set cardano.blockfrost_project_id, or cardano.{what}_ref"))?;
    let base_url = crate::cardano::bf_http::base_url(pid, cardano.blockfrost_url.as_deref());
    let mnemonic = cardano
        .mnemonic
        .clone()
        .or_else(|| {
            std::env::var("HEIMDALL_MNEMONIC")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .ok_or_else(|| format!("{what} reference script is unset and this node has no wallet to look in: set cardano.mnemonic / $HEIMDALL_MNEMONIC, or cardano.{what}_ref"))?;
    let wallet = crate::cardano::wallet::wallet_address_from_mnemonic(&mnemonic)?;
    let hash = script.hash_hex();
    let found = crate::cardano::ref_script::find_ref_script_anywhere(
        &base_url,
        pid,
        &wallet,
        Some(one_shot),
        &hash,
    )
    .await
    .map_err(|e| format!("{what} reference-script lookup: {e}"))?;
    let (found, origin) = found.ok_or_else(|| {
        format!(
            "no reference script for {what} ({hash}), at this wallet or at the wallet this \
             bridge was deployed from. Deploy one (`heimdall deploy-fault-ref` / \
             `deploy-spo-bans-ref`), or set cardano.{what}_ref to a copy held elsewhere"
        )
    })?;
    match origin {
        crate::cardano::ref_script::RefScriptOrigin::OwnWallet => {
            tracing::info!("{what} ref script {found} (this wallet)");
        }
        // Say whose it is: it is kept SPENDABLE on purpose, so an operator
        // depending on it should know rather than find out when enforcement
        // stops building.
        crate::cardano::ref_script::RefScriptOrigin::Deployer(addr) => {
            tracing::info!("{what} ref script {found} (the bridge deployer's, at {addr})");
        }
    }
    Ok(DkgFaultScriptRef {
        tx_hash: found.tx_hash,
        output_index: found.index,
    })
}

fn parse_script_ref(raw: &str) -> Result<DkgFaultScriptRef, String> {
    let (tx_id, output_index) = crate::cardano::roster::parse_outref(raw)
        .map_err(|e| format!("reference script outref: {e}"))?;
    Ok(DkgFaultScriptRef {
        tx_hash: hex::encode(tx_id),
        output_index,
    })
}

fn load_fault_srs(path: &Path, degree: u32) -> Result<ParamsKZG<Bls12>, String> {
    let file = File::open(path).map_err(|e| format!("open SRS {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut srs = ParamsKZG::<Bls12>::read_custom(&mut reader, SerdeFormat::Processed)
        .map_err(|e| format!("read SRS {}: {e}", path.display()))?;
    if srs.k() < degree {
        return Err(format!(
            "SRS {} has k={} but the fault circuit needs k={degree}",
            path.display(),
            srs.k()
        ));
    }
    if srs.k() > degree {
        srs.downsize(degree);
    }
    Ok(srs)
}

fn bls_scalar_bytes(scalar: BlsFr) -> Vec<u8> {
    let repr: [u8; 32] = scalar.to_repr();
    repr.to_vec()
}

fn public_input_bytes(instances: &[BlsFr]) -> Vec<Vec<u8>> {
    instances.iter().copied().map(bls_scalar_bytes).collect()
}

enum PreparedDkgFault {
    Round1 {
        accused_pool_id: [u8; 28],
        evidence_hash: [u8; 32],
        canonical_round1_bytes: Vec<u8>,
        payload_signature: [u8; 64],
        halo2_proof: Vec<u8>,
        halo2_public_inputs: Vec<Vec<u8>>,
    },
    Round2 {
        accused_pool_id: [u8; 28],
        evidence_hash: [u8; 32],
        canonical_round1_bytes: Vec<u8>,
        round1_signature: [u8; 64],
        canonical_round2_bytes: Vec<u8>,
        round2_signature: [u8; 64],
        round2_entry_index: u32,
        pad: [u8; 32],
        opened_share: [u8; 32],
        halo2_proof: Vec<u8>,
        halo2_public_inputs: Vec<Vec<u8>>,
    },
    Equivocation {
        accused_pool_id: [u8; 28],
        evidence_hash: [u8; 32],
        payload_a: Vec<u8>,
        signature_a: [u8; 64],
        payload_b: Vec<u8>,
        signature_b: [u8; 64],
    },
}

impl PreparedDkgFault {
    fn kind(&self) -> FaultProofKind {
        match self {
            Self::Round1 { .. } => FaultProofKind::Round1InvalidPayload,
            Self::Round2 { .. } => FaultProofKind::Round2InvalidPayload,
            Self::Equivocation { .. } => FaultProofKind::Equivocation,
        }
    }

    fn accused_pool_id(&self) -> [u8; 28] {
        match self {
            Self::Round1 {
                accused_pool_id, ..
            }
            | Self::Round2 {
                accused_pool_id, ..
            }
            | Self::Equivocation {
                accused_pool_id, ..
            } => *accused_pool_id,
        }
    }

    fn evidence_hash(&self) -> [u8; 32] {
        match self {
            Self::Round1 { evidence_hash, .. }
            | Self::Round2 { evidence_hash, .. }
            | Self::Equivocation { evidence_hash, .. } => *evidence_hash,
        }
    }
}

fn prepare_dkg_fault(
    flow: &DkgFaultBanFlow,
    evidence: crate::epoch::traits::DkgFaultEvidence,
) -> Result<PreparedDkgFault, String> {
    match evidence {
        crate::epoch::traits::DkgFaultEvidence::Round1InvalidPayload(ev) => {
            let srs = load_fault_srs(
                &flow.srs_path,
                crate::circuits::fault_evidence::round1_params().degree,
            )?;
            let canonical_round1_bytes = ev
                .canonical_bytes()
                .map_err(|e| format!("round1 canonical evidence: {e}"))?;
            let proof = crate::circuits::fault_evidence::prove_round1_pok_fault(&srs, &ev)
                .map_err(|e| format!("round1 fault proof: {e}"))?;
            Ok(PreparedDkgFault::Round1 {
                accused_pool_id: ev.accused_pool_id,
                evidence_hash: proof.evidence_hash,
                canonical_round1_bytes,
                payload_signature: ev.payload_signature,
                halo2_proof: proof.proof,
                halo2_public_inputs: public_input_bytes(&proof.public_instances),
            })
        }
        crate::epoch::traits::DkgFaultEvidence::Round2InvalidPayload(ev) => {
            let srs = load_fault_srs(
                &flow.srs_path,
                crate::circuits::fault_evidence::round2_params().degree,
            )?;
            let proof = crate::circuits::fault_evidence::prove_round2_share_fault_dyn(&srs, &ev)
                .map_err(|e| format!("round2 fault proof: {e}"))?;
            Ok(PreparedDkgFault::Round2 {
                accused_pool_id: ev.accused_pool_id,
                evidence_hash: proof.evidence_hash,
                canonical_round1_bytes: ev.canonical_round1_bytes,
                round1_signature: ev.round1_signature,
                canonical_round2_bytes: ev.round2_canonical_bytes,
                round2_signature: ev.round2_signature,
                round2_entry_index: ev.round2_entry_index,
                pad: ev.pad,
                opened_share: ev.share,
                halo2_proof: proof.proof,
                halo2_public_inputs: public_input_bytes(&proof.public_instances),
            })
        }
        crate::epoch::traits::DkgFaultEvidence::Equivocation(ev) => {
            ev.verify()
                .map_err(|e| format!("equivocation evidence: {e}"))?;
            Ok(PreparedDkgFault::Equivocation {
                accused_pool_id: ev.accused_pool_id,
                evidence_hash: ev.evidence_hash(),
                payload_a: ev.payload_a,
                signature_a: ev.signature_a,
                payload_b: ev.payload_b,
                signature_b: ev.signature_b,
            })
        }
    }
}

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
    /// Off-chain treasury parameters (leaf keys, CSV, bootstrap outpoint).
    treasury_config: TreasuryConfig,
    /// `bitcoin.fee_rate_sat_per_vb` — the DEV override, used only when no Config
    /// UTxO is configured or the deployed Config predates the operational-parameter
    /// fields. A node whose peers read the Config while it reads this agrees with
    /// them only by coincidence; see `cardano::config_params`. Defaults to 1 sat/vB;
    /// set it with [`Self::with_local_fee_rate`].
    local_fee_rate_sat_per_vb: u64,
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
    /// `[cardano]`, kept so the federation identity can be RE-RESOLVED from the
    /// bridge Config on every roster read rather than pinned at startup.
    ///
    /// The two fields above are what startup happened to see. Config #8 and
    /// #9–#10 are chain state a governance Update can move, exactly like the
    /// the `params` record the batch snapshot re-reads every batch — so pinning them makes
    /// two honest nodes disagree according to when each was last restarted, which
    /// is the divergence publishing them was supposed to end. `None` → nothing to
    /// refresh from (the fixture roster, or a Config predating the appends), and
    /// the pinned values stand.
    federation_refresh: Option<crate::config::CardanoConfig>,
    /// Where per-pool active stake is read for the DKG threshold. Defaults to
    /// Blockfrost (`/pools/{id}`); set to `YaciStore` for a local devnet.
    stake_source: crate::cardano::stake::StakeSource,
    /// DEMO-ONLY: when true, eligible pools whose Cardano stake can't be
    /// resolved are excluded from the roster instead of failing the whole
    /// stake-weighted derivation. Default false.
    demo_exclude_unstaked: bool,
    /// TEST-RUN ONLY: weight the DKG roster by `live_stake`. See
    /// [`crate::config::CardanoConfig::demo_live_stake`] — it is a consensus
    /// input, so every node of the roster must agree, and a mismatch is caught in
    /// the pre-ceremony handshake rather than left to look like a stalled
    /// ceremony.
    demo_live_stake: bool,
    /// TEST-RUN ONLY: which cycle the bridge runs on. `Cardano` (the default) is
    /// the real five-day epoch; `Virtual` shortens it so a test bridge can
    /// exercise a rotation in hours. See [`crate::epoch::virtual_epoch`].
    ///
    /// The split lives HERE and nowhere else: everything above this adapter sees
    /// one "epoch", and this is the only code that knows it may not be the
    /// Cardano one. Every `/epochs/{n}` read keeps using the real epoch
    /// ([`Self::chain_epoch`]); only the ceremony's own label and anchor move.
    epoch_scheme: crate::epoch::virtual_epoch::EpochScheme,
    /// How far into a cycle this node can first ENTER a ceremony, in slots —
    /// `protocol.dkg_window_secs + dkg_join_wait_secs`, at one slot per second.
    ///
    /// Held here only so a virtual epoch's rescaled `update_y_deadline` can be
    /// checked against it: a rotation deadline that falls inside the window a
    /// node cannot start before is one no honest node can ever meet, and the
    /// resulting signing window opens already closed without reporting anything.
    ceremony_floor_slots: u64,
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
    /// `protocol.state_dir`, read for the group keys of ceremonies this node took
    /// part in — extra candidates for the head's internal key.
    ///
    /// The head is locked under the key that held the treasury when it was
    /// created, and after an Update-Y that is a key the datum no longer names and
    /// the current ceremony did not produce: the OUTGOING epoch's. Without it the
    /// candidate list is `{this epoch's key, the datum's key, y_federation}` and a
    /// node in the handoff window cannot reconstruct the head's scriptPubKey at
    /// all — `query_treasury` fails outright, so the movement that would close the
    /// window is never even attempted. `None` keeps the pre-existing candidates,
    /// which is right for the one-shot CLI paths that persist no ceremony.
    state_dir: Option<std::path::PathBuf>,
    /// Whether to publish an oracle-update UTxO to Cardano after signing.
    submit_oracle: bool,
    /// Resolved Blockfrost base URL + project id, for raw-HTTP UTxO queries (lenient parsing).
    bf_base_url: String,
    bf_project_id: String,
    /// TreasuryMovementValidator CBOR, chain-sourced by the hash the Config
    /// publishes (#5) and verified against it — see `publish::resolve_tm_script`.
    /// `treasury_policy_id` is that same hash and `treasury_asset_name_hex` is
    /// empty. `None` means this chain cannot post a TM, which the startup gate
    /// refuses on a configured bridge (WI-HJ1N5).
    tm_script_cbor: Option<String>,
    /// Validity window (seconds) for posted TM txs (`invalid_hereafter`/`created` =
    /// latest + window). 1800 for preprod/mainnet; small on a short-epoch devnet whose
    /// era-forecast horizon is only ~tens-to-hundreds of slots ahead.
    validity_window_secs: u64,
    /// Bech32 address of the bridge Config UTxO and the config NFT unit
    /// (policy_id ++ asset_name hex) that authenticates it. The Config UTxO's field 11
    /// (initial_btc_treasury_utxo) anchors the TM chain. Required for treasury resolution.
    config_address: Option<String>,
    config_nft_unit: Option<String>,
    /// `(epoch, max_tx_size)` for the epoch it was read in (WI-107).
    ///
    /// Cached because `query_batch_snapshot` runs on every turn of the
    /// batch-opportunity poll, not once per batch, and two extra HTTP requests
    /// per turn is real load on a shared Blockfrost. Caching is exactly sound
    /// here and nowhere else: a protocol parameter is constant WITHIN an epoch by
    /// the ledger's own rules, which is the same property that makes reading it
    /// per epoch deterministic across SPOs in the first place.
    max_tx_size_by_epoch: Mutex<Option<(u64, u64)>>,
    /// The bridge Config as `query_batch_snapshot` last read it off the wire.
    ///
    /// The batch-opportunity poll runs every `batch_poll_ceiling` (5 min) for the
    /// whole of a `tm_batch_interval` (6 h on preprod), and re-reading the Config
    /// on each turn spent two requests to learn that a UTxO only governance can
    /// move had not moved. It is now re-read at the two moments its value can
    /// change what this node does — the start of a cycle, and the opportunity a
    /// movement is about to be built at — and reused in between. See
    /// [`config_refresh_due`].
    ///
    /// That is a pin, not merely a saving: every co-signer of one `B_i` now builds
    /// from a Config read at or after the SAME `B_i`, instead of from whenever each
    /// node's poll happened to land.
    config_cache: Mutex<Option<config_params::CachedConfig>>,
    /// The cycle anchor, cached for the cycle it describes.
    ///
    /// Sound for the same reason `max_tx_size_by_epoch` above is: an epoch's own
    /// boundaries do not move while the tip is inside it. Self-invalidating too —
    /// [`config_params::CycleAnchor::covers`] compares the tip against the span the
    /// chain reported, so the first tip past the boundary misses.
    epoch_anchor: Mutex<Option<config_params::CycleAnchor>>,
    /// The last TM this process submitted, and when. `query_treasury` reports
    /// `btc_confirmed = false` until that txid becomes the Confirmed chain tip, so the
    /// epoch machine waits for its own in-flight TM instead of double-spending the tip.
    ///
    /// The instant is what releases it: the bridge's published `tm_recovery_window`
    /// applies to this guard exactly as it does to the on-chain in-flight scan, and
    /// without it the node that SUBMITTED a movement that never confirms is the one
    /// node that can never recover — its peers time the record out and move on while
    /// it blocks itself for ever. A local `Instant` is the right clock here because
    /// this guard is itself process-local (a restart clears it, which is the case
    /// the on-chain scan covers).
    last_submitted_txid: Mutex<Option<(bitcoin::Txid, std::time::Instant)>>,
    /// Highest epoch `await_epoch_boundary` has already delivered, so a second
    /// call waits for the chain to move past it instead of firing again.
    last_boundary_epoch: Mutex<Option<u64>>,
    /// `(head outpoint → its scriptPubKey)`, resolved from the head-creating TM's
    /// bytes in Cardano history. Cached because the head only moves at Confirm and
    /// `address_history` is O(chain length) on Blockfrost. `Ok(None)` (the bootstrap
    /// anchor, which no TM created) is cached too.
    head_spk_cache: Mutex<Option<(bitcoin::OutPoint, Option<bitcoin::ScriptBuf>)>>,
    /// Optional automatic DKG fault proof mint + ApplyBan configuration.
    fault_ban_flow: Option<DkgFaultBanFlow>,
    /// Policy id of the bridge state singleton validator (Config field 3,
    /// `bridge_state_policy`). When set, `query_cpo_root` reads that singleton's
    /// `cpo_root` so `BuildTm` can
    /// cross-check its persisted trie against it. `None` disables the check.
    cpo_policy_id: Option<String>,
    /// Kupo base URL, used only to answer `query_cpo_root` when it is set — the
    /// same backend choice `reconstruct-cpo-trie` makes, so both reads see the
    /// same index. `None` falls back to the Blockfrost-compatible API.
    kupo_url: Option<String>,
    /// Where `query_pegout_requests` scans for PegOut UTxOs: the `peg_out.ak` bech32
    /// address plus the bridged-token unit that identifies one. `None` → the daemon pays
    /// no peg-out, and says so loudly on every build.
    pegout_source: Option<PegOutSource>,
    /// The contract identities of the batch currently being built, keyed on `B_i`.
    ///
    /// Written by [`Self::batch_snapshot`], which is the one read that already
    /// carries the spec's guarantees: it takes tip-then-Config, refuses a Config
    /// created after the tip, and retries — so everything derived from it belongs
    /// to one batch. Reading the identities from here instead of re-reading per
    /// scan is what turns "roughly current" into "as of this batch", which is the
    /// effect time the spec gives `params` (§Operational parameters) and which
    /// every co-signer of `B_i` reproduces.
    ///
    /// Shared with [`crate::cardano::blockfrost_source::BlockfrostPegInSource`],
    /// which scans a different address off the same Config and must not resolve it
    /// from a separate read — see [`Self::contracts_cache`].
    contracts_cache: crate::cardano::config_params::SharedContracts,
}

/// The bridge-state singleton as the post/build paths need it: the decoded
/// [`BridgeState`](crate::cardano::bridge_state::BridgeState) and the Cardano
/// UTxO holding it — the [PTM-7] mint reference input.
#[derive(Debug, Clone)]
pub struct SingletonView {
    pub state: crate::cardano::bridge_state::BridgeState,
    /// `(tx_hash, output_index)` of the singleton UTxO.
    pub utxo: (String, u32),
}

/// Enterprise (no stake part) bech32 address of a script hash. The bridge-state
/// singleton lives at exactly this shape: both bootstrap paths pay it to
/// `Address { payment: Script(policy), stake: None }`.
fn script_enterprise_address(hash: &[u8; 28], mainnet: bool) -> String {
    use pallas_addresses::{
        Address, Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
    };
    let network = if mainnet {
        Network::Mainnet
    } else {
        Network::Testnet
    };
    let shelley = ShelleyAddress::new(
        network,
        ShelleyPaymentPart::script_hash((*hash).into()),
        ShelleyDelegationPart::Null,
    );
    Address::Shelley(shelley)
        .to_bech32()
        .expect("bech32 encode script address")
}

/// Read the Config UTxO, then locate + decode the bridge-state singleton it
/// names ([PAR-1]): derive the enterprise address of `bridge_state_policy`
/// (Config field 3 — both deploy paths create the singleton there, stake part
/// `None`) and find the one UTxO holding the `(policy, "BSS")` NFT.
///
/// Returns the Config view (its UTxO is one mint reference input) and the
/// singleton view: the decoded BridgeState plus the Cardano UTxO holding it
/// (the [PTM-7] mint reference input). Shared by the epoch daemon and the CLI
/// sweep, so both resolve the treasury head the same way.
/// Whether a reused Config must be re-read before this snapshot may be used.
///
/// Two triggers, and they are the two moments at which a Config value can change
/// what this node does:
///
///  - **A new cycle.** Every schedule offset is measured from the cycle start, so
///    a Config carried over from the previous cycle places this cycle's grid — and
///    its rotation deadline — against a stale anchor.
///  - **An opportunity the read predates.** The Config decides the fee, the two
///    selection floors and the contract identities a movement is built from, and a
///    movement built at `B_i` must be built from a Config as of `B_i`. That is what
///    makes two co-signers of one opportunity reproduce each other's bytes.
///
/// Between those the Config is reused. It is a UTxO only governance moves, and a
/// governance move that lands mid-cycle then takes effect for every SPO at the
/// same anchor instead of at whenever each node's poll happened to land.
fn config_refresh_due(
    cached: &config_params::CachedConfig,
    anchor: Option<config_params::CycleAnchor>,
    batch: &crate::epoch::batch::BatchWindow,
) -> bool {
    // With no anchor there is no cycle to compare and no grid to place an
    // opportunity on. Nothing here can show the reuse is still good, so it is not
    // claimed to be.
    let Some(anchor) = anchor else { return true };
    anchor.start_slot != cached.anchor_slot
        || batch.open().is_some_and(|b| b.slot > cached.read_slot)
}

pub async fn fetch_config_singleton(
    bf_base_url: &str,
    bf_project_id: &str,
    config_address: &str,
    config_nft_unit: &str,
    mainnet: bool,
) -> Result<(config_params::ConfigView, SingletonView), String> {
    let view =
        config_params::fetch_config(bf_base_url, bf_project_id, config_address, config_nft_unit)
            .await?;
    let policy = view.params.bridge_state_policy;
    let policy_hex = hex::encode(policy);
    let address = script_enterprise_address(&policy, mainnet);
    let utxos = crate::cardano::bf_http::fetch_address_utxos(bf_base_url, bf_project_id, &address)
        .await
        .map_err(|e| format!("bridge-state singleton query: {e}"))?;
    let unit = format!(
        "{policy_hex}{}",
        crate::cardano::bridge_state::BSS_ASSET_NAME_HEX
    );
    let held: Vec<_> = utxos
        .iter()
        .filter(|u| u.amount.iter().any(|a| a.unit == unit && a.quantity == "1"))
        .collect();
    let u = match held.as_slice() {
        [only] => *only,
        [] => {
            return Err(format!(
                "no UTxO at {address} holds the bridge-state NFT {unit} — the singleton is not \
                 bootstrapped under Config field 3's policy, or the backend is not indexing it"
            ));
        }
        many => {
            return Err(format!(
                "{} UTxOs hold the bridge-state NFT {unit} — not a singleton, no state is \
                 authoritative",
                many.len()
            ));
        }
    };
    let inline = u.inline_datum.as_deref().ok_or_else(|| {
        format!(
            "the bridge-state singleton {}#{} carries no inline datum",
            u.tx_hash, u.output_index
        )
    })?;
    let cbor = hex::decode(inline).map_err(|e| format!("singleton datum hex decode: {e}"))?;
    let datum: PlutusData =
        minicbor::decode(&cbor).map_err(|e| format!("singleton datum CBOR decode: {e}"))?;
    let state = crate::cardano::bridge_state::parse_bridge_state(&datum)?;
    Ok((
        view,
        SingletonView {
            state,
            utxo: (u.tx_hash.clone(), u.output_index as u32),
        },
    ))
}

/// The scriptPubKey of `head`, read from the TM that created it: scan the TM
/// address's history (spent outputs INCLUDED — the head-creating record was
/// consumed by its own Confirm), parse each UnconfirmedTm datum, and take output
/// `head.vout` of the record whose btc txid equals the head's.
///
/// TRUSTLESS despite the address being permissionlessly payable:
/// `parse_unconfirmed_tm` RECOMPUTES the txid from the record's own embedded
/// bytes (`compute_txid()`), so a hostile record can only ever occupy the slot
/// of its own hash — which this lookup never asks for unless the singleton's
/// attested head leads there. `Ok(None)` = no record creates this head (the
/// bootstrap anchor). An output whose datum EXISTS but cannot be resolved is
/// skipped: if it hid the head-creating TM, the result degrades to the
/// bootstrap fallback, never to a wrong script.
pub async fn head_spk_from_history(
    source: &dyn crate::cardano::cpo_history::CpoHistorySource,
    tm_address: &str,
    head: &bitcoin::OutPoint,
) -> Result<Option<bitcoin::ScriptBuf>, String> {
    let outputs = source
        .address_history(tm_address)
        .await
        .map_err(|e| format!("TM address history ({}): {e}", source.backend()))?;
    for out in &outputs {
        let Some(datum) = out.datum.resolved() else {
            continue;
        };
        let Some(tm) = parse_unconfirmed_tm(datum) else {
            continue;
        };
        if tm.btc_txid == head.txid {
            return Ok(tm
                .outputs
                .get(head.vout as usize)
                .map(|(_, spk)| spk.clone()));
        }
    }
    Ok(None)
}

/// The two values `pegout_datum::fetch_pegout_requests` needs. The `sweep-pegins` CLI takes
/// them as arguments; the daemon has no argv, so the chain carries them.
#[derive(Debug, Clone)]
struct PegOutSource {
    /// Bech32 address of the `peg_out.ak` script holding PegOut UTxOs.
    address: String,
    /// Bridged-token (fBTC) unit `<policy_hex><asset_name_hex>` whose quantity in a UTxO's
    /// value is the locked peg-out amount.
    fbtc_unit: String,
}

/// How many retired peg-in internal keys a node keeps recognising, on real
/// Cardano epochs.
///
/// Every entry costs one full Taproot derivation per peg-in request scanned, and
/// the peg-in address is permissionlessly payable, so the cost is paid on foreign
/// deposits too. Eight epochs is ~40 days on Cardano — well past the published
/// refund timeout of any deposit made under such a key, so what falls off the end
/// is a deposit whose depositor can already take it back.
///
/// The justification is a span of TIME, but the unit is CEREMONIES — one key per
/// epoch. A virtual epoch runs the ceremony many times more often, so the cap is
/// scaled to hold the same wall-clock span (see
/// [`BlockfrostCardanoChain::recognised_retired_keys`]); leaving it at eight
/// there would forget keys after eight cycles — eight days on a 24-hour cycle —
/// while `pegin_refund_timeout_blocks` is a Bitcoin block count the virtual epoch
/// does not touch, so a depositor could NOT yet take the deposit back.
const MAX_RECOGNISED_RETIRED_KEYS: usize = 8;

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
            local_fee_rate_sat_per_vb: 1,
            fallback_roster,
            registry_roster: None,
            ban_source: None,
            federation_refresh: None,
            stake_source: crate::cardano::stake::StakeSource::Blockfrost,
            demo_exclude_unstaked: false,
            demo_live_stake: false,
            epoch_scheme: crate::epoch::virtual_epoch::EpochScheme::Cardano,
            ceremony_floor_slots: crate::config::ProtocolConfig::default().ceremony_floor_slots(),
            payment_key: None,
            wallet_base_address: None,
            treasury_y_51: Mutex::new(None),
            state_dir: None,
            submit_oracle: true,
            tm_script_cbor: None,
            validity_window_secs: 1800,
            config_address: None,
            config_nft_unit: None,
            last_submitted_txid: Mutex::new(None),
            last_boundary_epoch: Mutex::new(None),
            head_spk_cache: Mutex::new(None),
            config_cache: Mutex::new(None),
            epoch_anchor: Mutex::new(None),
            max_tx_size_by_epoch: Mutex::new(None),
            fault_ban_flow: None,
            cpo_policy_id: None,
            kupo_url: None,
            pegout_source: None,
            contracts_cache: crate::cardano::config_params::SharedContracts::default(),
        }
    }

    /// Point `query_pegout_requests` at the `peg_out.ak` address (WI-030). Without it the
    /// daemon builds Treasury Movements that pay no withdrawal at all.
    #[must_use]
    pub fn with_pegout_source(
        mut self,
        address: impl Into<String>,
        fbtc_unit: impl Into<String>,
    ) -> Self {
        self.pegout_source = Some(PegOutSource {
            address: address.into(),
            fbtc_unit: fbtc_unit.into(),
        });
        self
    }

    /// Locate the on-chain bridge state singleton so `query_cpo_root` can
    /// answer. Without it every `BuildTm` runs its trie unchecked, which is the
    /// state in which a stale persisted trie gets attested.
    pub fn with_cpo_source(mut self, cpo_policy_id: Option<&str>, kupo_url: Option<&str>) -> Self {
        self.cpo_policy_id = cpo_policy_id.map(|s| s.trim().to_ascii_lowercase());
        self.kupo_url = kupo_url.map(str::to_string);
        self
    }

    /// Mint the TM NFT under the real TreasuryMovementValidator policy. The CBOR
    /// comes from `publish::resolve_tm_script` — the chain, by Config #5 — so
    /// nothing here has to trust a value an operator typed.
    pub fn with_tm_policy(mut self, script_cbor: &str) -> Self {
        self.tm_script_cbor = Some(script_cbor.to_string());
        self
    }

    /// The REAL Cardano epoch — the index every `/epochs/{n}` read uses.
    ///
    /// Distinct from the trait's `current_epoch`, which answers the epoch the
    /// CEREMONY runs under and may be a virtual one. The two are the same
    /// number in production; conflating them under a virtual epoch would ask
    /// Blockfrost for the stake snapshot of an epoch that does not exist.
    async fn chain_epoch(&self) -> EpochResult<u64> {
        crate::cardano::bf_http::fetch_current_epoch(&self.bf_base_url, &self.bf_project_id)
            .await
            .map_err(|e| EpochError::Chain(format!("fetch current epoch: {e}")))
    }

    /// Read the DKG context for a ceremony epoch.
    ///
    /// The one place the two epochs meet. Every chain read inside
    /// `fetch_dkg_context` — the stake snapshot, the boundary time the ban
    /// filter is evaluated at — is indexed by the REAL Cardano epoch, because
    /// those are Cardano's own indices and a virtual number names an epoch the
    /// chain has never had. What the ceremony is LABELLED with, and anchors its
    /// round deadlines to, is the virtual cycle. On a production bridge the two
    /// are the same number and this does nothing.
    async fn fetch_ceremony_context(
        &self,
        registry: &crate::cardano::roster::RegistryRosterSource,
        bans: Option<&crate::cardano::ban_list::BanListSource>,
        epoch: u64,
        attempt: u32,
    ) -> EpochResult<crate::cardano::dkg_roster::DkgContext> {
        // Which Cardano epoch the chain reads are indexed by.
        //
        // On real epochs the requested epoch IS that epoch, used as given rather
        // than re-read: the caller asked for a specific one, and a tip that
        // ticked over between `await_epoch_boundary` and here would otherwise
        // silently move the ceremony onto the next epoch's stake snapshot and
        // boundary time.
        //
        // A virtual cycle needs a real epoch it cannot simply be handed, and
        // reading the CURRENT one would take exactly the race just described —
        // two nodes entering one virtual ceremony seconds apart across a Cardano
        // boundary would read 300 and 301, and derive different stake snapshots
        // and ban cutoffs for the same ceremony. So it is derived from the
        // CYCLE'S ANCHOR instead: the epoch containing the slot this cycle began
        // at, which is a function of the ceremony epoch and nothing else.
        let chain_epoch = match self.epoch_scheme.virtual_slots() {
            Some(slots) => {
                self.chain_epoch_containing(epoch.saturating_mul(slots))
                    .await?
            }
            None => epoch,
        };
        let mut ctx = crate::cardano::dkg_roster::fetch_dkg_context(
            registry,
            bans,
            &self.bf_base_url,
            &self.bf_project_id,
            self.stake_source,
            chain_epoch,
            attempt,
            self.demo_exclude_unstaked,
            self.demo_live_stake,
        )
        .await
        .map_err(eligible_roster_error(epoch, attempt))?;
        if let Some(anchor_ms) = self.ceremony_anchor_ms(epoch).await? {
            info!(
                "[virtual-epoch] ceremony epoch {epoch} (Cardano epoch {chain_epoch}) anchored \
                 at {anchor_ms} ms — the roster, its stake and the ban cutoff are read under \
                 the Cardano epoch; only the ceremony's own schedule is virtual"
            );
            ctx.epoch = epoch;
            ctx.schedule_anchor_ms = Some(anchor_ms);
        }
        Ok(ctx)
    }

    /// [`MAX_RECOGNISED_RETIRED_KEYS`], scaled so a virtual epoch keeps the same
    /// wall-clock span rather than the same number of ceremonies.
    ///
    /// The cap exists to bound a per-deposit derivation cost, and its size was
    /// chosen to outlast the published refund timeout. That timeout is measured
    /// in Bitcoin blocks and does not shrink with the bridge's cycle, so the cap
    /// must not either.
    fn recognised_retired_keys(&self) -> usize {
        use crate::epoch::virtual_epoch::CARDANO_EPOCH_SLOTS;

        match self.epoch_scheme.virtual_slots() {
            None => MAX_RECOGNISED_RETIRED_KEYS,
            Some(slots) => {
                let per_epoch = usize::try_from(CARDANO_EPOCH_SLOTS.div_ceil(slots.max(1)))
                    .unwrap_or(1)
                    .max(1);
                MAX_RECOGNISED_RETIRED_KEYS.saturating_mul(per_epoch)
            }
        }
    }

    /// The Cardano epoch that contains `slot`.
    ///
    /// Derived from the current epoch and its boundary rather than looked up,
    /// because the arithmetic normalises: a node that reads epoch 300 starting at
    /// `S` and one that has already rolled to 301 starting at `S + 432000` both
    /// answer the same epoch for the same slot. That is what makes it usable as a
    /// consensus input, where reading "the current epoch" is not.
    ///
    /// Only a virtual cycle calls it, and only to index chain reads; on a real
    /// epoch the ceremony epoch already IS the answer.
    async fn chain_epoch_containing(&self, slot: u64) -> EpochResult<u64> {
        use crate::epoch::virtual_epoch::CARDANO_EPOCH_SLOTS;

        let now = self.chain_epoch().await?;
        let start_ms = crate::cardano::bf_http::fetch_epoch_start_ms(
            &self.bf_base_url,
            &self.bf_project_id,
            now,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("epoch {now} boundary: {e}")))?;
        let (tip_slot, tip_ms) = self.tip_slot_time_ms().await?;
        let start_slot = crate::cardano::bf_http::slot_at_time(tip_slot, tip_ms, start_ms);
        Ok(if slot >= start_slot {
            // Inside the current epoch, or past it if the cycle anchor is ahead
            // of the tip — which a ceremony entered at its own boundary can be.
            now.saturating_add((slot - start_slot) / CARDANO_EPOCH_SLOTS)
        } else {
            // Whole epochs back from this one's boundary, rounding away from it.
            let back = (start_slot - slot).div_ceil(CARDANO_EPOCH_SLOTS);
            now.saturating_sub(back)
        })
    }

    /// The tip's `(slot, posix_time_ms)` — the only input a virtual cycle takes,
    /// which is what lets two nodes agree on one with no anchor to exchange.
    async fn tip_slot_time_ms(&self) -> EpochResult<(u64, i64)> {
        crate::cardano::bf_http::fetch_latest_block_slot_time(
            &self.bf_base_url,
            &self.bf_project_id,
        )
        .await
        .map(|(slot, secs)| (slot, secs * 1000))
        .map_err(|e| EpochError::Chain(format!("tip for the virtual epoch: {e}")))
    }

    /// The chain time a ceremony epoch began, or `None` on real Cardano epochs
    /// (where `fetch_dkg_context` reads the boundary from `/epochs/{n}`).
    ///
    /// Derived from the epoch NUMBER rather than from the tip, so the anchor
    /// always belongs to the epoch being run — a cycle that ticked over between
    /// `await_epoch_boundary` and here would otherwise hand the ceremony an
    /// anchor from the following one. The conversion is the exact post-Shelley
    /// one-second-per-slot identity, signed so it works for a start slot on
    /// either side of the tip.
    async fn ceremony_anchor_ms(&self, epoch: u64) -> EpochResult<Option<i64>> {
        let Some(slots) = self.epoch_scheme.virtual_slots() else {
            return Ok(None);
        };
        let (tip_slot, tip_ms) = self.tip_slot_time_ms().await?;
        let start_slot = i128::from(epoch).saturating_mul(i128::from(slots));
        let delta_ms = (start_slot - i128::from(tip_slot)).saturating_mul(1000);
        Ok(Some(tip_ms.saturating_add(
            i64::try_from(delta_ms).unwrap_or(i64::MAX),
        )))
    }

    /// The schedule in force for this deployment: the published one, rescaled if
    /// the bridge runs on a virtual epoch.
    ///
    /// One place, so the grid, the Update-Y close and the stuck-TM recovery
    /// window cannot end up on different versions of it.
    fn schedule_in_force(
        &self,
        raw: &crate::cardano::config_params::ScheduleParams,
    ) -> EpochResult<crate::cardano::config_params::ScheduleParams> {
        self.epoch_scheme
            .schedule(raw, self.ceremony_floor_slots)
            .map_err(|e| {
                EpochError::Chain(format!(
                    "the virtual epoch cannot hold this bridge's schedule: {e}. No batch will                      be built until this is resolved, on every node"
                ))
            })
    }

    /// The Config this node last read off the wire, if the cache still holds one.
    fn cached_config(&self) -> Option<config_params::CachedConfig> {
        self.config_cache.lock().ok().and_then(|c| c.clone())
    }

    /// The cycle `snapshot`'s tip falls in, read at most once per cycle.
    ///
    /// `None` means the boundary could not be read: the caller degrades to a grid
    /// without a membership cutoff, which is what an unreadable boundary has always
    /// cost. It is not cached, so the next turn tries again.
    async fn cycle_anchor(
        &self,
        snapshot: &config_params::ParamSnapshot,
    ) -> Option<config_params::CycleAnchor> {
        if let Some(a) = self.epoch_anchor.lock().ok().and_then(|a| *a)
            && a.covers(snapshot.slot)
        {
            return Some(a);
        }
        match config_params::cycle_anchor(
            &self.bf_base_url,
            &self.bf_project_id,
            snapshot,
            self.epoch_scheme,
        )
        .await
        {
            Ok(a) => {
                // Only a bounded anchor is worth keeping: without `end_slot` there
                // is no test for when it stops being true.
                if a.end_slot.is_some()
                    && let Ok(mut slot) = self.epoch_anchor.lock()
                {
                    *slot = Some(a);
                }
                Some(a)
            }
            Err(e) => {
                warn!(
                    "[batch] no epoch anchor ({e}) — building without the batch membership \
                     cutoff; peg-out selection falls back to whatever is open at this instant"
                );
                None
            }
        }
    }

    /// Cardano's `max_tx_size` for the current epoch, cached per epoch (WI-107).
    ///
    /// An error here refuses the batch rather than falling back to a default: a
    /// guessed budget is a guessed *consensus* value, and a node freezing against
    /// one computes a set no peer reproduces. Failing loudly costs one tick of
    /// back-off; guessing costs a signing round that cannot aggregate, with
    /// nothing in the logs pointing at why.
    async fn max_tx_size(&self, anchor: Option<config_params::CycleAnchor>) -> EpochResult<u64> {
        // The REAL epoch: `/epochs/{n}/parameters` is a Cardano index, and a
        // virtual epoch number would name an epoch the chain has never had.
        //
        // On a Cardano scheme the cycle anchor IS that epoch, and it is already
        // cached for the epoch's span — so the value below was cached per epoch
        // while the request that learned WHICH epoch went out on every turn of the
        // poll. A virtual cycle's label is not a Cardano epoch number and can never
        // stand in for one, so that scheme still reads.
        let epoch = match anchor {
            Some(a)
                if matches!(
                    self.epoch_scheme,
                    crate::epoch::virtual_epoch::EpochScheme::Cardano
                ) =>
            {
                a.epoch
            }
            _ => self.chain_epoch().await?,
        };
        if let Some((cached_epoch, value)) = *self.max_tx_size_by_epoch.lock().unwrap()
            && cached_epoch == epoch
        {
            return Ok(value);
        }
        let value = crate::cardano::bf_http::fetch_max_tx_size(
            &self.bf_base_url,
            &self.bf_project_id,
            epoch,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("max_tx_size for epoch {epoch}: {e}")))?;
        *self.max_tx_size_by_epoch.lock().unwrap() = Some((epoch, value));
        Ok(value)
    }

    /// `E` for the TM batch budget: the Post-TM bytes that do not scale with the
    /// batch (WI-107).
    ///
    /// The TM validator script is the dominant and the only variable part, and
    /// this adapter is the one place that knows it — `submit_signed_tm` hands it
    /// to whisky as a `ProvidedScriptSource`, so it rides INLINE in the witness
    /// set of every Post-TM. Deploying it as a reference script instead would
    /// give the batch roughly ten more peg-in/peg-out pairs; until then its bytes
    /// are honestly charged to the budget rather than assumed away.
    ///
    /// Deterministic across SPOs because the script is the bridge's, not the
    /// operator's: a node with different bytes here is minting under a different
    /// policy and is not on this bridge at all.
    fn post_tm_envelope(&self) -> u64 {
        let script_bytes = self
            .tm_script_cbor
            .as_deref()
            // Hex in, bytes out; +8 for the witness-set entry that wraps it.
            .map_or(0, |hex| (hex.len() as u64) / 2 + 8);
        crate::epoch::traits::POST_TM_ENVELOPE_WITHOUT_SCRIPT + script_bytes
    }

    /// Override the TM-tx validity window (seconds). Use a small value on short-epoch
    /// devnets to stay within the era-forecast horizon.
    pub fn with_validity_window(mut self, secs: u64) -> Self {
        self.validity_window_secs = secs;
        self
    }

    /// Wait until a submitted Cardano transaction is indexed, or until its
    /// validity window has elapsed. A timeout is returned to the epoch loop,
    /// which re-reads chain state and rebuilds the transaction from fresh
    /// UTxOs instead of replaying stale bytes.
    async fn wait_for_cardano_confirmation(&self, tx_hash: &str) -> EpochResult<()> {
        let timeout = Duration::from_secs(self.validity_window_secs.max(1));
        let poll = Duration::from_secs(5);
        let started = tokio::time::Instant::now();
        loop {
            match crate::cardano::bf_http::fetch_tx_inclusion(
                &self.bf_base_url,
                &self.bf_project_id,
                tx_hash,
            )
            .await
            {
                Ok(Some(block_time)) => {
                    info!(
                        "[submit] Cardano oracle-update confirmed: tx_hash={tx_hash} block_time={block_time}"
                    );
                    return Ok(());
                }
                Ok(None) if started.elapsed() < timeout => {
                    debug!("[submit] Cardano tx {tx_hash} pending; polling again in {poll:?}");
                    tokio::time::sleep(poll).await;
                }
                Ok(None) => {
                    return Err(EpochError::Chain(format!(
                        "Cardano tx {tx_hash} was not indexed before its validity window expired"
                    )));
                }
                Err(e) => {
                    return Err(EpochError::Chain(format!(
                        "Cardano tx {tx_hash} confirmation query failed: {e}"
                    )));
                }
            }
        }
    }

    /// Locate the bridge Config UTxO (address + config NFT unit `policy_id ++ asset_name`).
    /// Its field #11 (initial_btc_treasury_utxo) anchors the Treasury Movement chain, and
    /// its `params` record holds the operational parameters every TM is built from.
    pub fn with_config_utxo(mut self, address: &str, nft_unit: &str) -> Self {
        self.config_address = Some(address.to_string());
        self.config_nft_unit = Some(nft_unit.to_string());
        self
    }

    /// Where this node's persisted ceremonies live — see [`Self::state_dir`].
    #[must_use]
    pub fn with_state_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.state_dir = dir;
        self
    }

    /// The group keys of every ceremony persisted under `state_dir`, newest
    /// epoch first.
    ///
    /// Best-effort by design: these are only CANDIDATES, and the head's actual
    /// scriptPubKey decides. A state dir that cannot be read must not turn a
    /// treasury query into a failure — it just leaves the caller with the
    /// candidates it had before.
    fn persisted_internal_candidates(&self) -> Vec<(u64, bitcoin::key::UntweakedPublicKey)> {
        let Some(dir) = self.state_dir.as_deref() else {
            return Vec::new();
        };
        let Ok(epochs) = crate::epoch::persist::persisted_dkg_epochs(dir) else {
            return Vec::new();
        };
        epochs
            .into_iter()
            .filter_map(|e| {
                let state = crate::epoch::persist::read_dkg_state(dir, e)
                    .ok()
                    .flatten()?;
                let keys = state.to_group_keys().ok()?;
                let g = crate::frost::xonly::group_xonly(&keys.verifying_key).ok()?;
                Some((e, g.xonly))
            })
            .collect()
    }

    /// The `bitcoin.fee_rate_sat_per_vb` dev override, for the paths that have no
    /// Config UTxO to read (see [`Self::query_batch_snapshot`]).
    #[must_use]
    pub fn with_local_fee_rate(mut self, sat_per_vb: u64) -> Self {
        self.local_fee_rate_sat_per_vb = sat_per_vb;
        self
    }

    /// Configure automatic DKG fault proof minting followed by ApplyBan.
    pub fn with_dkg_fault_ban_flow(mut self, flow: DkgFaultBanFlow) -> Self {
        self.fault_ban_flow = Some(flow);
        self
    }

    /// Locate + decode the singleton `treasury_info` state UTxO (the one holding
    /// the K1 NFT) at the script address.
    async fn find_treasury_info_state(
        &self,
        registry: &crate::cardano::roster::RegistryRosterSource,
    ) -> EpochResult<crate::cardano::treasury_spend::TreasuryStateUtxo> {
        let utxos = crate::cardano::bf_http::fetch_address_utxos(
            &self.bf_base_url,
            &self.bf_project_id,
            &registry.treasury_info_address,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("treasury_info UTxO query: {e}")))?;
        crate::cardano::treasury_spend::find_treasury_state(
            &utxos,
            &registry.treasury_info_policy_hex,
            &registry.treasury_info_asset_name_hex,
        )
        .map_err(|e| EpochError::Chain(format!("locate treasury_info state: {e}")))
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

    /// Re-resolve the federation identity (Config #8, #9–#10) from the chain on
    /// every roster read, instead of running forever on whatever startup saw.
    pub fn with_federation_refresh(mut self, cardano: crate::config::CardanoConfig) -> Self {
        self.federation_refresh = Some(cardano);
        self
    }

    /// The registry + ban sources AS OF NOW, re-read from the bridge Config.
    ///
    /// The startup-resolved pair is the fallback, not the answer: #8 and #9–#10
    /// are chain state, and a node that pinned them at boot filters a different
    /// roster from a node booted after a governance Update — a divergence keyed on
    /// restart time, which no operator can see and no log records. The batch
    /// snapshot already re-reads `params` on the same reasoning.
    ///
    /// Refreshing is skipped (and the pinned pair returned) when there is nothing
    /// to refresh from: no Config locator, or a Config that publishes neither
    /// append, in which case `resolve` would fall back to the same local keys
    /// startup used anyway.
    async fn current_federation(
        &self,
    ) -> EpochResult<(
        Option<crate::cardano::roster::RegistryRosterSource>,
        Option<crate::cardano::ban_list::BanListSource>,
    )> {
        let pinned = || (self.registry_roster.clone(), self.ban_source.clone());
        let (Some(cardano), Some(addr), Some(unit)) = (
            self.federation_refresh.as_ref(),
            self.config_address.as_deref(),
            self.config_nft_unit.as_deref(),
        ) else {
            return Ok(pinned());
        };
        // A Config read that fails must NOT quietly leave the node on its pinned
        // copy — that is the divergence again, just triggered by a network blip
        // instead of a restart. So absorb the blip instead: every other
        // consensus-relevant read on this path retries (`fetch_snapshot`,
        // `fetch_ban_list`), and a read this one depends on should not be the one
        // that kills a ceremony over a 502.
        //
        // Retried unconditionally rather than on a classified error: `fetch_config`
        // reports as a plain string, and a permanent failure (a datum this build
        // cannot decode) repeats identically — so the cost of not classifying is
        // seven seconds before it surfaces, at epoch scale.
        let view = crate::cardano::retry::retry_transient(
            &crate::cardano::retry::DEFAULT_DELAYS,
            "federation-config",
            |_: &String| true,
            || {
                crate::cardano::config_params::fetch_config(
                    &self.bf_base_url,
                    &self.bf_project_id,
                    addr,
                    unit,
                )
            },
        )
        .await
        .map_err(|e| {
            EpochError::Chain(format!(
                "bridge Config (federation identity #8/#9-#10): {e}"
            ))
        })?;

        let registry =
            crate::cardano::roster::RegistryRosterSource::resolve(cardano, Some(&view.params))
                .map_err(|e| EpochError::Chain(format!("registry identity: {e}")))?;
        let bans = crate::cardano::ban_list::BanListSource::resolve(cardano, Some(&view.params))
            .map_err(|e| EpochError::Chain(format!("ban policy: {e}")))?;

        // Say so when the chain moved under us. A federation identity change is a
        // governance event, not a parameter tweak, and it must not be something an
        // operator only discovers by diffing two nodes' logs.
        for (what, was, now) in [
            (
                "registry",
                self.registry_roster
                    .as_ref()
                    .map(|r| &r.registry_policy_hex),
                registry.as_ref().map(|r| &r.registry_policy_hex),
            ),
            (
                "treasury_info",
                self.registry_roster
                    .as_ref()
                    .map(|r| &r.treasury_info_policy_hex),
                registry.as_ref().map(|r| &r.treasury_info_policy_hex),
            ),
            (
                "ban policy",
                self.ban_source.as_ref().map(|b| &b.ban_policy_hex),
                bans.as_ref().map(|b| &b.ban_policy_hex),
            ),
        ] {
            if was != now {
                warn!(
                    "[federation] the bridge Config now publishes a different {what}: {} -> {} \
                     (Config UTxO {}). This node follows the chain, not its startup snapshot",
                    was.map_or("<none>", String::as_str),
                    now.map_or("<none>", String::as_str),
                    view.utxo
                );
            }
        }
        Ok((registry, bans))
    }

    /// The shared cell this chain pins each batch's contract identities into.
    ///
    /// Hand it to the peg-in source so both scan the addresses of the SAME Config
    /// read. Two independent reads would be two chances to straddle a governance
    /// Update, and the peg-in scan is precisely where that is invisible: a policy
    /// from one read and an address from another filter every UTxO out, which
    /// looks like an empty bridge.
    #[must_use]
    pub fn contracts_cache(&self) -> crate::cardano::config_params::SharedContracts {
        std::sync::Arc::clone(&self.contracts_cache)
    }

    /// Pin the identities `B_i` is built against — ONCE per `B_i`, on its first read.
    ///
    /// The batch discipline lives here, on the write, not on the read. An earlier
    /// version re-pinned on every call and validated the window when reading, which
    /// defeated the whole purpose: `await_batch_opportunity` polls this in a loop,
    /// so node A pinning at `B_i + 10s` and node B at `B_i + 240s` straddled a
    /// governance Update landing between them and both passed the window test. They
    /// then scanned different addresses for the SAME movement. First-read-wins is
    /// what makes co-signers of one `B_i` agree.
    ///
    /// Three rules, each load-bearing:
    ///  - only while an opportunity is OPEN. `batch.next()` is a FUTURE slot, and
    ///    keying a pin to it means adopting a Config read that predates `B_i` as
    ///    though it were `B_i`'s snapshot.
    ///  - never over a pin for the same `B_i`, which is the rule above.
    ///  - a datum that will not decode CLEARS the cell rather than leaving the last
    ///    one standing. Leaving it lets the peg-in source keep scanning the previous
    ///    address with no log line while this side hard-errors — the two halves
    ///    disagreeing, which is the failure this cell exists to prevent.
    fn remember_contracts(
        &self,
        snapshot: &crate::cardano::config_params::ParamSnapshot,
        batch: Option<crate::epoch::batch::BatchSlot>,
    ) {
        let Some(batch) = batch else {
            return;
        };
        let Ok(mut slot) = self.contracts_cache.lock() else {
            return;
        };
        if slot.as_ref().and_then(|e| e.batch_key) == Some(batch.slot) {
            // Still inside the batch this was pinned for, so the pin stands — that
            // IS the rule. But say so when the chain has moved under it: "held
            // deliberately" and "never noticed" look identical in a log that says
            // nothing, and an operator who has just run update-config needs to be
            // able to tell that their change was seen and is queued rather than
            // lost. Reported once per newer Config, not once per poll.
            let seen = snapshot.config.utxo.to_string();
            if let Some(entry) = slot
                .as_mut()
                .filter(|e| e.config_utxo != seen && e.reported_unadopted.as_deref() != Some(&seen))
            {
                warn!(
                    "[contracts] a bridge Config Update has landed ({} -> {}) and this node \
                         is NOT on it yet: B_{} is already pinned to the earlier one, and an \
                         update takes effect from the next batch, never retroactively. Nothing \
                         is wrong; the next opportunity adopts it",
                    entry.config_utxo, seen, batch.index,
                );
                entry.reported_unadopted = Some(seen);
            }
            return;
        }
        let contracts = match snapshot.config.params.bridge_contracts(self.is_mainnet()) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "[contracts] the bridge Config at {} does not yield addresses ({e}) — \
                     dropping the batch pin so every reader fails on it by name rather than \
                     scanning the last batch's addresses in silence",
                    snapshot.config.utxo
                );
                *slot = None;
                return;
            }
        };
        let entry = crate::cardano::config_params::BatchContracts {
            batch_key: Some(batch.slot),
            pegin_tree_inputs: snapshot.config.params.pegin_tree_inputs(),
            reported_unadopted: None,
            contracts,
            config_utxo: snapshot.config.utxo.to_string(),
        };
        let moved = slot
            .as_ref()
            .filter(|p| p.contracts != entry.contracts)
            .map(|p| p.config_utxo.clone());
        if let Some(was) = moved {
            warn!(
                "[contracts] the bridge Config moved between batches: Config UTxO {was} -> {}. \
                 B_{} is built against the new one; peg-in {} peg-out {}",
                entry.config_utxo,
                batch.index,
                entry.contracts.pegin_script_address,
                entry.contracts.pegout_script_address,
            );
        }
        *slot = Some(entry);
    }

    /// The identities pinned for the batch — a cache read, nothing else.
    ///
    /// Deliberately NOT gated on "is that batch still open". Between opportunities
    /// the pin holds the last batch's Config, and holding it is correct: the spec's
    /// rule is that an update takes effect from the NEXT batch, so the next pin is
    /// what adopts it. The previous version gated this on an unretried tip read, so
    /// one 502 dropped a node onto a live Config read while its peers stayed pinned
    /// — the divergence again, with a network blip as the trigger — and cost an
    /// extra HTTP round trip per call besides.
    fn contracts_for_batch(&self) -> Option<crate::cardano::config_params::BridgeContracts> {
        let slot = self.contracts_cache.lock().ok()?;
        Some(slot.as_ref()?.contracts.clone())
    }

    /// The scanned contract identities AS OF NOW, re-read from the bridge Config.
    ///
    /// The other half of [`Self::current_federation`], on the same argument.
    /// `with_pegout_source` and `with_cpo_source` are set once from the boot read,
    /// so a governance Update to Config #2/#4/#7 leaves a long-running node
    /// scanning addresses nobody uses any more and reporting nothing pending —
    /// which reads exactly like a quiet bridge. Restarting does not fix it either:
    /// the restarted node then disagrees with every peer that has not restarted.
    ///
    /// This BOUNDS that divergence rather than removing it. Two nodes reading
    /// seconds apart across an Update still disagree for the width of one read —
    /// but that replaces "however long since each last restarted", which is
    /// unbounded, invisible, and does not heal on its own. Making it exactly zero
    /// needs an adoption point every node derives from chain rather than from
    /// observation time; the batch snapshot slot is the candidate, since every
    /// co-signer takes it for the same batch. That is a protocol decision
    /// (WI-2AHGZ), not one this can settle locally.
    ///
    /// `Ok(None)` → no Config locator to refresh from, and the pinned values stand.
    async fn current_contracts(
        &self,
    ) -> EpochResult<Option<crate::cardano::config_params::BridgeContracts>> {
        // The batch snapshot's answer, when there is one for the batch now open.
        // This is the path that matters: it is the same ConfigView every co-signer
        // of this B_i derived from, so no two of them can scan different addresses
        // for one movement.
        if let Some(c) = self.contracts_for_batch() {
            return Ok(Some(c));
        }
        // No batch taken yet (startup, or a deployment with no grid), so read for
        // ourselves rather than run on the boot copy. Bounded-and-self-healing, not
        // "as of the batch" — see the type doc on `contracts_cache`.
        let (Some(addr), Some(unit)) = (
            self.config_address.as_deref(),
            self.config_nft_unit.as_deref(),
        ) else {
            return Ok(None);
        };
        // Retried on `current_federation`'s reasoning: a Config read that fails must
        // not quietly leave the node on its pinned copy, or the divergence is back
        // with a 502 as the trigger instead of a restart.
        let view = crate::cardano::retry::retry_transient(
            &crate::cardano::retry::DEFAULT_DELAYS,
            "contracts-config",
            |_: &String| true,
            || {
                crate::cardano::config_params::fetch_config(
                    &self.bf_base_url,
                    &self.bf_project_id,
                    addr,
                    unit,
                )
            },
        )
        .await
        .map_err(|e| {
            EpochError::Chain(format!("bridge Config (contract identities #2/#4/#7): {e}"))
        })?;

        let contracts = view
            .params
            .bridge_contracts(self.is_mainnet())
            .map_err(|e| EpochError::Chain(format!("contract identities: {e}")))?;

        // Say so when the chain moved under us, for the reason the federation
        // refresh says so: a contract move is a governance event, and an operator
        // must not have to diff two nodes' logs to discover it.
        for (what, was, now) in [
            (
                "peg-out address",
                self.pegout_source.as_ref().map(|s| &s.address),
                &contracts.pegout_script_address,
            ),
            (
                "fBTC unit",
                self.pegout_source.as_ref().map(|s| &s.fbtc_unit),
                &contracts.bridged_token_unit,
            ),
            (
                "bridge-state policy",
                self.cpo_policy_id.as_ref(),
                &contracts.bridge_state_policy_id,
            ),
        ] {
            if was.is_some_and(|w| w != now) {
                warn!(
                    "[contracts] the bridge Config now publishes a different {what}: {} -> {now} \
                     (Config UTxO {}). This node follows the chain, not its startup snapshot",
                    was.map_or("<none>", String::as_str),
                    view.utxo
                );
            }
        }
        Ok(Some(contracts))
    }

    /// Select where per-pool active stake is read (Blockfrost vs a local
    /// yaci-devkit devnet). Only meaningful alongside [`Self::with_registry_roster`].
    pub fn with_stake_source(mut self, source: crate::cardano::stake::StakeSource) -> Self {
        self.stake_source = source;
        self
    }

    /// TEST-RUN ONLY: weight the DKG roster by `live_stake` rather than the epoch
    /// snapshot (see [`crate::config::CardanoConfig::demo_live_stake`]).
    #[must_use]
    pub fn with_demo_live_stake(mut self, v: bool) -> Self {
        self.demo_live_stake = v;
        self
    }

    /// TEST-RUN ONLY: run the bridge's cycle on a virtual epoch (see
    /// [`crate::config::CardanoConfig::demo_virtual_epoch_slots`]). The value is
    /// validated at config load, so an unusable one never reaches here.
    #[must_use]
    pub fn with_epoch_scheme(mut self, scheme: crate::epoch::virtual_epoch::EpochScheme) -> Self {
        self.epoch_scheme = scheme;
        self
    }

    /// The ceremony-entry floor a virtual epoch's Update-Y deadline is checked
    /// against — see [`Self::ceremony_floor_slots`].
    #[must_use]
    pub fn with_ceremony_floor_slots(mut self, slots: u64) -> Self {
        self.ceremony_floor_slots = slots;
        self
    }

    /// DEMO-ONLY: exclude eligible pools whose Cardano stake can't be resolved
    /// from the roster (instead of failing the stake-weighted derivation).
    pub fn with_demo_exclude_unstaked(mut self, v: bool) -> Self {
        self.demo_exclude_unstaked = v;
        self
    }

    /// Override the Cardano submission flag from config. There is no Bitcoin
    /// counterpart: heimdall does not send transactions to Bitcoin (WI-086).
    pub fn with_submit_config(mut self, submit_oracle: bool) -> Self {
        self.submit_oracle = submit_oracle;
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

    /// Read + decode the bridge Config UTxO (`cardano::config_params`).
    fn config_locator(&self) -> EpochResult<(String, String)> {
        match (&self.config_address, &self.config_nft_unit) {
            (Some(a), Some(u)) => Ok((a.clone(), u.clone())),
            _ => Err(EpochError::Chain(
                "cardano.config_address / config_nft_policy_id not set — required to read \
                 the bridge Config UTxO (the singleton locator and the operational parameters)"
                    .into(),
            )),
        }
    }

    /// Locate the bridge-state singleton through the Config ([PAR-1]): read
    /// `bridge_state_policy` (Config field 3), derive the policy's enterprise
    /// address (both deploy paths create the singleton there, stake part `None`),
    /// and find the one UTxO holding the `(policy, "BSS")` NFT.
    ///
    /// Returns the Config view (its UTxO is the second mint reference input) and
    /// the singleton view: the decoded [`BridgeState`] plus the Cardano UTxO
    /// holding it (the [PTM-7] mint reference input).
    async fn query_config_singleton(
        &self,
    ) -> EpochResult<(config_params::ConfigView, SingletonView)> {
        let (address, unit) = self.config_locator()?;
        fetch_config_singleton(
            &self.bf_base_url,
            &self.bf_project_id,
            &address,
            &unit,
            self.is_mainnet(),
        )
        .await
        .map_err(EpochError::Chain)
    }

    /// Whether this chain's addresses are mainnet (bech32 `addr1…`) — decided by
    /// the configured TM address, which every deployment sets.
    fn is_mainnet(&self) -> bool {
        self.treasury_address.starts_with("addr1")
    }

    /// The scriptPubKey the treasury head is locked under, sourced from CARDANO:
    /// output `head.vout` of the TM whose signed bytes the (spent) UnconfirmedTm
    /// record carries. `Ok(None)` = no TM created this head — the bootstrap
    /// anchor. Cached per head (it only moves at Confirm).
    async fn head_spk(&self, head: &bitcoin::OutPoint) -> EpochResult<Option<bitcoin::ScriptBuf>> {
        if let Some((cached_head, spk)) = &*self.head_spk_cache.lock().unwrap() {
            if cached_head == head {
                return Ok(spk.clone());
            }
        }
        // Same backend selection as `query_cpo_root`: Kupo when configured, else the
        // Blockfrost-compatible API. Both serve spent outputs with datums resolved.
        let source: Box<dyn crate::cardano::cpo_history::CpoHistorySource> =
            match self.kupo_url.as_deref() {
                Some(url) => Box::new(crate::cardano::cpo_history::KupoHistory::new(url)),
                None => Box::new(crate::cardano::cpo_history::BlockfrostHistory::new(
                    &self.bf_project_id,
                    Some(&self.bf_base_url),
                )),
            };
        let spk = head_spk_from_history(source.as_ref(), &self.treasury_address, head)
            .await
            .map_err(EpochError::Chain)?;
        *self.head_spk_cache.lock().unwrap() = Some((*head, spk.clone()));
        Ok(spk)
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

    async fn submit_cardano_tx(&self, label: &str, signed_tx_hex: &str) -> EpochResult<String> {
        let cbor = hex::decode(signed_tx_hex)
            .map_err(|e| EpochError::Chain(format!("{label} tx hex decode: {e}")))?;
        info!(
            "[fault-ban] submitting {label} tx ({} bytes CBOR) via Blockfrost",
            cbor.len()
        );
        let tx_hash = self
            .api
            .transactions_submit(cbor)
            .await
            .map_err(|e| EpochError::Chain(format!("{label} blockfrost tx submit: {e}")))?;
        info!("[fault-ban] submitted {label}: tx_hash={tx_hash}");
        Ok(tx_hash)
    }

    async fn wait_for_wallet_token_utxo(
        &self,
        token_unit: &str,
    ) -> EpochResult<(
        crate::cardano::bf_http::BfUtxo,
        Vec<crate::cardano::bf_http::BfUtxo>,
    )> {
        let wallet_addr = self
            .wallet_base_address
            .as_deref()
            .ok_or_else(|| EpochError::Chain("no wallet base address".into()))?;
        let attempts = FAULT_TOKEN_CONFIRM_TIMEOUT_SECS / FAULT_TOKEN_CONFIRM_POLL_SECS;
        for attempt in 0..=attempts {
            let wallet_raw = crate::cardano::bf_http::fetch_address_utxos(
                &self.bf_base_url,
                &self.bf_project_id,
                wallet_addr,
            )
            .await
            .map_err(|e| EpochError::Chain(format!("wallet UTxO query: {e}")))?;
            if let Some(found) = wallet_raw
                .iter()
                .find(|u| u.amount.iter().any(|a| a.unit == token_unit))
                .cloned()
            {
                return Ok((found, wallet_raw));
            }
            if attempt < attempts {
                tokio::time::sleep(Duration::from_secs(FAULT_TOKEN_CONFIRM_POLL_SECS)).await;
            }
        }
        Err(EpochError::Chain(format!(
            "fault token {token_unit} did not appear at the wallet within \
             {FAULT_TOKEN_CONFIRM_TIMEOUT_SECS}s"
        )))
    }

    async fn publish_dkg_fault_and_apply_ban_live(
        &self,
        flow: &DkgFaultBanFlow,
        evidence: crate::epoch::traits::DkgFaultEvidence,
    ) -> EpochResult<()> {
        let key = self.payment_key.as_ref().ok_or_else(|| {
            EpochError::Chain("cardano.mnemonic required for DKG fault ban flow".into())
        })?;
        let wallet_addr = self
            .wallet_base_address
            .as_deref()
            .ok_or_else(|| EpochError::Chain("no wallet base address".into()))?;
        let network = crate::cardano::tx_common::network_from_address(wallet_addr);
        let mainnet = matches!(network, pallas_addresses::Network::Mainnet);

        info!(
            "[fault-ban] preparing DKG fault proof using Bifrost blueprint {}",
            flow.blueprint_path
        );
        let prepared = prepare_dkg_fault(flow, evidence).map_err(EpochError::Chain)?;
        let accused_pool_id = prepared.accused_pool_id();
        let evidence_hash = prepared.evidence_hash();
        let (fault_script, fault_ref) = flow.fault_script(prepared.kind());
        let public_inputs = match &prepared {
            PreparedDkgFault::Round1 {
                halo2_public_inputs,
                ..
            }
            | PreparedDkgFault::Round2 {
                halo2_public_inputs,
                ..
            } => halo2_public_inputs.clone(),
            PreparedDkgFault::Equivocation { .. } => Vec::new(),
        };

        let registry_addr = flow.registry.enterprise_address(network);
        let registry_raw = crate::cardano::bf_http::fetch_address_utxos(
            &self.bf_base_url,
            &self.bf_project_id,
            &registry_addr,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("registry UTxO query: {e}")))?;
        let reg_unit = format!(
            "{}{}",
            flow.registry.hash_hex(),
            hex::encode(accused_pool_id)
        );
        let reg_node = registry_raw
            .iter()
            .find(|u| u.amount.iter().any(|a| a.unit == reg_unit))
            .ok_or_else(|| {
                EpochError::Chain(format!(
                    "accused pool {} is not in the on-chain registry",
                    hex::encode(accused_pool_id)
                ))
            })?;

        let cost_models =
            crate::cardano::bf_http::fetch_cost_models(&self.bf_base_url, &self.bf_project_id)
                .await
                .map_err(|e| EpochError::Chain(format!("fetch cost models: {e}")))?;
        let wallet_utxos = self.query_wallet_utxos().await?;
        let onchain_evidence = match &prepared {
            PreparedDkgFault::Round1 {
                canonical_round1_bytes,
                payload_signature,
                halo2_proof,
                ..
            } => crate::cardano::fault_proof::FaultProofEvidence::Round1InvalidPayload(
                crate::cardano::fault_proof::Round1InvalidPayloadEvidence {
                    accused_pool_id: &accused_pool_id,
                    canonical_round1_bytes,
                    payload_signature,
                    halo2_proof,
                    halo2_public_inputs: &public_inputs,
                },
            ),
            PreparedDkgFault::Round2 {
                canonical_round1_bytes,
                round1_signature,
                canonical_round2_bytes,
                round2_signature,
                round2_entry_index,
                pad,
                opened_share,
                halo2_proof,
                ..
            } => crate::cardano::fault_proof::FaultProofEvidence::Round2InvalidPayload(
                crate::cardano::fault_proof::Round2InvalidPayloadEvidence {
                    accused_pool_id: &accused_pool_id,
                    canonical_round1_bytes,
                    round1_signature,
                    canonical_round2_bytes,
                    round2_signature,
                    round2_entry_index: *round2_entry_index,
                    pad,
                    opened_share,
                    halo2_proof,
                    halo2_public_inputs: &public_inputs,
                },
            ),
            PreparedDkgFault::Equivocation {
                payload_a,
                signature_a,
                payload_b,
                signature_b,
                ..
            } => crate::cardano::fault_proof::FaultProofEvidence::Equivocation(
                crate::cardano::fault_proof::EquivocationEvidence {
                    accused_pool_id: &accused_pool_id,
                    payload_a,
                    signature_a,
                    payload_b,
                    signature_b,
                    evidence_hash: &evidence_hash,
                },
            ),
        };
        let mint = crate::cardano::fault_proof::build_fault_proof_mint_tx(
            &crate::cardano::fault_proof::FaultProofMintRequest {
                fault_verifier_script: fault_script,
                fault_verifier_ref_script: Some(crate::cardano::fault_proof::FaultProofRefScript {
                    tx_hash: &fault_ref.tx_hash,
                    output_index: fault_ref.output_index,
                    script_size: fault_script.cbor.len(),
                }),
                evidence: onchain_evidence,
                registration_ref: (&reg_node.tx_hash, reg_node.output_index),
                wallet_address: wallet_addr,
                wallet_utxos: &wallet_utxos,
                key,
                cost_models: Some(cost_models.clone()),
            },
        )
        .map_err(|e| EpochError::Chain(format!("build fault-proof mint tx: {e}")))?;
        info!(
            "[fault-ban] built FaultProof mint: policy={} token_name={}",
            mint.policy_id_hex,
            hex::encode(mint.token_name)
        );
        self.submit_cardano_tx("fault-proof mint", &mint.signed_tx_hex)
            .await?;

        let fault_unit = format!("{}{}", mint.policy_id_hex, hex::encode(mint.token_name));
        let (fault_bf, wallet_raw_after_mint) =
            self.wait_for_wallet_token_utxo(&fault_unit).await?;
        let fault_lovelace = lovelace_of(&fault_bf);
        let fault_utxo = crate::cardano::apply_ban::FaultProofUtxo {
            tx_hash: fault_bf.tx_hash,
            output_index: fault_bf.output_index,
            lovelace: fault_lovelace,
        };

        let ban_addr = flow.spo_bans.enterprise_address(network);
        let ban_raw = crate::cardano::bf_http::fetch_address_utxos(
            &self.bf_base_url,
            &self.bf_project_id,
            &ban_addr,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("ban UTxO query: {e}")))?;
        let window =
            crate::cardano::bf_http::fetch_epoch_window(&self.bf_base_url, &self.bf_project_id)
                .await
                .map_err(|e| EpochError::Chain(format!("epoch window: {e}")))?;
        let max_window_slots = (flow.ban_params.max_validity_window_ms / 1000).max(1) as u64;
        let avail = window.epoch_end_slot.saturating_sub(window.current_slot);
        let w = max_window_slots.min(avail);
        let invalid_before = window.current_slot;
        let invalid_hereafter = window.current_slot + w;
        let start_time_ms = window.block_time_ms + (w as i64) * 1000 - 1;
        let wallet_utxos_after_mint: Vec<WalletUtxo> = wallet_raw_after_mint
            .iter()
            .map(WalletUtxo::from_bf)
            .collect();
        let apply = crate::cardano::apply_ban::build_apply_ban_tx(
            &crate::cardano::apply_ban::ApplyBanRequest {
                spo_bans_script: &flow.spo_bans,
                fault_verifier_script: fault_script,
                fault_verifier_ref: Some((fault_ref.tx_hash.clone(), fault_ref.output_index)),
                ban_params: &flow.ban_params,
                accused_pool_id,
                evidence_hash,
                ban_utxos: &ban_raw,
                fault_utxo: &fault_utxo,
                registration_ref: (reg_node.tx_hash.clone(), reg_node.output_index),
                spo_bans_ref: (
                    flow.spo_bans_ref.tx_hash.clone(),
                    flow.spo_bans_ref.output_index,
                ),
                mainnet,
                start_time_ms,
                invalid_before,
                invalid_hereafter,
                wallet_address: wallet_addr,
                wallet_utxos: &wallet_utxos_after_mint,
                key,
                cost_models: Some(cost_models),
            },
        )
        .map_err(|e| EpochError::Chain(format!("build apply-ban tx: {e}")))?;
        info!(
            "[fault-ban] built ApplyBan: first_ban={} counter={} until={}",
            apply.first_ban, apply.ban_node.ban_counter, apply.ban_node.ban_until_time
        );
        self.submit_cardano_tx("apply-ban", &apply.signed_tx_hex)
            .await?;
        Ok(())
    }
}

fn lovelace_of(utxo: &crate::cardano::bf_http::BfUtxo) -> u64 {
    utxo.amount
        .iter()
        .find(|a| a.unit == "lovelace")
        .and_then(|a| a.quantity.parse().ok())
        .unwrap_or(0)
}

/// Classify a failure to derive the eligible roster.
///
/// `TooFew` is not a chain fault: it is the registry saying there are not enough
/// eligible SPOs to run a ceremony, which is precisely the state a bridge is in
/// from genesis until its operators register. Reporting it as `Chain` made it
/// fatal, and that stranded the one route built for exactly this state –
/// `phase1_fallback` keys off `dkg_unavailable`, which matches `DkgAborted`, so
/// an under-populated registry has to arrive as an ABORTED CEREMONY for the
/// federation to be asked to sign (WI-095/WI-098).
///
/// Everything else stays `Chain`. A failed fetch, a root mismatch or a duplicate
/// key are real faults, and a node that cannot READ the registry must never
/// conclude that the registry is empty.
fn eligible_roster_error(
    epoch: u64,
    attempt: u32,
) -> impl Fn(crate::cardano::dkg_roster::DkgFetchError) -> EpochError {
    use crate::cardano::dkg_roster::{DkgFetchError, DkgRosterError};
    use crate::cardano::roster::RosterError;
    move |e| {
        // Both spellings of "not enough": `Registry` counts what is REGISTERED,
        // `Derive` counts what survives bans and URL filtering. A bridge at
        // genesis hits the first; one whose whole roster is banned hits the
        // second. Neither is a fault to abort startup on.
        let too_few = match &e {
            DkgFetchError::Registry(RosterError::TooFew { got })
            | DkgFetchError::Derive(DkgRosterError::TooFew { got }) => Some(*got),
            // The whole roster is registered but none of its stake has activated
            // yet — the state a bridge is in for two epoch boundaries after every
            // SPO registers in one epoch, which is exactly how a test bridge is
            // stood up. There is no threshold to derive, but that is a bridge with
            // no usable roster, not a fault: it belongs with "not enough", so the
            // caller falls back to the Phase-1 federation instead of panicking on
            // a node whose own preflight passed (preflight reads no pool stake).
            DkgFetchError::Derive(DkgRosterError::ZeroStake) => Some(0),
            _ => None,
        };
        match too_few {
            Some(got) => EpochError::DkgAborted {
                epoch,
                attempt,
                qualified: got,
                eligible: got,
                reason: format!("eligible roster: {e}"),
            },
            None => EpochError::Chain(format!("eligible roster: {e}")),
        }
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
        //
        // The FIRST call returns at once: a node starting mid-epoch must join
        // that epoch, not sit out until the next boundary. Every call after it
        // waits for the epoch to actually advance. That distinction did not
        // matter while the machine ran a single cycle and stopped; once it
        // cycles, returning the current epoch immediately would start a fresh
        // ceremony the moment the previous one finished — a DKG and an Update-Y
        // per movement, rotating the treasury key continuously.
        loop {
            let epoch = self.current_epoch().await?;
            {
                let mut last = self.last_boundary_epoch.lock().unwrap();
                if last.is_none_or(|seen| epoch > seen) {
                    *last = Some(epoch);
                    return Ok(EpochBoundaryEvent { epoch });
                }
            }
            debug!(
                "[blockfrost] epoch {epoch} already run; waiting {}s for the next boundary",
                EPOCH_BOUNDARY_POLL.as_secs()
            );
            tokio::time::sleep(EPOCH_BOUNDARY_POLL).await;
        }
    }

    async fn current_epoch(&self) -> EpochResult<u64> {
        // The epoch the CEREMONY runs under. On a test bridge that is the
        // virtual cycle (WI-VMP6J) — every consumer above this adapter treats it
        // as "the epoch", and it is what the DKG namespace and the Update-Y
        // message carry. Chain reads keep using `chain_epoch`.
        match self.epoch_scheme.virtual_slots() {
            Some(_) => {
                let (tip_slot, _) = self.tip_slot_time_ms().await?;
                Ok(self.epoch_scheme.epoch_at(tip_slot).unwrap_or(0))
            }
            None => self.chain_epoch().await,
        }
    }

    async fn query_roster(&self, epoch: u64) -> EpochResult<Roster> {
        // Re-read the federation identity — see `query_dkg_context`.
        let (registry, bans) = self.current_federation().await?;
        let Some(registry) = registry else {
            return Ok(self.fallback_roster.clone());
        };
        // WI-012: eligible roster = registry − active bans, FROST threshold
        // stake-weighted. Any failure is hard — never silently fall back to
        // the fixture, which would let SPOs run DKG on divergent rosters.
        // `attempt` is 0 here; the orchestration layer (WI-014) bumps it on
        // a failed ceremony.
        let ctx = self
            .fetch_ceremony_context(&registry, bans.as_ref(), epoch, 0)
            .await?;
        Ok(ctx.to_roster())
    }

    async fn query_dkg_context(
        &self,
        epoch: u64,
        attempt: u32,
    ) -> EpochResult<crate::cardano::dkg_roster::DkgContext> {
        // Re-read #8/#9-#10 rather than trusting the startup snapshot: this is
        // the derivation whose inputs must be identical on every node, so it is
        // the last one that should run on a per-node copy of chain state.
        let (registry, bans) = self.current_federation().await?;
        match &registry {
            // WI-012: eligible roster = registry − active bans, FROST threshold
            // stake-weighted. Any failure is hard — never silently fall back to
            // the fixture, which would let SPOs run DKG on divergent rosters.
            Some(registry) => {
                self.fetch_ceremony_context(registry, bans.as_ref(), epoch, attempt)
                    .await
            }
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
        // Rev 5.4: the current treasury is the bridge-state singleton's head — outpoint AND
        // satoshi amount straight from the BridgeState datum. There is no Confirmed chain to
        // walk: Confirm burns the TM record and advances the singleton instead.
        let (config, singleton) = self.query_config_singleton().await?;
        let state = &singleton.state;
        use bitcoin::hashes::Hash;
        let txid_bytes: [u8; 32] = state.treasury_utxo_id[..32].try_into().unwrap();
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(txid_bytes),
            vout: u32::from_le_bytes(state.treasury_utxo_id[32..].try_into().unwrap()),
        };
        let value = bitcoin::Amount::from_sat(state.treasury_amount);

        // Scan the Unconfirmed records at the TM address (fresh HTTP client per call — the
        // pooled keep-alive goes stale across the DKG wait). A record whose embedded BTC tx
        // spends the head is a movement already in flight; a record we cannot read might be.
        let asset_unit = format!(
            "{}{}",
            self.treasury_policy_id, self.treasury_asset_name_hex
        );
        // `tm_recovery_window`, the bridge's PUBLISHED recovery deadline (Config
        // `params[0]`), finally acting on something. Without it a READABLE movement that
        // never confirms blocks the tip permanently: every later batch opportunity sees a
        // movement in flight and passes unused, for ever, with nothing in any log naming
        // the cause. Past the window the record stops blocking, so the next opportunity
        // builds a replacement spending the same head — the shape §Stuck-TM recovery
        // describes ("the replacement and the stuck original both spend the same head;
        // Bitcoin confirms exactly one").
        //
        // It comes from the CHAIN, not from a local key, for the usual reason: it decides
        // which head a TM spends, so two operators on different values build different TM
        // bytes. A bridge publishing 0 (no window) keeps the old block-for-ever behaviour
        // rather than inventing a default.
        let recovery_window = u64::try_from(
            self.schedule_in_force(&config.params.tunables.schedule)?
                .tm_recovery_window,
        )
        .ok()
        .filter(|secs| *secs > 0);
        let TmScan {
            in_flight_spends,
            parse_failures,
            opaque_unconfirmed,
            ..
        } = scan_tm_utxos(
            &self.bf_base_url,
            &self.bf_project_id,
            &self.treasury_address,
            &asset_unit,
            recovery_window,
        )
        .await
        .map_err(EpochError::Chain)?;

        // The key the bridge AUTHORIZES right now: `current_spos_frost_key` from
        // the treasury_info datum. Read from the chain rather than assumed, which
        // it used to be — `treasury_config.y_51` is seeded from the fixture as
        // `y_fed` on every process start, so before this read a restarted node
        // could not tell a genesis bridge from one that had already rotated. That
        // is what decides the rollout phase (spec §Rollout Phases: the Phase-2
        // transition IS the first Update-Y, so `authorized == y_federation` is
        // exactly the statement that none has landed).
        //
        // DISTINCT from `y_51` below, which is what the head UTxO is LOCKED
        // under. The two agree except in the window between an Update-Y and the
        // handoff movement that acts on it: Cardano rotates the datum, but the
        // BTC stays under the old key until a movement spends it there and pays
        // the change to the new address.
        let authorized_key = match self.current_federation().await?.0 {
            Some(registry) => {
                let state = self.find_treasury_info_state(&registry).await?;
                Some(
                    bitcoin::key::UntweakedPublicKey::from_slice(
                        &state.datum.current_spos_frost_key,
                    )
                    .map_err(|e| {
                        EpochError::Chain(format!(
                            "treasury_info current_spos_frost_key ({}) is not an x-only key: {e}",
                            hex::encode(&state.datum.current_spos_frost_key)
                        ))
                    })?,
                )
            }
            // No treasury_info to read: there is nothing that could have rotated,
            // so the head's own key stands in. Keeps the mock and the
            // no-registry demo on their existing behaviour.
            None => None,
        };

        // The treasury's Taproot internal key (Y_51) — what the head is locked
        // under. After DKG, publish_group_key stores the FROST group key here;
        // at bootstrap it is the config Y_51.
        let maybe_key = *self.treasury_y_51.lock().unwrap();
        let csv = self.treasury_config.federation_csv_blocks;

        // Which taproot tree is the head locked under? The singleton records the outpoint and
        // amount but not the scriptPubKey — and SPOs run no Bitcoin node, so the script is
        // sourced from CARDANO: the head was created as output 0 of a TM whose full signed
        // bytes live in the (spent) UnconfirmedTm record at the TM address. The candidate
        // trees — the federation seed (production) and, defensively, Y_51 itself (the demo's
        // collapsed Y_fed=Y_51 convention) — are reconstructed and checked against that
        // script. Never sign an outpoint whose on-chain scriptPubKey we cannot reconstruct.
        //
        // The BOOTSTRAP head is the funding tx, not a TM, so no record exists for it: the spk
        // is then constructed from the configured keys WITHOUT verification. That is the
        // spec's bootstrap trust model (operator-supplied, observer-verified) and it is
        // self-limiting — under wrong keys the FROST signatures simply do not verify, so
        // nothing can be signed away, let alone lost.
        let secp = bitcoin::key::Secp256k1::new();
        // No narrowing check: `federation_csv_blocks` is a `u16` end to end since
        // WI-069, validated where it enters from the treasury_info datum. It used
        // to be a `u32` that every consumer cast, so a value above 65535
        // truncated into a different Taproot tree.
        let csv_u16 = csv;
        // The INTERNAL key is a candidate too, not a given. It used to be fixed
        // to the configured value, which meant a node restarted after an Update-Y
        // had exactly one guess and it was the wrong one — the match failed and
        // the node could not read the treasury at all. The head can legitimately
        // be under the authorized key (steady state), the key it superseded (the
        // handoff window, where Cardano has rotated but the BTC has not moved
        // yet), or `y_federation` (a bridge that has never rotated), so all are
        // offered and the chain decides.
        //
        // The superseded key is neither configured nor in the datum — the datum
        // holds only the CURRENT one — so it comes from the ceremonies this node
        // persisted. That is also why it is a list rather than one previous key:
        // an epoch whose DKG failed posts no Update-Y and the old key carries
        // over, so the head can be several ceremonies behind.
        // Read once and used twice: to reconstruct the head below, and to name the
        // ceremonies this bridge has moved past, which is what lets peg-in
        // collection report a deposit that has stranded at a retired address.
        let persisted = self.persisted_internal_candidates();
        // Which ceremonies can already have been superseded. A read failure means
        // "cannot tell", and the safe answer there is to report nothing as retired
        // rather than to guess a key unsweepable.
        let now_epoch = self.current_epoch().await.unwrap_or(0);
        let mut internal_candidates = vec![maybe_key.unwrap_or(self.treasury_config.y_51)];
        for cand in authorized_key
            .into_iter()
            .chain(persisted.iter().map(|(_, k)| *k))
            .chain([self.treasury_config.y_fed])
        {
            if !internal_candidates.contains(&cand) {
                internal_candidates.push(cand);
            }
        }
        // Leaves to try for a given internal key: the PUBLISHED federation key,
        // then the internal key itself (the demo's collapsed Y_fed = Y_51
        // convention).
        let leaves_for = |internal: bitcoin::key::UntweakedPublicKey| {
            let mut leaves = vec![self.treasury_config.y_fed];
            if internal != self.treasury_config.y_fed {
                leaves.push(internal);
            }
            leaves
        };
        let head_spk = self.head_spk(&outpoint).await?;
        let (y_51, y_fed) = match &head_spk {
            Some(actual_spk) => internal_candidates
                .iter()
                .copied()
                .flat_map(|internal| {
                    leaves_for(internal)
                        .into_iter()
                        .map(move |leaf| (internal, leaf))
                })
                .find(|&(internal, leaf)| {
                    let spk = bitcoin::ScriptBuf::new_p2tr_tweaked(
                        treasury_spend_info(&secp, internal, leaf, csv_u16).output_key(),
                    );
                    spk == *actual_spk
                })
                .ok_or_else(|| {
                    EpochError::Chain(format!(
                        "the singleton's head {outpoint} is locked under a scriptPubKey \
                         ({}) that no candidate treasury tree reproduces — y_51/y_fed/csv \
                         configuration is out of step with the chain",
                        hex::encode(actual_spk.as_bytes())
                    ))
                })?,
            None => {
                let internal = internal_candidates[0];
                let y_fed = self.treasury_config.y_fed;
                eprintln!(
                    "[blockfrost] no TM record creates head {outpoint} — treating it as the \
                     BOOTSTRAP anchor and trusting the configured keys (y_fed {}) for the \
                     treasury tree. A wrong key set is self-limiting: FROST signatures over \
                     it simply fail",
                    hex::encode(y_fed.serialize()),
                );
                (internal, y_fed)
            }
        };

        // A movement already in flight against this head — or an in-flight movement we could
        // not read — means it is not yet safe to build the next TM; report btc_confirmed=false
        // so BuildTm waits for confirmation. Additionally, a TM this process submitted must
        // have become the head before the next one builds (DEC-022: restart-safe against a lost
        // Cardano post — the in-flight scan catches cross-process movements, this catches our
        // own). An unreadable datum at the NFT-gated TM address counts as possibly-in-flight
        // (fail closed, never double-post).
        //
        // `tm_recovery_window` releases this guard on the same terms as the
        // on-chain scan below. Without that the node that SUBMITTED a movement
        // that never confirms is the only one that never recovers: its peers time
        // the record out and take the next opportunity, while it holds itself
        // blocked for ever on its own bookkeeping.
        let own_pending = match *self.last_submitted_txid.lock().unwrap() {
            None => false,
            Some((t, _)) if outpoint.txid == t => false,
            Some((t, at)) => match recovery_window {
                Some(w) if at.elapsed().as_secs() > w => {
                    warn!(
                        "[blockfrost] our submitted movement {t} has not become the head in {}s \
                         (> tm_recovery_window {w}s) — no longer treating it as in flight",
                        at.elapsed().as_secs()
                    );
                    false
                }
                _ => true,
            },
        };
        // The other two terms have NO deadline and are not meant to: they mean
        // "there is a movement at the TM address we could not read", so a node
        // that timed them out would build while blind to what that movement swept.
        // A movement heimdall CAN read is what `tm_recovery_window` governs.
        let btc_confirmed = !own_pending
            && !in_flight_spends.contains(&outpoint)
            && opaque_unconfirmed == 0
            && parse_failures == 0;
        info!(
            "[blockfrost] treasury head {}:{} = {} sat (singleton, in_flight={}, btc_confirmed={})",
            outpoint.txid,
            outpoint.vout,
            value.to_sat(),
            !btc_confirmed,
            btc_confirmed,
        );

        // #11, params[7] and params[8] as this batch pinned them. Boot copies are
        // the fallback and nothing more: they are chain-published, must-match
        // values hashed into an ADDRESS, so a node running on its startup copies
        // after a governance move reconstructs a deposit address none of its peers
        // reconstructs — and reports `0 eligible peg-ins`, not an error.
        let pinned_tree_inputs = self
            .contracts_cache
            .lock()
            .ok()
            .and_then(|s| s.as_ref().map(|e| e.pegin_tree_inputs));

        Ok(TreasuryUtxo {
            outpoint,
            value,
            y_51,
            y_fed,
            // The PUBLISHED federation key, not the one the head happens to be locked
            // under: a depositor builds against what the Config names, so the peg-in tree
            // must too (`leaf_candidates[0]` above is this same value).
            config_y_fed: pinned_tree_inputs
                .and_then(|i| bitcoin::key::UntweakedPublicKey::from_slice(&i.y_federation).ok())
                .unwrap_or(self.treasury_config.y_fed),
            // With no treasury_info configured there is nothing that could have
            // rotated, so the head's own key stands in.
            authorized_key: authorized_key.unwrap_or(y_51),
            // The peg-in tree's copy, from the pin. The `csv` above stays as read:
            // it derives the TREASURY tree, whose head was created under whatever
            // was live then, and the candidate loop already handles that.
            federation_csv_blocks: pinned_tree_inputs.map_or(csv, |i| i.federation_csv_blocks),
            pegin_refund_timeout_blocks: pinned_tree_inputs
                .map_or(self.treasury_config.pegin_refund_timeout_blocks, |i| {
                    i.pegin_refund_timeout_blocks
                }),
            // Every internal key this bridge is known to have published, minus the
            // two that are still live. Whatever is left is a key no movement signs
            // under any more, so a deposit found under one can only be reported.
            //
            // `y_federation` belongs in the list and is not among the persisted
            // ceremonies: a Phase-1 bridge's peg-in address IS keyed to it (the datum
            // names the federation key until the first Update-Y lands), and the
            // federation share lives outside `state_dir` entirely. Leaving it out
            // meant deposits at the address the bridge published for the whole of
            // Phase 1 matched no tree after the handoff, and fell back to the "no
            // output pays the peg-in address" drop this exists to replace.
            retired_internal_keys: {
                // A ceremony for THIS epoch or a later one is not retired, it is
                // PENDING: write_dkg_state runs when the DKG completes locally,
                // which is before PublishKeys posts the Update-Y, so between those
                // two moments the incoming key is neither `y_51` nor the datum's.
                // Calling it retired made the collection log say a deposit under it
                // is unsweepable and recoverable only through the federation leaf —
                // about a key that goes live minutes later, and an operator acting
                // on that would emergency-sweep coins the bridge will happily take.
                // Excluding it costs one transient generic drop that heals itself
                // the moment the Update-Y lands.
                let mut out: Vec<bitcoin::key::UntweakedPublicKey> = Vec::new();
                let mut pending = 0usize;
                for (e, k) in persisted
                    .into_iter()
                    .map(|(e, k)| (Some(e), k))
                    .chain([(None, self.treasury_config.y_fed)])
                    .filter(|(_, k)| *k != y_51 && Some(*k) != authorized_key)
                {
                    if e.is_some_and(|e| e >= now_epoch) {
                        pending += 1;
                        continue;
                    }
                    if !out.contains(&k) {
                        out.push(k);
                    }
                }
                if pending > 0 {
                    debug!(
                        "[treasury] {pending} persisted ceremony key(s) for epoch >= {now_epoch} \
                         are not yet superseded — not reported as retired"
                    );
                }
                // Newest first, then bounded. Unbounded, this grows one entry per
                // epoch forever and every peg-in request pays a full Taproot
                // derivation per entry — including the foreign deposits anyone can
                // send to a permissionlessly payable address. A key older than the
                // cap is long past its own refund timeout, so recognising it buys
                // an operator nothing it can act on.
                out.reverse();
                let cap = self.recognised_retired_keys();
                if out.len() > cap {
                    warn!(
                        "[treasury] {} retired peg-in key(s) beyond the most recent {cap} are no \
                         longer recognised; a deposit under one is past its own refund timeout \
                         and reads as another bridge's",
                        out.len() - cap,
                    );
                    out.truncate(cap);
                }
                out
            },
            btc_confirmed,
        })
    }

    async fn plan_update_y(
        &self,
        epoch: u64,
        new_y_51: bitcoin::key::UntweakedPublicKey,
    ) -> EpochResult<Option<crate::epoch::traits::UpdateYPlan>> {
        // The treasury_info identity comes from the same re-read as the roster:
        // this is the address a completed ceremony writes the new group key to,
        // so a stale copy hands the treasury to a script nobody else watches.
        let Some(registry) = self.current_federation().await?.0 else {
            warn!(
                "[update-y] no treasury_info configured (cardano.registry_blueprint / \
                 registry_bootstrap / treasury_info_asset_name, or the Config's published \
                 identity at #9-#10) — the derived group key stays LOCAL to this node and \
                 the treasury is NOT handed over"
            );
            return Ok(None);
        };
        let state = self.find_treasury_info_state(&registry).await?;

        let current_key =
            bitcoin::key::UntweakedPublicKey::from_slice(&state.datum.current_spos_frost_key)
                .map_err(|e| {
                    EpochError::Chain(format!(
                        "treasury_info current_spos_frost_key ({}) is not an x-only key: {e}",
                        hex::encode(&state.datum.current_spos_frost_key)
                    ))
                })?;
        if current_key == new_y_51 {
            info!(
                "[update-y] treasury_info already names {} — nothing to rotate",
                hex::encode(new_y_51.serialize())
            );
            return Ok(None);
        }

        let spent_txid: [u8; 32] = hex::decode(&state.tx_hash)
            .map_err(|e| EpochError::Chain(format!("treasury state txid hex: {e}")))?
            .try_into()
            .map_err(|_| EpochError::Chain("treasury state txid must be 32 bytes".into()))?;
        Ok(Some(crate::epoch::traits::UpdateYPlan {
            epoch,
            current_key,
            new_key: new_y_51,
            sig_msg: crate::cardano::treasury_info::update_y_sig_msg(
                &spent_txid,
                state.output_index,
                epoch,
                &new_y_51.serialize(),
            ),
            state_outpoint: format!("{}:{}", state.tx_hash, state.output_index),
        }))
    }

    async fn submit_update_y(
        &self,
        plan: &crate::epoch::traits::UpdateYPlan,
        signature: &[u8; 64],
    ) -> EpochResult<String> {
        let registry = self.current_federation().await?.0.ok_or_else(|| {
            EpochError::Chain("no treasury_info configured — cannot submit Update-Y".into())
        })?;
        let key = self.payment_key.as_ref().ok_or_else(|| {
            EpochError::Chain(
                "cardano.mnemonic is required to pay the Update-Y fee (dry-run node)".into(),
            )
        })?;
        let wallet_addr = self
            .wallet_base_address
            .as_deref()
            .ok_or_else(|| EpochError::Chain("no wallet base address".into()))?;

        // Re-locate the state: between planning and here the datum could have
        // been spent (a peer's rotation, a registration). The signature is
        // pinned to the outpoint it was made for, so a moved state must fail
        // loudly rather than build a transaction that cannot validate.
        let state = self.find_treasury_info_state(&registry).await?;
        let outpoint = format!("{}:{}", state.tx_hash, state.output_index);
        if outpoint != plan.state_outpoint {
            return Err(EpochError::Chain(format!(
                "treasury_info state moved from {} to {outpoint} since the Update-Y was signed — \
                 the signature is pinned to the spent outpoint; re-plan and re-sign",
                plan.state_outpoint
            )));
        }

        let wallet_raw = crate::cardano::bf_http::fetch_address_utxos(
            &self.bf_base_url,
            &self.bf_project_id,
            wallet_addr,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("wallet UTxO query: {e}")))?;
        let wallet_utxos: Vec<WalletUtxo> = wallet_raw.iter().map(WalletUtxo::from_bf).collect();
        let cost_models =
            crate::cardano::bf_http::fetch_cost_models(&self.bf_base_url, &self.bf_project_id)
                .await
                .map_err(|e| EpochError::Chain(format!("fetch cost models: {e}")))?;
        let window =
            crate::cardano::bf_http::fetch_epoch_window(&self.bf_base_url, &self.bf_project_id)
                .await
                .map_err(|e| EpochError::Chain(format!("epoch window: {e}")))?;

        let epoch_i64 = i64::try_from(plan.epoch)
            .map_err(|_| EpochError::Chain("epoch too large for Plutus Int".into()))?;
        // Spending the state UTxO needs the compiled script, not just the policy
        // id the Config publishes (#10). A node reading the roster from the
        // published identity alone can still run every other phase, so say which
        // key is missing rather than failing at witness assembly.
        let treasury_script = registry.treasury_info_script.as_ref().ok_or_else(|| {
            EpochError::Chain(
                "the key handoff (Update-Y) spends the treasury_info state UTxO, which needs the \
                 compiled script — this node resolved the roster from the Config's published \
                 identity and has no cardano.registry_blueprint to compile it from"
                    .into(),
            )
        })?;
        // Rev 5.5: treasury.ak reads y_federation from the CONFIG ([UY-5]), so the
        // tx must carry the Config UTxO as a reference input and the redeemer must
        // name its index. Fetch it here rather than threading it through the plan:
        // the value it publishes is what the validator will check against, so a
        // cached copy could disagree with the UTxO the tx actually references.
        let (config_view, _) = self.query_config_singleton().await?;
        let config_ref_tx = config_view.utxo.tx_hash.clone();
        let y_federation = config_view.params.y_federation;

        let built = crate::cardano::update_y::build_update_y_tx(
            &crate::cardano::update_y::UpdateYRequest {
                treasury_script,
                state: &state,
                new_spos_frost_key: &plan.new_key.serialize(),
                epoch: epoch_i64,
                signature,
                y_federation: &y_federation,
                config_ref: (&config_ref_tx, config_view.utxo.index),
                // The DKG handoff is roster-authorized: `signature` is the
                // outgoing group key's (spec [UY-3]).
                authorizer: crate::cardano::update_y::UpdateYAuthorizer::Roster,
                wallet_address: wallet_addr,
                wallet_utxos: &wallet_utxos,
                key,
                invalid_before: Some(window.current_slot),
                invalid_hereafter: Some(window.epoch_end_slot),
                cost_models: Some(cost_models),
            },
        )
        .map_err(|e| EpochError::Chain(format!("build update-y tx: {e}")))?;

        let cbor = hex::decode(&built.signed_tx_hex)
            .map_err(|e| EpochError::Chain(format!("update-y tx hex: {e}")))?;
        let tx_id = self
            .api
            .transactions_submit(cbor)
            .await
            .map_err(|e| EpochError::Chain(format!("update-y blockfrost tx submit: {e}")))?;
        info!(
            "[update-y] rotated treasury_info {} -> {} (cardano tx {tx_id})",
            hex::encode(plan.current_key.serialize()),
            hex::encode(plan.new_key.serialize())
        );
        Ok(tx_id)
    }

    async fn publish_group_key(&self, y_51: bitcoin::key::UntweakedPublicKey) -> EpochResult<()> {
        *self.treasury_y_51.lock().unwrap() = Some(y_51);
        Ok(())
    }

    async fn publish_dkg_fault_and_apply_ban(
        &self,
        evidence: crate::epoch::traits::DkgFaultEvidence,
    ) -> EpochResult<()> {
        let Some(flow) = self.fault_ban_flow.clone() else {
            return Err(EpochError::Chain(format!(
                "automatic DKG fault banning is not configured \
                 (kind={}, accused_pool_id={})",
                evidence.kind_label(),
                hex::encode(evidence.accused_pool_id())
            )));
        };
        self.publish_dkg_fault_and_apply_ban_live(&flow, evidence)
            .await
    }

    /// Every open PegOut request at the `peg_out.ak` address (WI-030), carried through with
    /// each request's own datum fields — `per_pegout_fee` and `created` decide what the TM
    /// pays and whether it may pay it at all, and `por_id` / `outpoint` are what the CPO trie
    /// and the TM datum's `fulfilled_por_outpoints` are keyed by.
    ///
    /// No filtering happens here. `build_tm_phase` subtracts the already-paid multiset and
    /// `build_tm` applies the spec's skip rule (freshness, dust, non-standard script, already
    /// in the trie, duplicate within the batch) — keeping every skip decision in one place is
    /// what lets every SPO reach the identical verdict and build byte-identical TM bytes.
    ///
    /// Unconfigured is a loud no-op rather than an error: a daemon deployed before
    /// `cardano.pegout_script_address` / `cardano.bridged_token_unit` existed must keep
    /// building peg-in-only TMs, and paying nothing is under-payment (the request stays open
    /// until its own cancel deadline), never over-payment.
    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>> {
        let Some(pinned) = &self.pegout_source else {
            warn!(
                "[pegout] no cardano.pegout_script_address / cardano.bridged_token_unit \
                 — this TM pays NO peg-out; every pending withdrawal waits for a later batch"
            );
            return Ok(vec![]);
        };

        // Config #7 and #2, re-read rather than trusted from boot: a governance
        // Update moves where withdrawals sit, and a node still scanning the old
        // address reports "nothing pending", which is what a quiet bridge looks
        // like too. See `current_contracts` for what this does and does not fix.
        let refreshed = self.current_contracts().await?;
        let (address, fbtc_unit) =
            refreshed
                .as_ref()
                .map_or((pinned.address.as_str(), pinned.fbtc_unit.as_str()), |c| {
                    (
                        c.pegout_script_address.as_str(),
                        c.bridged_token_unit.as_str(),
                    )
                });

        // Malformed UTxOs at the (permissionlessly payable) peg-out address are skipped with a
        // per-UTxO line on stderr inside `fetch_pegout_requests`, matching the CLI sweep path:
        // one poison datum must not block every Treasury Movement bridge-wide.
        let scan = crate::cardano::pegout_datum::fetch_pegout_requests(
            &self.bf_base_url,
            &self.bf_project_id,
            address,
            fbtc_unit,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("fetch_pegout_requests: {e}")))?;

        // Resolve each request's CREATION SLOT before it reaches the freeze.
        // Without this every request carries `None`, `freeze_pegouts` maps that to
        // `u64::MAX`, and the cutoff defers ALL of them — so a daemon with a Config
        // schedule pays no peg-out, ever, and says nothing about it. The CLI sweep
        // path resolved them from the start; the daemon path never did.
        //
        // POSIX ms, matching `slot_at_time` (`/blocks/latest` reports seconds).
        let mut scan = scan;
        let tip = crate::cardano::bf_http::fetch_latest_block_slot_time(
            &self.bf_base_url,
            &self.bf_project_id,
        )
        .await
        .ok()
        .map(|(slot, time_secs)| (slot, time_secs.saturating_mul(1000)));
        crate::cardano::pegout_datum::resolve_created_slots(
            &self.bf_base_url,
            &self.bf_project_id,
            &mut scan.requests,
            tip,
        )
        .await;

        if scan.malformed > 0 {
            warn!(
                "[pegout] {} UTxO(s) at {} carry the bridged token but no decodable \
                 PegOutDatum — they are NOT payable by any TM and are absent from the open count \
                 below; their owners can still Cancel",
                scan.malformed, address,
            );
        }

        Ok(scan
            .requests
            .into_iter()
            .map(|r| PegOutRequestUtxo {
                script_pubkey: bitcoin::ScriptBuf::from_bytes(r.destination_script_pubkey),
                amount: bitcoin::Amount::from_sat(r.amount_sat),
                per_pegout_fee: bitcoin::Amount::from_sat(r.per_pegout_fee),
                created: r.created,
                por_id: r.por_id,
                outpoint: r.outpoint,
                created_slot: r.created_slot,
            })
            .collect())
    }

    /// Freeze the batch's consensus inputs at the Cardano tip: the tip block's
    /// time (`/blocks/latest`) and the Config UTxO's operational parameters.
    ///
    /// Chain values, not local ones. The time feeds the peg-out freshness skip
    /// rule and the parameters feed the fee and the two selection floors, so two
    /// SPOs that disagree on any of them build different TM bytes and fail the
    /// FROST round. Every honest node reading the same tip agrees.
    ///
    /// With no Config UTxO configured this degrades to the node's local
    /// `bitcoin.fee_rate_sat_per_vb` and no floors — the pre-WI-040 behaviour,
    /// which the returned [`ParamSource`] names so it shows up in the logs.
    async fn query_batch_snapshot(&self) -> EpochResult<BatchSnapshot> {
        let (addr, unit) = match (&self.config_address, &self.config_nft_unit) {
            (Some(a), Some(u)) => (a.as_str(), u.as_str()),
            _ => {
                let secs = crate::cardano::bf_http::fetch_latest_block_time(
                    &self.bf_base_url,
                    &self.bf_project_id,
                )
                .await
                .map_err(|e| EpochError::Chain(format!("chain now: {e}")))?;
                return Ok(BatchSnapshot::local_override(
                    secs.saturating_mul(1000),
                    TmParams::fee_rate_only(self.local_fee_rate_sat_per_vb),
                    "cardano.config_address / config_nft_policy_id not set",
                ));
            }
        };
        // Two attempts at most: the first may build the grid from a REUSED Config,
        // and the grid is what says whether that reuse was allowed. When it says
        // no, the second attempt reads the Config fresh and the same test cannot
        // fire again. See `config_refresh_due`.
        let mut reuse = self.cached_config();
        let (snapshot, anchor, schedule, batch) = loop {
            let snapshot = config_params::fetch_param_snapshot_reusing(
                &self.bf_base_url,
                &self.bf_project_id,
                addr,
                unit,
                reuse.as_ref(),
            )
            .await
            .map_err(|e| EpochError::Chain(format!("batch parameter snapshot: {e}")))?;
            // An unreadable boundary degrades to "no grid" exactly as it did when
            // `batch_at` resolved it: the cutoff is what is lost, not the bridge.
            let anchor = self.cycle_anchor(&snapshot).await;
            // The schedule this deployment runs on, resolved BEFORE the grid so both
            // read the same one. Rescaled when the bridge is on a virtual epoch, and
            // refused here — once — if the cycle cannot hold it.
            let schedule = self.schedule_in_force(&snapshot.config.params.tunables.schedule)?;
            let batch = match anchor {
                Some(a) => {
                    config_params::batch_at(
                        &self.bf_base_url,
                        &self.bf_project_id,
                        &snapshot,
                        self.epoch_scheme,
                        &schedule,
                        Some(a),
                    )
                    .await
                }
                None => crate::epoch::batch::BatchWindow::NoGrid,
            };
            match reuse.as_ref() {
                Some(cached) if config_refresh_due(cached, anchor, &batch) => reuse = None,
                _ => break (snapshot, anchor, schedule, batch),
            }
        };
        // Only a read off the wire updates the cache. Carrying `read_slot` forward
        // on a reuse would push it past every future `B_i` and the refresh would
        // never come due again.
        if let (None, Some(a)) = (reuse.as_ref(), anchor) {
            *self.config_cache.lock().unwrap() = Some(config_params::CachedConfig {
                config: snapshot.config.clone(),
                config_created_ms: snapshot.config_created_ms,
                read_slot: snapshot.slot,
                anchor_slot: a.start_slot,
            });
        }
        let (tm_params, source) =
            config_params::resolve_tm_params(Some(&snapshot), self.local_fee_rate_sat_per_vb);
        let max_tx_size = self.max_tx_size(anchor).await?;

        // Pin this batch's contract identities from the snapshot that just passed
        // the ordering guard. Everything scanned until the next opportunity now
        // resolves to the same answer, and to the answer every other co-signer of
        // this B_i resolves — which is the whole point: the identities become "as
        // of the batch", not "as of whenever this node happened to look".
        self.remember_contracts(&snapshot, batch.open());

        let schedule = &schedule;
        Ok(BatchSnapshot {
            now_ms: snapshot.time_ms,
            slot: snapshot.slot,
            batch,
            tm_params,
            max_tx_size,
            post_tm_envelope: self.post_tm_envelope(),
            leader_slot_t: u64::try_from(schedule.leader_slot_t)
                .unwrap_or(crate::epoch::traits::DEFAULT_LEADER_SLOT_T),
            sign_r1_window: u64::try_from(schedule.sign_r1_window)
                .unwrap_or(crate::epoch::traits::DEFAULT_SIGN_WINDOW),
            sign_r2_window: u64::try_from(schedule.sign_r2_window)
                .unwrap_or(crate::epoch::traits::DEFAULT_SIGN_WINDOW),
            // E-relative in the Config; absolute here, so every SPO's rotation
            // ceremony closes against the same slot. `None` where the deployment
            // has no epoch anchor to add it to.
            update_y_close_slot: anchor.and_then(|a| {
                u64::try_from(schedule.update_y_deadline)
                    .ok()
                    .map(|d| a.start_slot + d)
            }),
            source,
        })
    }

    async fn query_bridge_roots(&self) -> EpochResult<Option<crate::epoch::traits::BridgeRoots>> {
        let Some(pinned) = self.cpo_policy_id.as_deref() else {
            return Ok(None);
        };
        // Config #4, re-read for the same reason (`current_contracts`): a node
        // checking its trie against a singleton the bridge has retired attests a
        // root no peer reproduces.
        let refreshed = self.current_contracts().await?;
        let policy = refreshed
            .as_ref()
            .map_or(pinned, |c| c.bridge_state_policy_id.as_str());
        // Same backend selection as `reconstruct-cpo-trie` (see run_reconstruct_cpo_trie):
        // Kupo when configured, else the Blockfrost-compatible API. Reading the singleton
        // is a plain unspent-with-asset query, which both backends serve.
        let source: Box<dyn crate::cardano::cpo_history::CpoHistorySource> =
            match self.kupo_url.as_deref() {
                Some(url) => Box::new(crate::cardano::cpo_history::KupoHistory::new(url)),
                None => Box::new(crate::cardano::cpo_history::BlockfrostHistory::new(
                    &self.bf_project_id,
                    Some(&self.bf_base_url),
                )),
            };
        // Both roots BY NAME, per [LIB-1]: a positional read would swap them.
        crate::cardano::bridge_state::fetch_bridge_state(source.as_ref(), policy)
            .await
            .map(|state| {
                Some(crate::epoch::traits::BridgeRoots {
                    spi_root: state.spi_root,
                    cpo_root: state.cpo_root,
                })
            })
            .map_err(|e| EpochError::Chain(format!("read the bridge state singleton: {e}")))
    }

    async fn query_pool_stake(
        &self,
        pool_id: &str,
    ) -> EpochResult<crate::cardano::stake::PoolStake> {
        crate::cardano::stake::fetch_pool_stake(&self.bf_base_url, &self.bf_project_id, pool_id)
            .await
            .map_err(EpochError::Chain)
    }

    async fn submit_signed_tm(
        &self,
        tx_bytes: &[u8],
        fulfilled_por_outpoints: &[[u8; 36]],
    ) -> EpochResult<()> {
        info!(
            "[submit] signed BTC tx: {} bytes, hex: {}",
            tx_bytes.len(),
            hex::encode(tx_bytes)
        );

        // heimdall does not send this to Bitcoin, ever (WI-086). The bytes travel to
        // the watchtower INSIDE the UnconfirmedTm record posted below — that is what
        // the record is for — and the watchtower relays them. An SPO broadcasting its
        // own copy would not be a second path to the same outcome: it moves BTC that
        // Cardano has no record of. The hex is logged above for the operator who has
        // to send one by hand.

        // Track our in-flight TM: query_treasury reports btc_confirmed=false until this
        // txid becomes the Confirmed chain tip, so the epoch machine waits for its own
        // movement instead of double-spending the tip outpoint.
        if let Ok(tx) = deserialize::<Transaction>(tx_bytes) {
            *self.last_submitted_txid.lock().unwrap() =
                Some((tx.compute_txid(), std::time::Instant::now()));
        }

        // Publish the oracle update to Cardano if enabled.
        if !self.submit_oracle {
            info!("[submit] cardano.submit_oracle=false — skipping Cardano oracle publish");
            return Ok(());
        }

        let key = match &self.payment_key {
            Some(k) => k,
            None => {
                warn!(
                    "[submit] no mnemonic configured — skipping Cardano oracle publish (dry run)"
                );
                return Ok(());
            }
        };

        let wallet_addr = self
            .wallet_base_address
            .as_deref()
            .ok_or_else(|| EpochError::Chain("no wallet base address".into()))?;

        debug!("[submit] querying wallet UTxOs at {wallet_addr}");
        let wallet_utxos = self.query_wallet_utxos().await?;
        if wallet_utxos.is_empty() {
            return Err(EpochError::Chain(format!(
                "wallet has no UTxOs — fund it before publishing (address: {wallet_addr})"
            )));
        }

        let total_lovelace: u64 = wallet_utxos.iter().map(|u| u.lovelace).sum();
        debug!(
            "[submit] wallet: {} UTxO(s), {} lovelace total",
            wallet_utxos.len(),
            total_lovelace,
        );
        debug!(
            "[submit] building the TM post tx: treasury={} policy={}",
            self.treasury_address, self.treasury_policy_id
        );

        // Fetch the network's live cost models so the script-integrity hash matches the ledger's
        // (whisky's hardcoded preprod models are stale — see bf_http::fetch_cost_models).
        let cost_models =
            crate::cardano::bf_http::fetch_cost_models(&self.bf_base_url, &self.bf_project_id)
                .await
                .map_err(|e| EpochError::Chain(format!("fetch cost models: {e}")))?;
        debug!(
            "[submit] live cost models: V1={} V2={} V3={} params",
            cost_models[0].len(),
            cost_models[1].len(),
            cost_models[2].len()
        );

        // The real validator CBOR is REQUIRED — there is no scaffold fallback (a post minted
        // under anything else lands at an address nothing scans).
        let tm_script_cbor = self.tm_script_cbor.as_deref().ok_or_else(|| {
            EpochError::Chain(
                "no TM validator on this chain adapter — required to mint the TM NFT under the \
                 real TreasuryMovementValidator policy. It is sourced from the chain by Config \
                 #5 at startup, and preflight step 9 refuses to start a bridge node without \
                 it, so reaching here means this adapter was built off a path that skipped \
                 both"
                    .into(),
            )
        })?;

        // The chain-linkage mint references: the Config UTxO (the validator reads
        // `bridge_state_policy` from it, [PAR-1]) and the bridge-state singleton whose head the
        // posted TM must spend ([PTM-6]/[PTM-7]).
        let (config, singleton) = self.query_config_singleton().await?;
        let mint_refs = crate::cardano::publish::MintRefs {
            config: (config.utxo.tx_hash, config.utxo.index),
            singleton: singleton.utxo,
        };

        // Latest chain slot + time: seeds the datum's `created` and the finite
        // `invalid_hereafter` the TM mint policy requires (created-anchoring check).
        let latest_slot_time = crate::cardano::bf_http::fetch_latest_block_slot_time(
            &self.bf_base_url,
            &self.bf_project_id,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("fetch latest block slot/time: {e}")))?;

        let signed_tx_hex = build_oracle_update_tx(
            &self.treasury_address,
            wallet_addr,
            &self.treasury_policy_id,
            &self.treasury_asset_name_hex,
            tx_bytes,
            &wallet_utxos,
            key,
            tm_script_cbor,
            &mint_refs,
            Some(cost_models),
            latest_slot_time,
            self.validity_window_secs,
            fulfilled_por_outpoints,
        )?;

        let cardano_tx_cbor = hex::decode(&signed_tx_hex)
            .map_err(|e| EpochError::Chain(format!("tx hex decode: {e}")))?;

        // WI-107: the assembled Post-TM, measured rather than modelled. The batch
        // was already sized to fit and the built movement re-checked before
        // signing, so this is the ground truth those two were predicting — and the
        // only place `E` can be calibrated from real bytes instead of a derivation.
        //
        // Reporting the observed overhead every time is the point: the spec asks
        // implementations to measure it, and a number that arrives with each
        // movement never goes stale the way a one-off measurement would.
        let predicted_batch_bytes = crate::epoch::batch::plutus_chunked(tx_bytes.len() as u64)
            + crate::epoch::batch::POR_HINT_BYTES * fulfilled_por_outpoints.len() as u64;
        let observed_envelope =
            (cardano_tx_cbor.len() as u64).saturating_sub(predicted_batch_bytes);
        info!(
            "[submit] submitting Cardano oracle-update tx ({} bytes CBOR) via Blockfrost — \
             observed non-batch overhead {} B against the {} B this node budgeted",
            cardano_tx_cbor.len(),
            observed_envelope,
            self.post_tm_envelope(),
        );
        if observed_envelope > self.post_tm_envelope() {
            warn!(
                "[submit] the Post-TM's non-batch overhead ({observed_envelope} B) EXCEEDS the \
                 budgeted {} B. Nothing is wrong with this movement, but the batch sizing is \
                 optimistic by {} B and a fuller batch could overshoot max_tx_size — raise \
                 POST_TM_ENVELOPE_WITHOUT_SCRIPT.",
                self.post_tm_envelope(),
                observed_envelope - self.post_tm_envelope(),
            );
        }

        let tx_hash = self
            .api
            .transactions_submit(cardano_tx_cbor)
            .await
            .map_err(|e| EpochError::Chain(format!("blockfrost tx submit: {e}")))?;

        info!("[submit] Cardano oracle-update submitted: tx_hash={tx_hash}");

        self.wait_for_cardano_confirmation(&tx_hash).await?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared TM-UTxO scan (WI-028) — used by `query_treasury` and the sweep CLI.
// ---------------------------------------------------------------------------

/// Result of scanning the TM validator address for treasury movements.
pub struct TmScan {
    /// Every LEGACY Confirmed (Constr 1) TM datum found. Rev 5.4 mints none —
    /// this stays only so a scan of pre-migration history decodes (DEC-033);
    /// nothing chain-follows it any more.
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

impl TmScan {
    /// Whether the peg-out payment history can be trusted. A marker-token datum we could not read is
    /// a real (NFT-mint-gated) TM whose payments are invisible to us, so paying any peg-out while
    /// one exists risks re-paying it.
    #[must_use]
    pub fn pegout_history_is_complete(&self) -> bool {
        self.parse_failures == 0 && self.opaque_unconfirmed == 0
    }
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
                warn!("[tm-scan] marker-token TM datum failed hex decode: {e}");
                parse_failures += 1;
                continue;
            }
        };
        let datum: PlutusData = match minicbor::decode(&datum_cbor) {
            Ok(d) => d,
            Err(e) => {
                warn!("[tm-scan] marker-token TM datum failed CBOR decode: {e}");
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
                    warn!(
                        "[tm-scan] Unconfirmed TM datum's BTC tx did not deserialize — \
                         treating as a possible in-flight movement"
                    );
                    opaque_unconfirmed += 1;
                }
            },
            Err(e) => {
                warn!("[tm-scan] marker-token Confirmed TM datum failed to parse: {e}");
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
                    warn!("[tm-scan] could not read chain time for staleness deadline: {e}");
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
                        warn!(
                            "[tm-scan] Unconfirmed TM {} unconfirmed for {age}s (> {deadline}s \
                             deadline) — treating as dead/stale, ignoring",
                            tm.btc_txid
                        );
                        stale.insert(tm.btc_txid);
                    }
                }
                Err(e) => warn!(
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
            warn!(
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
    use super::{BlockfrostCardanoChain, DkgFaultBanFlow, viable_in_flight_spends};
    use crate::cardano::treasury_datum::UnconfirmedTm;
    use crate::epoch::state::Roster;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
    use std::collections::HashSet;

    /// One dealer-generated FROST group, standing in for a ceremony output. What
    /// is under test is which group KEYS a persisted ceremony contributes, so how
    /// the shares were produced does not matter.
    fn dealt_group_keys() -> crate::epoch::state::GroupKeys {
        use frost_secp256k1_tr as frost;
        let (shares, pkp) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand::thread_rng(),
        )
        .unwrap();
        let share = shares.into_values().next().unwrap();
        crate::epoch::state::GroupKeys {
            verifying_key: *pkp.verifying_key(),
            public_key_package: pkp,
            key_package: frost::keys::KeyPackage::try_from(share).unwrap(),
        }
    }

    /// The head's internal key after an Update-Y is the OUTGOING ceremony's, and
    /// nothing on chain names it: the datum holds only the key that supersedes
    /// it. So it has to come from the ceremonies this node persisted, or the
    /// candidate list cannot reproduce the head's scriptPubKey and
    /// `query_treasury` fails outright — taking with it the very movement that
    /// would close the window.
    ///
    /// Newest first, and several deep: an epoch whose DKG fails posts no Update-Y
    /// and the old key carries over, so the head can be more than one ceremony
    /// behind.
    #[test]
    fn persisted_ceremonies_are_offered_as_internal_key_candidates() {
        use crate::epoch::persist::{PersistedDkg, write_dkg_state};

        let dir = std::env::temp_dir().join(format!(
            "wi75wte-candidates-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        // No state dir → the candidates this node had before, and no failure.
        assert!(bare_chain().persisted_internal_candidates().is_empty());
        let chain = bare_chain().with_state_dir(Some(dir.clone()));
        assert!(
            chain.persisted_internal_candidates().is_empty(),
            "an unreadable or absent state dir is not an error — the head's own \
             scriptPubKey is still what decides"
        );

        let mut expected = Vec::new();
        for epoch in [6u64, 7] {
            let keys = dealt_group_keys();
            expected.push(
                crate::frost::xonly::group_xonly(&keys.verifying_key)
                    .unwrap()
                    .xonly,
            );
            write_dkg_state(
                &dir,
                &PersistedDkg::from_output(
                    epoch,
                    0,
                    &Roster {
                        epoch,
                        min_signers: 2,
                        max_signers: 3,
                        participants: Default::default(),
                    },
                    &keys,
                )
                .unwrap(),
            )
            .unwrap();
        }
        expected.reverse(); // newest epoch first

        assert_eq!(
            chain
                .persisted_internal_candidates()
                .into_iter()
                .map(|(_, k)| k)
                .collect::<Vec<_>>(),
            expected
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A chain with no Bitcoin/Cardano state worth speaking of — enough to reach
    /// the pure branches of `current_federation`, which is the only thing these
    /// tests touch.
    fn bare_chain() -> BlockfrostCardanoChain {
        let key = bitcoin::key::UntweakedPublicKey::from_slice(&[
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ])
        .unwrap();
        BlockfrostCardanoChain::new(
            "preprodxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "addr_test1_treasury",
            "aa".repeat(28),
            String::new(),
            crate::cardano::treasury_datum::TreasuryConfig {
                y_51: key,
                y_fed: key,
                federation_csv_blocks: 144,
                pegin_refund_timeout_blocks: 720,
                treasury_outpoint: op(0x11, 0),
                treasury_value: Amount::from_sat(100_000),
            },
            crate::epoch::state::Roster {
                epoch: 0,
                min_signers: 2,
                max_signers: 2,
                participants: std::collections::BTreeMap::new(),
            },
            None,
        )
    }

    /// The Config is re-read at the two moments its value can change what this
    /// node does — a new cycle, and an opportunity the last read predates — and
    /// reused in between.
    ///
    /// Reused is the common case by a wide margin: the poll runs every
    /// `batch_poll_ceiling` (5 min) for the whole of a `tm_batch_interval` (6 h on
    /// preprod), so all but one turn per opportunity now costs one request for the
    /// tip instead of five.
    #[test]
    fn the_config_is_re_read_at_a_new_cycle_and_at_a_new_opportunity() {
        use super::config_refresh_due;
        use crate::cardano::config_params::{
            CachedConfig, ConfigUtxoRef, ConfigView, CycleAnchor, test_config_params,
        };
        use crate::epoch::batch::{BatchSlot, BatchWindow};

        let cached = |read_slot: u64, anchor_slot: u64| CachedConfig {
            config: ConfigView {
                params: test_config_params(),
                utxo: ConfigUtxoRef {
                    tx_hash: "ab".repeat(32),
                    index: 0,
                },
            },
            config_created_ms: Some(1_699_000_000_000),
            read_slot,
            anchor_slot,
        };
        let anchor = |start: u64| CycleAnchor {
            epoch: 500,
            start_slot: start,
            end_slot: Some(start + 431_999),
        };
        let open_at = |slot: u64| BatchWindow::Open {
            batch: BatchSlot {
                index: 2,
                slot,
                cutoff_slot: slot - 100,
            },
            next: None,
        };
        let c = cached(5_100, 5_000);

        assert!(
            !config_refresh_due(&c, Some(anchor(5_000)), &open_at(5_000)),
            "a read taken inside the open opportunity is the pin every co-signer needs"
        );
        assert!(
            config_refresh_due(&c, Some(anchor(5_000)), &open_at(6_000)),
            "a movement built at B_i must be built from a Config read at or after B_i"
        );
        assert!(
            config_refresh_due(&c, Some(anchor(437_000)), &open_at(5_000)),
            "every schedule offset is measured from the cycle start, so a carried-over Config \
             places the new cycle's grid against a stale anchor"
        );
        assert!(
            !config_refresh_due(&c, Some(anchor(5_000)), &BatchWindow::Closed { next: None }),
            "waiting between opportunities in one cycle must cost no Config read at all"
        );
        assert!(
            config_refresh_due(&c, None, &BatchWindow::NoGrid),
            "with no anchor and no grid nothing here can show the reuse is still good"
        );
    }

    /// The refresh has nowhere to read from unless the Config locator is set, and
    /// in that state the startup-resolved pair must stand unchanged — that is the
    /// fixture-roster deployment and every bridge whose Config predates the
    /// federation appends. Without this, making the identity chain-live would
    /// silently drop the local-keys route.
    #[tokio::test]
    async fn without_a_config_locator_the_pinned_federation_stands() {
        let ban = crate::cardano::ban_list::BanListSource::from_policy_id(&[0xbb; 28], false);
        let registry = crate::cardano::roster::RegistryRosterSource::from_policy_ids(
            &[0xc1; 28],
            &[0xc2; 28],
            b"TMTx",
            false,
        );

        // No refresh config at all — the pre-WI-068 shape.
        let chain = bare_chain()
            .with_registry_roster(registry.clone())
            .with_ban_source(ban.clone());
        let (r, b) = chain.current_federation().await.unwrap();
        assert_eq!(r.unwrap().registry_policy_hex, "c1".repeat(28));
        assert_eq!(b.unwrap().ban_policy_hex, "bb".repeat(28));

        // Refresh config present but no Config UTxO to read it from: still the
        // pinned pair, and crucially NOT a fetch against an unset address.
        let chain = bare_chain()
            .with_registry_roster(registry)
            .with_ban_source(ban)
            .with_federation_refresh(crate::config::CardanoConfig::default());
        let (r, b) = chain.current_federation().await.unwrap();
        assert_eq!(r.unwrap().treasury_info_policy_hex, "c2".repeat(28));
        assert!(b.is_some());

        // And with nothing pinned either, there is simply no registry — the
        // fallback fixture roster, not an error.
        let chain = bare_chain().with_federation_refresh(crate::config::CardanoConfig::default());
        assert!(chain.current_federation().await.unwrap().0.is_none());
    }

    /// WI-2AHGZ, and the reason the batch discipline sits on the WRITE rather than
    /// the read: `await_batch_opportunity` POLLS this in a loop, so a second read
    /// inside the same `B_i` must not re-pin. When it did, node A pinning early in
    /// `B_i` and node B pinning late straddled a governance Update landing between
    /// them, both passed the read-side window check, and they scanned different
    /// addresses for the same movement.
    #[tokio::test]
    async fn a_batch_keeps_the_config_it_first_read_and_the_next_one_adopts_the_move() {
        use crate::cardano::config_params::{
            ConfigUtxoRef, ConfigView, ParamSnapshot, test_config_params,
        };
        let snap = |peg_in: u8, utxo: &str| ParamSnapshot {
            slot: 1_000,
            time_ms: 1_700_000_000_000,
            config: ConfigView {
                params: {
                    let mut p = test_config_params();
                    p.contracts.peg_in_script_hash = vec![peg_in; 28];
                    p.contracts.peg_out_script_hash = vec![peg_in ^ 0xff; 28];
                    p.contracts.bridged_token_policy_id = vec![0x77; 28];
                    p
                },
                utxo: ConfigUtxoRef {
                    tx_hash: utxo.repeat(32),
                    index: 0,
                },
            },
            config_created_ms: Some(1_699_000_000_000),
        };
        let b_i = crate::epoch::batch::BatchSlot {
            index: 3,
            slot: 1_000,
            cutoff_slot: 900,
        };
        let chain = bare_chain();

        chain.remember_contracts(&snap(0x11, "aa"), Some(b_i));
        let first = chain.contracts_for_batch().expect("B_i is pinned");

        // A governance Update lands mid-batch and a later poll of the SAME B_i sees
        // it. The pin must not move, or this node and one that polled earlier build
        // different bytes for one movement.
        chain.remember_contracts(&snap(0x22, "bb"), Some(b_i));
        assert_eq!(chain.contracts_for_batch().unwrap(), first);

        // WI-2AHGZ clause 4: not adopting it is correct, but staying SILENT about it
        // is not — an operator who just ran update-config must be able to tell their
        // change was seen and queued rather than lost. Reported once per newer
        // Config, not once per poll of a loop that runs every few seconds.
        let reported = |c: &BlockfrostCardanoChain| {
            c.contracts_cache
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|e| e.reported_unadopted.clone())
        };
        assert_eq!(
            reported(&chain).as_deref(),
            Some(format!("{}#0", "bb".repeat(32)).as_str())
        );
        chain.remember_contracts(&snap(0x22, "bb"), Some(b_i));
        assert_eq!(
            reported(&chain).as_deref(),
            Some(format!("{}#0", "bb".repeat(32)).as_str()),
            "the same newer Config is not re-reported on the next poll"
        );

        // No open opportunity must not clobber it either — `batch.next()` is a
        // FUTURE slot and NoGrid is a transient read failure, not a Config change.
        chain.remember_contracts(&snap(0x33, "cc"), None);
        assert_eq!(chain.contracts_for_batch().unwrap(), first);

        // The NEXT opportunity adopts it: "an update takes effect from the next
        // batch, never retroactively".
        let b_next = crate::epoch::batch::BatchSlot {
            index: 4,
            slot: 8_200,
            cutoff_slot: 1_000,
        };
        chain.remember_contracts(&snap(0x22, "bb"), Some(b_next));
        let now = chain.contracts_for_batch().unwrap();
        assert_ne!(now, first);
        assert_eq!(now.pegin_policy_id, "22".repeat(28));
    }

    /// WI-2AHGZ: the contract identities follow the chain, but a node with no
    /// Config to follow keeps what it was given rather than erroring or scanning
    /// nothing. This pins the fallback arm — the one that has to hold for every
    /// fixture, devnet and pre-Config deployment — and pins that the refresh does
    /// NOT fire against an unset Config address.
    #[tokio::test]
    async fn without_a_config_the_pinned_contract_set_stands() {
        let chain = bare_chain()
            .with_pegout_source("addr_test1_pegout", "aabbcc.fBTC")
            .with_cpo_source(Some("DD".repeat(28).as_str()), None);

        // No config_address / config_nft_unit → nothing to refresh from, and the
        // caller falls back to what boot handed it.
        assert!(chain.current_contracts().await.unwrap().is_none());

        // The pinned values are still there to fall back TO, and the policy kept its
        // normalisation (`with_cpo_source` lowercases, so a Config-derived hex and a
        // typed one compare equal instead of differing by case).
        assert_eq!(
            chain.cpo_policy_id.as_deref(),
            Some("dd".repeat(28).as_str())
        );
        let pinned = chain.pegout_source.as_ref().unwrap();
        assert_eq!(pinned.address, "addr_test1_pegout");
        assert_eq!(pinned.fbtc_unit, "aabbcc.fBTC");
    }

    /// WI-060: reading the ban list and enforcing faults are separate. A node
    /// may filter its roster without being able to publish a fault proof, so
    /// the absence of the whole enforcement key set is `None`, not an error —
    /// but any one of them present turns the whole path on. Since WI-091 the
    /// four `*_ref` locations are discovered rather than demanded, so what is
    /// mandatory is being able to LOOK, not having typed them.
    #[tokio::test]
    async fn fault_flow_is_optional_as_a_whole_and_mandatory_in_part() {
        let outref = format!("{}:0", "cc".repeat(32));

        // Ban list configured, no enforcement keys → enforcement simply off.
        let mut cardano = crate::config::CardanoConfig {
            federation_one_shot: Some(outref.clone()),
            registry_blueprint: Some("plutus.json".to_string()),
            ..Default::default()
        };
        assert!(
            DkgFaultBanFlow::from_config(&cardano, None)
                .await
                .expect("no enforcement keys is a valid configuration")
                .is_none()
        );

        // One enforcement key present → the path is on, and the rest must
        // resolve. The four *_ref keys are no longer among the things that MUST
        // be typed (WI-091): unset means "discover it". What still fails loudly
        // is being unable to look — here there is no blockfrost project id — and
        // the error names both ways out rather than only the key.
        cardano.fault_proof_srs_path = Some("/nonexistent/srs".to_string());
        let err = DkgFaultBanFlow::from_config(&cardano, None)
            .await
            .expect_err("a path that can neither find nor be told must fail at startup");
        assert!(
            err.contains("_ref") || err.contains("srs") || err.contains("blueprint"),
            "the error should name what is missing: {err}"
        );

        // Enforcement keys but no federation one-shot resolved from the chain →
        // named explicitly. Every fault verifier is parameterized by it, so
        // there is nothing to publish a proof under — and nothing to derive a
        // deployer address from either.
        let orphan = crate::config::CardanoConfig {
            fault_proof_srs_path: Some("/nonexistent/srs".to_string()),
            ..Default::default()
        };
        let err = DkgFaultBanFlow::from_config(&orphan, None)
            .await
            .expect_err("no one-shot");
        assert!(err.contains("federation one-shot"), "{err}");
    }

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

    // --- head_spk_from_history ------------------------------------------------

    mod head_spk {
        use crate::cardano::cpo_history::{CpoHistorySource, DatumState, HistoricalOutput};
        use async_trait::async_trait;
        use bitcoin::absolute::LockTime;
        use bitcoin::consensus::serialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
        use pallas_primitives::conway::{Constr, PlutusData};
        use pallas_primitives::{BoundedBytes, MaybeIndefArray};

        struct FakeHistory(Vec<HistoricalOutput>);

        #[async_trait]
        impl CpoHistorySource for FakeHistory {
            fn backend(&self) -> &'static str {
                "fake"
            }
            fn endpoint(&self) -> &str {
                "fake://"
            }
            fn datum_gap_advice(&self) -> &'static str {
                ""
            }
            async fn address_history(
                &self,
                _address: &str,
            ) -> Result<Vec<HistoricalOutput>, String> {
                Ok(self.0.clone())
            }
            async fn unspent_with_asset(
                &self,
                _policy_hex: &str,
                _asset_name_hex: &str,
            ) -> Result<Vec<HistoricalOutput>, String> {
                Ok(vec![])
            }
        }

        /// A tiny 1-in/1-out BTC tx whose output 0 pays `spk`.
        fn btc_tx(prev: u8, spk: &ScriptBuf) -> Transaction {
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([prev; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(9_000),
                    script_pubkey: spk.clone(),
                }],
            }
        }

        /// An UnconfirmedTm datum (Constr 0) embedding `tx`'s signed bytes.
        fn record(tx: &Transaction) -> HistoricalOutput {
            let datum = PlutusData::Constr(Constr {
                tag: 121,
                any_constructor: None,
                fields: MaybeIndefArray::Def(vec![
                    PlutusData::BoundedBytes(BoundedBytes::from(serialize(tx))),
                    PlutusData::BoundedBytes(BoundedBytes::from(vec![0x7a; 28])),
                    crate::cardano::plutus::int(1),
                    crate::cardano::plutus::array(vec![]),
                ]),
            });
            HistoricalOutput {
                tx_hash: "ab".repeat(32),
                output_index: 0,
                assets: Default::default(),
                datum: DatumState::Resolved(datum),
                datum_note: "inline".into(),
            }
        }

        fn junk() -> HistoricalOutput {
            HistoricalOutput {
                tx_hash: "cd".repeat(32),
                output_index: 1,
                assets: Default::default(),
                datum: DatumState::Absent,
                datum_note: "no datum".into(),
            }
        }

        // The head-creating TM is found among SPENT records by the txid RECOMPUTED
        // from its own bytes, and its output-0 script is returned.
        #[tokio::test]
        async fn finds_the_head_creating_tm_and_returns_its_spk() {
            let spk = ScriptBuf::from_bytes(vec![0x51, 0x20]);
            let tx = btc_tx(0x01, &spk);
            let head = OutPoint {
                txid: tx.compute_txid(),
                vout: 0,
            };
            let other = btc_tx(0x02, &ScriptBuf::from_bytes(vec![0x52]));
            let source = FakeHistory(vec![junk(), record(&other), record(&tx)]);
            let got = super::super::head_spk_from_history(&source, "addr_test", &head)
                .await
                .unwrap();
            assert_eq!(got, Some(spk));
        }

        // No record hashes to the head's txid: the BOOTSTRAP anchor case. The
        // caller then constructs the tree from the configured keys.
        #[tokio::test]
        async fn an_unknown_head_is_the_bootstrap_anchor() {
            let source = FakeHistory(vec![junk(), record(&btc_tx(0x02, &ScriptBuf::new()))]);
            let head = OutPoint {
                txid: Txid::from_byte_array([0xee; 32]),
                vout: 0,
            };
            let got = super::super::head_spk_from_history(&source, "addr_test", &head)
                .await
                .unwrap();
            assert_eq!(got, None);
        }

        // A hostile record cannot claim the head's slot: the lookup keys on the
        // txid recomputed from the record's OWN bytes, so a record embedding a
        // DIFFERENT transaction never matches the head, whatever its datum says.
        #[tokio::test]
        async fn a_record_with_foreign_bytes_never_matches_the_head() {
            let spk = ScriptBuf::from_bytes(vec![0x51, 0x20]);
            let tx = btc_tx(0x01, &spk);
            let head = OutPoint {
                txid: tx.compute_txid(),
                vout: 0,
            };
            // Only a record embedding some OTHER tx exists.
            let source = FakeHistory(vec![record(&btc_tx(0x03, &ScriptBuf::new()))]);
            let got = super::super::head_spk_from_history(&source, "addr_test", &head)
                .await
                .unwrap();
            assert_eq!(got, None, "foreign bytes must not occupy the head's slot");
        }
    }
}
