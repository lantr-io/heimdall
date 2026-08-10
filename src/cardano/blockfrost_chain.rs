//! `CardanoChain` backed by Blockfrost.
//!
//! Derives the current Bitcoin treasury UTxO from Cardano chain state (WI-028 +
//! DEC-022): `query_treasury` scans every TM UTxO at the treasury address,
//! parses the Confirmed (Constr 1) datums, and chain-follows them to the tip —
//! the TM whose own treasury output nobody has swept. Outpoint `(btc_txid, 0)`,
//! value, and scriptPubKey all come from the tip datum; the tip's SPK must match
//! the current treasury keys (both selecting among divergent lineages and
//! proving we can sign it). Before the first TM confirms, the treasury is the
//! anchor outpoint from the bridge Config UTxO's field 11
//! (`initial_btc_treasury_utxo`, located by the config NFT), priced via bitcoind
//! `gettxout` — there is no local treasury configuration. Unconfirmed (Constr 0)
//! datums are inspected only to detect a movement already in flight against the
//! tip, so heimdall waits instead of double-posting.
//!
//! `submit_signed_tm` builds a Cardano transaction that **creates a new
//! UTxO** at the treasury address with the signed BTC tx as an inline datum,
//! minting the TM NFT with the chain-linkage redeemer (Genesis when no TM has
//! confirmed yet, Chain(0) referencing the tip Confirmed record otherwise).
//! The old oracle UTxO is NOT spent — old confirmed UTxOs are kept on-chain
//! for minting proofs.

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
use crate::cardano::btc_rpc::{BtcRpcConfig, broadcast_btc_tx};
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
    /// (#18–#20) when the bridge publishes one, and its ban policy id (#17) is
    /// what the locally derived `spo_bans` is checked against (WI-065).
    pub fn from_config(
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
        let Some(ban_bootstrap) = cardano.ban_bootstrap.as_deref() else {
            return Err(
                "cardano.ban_bootstrap is required to publish a fault proof and apply a ban: \
                 the spo_bans policy is parameterized by its bootstrap outref"
                    .to_string(),
            );
        };
        let blueprint_path = req_fault_config(&cardano.registry_blueprint, "registry_blueprint")?;
        let registry_bootstrap =
            req_fault_config(&cardano.registry_bootstrap, "registry_bootstrap")?;
        let srs_path = PathBuf::from(req_fault_config(
            &cardano.fault_proof_srs_path,
            "fault_proof_srs_path",
        )?);
        let spo_bans_ref =
            parse_script_ref(req_fault_config(&cardano.spo_bans_ref, "spo_bans_ref")?)?;
        let round1_fault_ref = parse_script_ref(req_fault_config(
            &cardano.fault_verifier_round1_ref,
            "fault_verifier_round1_ref",
        )?)?;
        let round2_fault_ref = parse_script_ref(req_fault_config(
            &cardano.fault_verifier_round2_ref,
            "fault_verifier_round2_ref",
        )?)?;
        let equivocation_fault_ref = parse_script_ref(req_fault_config(
            &cardano.fault_verifier_equivocation_ref,
            "fault_verifier_equivocation_ref",
        )?)?;

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
        let registry = crate::cardano::blueprint::spos_registry_script(
            &blueprint_json,
            &reg_tx_id,
            u64::from(reg_index),
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
        if let Some(published) = config.and_then(|c| c.bans.as_ref())
            && published.spo_bans_policy_id != spo_bans.hash
        {
            return Err(format!(
                "the fault-enforcement keys derive spo_bans policy {} but the bridge Config \
                 publishes {} (field #17) — an ApplyBan built here would confirm into a ban \
                 list no other SPO reads. Check cardano.ban_bootstrap, \
                 cardano.fault_proof_policies and the ban-schedule keys against this bridge",
                spo_bans.hash_hex(),
                hex::encode(published.spo_bans_policy_id),
            ));
        }

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
    /// The two fields above are what startup happened to see. Config #17 and
    /// #21–#23 are chain state a governance Update can move, exactly like the
    /// #12–#16 the batch snapshot re-reads every batch — so pinning them makes
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
    /// Validity window (seconds) for posted TM txs (`invalid_hereafter`/`created` =
    /// latest + window). 1800 for preprod/mainnet; small on a short-epoch devnet whose
    /// era-forecast horizon is only ~tens-to-hundreds of slots ahead.
    validity_window_secs: u64,
    /// Bech32 address of the bridge Config UTxO and the config NFT unit
    /// (policy_id ++ asset_name hex) that authenticates it. The Config UTxO's field 11
    /// (initial_btc_treasury_utxo) anchors the TM chain. Required for treasury resolution.
    config_address: Option<String>,
    config_nft_unit: Option<String>,
    /// The txid of the last TM this process submitted. `query_treasury` reports
    /// `btc_confirmed = false` until that txid becomes the Confirmed chain tip, so the
    /// epoch machine waits for its own in-flight TM instead of double-spending the tip.
    last_submitted_txid: Mutex<Option<bitcoin::Txid>>,
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
            payment_key: None,
            wallet_base_address: None,
            treasury_y_51: Mutex::new(None),
            btc_rpc: None,
            submit_btc: true,
            submit_oracle: true,
            oracle_constructor: 0,
            tm_script_cbor: None,
            validity_window_secs: 1800,
            config_address: None,
            config_nft_unit: None,
            last_submitted_txid: Mutex::new(None),
            fault_ban_flow: None,
            cpo_policy_id: None,
            kupo_url: None,
            pegout_source: None,
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

    /// Mint the TM NFT under the real TreasuryMovementValidator policy (CBOR from
    /// `binocular tm-script`). Without this the always-ok scaffold policy is used.
    pub fn with_tm_policy(mut self, script_cbor: &str) -> Self {
        self.tm_script_cbor = Some(script_cbor.to_string());
        self
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
    /// its fields #12–#16 are the operational parameters every TM is built from.
    pub fn with_config_utxo(mut self, address: &str, nft_unit: &str) -> Self {
        self.config_address = Some(address.to_string());
        self.config_nft_unit = Some(nft_unit.to_string());
        self
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

    /// Re-resolve the federation identity (Config #17, #21–#23) from the chain on
    /// every roster read, instead of running forever on whatever startup saw.
    pub fn with_federation_refresh(mut self, cardano: crate::config::CardanoConfig) -> Self {
        self.federation_refresh = Some(cardano);
        self
    }

    /// The registry + ban sources AS OF NOW, re-read from the bridge Config.
    ///
    /// The startup-resolved pair is the fallback, not the answer: #17 and #21–#23
    /// are chain state, and a node that pinned them at boot filters a different
    /// roster from a node booted after a governance Update — a divergence keyed on
    /// restart time, which no operator can see and no log records. The batch
    /// snapshot already re-reads #12–#16 on the same reasoning.
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
                "bridge Config (federation identity #17/#21-#23): {e}"
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
        let ctx = crate::cardano::dkg_roster::fetch_dkg_context(
            &registry,
            bans.as_ref(),
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
        // Re-read #17/#21-#23 rather than trusting the startup snapshot: this is
        // the derivation whose inputs must be identical on every node, so it is
        // the last one that should run on a per-node copy of chain state.
        let (registry, bans) = self.current_federation().await?;
        match &registry {
            // WI-012: eligible roster = registry − active bans, FROST threshold
            // stake-weighted. Any failure is hard — never silently fall back to
            // the fixture, which would let SPOs run DKG on divergent rosters.
            Some(registry) => crate::cardano::dkg_roster::fetch_dkg_context(
                registry,
                bans.as_ref(),
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
        // Rev 5.4: the current treasury is the bridge-state singleton's head — outpoint AND
        // satoshi amount straight from the BridgeState datum. There is no Confirmed chain to
        // walk: Confirm burns the TM record and advances the singleton instead.
        let (_config, singleton) = self.query_config_singleton().await?;
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
            // Staleness deadline is applied on the mover/sweep path (run_sweep_pegins);
            // the epoch-machine daemon does not thread it through TreasuryConfig yet.
            None,
        )
        .await
        .map_err(EpochError::Chain)?;

        // The treasury's Taproot internal key (Y_51). After DKG, publish_group_key
        // stores the FROST group key here; at bootstrap it is the config Y_51.
        let maybe_key = *self.treasury_y_51.lock().unwrap();
        let y_51 = maybe_key.unwrap_or(self.treasury_config.y_51);
        let csv = self.treasury_config.federation_csv_blocks;

        // Which taproot tree is the head locked under? The singleton records the outpoint and
        // amount but not the scriptPubKey, so the candidate trees — the federation seed
        // (production) and, defensively, Y_51 itself (the demo's collapsed Y_fed=Y_51
        // convention) — are reconstructed and checked against bitcoind's gettxout on the head.
        // Never sign an outpoint whose on-chain scriptPubKey we cannot reconstruct.
        let rpc = self.btc_rpc.as_ref().ok_or_else(|| {
            EpochError::Chain(
                "treasury resolution needs bitcoin.rpc_url (gettxout on the singleton's head \
                 selects the taproot tree to spend under)"
                    .into(),
            )
        })?;
        let actual_spk_hex = crate::cardano::btc_rpc::get_txout_script_pub_key_hex(
            rpc,
            &outpoint.txid.to_string(),
            outpoint.vout,
        )
        .await?;
        let secp = bitcoin::key::Secp256k1::new();
        let csv_u16 = csv_to_u16(csv)?;
        let mut leaf_candidates = vec![self.treasury_config.y_fed];
        if y_51 != self.treasury_config.y_fed {
            leaf_candidates.push(y_51);
        }
        let y_fed = leaf_candidates
            .iter()
            .copied()
            .find(|&cand| {
                let spk = bitcoin::ScriptBuf::new_p2tr_tweaked(
                    treasury_spend_info(&secp, y_51, cand, csv_u16).output_key(),
                );
                hex::encode(spk.as_bytes()) == actual_spk_hex
            })
            .ok_or_else(|| {
                EpochError::Chain(format!(
                    "the singleton's head {outpoint} is locked under a scriptPubKey \
                     ({actual_spk_hex}) that no candidate treasury tree reproduces — \
                     y_51/y_fed/csv configuration is out of step with the chain"
                ))
            })?;

        // A movement already in flight against this head — or an in-flight movement we could
        // not read — means it is not yet safe to build the next TM; report btc_confirmed=false
        // so BuildTm waits for confirmation. Additionally, a TM this process submitted must
        // have become the head before the next one builds (DEC-022: restart-safe against a lost
        // Cardano post — the in-flight scan catches cross-process movements, this catches our
        // own). An unreadable datum at the NFT-gated TM address counts as possibly-in-flight
        // (fail closed, never double-post).
        let own_pending = match *self.last_submitted_txid.lock().unwrap() {
            None => false,
            Some(t) => outpoint.txid != t,
        };
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

        Ok(TreasuryUtxo {
            outpoint,
            value,
            y_51,
            y_fed,
            federation_csv_blocks: csv,
            btc_confirmed,
        })
    }

    async fn is_tm_confirmed(&self, txid: &bitcoin::Txid) -> EpochResult<bool> {
        let treasury = self.query_treasury().await?;
        Ok(treasury.btc_confirmed && treasury.outpoint.txid == *txid)
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
                 identity at #21-#23) — the derived group key stays LOCAL to this node and \
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
        // id the Config publishes (#22). A node reading the roster from the
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
        let built = crate::cardano::update_y::build_update_y_tx(
            &crate::cardano::update_y::UpdateYRequest {
                treasury_script,
                state: &state,
                new_spos_frost_key: &plan.new_key.serialize(),
                epoch: epoch_i64,
                signature,
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
        let Some(src) = &self.pegout_source else {
            warn!(
                "[pegout] no cardano.pegout_script_address / cardano.bridged_token_unit \
                 — this TM pays NO peg-out; every pending withdrawal waits for a later batch"
            );
            return Ok(vec![]);
        };

        // Malformed UTxOs at the (permissionlessly payable) peg-out address are skipped with a
        // per-UTxO line on stderr inside `fetch_pegout_requests`, matching the CLI sweep path:
        // one poison datum must not block every Treasury Movement bridge-wide.
        let scan = crate::cardano::pegout_datum::fetch_pegout_requests(
            &self.bf_base_url,
            &self.bf_project_id,
            &src.address,
            &src.fbtc_unit,
        )
        .await
        .map_err(|e| EpochError::Chain(format!("fetch_pegout_requests: {e}")))?;

        if scan.malformed > 0 {
            warn!(
                "[pegout] {} UTxO(s) at {} carry the bridged token but no decodable \
                 PegOutDatum — they are NOT payable by any TM and are absent from the open count \
                 below; their owners can still Cancel",
                scan.malformed, src.address,
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
        let snapshot =
            config_params::fetch_param_snapshot(&self.bf_base_url, &self.bf_project_id, addr, unit)
                .await
                .map_err(|e| EpochError::Chain(format!("batch parameter snapshot: {e}")))?;
        let (tm_params, source) =
            config_params::resolve_tm_params(Some(&snapshot), self.local_fee_rate_sat_per_vb);
        let batch =
            config_params::batch_at(&self.bf_base_url, &self.bf_project_id, &snapshot).await;
        Ok(BatchSnapshot {
            now_ms: snapshot.time_ms,
            slot: snapshot.slot,
            batch,
            tm_params,
            source,
        })
    }

    async fn query_cpo_root(&self) -> EpochResult<Option<[u8; 32]>> {
        let Some(policy) = self.cpo_policy_id.as_deref() else {
            return Ok(None);
        };
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
        // `cpo_root` BY NAME, per [LIB-1]: field 0 of the singleton is `spi_root`.
        crate::cardano::bridge_state::fetch_bridge_state(source.as_ref(), policy)
            .await
            .map(|state| Some(state.cpo_root))
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

        // Broadcast the signed BTC tx to Bitcoin if configured and enabled.
        if self.submit_btc {
            match &self.btc_rpc {
                Some(rpc) => broadcast_btc_tx(rpc, tx_bytes).await?,
                None => warn!(
                    "[submit] bitcoin.submit=true but rpc_url not set — skipping BTC broadcast"
                ),
            }
        } else {
            info!("[submit] bitcoin.submit=false — skipping BTC broadcast");
        }

        // Track our in-flight TM: query_treasury reports btc_confirmed=false until this
        // txid becomes the Confirmed chain tip, so the epoch machine waits for its own
        // movement instead of double-spending the tip outpoint.
        if let Ok(tx) = deserialize::<Transaction>(tx_bytes) {
            *self.last_submitted_txid.lock().unwrap() = Some(tx.compute_txid());
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
            "[submit] building Cardano oracle-update tx: treasury={} constructor={} policy={}",
            self.treasury_address, self.oracle_constructor, self.treasury_policy_id
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

        // The chain-linkage mint references: the Config UTxO (the validator reads
        // `bridge_state_policy` from it, [PAR-1]) and the bridge-state singleton whose head the
        // posted TM must spend ([PTM-6]/[PTM-7]). Only needed when minting under the real TM
        // validator.
        let mint_refs: Option<crate::cardano::publish::MintRefs> = if self.tm_script_cbor.is_some()
        {
            let (config, singleton) = self.query_config_singleton().await?;
            Some(crate::cardano::publish::MintRefs {
                config: (config.utxo.tx_hash, config.utxo.index),
                singleton: singleton.utxo,
            })
        } else {
            None
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
            self.oracle_constructor,
            &wallet_utxos,
            key,
            self.tm_script_cbor.as_deref(),
            mint_refs,
            Some(cost_models),
            latest_slot_time,
            self.validity_window_secs,
            fulfilled_por_outpoints,
        )?;

        let cardano_tx_cbor = hex::decode(&signed_tx_hex)
            .map_err(|e| EpochError::Chain(format!("tx hex decode: {e}")))?;

        info!(
            "[submit] submitting Cardano oracle-update tx ({} bytes CBOR) via Blockfrost",
            cardano_tx_cbor.len()
        );

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
    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
    use std::collections::HashSet;

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

    /// WI-060: reading the ban list and enforcing faults are separate. A node
    /// may filter its roster without being able to publish a fault proof, so
    /// the absence of the whole enforcement key set is `None`, not an error —
    /// but any one of them present demands all of them.
    #[test]
    fn fault_flow_is_optional_as_a_whole_and_mandatory_in_part() {
        let outref = format!("{}:0", "cc".repeat(32));

        // Ban list configured, no enforcement keys → enforcement simply off.
        let mut cardano = crate::config::CardanoConfig {
            ban_bootstrap: Some(outref.clone()),
            registry_blueprint: Some("plutus.json".to_string()),
            registry_bootstrap: Some(outref.clone()),
            ..Default::default()
        };
        assert!(
            DkgFaultBanFlow::from_config(&cardano, None)
                .expect("no enforcement keys is a valid configuration")
                .is_none()
        );

        // One enforcement key present → every one of them is now required, and
        // the error names the missing key rather than degrading.
        cardano.fault_proof_srs_path = Some("/nonexistent/srs".to_string());
        let err = DkgFaultBanFlow::from_config(&cardano, None)
            .expect_err("a half-configured publish path must fail at startup");
        assert!(err.contains("cardano.spo_bans_ref is required"), "{err}");

        // Enforcement keys without a ban list bootstrap → named explicitly.
        let orphan = crate::config::CardanoConfig {
            fault_proof_srs_path: Some("/nonexistent/srs".to_string()),
            ..Default::default()
        };
        let err = DkgFaultBanFlow::from_config(&orphan, None).expect_err("no ban bootstrap");
        assert!(err.contains("cardano.ban_bootstrap is required"), "{err}");
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
}
