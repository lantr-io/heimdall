//! ApplyBan transaction support (`spo_bans.ak`, WI-018 part 4).
//!
//! Applying a ban consumes a published FaultProof and writes a ban-list node.
//! Unlike register_spo (a mint + spends), the action is authorized by a
//! **zero-amount reward withdrawal** from the `spo_bans` *stake* credential:
//! `spo_bans.ak` has a `withdraw(ApplyBan{..})` handler, and its `mint`
//! (`MintBanNode`) and `spend` (`BanListAction`) branches only check that the
//! ApplyBan withdrawal is present (via a `withdraw_redeemer_index`). So one tx
//! carries up to three `spo_bans` script uses (withdraw + spend the anchor +
//! mint the node) plus a `fault_verifier.BurnProof` mint that burns the proof.
//!
//! Two shapes (the validator branches on `existing_ban_input_index`):
//! - **first ban** (`None`): linked-list `insert_ascending` — spend the anchor
//!   element, output the continued anchor + the new `"ban/"||pool_id` node, and
//!   MINT the node NFT. Plan it with [`super::ban_list::BanList::plan_insert`].
//! - **reban** (`Some`): `spend_for_updating_elements_data` — spend the
//!   existing node and reproduce it with updated [`BanNodeData`] (same asset
//!   name + link), and mint NO ban-policy token.
//!
//! This module currently provides the byte-exact redeemer encoders the
//! (forthcoming) tx builder sits on. The ApplyBan withdrawal is keyed by the
//! `spo_bans` reward address — see [`crate::cardano::blueprint::ParameterizedScript::reward_address`].
//! The on-chain shapes (confirmed against the compiled `spo_bans` blueprint schema):
//!
//! ```text
//! SpoBansWithdrawRedeemer = ApplyBan Constr(0, [ fault_input_index, registration_ref_input_index,
//!                                                accused_pool_id, evidence_hash,
//!                                                ban_anchor_input_index, ban_anchor_output_index,
//!                                                existing_ban_input_index: Option<Int>,
//!                                                ban_node_output_index ])
//! SpoBansMintRedeemer     = Bootstrap   Constr(0, [ OutputReference ])
//!                         | MintBanNode Constr(1, [ withdraw_redeemer_index, pool_id ])
//! SpoBansSpendRedeemer    = BanListAction Constr(0, [ withdraw_redeemer_index ])
//! Option<Int>             = Some Constr(0, [ Int ]) | None Constr(1, [])
//! ```
//!
//! The FaultProof burn uses [`super::fault_proof::burn_proof_redeemer`].

use pallas_codec::minicbor;
use pallas_codec::utils::NonEmptySet;
use pallas_primitives::PlutusData;
use pallas_primitives::conway::Tx;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::ban_list::{
    BAN_NODE_KEY_PREFIX, BAN_ROOT_KEY, BanElement, BanElementData, BanList, BanListError,
    BanNodeData, BanPolicyParams, BanUtxo, fault_token_name, find_ban_utxos,
};
use crate::cardano::bf_http::BfUtxo;
use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::fault_proof::{burn_proof_redeemer, output_reference};
use crate::cardano::plutus::{bytes, constr, int, option};
use crate::cardano::publish::WalletUtxo;
use crate::cardano::tx_common::{
    BootstrapError, OneShotBootstrapParams, build_oneshot_bootstrap_tx, element_lovelace,
    select_collateral, select_fee, sign_built_tx as common_sign_built_tx, whisky_network,
};
use crate::cardano::wallet::pub_key_hash_hex;

// ---------------------------------------------------------------------------
// Redeemer encoders
// ---------------------------------------------------------------------------

/// `Option<Int>` — `Some(i)` = `Constr(0, [int(i)])`, `None` = `Constr(1, [])`
/// (the standard Aiken `Option` encoding).
#[must_use]
pub fn option_int(v: Option<i64>) -> PlutusData {
    option(v.map(int))
}

/// `SpoBansWithdrawRedeemer::ApplyBan` — constructor 0, the 8 fields in the
/// order `spo_bans.ak` declares them. The index fields point into the built
/// tx's (ledger-sorted) input / reference-input / output lists; the builder
/// computes them.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn apply_ban_redeemer(
    fault_input_index: i64,
    registration_ref_input_index: i64,
    accused_pool_id: &[u8],
    evidence_hash: &[u8],
    ban_anchor_input_index: i64,
    ban_anchor_output_index: i64,
    existing_ban_input_index: Option<i64>,
    ban_node_output_index: i64,
) -> PlutusData {
    constr(
        0,
        vec![
            int(fault_input_index),
            int(registration_ref_input_index),
            bytes(accused_pool_id),
            bytes(evidence_hash),
            int(ban_anchor_input_index),
            int(ban_anchor_output_index),
            option_int(existing_ban_input_index),
            int(ban_node_output_index),
        ],
    )
}

/// `SpoBansMintRedeemer::MintBanNode` — constructor 1 (constructor 0 is
/// `Bootstrap`). `withdraw_redeemer_index` points at the ApplyBan withdrawal in
/// the tx's reward-withdrawal list; `pool_id` is the accused pool (the node's
/// asset name is `"ban/" || pool_id`).
#[must_use]
pub fn mint_ban_node_redeemer(withdraw_redeemer_index: i64, pool_id: &[u8]) -> PlutusData {
    constr(1, vec![int(withdraw_redeemer_index), bytes(pool_id)])
}

/// `SpoBansSpendRedeemer::BanListAction` — constructor 0, the redeemer for
/// spending a ban-list element (the anchor on a first ban, the existing node on
/// a reban). Carries the same `withdraw_redeemer_index`.
#[must_use]
pub fn ban_list_action_redeemer(withdraw_redeemer_index: i64) -> PlutusData {
    constr(0, vec![int(withdraw_redeemer_index)])
}

// ---------------------------------------------------------------------------
// ApplyBan tx builder
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ApplyBanError {
    /// Reading/validating the on-chain ban list or planning the insert failed.
    BanList(BanListError),
    /// The pool is already PERMANENTLY banned — the validator's reban branch
    /// requires `!permanent`, so there is nothing to do.
    AlreadyPermanent,
    /// This `evidence_hash` was already applied to the pool — the validator
    /// rejects re-banning on evidence already present.
    EvidenceAlreadyApplied,
    Wallet(String),
    Build(String),
}

impl From<BootstrapError> for ApplyBanError {
    fn from(e: BootstrapError) -> Self {
        match e {
            BootstrapError::Wallet(m) => ApplyBanError::Wallet(m),
            BootstrapError::Build(m) => ApplyBanError::Build(m),
        }
    }
}

impl std::fmt::Display for ApplyBanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BanList(e) => write!(f, "ban list: {e}"),
            Self::AlreadyPermanent => write!(f, "pool is already permanently banned"),
            Self::EvidenceAlreadyApplied => {
                write!(f, "this evidence_hash was already applied to the pool")
            }
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "tx build: {e}"),
        }
    }
}

impl std::error::Error for ApplyBanError {}

impl From<BanListError> for ApplyBanError {
    fn from(e: BanListError) -> Self {
        Self::BanList(e)
    }
}

/// The parked FaultProof UTxO (Part 3b output, at the operator wallet) the
/// ApplyBan tx spends and burns.
#[derive(Debug, Clone)]
pub struct FaultProofUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub lovelace: u64,
}

/// Everything [`build_apply_ban_tx`] needs. UTxO sets are caller-fetched so the
/// builder stays pure/testable.
pub struct ApplyBanRequest<'a> {
    /// The 7-param `spo_bans` policy (the ban-list policy id + script).
    pub spo_bans_script: &'a ParameterizedScript,
    /// The `fault_verifier` policy that minted the FaultProof (its token is
    /// burned). Must be one of the `ban_params.fault_proof_policies`.
    pub fault_verifier_script: &'a ParameterizedScript,
    pub ban_params: &'a BanPolicyParams,
    /// 28-byte accused pool id (= `blake2b_224(cold_vkey)`).
    pub accused_pool_id: [u8; 28],
    /// 32-byte fault evidence hash (binds the FaultProof token name).
    pub evidence_hash: [u8; 32],
    /// UTxOs at the ban script address (root + nodes).
    pub ban_utxos: &'a [BfUtxo],
    /// The FaultProof UTxO parked by Part 3b (wallet-locked).
    pub fault_utxo: &'a FaultProofUtxo,
    /// `(tx_hash, index)` of the accused pool's registry node UTxO — the
    /// read-only reference input the validator checks against.
    pub registration_ref: (String, u32),
    /// `(tx_hash, index)` of a UTxO carrying the `spo_bans` script as a
    /// reference script. REQUIRED: the ~5.5 KB script is used 3× (withdraw +
    /// anchor spend + node mint) and would not fit embedded.
    pub spo_bans_ref: (String, u32),
    pub mainnet: bool,
    /// Ban-start time (POSIX ms) = the resolved upper bound of the validity
    /// interval the validator derives (`ban_start_time`). Drives the output
    /// `BanNodeData`; the caller must set it to `slot_to_posix(invalid_hereafter)`.
    pub start_time_ms: i64,
    /// Validity interval (slots). Must be finite and `<= max_validity_window_ms`
    /// wide once converted to POSIX time (the validator enforces the width).
    pub invalid_before: u64,
    pub invalid_hereafter: u64,
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    pub key: &'a PrivateKey,
    pub cost_models: Option<Vec<Vec<i64>>>,
}

/// A built (signed, unsubmitted) ApplyBan tx + what the operator records.
#[derive(Debug, Clone)]
pub struct ApplyBanTx {
    pub signed_tx_hex: String,
    /// Whether this was a first ban (new node minted) or a reban (in-place).
    pub first_ban: bool,
    /// The new/updated `BanNodeData` written on-chain.
    pub ban_node: BanNodeData,
    /// `"ban/" || accused_pool_id` — the ban node NFT asset name.
    pub ban_node_asset_name: Vec<u8>,
    /// The FaultProof token burned (`blake2b_256(pool_id || evidence_hash)`).
    pub burned_fault_token: [u8; 32],
}

fn tx_id_bytes(tx_hash: &str) -> Result<[u8; 32], ApplyBanError> {
    hex::decode(tx_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApplyBanError::Build(format!("bad tx hash: {tx_hash}")))
}

/// Pick the fee input (richest clean wallet UTxO) and a DISTINCT pure-ADA
/// collateral. Both skip token-bearing / ref-script UTxOs.
fn select_fee_and_collateral(
    wallet_utxos: &[WalletUtxo],
    min_fee_lovelace: u64,
) -> Result<(&WalletUtxo, &WalletUtxo), ApplyBanError> {
    let fee = select_fee(wallet_utxos, min_fee_lovelace).map_err(ApplyBanError::Wallet)?;
    let coll = select_collateral(wallet_utxos, &[fee]).map_err(ApplyBanError::Wallet)?;
    Ok((fee, coll))
}

fn sign_built_tx(unsigned_hex: &str, key: &PrivateKey) -> Result<String, ApplyBanError> {
    common_sign_built_tx(unsigned_hex, key).map_err(ApplyBanError::Build)
}

// ---------------------------------------------------------------------------
// Ban-list bootstrap (the "ban-root" anchor mint) — WI-015
// ---------------------------------------------------------------------------

/// A built (signed, unsubmitted) ban-list bootstrap tx.
#[derive(Debug, Clone)]
pub struct BanBootstrapTx {
    pub signed_tx_hex: String,
    /// `spo_bans` script hash = the ban-list policy id.
    pub policy_id_hex: String,
    /// Enterprise script address holding the ban-list elements.
    pub script_address: String,
}

/// Build + sign the ban-list bootstrap: spend the one-shot outref that
/// parameterizes `spo_bans` (it MUST be among `wallet_utxos`) and mint the
/// `"ban-root"` anchor NFT to the ban script address with the
/// `Element{Root(BanListRootData), link: None}` inline datum. This is the
/// precondition for any `apply-ban` (the linked list must be initialized).
///
/// Mirrors [`crate::cardano::register_spo::build_registry_bootstrap_tx`]; the one
/// material difference is the mint redeemer. `spo_bans`'s `Bootstrap { input_ref }`
/// carries the one-shot `OutputReference`, and the validator asserts both that
/// the input is spent and that `input_ref == OutputReference(bootstrap_tx_id,
/// bootstrap_output_index)` — the exact outpoint baked into the policy params.
/// The registry's `Bootstrap` is field-less by contrast.
///
/// `one_shot_ref_script_size`: byte size of a reference script on the one-shot
/// UTxO, if any. The outref cannot be swapped (it parameterizes the policy), so
/// the ledger's per-byte ref-script fee is added explicitly on a second build
/// pass (whisky's estimate cannot see it).
#[allow(clippy::too_many_arguments)]
pub fn build_ban_bootstrap_tx(
    spo_bans_script: &ParameterizedScript,
    bootstrap_tx_hash: &str,
    bootstrap_output_index: u32,
    wallet_address: &str,
    wallet_utxos: &[WalletUtxo],
    key: &PrivateKey,
    one_shot_ref_script_size: Option<u64>,
    cost_models: Option<Vec<Vec<i64>>>,
) -> Result<BanBootstrapTx, ApplyBanError> {
    let root_element = BanElement {
        data: BanElementData::Root,
        link: None,
    };
    // `Bootstrap { input_ref }` = Constr(0, [OutputReference(one-shot)]); the
    // outref must equal the one baked into the policy params (and be spent). The
    // registry's `Bootstrap` is field-less by contrast — the one material
    // difference between the two one-shot bootstraps.
    let bootstrap_tx_id = tx_id_bytes(bootstrap_tx_hash)?;
    let mint_redeemer_cbor = hex::encode(
        minicbor::to_vec(constr(
            0,
            vec![output_reference(&bootstrap_tx_id, bootstrap_output_index)],
        ))
        .expect("redeemer CBOR encode"),
    );

    let built = build_oneshot_bootstrap_tx(OneShotBootstrapParams {
        policy_script: spo_bans_script,
        bootstrap_tx_hash,
        bootstrap_output_index,
        wallet_address,
        wallet_utxos,
        key,
        one_shot_ref_script_size,
        cost_models,
        root_datum_cbor: root_element.to_cbor(),
        root_asset_name: BAN_ROOT_KEY,
        mint_redeemer_cbor,
        outref_label: "ban",
    })?;

    Ok(BanBootstrapTx {
        signed_tx_hex: built.signed_tx_hex,
        policy_id_hex: built.policy_id_hex,
        script_address: built.script_address,
    })
}

/// `spo_bans` as a reference-script source (used by the withdraw, the anchor
/// spend, and the node mint — one deployed script, referenced 3×).
fn spo_bans_ref_source(req: &ApplyBanRequest) -> ScriptSource {
    ScriptSource::InlineScriptSource(InlineScriptSource {
        ref_tx_in: RefTxIn {
            tx_hash: req.spo_bans_ref.0.clone(),
            tx_index: req.spo_bans_ref.1,
            script_size: Some(req.spo_bans_script.cbor.len()),
        },
        script_hash: req.spo_bans_script.hash_hex(),
        language_version: LanguageVersion::V3,
        script_size: req.spo_bans_script.cbor.len(),
    })
}

/// Build + sign the `spo_bans.ApplyBan` tx: a zero-amount withdrawal authorizes
/// the action; it spends + burns the FaultProof, references the accused pool's
/// registry node, and writes the ban node (mint + linked-list insert on a first
/// ban, in-place update on a reban).
pub fn build_apply_ban_tx(req: &ApplyBanRequest) -> Result<ApplyBanTx, ApplyBanError> {
    let ban_policy_hex = req.spo_bans_script.hash_hex();
    let fault_policy_hex = req.fault_verifier_script.hash_hex();
    let token_name = fault_token_name(&req.accused_pool_id, &req.evidence_hash);

    let network = if req.mainnet {
        pallas_addresses::Network::Mainnet
    } else {
        pallas_addresses::Network::Testnet
    };
    let ban_address = req.spo_bans_script.enterprise_address(network);
    let reward_address = req.spo_bans_script.reward_address(req.mainnet);

    // Validated snapshot of the on-chain ban list.
    let ban_utxos = find_ban_utxos(req.ban_utxos, &ban_policy_hex)?;
    let list = BanList::from_elements(
        ban_utxos
            .iter()
            .map(|u| (u.asset_name.clone(), u.element.clone())),
    )?;

    let ban_node_asset_name = [BAN_NODE_KEY_PREFIX, &req.accused_pool_id].concat();
    let ban_node_unit = format!("{ban_policy_hex}{}", hex::encode(&ban_node_asset_name));

    // The single ApplyBan withdrawal sits at reward-redeemer index 0.
    let withdraw_redeemer_index = 0i64;

    // Decide first-ban vs reban from the validated list, and produce: the ban
    // element UTxO to SPEND, the OUTPUT element datums + lovelaces, the ban-NFT
    // mints, and the redeemer's output indices.
    let existing = list
        .node(&req.accused_pool_id)
        .map(|(d, l)| (d.clone(), l.map(<[u8]>::to_vec)));
    let (spend_utxo, outputs_data, ban_mints, ban_node_out, new_ban_node, is_first): (
        &BanUtxo,
        Vec<(Vec<u8>, u64)>, // (inline datum cbor, lovelace) per output, in order
        Vec<MintItem>,
        i64,
        BanNodeData,
        bool,
    ) = match existing {
        // ── reban: spend the existing node, reproduce it with updated data ──
        Some((old, _link)) => {
            if old.permanent {
                return Err(ApplyBanError::AlreadyPermanent);
            }
            if old.evidence_hashes.iter().any(|h| h == &req.evidence_hash) {
                return Err(ApplyBanError::EvidenceAlreadyApplied);
            }
            let node_utxo = ban_utxos
                .iter()
                .find(|u| u.asset_name == ban_node_asset_name)
                .ok_or_else(|| {
                    ApplyBanError::Build("existing ban node UTxO not found in snapshot".into())
                })?;
            let updated = old.repeated_ban(
                req.evidence_hash.to_vec(),
                req.start_time_ms,
                req.ban_params.base_ban_duration_ms,
                req.ban_params.max_faults_before_permanent,
            );
            // Continued node: SAME asset name + SAME link, only data changes.
            let continued = BanElement {
                data: BanElementData::Node(updated.clone()),
                link: node_utxo.element.link.clone(),
            };
            (
                node_utxo,
                vec![(continued.to_cbor(), node_utxo.lovelace)],
                vec![], // reban mints NO ban-policy token
                0,      // ban_node_output_index
                updated,
                false,
            )
        }
        // ── first ban: insert a new node + mint its NFT ──────────────────────
        None => {
            let new = BanNodeData::first_ban(
                req.evidence_hash.to_vec(),
                req.start_time_ms,
                req.ban_params.base_ban_duration_ms,
                req.ban_params.max_faults_before_permanent,
            );
            let plan = list.plan_insert(&req.accused_pool_id, new.clone())?;
            let anchor = ban_utxos
                .iter()
                .find(|u| u.asset_name == plan.anchor_asset_name)
                .ok_or_else(|| ApplyBanError::Build("anchor UTxO not found in snapshot".into()))?;
            let mint = MintItem::ScriptMint(ScriptMint {
                mint: MintParameter {
                    policy_id: ban_policy_hex.clone(),
                    asset_name: hex::encode(&ban_node_asset_name),
                    amount: 1,
                },
                redeemer: Some(Redeemer {
                    data: hex::encode(
                        minicbor::to_vec(mint_ban_node_redeemer(
                            withdraw_redeemer_index,
                            &req.accused_pool_id,
                        ))
                        .expect("redeemer CBOR"),
                    ),
                    ex_units: Budget {
                        mem: 1_500_000,
                        steps: 700_000_000,
                    },
                }),
                script_source: Some(spo_bans_ref_source(req)),
            });
            // Output[0] continued anchor (value unchanged), [1] new node.
            (
                anchor,
                vec![
                    (plan.continued_anchor.to_cbor(), anchor.lovelace),
                    (plan.new_node.to_cbor(), 0), // lovelace filled below
                ],
                vec![mint],
                1, // ban_node_output_index
                new,
                true,
            )
        }
    };

    // The fault token burn (BurnProof, -1) under the fault_verifier policy.
    let fault_unit = format!("{fault_policy_hex}{}", hex::encode(token_name));
    let fault_burn = MintItem::ScriptMint(ScriptMint {
        mint: MintParameter {
            policy_id: fault_policy_hex.clone(),
            asset_name: hex::encode(token_name),
            amount: -1,
        },
        redeemer: Some(Redeemer {
            data: hex::encode(minicbor::to_vec(burn_proof_redeemer()).expect("redeemer CBOR")),
            ex_units: Budget {
                mem: 1_000_000,
                steps: 500_000_000,
            },
        }),
        script_source: Some(ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
            script_cbor: req.fault_verifier_script.cbor_hex(),
            language_version: LanguageVersion::V3,
        })),
    });
    let mut mints = ban_mints;
    mints.push(fault_burn);

    // ── inputs: fee, FaultProof, ban element (spo_bans spend) ──────────────
    let proof_out_lovelace = element_lovelace(outputs_data.last().map_or(0, |(d, _)| d.len()));
    let min_fee = proof_out_lovelace + 2_000_000;
    let (fee_utxo, coll_utxo) = select_fee_and_collateral(req.wallet_utxos, min_fee)?;

    let fee_ref = (tx_id_bytes(&fee_utxo.tx_hash)?, fee_utxo.output_index);
    let fault_ref = (
        tx_id_bytes(&req.fault_utxo.tx_hash)?,
        req.fault_utxo.output_index,
    );
    let ban_ref = (tx_id_bytes(&spend_utxo.tx_hash)?, spend_utxo.output_index);
    if fee_ref == fault_ref || fee_ref == ban_ref || fault_ref == ban_ref {
        return Err(ApplyBanError::Build(
            "fee / fault / ban-element inputs must be distinct outpoints".into(),
        ));
    }
    let mut sorted = [fee_ref, fault_ref, ban_ref];
    sorted.sort();
    let idx_of = |r: &([u8; 32], u32)| sorted.iter().position(|x| x == r).unwrap() as i64;
    let fault_input_index = idx_of(&fault_ref);
    let ban_input_index = idx_of(&ban_ref);

    // reference inputs: the registry node (data) + the spo_bans ref script.
    // whisky appends the ref-script input(s); both get sorted by (tx_id,index)
    // in the body. registration_ref_input_index = the registry node's slot.
    let reg_ref = (
        tx_id_bytes(&req.registration_ref.0)?,
        req.registration_ref.1,
    );
    let spo_ref = (tx_id_bytes(&req.spo_bans_ref.0)?, req.spo_bans_ref.1);
    let mut ref_sorted = vec![reg_ref, spo_ref];
    ref_sorted.sort();
    ref_sorted.dedup();
    let registration_ref_input_index =
        ref_sorted.iter().position(|x| *x == reg_ref).unwrap() as i64;

    let existing_ban_input_index = if is_first {
        None
    } else {
        Some(ban_input_index)
    };
    let ban_anchor_input_index = if is_first { ban_input_index } else { 0 };
    let ban_anchor_output_index = if is_first { 0 } else { 0 };

    let apply_redeemer = apply_ban_redeemer(
        fault_input_index,
        registration_ref_input_index,
        &req.accused_pool_id,
        &req.evidence_hash,
        ban_anchor_input_index,
        ban_anchor_output_index,
        existing_ban_input_index,
        ban_node_out,
    );

    // ── assemble outputs (fill the new-node min-ADA) ───────────────────────
    let outputs: Vec<Output> = outputs_data
        .iter()
        .enumerate()
        .map(|(i, (datum, lovelace))| {
            // Output[i]: the ban element. The continued anchor/node keeps its
            // input lovelace (anchor_lovelace_change == 0); the NEW node carries
            // its own min-ADA + the freshly minted NFT.
            let new_node_output = is_first && i == 1;
            let lovelace = if new_node_output {
                element_lovelace(datum.len())
            } else {
                *lovelace
            };
            let mut amount = vec![Asset::new_from_str("lovelace", &lovelace.to_string())];
            // The continued anchor/node carries its existing NFT; the new node
            // carries the minted one.
            let unit = if new_node_output {
                ban_node_unit.clone()
            } else if is_first {
                // continued anchor: its own NFT (anchor asset name).
                format!("{ban_policy_hex}{}", hex::encode(&spend_utxo.asset_name))
            } else {
                // reban continued node: same NFT as the spent node.
                ban_node_unit.clone()
            };
            amount.push(Asset::new_from_str(&unit, "1"));
            Output {
                address: ban_address.clone(),
                amount,
                datum: Some(Datum::Inline(hex::encode(datum.clone()))),
                reference_script: None,
            }
        })
        .collect();

    // ── the ban-element spend leg (spo_bans spend, BanListAction) ──────────
    let spend_unit = format!("{ban_policy_hex}{}", hex::encode(&spend_utxo.asset_name));
    let spend_value = vec![
        Asset::new_from_str("lovelace", &spend_utxo.lovelace.to_string()),
        Asset::new_from_str(&spend_unit, "1"),
    ];
    let ban_spend_in = TxIn::ScriptTxIn(ScriptTxIn {
        tx_in: TxInParameter {
            tx_hash: spend_utxo.tx_hash.clone(),
            tx_index: spend_utxo.output_index,
            amount: Some(spend_value),
            address: Some(ban_address.clone()),
        },
        script_tx_in: ScriptTxInParameter {
            script_source: Some(spo_bans_ref_source(req)),
            datum_source: Some(DatumSource::InlineDatumSource(InlineDatumSource {
                tx_hash: spend_utxo.tx_hash.clone(),
                tx_index: spend_utxo.output_index,
            })),
            redeemer: Some(Redeemer {
                data: hex::encode(
                    minicbor::to_vec(ban_list_action_redeemer(withdraw_redeemer_index))
                        .expect("redeemer CBOR"),
                ),
                ex_units: Budget {
                    mem: 1_000_000,
                    steps: 500_000_000,
                },
            }),
        },
    });

    // ── the FaultProof input (wallet pubkey, carries the token) ────────────
    let fault_in = TxIn::PubKeyTxIn(PubKeyTxIn {
        tx_in: TxInParameter {
            tx_hash: req.fault_utxo.tx_hash.clone(),
            tx_index: req.fault_utxo.output_index,
            amount: Some(vec![
                Asset::new_from_str("lovelace", &req.fault_utxo.lovelace.to_string()),
                Asset::new_from_str(&fault_unit, "1"),
            ]),
            address: Some(req.wallet_address.to_string()),
        },
    });
    let fee_in = TxIn::PubKeyTxIn(PubKeyTxIn {
        tx_in: TxInParameter {
            tx_hash: fee_utxo.tx_hash.clone(),
            tx_index: fee_utxo.output_index,
            amount: Some(vec![Asset::new_from_str(
                "lovelace",
                &fee_utxo.lovelace.to_string(),
            )]),
            address: Some(req.wallet_address.to_string()),
        },
    });

    let withdrawal = Withdrawal::PlutusScriptWithdrawal(PlutusScriptWithdrawal {
        address: reward_address.clone(),
        coin: 0,
        script_source: Some(spo_bans_ref_source(req)),
        redeemer: Some(Redeemer {
            data: hex::encode(minicbor::to_vec(&apply_redeemer).expect("redeemer CBOR")),
            ex_units: Budget {
                mem: 8_000_000,
                steps: 4_000_000_000,
            },
        }),
    });

    let body = TxBuilderBody {
        inputs: vec![fee_in, fault_in, ban_spend_in],
        outputs,
        collaterals: vec![PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: coll_utxo.tx_hash.clone(),
                tx_index: coll_utxo.output_index,
                amount: Some(vec![Asset::new_from_str(
                    "lovelace",
                    &coll_utxo.lovelace.to_string(),
                )]),
                address: Some(req.wallet_address.to_string()),
            },
        }],
        required_signatures: vec![pub_key_hash_hex(req.key)],
        change_address: req.wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(&req.cost_models)),
        reference_inputs: vec![RefTxIn {
            tx_hash: req.registration_ref.0.clone(),
            tx_index: req.registration_ref.1,
            script_size: None,
        }],
        withdrawals: vec![withdrawal],
        mints,
        certificates: vec![],
        votes: vec![],
        fee: None,
        change_datum: None,
        metadata: vec![],
        validity_range: ValidityRange {
            invalid_before: Some(req.invalid_before),
            invalid_hereafter: Some(req.invalid_hereafter),
        },
        total_collateral: None,
        collateral_return_address: None,
    };

    let mut pallas = WhiskyPallas::new(None);
    pallas.tx_builder_body = body;
    let unsigned_hex = pallas
        .serialize_tx_body()
        .map_err(|e| ApplyBanError::Build(format!("whisky tx build: {e:?}")))?;

    // Post-build: dedupe the ref inputs whisky pushes per InlineScriptSource use
    // (duplicate set elements are rejected; ref inputs sit outside the script-
    // integrity hash, so editing pre-signature is safe), then verify the
    // input/ref-input slots the redeemer points at match the built tx.
    let unsigned_hex = {
        let tx_bytes = hex::decode(&unsigned_hex)
            .map_err(|e| ApplyBanError::Build(format!("unsigned hex decode: {e}")))?;
        let mut tx: Tx = minicbor::decode(&tx_bytes)
            .map_err(|e| ApplyBanError::Build(format!("tx decode: {e}")))?;
        if let Some(refs) = tx.transaction_body.reference_inputs.take() {
            let mut v = refs.to_vec();
            v.sort_by_key(|i| (i.transaction_id, i.index));
            v.dedup();
            tx.transaction_body.reference_inputs = NonEmptySet::from_vec(v);
        }
        {
            let inputs: Vec<_> = tx.transaction_body.inputs.iter().collect();
            let at = |i: i64, want: &([u8; 32], u32), what: &str| -> Result<(), ApplyBanError> {
                let got = inputs.get(i as usize).ok_or_else(|| {
                    ApplyBanError::Build(format!("{what} input index {i} out of range"))
                })?;
                if got.transaction_id.as_slice() != want.0 || got.index != u64::from(want.1) {
                    return Err(ApplyBanError::Build(format!(
                        "{what} not at redeemer index {i} — input ordering changed"
                    )));
                }
                Ok(())
            };
            at(fault_input_index, &fault_ref, "fault")?;
            at(ban_input_index, &ban_ref, "ban-element")?;
            let refs: Vec<_> = tx
                .transaction_body
                .reference_inputs
                .as_ref()
                .map(|s| s.iter().collect())
                .unwrap_or_default();
            let got = refs
                .get(registration_ref_input_index as usize)
                .ok_or_else(|| {
                    ApplyBanError::Build("registration ref input index out of range".into())
                })?;
            if got.transaction_id.as_slice() != reg_ref.0 || got.index != u64::from(reg_ref.1) {
                return Err(ApplyBanError::Build(
                    "registry node not at redeemer ref index — ref ordering changed".into(),
                ));
            }
        }
        hex::encode(
            minicbor::to_vec(&tx).map_err(|e| ApplyBanError::Build(format!("re-encode: {e}")))?,
        )
    };

    let signed_tx_hex = sign_built_tx(&unsigned_hex, req.key)?;
    Ok(ApplyBanTx {
        signed_tx_hex,
        first_ban: is_first,
        ban_node: new_ban_node,
        ban_node_asset_name,
        burned_fault_token: token_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::ban_list::BAN_ROOT_KEY;
    use crate::cardano::bf_http::BfAmount;
    use crate::cardano::plutus::{self, as_constr};
    use crate::cardano::wallet::{derive_payment_key, wallet_address};
    use pallas_codec::minicbor;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn apply_ban_redeemer_shape() {
        // first ban: existing_ban_input_index = None.
        let pool = [0x11u8; 28];
        let ev = [0x22u8; 32];
        let r = apply_ban_redeemer(1, 0, &pool, &ev, 2, 0, None, 1);
        let f = plutus::constr_fields(&r, 0).unwrap();
        assert_eq!(f.len(), 8);
        assert_eq!(plutus::field_int(f, 0).unwrap(), 1); // fault_input_index
        assert_eq!(plutus::field_int(f, 1).unwrap(), 0); // registration_ref_input_index
        assert_eq!(plutus::field_bytes(f, 2).unwrap(), pool);
        assert_eq!(plutus::field_bytes(f, 3).unwrap(), ev);
        assert_eq!(plutus::field_int(f, 4).unwrap(), 2); // ban_anchor_input_index
        assert_eq!(plutus::field_int(f, 5).unwrap(), 0); // ban_anchor_output_index
        // existing_ban_input_index = None = Constr(1, []).
        let (oc, of) = as_constr(&f[6]).unwrap();
        assert_eq!((oc, of.len()), (1, 0));
        assert_eq!(plutus::field_int(f, 7).unwrap(), 1); // ban_node_output_index

        // reban: existing_ban_input_index = Some(3) = Constr(0, [3]).
        let r2 = apply_ban_redeemer(1, 0, &pool, &ev, 0, 0, Some(3), 2);
        let f2 = plutus::constr_fields(&r2, 0).unwrap();
        let (sc, sf) = as_constr(&f2[6]).unwrap();
        assert_eq!(sc, 0);
        assert_eq!(plutus::field_int(sf, 0).unwrap(), 3);
    }

    #[test]
    fn mint_and_spend_redeemer_shapes() {
        // MintBanNode = Constr(1, [idx, pool_id]).
        let pool = [0xAAu8; 28];
        let m = mint_ban_node_redeemer(0, &pool);
        let mf = plutus::constr_fields(&m, 1).unwrap();
        assert_eq!(mf.len(), 2);
        assert_eq!(plutus::field_int(mf, 0).unwrap(), 0);
        assert_eq!(plutus::field_bytes(mf, 1).unwrap(), pool);

        // BanListAction = Constr(0, [idx]).
        let s = ban_list_action_redeemer(0);
        let sf = plutus::constr_fields(&s, 0).unwrap();
        assert_eq!(sf.len(), 1);
        assert_eq!(plutus::field_int(sf, 0).unwrap(), 0);

        // Both round-trip through canonical CBOR.
        for pd in [m, s] {
            let cbor = minicbor::to_vec(&pd).unwrap();
            let back: PlutusData = minicbor::decode(&cbor).unwrap();
            assert_eq!(back, pd);
        }
    }

    // ---- ApplyBan tx builder -----------------------------------------------

    fn spo_bans_script() -> ParameterizedScript {
        // Real spo_bans program bytes (for realistic ref-script size); the hash
        // is a fixed stand-in policy id — internally consistent for an offline
        // structural build (no submission).
        let cbor =
            hex::decode(include_str!("../../tests/fixtures/spo_bans_code.txt").trim()).unwrap();
        ParameterizedScript {
            cbor,
            hash: [0xBA; 28],
        }
    }

    fn fault_verifier_script() -> ParameterizedScript {
        let cbor = hex::decode(include_str!("../../tests/fixtures/fault_verifier_code.txt").trim())
            .unwrap();
        ParameterizedScript {
            cbor,
            hash: [0xFA; 28],
        }
    }

    fn ban_params() -> BanPolicyParams {
        BanPolicyParams {
            fault_proof_policies: vec![[0xFA; 28], [0x01; 28], [0x02; 28]],
            base_ban_duration_ms: 86_400_000,
            max_faults_before_permanent: 3,
            max_validity_window_ms: 600_000,
        }
    }

    fn wallet() -> Vec<WalletUtxo> {
        vec![
            WalletUtxo {
                tx_hash: "aa".repeat(32),
                output_index: 0,
                lovelace: 50_000_000,
                pure_ada: true,
            },
            WalletUtxo {
                tx_hash: "bb".repeat(32),
                output_index: 1,
                lovelace: 6_000_000,
                pure_ada: true,
            },
        ]
    }

    /// A ban-list element UTxO carrying `policy_hex.asset_name` + the datum.
    fn ban_bfutxo(policy_hex: &str, tx: &str, asset_name: &[u8], elem: &BanElement) -> BfUtxo {
        BfUtxo {
            tx_hash: tx.to_string(),
            output_index: 0,
            amount: vec![
                BfAmount {
                    unit: "lovelace".into(),
                    quantity: "2000000".into(),
                },
                BfAmount {
                    unit: format!("{policy_hex}{}", hex::encode(asset_name)),
                    quantity: "1".into(),
                },
            ],
            inline_datum: Some(hex::encode(elem.to_cbor())),
            reference_script_hash: None,
        }
    }

    fn node_elem(data: BanNodeData, link: Option<&[u8]>) -> BanElement {
        BanElement {
            data: BanElementData::Node(data),
            link: link.map(<[u8]>::to_vec),
        }
    }

    fn root_elem(link: Option<&[u8]>) -> BanElement {
        BanElement {
            data: BanElementData::Root,
            link: link.map(<[u8]>::to_vec),
        }
    }

    /// (policy_hex, asset_name_hex, amount) for every mint in the tx.
    fn mints(tx: &Tx) -> Vec<(String, String, i64)> {
        let mut out = vec![];
        if let Some(m) = tx.transaction_body.mint.as_ref() {
            for p in m.iter() {
                for a in p.1.iter() {
                    out.push((
                        hex::encode(p.0.as_slice()),
                        hex::encode(a.0.as_slice()),
                        i64::from(a.1),
                    ));
                }
            }
        }
        out
    }

    fn decode_ban_output(tx: &Tx, i: usize) -> BanElement {
        use pallas_primitives::conway::{DatumOption, PseudoTransactionOutput};
        let PseudoTransactionOutput::PostAlonzo(out) = &tx.transaction_body.outputs[i] else {
            panic!("post-alonzo output");
        };
        let Some(DatumOption::Data(d)) = &out.datum_option else {
            panic!("inline datum on output {i}");
        };
        BanElement::from_plutus_data(&d.0).unwrap()
    }

    fn request<'a>(
        spo_bans: &'a ParameterizedScript,
        fault: &'a ParameterizedScript,
        params: &'a BanPolicyParams,
        ban_utxos: &'a [BfUtxo],
        fault_utxo: &'a FaultProofUtxo,
        wallet_utxos: &'a [WalletUtxo],
        key: &'a PrivateKey,
        addr: &'a str,
        pool: [u8; 28],
        evidence: [u8; 32],
    ) -> ApplyBanRequest<'a> {
        ApplyBanRequest {
            spo_bans_script: spo_bans,
            fault_verifier_script: fault,
            ban_params: params,
            accused_pool_id: pool,
            evidence_hash: evidence,
            ban_utxos,
            fault_utxo,
            registration_ref: ("dd".repeat(32), 0),
            spo_bans_ref: ("ee".repeat(32), 1),
            mainnet: false,
            start_time_ms: 1_700_000_000_000,
            invalid_before: 100,
            invalid_hereafter: 200,
            wallet_address: addr,
            wallet_utxos,
            key,
            cost_models: None,
        }
    }

    #[test]
    fn ban_bootstrap_end_to_end() {
        use pallas_primitives::conway::{RedeemerTag, Redeemers};

        let bans = spo_bans_script();
        let policy_hex = bans.hash_hex();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        // The one-shot that parameterizes spo_bans must be an unspent wallet UTxO.
        let one_shot_tx = "aa".repeat(32);
        let w = wallet(); // aa..#0 (50 ADA) + bb..#1 (6 ADA)

        let built = build_ban_bootstrap_tx(&bans, &one_shot_tx, 0, &addr, &w, &key, None, None)
            .expect("build ban bootstrap");
        assert_eq!(built.policy_id_hex, policy_hex);

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();

        // Mints exactly one "ban-root" NFT under the ban policy, nothing else.
        assert_eq!(
            mints(&tx),
            vec![(policy_hex.clone(), hex::encode(BAN_ROOT_KEY), 1)],
            "expected a single ban-root mint"
        );

        // The one-shot outpoint is among the spent inputs (the validator both
        // requires it spent and pins input_ref to it).
        assert!(
            tx.transaction_body
                .inputs
                .iter()
                .any(|i| hex::encode(i.transaction_id.as_slice()) == one_shot_tx && i.index == 0),
            "one-shot input must be spent"
        );

        // Collateral must be pure-ADA AND disjoint from the spent inputs: here
        // the one-shot (aa..#0) is the sole input, so collateral must be the
        // OTHER UTxO (bb..#1), never the one-shot. (A UTxO that is both a spent
        // input and collateral is rejected by the ledger at phase 1.)
        let collateral = tx
            .transaction_body
            .collateral
            .as_ref()
            .expect("collateral present");
        for c in collateral.iter() {
            let c_op = (hex::encode(c.transaction_id.as_slice()), c.index);
            assert!(
                !tx.transaction_body
                    .inputs
                    .iter()
                    .any(|i| (hex::encode(i.transaction_id.as_slice()), i.index) == c_op),
                "collateral {c_op:?} must not also be a spending input"
            );
        }
        assert!(
            collateral.iter().any(
                |c| hex::encode(c.transaction_id.as_slice()) == "bb".repeat(32) && c.index == 1
            ),
            "collateral must be the non-one-shot UTxO (bb..#1)"
        );

        // Output[0]: the Root anchor with no link — an initialized empty list.
        let root = decode_ban_output(&tx, 0);
        assert_eq!(root.data, BanElementData::Root);
        assert!(root.link.is_none());

        // The mint redeemer is Bootstrap = Constr(0, [OutputReference(one_shot, 0)]),
        // and the OutputReference must equal the spent one-shot (≡ the policy param).
        let redeemers = tx.transaction_witness_set.redeemer.as_ref().unwrap();
        let mint_rdmr = match redeemers {
            Redeemers::List(rs) => rs
                .iter()
                .find(|r| matches!(r.tag, RedeemerTag::Mint))
                .expect("mint redeemer")
                .data
                .clone(),
            Redeemers::Map(kv) => kv
                .iter()
                .find(|(k, _)| matches!(k.tag, RedeemerTag::Mint))
                .expect("mint redeemer")
                .1
                .data
                .clone(),
        };
        let f = plutus::constr_fields(&mint_rdmr, 0).unwrap();
        assert_eq!(
            f.len(),
            1,
            "Bootstrap carries one field (the OutputReference)"
        );
        let or = plutus::constr_fields(&f[0], 0).unwrap();
        assert_eq!(
            hex::encode(plutus::field_bytes(or, 0).unwrap()),
            one_shot_tx
        );
        assert_eq!(plutus::field_int(or, 1).unwrap(), 0);

        // Signed by the wallet key.
        let pk: [u8; 32] = key.public_key().into();
        assert!(
            tx.transaction_witness_set
                .vkeywitness
                .as_ref()
                .unwrap()
                .iter()
                .any(|v| v.vkey.as_slice() == pk)
        );
    }

    #[test]
    fn first_ban_end_to_end() {
        let bans = spo_bans_script();
        let fault = fault_verifier_script();
        let params = ban_params();
        let policy_hex = bans.hash_hex();
        let pool = [0x55u8; 28];
        let evidence = [0x66u8; 32];
        // Bootstrapped, empty list: just the root.
        let ban_utxos = vec![ban_bfutxo(
            &policy_hex,
            &"11".repeat(32),
            BAN_ROOT_KEY,
            &root_elem(None),
        )];
        let fault_utxo = FaultProofUtxo {
            tx_hash: "cc".repeat(32),
            output_index: 0,
            lovelace: 2_000_000,
        };
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        let w = wallet();
        let req = request(
            &bans,
            &fault,
            &params,
            &ban_utxos,
            &fault_utxo,
            &w,
            &key,
            &addr,
            pool,
            evidence,
        );
        let built = build_apply_ban_tx(&req).expect("build first ban");

        assert!(built.first_ban);
        assert_eq!(built.burned_fault_token, fault_token_name(&pool, &evidence));
        assert_eq!(
            built.ban_node_asset_name,
            [BAN_NODE_KEY_PREFIX, &pool].concat()
        );
        assert_eq!(built.ban_node.ban_counter, 1);

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        // Mint: ban node +1 (ban policy) AND fault token -1 (fault policy).
        let m = mints(&tx);
        let ban_name = hex::encode([BAN_NODE_KEY_PREFIX, &pool].concat());
        let fault_name = hex::encode(fault_token_name(&pool, &evidence));
        assert!(
            m.contains(&("ba".repeat(28), ban_name, 1)),
            "ban node mint missing: {m:?}"
        );
        assert!(
            m.contains(&("fa".repeat(28), fault_name, -1)),
            "fault burn missing: {m:?}"
        );
        // Exactly one withdrawal (the ApplyBan reward withdrawal).
        assert_eq!(
            tx.transaction_body
                .withdrawals
                .as_ref()
                .map_or(0, |w| w.len()),
            1
        );
        // Output[0] continued root (link → pool), output[1] new node (counter 1).
        assert_eq!(
            decode_ban_output(&tx, 0).link.as_deref(),
            Some(pool.as_slice())
        );
        assert_eq!(
            decode_ban_output(&tx, 1).data,
            BanElementData::Node(built.ban_node.clone())
        );
        // Signed by the wallet key.
        let pk: [u8; 32] = key.public_key().into();
        assert!(
            tx.transaction_witness_set
                .vkeywitness
                .as_ref()
                .unwrap()
                .iter()
                .any(|v| v.vkey.as_slice() == pk)
        );
    }

    #[test]
    fn reban_end_to_end() {
        let bans = spo_bans_script();
        let fault = fault_verifier_script();
        let params = ban_params();
        let policy_hex = bans.hash_hex();
        let pool = [0x55u8; 28];
        let evidence = [0x66u8; 32];
        // List: root -> pool (counter 1, one prior evidence).
        let existing = BanNodeData {
            ban_counter: 1,
            ban_until_time: 1_700_000_500_000,
            permanent: false,
            evidence_hashes: vec![vec![0x99; 32]],
        };
        let ban_utxos = vec![
            ban_bfutxo(
                &policy_hex,
                &"11".repeat(32),
                BAN_ROOT_KEY,
                &root_elem(Some(&pool)),
            ),
            ban_bfutxo(
                &policy_hex,
                &"22".repeat(32),
                &[BAN_NODE_KEY_PREFIX, &pool].concat(),
                &node_elem(existing, None),
            ),
        ];
        let fault_utxo = FaultProofUtxo {
            tx_hash: "cc".repeat(32),
            output_index: 0,
            lovelace: 2_000_000,
        };
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        let w = wallet();
        let req = request(
            &bans,
            &fault,
            &params,
            &ban_utxos,
            &fault_utxo,
            &w,
            &key,
            &addr,
            pool,
            evidence,
        );
        let built = build_apply_ban_tx(&req).expect("build reban");

        assert!(!built.first_ban);
        assert_eq!(built.ban_node.ban_counter, 2);
        // New evidence prepended; len == counter.
        assert_eq!(built.ban_node.evidence_hashes.len(), 2);
        assert_eq!(built.ban_node.evidence_hashes[0], evidence);

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        // Reban mints NO ban-policy token — only the fault burn (-1).
        let m = mints(&tx);
        assert_eq!(m.len(), 1, "reban should mint only the fault burn: {m:?}");
        assert_eq!(m[0].0, "fa".repeat(28));
        assert_eq!(m[0].2, -1);
        // Output[0] = continued node with the updated data, same asset name.
        assert_eq!(
            decode_ban_output(&tx, 0).data,
            BanElementData::Node(built.ban_node.clone())
        );
    }

    #[test]
    fn reban_rejects_permanent_and_repeat_evidence() {
        let bans = spo_bans_script();
        let fault = fault_verifier_script();
        let params = ban_params();
        let policy_hex = bans.hash_hex();
        let pool = [0x55u8; 28];
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        let w = wallet();
        let fault_utxo = FaultProofUtxo {
            tx_hash: "cc".repeat(32),
            output_index: 0,
            lovelace: 2_000_000,
        };
        let node = |permanent: bool, ev: Vec<Vec<u8>>| {
            vec![
                ban_bfutxo(
                    &policy_hex,
                    &"11".repeat(32),
                    BAN_ROOT_KEY,
                    &root_elem(Some(&pool)),
                ),
                ban_bfutxo(
                    &policy_hex,
                    &"22".repeat(32),
                    &[BAN_NODE_KEY_PREFIX, &pool].concat(),
                    &node_elem(
                        BanNodeData {
                            ban_counter: ev.len() as i64,
                            ban_until_time: 1_700_000_500_000,
                            permanent,
                            evidence_hashes: ev,
                        },
                        None,
                    ),
                ),
            ]
        };

        // Already permanent → AlreadyPermanent.
        let utxos = node(true, vec![vec![0x99; 32]]);
        let req = request(
            &bans,
            &fault,
            &params,
            &utxos,
            &fault_utxo,
            &w,
            &key,
            &addr,
            pool,
            [0x66; 32],
        );
        assert!(matches!(
            build_apply_ban_tx(&req),
            Err(ApplyBanError::AlreadyPermanent)
        ));

        // Evidence already applied → EvidenceAlreadyApplied.
        let utxos = node(false, vec![vec![0x66; 32]]);
        let req = request(
            &bans,
            &fault,
            &params,
            &utxos,
            &fault_utxo,
            &w,
            &key,
            &addr,
            pool,
            [0x66; 32],
        );
        assert!(matches!(
            build_apply_ban_tx(&req),
            Err(ApplyBanError::EvidenceAlreadyApplied)
        ));
    }
}
