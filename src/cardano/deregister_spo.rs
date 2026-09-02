//! deregister_spo: build the `spos_registry.Deregister` Cardano transaction.
//!
//! The exit half of [`crate::cardano::register_spo`], and the only way an SPO
//! leaves the registry under its own control (the other way out is a roster
//! ban, which is `apply_ban`'s business). In ONE transaction it must:
//!
//! 1. spend the registration node UTxO being removed and its linked-list
//!    **anchor** — the predecessor element that links to it, found off-chain
//!    by [`RegistryList::plan_remove`] — both with
//!    `SposRegistrySpendRedeemer::RegistrationListAction`,
//! 2. spend the `treasury_info` state UTxO (via
//!    [`crate::cardano::treasury_spend::treasury_spend_leg`]),
//! 3. burn exactly 1 membership token under the registry policy with asset
//!    name `pool_id = blake2b_224(cold_vkey)` and the
//!    `SposRegistryMintRedeemer::Deregister` redeemer,
//! 4. output the continued anchor (data + lovelace unchanged, link → whatever
//!    the removed node pointed at) and the continued treasury state (only
//!    `bifrost_identity_root` advanced by the MPF delete of
//!    `bifrost_id_pk → pool_id`).
//!
//! The `Deregister` redeemer carries ONE signature: the cold Ed25519 signature
//! over the revocation message `"bifrost-revoke" || pool_id` (spec [DRG-2]).
//! The bifrost identity key does not sign its own removal — the cold key is
//! the registration authority, and asking the operational key to consent would
//! mean an SPO that lost it could never leave. It is verified locally before
//! any tx is built, which also covers the air-gapped flow where the signature
//! arrives from the machine that holds the cold key.
//!
//! Two things this transaction does NOT do, both of which the caller has to
//! say out loud:
//!
//! - It does not retract a roster already frozen for the current epoch. The
//!   operator still owes that epoch's DKG and signing duties; leaving the node
//!   switched off before the boundary is a fault, not an exit.
//! - It does not choose who gets the deposit. The removed element's lovelace
//!   is freed into the transaction's change, so it lands wherever the fee was
//!   paid from — this builder's `wallet_address`.
//!
//! The redeemer's input indices refer to positions in the tx's input list,
//! which the ledger (and whisky) orders lexicographically by `(tx_id, index)`
//! — [`build_deregister_spo_tx`] computes them from that order and re-checks
//! against the built tx. Output indices are ours to choose: `[0]` continued
//! anchor, `[1]` continued treasury, `[2]` wallet change.

use pallas_codec::minicbor;
use pallas_crypto::key::ed25519;
use pallas_primitives::PlutusData;
use pallas_primitives::conway::Tx;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::bf_http::BfUtxo;
use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::mpf;
use crate::cardano::plutus::{bytes, constr, int};
use crate::cardano::publish::WalletUtxo;
use crate::cardano::register_spo::{
    RegisterSpoError, find_registry_utxos, pool_id_from_cold_vkey,
    registration_list_action_redeemer,
};
use crate::cardano::registry::{RegistryError, RegistryList};
use crate::cardano::treasury_info::{
    TreasuryInfoError, apply_deregistration, proof_to_plutus_data, registry_update_redeemer,
};
use crate::cardano::treasury_spend::{TreasurySpendError, find_treasury_state, treasury_spend_leg};
use crate::cardano::tx_common::{
    network_from_address, select_collateral, select_fee, sign_built_tx as common_sign_built_tx,
    whisky_network,
};
use crate::cardano::wallet::pub_key_hash_hex;

/// `revocation_domain_separator` in `spos-registry.ak`.
pub const REVOCATION_DOMAIN_SEPARATOR: &[u8] = b"bifrost-revoke";

#[derive(Debug)]
pub enum DeregisterSpoError {
    Registry(RegistryError),
    TreasurySpend(TreasurySpendError),
    TreasuryInfo(TreasuryInfoError),
    /// A UTxO at the registry script address is not a well-formed element —
    /// raised by the shared [`find_registry_utxos`] scan.
    Element(RegisterSpoError),
    /// The cold Ed25519 signature does not verify over the revocation
    /// message — the on-chain `verify_ed25519_signature` would reject it.
    ColdSignatureInvalid,
    Wallet(String),
    Build(String),
}

impl std::fmt::Display for DeregisterSpoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry(e) => write!(f, "registry: {e}"),
            Self::TreasurySpend(e) => write!(f, "treasury spend: {e}"),
            Self::TreasuryInfo(e) => write!(f, "treasury info: {e}"),
            Self::Element(e) => write!(f, "{e}"),
            Self::ColdSignatureInvalid => write!(
                f,
                "cold Ed25519 signature does not verify over the revocation message"
            ),
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "tx build: {e}"),
        }
    }
}

impl std::error::Error for DeregisterSpoError {}

impl From<RegistryError> for DeregisterSpoError {
    fn from(e: RegistryError) -> Self {
        Self::Registry(e)
    }
}
impl From<TreasurySpendError> for DeregisterSpoError {
    fn from(e: TreasurySpendError) -> Self {
        Self::TreasurySpend(e)
    }
}
impl From<TreasuryInfoError> for DeregisterSpoError {
    fn from(e: TreasuryInfoError) -> Self {
        Self::TreasuryInfo(e)
    }
}
impl From<RegisterSpoError> for DeregisterSpoError {
    fn from(e: RegisterSpoError) -> Self {
        Self::Element(e)
    }
}

// ---------------------------------------------------------------------------
// Revocation message + signature
// ---------------------------------------------------------------------------

/// `revocation_message` in `spos-registry.ak`: `"bifrost-revoke" || pool_id`.
///
/// Note what it does NOT commit to: no epoch, no outpoint, no nonce. A
/// revocation signature is therefore replayable for the life of the pool key —
/// but the only thing it can be replayed against is a registration of that
/// same `pool_id`, i.e. re-exiting an SPO that re-registered. Treat it as a
/// standing authorization to leave, and keep it as private as the cold key.
#[must_use]
pub fn revocation_message(pool_id: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(REVOCATION_DOMAIN_SEPARATOR.len() + pool_id.len());
    m.extend_from_slice(REVOCATION_DOMAIN_SEPARATOR);
    m.extend_from_slice(pool_id);
    m
}

/// The revocation signature plus the cold verification key it binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationSignature {
    pub cold_vkey: [u8; 32],
    /// Ed25519 over the raw revocation message.
    pub cold_sig: [u8; 64],
}

/// Produce the revocation signature locally (non-air-gapped flow).
#[must_use]
pub fn sign_revocation(cold_skey: &ed25519::SecretKey) -> RevocationSignature {
    let cold_vkey: [u8; 32] = cold_skey.public_key().into();
    let pool_id = pool_id_from_cold_vkey(&cold_vkey);
    let cold_sig: [u8; 64] = cold_skey
        .sign(revocation_message(&pool_id))
        .as_ref()
        .try_into()
        .expect("ed25519 signature is 64 bytes");
    RevocationSignature {
        cold_vkey,
        cold_sig,
    }
}

/// Verify the revocation signature exactly as `spos-registry.ak` will,
/// returning the `pool_id` it authorizes. Catches a wrong key or a mis-copied
/// air-gapped signature before any fee is spent.
pub fn verify_revocation(sig: &RevocationSignature) -> Result<[u8; 28], DeregisterSpoError> {
    let pool_id = pool_id_from_cold_vkey(&sig.cold_vkey);
    let vkey = ed25519::PublicKey::from(sig.cold_vkey);
    if !vkey.verify(
        revocation_message(&pool_id),
        &ed25519::Signature::from(sig.cold_sig),
    ) {
        return Err(DeregisterSpoError::ColdSignatureInvalid);
    }
    Ok(pool_id)
}

// ---------------------------------------------------------------------------
// Redeemer
// ---------------------------------------------------------------------------

/// `SposRegistryMintRedeemer::Deregister` — constructor 2, field order pinned
/// by `bifrost/types/spos-registry.ak`:
/// `{cold_vkey, cold_sig, registration_input_index,
/// registration_anchor_input_index, registration_anchor_output_index,
/// treasury_input_index, treasury_output_index,
/// bifrost_identity_removal_proof}`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn deregister_mint_redeemer(
    sig: &RevocationSignature,
    registration_input_index: i64,
    anchor_input_index: i64,
    anchor_output_index: i64,
    treasury_input_index: i64,
    treasury_output_index: i64,
    removal_proof: &mpf::Proof,
) -> PlutusData {
    constr(
        2,
        vec![
            bytes(&sig.cold_vkey),
            bytes(&sig.cold_sig),
            int(registration_input_index),
            int(anchor_input_index),
            int(anchor_output_index),
            int(treasury_input_index),
            int(treasury_output_index),
            proof_to_plutus_data(removal_proof),
        ],
    )
}

// ---------------------------------------------------------------------------
// deregister_spo tx builder
// ---------------------------------------------------------------------------

/// Everything [`build_deregister_spo_tx`] needs. UTxO sets are caller-fetched
/// so the builder stays pure/testable; `wallet_utxos` pays fees + collateral
/// and receives both the change and the freed element deposit.
pub struct DeregisterSpoRequest<'a> {
    pub registry_script: &'a ParameterizedScript,
    pub treasury_script: &'a ParameterizedScript,
    /// Treasury NFT asset name (hex), fixed at K1.
    pub treasury_asset_name_hex: &'a str,
    /// UTxOs at the registry script address.
    pub registry_utxos: &'a [BfUtxo],
    /// UTxOs at the treasury script address.
    pub treasury_utxos: &'a [BfUtxo],
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    /// Wallet payment key (fees/collateral) — NOT the cold key.
    pub key: &'a PrivateKey,
    pub sig: &'a RevocationSignature,
    /// Slot window, if the caller wants one. Unlike registration this tx binds
    /// to no epoch snapshot — the spec leaves the validity interval
    /// unconstrained — so `None`/`None` is the normal case.
    pub invalid_before: Option<u64>,
    pub invalid_hereafter: Option<u64>,
    /// `(tx_hash, index)` of a UTxO carrying the registry script as a
    /// reference script. REQUIRED on a real network: the ~12 KB registry
    /// script is needed by two spends AND the burn, and embedding it would
    /// blow past the 16 KB tx-size limit. `None` embeds it (offline tests).
    pub registry_ref: Option<(String, u32)>,
    /// `(tx_hash, index)` of the Config UTxO — `treasury.ak`'s
    /// `RegistryUpdate` branch reads `spos_registry_policy_id` from it
    /// ([TSY-12], [TSY-13]), and [DRG-5] applies that unchanged to Deregister.
    pub config_ref: (String, u32),
    /// Live `[V1, V2, V3]` cost models; `None` → whisky's built-in Preprod.
    pub cost_models: Option<Vec<Vec<i64>>>,
}

/// A built (signed, unsubmitted) deregister_spo tx plus what the operator
/// needs to record.
#[derive(Debug, Clone)]
pub struct DeregisterSpoTx {
    pub signed_tx_hex: String,
    /// `blake2b_224(cold_vkey)` — burnt membership token name / removed key.
    pub pool_id: [u8; 28],
    /// The bifrost identity this registration bound, freed by the removal.
    pub bifrost_id_pk: Vec<u8>,
    /// The spent anchor element's NFT name (`"reg-root"` or a pool_id).
    pub anchor_asset_name: Vec<u8>,
    /// The continued treasury datum's `bifrost_identity_root`.
    pub new_bifrost_identity_root: mpf::Hash,
    /// Lovelace freed from the removed element's UTxO — it lands in the
    /// change output, i.e. at `wallet_address`.
    pub freed_lovelace: u64,
}

/// Decode `tx_hash` hex into the 32-byte id whisky sorts inputs by.
fn tx_id_bytes(tx_hash: &str) -> Result<[u8; 32], DeregisterSpoError> {
    hex::decode(tx_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| DeregisterSpoError::Build(format!("bad tx hash: {tx_hash}")))
}

/// Build + sign the deregister_spo tx. Verifies the revocation signature,
/// reconstructs the on-chain list and identity trie, plans the removal, and
/// composes the four legs (anchor spend, node spend, treasury spend, burn).
pub fn build_deregister_spo_tx(
    req: &DeregisterSpoRequest,
) -> Result<DeregisterSpoTx, DeregisterSpoError> {
    // Fail fast on anything the on-chain validator would reject.
    let pool_id = verify_revocation(req.sig)?;

    let registry_policy_hex = req.registry_script.hash_hex();
    let elements = find_registry_utxos(req.registry_utxos, &registry_policy_hex)?;
    let list = RegistryList::from_elements(
        elements
            .iter()
            .map(|u| (u.asset_name.clone(), u.element.clone())),
    )?;
    let plan = list.plan_remove(&pool_id)?;
    // The identity being freed comes from the chain, not the caller: the
    // validator reads it from the registration input's own datum, so a value
    // supplied here could only ever disagree.
    let bifrost_id_pk = list
        .get(&pool_id)
        .ok_or(RegistryError::NotRegistered)?
        .bifrost_id_pk
        .clone();

    let find = |name: &[u8]| {
        elements
            .iter()
            .find(|u| u.asset_name == name)
            .ok_or_else(|| {
                DeregisterSpoError::Build(format!(
                    "element {} vanished from the snapshot",
                    hex::encode(name)
                ))
            })
    };
    let anchor = find(&plan.anchor_asset_name)?;
    let node = find(&plan.removed_asset_name)?;

    // Treasury leg: rebuild the identity trie from the (pre-removal) list and
    // derive the post-deregistration datum + removal proof.
    let identity_trie =
        mpf::Trie::from_pairs(list.identity_pairs()).map_err(TreasuryInfoError::Mpf)?;
    let state = find_treasury_state(
        req.treasury_utxos,
        &req.treasury_script.hash_hex(),
        req.treasury_asset_name_hex,
    )?;
    let (new_treasury_datum, removal_proof) =
        apply_deregistration(&state.datum, &identity_trie, &bifrost_id_pk, &pool_id)?;

    let network = network_from_address(req.wallet_address);
    let registry_address = req.registry_script.enterprise_address(network);

    // Reference inputs, in the order the built tx will carry them. whisky adds
    // the registry reference script itself and the post-build fixup sorts the
    // set by (tx_id, index), so the Config's redeemer index must be computed
    // against that SAME sort — not assumed to be 0.
    let mut reference_inputs = vec![RefTxIn {
        tx_hash: req.config_ref.0.clone(),
        tx_index: req.config_ref.1,
        script_size: None,
    }];
    if let Some((ref_tx, ref_ix)) = &req.registry_ref {
        reference_inputs.push(RefTxIn {
            tx_hash: ref_tx.clone(),
            tx_index: *ref_ix,
            script_size: None,
        });
    }
    let config_ref_index = {
        let mut keys: Vec<(Vec<u8>, u32)> = reference_inputs
            .iter()
            .map(|r| (hex::decode(&r.tx_hash).unwrap_or_default(), r.tx_index))
            .collect();
        keys.sort();
        keys.dedup();
        let want = (
            hex::decode(&req.config_ref.0).unwrap_or_default(),
            req.config_ref.1,
        );
        u64::try_from(keys.iter().position(|k| *k == want).unwrap_or(0)).unwrap_or(0)
    };

    let (treasury_in, treasury_out) = treasury_spend_leg(
        &state,
        req.treasury_script,
        &new_treasury_datum,
        registry_update_redeemer(config_ref_index),
        network,
    );

    // No new element output here, so nothing but the fee has to be covered —
    // the removed node's own deposit comes back in the change. Two ADA rather
    // than one because this transaction runs three scripts (two spends and the
    // burn), and a floor under what they cost is cheaper than a balancing
    // failure the operator has to interpret.
    let (fee_utxo, coll_utxo) = {
        let fee = select_fee(req.wallet_utxos, 2_000_000).map_err(DeregisterSpoError::Wallet)?;
        let coll =
            select_collateral(req.wallet_utxos, &[fee]).map_err(DeregisterSpoError::Wallet)?;
        (fee, coll)
    };

    // The ledger orders tx inputs lexicographically by (tx_id, index); the
    // redeemer indices must point into that order.
    let fee_ref = (tx_id_bytes(&fee_utxo.tx_hash)?, fee_utxo.output_index);
    let anchor_ref = (tx_id_bytes(&anchor.tx_hash)?, anchor.output_index);
    let node_ref = (tx_id_bytes(&node.tx_hash)?, node.output_index);
    let treasury_ref = (tx_id_bytes(&state.tx_hash)?, state.output_index);
    let mut sorted = vec![fee_ref, anchor_ref, node_ref, treasury_ref];
    sorted.sort();
    let distinct = {
        let mut d = sorted.clone();
        d.dedup();
        d.len()
    };
    if distinct != sorted.len() {
        return Err(DeregisterSpoError::Build(
            "fee/anchor/node/treasury inputs must be distinct outpoints".into(),
        ));
    }
    let index_of = |r: &([u8; 32], u32)| sorted.iter().position(|s| s == r).unwrap() as i64;
    let anchor_input_index = index_of(&anchor_ref);
    let node_input_index = index_of(&node_ref);
    let treasury_input_index = index_of(&treasury_ref);
    // Outputs are ours to order: [0] continued anchor, [1] continued treasury
    // (whisky appends the change output after). There is no node output — that
    // element is what this transaction destroys.
    let (anchor_output_index, treasury_output_index) = (0i64, 1i64);

    // The registry script witness: referenced when a ref-script UTxO is given
    // (the ~12 KB script would not fit three times in one tx), embedded
    // otherwise.
    let registry_source = match &req.registry_ref {
        Some((tx_hash, index)) => ScriptSource::InlineScriptSource(InlineScriptSource {
            ref_tx_in: RefTxIn {
                tx_hash: tx_hash.clone(),
                tx_index: *index,
                script_size: Some(req.registry_script.cbor.len()),
            },
            script_hash: registry_policy_hex.clone(),
            language_version: LanguageVersion::V3,
            script_size: req.registry_script.cbor.len(),
        }),
        None => ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
            script_cbor: req.registry_script.cbor_hex(),
            language_version: LanguageVersion::V3,
        }),
    };

    let list_action_redeemer_hex = hex::encode(
        minicbor::to_vec(registration_list_action_redeemer()).expect("redeemer CBOR encode"),
    );
    let element_in = |u: &crate::cardano::register_spo::RegistryUtxo, value: Vec<Asset>| {
        TxIn::ScriptTxIn(ScriptTxIn {
            tx_in: TxInParameter {
                tx_hash: u.tx_hash.clone(),
                tx_index: u.output_index,
                amount: Some(value),
                address: Some(registry_address.clone()),
            },
            script_tx_in: ScriptTxInParameter {
                script_source: Some(registry_source.clone()),
                datum_source: Some(DatumSource::InlineDatumSource(InlineDatumSource {
                    tx_hash: u.tx_hash.clone(),
                    tx_index: u.output_index,
                })),
                redeemer: Some(Redeemer {
                    data: list_action_redeemer_hex.clone(),
                    // The spend branch only checks for a non-zero registry mint.
                    ex_units: Budget {
                        mem: 1_000_000,
                        steps: 500_000_000,
                    },
                }),
            },
        })
    };

    let unit_of = |name: &[u8]| format!("{registry_policy_hex}{}", hex::encode(name));
    let anchor_value = vec![
        Asset::new_from_str("lovelace", &anchor.lovelace.to_string()),
        Asset::new_from_str(&unit_of(&plan.anchor_asset_name), "1"),
    ];
    let node_value = vec![
        Asset::new_from_str("lovelace", &node.lovelace.to_string()),
        Asset::new_from_str(&unit_of(&plan.removed_asset_name), "1"),
    ];
    let anchor_in = element_in(anchor, anchor_value.clone());
    let node_in = element_in(node, node_value);

    // Continued anchor: same address, same value (anchor_lovelace_change must
    // be 0 on-chain), data unchanged, link → the removed node's old link.
    let continued_anchor_out = Output {
        address: registry_address,
        amount: anchor_value,
        datum: Some(Datum::Inline(hex::encode(plan.continued_anchor.to_cbor()))),
        reference_script: None,
    };

    let mint_redeemer = deregister_mint_redeemer(
        req.sig,
        node_input_index,
        anchor_input_index,
        anchor_output_index,
        treasury_input_index,
        treasury_output_index,
        &removal_proof,
    );
    let mint_redeemer_hex =
        hex::encode(minicbor::to_vec(&mint_redeemer).expect("redeemer CBOR encode"));

    let body = TxBuilderBody {
        inputs: vec![
            TxIn::PubKeyTxIn(PubKeyTxIn {
                tx_in: TxInParameter {
                    tx_hash: fee_utxo.tx_hash.clone(),
                    tx_index: fee_utxo.output_index,
                    amount: Some(vec![Asset::new_from_str(
                        "lovelace",
                        &fee_utxo.lovelace.to_string(),
                    )]),
                    address: Some(req.wallet_address.to_string()),
                },
            }),
            anchor_in,
            node_in,
            treasury_in,
        ],
        outputs: vec![continued_anchor_out, treasury_out],
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
        reference_inputs: reference_inputs.clone(),
        withdrawals: vec![],
        mints: vec![MintItem::ScriptMint(ScriptMint {
            mint: MintParameter {
                policy_id: registry_policy_hex.clone(),
                asset_name: hex::encode(pool_id),
                amount: -1,
            },
            redeemer: Some(Redeemer {
                data: mint_redeemer_hex,
                // Deregister walks the linked-list removal, verifies an
                // Ed25519 signature and recomputes the MPF delete — the same
                // weight as Register minus the Schnorr check.
                ex_units: Budget {
                    mem: 6_000_000,
                    steps: 3_000_000_000,
                },
            }),
            script_source: Some(registry_source.clone()),
        })],
        certificates: vec![],
        votes: vec![],
        fee: None,
        change_datum: None,
        metadata: vec![],
        validity_range: ValidityRange {
            invalid_before: req.invalid_before,
            invalid_hereafter: req.invalid_hereafter,
        },
        total_collateral: None,
        collateral_return_address: None,
    };

    let mut pallas = WhiskyPallas::new(None);
    pallas.tx_builder_body = body;
    let unsigned_hex = pallas
        .serialize_tx_body()
        .map_err(|e| DeregisterSpoError::Build(format!("whisky tx build: {e:?}")))?;

    // Post-build pass before signing: (a) whisky pushes one reference input
    // per InlineScriptSource use — three of them here — so dedupe (duplicate
    // set elements would be rejected; ref inputs sit outside the
    // script-integrity hash, so the edit is safe pre-signature); (b) defensive
    // check that the redeemer indices derived from the expected input sort
    // match the built tx.
    let unsigned_hex = {
        let tx_bytes = hex::decode(&unsigned_hex)
            .map_err(|e| DeregisterSpoError::Build(format!("unsigned tx hex decode: {e}")))?;
        let mut tx: Tx = minicbor::decode(&tx_bytes)
            .map_err(|e| DeregisterSpoError::Build(format!("tx minicbor decode: {e}")))?;

        if let Some(ref_ins) = tx.transaction_body.reference_inputs.take() {
            let mut v = ref_ins.to_vec();
            v.sort_by_key(|i| (i.transaction_id, i.index));
            v.dedup();
            tx.transaction_body.reference_inputs = pallas_codec::utils::NonEmptySet::from_vec(v);
        }

        {
            let inputs: Vec<_> = tx.transaction_body.inputs.iter().collect();
            let at =
                |i: i64, want: &([u8; 32], u32), what: &str| -> Result<(), DeregisterSpoError> {
                    let got = inputs.get(i as usize).ok_or_else(|| {
                        DeregisterSpoError::Build(format!("{what} input index {i} out of range"))
                    })?;
                    if got.transaction_id.as_slice() != want.0 || got.index != u64::from(want.1) {
                        return Err(DeregisterSpoError::Build(format!(
                            "{what} input not at redeemer index {i} — input ordering changed"
                        )));
                    }
                    Ok(())
                };
            at(anchor_input_index, &anchor_ref, "anchor")?;
            at(node_input_index, &node_ref, "registration node")?;
            at(treasury_input_index, &treasury_ref, "treasury")?;
        }

        hex::encode(
            minicbor::to_vec(&tx)
                .map_err(|e| DeregisterSpoError::Build(format!("tx re-encode: {e}")))?,
        )
    };

    let signed_tx_hex =
        common_sign_built_tx(&unsigned_hex, req.key).map_err(DeregisterSpoError::Build)?;
    Ok(DeregisterSpoTx {
        signed_tx_hex,
        pool_id,
        bifrost_id_pk,
        anchor_asset_name: plan.anchor_asset_name,
        new_bifrost_identity_root: new_treasury_datum.bifrost_identity_root,
        freed_lovelace: node.lovelace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::bf_http::BfAmount;
    use crate::cardano::blueprint;
    use crate::cardano::registry::{
        ElementData, REGISTRATION_ROOT_KEY, RegistrationNodeData, RegistryElement,
    };
    use crate::cardano::treasury_info::TreasuryInfoDatum;
    use crate::cardano::wallet::derive_payment_key;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// Sorts below every pool_id (a 28-byte hash is never all zeros).
    const LOW_KEY: [u8; 28] = [0x00; 28];
    /// Sorts above every pool_id.
    const HIGH_KEY: [u8; 28] = [0xFF; 28];
    const SELF_PK: [u8; 32] = [0x7A; 32];

    fn registry_script() -> ParameterizedScript {
        let code = include_str!("../../tests/fixtures/spos_registry_code.txt");
        blueprint::apply_params(
            code.trim(),
            &[bytes(&[0xbb; 32]), crate::cardano::plutus::int_from_u64(3)],
        )
        .unwrap()
    }

    fn treasury_script(registry_policy: &[u8; 28]) -> ParameterizedScript {
        let code = include_str!("../../tests/fixtures/treasury_info_code.txt");
        blueprint::apply_params(code.trim(), &[bytes(registry_policy)]).unwrap()
    }

    fn cold_skey() -> ed25519::SecretKey {
        ed25519::SecretKey::from([42u8; 32])
    }

    fn test_sig() -> RevocationSignature {
        sign_revocation(&cold_skey())
    }

    fn test_pool_id() -> [u8; 28] {
        pool_id_from_cold_vkey(&test_sig().cold_vkey)
    }

    fn element_utxo(
        policy_hex: &str,
        tx_hash: &str,
        index: u32,
        lovelace: u64,
        asset_name: &[u8],
        element: &RegistryElement,
    ) -> BfUtxo {
        BfUtxo {
            tx_hash: tx_hash.to_string(),
            output_index: index,
            amount: vec![
                BfAmount {
                    unit: "lovelace".into(),
                    quantity: lovelace.to_string(),
                },
                BfAmount {
                    unit: format!("{policy_hex}{}", hex::encode(asset_name)),
                    quantity: "1".into(),
                },
            ],
            inline_datum: Some(hex::encode(element.to_cbor())),
            reference_script_hash: None,
        }
    }

    fn root_element(link: Option<&[u8]>) -> RegistryElement {
        RegistryElement {
            data: ElementData::Root,
            link: link.map(<[u8]>::to_vec),
        }
    }

    fn node_element(pk: &[u8], link: Option<&[u8]>) -> RegistryElement {
        RegistryElement {
            data: ElementData::Node(RegistrationNodeData {
                bifrost_id_pk: pk.to_vec(),
                bifrost_url: b"https://spo.example:18500".to_vec(),
            }),
            link: link.map(<[u8]>::to_vec),
        }
    }

    #[test]
    fn revocation_message_is_domain_separated_concatenation() {
        assert_eq!(revocation_message(b"POOL"), b"bifrost-revokePOOL");
    }

    // The local verification mirrors the on-chain check: Ed25519 by the cold
    // key over the raw revocation message, and pool_id derived from that same
    // key (so a signature cannot be pointed at someone else's registration).
    #[test]
    fn sign_verify_roundtrip_and_tamper_detection() {
        let sig = test_sig();
        assert_eq!(
            verify_revocation(&sig).unwrap(),
            pool_id_from_cold_vkey(&sig.cold_vkey)
        );

        let mut flipped = sig.clone();
        flipped.cold_sig[0] ^= 1;
        assert!(matches!(
            verify_revocation(&flipped),
            Err(DeregisterSpoError::ColdSignatureInvalid)
        ));

        // A signature by one cold key presented under another's vkey: the
        // pool_id moves with the vkey, so the message changes and the check
        // fails — this is what stops a revocation being replayed at a
        // different pool.
        let mut swapped = sig;
        swapped.cold_vkey = ed25519::SecretKey::from([43u8; 32]).public_key().into();
        assert!(matches!(
            verify_revocation(&swapped),
            Err(DeregisterSpoError::ColdSignatureInvalid)
        ));
    }

    #[test]
    fn redeemer_shape_and_canonical_encoding() {
        let sig = test_sig();
        let proof: mpf::Proof = vec![];
        let r = deregister_mint_redeemer(&sig, 1, 0, 0, 3, 1, &proof);
        let cbor = minicbor::to_vec(&r).unwrap();
        let hex_str = hex::encode(&cbor);
        // Constr 2 → tag 123 (0xd87b), indefinite-length fields.
        assert!(hex_str.starts_with("d87b9f"), "{hex_str}");
        assert!(hex_str.ends_with("ff"), "{hex_str}");

        let back: PlutusData = minicbor::decode(&cbor).unwrap();
        let PlutusData::Constr(c) = back else {
            panic!("expected Constr");
        };
        assert_eq!(c.tag, 123, "Deregister is constructor 2");
        let fields: Vec<_> = c.fields.iter().collect();
        assert_eq!(fields.len(), 8);
        assert!(matches!(fields[0], PlutusData::BoundedBytes(b) if **b == sig.cold_vkey));
        assert!(matches!(fields[1], PlutusData::BoundedBytes(b) if **b == sig.cold_sig));
        assert!(matches!(fields[7], PlutusData::Array(_)));
    }

    /// `(list elements, identity pairs)` for a three-node registry whose
    /// middle node is ours. `neighbours` picks whether the low/high siblings
    /// are present, which is what moves the anchor between a node and the root.
    fn chain(
        policy: &str,
        low: bool,
        high: bool,
    ) -> (Vec<BfUtxo>, Vec<(Vec<u8>, Vec<u8>)>, Vec<BfUtxo>) {
        let pool_id = test_pool_id();
        let mut elements = Vec::new();
        let mut pairs = Vec::new();

        let first: &[u8] = if low { &LOW_KEY } else { &pool_id };
        elements.push(element_utxo(
            policy,
            &"11".repeat(32),
            0,
            2_600_000,
            REGISTRATION_ROOT_KEY,
            &root_element(Some(first)),
        ));
        if low {
            elements.push(element_utxo(
                policy,
                &"33".repeat(32),
                0,
                2_700_000,
                &LOW_KEY,
                &node_element(&[0x01; 32], Some(&pool_id)),
            ));
            pairs.push(([0x01; 32].to_vec(), LOW_KEY.to_vec()));
        }
        let self_link: Option<&[u8]> = if high { Some(&HIGH_KEY) } else { None };
        elements.push(element_utxo(
            policy,
            &"22".repeat(32),
            0,
            2_800_000,
            &pool_id,
            &node_element(&SELF_PK, self_link),
        ));
        pairs.push((SELF_PK.to_vec(), pool_id.to_vec()));
        if high {
            elements.push(element_utxo(
                policy,
                &"44".repeat(32),
                0,
                2_900_000,
                &HIGH_KEY,
                &node_element(&[0x03; 32], None),
            ));
            pairs.push(([0x03; 32].to_vec(), HIGH_KEY.to_vec()));
        }
        (elements, pairs, Vec::new())
    }

    /// Build against a synthetic chain state and return the built tx.
    fn build_against(
        registry_elements: Vec<BfUtxo>,
        identity_pairs: &[(Vec<u8>, Vec<u8>)],
        sig: &RevocationSignature,
    ) -> Result<(DeregisterSpoTx, Tx, ParameterizedScript, mpf::Hash), DeregisterSpoError> {
        let registry = registry_script();
        let treasury = treasury_script(&registry.hash);

        let trie = mpf::Trie::from_pairs(identity_pairs.iter().map(|(k, v)| (k, v))).unwrap();
        let treasury_datum = TreasuryInfoDatum {
            bifrost_identity_root: trie.root_hash(),
            current_spos_frost_key: vec![0xAB; 32],
        };
        let nft_name = "ee".repeat(32);
        let treasury_utxos = vec![BfUtxo {
            tx_hash: "dd".repeat(32),
            output_index: 0,
            amount: vec![
                BfAmount {
                    unit: "lovelace".into(),
                    quantity: "3104330".into(),
                },
                BfAmount {
                    unit: format!("{}{nft_name}", treasury.hash_hex()),
                    quantity: "1".into(),
                },
            ],
            inline_datum: Some(hex::encode(treasury_datum.to_cbor())),
            reference_script_hash: None,
        }];

        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let wallet_addr = crate::cardano::wallet::wallet_address(&key);
        let wallet_utxos = vec![
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
        ];

        let req = DeregisterSpoRequest {
            registry_script: &registry,
            treasury_script: &treasury,
            treasury_asset_name_hex: &nft_name,
            registry_utxos: &registry_elements,
            treasury_utxos: &treasury_utxos,
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            sig,
            invalid_before: None,
            invalid_hereafter: None,
            registry_ref: None,
            config_ref: ("cc".repeat(32), 0),
            cost_models: None,
        };
        let built = build_deregister_spo_tx(&req)?;
        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        Ok((built, tx, registry, trie.root_hash()))
    }

    /// The eight redeemer fields that matter for placement:
    /// `(registration_input, anchor_input, anchor_output, treasury_input,
    /// treasury_output)`.
    fn decoded_deregister_redeemer(tx: &Tx) -> (i64, i64, i64, i64, i64) {
        let redeemers = tx.transaction_witness_set.redeemer.as_ref().unwrap();
        let all: Vec<pallas_primitives::conway::Redeemer> = match redeemers {
            pallas_primitives::conway::Redeemers::List(rs) => rs.iter().cloned().collect(),
            pallas_primitives::conway::Redeemers::Map(kv) => kv
                .iter()
                .map(|(k, v)| pallas_primitives::conway::Redeemer {
                    tag: k.tag,
                    index: k.index,
                    data: v.data.clone(),
                    ex_units: v.ex_units,
                })
                .collect(),
        };
        let mint = all
            .iter()
            .find(|r| matches!(r.tag, pallas_primitives::conway::RedeemerTag::Mint))
            .expect("mint redeemer present");
        let PlutusData::Constr(c) = &mint.data else {
            panic!("expected Constr mint redeemer");
        };
        assert_eq!(c.tag, 123, "Deregister is constructor 2");
        let f: Vec<_> = c.fields.iter().collect();
        assert_eq!(f.len(), 8);
        let as_int = |pd: &PlutusData| -> i64 {
            let PlutusData::BigInt(pallas_primitives::BigInt::Int(i)) = pd else {
                panic!("expected int field");
            };
            i128::from(*i) as i64
        };
        (
            as_int(f[2]),
            as_int(f[3]),
            as_int(f[4]),
            as_int(f[5]),
            as_int(f[6]),
        )
    }

    fn decode_element_output(tx: &Tx, index: usize) -> (u64, RegistryElement) {
        use pallas_primitives::conway::{DatumOption, PseudoTransactionOutput};
        let PseudoTransactionOutput::PostAlonzo(o) = &tx.transaction_body.outputs[index] else {
            panic!("expected post-alonzo output");
        };
        let Some(DatumOption::Data(d)) = &o.datum_option else {
            panic!("expected inline datum");
        };
        let element = RegistryElement::from_plutus_data(&d.0).unwrap();
        let lovelace = match &o.value {
            pallas_primitives::conway::Value::Coin(c) => *c,
            pallas_primitives::conway::Value::Multiasset(c, _) => *c,
        };
        (lovelace, element)
    }

    /// End-to-end with a node on each side: the anchor is the predecessor
    /// node, and the continued anchor takes over our link.
    #[test]
    fn build_deregister_spo_tx_mid_list_end_to_end() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        let (elements, pairs, _) = chain(&policy, true, true);
        let (built, tx, registry, old_root) =
            build_against(elements, &pairs, &test_sig()).expect("build deregister tx");

        let pool_id = test_pool_id();
        assert_eq!(built.pool_id, pool_id);
        assert_eq!(built.anchor_asset_name, LOW_KEY);
        assert_eq!(built.bifrost_id_pk, SELF_PK);
        assert_eq!(built.freed_lovelace, 2_800_000);

        // Inputs sort 11(anchor) < 22(node) < aa(fee) < dd(treasury).
        let inputs: Vec<_> = tx.transaction_body.inputs.iter().collect();
        assert_eq!(inputs.len(), 4);
        let (node_in, anchor_in, anchor_out, treasury_in, treasury_out) =
            decoded_deregister_redeemer(&tx);
        assert_eq!(
            inputs[anchor_in as usize].transaction_id.as_slice(),
            [0x33; 32]
        );
        assert_eq!(
            inputs[node_in as usize].transaction_id.as_slice(),
            [0x22; 32]
        );
        assert_eq!(
            inputs[treasury_in as usize].transaction_id.as_slice(),
            [0xdd; 32]
        );
        assert_eq!((anchor_out, treasury_out), (0, 1));

        // Mint: exactly (registry policy, pool_id, -1). A burn, not a mint —
        // that sign is [DRG-1].
        let mint = tx.transaction_body.mint.as_ref().expect("mint present");
        let policies: Vec<_> = mint.iter().collect();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].0.as_slice(), registry.hash);
        let assets: Vec<_> = policies[0].1.iter().collect();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].0.as_slice(), pool_id);
        assert_eq!(i64::from(assets[0].1), -1);

        // Output[0]: continued anchor — the predecessor's data, its lovelace
        // unchanged (anchor_lovelace_change == 0 on-chain), link jumped over
        // the removed node.
        let (lovelace, element) = decode_element_output(&tx, 0);
        assert_eq!(lovelace, 2_700_000);
        assert_eq!(element.link.as_deref(), Some(&HIGH_KEY[..]));
        assert!(matches!(element.data, ElementData::Node(_)));

        // Only two outputs are ours; whisky appends the change (which is where
        // the freed 2_800_000 lands).
        assert!(tx.transaction_body.outputs.len() >= 3);

        // The new identity root is the old trie minus our pair.
        let expected = mpf::Trie::from_pairs(
            pairs
                .iter()
                .filter(|(k, _)| k.as_slice() != SELF_PK)
                .map(|(k, v)| (k, v)),
        )
        .unwrap();
        assert_eq!(built.new_bifrost_identity_root, expected.root_hash());
        assert_ne!(built.new_bifrost_identity_root, old_root);
    }

    /// Removing the first node anchors on the ROOT element, which is the
    /// branch `plan_remove` shares with an empty-list insert.
    #[test]
    fn build_deregister_spo_tx_root_anchor() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        let (elements, pairs, _) = chain(&policy, false, true);
        let (built, tx, _, _) =
            build_against(elements, &pairs, &test_sig()).expect("build deregister tx");

        assert_eq!(built.anchor_asset_name, REGISTRATION_ROOT_KEY);
        let (lovelace, element) = decode_element_output(&tx, 0);
        assert_eq!(lovelace, 2_600_000);
        assert_eq!(element.data, ElementData::Root);
        assert_eq!(element.link.as_deref(), Some(&HIGH_KEY[..]));
    }

    /// The last node out leaves the root pointing nowhere — the list is empty
    /// again, and the identity root is back to the empty trie.
    #[test]
    fn build_deregister_spo_tx_last_member_empties_the_list() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        let (elements, pairs, _) = chain(&policy, false, false);
        let (built, tx, _, _) =
            build_against(elements, &pairs, &test_sig()).expect("build deregister tx");

        let (_, element) = decode_element_output(&tx, 0);
        assert_eq!(element.data, ElementData::Root);
        assert_eq!(element.link, None);
        assert_eq!(
            built.new_bifrost_identity_root,
            mpf::Trie::from_pairs(Vec::<(Vec<u8>, Vec<u8>)>::new())
                .unwrap()
                .root_hash()
        );
    }

    /// A cold key that never registered has nothing to remove — and the error
    /// says that rather than failing later inside the trie.
    #[test]
    fn refuses_a_pool_that_is_not_in_the_registry() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        let (elements, pairs, _) = chain(&policy, true, true);
        let stranger = sign_revocation(&ed25519::SecretKey::from([44u8; 32]));
        assert!(matches!(
            build_against(elements, &pairs, &stranger),
            Err(DeregisterSpoError::Registry(RegistryError::NotRegistered))
        ));
    }

    /// A bad signature costs no fee: the check runs before anything is built.
    #[test]
    fn refuses_a_bad_signature_before_building() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        let (elements, pairs, _) = chain(&policy, true, true);
        let mut sig = test_sig();
        sig.cold_sig[63] ^= 1;
        assert!(matches!(
            build_against(elements, &pairs, &sig),
            Err(DeregisterSpoError::ColdSignatureInvalid)
        ));
    }
}
