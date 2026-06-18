//! Transaction-building helpers shared across the tx builders (`register_spo`,
//! `apply_ban`, `fault_proof`, `treasury_bootstrap`, `publish`).
//!
//! Centralizes pieces that were independently open-coded in every builder:
//! network selection (from a wallet address, and the whisky cost-model param),
//! the min-UTxO and Conway ref-script fee formulas, collateral selection
//! (pure-ADA and disjoint from the spending inputs), body signing, and the
//! one-shot linked-list bootstrap tx (the registry and ban lists share an
//! identical skeleton, differing only in root datum, root asset name, and the
//! mint `Bootstrap` redeemer).

use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptySet};
use pallas_primitives::conway::{Tx, VKeyWitness};
use pallas_traverse::ComputeHash;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::publish::WalletUtxo;
use crate::cardano::wallet::pub_key_hash_hex;

/// Whether a bech32 address is a testnet address (`addr_test…` HRP).
#[must_use]
pub fn is_testnet_address(wallet_address: &str) -> bool {
    wallet_address.starts_with("addr_test")
}

/// The `pallas_addresses::Network` implied by a bech32 wallet address.
#[must_use]
pub fn network_from_address(wallet_address: &str) -> pallas_addresses::Network {
    if is_testnet_address(wallet_address) {
        pallas_addresses::Network::Testnet
    } else {
        pallas_addresses::Network::Mainnet
    }
}

/// The whisky `Network` to evaluate scripts against: the caller's live `[V1, V2,
/// V3]` cost models when fetched, else whisky's built-in Preprod set.
#[must_use]
pub fn whisky_network(cost_models: &Option<Vec<Vec<i64>>>) -> whisky::Network {
    match cost_models {
        Some(cm) => whisky::Network::Custom(cm.clone()),
        None => whisky::Network::Preprod,
    }
}

/// Min-UTxO for a datum-carrying script output — the conservative datum-scaled
/// formula shared by the registry / ban / treasury elements (the locked value
/// persists for the element's whole on-chain life).
#[must_use]
pub fn element_lovelace(datum_cbor_len: usize) -> u64 {
    std::cmp::max(2_000_000u64, (datum_cbor_len as u64 + 600) * 4310)
}

/// Conway `minFeeRefScriptCostPerByte` (preprod + mainnet). Charged on reference
/// scripts attached to SPENT inputs — which whisky's fee estimation does not
/// model; the bootstrap/apply builders add it explicitly when the one-shot is
/// forced to be a ref-script UTxO.
const REF_SCRIPT_FEE_PER_BYTE: u64 = 15;

/// The Conway tiered ref-script fee (×1.2 per started 25600-byte tier).
#[must_use]
pub fn ref_script_fee(script_size: u64) -> u64 {
    const TIER: u64 = 25_600;
    let mut fee = 0f64;
    let mut multiplier = 1f64;
    let mut remaining = script_size;
    while remaining >= TIER {
        fee += TIER as f64 * multiplier * REF_SCRIPT_FEE_PER_BYTE as f64;
        remaining -= TIER;
        multiplier *= 1.2;
    }
    fee += remaining as f64 * multiplier * REF_SCRIPT_FEE_PER_BYTE as f64;
    fee.ceil() as u64
}

/// Pick the fee input: the richest pure-ADA wallet UTxO, requiring it to cover
/// `min_fee_lovelace` (the outputs plus a fee margin). Pure-ADA only — a
/// token-bearing input would be declared lovelace-only and unbalance the tx.
pub fn select_fee(
    wallet_utxos: &[WalletUtxo],
    min_fee_lovelace: u64,
) -> Result<&WalletUtxo, String> {
    let fee = wallet_utxos
        .iter()
        .filter(|u| u.pure_ada)
        .max_by_key(|u| u.lovelace)
        .ok_or_else(|| "no pure-ADA wallet UTxO available for the fee input".to_string())?;
    if fee.lovelace < min_fee_lovelace {
        return Err(format!(
            "largest pure-ADA wallet UTxO ({} lovelace) cannot cover the outputs plus fees \
             (needs >= {min_fee_lovelace}) — fund the wallet or consolidate UTxOs",
            fee.lovelace
        ));
    }
    Ok(fee)
}

/// Find a pure-ADA collateral UTxO (>= 5 ADA) that is NOT among `spent_inputs`.
/// Collateral must be pure-ADA and disjoint from the tx's regular inputs — a
/// UTxO cannot be both a spent input and a collateral input, and the ledger
/// rejects such a tx at phase 1.
pub fn select_collateral<'a>(
    wallet_utxos: &'a [WalletUtxo],
    spent_inputs: &[&WalletUtxo],
) -> Result<&'a WalletUtxo, String> {
    wallet_utxos
        .iter()
        .find(|u| {
            u.lovelace >= 5_000_000
                && u.pure_ada
                && !spent_inputs
                    .iter()
                    .any(|s| s.tx_hash == u.tx_hash && s.output_index == u.output_index)
        })
        .ok_or_else(|| {
            "no pure-ADA wallet UTxO with >= 5 ADA for collateral, distinct from the \
             spending inputs"
                .to_string()
        })
}

/// Sign a whisky-built tx body with the wallet key and splice in the vkey
/// witness (the flow every builder uses after `serialize_tx_body`).
pub fn sign_built_tx(unsigned_hex: &str, key: &PrivateKey) -> Result<String, String> {
    let bytes = hex::decode(unsigned_hex).map_err(|e| format!("unsigned tx hex decode: {e}"))?;
    let mut tx: Tx = minicbor::decode(&bytes).map_err(|e| format!("tx minicbor decode: {e}"))?;
    let body_hash = tx.transaction_body.compute_hash();
    let signature = key.sign(body_hash);
    let pk: [u8; 32] = key.public_key().into();
    let vkw = VKeyWitness {
        vkey: Bytes::from(pk.to_vec()),
        signature: Bytes::from(signature.as_ref().to_vec()),
    };
    let mut vkeys: Vec<VKeyWitness> = tx
        .transaction_witness_set
        .vkeywitness
        .take()
        .map(|s| s.to_vec())
        .unwrap_or_default();
    vkeys.push(vkw);
    tx.transaction_witness_set.vkeywitness = NonEmptySet::from_vec(vkeys);
    let signed = minicbor::to_vec(&tx).map_err(|e| format!("signed tx encode: {e}"))?;
    Ok(hex::encode(signed))
}

/// Error from [`build_oneshot_bootstrap_tx`]. Split so each caller can map it
/// onto its own module error preserving the wallet/build distinction.
#[derive(Debug)]
pub enum BootstrapError {
    /// Wallet/coin-selection problem (one-shot missing, no collateral, etc.).
    Wallet(String),
    /// whisky tx build / CBOR (de)code / signing failure.
    Build(String),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "tx build: {e}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// A built (signed, unsubmitted) one-shot linked-list bootstrap tx.
#[derive(Debug, Clone)]
pub struct OneShotBootstrapTx {
    pub signed_tx_hex: String,
    /// The minting-policy script hash (= the list policy id).
    pub policy_id_hex: String,
    /// Enterprise script address holding the list elements.
    pub script_address: String,
}

/// Inputs to [`build_oneshot_bootstrap_tx`]. The varying pieces — root datum,
/// root asset name, and mint redeemer — are precomputed by the caller; the
/// shared skeleton (one-shot spend, fee/collateral selection, root output mint,
/// two-pass ref-script fee, signing) is identical for registry and ban.
pub struct OneShotBootstrapParams<'a> {
    /// The list minting policy (cbor + hash), parameterized by the one-shot.
    pub policy_script: &'a ParameterizedScript,
    pub bootstrap_tx_hash: &'a str,
    pub bootstrap_output_index: u32,
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    pub key: &'a PrivateKey,
    pub one_shot_ref_script_size: Option<u64>,
    /// Live `[V1, V2, V3]` cost models; `None` → whisky's built-in Preprod.
    pub cost_models: Option<Vec<Vec<i64>>>,
    /// CBOR of the `Element{Root, link: None}` datum locked at the script.
    pub root_datum_cbor: Vec<u8>,
    /// The root anchor NFT asset name (`"reg-root"` / `"ban-root"`).
    pub root_asset_name: &'a [u8],
    /// CBOR of the mint `Bootstrap` redeemer (registry: field-less; ban: carries
    /// the one-shot `OutputReference`).
    pub mint_redeemer_cbor: String,
    /// Short noun for error messages (`"registry"` / `"ban"`).
    pub outref_label: &'a str,
}

/// Build + sign the one-shot bootstrap: spend the outref that parameterizes the
/// `policy_script` (it MUST be among `wallet_utxos`) and mint the root anchor
/// NFT to the script address with the inline root datum. This initializes the
/// linked list (the precondition for any insert).
pub fn build_oneshot_bootstrap_tx(
    p: OneShotBootstrapParams,
) -> Result<OneShotBootstrapTx, BootstrapError> {
    let one_shot = p
        .wallet_utxos
        .iter()
        .find(|u| u.tx_hash == p.bootstrap_tx_hash && u.output_index == p.bootstrap_output_index)
        .ok_or_else(|| {
            BootstrapError::Wallet(format!(
                "{} bootstrap outref {}#{} is not an unspent wallet UTxO — the parameterized \
                 policy can only validate a tx spending exactly that outpoint",
                p.outref_label, p.bootstrap_tx_hash, p.bootstrap_output_index
            ))
        })?;
    // The one-shot cannot be swapped (it parameterizes the policy). It MAY carry
    // a reference script — that case is handled by `one_shot_ref_script_size`,
    // which prices the Conway ref-script fee in below; a supplied size is the
    // caller's signal that a non-pure-ADA one-shot is the intended ref-script
    // case. It must NOT carry native tokens, though: the builder declares inputs
    // lovelace-only, so tokens would be dropped from the value balance. `pure_ada`
    // can't tell tokens from a ref script, so reject only when it is non-pure-ADA
    // AND no ref-script size was supplied (i.e. effectively token-bearing).
    if !one_shot.pure_ada && p.one_shot_ref_script_size.is_none() {
        return Err(BootstrapError::Wallet(format!(
            "{} bootstrap outref {}#{} is not a pure-ADA UTxO and no reference-script size was \
             supplied — the one-shot must hold only ADA, else its native tokens are dropped from \
             the value balance",
            p.outref_label, p.bootstrap_tx_hash, p.bootstrap_output_index
        )));
    }

    let network = network_from_address(p.wallet_address);
    let policy_id_hex = p.policy_script.hash_hex();
    let script_address = p.policy_script.enterprise_address(network);
    let root_lovelace = element_lovelace(p.root_datum_cbor.len());

    // The one-shot doubles as the fee input when rich enough; otherwise add the
    // richest other PURE-ADA wallet UTxO alongside it (token-bearing UTxOs are
    // skipped — the builder declares inputs lovelace-only).
    let mut inputs: Vec<&WalletUtxo> = vec![one_shot];
    if one_shot.lovelace < root_lovelace + 1_000_000 {
        let extra = p
            .wallet_utxos
            .iter()
            .filter(|u| {
                u.pure_ada
                    && !(u.tx_hash == one_shot.tx_hash && u.output_index == one_shot.output_index)
            })
            .max_by_key(|u| u.lovelace)
            .filter(|u| one_shot.lovelace + u.lovelace >= root_lovelace + 1_000_000)
            .ok_or_else(|| {
                BootstrapError::Wallet(format!(
                    "wallet cannot cover the {root_lovelace}-lovelace root output plus fees — \
                     fund the wallet"
                ))
            })?;
        inputs.push(extra);
    }
    // Collateral must be pure-ADA AND disjoint from the spending inputs above
    // (the one-shot, plus the extra fee input if added) — the same outpoint
    // cannot be both spent and collateral.
    let coll_utxo = select_collateral(p.wallet_utxos, &inputs).map_err(BootstrapError::Wallet)?;

    let root_unit = format!("{policy_id_hex}{}", hex::encode(p.root_asset_name));

    let build = |fee: Option<String>| -> Result<String, BootstrapError> {
        let body = TxBuilderBody {
            inputs: inputs
                .iter()
                .map(|u| {
                    TxIn::PubKeyTxIn(PubKeyTxIn {
                        tx_in: TxInParameter {
                            tx_hash: u.tx_hash.clone(),
                            tx_index: u.output_index,
                            amount: Some(vec![Asset::new_from_str(
                                "lovelace",
                                &u.lovelace.to_string(),
                            )]),
                            address: Some(p.wallet_address.to_string()),
                        },
                    })
                })
                .collect(),
            outputs: vec![Output {
                address: script_address.clone(),
                amount: vec![
                    Asset::new_from_str("lovelace", &root_lovelace.to_string()),
                    Asset::new_from_str(&root_unit, "1"),
                ],
                datum: Some(Datum::Inline(hex::encode(&p.root_datum_cbor))),
                reference_script: None,
            }],
            collaterals: vec![PubKeyTxIn {
                tx_in: TxInParameter {
                    tx_hash: coll_utxo.tx_hash.clone(),
                    tx_index: coll_utxo.output_index,
                    amount: Some(vec![Asset::new_from_str(
                        "lovelace",
                        &coll_utxo.lovelace.to_string(),
                    )]),
                    address: Some(p.wallet_address.to_string()),
                },
            }],
            required_signatures: vec![pub_key_hash_hex(p.key)],
            change_address: p.wallet_address.to_string(),
            signing_key: vec![],
            network: Some(whisky_network(&p.cost_models)),
            reference_inputs: vec![],
            withdrawals: vec![],
            mints: vec![MintItem::ScriptMint(ScriptMint {
                mint: MintParameter {
                    policy_id: policy_id_hex.clone(),
                    asset_name: hex::encode(p.root_asset_name),
                    amount: 1,
                },
                redeemer: Some(Redeemer {
                    data: p.mint_redeemer_cbor.clone(),
                    // Bootstrap checks the one-shot is spent + the root output
                    // shape and runs linked_list.init — light.
                    ex_units: Budget {
                        mem: 2_000_000,
                        steps: 900_000_000,
                    },
                }),
                script_source: Some(ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
                    script_cbor: p.policy_script.cbor_hex(),
                    language_version: LanguageVersion::V3,
                })),
            })],
            certificates: vec![],
            votes: vec![],
            fee,
            change_datum: None,
            metadata: vec![],
            validity_range: ValidityRange {
                invalid_before: None,
                invalid_hereafter: None,
            },
            total_collateral: None,
            collateral_return_address: None,
        };
        let mut pallas = WhiskyPallas::new(None);
        pallas.tx_builder_body = body;
        pallas
            .serialize_tx_body()
            .map_err(|e| BootstrapError::Build(format!("whisky tx build: {e:?}")))
    };

    // Pass 1: whisky's own fee estimate. When the one-shot carries a reference
    // script, rebuild with that fee plus the ledger's ref-script charge (and a
    // small margin for the changed fee bytes).
    let mut unsigned_hex = build(None)?;
    if let Some(script_size) = p.one_shot_ref_script_size {
        let tx_bytes = hex::decode(&unsigned_hex)
            .map_err(|e| BootstrapError::Build(format!("unsigned tx hex decode: {e}")))?;
        let tx: Tx = minicbor::decode(&tx_bytes)
            .map_err(|e| BootstrapError::Build(format!("tx minicbor decode: {e}")))?;
        let auto_fee = tx.transaction_body.fee;
        let fee = auto_fee + ref_script_fee(script_size) + 4_400;
        unsigned_hex = build(Some(fee.to_string()))?;
    }
    let signed_tx_hex = sign_built_tx(&unsigned_hex, p.key).map_err(BootstrapError::Build)?;

    Ok(OneShotBootstrapTx {
        signed_tx_hex,
        policy_id_hex,
        script_address,
    })
}
