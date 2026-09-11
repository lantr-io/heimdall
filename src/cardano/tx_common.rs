//! Transaction-building helpers shared across the tx builders (`register_spo`,
//! `apply_ban`, `fault_proof`, `treasury_bootstrap`, `publish`).
//!
//! Centralizes pieces that were independently open-coded in every builder:
//! network selection (from a wallet address, and the whisky cost-model param),
//! the min-UTxO and Conway ref-script fee formulas, collateral selection
//! (ada-only and disjoint from the spending inputs), body signing, and the
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

/// What a collateral UTxO must hold. Generous next to the ledger's floor (150%
/// of the fee, so a few hundred thousand lovelace), and deliberately so: it is
/// what a phase-2 failure would forfeit, and it is the size `ensure-collateral`
/// hands out, so the two must agree.
pub const COLLATERAL_LOVELACE: u64 = 5_000_000;

/// How many ada-only UTxOs a wallet needs to keep building script transactions:
/// one to pay the fee, one to point at as collateral, and the ledger will not
/// let a single UTxO be both.
pub const COLLATERAL_UTXOS_WANTED: usize = 2;

/// The wallet's usable collateral candidates: ada-only, no reference script,
/// and fat enough to post.
pub fn collateral_candidates(wallet_utxos: &[WalletUtxo]) -> Vec<&WalletUtxo> {
    wallet_utxos
        .iter()
        .filter(|u| u.pure_ada() && u.lovelace >= COLLATERAL_LOVELACE)
        .collect()
}

/// What `ensure-collateral` built, for the caller to report and submit.
#[derive(Debug, Clone)]
pub struct CollateralTopUp {
    pub signed_tx_hex: String,
    /// Ada-only outputs the tx creates, each of [`COLLATERAL_LOVELACE`].
    pub created: usize,
    /// Collateral candidates the wallet had before it.
    pub had: usize,
}

/// Build a self-payment that splits the wallet enough ada-only UTxOs to keep
/// posting script transactions, or `Ok(None)` when it already has them.
///
/// This is the way out of the trap described in WI-20260910-5DRP6. A wallet
/// whose ADA all sits behind native tokens has no ada-only UTxO to offer as
/// collateral, and whisky cannot emit the `collateral_return` that would let a
/// token-bearing one serve. But THIS tx runs no script, so it needs no
/// collateral at all — only a fee input, and since a fee input may now carry
/// tokens, it can always be built. The tokens ride through to the change
/// output; what comes back is clean ADA.
pub fn build_collateral_top_up(
    wallet_utxos: &[WalletUtxo],
    wallet_address: &str,
    key: &PrivateKey,
    cost_models: &Option<Vec<Vec<i64>>>,
) -> Result<Option<CollateralTopUp>, String> {
    let had = collateral_candidates(wallet_utxos).len();
    if had >= COLLATERAL_UTXOS_WANTED {
        return Ok(None);
    }

    // Always mint the full set rather than only the shortfall: an existing
    // candidate may well be the richest UTxO and get spent as the fee input,
    // and re-creating one we did not have to is harmless.
    let created = COLLATERAL_UTXOS_WANTED;
    let split = created as u64 * COLLATERAL_LOVELACE;

    // The change output inherits every token the inputs carry, and a
    // token-bearing output's min-UTxO is higher than a bare one's. Leave it
    // room rather than discovering the floor from a rejected tx.
    let change_floor = element_lovelace(0);
    let needed = split + change_floor + 1_000_000;

    let mut picked: Vec<&WalletUtxo> = Vec::new();
    let mut sum = 0u64;
    let mut by_value: Vec<&WalletUtxo> =
        wallet_utxos.iter().filter(|u| !u.has_ref_script).collect();
    by_value.sort_by_key(|u| std::cmp::Reverse(u.lovelace));
    for u in by_value {
        if sum >= needed {
            break;
        }
        sum = sum.saturating_add(u.lovelace);
        picked.push(u);
    }
    if sum < needed {
        return Err(format!(
            "wallet holds {sum} lovelace across {} spendable UTxO(s) — not enough to split              {created} collateral UTxOs of {COLLATERAL_LOVELACE} plus fees (needs >= {needed}).              Fund the wallet",
            picked.len()
        ));
    }

    let body = TxBuilderBody {
        inputs: picked
            .iter()
            .map(|u| {
                TxIn::PubKeyTxIn(PubKeyTxIn {
                    tx_in: TxInParameter {
                        tx_hash: u.tx_hash.clone(),
                        tx_index: u.output_index,
                        amount: Some(wallet_input_amount(u)),
                        address: Some(wallet_address.to_string()),
                    },
                })
            })
            .collect(),
        outputs: (0..created)
            .map(|_| Output {
                address: wallet_address.to_string(),
                amount: vec![Asset::new_from_str(
                    "lovelace",
                    &COLLATERAL_LOVELACE.to_string(),
                )],
                datum: None,
                reference_script: None,
            })
            .collect(),
        // No script runs here — which is the whole point.
        collaterals: vec![],
        required_signatures: vec![pub_key_hash_hex(key)],
        change_address: wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(cost_models)),
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![],
        certificates: vec![],
        votes: vec![],
        fee: None,
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
    let unsigned_hex = pallas
        .serialize_tx_body()
        .map_err(|e| format!("whisky tx build: {e:?}"))?;
    let signed_tx_hex = sign_built_tx(&unsigned_hex, key)?;

    Ok(Some(CollateralTopUp {
        signed_tx_hex,
        created,
        had,
    }))
}

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

/// Pick the fee input: the richest wallet UTxO that carries no reference
/// script, requiring it to cover `min_fee_lovelace` (the outputs plus a fee
/// margin).
///
/// Native tokens on the fee input are FINE. Every caller declares the input's
/// full value (`wallet_input_amount`), so whisky carries the tokens into the
/// change output and the tx balances. This used to demand pure-ADA, which left
/// a wallet whose ADA all sat behind tokens unable to pay a fee at all — and
/// therefore unable to split itself a clean UTxO to get out of it
/// (WI-20260910-5DRP6). A reference script is still disqualifying: the Conway
/// per-byte ref-script fee is invisible to generic fee estimation.
pub fn select_fee(
    wallet_utxos: &[WalletUtxo],
    min_fee_lovelace: u64,
) -> Result<&WalletUtxo, String> {
    let fee = wallet_utxos
        .iter()
        .filter(|u| !u.has_ref_script)
        .max_by_key(|u| u.lovelace)
        .ok_or_else(|| "no wallet UTxO available for the fee input".to_string())?;
    if fee.lovelace < min_fee_lovelace {
        return Err(format!(
            "largest wallet UTxO ({} lovelace) cannot cover the outputs plus fees \
             (needs >= {min_fee_lovelace}) — fund the wallet or consolidate UTxOs",
            fee.lovelace
        ));
    }
    Ok(fee)
}

/// The whisky input amount for a wallet UTxO: its lovelace AND every native
/// token it holds.
///
/// Declaring the full value is what lets a token-bearing UTxO be spent at all.
/// whisky's change math is a multi-asset `Value`, so anything declared here
/// that the outputs do not claim comes back in the change output; anything NOT
/// declared is simply missing from the balance, and the node rejects the tx.
#[must_use]
pub fn wallet_input_amount(u: &WalletUtxo) -> Vec<Asset> {
    let mut amount = vec![Asset::new_from_str("lovelace", &u.lovelace.to_string())];
    amount.extend(
        u.tokens
            .iter()
            .map(|(unit, quantity)| Asset::new_from_str(unit, quantity)),
    );
    amount
}

/// Find a pure-ADA collateral UTxO (>= 5 ADA) that is NOT among `spent_inputs`.
///
/// Pure-ADA is OUR restriction, not the ledger's. Since Babbage (CIP-40) the
/// ada-only rule applies to the collateral BALANCE — `sum(collateral inputs) -
/// collateral_return` — so a token-bearing UTxO is legal collateral as long as
/// the tx carries a `collateral_return` (body field 16) handing every token
/// back. We cannot emit one: whisky's pallas backend ignores
/// `collateral_return_address` and hardcodes the body's `collateral_return` to
/// `None`, so `set_collateral_return_address` is a silent no-op here. Until
/// that changes, token-bearing UTxOs are unusable as collateral and a wallet
/// whose ADA all sits behind native tokens cannot post a script tx (WI-20260910-5DRP6).
///
/// Disjointness from the regular inputs is belt-and-braces, not a ledger rule:
/// no phase-1 predicate forbids the overlap (collateral is only consumed when
/// the inputs are not), but every wallet keeps them apart and so do we.
pub fn select_collateral<'a>(
    wallet_utxos: &'a [WalletUtxo],
    spent_inputs: &[&WalletUtxo],
) -> Result<&'a WalletUtxo, String> {
    wallet_utxos
        .iter()
        .find(|u| {
            u.lovelace >= COLLATERAL_LOVELACE
                && u.pure_ada()
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
    if !one_shot.pure_ada() && p.one_shot_ref_script_size.is_none() {
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
    // richest other wallet UTxO alongside it. Tokens on that one are fine —
    // its full value is declared and they come back in the change.
    let mut inputs: Vec<&WalletUtxo> = vec![one_shot];
    if one_shot.lovelace < root_lovelace + 1_000_000 {
        let extra = p
            .wallet_utxos
            .iter()
            .filter(|u| {
                let is_one_shot =
                    u.tx_hash == one_shot.tx_hash && u.output_index == one_shot.output_index;
                !(u.has_ref_script || is_one_shot)
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
                            amount: Some(wallet_input_amount(u)),
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
                    amount: Some(wallet_input_amount(coll_utxo)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
    use std::collections::BTreeMap;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const FSAT: &str = "d8c06b705b0089b8da32e1a17550bc0d3a4fea7999508e3e95669d1066534154";

    fn utxo(ix: u32, lovelace: u64, tokens: &[(&str, &str)]) -> WalletUtxo {
        WalletUtxo {
            tx_hash: format!("{ix:064x}"),
            output_index: ix,
            lovelace,
            tokens: tokens
                .iter()
                .map(|(u, q)| ((*u).to_string(), (*q).to_string()))
                .collect::<BTreeMap<_, _>>(),
            has_ref_script: false,
        }
    }

    /// The asymmetry this whole change rests on: a fee input may carry native
    /// tokens, a collateral input may not.
    ///
    /// Not a preference. The tokens on a fee input are declared and come back
    /// in the change, so the tx balances. Collateral has no such escape here —
    /// the ledger would take it with a `collateral_return` (Babbage/CIP-40
    /// puts the ada-only test on the BALANCE, not the inputs), but whisky's
    /// pallas backend cannot emit that field.
    #[test]
    fn a_fee_input_may_carry_tokens_but_collateral_may_not() {
        let wallet = vec![utxo(0, 11_000_000_000, &[(FSAT, "42")])];

        let fee = select_fee(&wallet, 2_000_000).expect("a token-bearing UTxO can pay the fee");
        assert_eq!(fee.output_index, 0);

        let err = select_collateral(&wallet, &[]).expect_err("but it cannot be collateral");
        assert!(err.contains("collateral"), "{err}");
        assert!(collateral_candidates(&wallet).is_empty());
    }

    /// A reference script still disqualifies a UTxO from both, for a reason
    /// that has nothing to do with tokens: the Conway per-byte ref-script fee
    /// is invisible to generic fee estimation.
    #[test]
    fn a_reference_script_utxo_is_skipped_whatever_else_it_holds() {
        let mut clean = utxo(0, 100_000_000, &[]);
        clean.has_ref_script = true;
        assert!(!clean.pure_ada());
        let err = select_fee(std::slice::from_ref(&clean), 1).expect_err("not a fee input");
        assert!(err.contains("no wallet UTxO"), "{err}");
    }

    /// Whatever a UTxO holds is declared on the input. Anything left out is
    /// missing from the value balance and the node rejects the tx — which is
    /// exactly how token-bearing UTxOs became unspendable.
    #[test]
    fn the_input_amount_declares_every_token() {
        let amount = wallet_input_amount(&utxo(0, 5_000_000, &[(FSAT, "42")]));
        assert_eq!(amount.len(), 2);
        assert_eq!(amount[0].unit(), "lovelace");
        assert_eq!(amount[0].quantity(), "5000000");
        assert_eq!(amount[1].unit(), FSAT);
        assert_eq!(amount[1].quantity(), "42");
    }

    #[test]
    fn a_wallet_that_can_already_post_collateral_is_left_alone() {
        let wallet = vec![
            utxo(0, COLLATERAL_LOVELACE, &[]),
            utxo(1, COLLATERAL_LOVELACE, &[]),
        ];
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address_from_mnemonic(TEST_MNEMONIC).unwrap();
        let built = build_collateral_top_up(&wallet, &addr, &key, &None).unwrap();
        assert!(built.is_none(), "nothing to split");
    }

    /// The spo4 case, and the point of the whole exercise: every lovelace sits
    /// behind a native token, so there is no collateral and — before this —
    /// no way to make one, because making one needed one. This tx runs no
    /// script, so it needs no collateral to build.
    #[test]
    fn a_wallet_whose_ada_is_all_behind_tokens_can_still_split_itself_collateral() {
        let wallet = vec![utxo(0, 11_000_000_000, &[(FSAT, "42")])];
        assert!(collateral_candidates(&wallet).is_empty(), "stuck, before");

        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address_from_mnemonic(TEST_MNEMONIC).unwrap();
        let built = build_collateral_top_up(&wallet, &addr, &key, &None)
            .expect("builds")
            .expect("something to do");
        assert_eq!(built.had, 0);
        assert_eq!(built.created, COLLATERAL_UTXOS_WANTED);
        assert!(!built.signed_tx_hex.is_empty());
    }

    /// An empty wallet is a funding problem, and says so rather than failing
    /// somewhere further in.
    #[test]
    fn an_unfunded_wallet_is_named_as_such() {
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address_from_mnemonic(TEST_MNEMONIC).unwrap();
        let err = build_collateral_top_up(&[], &addr, &key, &None).expect_err("cannot split");
        assert!(err.contains("Fund the wallet"), "{err}");
    }
}
