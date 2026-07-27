//! Update-Y: rotate `current_spos_frost_key` in the live `treasury_info` state
//! UTxO (the DKG key handoff — technical_documentation.md §Update-Y).
//!
//! `treasury.ak`'s `UpdateY` branch spends the state UTxO and requires, in the
//! SAME transaction:
//!
//! 1. a continuing output at the SAME address with the SAME value (the treasury
//!    NFT + its locked ADA travel forward),
//! 2. the continuing inline datum equal to the spent datum with ONLY
//!    `current_spos_frost_key` replaced by `new_spos_frost_key`,
//! 3. a BIP340 signature under the SPENT datum's `current_spos_frost_key` over
//!    [`crate::cardano::treasury_info::update_y_sig_msg`].
//!
//! Submission is permissionless — the signature is the authorization — so this
//! tx needs no registry mint and no required signer beyond the fee payer.
//!
//! Unlike register_spo, the caller signs the message itself (the outgoing key is
//! the roster's, not this node's wallet key): locate the state
//! ([`crate::cardano::treasury_spend::find_treasury_state`]), sign the message,
//! then call [`build_update_y_tx`] with the resulting signature.

use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::publish::WalletUtxo;
use crate::cardano::treasury_info::{TreasuryInfoDatum, update_y_redeemer};
use crate::cardano::treasury_spend::{TreasuryStateUtxo, treasury_spend_leg};
use crate::cardano::tx_common::{select_collateral, select_fee, sign_built_tx};

#[derive(Debug)]
pub enum UpdateYError {
    /// `new_spos_frost_key` is not a 32-byte x-only key.
    BadNewKeyLen(usize),
    /// The BIP340 signature is not 64 bytes.
    BadSigLen(usize),
    Wallet(String),
    Build(String),
}

impl std::fmt::Display for UpdateYError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadNewKeyLen(n) => write!(f, "new_spos_frost_key must be 32 bytes, got {n}"),
            Self::BadSigLen(n) => write!(f, "update-y signature must be 64 bytes, got {n}"),
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "build: {e}"),
        }
    }
}

impl std::error::Error for UpdateYError {}

/// Inputs to [`build_update_y_tx`]. The treasury state UTxO must already be
/// located (so the caller could compute + sign the message it commits to).
pub struct UpdateYRequest<'a> {
    pub treasury_script: &'a ParameterizedScript,
    /// The located, decoded `treasury_info` state UTxO being spent.
    pub state: &'a TreasuryStateUtxo,
    /// The incoming roster's x-only Y_51' (32 bytes).
    pub new_spos_frost_key: &'a [u8],
    pub epoch: i64,
    /// 64-byte BIP340 signature under the SPENT datum's `current_spos_frost_key`
    /// over `update_y_sig_msg(state.tx_hash, state.output_index, epoch, new_key)`.
    pub signature: &'a [u8],
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    /// Fee-paying wallet key (any funded key — submission is permissionless).
    pub key: &'a PrivateKey,
    pub invalid_before: Option<u64>,
    pub invalid_hereafter: Option<u64>,
    pub cost_models: Option<Vec<Vec<i64>>>,
}

/// A built (signed, unsubmitted) Update-Y tx.
#[derive(Debug, Clone)]
pub struct UpdateYTx {
    pub signed_tx_hex: String,
    /// The rotated datum written to the continuing treasury output.
    pub new_datum: TreasuryInfoDatum,
}

/// Build + sign the Update-Y tx: spend the treasury state UTxO with the
/// `UpdateY` redeemer, reproduce it at the same address/value with only
/// `current_spos_frost_key` rotated, and pay the fee from the wallet.
pub fn build_update_y_tx(req: &UpdateYRequest) -> Result<UpdateYTx, UpdateYError> {
    if req.new_spos_frost_key.len() != 32 {
        return Err(UpdateYError::BadNewKeyLen(req.new_spos_frost_key.len()));
    }
    if req.signature.len() != 64 {
        return Err(UpdateYError::BadSigLen(req.signature.len()));
    }

    let network = crate::cardano::tx_common::network_from_address(req.wallet_address);

    // Only current_spos_frost_key changes — mirrors treasury.ak's record-update
    // spread. Every other field is copied from the spent datum verbatim.
    let mut new_datum = req.state.datum.clone();
    new_datum.current_spos_frost_key = req.new_spos_frost_key.to_vec();

    let redeemer = update_y_redeemer(req.new_spos_frost_key, req.epoch, req.signature);
    let (treasury_in, treasury_out) = treasury_spend_leg(
        req.state,
        req.treasury_script,
        &new_datum,
        redeemer,
        network,
    );

    // Fee + collateral: the treasury input carries the NFT, so a separate
    // pure-ADA input pays the fee, and a distinct pure-ADA UTxO is collateral
    // (the tx runs the treasury spend script).
    let fee_utxo = select_fee(req.wallet_utxos, 2_000_000).map_err(UpdateYError::Wallet)?;
    let coll_utxo =
        select_collateral(req.wallet_utxos, &[fee_utxo]).map_err(UpdateYError::Wallet)?;

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
            treasury_in,
        ],
        outputs: vec![treasury_out],
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
        required_signatures: vec![crate::cardano::wallet::pub_key_hash_hex(req.key)],
        change_address: req.wallet_address.to_string(),
        signing_key: vec![],
        network: Some(crate::cardano::tx_common::whisky_network(&req.cost_models)),
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![],
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
        .map_err(|e| UpdateYError::Build(format!("whisky tx build: {e:?}")))?;

    let signed_tx_hex = sign_built_tx(&unsigned_hex, req.key).map_err(UpdateYError::Build)?;
    Ok(UpdateYTx {
        signed_tx_hex,
        new_datum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::bf_http::{BfAmount, BfUtxo};
    use crate::cardano::blueprint;
    use crate::cardano::mpf;
    use crate::cardano::treasury_spend::find_treasury_state;
    use crate::cardano::wallet::derive_payment_key;
    use pallas_codec::minicbor;
    use pallas_primitives::PlutusData;
    use pallas_primitives::conway::Tx;

    fn test_script() -> blueprint::ParameterizedScript {
        let code = include_str!("../../tests/fixtures/treasury_info_code.txt");
        blueprint::apply_params(
            code.trim(),
            &[PlutusData::BoundedBytes(
                pallas_primitives::BoundedBytes::from(vec![0x79u8; 28]),
            )],
        )
        .unwrap()
    }

    fn sample_datum() -> TreasuryInfoDatum {
        TreasuryInfoDatum {
            bifrost_identity_root: mpf::NULL_HASH,
            current_spos_frost_key: vec![0xABu8; 32],
            y_federation: vec![0xCDu8; 32],
            federation_csv_blocks: 144,
            last_reset_tm_txid: vec![],
        }
    }

    fn nft_name() -> String {
        "ee".repeat(32)
    }

    fn state_utxo(policy_hex: &str, datum: &TreasuryInfoDatum) -> BfUtxo {
        BfUtxo {
            tx_hash: "dd".repeat(32),
            output_index: 0,
            amount: vec![
                BfAmount {
                    unit: "lovelace".into(),
                    quantity: "3104330".into(),
                },
                BfAmount {
                    unit: format!("{policy_hex}{}", nft_name()),
                    quantity: "1".into(),
                },
            ],
            inline_datum: Some(hex::encode(datum.to_cbor())),
            reference_script_hash: None,
        }
    }

    fn ada_bf_utxo(tx_hash: &str, lovelace: u64) -> BfUtxo {
        BfUtxo {
            tx_hash: tx_hash.to_string(),
            output_index: 1,
            amount: vec![BfAmount {
                unit: "lovelace".into(),
                quantity: lovelace.to_string(),
            }],
            inline_datum: None,
            reference_script_hash: None,
        }
    }

    // Assemble the Update-Y tx offline and prove it survives into the wire
    // format: the treasury input is spent, the continuing output carries the
    // rotated datum (only current_spos_frost_key changed), and a Spend redeemer
    // encoding UpdateY (Constr 1) is attached.
    #[test]
    fn builds_a_rotation_tx_with_updatey_redeemer() {
        let script = test_script();
        let old = sample_datum();
        let state = find_treasury_state(
            &[state_utxo(&script.hash_hex(), &old)],
            &script.hash_hex(),
            &nft_name(),
        )
        .unwrap();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_payment_key(mnemonic).unwrap();
        let wallet_addr = crate::cardano::wallet::wallet_address(&key);
        let wallet_utxos = vec![
            WalletUtxo::from_bf(&ada_bf_utxo(&"aa".repeat(32), 50_000_000)),
            WalletUtxo::from_bf(&ada_bf_utxo(&"bb".repeat(32), 50_000_000)),
        ];

        let new_key = [0xCDu8; 32];
        let req = UpdateYRequest {
            treasury_script: &script,
            state: &state,
            new_spos_frost_key: &new_key,
            epoch: 3,
            signature: &[0x00u8; 64], // structure test — on-chain sig check not simulated
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            invalid_before: None,
            invalid_hereafter: None,
            cost_models: None,
        };
        let built = build_update_y_tx(&req).unwrap();

        // Rotated datum: only the key changed.
        assert_eq!(built.new_datum.current_spos_frost_key, new_key.to_vec());
        assert_eq!(
            built.new_datum.bifrost_identity_root,
            old.bifrost_identity_root
        );
        assert_eq!(built.new_datum.y_federation, old.y_federation);
        assert_eq!(
            built.new_datum.federation_csv_blocks,
            old.federation_csv_blocks
        );

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        // The treasury state UTxO is spent.
        assert!(
            tx.transaction_body
                .inputs
                .iter()
                .any(|i| i.transaction_id.as_slice() == [0xdd; 32] && i.index == 0)
        );
        // A Spend redeemer is attached (its UpdateY = Constr 1 encoding is
        // unit-tested in treasury_info::update_y_redeemer_is_constr1_three_fields).
        let redeemers = tx.transaction_witness_set.redeemer.as_ref().unwrap();
        let has_spend = match redeemers {
            pallas_primitives::conway::Redeemers::List(rs) => rs
                .iter()
                .any(|r| matches!(r.tag, pallas_primitives::conway::RedeemerTag::Spend)),
            pallas_primitives::conway::Redeemers::Map(kv) => kv
                .iter()
                .any(|(k, _)| matches!(k.tag, pallas_primitives::conway::RedeemerTag::Spend)),
        };
        assert!(has_spend, "spend redeemer attached");
    }
}
