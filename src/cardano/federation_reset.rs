//! Federation reset: the emergency dead-roster recovery (technical_documentation
//! §Update-Y — federation reset variant). When a roster is permanently dead an
//! ordinary Update-Y cannot rotate the key (it needs the *current* roster's
//! signature). The reset breaks the deadlock: it rotates `current_spos_frost_key`
//! back to the datum's own `y_federation` (Phase-1 federation key), and ONLY to
//! that, so the bridge returns to federation key-path signing while the roster
//! rebuilds.
//!
//! `treasury.ak`'s `FederationReset` branch spends the `treasury_info` state UTxO
//! and requires, in the SAME transaction:
//!
//! 1. a continuing output at the SAME address with the SAME value,
//! 2. its inline datum equal to the spent datum with `current_spos_frost_key`
//!    replaced by `y_federation` and `last_reset_tm_txid` set to the referenced
//!    TM's `btc_txid` (every other field preserved),
//! 3. a REFERENCE input to a Confirmed TM (authenticated by the TM NFT, at
//!    `tm_ref_input_index` in the tx's reference inputs) whose
//!    `spent_via_federation_leaf` flag is set and whose `btc_txid !=
//!    last_reset_tm_txid` (freshness / anti-replay),
//! 4. a BIP340 signature under `y_federation` over
//!    [`crate::cardano::treasury_info::federation_reset_sig_msg`].
//!
//! Like Update-Y this is permissionless (the federation signature is the
//! authorization) and air-gapped: the caller locates the state
//! ([`crate::cardano::treasury_spend::find_treasury_state`]) and the Confirmed
//! federation-sweep TM, computes + signs the message under `y_federation`, then
//! calls [`build_federation_reset_tx`].
//!
//! The treasury script is provided INLINE (a witness, not a reference input — see
//! [`crate::cardano::treasury_spend::treasury_spend_leg`]), so the Confirmed TM is
//! the ONLY reference input and its `tm_ref_input_index` is deterministically 0.

use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::publish::WalletUtxo;
use crate::cardano::treasury_info::{TreasuryInfoDatum, federation_reset_redeemer};
use crate::cardano::treasury_spend::{TreasuryStateUtxo, treasury_spend_leg};
use crate::cardano::tx_common::{select_collateral, select_fee, sign_built_tx};

/// The referenced Confirmed federation-sweep TM: the UTxO to add as a reference
/// input, plus the `btc_txid` (32 bytes, internal order) the reset writes into
/// `last_reset_tm_txid`. Its `spent_via_federation_leaf` flag must be set and its
/// `btc_txid` must differ from the state's current `last_reset_tm_txid` — the
/// caller checks both when it locates the TM (the on-chain branch re-checks).
#[derive(Debug, Clone)]
pub struct ConfirmedTmRef {
    pub tx_hash: String,
    pub output_index: u32,
    /// The Confirmed TM's `btc_txid` (internal/32-byte order), copied from its
    /// datum — written verbatim into the reset datum's `last_reset_tm_txid`.
    pub btc_txid: Vec<u8>,
}

#[derive(Debug)]
pub enum FederationResetError {
    /// The BIP340 signature is not 64 bytes.
    BadSigLen(usize),
    /// The referenced TM `btc_txid` is not 32 bytes.
    BadTmTxidLen(usize),
    /// The spent datum's `y_federation` is not a 32-byte x-only key.
    BadYFederationLen(usize),
    /// The referenced TM `btc_txid` equals the state's `last_reset_tm_txid` — a
    /// stale sweep the on-chain freshness guard would reject.
    StaleSweep,
    Wallet(String),
    Build(String),
}

impl std::fmt::Display for FederationResetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSigLen(n) => write!(f, "reset signature must be 64 bytes, got {n}"),
            Self::BadTmTxidLen(n) => write!(f, "referenced TM btc_txid must be 32 bytes, got {n}"),
            Self::BadYFederationLen(n) => write!(f, "y_federation must be 32 bytes, got {n}"),
            Self::StaleSweep => write!(
                f,
                "referenced TM btc_txid == last_reset_tm_txid (stale sweep; on-chain \
                 freshness guard would reject the reset)"
            ),
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "build: {e}"),
        }
    }
}

impl std::error::Error for FederationResetError {}

/// Inputs to [`build_federation_reset_tx`]. The state UTxO and the Confirmed TM
/// must already be located (so the caller could compute + sign the message and
/// copy the TM's `btc_txid`).
pub struct FederationResetRequest<'a> {
    pub treasury_script: &'a ParameterizedScript,
    /// The located, decoded `treasury_info` state UTxO being spent.
    pub state: &'a TreasuryStateUtxo,
    /// The Confirmed federation-sweep TM to reference (dead-roster evidence).
    pub tm_ref: &'a ConfirmedTmRef,
    pub epoch: i64,
    /// 64-byte BIP340 signature under the SPENT datum's `y_federation` over
    /// `federation_reset_sig_msg(state.tx_hash, state.output_index, epoch,
    /// y_federation)`.
    pub signature: &'a [u8],
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    /// Fee-paying wallet key (any funded key — submission is permissionless).
    pub key: &'a PrivateKey,
    pub invalid_before: Option<u64>,
    pub invalid_hereafter: Option<u64>,
    pub cost_models: Option<Vec<Vec<i64>>>,
}

/// A built (signed, unsubmitted) FederationReset tx.
#[derive(Debug, Clone)]
pub struct FederationResetTx {
    pub signed_tx_hex: String,
    /// The reset datum written to the continuing treasury output.
    pub new_datum: TreasuryInfoDatum,
}

/// Build + sign the FederationReset tx: spend the treasury state UTxO with the
/// `FederationReset` redeemer, reference the Confirmed federation-sweep TM,
/// reproduce the state at the same address/value with `current_spos_frost_key`
/// rotated to `y_federation` and `last_reset_tm_txid` set to the TM's `btc_txid`,
/// and pay the fee from the wallet.
pub fn build_federation_reset_tx(
    req: &FederationResetRequest,
) -> Result<FederationResetTx, FederationResetError> {
    if req.signature.len() != 64 {
        return Err(FederationResetError::BadSigLen(req.signature.len()));
    }
    if req.tm_ref.btc_txid.len() != 32 {
        return Err(FederationResetError::BadTmTxidLen(
            req.tm_ref.btc_txid.len(),
        ));
    }
    if req.state.datum.y_federation.len() != 32 {
        return Err(FederationResetError::BadYFederationLen(
            req.state.datum.y_federation.len(),
        ));
    }
    // Freshness: the on-chain branch requires btc_txid != last_reset_tm_txid.
    // Fail fast off-chain rather than build a tx the script will reject.
    if req.tm_ref.btc_txid == req.state.datum.last_reset_tm_txid {
        return Err(FederationResetError::StaleSweep);
    }

    let network = crate::cardano::tx_common::network_from_address(req.wallet_address);

    // Rotate ONLY current_spos_frost_key -> y_federation and advance the reset
    // anchor to the consumed sweep's txid — mirrors treasury.ak's record-update
    // spread; every other field is copied from the spent datum verbatim.
    let mut new_datum = req.state.datum.clone();
    new_datum.current_spos_frost_key = req.state.datum.y_federation.clone();
    new_datum.last_reset_tm_txid = req.tm_ref.btc_txid.clone();

    // The treasury script is inline, so the Confirmed TM is the ONLY reference
    // input → index 0.
    let redeemer = federation_reset_redeemer(0, req.epoch, req.signature);
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
    let fee_utxo = select_fee(req.wallet_utxos, 2_000_000).map_err(FederationResetError::Wallet)?;
    let coll_utxo =
        select_collateral(req.wallet_utxos, &[fee_utxo]).map_err(FederationResetError::Wallet)?;

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
        // The dead-roster evidence: the Confirmed federation-sweep TM. Sole
        // reference input, so `tm_ref_input_index` in the redeemer is 0.
        reference_inputs: vec![RefTxIn {
            tx_hash: req.tm_ref.tx_hash.clone(),
            tx_index: req.tm_ref.output_index,
            script_size: None,
        }],
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
        .map_err(|e| FederationResetError::Build(format!("whisky tx build: {e:?}")))?;

    let signed_tx_hex =
        sign_built_tx(&unsigned_hex, req.key).map_err(FederationResetError::Build)?;
    Ok(FederationResetTx {
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
            current_spos_frost_key: vec![0xABu8; 32], // a live roster key
            y_federation: vec![0xFEu8; 32],
            federation_csv_blocks: 144,
            last_reset_tm_txid: vec![], // no prior reset
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

    // Assemble the FederationReset tx offline and prove it survives into the wire
    // format: the state is spent, the continuing output rotates the key to
    // y_federation and records the consumed sweep's txid, and the Confirmed TM is
    // attached as the sole reference input.
    #[test]
    fn builds_a_reset_tx_rotating_to_y_federation() {
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

        let tm_btc_txid = vec![0x33u8; 32];
        let tm_ref = ConfirmedTmRef {
            tx_hash: "cc".repeat(32),
            output_index: 0,
            btc_txid: tm_btc_txid.clone(),
        };
        let req = FederationResetRequest {
            treasury_script: &script,
            state: &state,
            tm_ref: &tm_ref,
            epoch: 9,
            signature: &[0x00u8; 64], // structure test — on-chain sig check not simulated
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            invalid_before: None,
            invalid_hereafter: None,
            cost_models: None,
        };
        let built = build_federation_reset_tx(&req).unwrap();

        // Reset datum: key -> y_federation, last_reset_tm_txid -> the sweep txid,
        // everything else preserved.
        assert_eq!(built.new_datum.current_spos_frost_key, old.y_federation);
        assert_eq!(built.new_datum.last_reset_tm_txid, tm_btc_txid);
        assert_eq!(built.new_datum.y_federation, old.y_federation);
        assert_eq!(
            built.new_datum.bifrost_identity_root,
            old.bifrost_identity_root
        );
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
        // The Confirmed TM is referenced (the dead-roster evidence).
        let refs = tx
            .transaction_body
            .reference_inputs
            .as_ref()
            .expect("a reference input is present");
        assert_eq!(refs.len(), 1);
        assert!(
            refs.iter()
                .any(|i| i.transaction_id.as_slice() == [0xcc; 32] && i.index == 0)
        );
    }

    /// A stale sweep (btc_txid == last_reset_tm_txid) is refused off-chain before
    /// building a tx the on-chain freshness guard would reject.
    #[test]
    fn stale_sweep_is_refused() {
        let script = test_script();
        let mut old = sample_datum();
        old.last_reset_tm_txid = vec![0x33u8; 32]; // already reset by this txid
        let state = find_treasury_state(
            &[state_utxo(&script.hash_hex(), &old)],
            &script.hash_hex(),
            &nft_name(),
        )
        .unwrap();
        let key = derive_payment_key(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let wallet_addr = crate::cardano::wallet::wallet_address(&key);
        let wallet_utxos = vec![WalletUtxo::from_bf(&ada_bf_utxo(
            &"aa".repeat(32),
            50_000_000,
        ))];
        let tm_ref = ConfirmedTmRef {
            tx_hash: "cc".repeat(32),
            output_index: 0,
            btc_txid: vec![0x33u8; 32], // same as last_reset_tm_txid
        };
        let req = FederationResetRequest {
            treasury_script: &script,
            state: &state,
            tm_ref: &tm_ref,
            epoch: 9,
            signature: &[0x00u8; 64],
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            invalid_before: None,
            invalid_hereafter: None,
            cost_models: None,
        };
        assert!(matches!(
            build_federation_reset_tx(&req),
            Err(FederationResetError::StaleSweep)
        ));
    }
}
