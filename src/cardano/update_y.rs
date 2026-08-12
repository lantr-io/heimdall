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
//! 3. a BIP340 signature over
//!    [`crate::cardano::treasury_info::update_y_sig_msg`], under the SPENT
//!    datum's `current_spos_frost_key` (the outgoing roster) OR, per spec
//!    [UY-5], under the SPENT datum's `y_federation` (the standing federation
//!    co-authority that replaces the removed `FederationReset` branch).
//!
//! The two authorizations build the SAME transaction: same redeemer, same
//! message, same datum transition. Per the withdrawal of [UY-6] the federation
//! MAY name any successor key. [`UpdateYAuthorizer`] names the key the caller
//! signed under; [`build_update_y_tx`] verifies the signature under that key
//! before building, so a wrong-key signature never reaches the chain.
//!
//! Submission is permissionless — the signature is the authorization — so this
//! tx needs no registry mint and no required signer beyond the fee payer.
//!
//! Unlike register_spo, the caller signs the message itself (the outgoing key is
//! the roster's, not this node's wallet key): locate the state
//! ([`crate::cardano::treasury_spend::find_treasury_state`]), sign the message,
//! then call [`build_update_y_tx`] with the resulting signature.

use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{Message, XOnlyPublicKey, schnorr};
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::publish::WalletUtxo;
use crate::cardano::treasury_info::{TreasuryInfoDatum, update_y_redeemer, update_y_sig_msg};
use crate::cardano::treasury_spend::{TreasuryStateUtxo, treasury_spend_leg};
use crate::cardano::tx_common::{select_collateral, select_fee, sign_built_tx};

#[derive(Debug)]
pub enum UpdateYError {
    /// `new_spos_frost_key` is not a 32-byte x-only key.
    BadNewKeyLen(usize),
    /// The BIP340 signature is not 64 bytes.
    BadSigLen(usize),
    /// The spent datum's key named by `UpdateYRequest::authorizer` is not a
    /// valid x-only point, so nothing could ever authorize under it.
    BadAuthorizerKey {
        role: &'static str,
        reason: String,
    },
    /// `epoch` is negative — the signed message encodes it as a u64.
    NegativeEpoch(i64),
    /// The signature does not verify over the Update-Y message under the
    /// spent datum's key named by `UpdateYRequest::authorizer`.
    SignatureInvalid {
        role: &'static str,
    },
    Wallet(String),
    Build(String),
}

impl std::fmt::Display for UpdateYError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadNewKeyLen(n) => write!(f, "new_spos_frost_key must be 32 bytes, got {n}"),
            Self::BadSigLen(n) => write!(f, "update-y signature must be 64 bytes, got {n}"),
            Self::BadAuthorizerKey { role, reason } => {
                write!(
                    f,
                    "spent datum's {role} is not a valid x-only key: {reason}"
                )
            }
            Self::NegativeEpoch(e) => write!(f, "epoch must be non-negative, got {e}"),
            Self::SignatureInvalid { role } => {
                write!(
                    f,
                    "signature does not verify under the spent datum's {role} — \
                     the key named by the authorizer must sign the Update-Y message"
                )
            }
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "build: {e}"),
        }
    }
}

impl std::error::Error for UpdateYError {}

/// Which SPENT-datum key authorized this Update-Y – i.e. which key produced
/// `UpdateYRequest::signature`. The built transaction is identical either way
/// (spec [UY-5]: the validator accepts either key over the same message);
/// [`build_update_y_tx`] verifies the signature under the named key and
/// rejects the request when it does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateYAuthorizer {
    /// The outgoing roster: the spent datum's `current_spos_frost_key`.
    Roster,
    /// The federation: the CONFIG's `y_federation` ([UY-5]). Rev 5.5 moved that
    /// key out of the treasury datum and into Config #11, so the co-authority is
    /// governance data now rather than state a rotation could disturb.
    Federation,
}

impl UpdateYAuthorizer {
    /// The key the signature must verify under, plus a name for error messages.
    /// The single place the authorizer is mapped to a key, so the builder and the
    /// CLI cannot disagree.
    ///
    /// The two now come from different UTxOs: the roster key from the SPENT
    /// datum, the federation key from the CONFIG ([UY-5], rev 5.5).
    #[must_use]
    pub fn signing_key<'a>(
        self,
        datum: &'a TreasuryInfoDatum,
        y_federation: &'a [u8; 32],
    ) -> (&'a [u8], &'static str) {
        match self {
            Self::Roster => (&datum.current_spos_frost_key, "current_spos_frost_key"),
            Self::Federation => (y_federation.as_slice(), "config y_federation"),
        }
    }
}

/// Inputs to [`build_update_y_tx`]. The treasury state UTxO must already be
/// located (so the caller could compute + sign the message it commits to).
pub struct UpdateYRequest<'a> {
    pub treasury_script: &'a ParameterizedScript,
    /// The located, decoded `treasury_info` state UTxO being spent.
    pub state: &'a TreasuryStateUtxo,
    /// The incoming roster's x-only Y_51' (32 bytes).
    pub new_spos_frost_key: &'a [u8],
    pub epoch: i64,
    /// 64-byte BIP340 signature over `update_y_sig_msg(state.tx_hash,
    /// state.output_index, epoch, new_key)`, under the SPENT-datum key named
    /// by `authorizer`.
    pub signature: &'a [u8],
    /// Which key produced `signature` (spec [UY-5]).
    pub authorizer: UpdateYAuthorizer,
    /// Config #11 `y_federation`, for the [UY-5] federation branch. Also what
    /// `treasury.ak` reads, so the builder verifies under the same key the
    /// validator will.
    pub y_federation: &'a [u8; 32],
    /// The Config UTxO, added to the tx as a REFERENCE input. `treasury.ak`
    /// reads `y_federation` from it (spec [TSY-12]) and locates it by the index
    /// below, never by scanning.
    pub config_ref: (&'a str, u32),
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
///
/// `req.authorizer` does not change the built bytes: the roster and federation
/// branches share one redeemer and one signed message ([UY-5] – the validator
/// verifies the signature against either key). It DOES select the datum key
/// this builder verifies `req.signature` under, mirroring the on-chain check
/// (like `register_spo::verify_registration`): a signature made under the
/// wrong key is rejected here instead of failing phase-2 validation on chain
/// and forfeiting collateral.
pub fn build_update_y_tx(req: &UpdateYRequest) -> Result<UpdateYTx, UpdateYError> {
    if req.new_spos_frost_key.len() != 32 {
        return Err(UpdateYError::BadNewKeyLen(req.new_spos_frost_key.len()));
    }
    if req.signature.len() != 64 {
        return Err(UpdateYError::BadSigLen(req.signature.len()));
    }

    // Verify the BIP340 signature under the spent datum's key named by
    // `authorizer`, over the same message treasury.ak checks ([UY-5]).
    let (authorizer_key, role) = req
        .authorizer
        .signing_key(&req.state.datum, req.y_federation);
    let xonly =
        XOnlyPublicKey::from_slice(authorizer_key).map_err(|e| UpdateYError::BadAuthorizerKey {
            role,
            reason: e.to_string(),
        })?;
    let spent_txid: [u8; 32] = hex::decode(&req.state.tx_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| {
            UpdateYError::Build(format!(
                "state tx_hash is not 32-byte hex: {}",
                req.state.tx_hash
            ))
        })?;
    let epoch = u64::try_from(req.epoch).map_err(|_| UpdateYError::NegativeEpoch(req.epoch))?;
    let msg = update_y_sig_msg(
        &spent_txid,
        req.state.output_index,
        epoch,
        req.new_spos_frost_key,
    );
    let sig = schnorr::Signature::from_slice(req.signature)
        .map_err(|_| UpdateYError::BadSigLen(req.signature.len()))?;
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(msg), &xonly)
        .map_err(|_| UpdateYError::SignatureInvalid { role })?;

    let network = crate::cardano::tx_common::network_from_address(req.wallet_address);

    // Only current_spos_frost_key changes; treasury.ak asserts
    // bifrost_identity_root is untouched ([TSY-17]). Rev 5.5 also reads the new
    // key FROM this datum rather than from the redeemer, which is safe because
    // the signed message commits to it.
    let mut new_datum = req.state.datum.clone();
    new_datum.current_spos_frost_key = req.new_spos_frost_key.to_vec();

    // The Config is the only reference input, so its index is 0.
    let redeemer = update_y_redeemer(req.epoch, req.signature, 0);
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
        reference_inputs: vec![RefTxIn {
            tx_hash: req.config_ref.0.to_string(),
            tx_index: req.config_ref.1,
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
        .map_err(|e| UpdateYError::Build(format!("whisky tx build: {e:?}")))?;

    let signed_tx_hex = sign_built_tx(&unsigned_hex, req.key).map_err(UpdateYError::Build)?;
    Ok(UpdateYTx {
        signed_tx_hex,
        new_datum,
    })
}

#[cfg(test)]
mod tests {
    /// The Config UTxO the tx references so `treasury.ak` can read #11
    /// `y_federation` (spec [TSY-12]).
    const CONFIG_REF_TX: &str = "cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11";
    use super::*;
    use crate::cardano::bf_http::{BfAmount, BfUtxo};
    use crate::cardano::blueprint;
    use crate::cardano::mpf;
    use crate::cardano::treasury_spend::find_treasury_state;
    use crate::cardano::wallet::derive_payment_key;
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::{Keypair, Message, SecretKey, XOnlyPublicKey, schnorr};
    use pallas_codec::minicbor;
    use pallas_primitives::PlutusData;
    use pallas_primitives::conway::Tx;

    /// The txid of the fixture treasury state UTxO every test spends
    /// (`STATE_TXID:0`), as bytes; `state_utxo` reports it in hex.
    const STATE_TXID: [u8; 32] = [0xdd; 32];

    /// Deterministic secp keypair from a repeated seed byte (valid scalar for
    /// the bytes used here) plus its 32-byte x-only public key.
    fn test_keypair(seed: u8) -> (Keypair, [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        (kp, kp.x_only_public_key().0.serialize())
    }

    /// The Update-Y message committing to the fixture state outpoint.
    fn update_y_msg(epoch: u64, new_key: &[u8; 32]) -> [u8; 32] {
        crate::cardano::treasury_info::update_y_sig_msg(&STATE_TXID, 0, epoch, new_key)
    }

    /// BIP340-sign the Update-Y message for the fixture state outpoint with `kp`.
    fn sign_update_y(kp: &Keypair, epoch: u64, new_key: &[u8; 32]) -> [u8; 64] {
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(update_y_msg(epoch, new_key)), kp)
            .serialize()
    }

    /// Pull the 64-byte signature out of the Spend redeemer of a built tx
    /// (`UpdateY` = Constr 1 `[new_key, epoch, signature]`).
    fn redeemer_signature(signed_tx_hex: &str) -> [u8; 64] {
        let tx: Tx = minicbor::decode(&hex::decode(signed_tx_hex).unwrap()).unwrap();
        let redeemers = tx.transaction_witness_set.redeemer.as_ref().unwrap();
        let data = match redeemers {
            pallas_primitives::conway::Redeemers::List(rs) => rs
                .iter()
                .find(|r| matches!(r.tag, pallas_primitives::conway::RedeemerTag::Spend))
                .map(|r| r.data.clone()),
            pallas_primitives::conway::Redeemers::Map(kv) => kv
                .iter()
                .find(|(k, _)| matches!(k.tag, pallas_primitives::conway::RedeemerTag::Spend))
                .map(|(_, v)| v.data.clone()),
        }
        .expect("spend redeemer attached");
        let PlutusData::Constr(constr) = data else {
            panic!("UpdateY redeemer must be a Constr");
        };
        let fields: Vec<_> = constr.fields.iter().collect();
        assert_eq!(
            fields.len(),
            3,
            "rev 5.5 UpdateY carries [epoch, sig, config_ref_input_index]"
        );
        let PlutusData::BoundedBytes(sig) = fields[1] else {
            panic!("second UpdateY field must be the signature bytes");
        };
        sig.to_vec().try_into().expect("64-byte signature")
    }

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

    fn sample_datum(current_spos_frost_key: Vec<u8>) -> TreasuryInfoDatum {
        TreasuryInfoDatum {
            bifrost_identity_root: mpf::NULL_HASH,
            current_spos_frost_key,
        }
    }

    fn nft_name() -> String {
        "ee".repeat(32)
    }

    /// The located, decoded fixture state UTxO holding `datum` at `script`.
    fn located_state(
        script: &blueprint::ParameterizedScript,
        datum: &TreasuryInfoDatum,
    ) -> TreasuryStateUtxo {
        find_treasury_state(
            &[state_utxo(&script.hash_hex(), datum)],
            &script.hash_hex(),
            &nft_name(),
        )
        .unwrap()
    }

    /// A funded fee payer: the derived key, its address, and two pure-ADA
    /// UTxOs (one pays the fee, one is collateral).
    fn test_wallet() -> (PrivateKey, String, Vec<WalletUtxo>) {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_payment_key(mnemonic).unwrap();
        let addr = crate::cardano::wallet::wallet_address(&key);
        let utxos = vec![
            WalletUtxo::from_bf(&ada_bf_utxo(&"aa".repeat(32), 50_000_000)),
            WalletUtxo::from_bf(&ada_bf_utxo(&"bb".repeat(32), 50_000_000)),
        ];
        (key, addr, utxos)
    }

    fn state_utxo(policy_hex: &str, datum: &TreasuryInfoDatum) -> BfUtxo {
        BfUtxo {
            tx_hash: hex::encode(STATE_TXID),
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
        let (roster_kp, roster_pk) = test_keypair(0xA1);
        let old = sample_datum(roster_pk.to_vec());
        let fed_pk = [0xCDu8; 32];
        let state = located_state(&script, &old);
        let (key, wallet_addr, wallet_utxos) = test_wallet();

        let new_key = [0xCDu8; 32];
        let signature = sign_update_y(&roster_kp, 3, &new_key);
        let req = UpdateYRequest {
            treasury_script: &script,
            state: &state,
            new_spos_frost_key: &new_key,
            epoch: 3,
            signature: &signature,
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            invalid_before: None,
            invalid_hereafter: None,
            cost_models: None,
            authorizer: UpdateYAuthorizer::Roster,
            y_federation: &fed_pk,
            config_ref: (CONFIG_REF_TX, 0),
        };
        let built = build_update_y_tx(&req).unwrap();

        // Rotated datum: only the key changed.
        assert_eq!(built.new_datum.current_spos_frost_key, new_key.to_vec());
        assert_eq!(
            built.new_datum.bifrost_identity_root,
            old.bifrost_identity_root
        );

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        // The treasury state UTxO is spent.
        assert!(
            tx.transaction_body
                .inputs
                .iter()
                .any(|i| i.transaction_id.as_slice() == STATE_TXID && i.index == 0)
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

    // spec [UY-5]: an Update-Y is equally authorized by a BIP340 signature under
    // the SPENT datum's `y_federation` — the standing federation co-authority
    // that replaces the removed FederationReset branch. [UY-6] is withdrawn: the
    // federation MAY name ANY successor key (here one that is neither the old
    // roster key nor `y_federation` itself). The signature is made under the
    // real federation key; the builder accepts it, and the signature carried in
    // the built UpdateY redeemer BIP340-verifies against the spent datum's
    // y_federation over the Update-Y message.
    #[test]
    fn update_y_accepts_federation_key_authorization() {
        let script = test_script();
        let (fed_kp, fed_pk) = test_keypair(0xB2);
        // Roster key is junk: the federation branch must never consult it.
        let old = sample_datum(vec![0xABu8; 32]);
        let state = located_state(&script, &old);
        let (key, wallet_addr, wallet_utxos) = test_wallet();

        // Any successor key: distinct from both the roster key and
        // y_federation ([UY-6] withdrawn — no restriction on the named key).
        let successor = [0x55u8; 32];
        let signature = sign_update_y(&fed_kp, 12, &successor);
        let req = UpdateYRequest {
            treasury_script: &script,
            state: &state,
            new_spos_frost_key: &successor,
            epoch: 12,
            signature: &signature,
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            invalid_before: None,
            invalid_hereafter: None,
            cost_models: None,
            authorizer: UpdateYAuthorizer::Federation,
            y_federation: &fed_pk,
            config_ref: (CONFIG_REF_TX, 0),
        };
        let built = build_update_y_tx(&req).unwrap();

        // The rotation is an ordinary Update-Y: only the key changes, to the
        // arbitrary successor; y_federation itself is preserved.
        assert_eq!(built.new_datum.current_spos_frost_key, successor.to_vec());
        assert_eq!(
            built.new_datum.bifrost_identity_root,
            old.bifrost_identity_root
        );

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        // The treasury state UTxO is spent — same shape as the roster rotation.
        assert!(
            tx.transaction_body
                .inputs
                .iter()
                .any(|i| i.transaction_id.as_slice() == STATE_TXID && i.index == 0)
        );
        // The authorization travelling on-chain IS a BIP340 signature under
        // y_federation: pull it back out of the Spend redeemer and verify it
        // against the spent datum's y_federation over the Update-Y message.
        let carried = redeemer_signature(&built.signed_tx_hex);
        assert_eq!(carried, signature, "redeemer carries the signature");
        let msg = update_y_msg(12, &successor);
        Secp256k1::verification_only()
            .verify_schnorr(
                &schnorr::Signature::from_slice(&carried).unwrap(),
                &Message::from_digest(msg),
                &XOnlyPublicKey::from_slice(&fed_pk).unwrap(),
            )
            .expect("redeemer signature verifies under y_federation");
    }

    // The `authorizer` field is load-bearing: the builder verifies the BIP340
    // signature under the datum key it names, before any fee is spent. A
    // signature made under the OTHER datum key must be rejected client-side —
    // on-chain it would fail phase-2 validation and forfeit collateral.
    #[test]
    fn rejects_signature_under_the_wrong_datum_key() {
        let script = test_script();
        let (roster_kp, roster_pk) = test_keypair(0xA1);
        let (fed_kp, fed_pk) = test_keypair(0xB2);
        let old = sample_datum(roster_pk.to_vec());
        let state = located_state(&script, &old);
        let (key, wallet_addr, wallet_utxos) = test_wallet();

        let new_key = [0x55u8; 32];
        let roster_sig = sign_update_y(&roster_kp, 12, &new_key);
        let fed_sig = sign_update_y(&fed_kp, 12, &new_key);

        let build = |signature: &[u8; 64], authorizer: UpdateYAuthorizer| {
            build_update_y_tx(&UpdateYRequest {
                treasury_script: &script,
                state: &state,
                new_spos_frost_key: &new_key,
                epoch: 12,
                signature,
                wallet_address: &wallet_addr,
                wallet_utxos: &wallet_utxos,
                key: &key,
                invalid_before: None,
                invalid_hereafter: None,
                cost_models: None,
                authorizer,
                y_federation: &fed_pk,
                config_ref: (CONFIG_REF_TX, 0),
            })
        };

        // Roster-signed but claimed as federation-authorized: rejected.
        assert!(matches!(
            build(&roster_sig, UpdateYAuthorizer::Federation),
            Err(UpdateYError::SignatureInvalid {
                role: "config y_federation"
            })
        ));
        // Federation-signed but claimed as roster-authorized: rejected.
        assert!(matches!(
            build(&fed_sig, UpdateYAuthorizer::Roster),
            Err(UpdateYError::SignatureInvalid {
                role: "current_spos_frost_key"
            })
        ));
        // Both verify when the authorizer names the key that actually signed.
        assert!(build(&fed_sig, UpdateYAuthorizer::Federation).is_ok());
        assert!(build(&roster_sig, UpdateYAuthorizer::Roster).is_ok());
    }
}
