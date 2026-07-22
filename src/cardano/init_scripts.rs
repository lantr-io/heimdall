//! Script reward-account initialization — the `init-scripts` transaction.
//!
//! Bitfrost validators authorize through the **withdraw-zero** pattern: a
//! zero-amount reward withdrawal from the script's own stake credential, which
//! forces the script to run and lets one script cover several purposes in one
//! transaction. Conway only admits a withdrawal whose reward account is
//! **registered on chain**, so every such script needs a one-time stake
//! registration before its first withdraw — otherwise submission fails with
//!
//!     ConwayCertsFailure (WithdrawalsNotInRewardsCERTS … ScriptHashObj …)
//!
//! Registration cannot be folded into the withdrawing transaction: certificates
//! validate against the **pre-transaction** ledger state, so a withdrawal in the
//! same tx still sees an unregistered account.
//!
//! Scope: the withdraw-using scripts *heimdall* deploys — today `spo_bans`
//! alone. `peg_in`/`peg_out` are registered by binocular's `deploy-bridge`
//! (atomically, in the bootstrap tx) and its idempotent `register-bridge-creds`;
//! registering them from here would duplicate that and break a canonically
//! deployed instance, since re-registering an existing credential is a ledger
//! error.
//!
//! The certificate needs no witness from the credential it registers — only
//! *de*registration runs the script — so this tx carries no redeemer, no script
//! witness and no collateral.

use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_common::{Certificate, CertificateType, RegisterStake};
use whisky_pallas::WhiskyPallas;

use crate::cardano::publish::WalletUtxo;
use crate::cardano::tx_common::{select_fee, sign_built_tx, whisky_network};
use crate::cardano::wallet::pub_key_hash_hex;

/// One withdraw-using script to register, named for operator output.
///
/// `reward_address` must come from `ParameterizedScript::reward_address` — the
/// same call that keys the corresponding withdrawal (see `apply_ban.rs`), so the
/// registered credential cannot drift from the withdrawn one.
#[derive(Debug, Clone)]
pub struct WithdrawScript {
    /// Blueprint name, e.g. `spo_bans`.
    pub name: &'static str,
    /// Script hash (hex) — printed so an operator can see which instance is
    /// being initialized.
    pub hash_hex: String,
    /// Bech32 reward address of the script hash used as a stake credential.
    pub reward_address: String,
}

/// A built (signed, unsubmitted) init transaction.
#[derive(Debug, Clone)]
pub struct InitScriptsTx {
    pub signed_tx_hex: String,
    /// Total deposit locked by this tx (`key_deposit` × certificates).
    pub deposit_total: u64,
}

/// Build the init transaction: one legacy `stake_registration` certificate per
/// script, paid and signed by the wallet.
///
/// `key_deposit` is the protocol's stake-key deposit, which the registration
/// locks per certificate (refundable only by deregistration).
pub fn build_init_scripts_tx(
    scripts: &[WithdrawScript],
    key_deposit: u64,
    wallet_address: &str,
    wallet_utxos: &[WalletUtxo],
    key: &PrivateKey,
    cost_models: Option<Vec<Vec<i64>>>,
) -> Result<InitScriptsTx, String> {
    if scripts.is_empty() {
        return Err("no scripts to register".to_string());
    }
    let deposit_total = key_deposit
        .checked_mul(scripts.len() as u64)
        .ok_or("deposit total overflows")?;

    // No scripts execute here, so a fee input is all this tx needs — no
    // collateral. The input must additionally cover the deposits, which leave
    // the transaction for the deposit pot rather than returning as change.
    let fee_utxo = select_fee(wallet_utxos, deposit_total + 1_000_000)?;

    // whisky's change balancer DROPS the deposit for legacy StakeRegistration
    // certificates: the `Certificate::StakeRegistration` arm of core_pallas.rs
    // calls `change_value.sub(..)` and discards the result — `Value::sub` takes
    // `&self` and returns a new value, so the line is a no-op. Every other
    // deposit-bearing arm (Reg, StakeRegDeleg, PoolRegistration) assigns. Left
    // alone the change output is `key_deposit` per certificate too high and the
    // node rejects the tx with ValueNotConservedUTxO. (This is why register_pool
    // works today: it goes through StakeRegistrationAndDelegation, a different
    // arm.)
    //
    // It cannot be corrected through the outputs or the declared fee: whisky
    // always lands on `outputs = inputs - fee`, whereas the ledger requires
    // `outputs = inputs - fee - deposits`. An explicit output shrinks change by
    // exactly what it adds; a padded fee shrinks change but is then itself
    // charged.
    //
    // So correct it on the input side. whisky computes change from the
    // *declared* input amounts (`inputs_map`, fed by `TxInParameter.amount`),
    // and a serialized transaction input is only (tx_hash, index) — the declared
    // amount never reaches the CBOR. Under-declaring the fee input by
    // `deposit_total` therefore makes whisky's own arithmetic produce exactly
    // the change the ledger wants, with no post-hoc CBOR surgery, and keeps the
    // fee estimate consistent with the change output actually emitted.
    let declared_input = fee_utxo
        .lovelace
        .checked_sub(deposit_total)
        .ok_or_else(|| {
            format!(
                "fee UTxO ({} lovelace) cannot cover {} certificate deposit(s) of {key_deposit}",
                fee_utxo.lovelace,
                scripts.len()
            )
        })?;

    let certificates: Vec<Certificate> = scripts
        .iter()
        .map(|s| {
            Certificate::BasicCertificate(CertificateType::RegisterStake(RegisterStake {
                stake_key_address: s.reward_address.clone(),
                // Dropped by whisky for the legacy cert (tag 0 carries no
                // explicit deposit); kept to state the intent.
                coin: key_deposit,
            }))
        })
        .collect();

    let body = TxBuilderBody {
        inputs: vec![TxIn::PubKeyTxIn(PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: fee_utxo.tx_hash.clone(),
                tx_index: fee_utxo.output_index,
                amount: Some(vec![Asset::new_from_str(
                    "lovelace",
                    &declared_input.to_string(),
                )]),
                address: Some(wallet_address.to_string()),
            },
        })],
        // Everything not spent on fee and deposits returns as change.
        outputs: vec![],
        collaterals: vec![],
        required_signatures: vec![pub_key_hash_hex(key)],
        change_address: wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(&cost_models)),
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![],
        certificates,
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

    Ok(InitScriptsTx {
        signed_tx_hex,
        deposit_total,
    })
}

/// True when a submission error says the credential is already registered.
///
/// Idempotency backstop for backends whose `/accounts` route we cannot trust
/// (yaci-store does not implement every Blockfrost route). Re-registering is
/// rejected in **phase 1**, so an optimistic attempt costs nothing — and this
/// turns that rejection into the success it semantically is.
#[must_use]
pub fn is_already_registered_error(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    // Conway: StakeKeyAlreadyRegisteredDELEG. Older eras spell it
    // StakeKeyAlreadyRegisteredDELEG / StakeKeyNonZeroAccountBalanceDELEG; the
    // substring below covers the registered-already family without pinning the
    // era suffix.
    e.contains("alreadyregistered")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::register_pool::normal_key_from_seed;
    use pallas_codec::minicbor;
    use pallas_primitives::conway::Tx;

    /// The wallet address matching `key` — an enterprise testnet address over
    /// the key's own hash, so it agrees with the `required_signatures` entry
    /// the builder derives from the same key.
    fn wallet_addr(key: &PrivateKey) -> String {
        use crate::cardano::register_pool::key_hash;
        use pallas_addresses::{
            Address, Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
        };
        Address::Shelley(ShelleyAddress::new(
            Network::Testnet,
            ShelleyPaymentPart::key_hash(key_hash(key).into()),
            ShelleyDelegationPart::Null,
        ))
        .to_bech32()
        .expect("bech32")
    }

    fn utxo(lovelace: u64) -> WalletUtxo {
        WalletUtxo {
            tx_hash: "a".repeat(64),
            output_index: 0,
            lovelace,
            pure_ada: true,
        }
    }

    /// The reward address of an arbitrary script hash — shape only; the test
    /// cares about ledger conservation, not which script it is.
    fn reward_addr(tag: u8) -> String {
        use crate::cardano::blueprint::ParameterizedScript;
        ParameterizedScript {
            cbor: vec![],
            hash: [tag; 28],
        }
        .reward_address(false)
    }

    /// The whole point of the input-side deposit correction: the built tx must
    /// satisfy the ledger's conservation rule
    /// `inputs = outputs + fee + deposits`. Without the correction the change
    /// output is `key_deposit` per certificate too high and the node rejects
    /// with ValueNotConservedUTxO.
    #[test]
    fn built_tx_conserves_value_across_fee_and_deposits() {
        let key = normal_key_from_seed([7u8; 32]);
        let input_lovelace = 5_000_000_000u64;
        let key_deposit = 2_000_000u64;
        let scripts = vec![
            WithdrawScript {
                name: "spo_bans",
                hash_hex: hex::encode([0x9du8; 28]),
                reward_address: reward_addr(0x9d),
            },
            WithdrawScript {
                name: "second",
                hash_hex: hex::encode([0x4eu8; 28]),
                reward_address: reward_addr(0x4e),
            },
        ];

        let built = build_init_scripts_tx(
            &scripts,
            key_deposit,
            &wallet_addr(&key),
            &[utxo(input_lovelace)],
            &key,
            None,
        )
        .expect("build");

        assert_eq!(built.deposit_total, 2 * key_deposit);

        let bytes = hex::decode(&built.signed_tx_hex).expect("hex");
        let tx: Tx = minicbor::decode(&bytes).expect("decode");
        let body = &tx.transaction_body;

        let outputs: u64 = body
            .outputs
            .iter()
            .map(|o| match o {
                pallas_primitives::conway::PseudoTransactionOutput::PostAlonzo(o) => {
                    match &o.value {
                        pallas_primitives::conway::Value::Coin(c) => *c,
                        pallas_primitives::conway::Value::Multiasset(c, _) => *c,
                    }
                }
                pallas_primitives::conway::PseudoTransactionOutput::Legacy(o) => match &o.amount {
                    pallas_primitives::alonzo::Value::Coin(c) => *c,
                    pallas_primitives::alonzo::Value::Multiasset(c, _) => *c,
                },
            })
            .sum();

        assert_eq!(
            input_lovelace,
            outputs + body.fee + built.deposit_total,
            "inputs must equal outputs + fee + deposits (outputs={outputs} fee={} deposits={})",
            body.fee,
            built.deposit_total
        );
    }

    /// One certificate per script, and the tx runs no scripts.
    #[test]
    fn emits_one_certificate_per_script_and_no_witnesses() {
        let key = normal_key_from_seed([7u8; 32]);
        let scripts = vec![WithdrawScript {
            name: "spo_bans",
            hash_hex: hex::encode([0x9du8; 28]),
            reward_address: reward_addr(0x9d),
        }];
        let built = build_init_scripts_tx(
            &scripts,
            2_000_000,
            &wallet_addr(&key),
            &[utxo(100_000_000)],
            &key,
            None,
        )
        .expect("build");

        let bytes = hex::decode(&built.signed_tx_hex).expect("hex");
        let tx: Tx = minicbor::decode(&bytes).expect("decode");
        let certs = tx
            .transaction_body
            .certificates
            .as_ref()
            .expect("certificates present");
        assert_eq!(certs.len(), 1);
        assert!(
            matches!(
                certs[0],
                pallas_primitives::conway::Certificate::StakeRegistration(
                    pallas_primitives::conway::StakeCredential::ScriptHash(_)
                )
            ),
            "expected a script-credential stake registration, got {:?}",
            certs[0]
        );
        assert!(
            tx.transaction_witness_set.redeemer.is_none(),
            "registration runs no script — no redeemers"
        );
        assert!(
            tx.transaction_body.collateral.is_none(),
            "registration runs no script — no collateral"
        );
    }

    #[test]
    fn rejects_a_fee_utxo_too_small_for_the_deposits() {
        let key = normal_key_from_seed([7u8; 32]);
        let scripts = vec![WithdrawScript {
            name: "spo_bans",
            hash_hex: hex::encode([0x9du8; 28]),
            reward_address: reward_addr(0x9d),
        }];
        // select_fee's floor (deposit + 1 ADA) rejects before the subtraction.
        let err = build_init_scripts_tx(
            &scripts,
            2_000_000,
            &wallet_addr(&key),
            &[utxo(2_500_000)],
            &key,
            None,
        )
        .expect_err("must not build");
        assert!(err.contains("cannot cover"), "unexpected error: {err}");
    }
}
