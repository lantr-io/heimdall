//! Test-utility: build a Cardano **stake-pool registration + self-delegation**
//! transaction (WI-024). This exists so the demo SPOs can have non-zero
//! `active_stake`, which the stake-weighted DKG roster
//! ([`crate::cardano::dkg_roster::fetch_dkg_context`]) requires — without it a
//! registered-but-unstaked pool is fatal (`MissingStake`/`ZeroStake`) and the
//! ceremony can't run off the on-chain registry.
//!
//! It is NOT part of the SPO control plane (like `register_spo` /
//! `bootstrap_*`); it's an operator helper, driven by the `register-pool`
//! binary, intended for a local **yaci devnet** (short epochs → stake goes
//! active in seconds) but works against any Blockfrost-compatible endpoint.
//!
//! ## What one tx does
//!
//! - `Certificate::PoolRegistration` — operator = `blake2b_224(cold_vkey)`, a
//!   (synthetic) VRF key hash (no block production is needed for stake-
//!   weighting; the ledger stores the hash without resolving it), pledge,
//!   cost, margin, reward account = the pool's stake address, owners = the
//!   pool's stake key.
//! - `Certificate::StakeRegistrationAndDelegation` — registers the pool's
//!   stake key and delegates it to the pool in one cert.
//! - **A funding output to `base(wallet_payment, pool_stake)`** — the active
//!   stake of a pool is the ADA sitting at addresses that delegate to it, NOT
//!   the certs themselves. Routing `delegated_lovelace` to a base address whose
//!   delegation part is the pool's stake key (payment part stays the fee
//!   wallet, so the funds remain wallet-controlled) is what makes the pool show
//!   stake. Use roughly EQUAL amounts across the 3 demo pools so the
//!   stake-weighted threshold lands on 2-of-3.
//!
//! Witnessed by the payment key (fees + the funding input), the cold key (pool
//! operator), and the stake key (registration/delegation).

use pallas_addresses::{
    Address, Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart, StakeAddress,
};
use pallas_crypto::key::ed25519::SecretKey;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_common::{
    Certificate, CertificateType, PoolParams, RegisterPool, StakeRegistrationAndDelegation,
};
use whisky_pallas::WhiskyPallas;

use crate::cardano::hash::{blake2b_224, blake2b_256, pool_id_bech32};
use crate::cardano::publish::WalletUtxo;
use crate::cardano::tx_common::{sign_built_tx, whisky_network};
use crate::cardano::wallet::pub_key_hash_hex;

/// A 32-byte ed25519 seed → a `Normal` (non-HD) signing key, usable both as a
/// tx witness and to derive its public-key hash.
#[must_use]
pub fn normal_key_from_seed(seed: [u8; 32]) -> PrivateKey {
    PrivateKey::Normal(SecretKey::from(seed))
}

/// 28-byte `blake2b_224` hash of a signing key's public key.
#[must_use]
pub fn key_hash(key: &PrivateKey) -> [u8; 28] {
    let pk: [u8; 32] = key.public_key().into();
    blake2b_224(&pk)
}

/// The pool's bech32 reward/stake address (`stake_test1…` / `stake1…`) for the
/// pool's stake key hash.
#[must_use]
pub fn reward_address(stake_key_hash: &[u8; 28], network: Network) -> String {
    // StakeAddress has no public constructor; build via a Shelley base address
    // (the payment part is irrelevant — only the delegation part survives the
    // conversion) and extract the stake address.
    let shelley = ShelleyAddress::new(
        network,
        ShelleyPaymentPart::key_hash((*stake_key_hash).into()),
        ShelleyDelegationPart::key_hash((*stake_key_hash).into()),
    );
    StakeAddress::try_from(shelley)
        .expect("shelley address with a key delegation part yields a stake address")
        .to_bech32()
        .expect("bech32 encode stake address")
}

/// The base address holding the pool's delegated stake: payment part = the fee
/// wallet's payment key (funds stay wallet-spendable), delegation part = the
/// pool's stake key (so the ADA here counts toward the pool's active stake).
#[must_use]
pub fn stake_base_address(
    wallet_payment_pkh: &[u8; 28],
    stake_key_hash: &[u8; 28],
    network: Network,
) -> String {
    let shelley = ShelleyAddress::new(
        network,
        ShelleyPaymentPart::key_hash((*wallet_payment_pkh).into()),
        ShelleyDelegationPart::key_hash((*stake_key_hash).into()),
    );
    Address::Shelley(shelley)
        .to_bech32()
        .expect("bech32 encode base address")
}

/// A deterministic, synthetic VRF key hash derived from the cold seed. The
/// pool never produces blocks (we only need its stake to count), and the
/// ledger does not check that this hash resolves to a real VRF key.
#[must_use]
pub fn synthetic_vrf_key_hash(cold_seed: &[u8; 32]) -> [u8; 32] {
    let mut preimage = b"heimdall-demo-vrf".to_vec();
    preimage.extend_from_slice(cold_seed);
    blake2b_256(&preimage)
}

/// Everything [`build_register_pool_tx`] needs. UTxOs are caller-fetched so the
/// builder stays pure and testable.
pub struct RegisterPoolRequest<'a> {
    /// Fee wallet base address (change + UTxO source).
    pub wallet_address: &'a str,
    /// Fee wallet payment key hash (delegation funding output's payment part).
    pub wallet_payment_pkh: [u8; 28],
    pub wallet_utxos: &'a [WalletUtxo],
    /// Pays fees + the delegation funding output.
    pub payment_key: &'a PrivateKey,
    /// Pool operator cold key.
    pub cold_key: &'a PrivateKey,
    /// The pool's stake key (distinct per pool).
    pub stake_key: &'a PrivateKey,
    pub vrf_key_hash: [u8; 32],
    pub pledge: u64,
    /// Pool cost; must be `>= minPoolCost` or the ledger rejects.
    pub cost: u64,
    /// Margin as `(numerator, denominator)`.
    pub margin: (u64, u64),
    /// ADA routed to `base(wallet_payment, pool_stake)` — the pool's active
    /// stake. Keep roughly equal across pools for a 2-of-3 threshold.
    pub delegated_lovelace: u64,
    pub pool_deposit: u64,
    pub key_deposit: u64,
    /// Live `[V1, V2, V3]` cost models; `None` → whisky's built-in Preprod.
    pub cost_models: Option<Vec<Vec<i64>>>,
    pub network: Network,
}

/// A built (signed, unsubmitted) pool-registration tx plus the identifiers an
/// operator needs to wire the pool into `register_spo` / `show-roster`.
#[derive(Debug, Clone)]
pub struct BuiltRegisterPoolTx {
    pub signed_tx_hex: String,
    /// Operator key hash (= pool id), hex.
    pub pool_id_hex: String,
    /// Operator key hash as a bech32 `pool1…` id.
    pub pool_id_bech32: String,
    /// The pool's reward/stake address (`stake_test1…`).
    pub stake_address: String,
    /// Base address holding the delegated stake.
    pub stake_base_address: String,
}

#[derive(Debug)]
pub enum RegisterPoolError {
    /// Wallet/coin-selection problem (insufficient funds, no pure-ADA UTxO).
    Wallet(String),
    /// whisky tx build / CBOR (de)code / signing failure.
    Build(String),
}

impl std::fmt::Display for RegisterPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "tx build: {e}"),
        }
    }
}

impl std::error::Error for RegisterPoolError {}

/// Select pure-ADA wallet UTxOs (richest first) until they cover `needed`
/// lovelace. Token-/ref-script-bearing UTxOs are skipped (inputs are declared
/// lovelace-only).
fn select_inputs(wallet_utxos: &[WalletUtxo], needed: u64) -> Result<Vec<&WalletUtxo>, String> {
    let mut pure: Vec<&WalletUtxo> = wallet_utxos.iter().filter(|u| u.pure_ada).collect();
    pure.sort_by_key(|u| std::cmp::Reverse(u.lovelace));
    let mut picked = Vec::new();
    let mut sum = 0u64;
    for u in pure {
        if sum >= needed {
            break;
        }
        sum = sum.saturating_add(u.lovelace);
        picked.push(u);
    }
    if sum < needed {
        return Err(format!(
            "wallet pure-ADA UTxOs total {sum} lovelace but the registration needs >= {needed} \
             (pool deposit + key deposit + delegated stake + fee) — fund or consolidate the wallet"
        ));
    }
    Ok(picked)
}

/// Build + sign the pool-registration tx. Pure (no I/O): UTxOs and cost models
/// are passed in; the caller fetches them and submits the result.
pub fn build_register_pool_tx(
    req: RegisterPoolRequest,
) -> Result<BuiltRegisterPoolTx, RegisterPoolError> {
    let cold_hash = key_hash(req.cold_key);
    let stake_hash = key_hash(req.stake_key);
    let pool_id_hex = hex::encode(cold_hash);
    let pool_id_bech32 = pool_id_bech32(&cold_hash);
    let stake_address = reward_address(&stake_hash, req.network);
    let stake_base = stake_base_address(&req.wallet_payment_pkh, &stake_hash, req.network);

    // Inputs must cover both deposits, the delegation output, the fee, and the
    // change min-UTxO. A generous fee/change margin keeps a single greedy pass
    // sufficient.
    let needed = req
        .pool_deposit
        .saturating_add(req.key_deposit)
        .saturating_add(req.delegated_lovelace)
        .saturating_add(2_000_000); // fee + change-min margin
    let inputs = select_inputs(req.wallet_utxos, needed).map_err(RegisterPoolError::Wallet)?;

    let certs = vec![
        Certificate::BasicCertificate(CertificateType::RegisterPool(RegisterPool {
            pool_params: PoolParams {
                vrf_key_hash: hex::encode(req.vrf_key_hash),
                operator: pool_id_hex.clone(),
                pledge: req.pledge.to_string(),
                cost: req.cost.to_string(),
                margin: req.margin,
                relays: vec![],
                owners: vec![hex::encode(stake_hash)],
                reward_address: stake_address.clone(),
                metadata: None,
            },
        })),
        Certificate::BasicCertificate(CertificateType::StakeRegistrationAndDelegation(
            StakeRegistrationAndDelegation {
                stake_key_address: stake_address.clone(),
                pool_key_hash: pool_id_hex.clone(),
                coin: req.key_deposit,
            },
        )),
    ];

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
                        address: Some(req.wallet_address.to_string()),
                    },
                })
            })
            .collect(),
        outputs: vec![Output {
            address: stake_base.clone(),
            amount: vec![Asset::new_from_str(
                "lovelace",
                &req.delegated_lovelace.to_string(),
            )],
            datum: None,
            reference_script: None,
        }],
        collaterals: vec![],
        required_signatures: vec![
            pub_key_hash_hex(req.payment_key),
            hex::encode(cold_hash),
            hex::encode(stake_hash),
        ],
        change_address: req.wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(&req.cost_models)),
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![],
        certificates: certs,
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
        .map_err(|e| RegisterPoolError::Build(format!("whisky tx build: {e:?}")))?;

    // Three witnesses: fee/payment, pool operator (cold), stake key.
    let signed = sign_built_tx(&unsigned_hex, req.payment_key).map_err(RegisterPoolError::Build)?;
    let signed = sign_built_tx(&signed, req.cold_key).map_err(RegisterPoolError::Build)?;
    let signed = sign_built_tx(&signed, req.stake_key).map_err(RegisterPoolError::Build)?;

    Ok(BuiltRegisterPoolTx {
        signed_tx_hex: signed,
        pool_id_hex,
        pool_id_bech32,
        stake_address,
        stake_base_address: stake_base,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_codec::minicbor;
    use pallas_primitives::conway::{Certificate as PCert, Tx};

    fn wallet_utxo(tx: &str, ix: u32, lovelace: u64) -> WalletUtxo {
        WalletUtxo {
            tx_hash: tx.to_string(),
            output_index: ix,
            lovelace,
            pure_ada: true,
        }
    }

    // Derived identifiers are deterministic and the bech32 forms are well-formed.
    #[test]
    fn derives_pool_and_stake_identifiers() {
        let cold = normal_key_from_seed([0x21; 32]);
        let stake = normal_key_from_seed([0x31; 32]);
        let ch = key_hash(&cold);
        let sh = key_hash(&stake);
        assert_eq!(pool_id_bech32(&ch), pool_id_bech32(&ch)); // stable
        let stake_addr = reward_address(&sh, Network::Testnet);
        assert!(stake_addr.starts_with("stake_test1"), "{stake_addr}");
        let base = stake_base_address(&[0x99; 28], &sh, Network::Testnet);
        assert!(base.starts_with("addr_test1"), "{base}");
        // Mainnet HRPs.
        assert!(reward_address(&sh, Network::Mainnet).starts_with("stake1"));
    }

    // A built tx decodes and carries exactly the two certificates (pool
    // registration + stake registration-and-delegation) plus the delegation
    // funding output.
    #[test]
    fn builds_tx_with_pool_and_delegation_certs() {
        let payment = normal_key_from_seed([0x01; 32]);
        let cold = normal_key_from_seed([0x21; 32]);
        let stake = normal_key_from_seed([0x31; 32]);
        let wallet_pkh = key_hash(&payment);
        // A testnet base address for the fee wallet.
        let wallet_addr = stake_base_address(&wallet_pkh, &key_hash(&stake), Network::Testnet);

        let utxos = vec![wallet_utxo(&"ab".repeat(32), 0, 1_000_000_000)];
        let req = RegisterPoolRequest {
            wallet_address: &wallet_addr,
            wallet_payment_pkh: wallet_pkh,
            wallet_utxos: &utxos,
            payment_key: &payment,
            cold_key: &cold,
            stake_key: &stake,
            vrf_key_hash: synthetic_vrf_key_hash(&[0x21; 32]),
            pledge: 0,
            cost: 340_000_000,
            margin: (0, 1),
            delegated_lovelace: 10_000_000,
            pool_deposit: 500_000_000,
            key_deposit: 2_000_000,
            cost_models: None,
            network: Network::Testnet,
        };
        let built = build_register_pool_tx(req).expect("build");
        assert_eq!(built.pool_id_hex, hex::encode(key_hash(&cold)));

        let bytes = hex::decode(&built.signed_tx_hex).unwrap();
        let tx: Tx = minicbor::decode(&bytes).unwrap();
        let certs = tx.transaction_body.certificates.as_ref().expect("certs");
        assert_eq!(certs.len(), 2, "pool reg + stake reg-deleg");
        assert!(
            certs
                .iter()
                .any(|c| matches!(c, PCert::PoolRegistration { .. }))
        );
        assert!(
            certs.iter().any(|c| matches!(c, PCert::StakeRegDeleg(..))),
            "expected a StakeRegDeleg certificate"
        );
        // Three vkey witnesses (payment, cold, stake).
        let vkeys = tx
            .transaction_witness_set
            .vkeywitness
            .as_ref()
            .expect("vkey witnesses");
        assert_eq!(vkeys.len(), 3);
    }

    #[test]
    fn rejects_underfunded_wallet() {
        let payment = normal_key_from_seed([0x01; 32]);
        let cold = normal_key_from_seed([0x21; 32]);
        let stake = normal_key_from_seed([0x31; 32]);
        let wallet_pkh = key_hash(&payment);
        let wallet_addr = stake_base_address(&wallet_pkh, &key_hash(&stake), Network::Testnet);
        let utxos = vec![wallet_utxo(&"cd".repeat(32), 0, 100_000_000)]; // < 502 ADA
        let req = RegisterPoolRequest {
            wallet_address: &wallet_addr,
            wallet_payment_pkh: wallet_pkh,
            wallet_utxos: &utxos,
            payment_key: &payment,
            cold_key: &cold,
            stake_key: &stake,
            vrf_key_hash: synthetic_vrf_key_hash(&[0x21; 32]),
            pledge: 0,
            cost: 340_000_000,
            margin: (0, 1),
            delegated_lovelace: 10_000_000,
            pool_deposit: 500_000_000,
            key_deposit: 2_000_000,
            cost_models: None,
            network: Network::Testnet,
        };
        assert!(matches!(
            build_register_pool_tx(req),
            Err(RegisterPoolError::Wallet(_))
        ));
    }
}
