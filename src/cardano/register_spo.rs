//! register_spo R1: build the `spos_registry.Register` Cardano transaction.
//!
//! The registration tx binds a Cardano pool identity (cold key) to a Bifrost
//! identity (secp256k1 key + URL). In ONE transaction it must:
//!
//! 1. spend the registry **anchor** element UTxO (the linked-list predecessor
//!    of the new `pool_id`, found off-chain by [`RegistryList::plan_insert`])
//!    with `SposRegistrySpendRedeemer::RegistrationListAction`,
//! 2. spend the `treasury_info` state UTxO (via
//!    [`crate::cardano::treasury_spend::treasury_spend_leg`]),
//! 3. mint exactly 1 membership token under the registry policy with asset
//!    name `pool_id = blake2b_224(cold_vkey)` and the
//!    `SposRegistryMintRedeemer::Register` redeemer,
//! 4. output the continued anchor (data + lovelace unchanged, link →
//!    `pool_id`), the new registration node (`{bifrost_id_pk, bifrost_url}`,
//!    link = anchor's old link) and the continued treasury state (only
//!    `bifrost_identity_root` advanced by the MPF insert
//!    `bifrost_id_pk → pool_id`).
//!
//! The `Register` redeemer carries two signatures over the registration
//! message `"bifrost-spo" || pool_id || bifrost_id_pk || bifrost_url`:
//! the cold Ed25519 signature over the raw message, and the bifrost BIP340
//! Schnorr signature over `sha2_256(message)` (matching the on-chain
//! `verify_schnorr_signature(bifrost_id_pk, sha2_256(message), bifrost_sig)`).
//! Both are verified locally before any tx is built — also covering the
//! air-gapped flow where the signatures arrive from another machine.
//!
//! The redeemer's input indices refer to positions in the tx's input list,
//! which the ledger (and whisky) orders lexicographically by `(tx_id, index)`
//! — [`build_register_spo_tx`] computes them from that order and re-checks
//! against the built tx. Output indices are ours to choose: `[0]` continued
//! anchor, `[1]` new node, `[2]` continued treasury, `[3]` wallet change.
//!
//! This module also provides the registry-list **bootstrap**
//! ([`build_registry_bootstrap_tx`]): the one-shot `Bootstrap` mint that
//! spends the outref parameterizing `spos_registry` and creates the
//! `"reg-root"` anchor element — without it there is no anchor to insert
//! after. (Counterpart of K1 / `treasury_bootstrap` on the registry side.)
//!
//! Submission is gated on R2 (`crate::cardano::stake`): the pool's
//! epoch-snapshot `active_stake` must meet the protocol `min_stake` — the
//! contract cannot read stake, so the gate is enforced by the CLI before
//! broadcasting.

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{Keypair, Message, XOnlyPublicKey, schnorr};
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
use crate::cardano::registry::{
    REGISTRATION_ROOT_KEY, RegistrationNodeData, RegistryElement, RegistryError, RegistryList,
};
use crate::cardano::treasury_info::{
    TreasuryInfoError, apply_registration, proof_to_plutus_data, registry_update_redeemer,
};
use crate::cardano::treasury_spend::{TreasurySpendError, find_treasury_state, treasury_spend_leg};
use crate::cardano::tx_common::{
    BootstrapError, NonceOutpoint, OneShotBootstrapParams, build_oneshot_bootstrap_tx,
    element_lovelace, network_from_address, select_collateral, select_fee,
    sign_built_tx as common_sign_built_tx, wallet_input_amount, whisky_network,
};
use crate::cardano::wallet::pub_key_hash_hex;

/// `registration_domain_separator` in `spos_registry.ak`.
pub const REGISTRATION_DOMAIN_SEPARATOR: &[u8] = b"bifrost-spo";

#[derive(Debug)]
pub enum RegisterSpoError {
    Registry(RegistryError),
    TreasurySpend(TreasurySpendError),
    TreasuryInfo(TreasuryInfoError),
    /// The cold Ed25519 signature does not verify over the registration
    /// message — the on-chain `verify_ed25519_signature` would reject it.
    ColdSignatureInvalid,
    /// The bifrost BIP340 signature does not verify over
    /// `sha2_256(message)` — the on-chain `verify_schnorr_signature` would
    /// reject it.
    BifrostSignatureInvalid,
    /// `bifrost_id_pk` is not a valid x-only secp256k1 point.
    BadBifrostKey(String),
    /// A UTxO at the registry script address carrying registry-policy assets
    /// is not a well-formed list element.
    BadElementUtxo(String),
    Wallet(String),
    Build(String),
}

impl From<BootstrapError> for RegisterSpoError {
    fn from(e: BootstrapError) -> Self {
        match e {
            BootstrapError::Wallet(m) => RegisterSpoError::Wallet(m),
            BootstrapError::Build(m) => RegisterSpoError::Build(m),
        }
    }
}

impl std::fmt::Display for RegisterSpoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry(e) => write!(f, "registry: {e}"),
            Self::TreasurySpend(e) => write!(f, "treasury spend: {e}"),
            Self::TreasuryInfo(e) => write!(f, "treasury info: {e}"),
            Self::ColdSignatureInvalid => {
                write!(
                    f,
                    "cold Ed25519 signature does not verify over the registration message"
                )
            }
            Self::BifrostSignatureInvalid => write!(
                f,
                "bifrost BIP340 signature does not verify over sha2_256(registration message)"
            ),
            Self::BadBifrostKey(e) => write!(f, "bifrost_id_pk: {e}"),
            Self::BadElementUtxo(e) => write!(f, "registry element UTxO: {e}"),
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "tx build: {e}"),
        }
    }
}

impl std::error::Error for RegisterSpoError {}

impl From<RegistryError> for RegisterSpoError {
    fn from(e: RegistryError) -> Self {
        Self::Registry(e)
    }
}
impl From<TreasurySpendError> for RegisterSpoError {
    fn from(e: TreasurySpendError) -> Self {
        Self::TreasurySpend(e)
    }
}
impl From<TreasuryInfoError> for RegisterSpoError {
    fn from(e: TreasuryInfoError) -> Self {
        Self::TreasuryInfo(e)
    }
}

// ---------------------------------------------------------------------------
// Registration message + signatures
// ---------------------------------------------------------------------------

/// `pool_id = blake2b_224(cold_vkey)` — the pool key hash, the membership
/// token name and the new node's key, all in one.
#[must_use]
pub fn pool_id_from_cold_vkey(cold_vkey: &[u8; 32]) -> [u8; 28] {
    crate::cardano::hash::blake2b_224(cold_vkey)
}

/// `registration_message` in `spos_registry.ak`:
/// `"bifrost-spo" || pool_id || bifrost_id_pk || bifrost_url || nonce_outpoint`.
///
/// The trailing 36-byte nonce is what makes the signatures single-use ([REG-10],
/// rev 5.6). Everything before it is the same for every registration of a pool
/// — the domain separator, a pool id derived from a cold key that does not
/// change, and the identity the operator declares — and both signatures travel
/// in the redeemer, so they are public from the first transaction that carries
/// them. Before the nonce, a published registration signature could put a pool
/// that had left back into the registry with its old key and URL, where the
/// roster faults it and the ban list records that against the real pool.
///
/// Its fixed length also keeps the message unambiguous: it follows a
/// variable-length URL, and a suffix of known length is the only thing that
/// stops the two being re-split.
#[must_use]
pub fn registration_message(
    pool_id: &[u8],
    bifrost_id_pk: &[u8],
    bifrost_url: &[u8],
    nonce: &NonceOutpoint,
) -> Vec<u8> {
    let nonce_bytes = nonce.to_message_bytes();
    let mut m = Vec::with_capacity(
        REGISTRATION_DOMAIN_SEPARATOR.len()
            + pool_id.len()
            + bifrost_id_pk.len()
            + bifrost_url.len()
            + nonce_bytes.len(),
    );
    m.extend_from_slice(REGISTRATION_DOMAIN_SEPARATOR);
    m.extend_from_slice(pool_id);
    m.extend_from_slice(bifrost_id_pk);
    m.extend_from_slice(bifrost_url);
    m.extend_from_slice(&nonce_bytes);
    m
}

/// The two registration signatures, the cold verification key they bind, and
/// the outpoint they are bound TO.
///
/// The nonce travels with the signatures because it is part of what they mean:
/// a pair of signatures without it names no transaction, and a builder that
/// paired them with a different outpoint would produce a transaction the chain
/// rejects with nothing but "signature invalid" to go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationSignatures {
    pub cold_vkey: [u8; 32],
    /// Ed25519 over the raw registration message.
    pub cold_sig: [u8; 64],
    /// BIP340 Schnorr over `sha2_256(registration message)`.
    pub bifrost_sig: [u8; 64],
    /// spec [REG-10]: the UTxO the transaction must spend for these signatures
    /// to verify. Chosen among the registrant's own UTxOs.
    pub nonce: NonceOutpoint,
}

/// Produce both registration signatures locally (non-air-gapped flow).
/// `bifrost_id_pk` is the keypair's x-only key; the message commits to it.
#[must_use]
pub fn sign_registration(
    cold_skey: &ed25519::SecretKey,
    bifrost_keypair: &Keypair,
    bifrost_url: &[u8],
    nonce: NonceOutpoint,
) -> RegistrationSignatures {
    let cold_vkey: [u8; 32] = cold_skey.public_key().into();
    let pool_id = pool_id_from_cold_vkey(&cold_vkey);
    let bifrost_id_pk = bifrost_keypair.x_only_public_key().0.serialize();
    let message = registration_message(&pool_id, &bifrost_id_pk, bifrost_url, &nonce);

    let cold_sig: [u8; 64] = cold_skey
        .sign(&message)
        .as_ref()
        .try_into()
        .expect("ed25519 signature is 64 bytes");

    let secp = Secp256k1::new();
    let digest = sha256::Hash::hash(&message).to_byte_array();
    // BIP340 with zeroed aux randomness: deterministic, equally valid to any
    // verifier (the aux only blinds the nonce derivation).
    let bifrost_sig = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), bifrost_keypair)
        .serialize();

    RegistrationSignatures {
        cold_vkey,
        cold_sig,
        bifrost_sig,
        nonce,
    }
}

/// Verify both signatures exactly as `spos_registry.ak` will, returning the
/// `pool_id` they authorize. Catches a bad local key as well as a stale or
/// mis-copied air-gapped signature before any fee is spent.
pub fn verify_registration(
    sigs: &RegistrationSignatures,
    bifrost_id_pk: &[u8; 32],
    bifrost_url: &[u8],
) -> Result<[u8; 28], RegisterSpoError> {
    // Structural check first: a non-point bifrost_id_pk can never register.
    let xonly = XOnlyPublicKey::from_slice(bifrost_id_pk)
        .map_err(|e| RegisterSpoError::BadBifrostKey(e.to_string()))?;

    let pool_id = pool_id_from_cold_vkey(&sigs.cold_vkey);
    let message = registration_message(&pool_id, bifrost_id_pk, bifrost_url, &sigs.nonce);

    let vkey = ed25519::PublicKey::from(sigs.cold_vkey);
    if !vkey.verify(&message, &ed25519::Signature::from(sigs.cold_sig)) {
        return Err(RegisterSpoError::ColdSignatureInvalid);
    }

    let digest = sha256::Hash::hash(&message).to_byte_array();
    let sig = schnorr::Signature::from_slice(&sigs.bifrost_sig)
        .map_err(|_| RegisterSpoError::BifrostSignatureInvalid)?;
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(digest), &xonly)
        .map_err(|_| RegisterSpoError::BifrostSignatureInvalid)?;

    Ok(pool_id)
}

// ---------------------------------------------------------------------------
// Redeemers
// ---------------------------------------------------------------------------

/// `SposRegistryMintRedeemer::Register` — constructor 1, field order pinned by
/// `bifrost/types/spos_registry.ak`:
/// `{cold_vkey, cold_sig, bifrost_sig, nonce_input_index,
/// registration_anchor_input_index, registration_anchor_output_index,
/// treasury_input_index, treasury_output_index, bifrost_identity_absence_proof}`.
///
/// `nonce_input_index` sits directly after the signatures it makes single-use
/// (rev 5.6, [REG-10]); every index after it keeps the position it had. There is
/// no schema between this function and the Aiken constructor — the fields are
/// positional on both sides — so the order here is a contract, not a
/// convenience.
#[must_use]
pub fn register_mint_redeemer(
    sigs: &RegistrationSignatures,
    nonce_input_index: i64,
    anchor_input_index: i64,
    anchor_output_index: i64,
    treasury_input_index: i64,
    treasury_output_index: i64,
    absence_proof: &mpf::Proof,
) -> PlutusData {
    constr(
        1,
        vec![
            bytes(&sigs.cold_vkey),
            bytes(&sigs.cold_sig),
            bytes(&sigs.bifrost_sig),
            int(nonce_input_index),
            int(anchor_input_index),
            int(anchor_output_index),
            int(treasury_input_index),
            int(treasury_output_index),
            proof_to_plutus_data(absence_proof),
        ],
    )
}

/// `SposRegistryMintRedeemer::Bootstrap` — constructor 0, no fields.
#[must_use]
pub fn bootstrap_mint_redeemer() -> PlutusData {
    constr(0, vec![])
}

/// `SposRegistrySpendRedeemer::RegistrationListAction` — the redeemer for
/// spending any registry element UTxO (the spend branch only requires a
/// non-zero registry-policy mint in the same tx).
#[must_use]
pub fn registration_list_action_redeemer() -> PlutusData {
    constr(0, vec![])
}

// ---------------------------------------------------------------------------
// Registry snapshot from on-chain UTxOs
// ---------------------------------------------------------------------------

/// One located registry element UTxO, decoded.
#[derive(Debug, Clone)]
pub struct RegistryUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub lovelace: u64,
    /// The element's NFT asset name (`"reg-root"` or a pool_id).
    pub asset_name: Vec<u8>,
    pub element: RegistryElement,
}

/// Decode the registry list elements among `utxos` (fetched from the registry
/// script address). A UTxO carrying no registry-policy asset is ignored
/// (anyone can send unrelated value to a script address); a UTxO carrying
/// registry assets in any shape other than exactly `[ADA, one NFT]` with an
/// inline element datum is an error — the on-chain list could never have
/// produced it, so the snapshot is not trustworthy.
pub fn find_registry_utxos(
    utxos: &[BfUtxo],
    policy_id_hex: &str,
) -> Result<Vec<RegistryUtxo>, RegisterSpoError> {
    crate::cardano::nft_scan::find_policy_nft_utxos(utxos, policy_id_hex)
        .map_err(RegisterSpoError::BadElementUtxo)?
        .into_iter()
        .map(|u| {
            let element = RegistryElement::from_plutus_data(&u.datum).map_err(|e| {
                RegisterSpoError::BadElementUtxo(format!(
                    "{}#{}: datum: {e}",
                    u.tx_hash, u.output_index
                ))
            })?;
            Ok(RegistryUtxo {
                tx_hash: u.tx_hash,
                output_index: u.output_index,
                lovelace: u.lovelace,
                asset_name: u.asset_name,
                element,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// register_spo tx builder
// ---------------------------------------------------------------------------

/// Everything `build_register_spo_tx` needs. UTxO sets are caller-fetched so
/// the builder stays pure/testable; `wallet_utxos` pays fees + collateral.
pub struct RegisterSpoRequest<'a> {
    pub registry_script: &'a ParameterizedScript,
    pub treasury_script: &'a ParameterizedScript,
    /// Treasury NFT asset name (hex), fixed at K1.
    pub treasury_asset_name_hex: &'a str,
    /// UTxOs at the registry script address.
    pub registry_utxos: &'a [BfUtxo],
    /// UTxOs at the treasury script address.
    pub treasury_utxos: &'a [BfUtxo],
    /// `(policy hex, UTxOs)` of the registry a migration is coming FROM —
    /// Config #13, `None` when no migration is in progress ([CFG-10]).
    ///
    /// Needed for the identity trie, not for the transaction. `Migrate` does
    /// not move the Treasury state's `bifrost_identity_root` ([MIG-3]), so
    /// while pools are crossing, the root commits to the bindings of BOTH
    /// lists. A registration that rebuilt the trie from the current list alone
    /// would compute a different root, and `apply_registration` would refuse
    /// before building anything — which is to say joining the bridge would be
    /// impossible for the length of the migration.
    pub previous_registry: Option<(&'a str, &'a [BfUtxo])>,
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    /// Wallet payment key (fees/collateral) — NOT the cold key.
    pub key: &'a PrivateKey,
    pub sigs: &'a RegistrationSignatures,
    pub bifrost_id_pk: [u8; 32],
    pub bifrost_url: Vec<u8>,
    /// Epoch-boundary validity window (slots): the tx is valid from
    /// `invalid_before` and must land strictly before `invalid_hereafter`
    /// (the next epoch boundary), so a delayed submission cannot register
    /// into a different epoch's candidate snapshot than intended.
    pub invalid_before: Option<u64>,
    pub invalid_hereafter: Option<u64>,
    /// `(tx_hash, index)` of a UTxO carrying the registry script as a
    /// reference script (see [`build_ref_script_deploy_tx`]). REQUIRED on a
    /// real network: the ~12 KB registry script is needed by BOTH the anchor
    /// spend and the mint, and embedding it twice blows past the 16 KB
    /// tx-size limit. `None` embeds it (offline tests).
    pub registry_ref: Option<(String, u32)>,
    /// `(tx_hash, index)` of the Config UTxO. Rev 5.5: `treasury.ak`'s
    /// `RegistryUpdate` branch reads `spos_registry_policy_id` from the Config
    /// datum ([TSY-12], [TSY-13]) instead of taking the registry policy as a
    /// compile parameter — which is what broke the dependency cycle and let
    /// `spo_registry` pin this UTxO ([REG-6]). So the tx must REFERENCE it.
    pub config_ref: (String, u32),
    /// Live `[V1, V2, V3]` cost models; `None` → whisky's built-in Preprod.
    pub cost_models: Option<Vec<Vec<i64>>>,
}

/// A built (signed, unsubmitted) register_spo tx plus what the operator needs
/// to record.
#[derive(Debug, Clone)]
pub struct RegisterSpoTx {
    pub signed_tx_hex: String,
    /// `blake2b_224(cold_vkey)` — minted membership token name / node key.
    pub pool_id: [u8; 28],
    /// The spent anchor element's NFT name (`"reg-root"` or a pool_id).
    pub anchor_asset_name: Vec<u8>,
    /// The continued treasury datum's `bifrost_identity_root`.
    pub new_bifrost_identity_root: mpf::Hash,
}

/// One `bifrost_id_pk -> pool_id` binding, as the MPF trie stores it.
pub type IdentityPair = (Vec<u8>, Vec<u8>);

/// The `bifrost_id_pk -> pool_id` bindings the Treasury state's identity root
/// commits to: the current registry list, plus the previous one while a
/// migration is in progress ([CFG-10], [MIG-3]).
///
/// Shared by `register_spo`, `deregister_spo` and `migrate_registration`,
/// because getting it wrong is the same failure in all three: a trie that does
/// not rebuild the treasury's root, and a proof the validator rejects.
///
/// Deduplicated by identity key, which is also the invariant the trie itself
/// encodes — [REG-5] exists to make `bifrost_id_pk` globally unique, so a pool
/// present in both lists is one entry, not two.
pub fn union_identity_pairs(
    current: &RegistryList,
    previous: Option<(&str, &[BfUtxo])>,
) -> Result<Vec<IdentityPair>, RegisterSpoError> {
    let mut seen: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    let mut pairs: Vec<IdentityPair> = Vec::new();
    for (pk, pool_id) in current.identity_pairs() {
        if seen.insert(pk.clone()) {
            pairs.push((pk, pool_id));
        }
    }
    if let Some((policy_hex, utxos)) = previous {
        let elements = find_registry_utxos(utxos, policy_hex)?;
        let list = RegistryList::from_elements(
            elements
                .iter()
                .map(|u| (u.asset_name.clone(), u.element.clone())),
        )?;
        for (pk, pool_id) in list.identity_pairs() {
            if seen.insert(pk.clone()) {
                pairs.push((pk, pool_id));
            }
        }
    }
    Ok(pairs)
}

/// Decode `tx_hash` hex into the 32-byte id whisky sorts inputs by.
fn tx_id_bytes(tx_hash: &str) -> Result<[u8; 32], RegisterSpoError> {
    hex::decode(tx_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| RegisterSpoError::Build(format!("bad tx hash: {tx_hash}")))
}

/// Pick the fee input and an ada-only collateral, both via the shared rules.
/// They differ: the fee input may carry native tokens (declared on the input,
/// returned in the change), collateral may not. Neither may carry a reference
/// script — that spend incurs the Conway per-byte fee the builder doesn't price.
fn select_fee_and_collateral(
    wallet_utxos: &[WalletUtxo],
    min_fee_lovelace: u64,
) -> Result<(&WalletUtxo, &WalletUtxo), RegisterSpoError> {
    let fee_utxo = select_fee(wallet_utxos, min_fee_lovelace).map_err(RegisterSpoError::Wallet)?;
    // Collateral must be ada-only and DISTINCT from the fee input. Both calls
    // also skip a `reserved` UTxO, which is how the nonce a cold signature is
    // bound to survives the round trip to the cold key ([REG-10], [DRG-6]).
    let coll_utxo =
        select_collateral(wallet_utxos, &[fee_utxo]).map_err(RegisterSpoError::Wallet)?;
    Ok((fee_utxo, coll_utxo))
}

/// Sign the whisky-built tx body with the wallet key and splice the vkey
/// witness in (same flow as the treasury bootstrap).
fn sign_built_tx(unsigned_hex: &str, key: &PrivateKey) -> Result<String, RegisterSpoError> {
    common_sign_built_tx(unsigned_hex, key).map_err(RegisterSpoError::Build)
}

/// Build + sign the register_spo tx. Verifies the registration signatures,
/// reconstructs the on-chain list and identity trie, plans the insert, and
/// composes the three legs (anchor spend, treasury spend, membership mint).
pub fn build_register_spo_tx(req: &RegisterSpoRequest) -> Result<RegisterSpoTx, RegisterSpoError> {
    // Fail fast on anything the on-chain validator would reject.
    let pool_id = verify_registration(req.sigs, &req.bifrost_id_pk, &req.bifrost_url)?;

    let registry_policy_hex = req.registry_script.hash_hex();
    let elements = find_registry_utxos(req.registry_utxos, &registry_policy_hex)?;
    let list = RegistryList::from_elements(
        elements
            .iter()
            .map(|u| (u.asset_name.clone(), u.element.clone())),
    )?;
    let plan = list.plan_insert(
        &pool_id,
        RegistrationNodeData {
            bifrost_id_pk: req.bifrost_id_pk.to_vec(),
            bifrost_url: req.bifrost_url.clone(),
        },
    )?;
    let anchor = elements
        .iter()
        .find(|u| u.asset_name == plan.anchor_asset_name)
        .expect("plan_insert anchors on an element from this snapshot");

    // Treasury leg: rebuild the identity trie from the (pre-insert) list and
    // derive the post-registration datum + absence proof.
    //
    // From BOTH lists while a registry migration is in progress: the root the
    // treasury carries commits to every binding written under either policy,
    // because `Migrate` carries one across without moving it. Keyed by
    // `bifrost_id_pk`, so a pool that has already migrated — and is therefore
    // in both lists — contributes once.
    let identity_trie = mpf::Trie::from_pairs(union_identity_pairs(&list, req.previous_registry)?)
        .map_err(TreasuryInfoError::Mpf)?;
    let state = find_treasury_state(
        req.treasury_utxos,
        &req.treasury_script.hash_hex(),
        req.treasury_asset_name_hex,
    )?;
    let (new_treasury_datum, absence_proof) =
        apply_registration(&state.datum, &identity_trie, &req.bifrost_id_pk, &pool_id)?;

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

    // New node output: min-ADA + the freshly minted membership NFT.
    let new_node_datum_cbor = plan.new_node.to_cbor();
    let node_lovelace = element_lovelace(new_node_datum_cbor.len());

    // spec [REG-10]: the transaction MUST spend the UTxO the signatures name, or
    // the message the validator rebuilds is not the message that was signed.
    // Locate it in the wallet first: gone from the set means already spent, and
    // saying so here is worth more than the chain's "signature invalid".
    let nonce = req.sigs.nonce;
    let nonce_utxo = req
        .wallet_utxos
        .iter()
        .find(|u| u.outpoint() == Some(nonce))
        .ok_or_else(|| {
            RegisterSpoError::Build(format!(
                "the nonce UTxO {nonce} these signatures are bound to is not in the wallet. \
                 Either it has been spent — in which case the signatures are used up and the \
                 cold key must sign again — or this is the wrong wallet",
            ))
        })?;

    let (fee_utxo, coll_utxo) =
        select_fee_and_collateral(req.wallet_utxos, node_lovelace + 1_000_000)?;

    // The ledger orders tx inputs lexicographically by (tx_id, index); the
    // redeemer indices must point into that order.
    let fee_ref = (tx_id_bytes(&fee_utxo.tx_hash)?, fee_utxo.output_index);
    let nonce_ref = (nonce.tx_hash, nonce.index);
    let anchor_ref = (tx_id_bytes(&anchor.tx_hash)?, anchor.output_index);
    let treasury_ref = (tx_id_bytes(&state.tx_hash)?, state.output_index);
    // The nonce MAY be the fee input — that is the one-machine flow, where the
    // request and the submission happen in the same command and nothing can
    // spend it in between. Everywhere else it is its own input, reserved in the
    // state dir so fee selection skips it.
    let nonce_is_fee = nonce_ref == fee_ref;
    let mut sorted = vec![fee_ref, anchor_ref, treasury_ref];
    if !nonce_is_fee {
        sorted.push(nonce_ref);
    }
    let distinct = {
        let mut d = sorted.clone();
        d.sort();
        d.dedup();
        d.len()
    };
    if distinct != sorted.len() {
        return Err(RegisterSpoError::Build(
            "fee/nonce/anchor/treasury inputs must be distinct outpoints".into(),
        ));
    }
    sorted.sort();
    let index_of = |r: &([u8; 32], u32)| sorted.iter().position(|s| s == r).unwrap() as i64;
    let anchor_input_index = index_of(&anchor_ref);
    let treasury_input_index = index_of(&treasury_ref);
    let nonce_input_index = index_of(&nonce_ref);
    // Outputs are ours to order: [0] continued anchor, [1] new node,
    // [2] continued treasury (whisky appends the change output after).
    let (anchor_output_index, treasury_output_index) = (0i64, 2i64);

    // The registry script witness: referenced when a ref-script UTxO is given
    // (the ~12 KB script would not fit twice in one tx), embedded otherwise.
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

    let anchor_unit = format!(
        "{registry_policy_hex}{}",
        hex::encode(&plan.anchor_asset_name)
    );
    let anchor_value = vec![
        Asset::new_from_str("lovelace", &anchor.lovelace.to_string()),
        Asset::new_from_str(&anchor_unit, "1"),
    ];
    let anchor_redeemer_hex = hex::encode(
        minicbor::to_vec(registration_list_action_redeemer()).expect("redeemer CBOR encode"),
    );
    let anchor_in = TxIn::ScriptTxIn(ScriptTxIn {
        tx_in: TxInParameter {
            tx_hash: anchor.tx_hash.clone(),
            tx_index: anchor.output_index,
            amount: Some(anchor_value.clone()),
            address: Some(registry_address.clone()),
        },
        script_tx_in: ScriptTxInParameter {
            script_source: Some(registry_source.clone()),
            datum_source: Some(DatumSource::InlineDatumSource(InlineDatumSource {
                tx_hash: anchor.tx_hash.clone(),
                tx_index: anchor.output_index,
            })),
            redeemer: Some(Redeemer {
                data: anchor_redeemer_hex,
                // The spend branch only checks for a non-zero registry mint.
                ex_units: Budget {
                    mem: 1_000_000,
                    steps: 500_000_000,
                },
            }),
        },
    });

    // Continued anchor: same address, same value (anchor_lovelace_change must
    // be 0 on-chain), data unchanged, link → pool_id.
    let continued_anchor_out = Output {
        address: registry_address.clone(),
        amount: anchor_value,
        datum: Some(Datum::Inline(hex::encode(plan.continued_anchor.to_cbor()))),
        reference_script: None,
    };
    let new_node_unit = format!(
        "{registry_policy_hex}{}",
        hex::encode(&plan.new_node_asset_name)
    );
    let new_node_out = Output {
        address: registry_address,
        amount: vec![
            Asset::new_from_str("lovelace", &node_lovelace.to_string()),
            Asset::new_from_str(&new_node_unit, "1"),
        ],
        datum: Some(Datum::Inline(hex::encode(new_node_datum_cbor))),
        reference_script: None,
    };

    let mint_redeemer = register_mint_redeemer(
        req.sigs,
        nonce_input_index,
        anchor_input_index,
        anchor_output_index,
        treasury_input_index,
        treasury_output_index,
        &absence_proof,
    );
    let mint_redeemer_hex =
        hex::encode(minicbor::to_vec(&mint_redeemer).expect("redeemer CBOR encode"));

    let mut inputs = vec![TxIn::PubKeyTxIn(PubKeyTxIn {
        tx_in: TxInParameter {
            tx_hash: fee_utxo.tx_hash.clone(),
            tx_index: fee_utxo.output_index,
            amount: Some(wallet_input_amount(fee_utxo)),
            address: Some(req.wallet_address.to_string()),
        },
    })];
    if !nonce_is_fee {
        inputs.push(TxIn::PubKeyTxIn(PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: nonce_utxo.tx_hash.clone(),
                tx_index: nonce_utxo.output_index,
                amount: Some(wallet_input_amount(nonce_utxo)),
                address: Some(req.wallet_address.to_string()),
            },
        }));
    }
    inputs.push(anchor_in);
    inputs.push(treasury_in);

    let body = TxBuilderBody {
        inputs,
        outputs: vec![continued_anchor_out, new_node_out, treasury_out],
        collaterals: vec![PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: coll_utxo.tx_hash.clone(),
                tx_index: coll_utxo.output_index,
                amount: Some(wallet_input_amount(coll_utxo)),
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
                amount: 1,
            },
            redeemer: Some(Redeemer {
                data: mint_redeemer_hex,
                // Register walks the linked-list checks, verifies an Ed25519 +
                // a Schnorr signature and recomputes the MPF insert — the
                // heavyweight leg of this tx.
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
        .map_err(|e| RegisterSpoError::Build(format!("whisky tx build: {e:?}")))?;

    // Post-build pass before signing: (a) whisky pushes one reference input
    // per InlineScriptSource use — dedupe them (duplicate set elements would
    // be rejected; ref inputs sit outside the script-integrity hash, so the
    // edit is safe pre-signature); (b) defensive check that the redeemer
    // indices derived from the expected input sort match the built tx.
    let unsigned_hex = {
        let tx_bytes = hex::decode(&unsigned_hex)
            .map_err(|e| RegisterSpoError::Build(format!("unsigned tx hex decode: {e}")))?;
        let mut tx: Tx = minicbor::decode(&tx_bytes)
            .map_err(|e| RegisterSpoError::Build(format!("tx minicbor decode: {e}")))?;

        if let Some(ref_ins) = tx.transaction_body.reference_inputs.take() {
            let mut v = ref_ins.to_vec();
            v.sort_by_key(|i| (i.transaction_id, i.index));
            v.dedup();
            tx.transaction_body.reference_inputs = pallas_codec::utils::NonEmptySet::from_vec(v);
        }

        {
            let inputs: Vec<_> = tx.transaction_body.inputs.iter().collect();
            let at = |i: i64, want: &([u8; 32], u32), what: &str| -> Result<(), RegisterSpoError> {
                let got = inputs.get(i as usize).ok_or_else(|| {
                    RegisterSpoError::Build(format!("{what} input index {i} out of range"))
                })?;
                if got.transaction_id.as_slice() != want.0 || got.index != u64::from(want.1) {
                    return Err(RegisterSpoError::Build(format!(
                        "{what} input not at redeemer index {i} — input ordering changed"
                    )));
                }
                Ok(())
            };
            at(anchor_input_index, &anchor_ref, "anchor")?;
            at(treasury_input_index, &treasury_ref, "treasury")?;
            // spec [REG-10]. The one index whose drift the chain reports as
            // nothing but a bad signature, so it is worth naming here.
            at(nonce_input_index, &nonce_ref, "nonce")?;
            // And the one REFERENCE index this transaction carries. Computed
            // before the build like every other, so it is a prediction until
            // something compares it; `migrate_registration` and `apply_ban`
            // check theirs, and an unchecked one would surface only as a
            // phase-2 failure with nothing to point at.
            {
                let refs: Vec<_> = tx
                    .transaction_body
                    .reference_inputs
                    .as_ref()
                    .map(|s| s.iter().collect())
                    .unwrap_or_default();
                let got = refs.get(config_ref_index as usize).ok_or_else(|| {
                    RegisterSpoError::Build(format!(
                        "Config reference index {config_ref_index} out of range"
                    ))
                })?;
                if hex::encode(got.transaction_id.as_slice()) != req.config_ref.0
                    || got.index != u64::from(req.config_ref.1)
                {
                    return Err(RegisterSpoError::Build(format!(
                        "Config not at redeemer reference index {config_ref_index} — reference \
                         ordering changed"
                    )));
                }
            }
        }

        hex::encode(
            minicbor::to_vec(&tx)
                .map_err(|e| RegisterSpoError::Build(format!("tx re-encode: {e}")))?,
        )
    };

    let signed_tx_hex = sign_built_tx(&unsigned_hex, req.key)?;
    Ok(RegisterSpoTx {
        signed_tx_hex,
        pool_id,
        anchor_asset_name: plan.anchor_asset_name,
        new_bifrost_identity_root: new_treasury_datum.bifrost_identity_root,
    })
}

// ---------------------------------------------------------------------------
// Registry-list bootstrap (the "reg-root" anchor mint)
// ---------------------------------------------------------------------------

/// A built (signed, unsubmitted) registry bootstrap tx.
#[derive(Debug, Clone)]
pub struct RegistryBootstrapTx {
    pub signed_tx_hex: String,
    /// `spos_registry` script hash = the registry policy id.
    pub policy_id_hex: String,
    /// Enterprise script address holding the list elements.
    pub script_address: String,
}

/// Build + sign the registry-list bootstrap: spend the one-shot outref that
/// parameterizes `spos_registry` (it MUST be among `wallet_utxos`) and mint
/// the `"reg-root"` anchor NFT to the registry script address with the
/// `Element{Root, link: None}` inline datum.
///
/// `one_shot_ref_script_size`: byte size of a reference script attached to the
/// one-shot UTxO, if any. The outref was fixed when the policy was
/// parameterized, so unlike ordinary coin selection it cannot be swapped for a
/// clean UTxO — instead the ledger's per-byte ref-script fee is added on top
/// of whisky's estimate (second build pass with an explicit fee).
#[allow(clippy::too_many_arguments)]
pub fn build_registry_bootstrap_tx(
    registry_script: &ParameterizedScript,
    bootstrap_tx_hash: &str,
    bootstrap_output_index: u32,
    wallet_address: &str,
    wallet_utxos: &[WalletUtxo],
    key: &PrivateKey,
    one_shot_ref_script_size: Option<u64>,
    cost_models: Option<Vec<Vec<i64>>>,
) -> Result<RegistryBootstrapTx, RegisterSpoError> {
    let root_element = RegistryElement {
        data: crate::cardano::registry::ElementData::Root,
        link: None,
    };
    // The registry's `Bootstrap` mint redeemer is field-less (`Constr(0, [])`) —
    // the one material difference from the ban list's, which carries the one-shot
    // `OutputReference`. Everything else is the shared one-shot bootstrap.
    let mint_redeemer_cbor =
        hex::encode(minicbor::to_vec(bootstrap_mint_redeemer()).expect("redeemer CBOR encode"));

    let built = build_oneshot_bootstrap_tx(OneShotBootstrapParams {
        policy_script: registry_script,
        bootstrap_tx_hash,
        bootstrap_output_index,
        wallet_address,
        wallet_utxos,
        key,
        one_shot_ref_script_size,
        cost_models,
        root_datum_cbor: root_element.to_cbor(),
        root_asset_name: REGISTRATION_ROOT_KEY,
        mint_redeemer_cbor,
        outref_label: "registry",
    })?;

    Ok(RegistryBootstrapTx {
        signed_tx_hex: built.signed_tx_hex,
        policy_id_hex: built.policy_id_hex,
        script_address: built.script_address,
    })
}

// ---------------------------------------------------------------------------
// Reference-script deployment
// ---------------------------------------------------------------------------

/// A built (signed, unsubmitted) reference-script deploy tx. The script lands
/// at output #0 of this tx, key-locked at the wallet address (reclaimable).
#[derive(Debug, Clone)]
pub struct RefScriptDeployTx {
    pub signed_tx_hex: String,
    pub script_hash_hex: String,
    /// Lovelace locked with the reference script (min-UTxO scales with size).
    pub lovelace: u64,
}

/// Deploy `script` as a reference script: a plain payment tx whose output #0
/// (at the wallet's own address) carries the script in its `reference_script`
/// field. register_spo then references it instead of embedding the ~12 KB
/// script twice — which would not fit in the 16 KB tx-size limit.
pub fn build_ref_script_deploy_tx(
    script: &ParameterizedScript,
    wallet_address: &str,
    wallet_utxos: &[WalletUtxo],
    key: &PrivateKey,
    cost_models: Option<Vec<Vec<i64>>>,
) -> Result<RefScriptDeployTx, RegisterSpoError> {
    // Min-UTxO scales with the serialized output, dominated by the script.
    let ref_lovelace = (script.cbor.len() as u64 + 600) * 4310;
    // A ref-script deploy executes no scripts (collaterals: vec![] below), so it
    // needs only a fee input — not a distinct collateral UTxO.
    let fee_utxo =
        select_fee(wallet_utxos, ref_lovelace + 1_000_000).map_err(RegisterSpoError::Wallet)?;

    let body = TxBuilderBody {
        inputs: vec![TxIn::PubKeyTxIn(PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: fee_utxo.tx_hash.clone(),
                tx_index: fee_utxo.output_index,
                amount: Some(wallet_input_amount(fee_utxo)),
                address: Some(wallet_address.to_string()),
            },
        })],
        outputs: vec![Output {
            address: wallet_address.to_string(),
            amount: vec![Asset::new_from_str("lovelace", &ref_lovelace.to_string())],
            datum: None,
            reference_script: Some(OutputScriptSource::ProvidedScriptSource(
                ProvidedScriptSource {
                    script_cbor: script.cbor_hex(),
                    language_version: LanguageVersion::V3,
                },
            )),
        }],
        // No scripts execute in this tx — no collateral needed.
        collaterals: vec![],
        required_signatures: vec![pub_key_hash_hex(key)],
        change_address: wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(&cost_models)),
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
        .map_err(|e| RegisterSpoError::Build(format!("whisky tx build: {e:?}")))?;
    let signed_tx_hex = sign_built_tx(&unsigned_hex, key)?;

    Ok(RefScriptDeployTx {
        signed_tx_hex,
        script_hash_hex: script.hash_hex(),
        lovelace: ref_lovelace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::bf_http::BfAmount;
    use crate::cardano::blueprint;
    use crate::cardano::registry::ElementData;
    use crate::cardano::treasury_info::TreasuryInfoDatum;
    use crate::cardano::wallet::derive_payment_key;
    use pallas_primitives::conway::{DatumOption, PseudoTransactionOutput};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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

    fn bifrost_keypair() -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[7u8; 32]).unwrap()
    }

    fn bifrost_pk() -> [u8; 32] {
        bifrost_keypair().x_only_public_key().0.serialize()
    }

    const URL: &[u8] = b"https://spo.example:18500";

    /// The nonce the fixture signatures are bound to ([REG-10]).
    fn test_nonce() -> NonceOutpoint {
        NonceOutpoint::new([0x7a; 32], 3)
    }

    /// A different one, for the replay negatives.
    fn other_nonce() -> NonceOutpoint {
        NonceOutpoint::new([0x5c; 32], 1)
    }

    fn test_sigs() -> RegistrationSignatures {
        sign_registration(&cold_skey(), &bifrost_keypair(), URL, test_nonce())
    }

    fn test_pool_id() -> [u8; 28] {
        pool_id_from_cold_vkey(&test_sigs().cold_vkey)
    }

    #[test]
    fn message_is_domain_separated_concatenation() {
        let m = registration_message(b"POOL", b"PK", b"URL", &test_nonce());
        let mut want = b"bifrost-spoPOOLPKURL".to_vec();
        want.extend_from_slice(&[0x7a; 32]);
        want.extend_from_slice(&3u32.to_le_bytes());
        assert_eq!(m, want);
    }

    /// The golden bytes, pinned against the SAME fixture the Aiken suite uses
    /// (`register_happy` in `spos-registry.ak`): cold seed [42; 32], bifrost
    /// seckey [7; 32], this URL, this outpoint. Two suites, one message format —
    /// a change to either concatenation breaks both, which is the point.
    #[test]
    fn the_registration_message_matches_the_on_chain_golden_bytes() {
        let cold: [u8; 32] = cold_skey().public_key().into();
        let pool_id = pool_id_from_cold_vkey(&cold);
        let m = registration_message(
            &pool_id,
            &bifrost_pk(),
            b"https://spo.example/bifrost",
            &test_nonce(),
        );
        assert_eq!(
            hex::encode(&m),
            "626966726f73742d73706f1dfb74a8cbcda254c65b5dd5d95df89f60b28b11de4da2ded3bc1f9b989c0b\
             76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f68747470733a2f2f73706f2e65\
             78616d706c652f626966726f73747a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a\
             7a7a7a7a03000000"
                .replace(['\n', ' '], "")
        );
        // The outpoint is the LAST 36 bytes, after the variable-length URL, and
        // that fixed width is what keeps the message unambiguous.
        assert_eq!(&m[m.len() - 36..][..32], &[0x7a; 32]);
        assert_eq!(&m[m.len() - 4..], &3u32.to_le_bytes());
    }

    /// Every field is covered, INCLUDING the nonce: change any one of them and
    /// the signatures the cold key made stop verifying.
    #[test]
    fn verification_rejects_a_tamper_in_any_field() {
        let sigs = test_sigs();
        assert!(verify_registration(&sigs, &bifrost_pk(), URL).is_ok());

        let mut moved_nonce = sigs.clone();
        moved_nonce.nonce = other_nonce();
        assert!(
            verify_registration(&moved_nonce, &bifrost_pk(), URL).is_err(),
            "a different nonce outpoint must invalidate both signatures ([REG-10])"
        );

        assert!(
            verify_registration(&sigs, &bifrost_pk(), b"https://attacker.example").is_err(),
            "a different URL must invalidate the signatures"
        );

        let mut other_key = sigs.clone();
        other_key.cold_vkey = ed25519::SecretKey::from([43u8; 32]).public_key().into();
        assert!(
            verify_registration(&other_key, &bifrost_pk(), URL).is_err(),
            "a different cold key must invalidate the signatures"
        );

        let mut flipped = sigs.clone();
        flipped.cold_sig[0] ^= 0xff;
        assert!(verify_registration(&flipped, &bifrost_pk(), URL).is_err());
    }

    /// Sign / verify round trip, which is what the one-machine flow does.
    #[test]
    fn signing_and_verifying_round_trip() {
        let sigs = test_sigs();
        let pool_id = verify_registration(&sigs, &bifrost_pk(), URL).expect("verify");
        assert_eq!(pool_id, test_pool_id());
        assert_eq!(sigs.nonce, test_nonce());
    }

    // Pinned externally (python hashlib.blake2b(b'\x11'*32, digest_size=28)):
    // a cold vkey of 32 0x11 bytes must give exactly this pool id.
    #[test]
    fn pool_id_is_blake2b_224_of_cold_vkey() {
        assert_eq!(
            hex::encode(pool_id_from_cold_vkey(&[0x11; 32])),
            "8cf0020fd6584f7b130db5ca0229c51f934821a2eb07c1df512d8aca"
        );
    }

    // The local verification mirrors the on-chain checks: Ed25519 over the raw
    // message, BIP340 over sha2_256(message). Any tamper must fail.
    #[test]
    fn sign_verify_roundtrip_and_tamper_detection() {
        let sigs = test_sigs();
        let pk = bifrost_pk();
        let pool_id = verify_registration(&sigs, &pk, URL).unwrap();
        assert_eq!(pool_id, pool_id_from_cold_vkey(&sigs.cold_vkey));

        // wrong URL → both signatures cover it → cold check fails first
        assert!(matches!(
            verify_registration(&sigs, &pk, b"https://other.example"),
            Err(RegisterSpoError::ColdSignatureInvalid)
        ));
        // flipped cold sig byte
        let mut bad = sigs.clone();
        bad.cold_sig[0] ^= 1;
        assert!(matches!(
            verify_registration(&bad, &pk, URL),
            Err(RegisterSpoError::ColdSignatureInvalid)
        ));
        // flipped bifrost sig byte
        let mut bad = sigs.clone();
        bad.bifrost_sig[0] ^= 1;
        assert!(matches!(
            verify_registration(&bad, &pk, URL),
            Err(RegisterSpoError::BifrostSignatureInvalid)
        ));
        // bifrost pk not matching the signature: the message changes with the
        // pk, so the cold signature breaks first — still a hard reject.
        let other_pk = Keypair::from_seckey_slice(&Secp256k1::new(), &[9u8; 32])
            .unwrap()
            .x_only_public_key()
            .0
            .serialize();
        assert!(verify_registration(&sigs, &other_pk, URL).is_err());
        // garbage pk bytes (not a curve point)
        assert!(matches!(
            verify_registration(&sigs, &[0xFF; 32], URL),
            Err(RegisterSpoError::BadBifrostKey(_))
        ));
    }

    // The bifrost signature verifies exactly the way the Plutus builtin will:
    // BIP340 with the 32-byte sha2_256 digest as the message.
    #[test]
    fn bifrost_sig_is_bip340_over_sha256_of_message() {
        let sigs = test_sigs();
        let pool_id = pool_id_from_cold_vkey(&sigs.cold_vkey);
        let message = registration_message(&pool_id, &bifrost_pk(), URL, &sigs.nonce);
        let digest = sha256::Hash::hash(&message).to_byte_array();
        let secp = Secp256k1::verification_only();
        secp.verify_schnorr(
            &schnorr::Signature::from_slice(&sigs.bifrost_sig).unwrap(),
            &Message::from_digest(digest),
            &XOnlyPublicKey::from_slice(&bifrost_pk()).unwrap(),
        )
        .expect("BIP340 over sha2_256(message)");
    }

    #[test]
    fn redeemer_shapes_and_canonical_encoding() {
        // Bootstrap / RegistrationListAction: bare Constr 0 → d87980.
        assert_eq!(
            hex::encode(minicbor::to_vec(bootstrap_mint_redeemer()).unwrap()),
            "d87980"
        );
        assert_eq!(
            hex::encode(minicbor::to_vec(registration_list_action_redeemer()).unwrap()),
            "d87980"
        );

        // Register: Constr 1 (tag 122), 8 fields in the pinned order,
        // canonically (indefinite-length) encoded.
        let sigs = test_sigs();
        let proof: mpf::Proof = vec![];
        // nonce_input_index goes FIRST of the indices, directly after the
        // signatures it makes single-use — the position the Aiken constructor
        // pins ([REG-10]).
        let r = register_mint_redeemer(&sigs, 0, 2, 0, 3, 2, &proof);
        let cbor = minicbor::to_vec(&r).unwrap();
        let hex_str = hex::encode(&cbor);
        assert!(hex_str.starts_with("d87a9f"), "{hex_str}");
        assert!(hex_str.ends_with("ff"), "{hex_str}");
        let back: PlutusData = minicbor::decode(&cbor).unwrap();
        let PlutusData::Constr(c) = back else {
            panic!("expected Constr");
        };
        assert_eq!(c.tag, 122);
        let fields: Vec<_> = c.fields.iter().collect();
        assert_eq!(fields.len(), 9);
        assert!(matches!(fields[0], PlutusData::BoundedBytes(b) if **b == sigs.cold_vkey));
        assert!(matches!(fields[1], PlutusData::BoundedBytes(b) if **b == sigs.cold_sig));
        assert!(matches!(fields[2], PlutusData::BoundedBytes(b) if **b == sigs.bifrost_sig));
        // The nonce index, then the four it used to be followed by.
        assert!(matches!(fields[3], PlutusData::BigInt(_)));
        assert!(matches!(fields[8], PlutusData::Array(_)));
    }

    // ---- fixtures for the snapshot/build tests --------------------------

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
                bifrost_url: b"https://other-spo.example".to_vec(),
            }),
            link: link.map(<[u8]>::to_vec),
        }
    }

    #[test]
    fn find_registry_utxos_decodes_and_rejects() {
        let policy = "aa".repeat(28);
        let root = element_utxo(
            &policy,
            &"11".repeat(32),
            0,
            2_000_000,
            b"reg-root",
            &root_element(None),
        );
        // a stray pure-ADA UTxO at the address is ignored
        let stray = BfUtxo {
            tx_hash: "22".repeat(32),
            output_index: 1,
            amount: vec![BfAmount {
                unit: "lovelace".into(),
                quantity: "1000000".into(),
            }],
            inline_datum: None,
            reference_script_hash: None,
        };
        let got = find_registry_utxos(&[stray, root.clone()], &policy).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].asset_name, b"reg-root");
        assert_eq!(got[0].lovelace, 2_000_000);
        assert_eq!(got[0].element, root_element(None));

        // element with a foreign asset → corrupt snapshot
        let mut foreign = root.clone();
        foreign.amount.push(BfAmount {
            unit: format!("{}{}", "cc".repeat(28), "dd"),
            quantity: "1".into(),
        });
        assert!(matches!(
            find_registry_utxos(&[foreign], &policy),
            Err(RegisterSpoError::BadElementUtxo(_))
        ));
        // element NFT with quantity != 1
        let mut dup = root.clone();
        dup.amount[1].quantity = "2".into();
        assert!(matches!(
            find_registry_utxos(&[dup], &policy),
            Err(RegisterSpoError::BadElementUtxo(_))
        ));
        // element without an inline datum
        let mut no_datum = root;
        no_datum.inline_datum = None;
        assert!(matches!(
            find_registry_utxos(&[no_datum], &policy),
            Err(RegisterSpoError::BadElementUtxo(_))
        ));
    }

    /// Compose a full request against a synthetic chain state and return the
    /// built tx + the values needed for assertions.
    fn build_against(
        registry_elements: Vec<BfUtxo>,
        identity_pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> (RegisterSpoTx, Tx, ParameterizedScript, ParameterizedScript) {
        build_against_treasury_at(registry_elements, identity_pairs, "dd")
    }

    /// As [`build_against`], but fallible and told about a migration window.
    fn build_with_previous(
        registry_elements: Vec<BfUtxo>,
        identity_pairs: &[(Vec<u8>, Vec<u8>)],
        previous: Option<(&str, &[BfUtxo])>,
    ) -> Result<RegisterSpoTx, RegisterSpoError> {
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
        let wallet_addr =
            crate::cardano::wallet::wallet_address(&key, pallas_addresses::Network::Testnet);
        let wallet_utxos = vec![
            WalletUtxo {
                tx_hash: "aa".repeat(32),
                output_index: 0,
                lovelace: 50_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: false,
            },
            WalletUtxo {
                tx_hash: "bb".repeat(32),
                output_index: 1,
                lovelace: 6_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: false,
            },
            WalletUtxo {
                tx_hash: "7a".repeat(32),
                output_index: 3,
                lovelace: 2_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: true,
            },
        ];
        let sigs = test_sigs();
        build_register_spo_tx(&RegisterSpoRequest {
            registry_script: &registry,
            treasury_script: &treasury,
            treasury_asset_name_hex: &nft_name,
            registry_utxos: &registry_elements,
            treasury_utxos: &treasury_utxos,
            previous_registry: previous,
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            sigs: &sigs,
            bifrost_id_pk: bifrost_pk(),
            bifrost_url: URL.to_vec(),
            invalid_before: None,
            invalid_hereafter: None,
            registry_ref: None,
            config_ref: ("cc".repeat(32), 0),
            cost_models: None,
        })
    }

    /// As [`build_against`], with the Treasury state UTxO at a caller-chosen
    /// outpoint — for the lost-race test below.
    fn build_against_treasury_at(
        registry_elements: Vec<BfUtxo>,
        identity_pairs: &[(Vec<u8>, Vec<u8>)],
        treasury_tx_byte: &str,
    ) -> (RegisterSpoTx, Tx, ParameterizedScript, ParameterizedScript) {
        let registry = registry_script();
        let treasury = treasury_script(&registry.hash);

        let trie = mpf::Trie::from_pairs(identity_pairs.iter().map(|(k, v)| (k, v))).unwrap();
        let treasury_datum = TreasuryInfoDatum {
            bifrost_identity_root: trie.root_hash(),
            current_spos_frost_key: vec![0xAB; 32],
        };
        let nft_name = "ee".repeat(32);
        let treasury_utxos = vec![BfUtxo {
            tx_hash: treasury_tx_byte.repeat(32),
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
        let wallet_addr =
            crate::cardano::wallet::wallet_address(&key, pallas_addresses::Network::Testnet);
        let wallet_utxos = vec![
            WalletUtxo {
                tx_hash: "aa".repeat(32),
                output_index: 0,
                lovelace: 50_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: false,
            },
            // Distinct pure-ADA collateral — the fee input can't double as collateral.
            WalletUtxo {
                tx_hash: "bb".repeat(32),
                output_index: 1,
                lovelace: 6_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: false,
            },
            // The reserved nonce UTxO the signatures are bound to ([REG-10]).
            // Flagged `reserved`, so fee and collateral selection leave it to
            // the one input that is allowed to spend it.
            WalletUtxo {
                tx_hash: "7a".repeat(32),
                output_index: 3,
                lovelace: 2_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: true,
            },
        ];

        let sigs = test_sigs();
        let req = RegisterSpoRequest {
            registry_script: &registry,
            treasury_script: &treasury,
            treasury_asset_name_hex: &nft_name,
            registry_utxos: &registry_elements,
            treasury_utxos: &treasury_utxos,
            previous_registry: None,
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            sigs: &sigs,
            bifrost_id_pk: bifrost_pk(),
            bifrost_url: URL.to_vec(),
            invalid_before: Some(70_000_000),
            invalid_hereafter: Some(70_432_000),
            registry_ref: None,
            config_ref: ("cc".repeat(32), 0),
            cost_models: None,
        };
        let built = build_register_spo_tx(&req).expect("build register_spo tx");
        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        (built, tx, registry, treasury)
    }

    /// `(nonce_in, anchor_in, anchor_out, treasury_in, treasury_out)` from the
    /// built transaction's mint redeemer.
    fn decoded_register_redeemer(tx: &Tx) -> (i64, i64, i64, i64, i64) {
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
        assert_eq!(c.tag, 122, "Register is constructor 1");
        let f: Vec<_> = c.fields.iter().collect();
        assert_eq!(f.len(), 9);
        let as_int = |pd: &PlutusData| -> i64 {
            let PlutusData::BigInt(pallas_primitives::BigInt::Int(i)) = pd else {
                panic!("expected int field");
            };
            i128::from(*i) as i64
        };
        (
            as_int(f[3]),
            as_int(f[4]),
            as_int(f[5]),
            as_int(f[6]),
            as_int(f[7]),
        )
    }

    /// Joining the bridge must still work while a registry migration is running
    /// ([CFG-10], [MIG-3]).
    ///
    /// `Migrate` carries a registration across without moving the Treasury
    /// state's identity root, so during a window the root commits to the
    /// bindings of BOTH lists. A registration that rebuilt the trie from the
    /// current list alone would compute a different root and `apply_registration`
    /// would refuse — which is to say nobody could join, and nobody could leave,
    /// for the length of the rollout. And a rollout is exactly when an operator
    /// is most likely to be doing one of the two.
    #[test]
    fn registering_works_while_a_migration_is_in_progress() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        // The previous registry still holds a pool that has not migrated. Its
        // binding is in the treasury root and in neither the current list nor
        // this registrant's own.
        let previous_policy = "b2".repeat(28);
        let stranded_pool = [0x99u8; 28];
        let stranded_pk = b"pk-not-yet-migrated".to_vec();
        let previous = vec![
            element_utxo(
                &previous_policy,
                &"77".repeat(32),
                0,
                2_600_000,
                REGISTRATION_ROOT_KEY,
                &root_element(Some(&stranded_pool)),
            ),
            element_utxo(
                &previous_policy,
                &"88".repeat(32),
                0,
                2_600_000,
                &stranded_pool,
                &node_element(&stranded_pk, None),
            ),
        ];
        let elements = vec![element_utxo(
            &policy,
            &"11".repeat(32),
            0,
            2_600_000,
            REGISTRATION_ROOT_KEY,
            &root_element(None),
        )];

        // The treasury root is the UNION — here, just the stranded pool, since
        // the current list is empty.
        let pairs = vec![(stranded_pk.clone(), stranded_pool.to_vec())];
        let built = build_with_previous(
            elements,
            &pairs,
            Some((previous_policy.as_str(), previous.as_slice())),
        )
        .expect("a registration during a migration window must build");
        assert_eq!(built.pool_id, test_pool_id());

        // Without the previous list the same registration cannot be built: the
        // trie rebuilt from the current list alone is a different trie.
        let elements = vec![element_utxo(
            &policy,
            &"11".repeat(32),
            0,
            2_600_000,
            REGISTRATION_ROOT_KEY,
            &root_element(None),
        )];
        let err = build_with_previous(elements, &pairs, None)
            .expect_err("the current list alone cannot rebuild the root");
        assert!(
            format!("{err}").to_lowercase().contains("root"),
            "expected a root mismatch, got {err}"
        );
    }

    /// The retry the nonce is designed to survive ([REG-10]).
    ///
    /// The Treasury state UTxO is spent by every pool's registration, exit and
    /// key rotation, so a registration racing for it loses routinely. The nonce
    /// is deliberately NOT that outpoint: it is one under the registrant's own
    /// key, which nobody else can consume. So the same signatures, made once on
    /// an air-gapped machine, build a valid transaction against a Treasury state
    /// that has since moved — no second trip to the cold key.
    ///
    /// Binding to the Treasury state instead, as Update-Y does, would have made
    /// this case fatal: the roster re-signs Update-Y online, seconds before
    /// submitting, and a cold key on an air-gapped machine cannot.
    #[test]
    fn the_same_signatures_still_build_after_the_treasury_state_moves() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        let elements = || {
            vec![element_utxo(
                &policy,
                &"11".repeat(32),
                0,
                2_600_000,
                REGISTRATION_ROOT_KEY,
                &root_element(None),
            )]
        };

        // The first attempt loses the race for the Treasury state at dd…#0.
        let (first, _, _, _) = build_against_treasury_at(elements(), &[], "dd");
        // It is now at c1…#0. The signatures are unchanged — the same
        // `test_sigs()` both times — and the transaction still builds.
        // (Not cc…: that is this fixture's Config reference outpoint, and an
        // outpoint cannot be both a spent input and a reference input.)
        let (retry, tx, _, _) = build_against_treasury_at(elements(), &[], "c1");

        assert_eq!(first.pool_id, retry.pool_id);
        assert_ne!(
            first.signed_tx_hex, retry.signed_tx_hex,
            "a different treasury outpoint is a different transaction"
        );
        let inputs: Vec<_> = tx.transaction_body.inputs.iter().collect();
        assert!(
            inputs
                .iter()
                .any(|i| i.transaction_id.as_slice() == [0xc1; 32]),
            "the retry spends the treasury state where it now is"
        );
        let (nonce_in, ..) = decoded_register_redeemer(&tx);
        assert_eq!(
            inputs[nonce_in as usize].transaction_id.as_slice(),
            [0x7a; 32],
            "and the nonce it is bound to has not moved"
        );
    }

    /// End-to-end against an EMPTY list: the anchor is the root, the identity
    /// trie is empty, the new node becomes the first element.
    #[test]
    fn build_register_spo_tx_root_anchor_end_to_end() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        let elements = vec![element_utxo(
            &policy,
            &"11".repeat(32),
            0,
            2_600_000,
            REGISTRATION_ROOT_KEY,
            &root_element(None),
        )];
        let (built, tx, registry, _treasury) = build_against(elements, &[]);

        let pool_id = test_pool_id();
        assert_eq!(built.pool_id, pool_id);
        assert_eq!(built.anchor_asset_name, REGISTRATION_ROOT_KEY);

        // Inputs are sorted (anchor 11…:0, fee aa…:0, nonce 7a…:3, treasury
        // dd…:0 → 11 < 7a < aa < dd) and the redeemer indices point at the
        // right ones. Four inputs since rev 5.6: the nonce UTxO the signatures
        // are bound to is spent here, which is what makes them single-use
        // ([REG-10]).
        let inputs: Vec<_> = tx.transaction_body.inputs.iter().collect();
        assert_eq!(inputs.len(), 4);
        let (nonce_in, anchor_in, anchor_out, treasury_in, treasury_out) =
            decoded_register_redeemer(&tx);
        assert_eq!(
            inputs[nonce_in as usize].transaction_id.as_slice(),
            [0x7a; 32],
            "the redeemer's nonce_input_index must name the signed outpoint"
        );
        assert_eq!(inputs[nonce_in as usize].index, 3);
        assert_eq!(
            inputs[anchor_in as usize].transaction_id.as_slice(),
            [0x11; 32]
        );
        assert_eq!(
            inputs[treasury_in as usize].transaction_id.as_slice(),
            [0xdd; 32]
        );
        assert_eq!((anchor_out, treasury_out), (0, 2));

        // Mint: exactly (registry policy, pool_id, +1).
        let mint = tx.transaction_body.mint.as_ref().expect("mint present");
        let policies: Vec<_> = mint.iter().collect();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].0.as_slice(), registry.hash);
        let assets: Vec<_> = policies[0].1.iter().collect();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].0.as_slice(), pool_id);
        assert_eq!(i64::from(assets[0].1), 1);

        // Output[0]: continued anchor — root data, link → pool_id, lovelace
        // unchanged (anchor_lovelace_change == 0 on-chain).
        let out0 = decode_element_output(&tx, 0);
        assert_eq!(out0.0, 2_600_000);
        assert_eq!(out0.1.data, ElementData::Root);
        assert_eq!(out0.1.link.as_deref(), Some(pool_id.as_slice()));

        // Output[1]: the new node — our identity data, link None (took over
        // the root's old link).
        let out1 = decode_element_output(&tx, 1);
        assert_eq!(
            out1.1.data,
            ElementData::Node(RegistrationNodeData {
                bifrost_id_pk: bifrost_pk().to_vec(),
                bifrost_url: URL.to_vec(),
            })
        );
        assert_eq!(out1.1.link, None);

        // Output[2]: continued treasury with the proof-derived new root.
        let PseudoTransactionOutput::PostAlonzo(t_out) = &tx.transaction_body.outputs[2] else {
            panic!("expected post-alonzo output");
        };
        let Some(DatumOption::Data(wrapped)) = &t_out.datum_option else {
            panic!("expected inline treasury datum");
        };
        let continued = TreasuryInfoDatum::from_plutus_data(&wrapped.0).unwrap();
        assert_eq!(
            continued.bifrost_identity_root,
            built.new_bifrost_identity_root
        );
        // Empty trie + insert == single-leaf root.
        let expected = mpf::Trie::empty()
            .insert(&bifrost_pk(), &pool_id)
            .unwrap()
            .root_hash();
        assert_eq!(continued.bifrost_identity_root, expected);

        // Validity window made it into the body.
        assert_eq!(
            tx.transaction_body.validity_interval_start,
            Some(70_000_000)
        );
        assert_eq!(tx.transaction_body.ttl, Some(70_432_000));

        // Signed by the wallet key.
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let pk: [u8; 32] = key.public_key().into();
        assert!(
            tx.transaction_witness_set
                .vkeywitness
                .as_ref()
                .unwrap()
                .iter()
                .any(|w| w.vkey.as_slice() == pk)
        );
    }

    /// End-to-end against a populated list: the anchor is a NODE (the
    /// predecessor), and the absence proof is non-empty.
    #[test]
    fn build_register_spo_tx_node_anchor_end_to_end() {
        let registry = registry_script();
        let policy = registry.hash_hex();
        let pool_id = test_pool_id();
        // Two existing nodes bracketing every realistic pool_id: 0x00…00 and
        // 0xff…ff. The predecessor anchor is the low node.
        let lo = [0x00u8; 28];
        let hi = [0xffu8; 28];
        assert!(lo.as_slice() < pool_id.as_slice() && pool_id.as_slice() < hi.as_slice());
        let elements = vec![
            element_utxo(
                &policy,
                &"33".repeat(32),
                0,
                2_600_000,
                REGISTRATION_ROOT_KEY,
                &root_element(Some(&lo)),
            ),
            element_utxo(
                &policy,
                &"44".repeat(32),
                1,
                2_700_000,
                &lo,
                &node_element(b"pk-lo", Some(&hi)),
            ),
            element_utxo(
                &policy,
                &"55".repeat(32),
                2,
                2_800_000,
                &hi,
                &node_element(b"pk-hi", None),
            ),
        ];
        let identity_pairs = vec![
            (b"pk-lo".to_vec(), lo.to_vec()),
            (b"pk-hi".to_vec(), hi.to_vec()),
        ];
        let (built, tx, _registry, _treasury) = build_against(elements, &identity_pairs);

        // The anchor is the low node, not the root.
        assert_eq!(built.anchor_asset_name, lo);
        let (nonce_in, anchor_in, _, treasury_in, _) = decoded_register_redeemer(&tx);
        let inputs: Vec<_> = tx.transaction_body.inputs.iter().collect();
        assert_eq!(
            inputs[nonce_in as usize].transaction_id.as_slice(),
            [0x7a; 32],
            "the nonce index holds through a node anchor too"
        );
        assert_eq!(
            (
                inputs[anchor_in as usize].transaction_id.as_slice(),
                inputs[anchor_in as usize].index
            ),
            ([0x44; 32].as_slice(), 1)
        );
        assert_eq!(
            inputs[treasury_in as usize].transaction_id.as_slice(),
            [0xdd; 32]
        );

        // Continued anchor keeps the node data + lovelace, links to pool_id;
        // the new node takes over the anchor's old link (the high node).
        let out0 = decode_element_output(&tx, 0);
        assert_eq!(out0.0, 2_700_000);
        assert_eq!(
            out0.1.data,
            ElementData::Node(RegistrationNodeData {
                bifrost_id_pk: b"pk-lo".to_vec(),
                bifrost_url: b"https://other-spo.example".to_vec(),
            })
        );
        assert_eq!(out0.1.link.as_deref(), Some(pool_id.as_slice()));
        let out1 = decode_element_output(&tx, 1);
        assert_eq!(out1.1.link.as_deref(), Some(hi.as_slice()));

        // The treasury root advanced exactly as the on-chain mpf.insert will
        // recompute it from the (non-empty) absence proof.
        let trie = mpf::Trie::from_pairs(identity_pairs.iter().map(|(k, v)| (k, v))).unwrap();
        let expected = trie.insert(&bifrost_pk(), &pool_id).unwrap().root_hash();
        assert_eq!(built.new_bifrost_identity_root, expected);
    }

    /// Building must fail loudly when the registration is unbuildable.
    #[test]
    fn build_rejects_already_registered_and_stale_treasury() {
        let registry = registry_script();
        let treasury = treasury_script(&registry.hash);
        let policy = registry.hash_hex();
        let pool_id = test_pool_id();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let wallet_addr =
            crate::cardano::wallet::wallet_address(&key, pallas_addresses::Network::Testnet);
        let wallet_utxos = vec![
            WalletUtxo {
                tx_hash: "aa".repeat(32),
                output_index: 0,
                lovelace: 50_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: false,
            },
            // Distinct pure-ADA collateral — the fee input can't double as collateral.
            WalletUtxo {
                tx_hash: "bb".repeat(32),
                output_index: 1,
                lovelace: 6_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: false,
            },
            // The reserved nonce UTxO the signatures are bound to ([REG-10]).
            // Flagged `reserved`, so fee and collateral selection leave it to
            // the one input that is allowed to spend it.
            WalletUtxo {
                tx_hash: "7a".repeat(32),
                output_index: 3,
                lovelace: 2_000_000,
                tokens: Default::default(),
                has_ref_script: false,
                reserved: true,
            },
        ];
        let sigs = test_sigs();

        // Already registered: a node with OUR pool_id exists.
        let elements = vec![
            element_utxo(
                &policy,
                &"33".repeat(32),
                0,
                2_600_000,
                REGISTRATION_ROOT_KEY,
                &root_element(Some(&pool_id)),
            ),
            element_utxo(
                &policy,
                &"44".repeat(32),
                1,
                2_700_000,
                &pool_id,
                &node_element(b"pk-x", None),
            ),
        ];
        let req = RegisterSpoRequest {
            registry_script: &registry,
            treasury_script: &treasury,
            treasury_asset_name_hex: &"ee".repeat(32),
            registry_utxos: &elements,
            treasury_utxos: &[],
            previous_registry: None,
            wallet_address: &wallet_addr,
            wallet_utxos: &wallet_utxos,
            key: &key,
            sigs: &sigs,
            bifrost_id_pk: bifrost_pk(),
            bifrost_url: URL.to_vec(),
            invalid_before: None,
            invalid_hereafter: None,
            registry_ref: None,
            config_ref: ("cc".repeat(32), 0),
            cost_models: None,
        };
        assert!(matches!(
            build_register_spo_tx(&req),
            Err(RegisterSpoError::Registry(RegistryError::AlreadyRegistered))
        ));

        // Stale treasury: datum root disagreeing with the list-derived trie.
        let elements = vec![element_utxo(
            &policy,
            &"33".repeat(32),
            0,
            2_600_000,
            REGISTRATION_ROOT_KEY,
            &root_element(None),
        )];
        let bad_datum = TreasuryInfoDatum {
            bifrost_identity_root: [9u8; 32],
            current_spos_frost_key: vec![3],
        };
        let treasury_utxos = vec![BfUtxo {
            tx_hash: "dd".repeat(32),
            output_index: 0,
            amount: vec![
                BfAmount {
                    unit: "lovelace".into(),
                    quantity: "3104330".into(),
                },
                BfAmount {
                    unit: format!("{}{}", treasury.hash_hex(), "ee".repeat(32)),
                    quantity: "1".into(),
                },
            ],
            inline_datum: Some(hex::encode(bad_datum.to_cbor())),
            reference_script_hash: None,
        }];
        let req = RegisterSpoRequest {
            registry_utxos: &elements,
            treasury_utxos: &treasury_utxos,
            previous_registry: None,
            ..req
        };
        assert!(matches!(
            build_register_spo_tx(&req),
            Err(RegisterSpoError::TreasuryInfo(
                TreasuryInfoError::RootMismatch
            ))
        ));
    }

    fn decode_element_output(tx: &Tx, index: usize) -> (u64, RegistryElement) {
        let PseudoTransactionOutput::PostAlonzo(out) = &tx.transaction_body.outputs[index] else {
            panic!("expected post-alonzo output");
        };
        let Some(DatumOption::Data(wrapped)) = &out.datum_option else {
            panic!("expected inline datum on output {index}");
        };
        let element = RegistryElement::from_plutus_data(&wrapped.0).unwrap();
        let lovelace = match &out.value {
            pallas_primitives::conway::Value::Coin(c) => *c,
            pallas_primitives::conway::Value::Multiasset(c, _) => *c,
        };
        (lovelace, element)
    }

    // ---- registry bootstrap ---------------------------------------------

    #[test]
    fn build_registry_bootstrap_end_to_end() {
        let registry = registry_script();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let wallet_addr =
            crate::cardano::wallet::wallet_address(&key, pallas_addresses::Network::Testnet);
        // The script fixture is parameterized with (0xbb…bb, 3) — the one-shot
        // must be exactly that outpoint.
        let one_shot = WalletUtxo {
            tx_hash: "bb".repeat(32),
            output_index: 3,
            lovelace: 50_000_000,
            tokens: Default::default(),
            has_ref_script: false,
            reserved: false,
        };
        // A distinct pure-ADA UTxO for collateral — collateral cannot reuse the
        // one-shot (a UTxO can't be both a spent input and collateral).
        let collateral_utxo = WalletUtxo {
            tx_hash: "cc".repeat(32),
            output_index: 0,
            lovelace: 6_000_000,
            tokens: Default::default(),
            has_ref_script: false,
            reserved: false,
        };
        let utxos = vec![one_shot, collateral_utxo];

        let built = build_registry_bootstrap_tx(
            &registry,
            &"bb".repeat(32),
            3,
            &wallet_addr,
            &utxos,
            &key,
            None,
            None,
        )
        .unwrap();
        assert_eq!(built.policy_id_hex, registry.hash_hex());

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        // The parameterizing one-shot is spent.
        assert!(
            tx.transaction_body
                .inputs
                .iter()
                .any(|i| i.transaction_id.as_slice() == [0xbb; 32] && i.index == 3)
        );
        // Collateral must be the distinct UTxO (cc..#0), never the one-shot —
        // disjoint from the spending inputs (the ledger rejects an overlap).
        let collateral = tx
            .transaction_body
            .collateral
            .as_ref()
            .expect("collateral present");
        for c in collateral.iter() {
            let c_op = (c.transaction_id.as_slice().to_vec(), c.index);
            assert!(
                !tx.transaction_body
                    .inputs
                    .iter()
                    .any(|i| (i.transaction_id.as_slice().to_vec(), i.index) == c_op),
                "collateral must not also be a spending input"
            );
        }
        assert!(
            collateral
                .iter()
                .any(|c| c.transaction_id.as_slice() == [0xcc; 32] && c.index == 0),
            "collateral must be the distinct cc..#0 UTxO"
        );
        // Mint: exactly ("reg-root", +1) under the registry policy.
        let mint = tx.transaction_body.mint.as_ref().expect("mint present");
        let policies: Vec<_> = mint.iter().collect();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].0.as_slice(), registry.hash);
        let assets: Vec<_> = policies[0].1.iter().collect();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].0.as_slice(), REGISTRATION_ROOT_KEY);
        assert_eq!(i64::from(assets[0].1), 1);
        // Output[0]: the root element (Root data, no link) at the script.
        let (_, element) = decode_element_output(&tx, 0);
        assert_eq!(element, root_element(None));
        // Signed.
        let pk: [u8; 32] = key.public_key().into();
        assert!(
            tx.transaction_witness_set
                .vkeywitness
                .as_ref()
                .unwrap()
                .iter()
                .any(|w| w.vkey.as_slice() == pk)
        );
    }

    #[test]
    fn registry_bootstrap_requires_the_exact_one_shot() {
        let registry = registry_script();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let wallet_addr =
            crate::cardano::wallet::wallet_address(&key, pallas_addresses::Network::Testnet);
        let utxos = vec![WalletUtxo {
            tx_hash: "cc".repeat(32),
            output_index: 0,
            lovelace: 50_000_000,
            tokens: Default::default(),
            has_ref_script: false,
            reserved: false,
        }];
        let err = build_registry_bootstrap_tx(
            &registry,
            &"bb".repeat(32),
            3,
            &wallet_addr,
            &utxos,
            &key,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, RegisterSpoError::Wallet(_)), "{err}");
    }
}
