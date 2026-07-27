//! Parameterize compiled Aiken validators from the bifrost blueprint
//! (`plutus.json`, CIP-57).
//!
//! Each validator's `compiledCode` is a CBOR-wrapped, flat-encoded UPLC
//! program. Parameterized validators (`spos_registry`, `treasury_info`) have
//! no script hash — and therefore no policy id or address — until their
//! parameters are applied. This module mirrors `aiken blueprint apply`:
//! UPLC-apply each parameter as a Plutus `Data` term, re-serialize, and hash
//! as Plutus V3 (`blake2b_224(0x03 || script_cbor)`).
//!
//! The parameterization chain for the bifrost state scripts is:
//!
//! ```text
//! spos_registry(bootstrap_tx_id, bootstrap_output_index)  → registry_policy_id
//! treasury_info(registry_policy_id)                       → treasury policy id / address
//! ```
//!
//! so the registry's one-shot bootstrap output ref must be chosen before the
//! `treasury_info` script (and the K1 bootstrap tx, see
//! [`crate::cardano::treasury_bootstrap`]) can exist.

use pallas_addresses::{
    Address, Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart, StakeAddress,
};
use pallas_codec::minicbor;
use pallas_crypto::hash::Hasher;
use pallas_primitives::{MaybeIndefArray, PlutusData};

use crate::cardano::plutus::{array, bytes, int, int_from_u64};

/// Blueprint title of the spos_registry minting policy (the membership-token
/// policy; its hash is the `registry_policy_id`).
pub const SPOS_REGISTRY_TITLE: &str = "bitcoin/spos_registry.spo_registry.mint";

/// Blueprint title of the treasury_info validator (mint + spend share one hash).
pub const TREASURY_INFO_TITLE: &str = "bitcoin/treasury.treasury_info.mint";

/// Blueprint title of the spo_bans validator (mint + spend + withdraw share
/// one hash; its hash is the ban-list policy id).
pub const SPO_BANS_TITLE: &str = "bitcoin/spo_bans.spo_bans.mint";

/// Blueprint title of the Round 1 invalid-payload fault verifier.
pub const FAULT_VERIFIER_ROUND1_TITLE: &str =
    "bitcoin/fault_verifier_round1.fault_verifier_round1.mint";

/// Blueprint title of the Round 2 invalid-payload fault verifier.
pub const FAULT_VERIFIER_ROUND2_TITLE: &str =
    "bitcoin/fault_verifier_round2.fault_verifier_round2.mint";

/// Blueprint title of the direct equivocation fault verifier.
pub const FAULT_VERIFIER_EQUIVOCATION_TITLE: &str =
    "bitcoin/fault_verifier_equivocation.fault_verifier_equivocation.mint";

/// The three specialized fault verifier policies accepted by `spo_bans`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultVerifierKind {
    Round1,
    Round2,
    Equivocation,
}

impl FaultVerifierKind {
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Round1 => FAULT_VERIFIER_ROUND1_TITLE,
            Self::Round2 => FAULT_VERIFIER_ROUND2_TITLE,
            Self::Equivocation => FAULT_VERIFIER_EQUIVOCATION_TITLE,
        }
    }
}

#[derive(Debug)]
pub enum BlueprintError {
    /// The blueprint file is not valid JSON or lacks the expected structure.
    BadBlueprint(String),
    /// No validator with the given title.
    ValidatorNotFound(String),
    BadHex(String),
    /// UPLC decode / parameter application / re-encode failed.
    Uplc(String),
}

impl std::fmt::Display for BlueprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadBlueprint(e) => write!(f, "bad blueprint: {e}"),
            Self::ValidatorNotFound(t) => write!(f, "validator not in blueprint: {t}"),
            Self::BadHex(e) => write!(f, "bad hex: {e}"),
            Self::Uplc(e) => write!(f, "uplc: {e}"),
        }
    }
}

impl std::error::Error for BlueprintError {}

/// A validator with all parameters applied: ready to provide as a tx witness
/// and to derive policy id / address from.
#[derive(Debug, Clone)]
pub struct ParameterizedScript {
    /// CBOR-wrapped flat program — the blueprint `compiledCode` form, which is
    /// also what `ProvidedScriptSource` / the witness set expect.
    pub cbor: Vec<u8>,
    /// Plutus V3 script hash (= policy id for a minting policy).
    pub hash: [u8; 28],
}

impl ParameterizedScript {
    #[must_use]
    pub fn cbor_hex(&self) -> String {
        hex::encode(&self.cbor)
    }

    #[must_use]
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }

    /// Enterprise (no stake part) bech32 address of the script. The bifrost
    /// state validators require exactly this shape: `Address { payment:
    /// Script(hash), stake: None }`.
    #[must_use]
    pub fn enterprise_address(&self, network: Network) -> String {
        let shelley = ShelleyAddress::new(
            network,
            ShelleyPaymentPart::script_hash(self.hash.into()),
            ShelleyDelegationPart::Null,
        );
        Address::Shelley(shelley)
            .to_bech32()
            .expect("bech32 encode script address")
    }

    /// The bech32 reward (stake) address (`stake_test1…` / `stake1…`) of this
    /// script's hash used as a stake credential — e.g. the key for a
    /// withdraw-validator's zero-amount reward withdrawal (the ApplyBan action
    /// on `spo_bans`). Sibling of [`Self::enterprise_address`]; both derive an
    /// address from the script hash. Takes `mainnet: bool` (not `Network`) so
    /// only the two valid networks are representable and the bech32 encoding is
    /// total.
    #[must_use]
    pub fn reward_address(&self, mainnet: bool) -> String {
        let network = if mainnet {
            Network::Mainnet
        } else {
            Network::Testnet
        };
        let shelley = ShelleyAddress::new(
            network,
            // Payment part is unused by the StakeAddress derivation; reuse the hash.
            ShelleyPaymentPart::script_hash(self.hash.into()),
            ShelleyDelegationPart::script_hash(self.hash.into()),
        );
        StakeAddress::try_from(shelley)
            .expect("a script delegation part always yields a StakeAddress")
            .to_bech32()
            .expect("bech32 of a mainnet/testnet stake address is total")
    }
}

/// `compiledCode` (hex) of the validator titled `title`.
pub fn validator_compiled_code(
    blueprint_json: &str,
    title: &str,
) -> Result<String, BlueprintError> {
    let bp: serde_json::Value = serde_json::from_str(blueprint_json)
        .map_err(|e| BlueprintError::BadBlueprint(e.to_string()))?;
    let validators = bp["validators"]
        .as_array()
        .ok_or_else(|| BlueprintError::BadBlueprint("no validators array".into()))?;
    let validator = validators
        .iter()
        .find(|v| v["title"].as_str() == Some(title))
        .ok_or_else(|| BlueprintError::ValidatorNotFound(title.into()))?;
    validator["compiledCode"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| BlueprintError::BadBlueprint(format!("{title}: no compiledCode")))
}

/// Plutus V3 script hash: `blake2b_224(0x03 || script_cbor)`.
#[must_use]
pub fn script_hash_v3(script_cbor: &[u8]) -> [u8; 28] {
    let mut hasher = Hasher::<224>::new();
    hasher.input(&[0x03]);
    hasher.input(script_cbor);
    (*hasher.finalize()).into()
}

/// Apply Plutus-data parameters (in order) to a `compiledCode` and hash the
/// result. Byte-equivalent to running `aiken blueprint apply` once per param.
pub fn apply_params(
    compiled_code_hex: &str,
    params: &[PlutusData],
) -> Result<ParameterizedScript, BlueprintError> {
    let script =
        hex::decode(compiled_code_hex).map_err(|e| BlueprintError::BadHex(e.to_string()))?;
    // uplc's apply_params_to_script unwrap()s the params decode and panics on a
    // non-Array — unreachable from here because we encode the Array ourselves
    // (keep it that way). Garbage `compiled_code_hex` returns Err cleanly;
    // pathologically nested code can still abort via unbounded recursion in
    // uplc's flat decoder, acceptable for an operator-supplied local file.
    // NB: any future Constr-typed param must be canonically encoded
    // (indefinite-length fields) — the encoding is embedded into the script.
    let params_array = PlutusData::Array(MaybeIndefArray::Def(params.to_vec()));
    let params_cbor =
        minicbor::to_vec(&params_array).map_err(|e| BlueprintError::Uplc(e.to_string()))?;
    let applied = uplc::tx::apply_params_to_script(&params_cbor, &script)
        .map_err(|e| BlueprintError::Uplc(e.to_string()))?;
    let hash = script_hash_v3(&applied);
    Ok(ParameterizedScript {
        cbor: applied,
        hash,
    })
}

/// `spos_registry` parameterized by its one-shot bootstrap output ref
/// (`bootstrap_tx_id`, `bootstrap_output_index` — two separate params, not an
/// `OutputReference`). The resulting hash is the `registry_policy_id`.
pub fn spos_registry_script(
    blueprint_json: &str,
    bootstrap_tx_id: &[u8; 32],
    bootstrap_output_index: u64,
) -> Result<ParameterizedScript, BlueprintError> {
    let code = validator_compiled_code(blueprint_json, SPOS_REGISTRY_TITLE)?;
    apply_params(
        &code,
        &[bytes(bootstrap_tx_id), int_from_u64(bootstrap_output_index)],
    )
}

/// `treasury_info` parameterized by (registry policy id, TM-NFT policy id). N10b
/// added the 2nd param: `treasury.ak::FederationReset` authenticates the referenced
/// Confirmed TM by the TM NFT (`tm_nft_policy_id` = the binocular
/// TreasuryMovementValidator script hash — derive it with [`script_hash_v3`] over
/// `cardano.tm_script_cbor`). Every caller MUST pass the same value or they compute
/// a different treasury_info hash (→ a different address, → the state UTxO is
/// unfindable).
pub fn treasury_info_script(
    blueprint_json: &str,
    registry_policy_id: &[u8; 28],
    tm_nft_policy_id: &[u8; 28],
) -> Result<ParameterizedScript, BlueprintError> {
    let code = validator_compiled_code(blueprint_json, TREASURY_INFO_TITLE)?;
    apply_params(&code, &[bytes(registry_policy_id), bytes(tm_nft_policy_id)])
}

/// The TM-NFT policy id = the binocular `TreasuryMovementValidator` script hash,
/// derived from its fully-applied CBOR (`cardano.tm_script_cbor`, the same bytes
/// `binocular tm-script` prints). This is the 2nd parameter every
/// [`treasury_info_script`] call needs (N10b), so all callers agree on the
/// treasury_info address.
pub fn tm_nft_policy_from_script_cbor(
    tm_script_cbor_hex: &str,
) -> Result<[u8; 28], BlueprintError> {
    let cbor = hex::decode(tm_script_cbor_hex.trim())
        .map_err(|e| BlueprintError::BadHex(e.to_string()))?;
    Ok(script_hash_v3(&cbor))
}

/// The blueprint's own `hash` field of the validator titled `title` — final
/// only for PARAMETERLESS validators (e.g. fault_verifier); a parameterized
/// validator's blueprint hash is pre-application and meaningless.
pub fn validator_hash(blueprint_json: &str, title: &str) -> Result<[u8; 28], BlueprintError> {
    let bp: serde_json::Value = serde_json::from_str(blueprint_json)
        .map_err(|e| BlueprintError::BadBlueprint(e.to_string()))?;
    let validators = bp["validators"]
        .as_array()
        .ok_or_else(|| BlueprintError::BadBlueprint("no validators array".into()))?;
    let validator = validators
        .iter()
        .find(|v| v["title"].as_str() == Some(title))
        .ok_or_else(|| BlueprintError::ValidatorNotFound(title.into()))?;
    let hash_hex = validator["hash"]
        .as_str()
        .ok_or_else(|| BlueprintError::BadBlueprint(format!("{title}: no hash")))?;
    hex::decode(hash_hex)
        .map_err(|e| BlueprintError::BadHex(e.to_string()))?
        .try_into()
        .map_err(|_| BlueprintError::BadBlueprint(format!("{title}: hash is not 28 bytes")))
}

/// A specialized fault verifier minting policy, parameterized by the
/// `spos_registry` policy id (`registration_script_hash`). The validator reads
/// the accused registration node to bind `bifrost_id_pk -> accused_pool_id`.
pub fn fault_verifier_script(
    blueprint_json: &str,
    kind: FaultVerifierKind,
    registration_script_hash: &[u8; 28],
) -> Result<ParameterizedScript, BlueprintError> {
    let code = validator_compiled_code(blueprint_json, kind.title())?;
    apply_params(&code, &[bytes(registration_script_hash)])
}

pub fn fault_verifier_round1_script(
    blueprint_json: &str,
    registration_script_hash: &[u8; 28],
) -> Result<ParameterizedScript, BlueprintError> {
    fault_verifier_script(
        blueprint_json,
        FaultVerifierKind::Round1,
        registration_script_hash,
    )
}

pub fn fault_verifier_round2_script(
    blueprint_json: &str,
    registration_script_hash: &[u8; 28],
) -> Result<ParameterizedScript, BlueprintError> {
    fault_verifier_script(
        blueprint_json,
        FaultVerifierKind::Round2,
        registration_script_hash,
    )
}

pub fn fault_verifier_equivocation_script(
    blueprint_json: &str,
    registration_script_hash: &[u8; 28],
) -> Result<ParameterizedScript, BlueprintError> {
    fault_verifier_script(
        blueprint_json,
        FaultVerifierKind::Equivocation,
        registration_script_hash,
    )
}

/// `spo_bans` parameterized by its full upstream parameter list (7 params, in
/// the order the compiled validator declares them):
///
/// 1. `registration_script_hash` — the registry policy id (the registered-pool
///    reference input is checked against it).
/// 2. `fault_proof_policy_ids` — the authorized fault-verifier policies. The
///    contract's `ban_config_ok` requires **exactly 3, all distinct**, and the
///    hash is order-sensitive, so pass them in the exact deployment order.
/// 3. `base_ban_duration_ms`, 4. `max_faults_before_permanent`,
/// 5. `max_validity_window_ms` — ban-schedule params baked into the policy id
///    (the same values must drive the `BanNodeData` an ApplyBan tx emits).
/// 6/7. the one-shot bootstrap output ref.
///
/// The resulting hash is the ban-list policy id; the enterprise address of the
/// same hash holds the list elements.
///
/// NOTE: this matches upstream FluidTokens `main` (WI-018). The earlier
/// 4-parameter form (single fault policy, no ban-schedule params) predated the
/// evidence-bound rework and derived the wrong hash/address.
#[allow(clippy::too_many_arguments)]
pub fn spo_bans_script(
    blueprint_json: &str,
    registration_script_hash: &[u8; 28],
    fault_proof_policy_ids: &[[u8; 28]],
    base_ban_duration_ms: i64,
    max_faults_before_permanent: i64,
    max_validity_window_ms: i64,
    bootstrap_tx_id: &[u8; 32],
    bootstrap_output_index: u64,
) -> Result<ParameterizedScript, BlueprintError> {
    let code = validator_compiled_code(blueprint_json, SPO_BANS_TITLE)?;
    apply_params(
        &code,
        &[
            bytes(registration_script_hash),
            array(fault_proof_policy_ids.iter().map(|p| bytes(p)).collect()),
            int(base_ban_duration_ms),
            int(max_faults_before_permanent),
            int(max_validity_window_ms),
            bytes(bootstrap_tx_id),
            int_from_u64(bootstrap_output_index),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // `bitcoin/treasury_movement.treasury_movement.mint` from the bifrost
    // blueprint (ft-bifrost-bridge @ 4bc8b34): zero params, so the blueprint's
    // own `hash` field is a ground-truth vector for `script_hash_v3`.
    const TREASURY_MOVEMENT_CODE: &str = "59012701010029800aba4aba2aba1aab9faab9eaab9dab9cab9a488888888c9660026464653001300737540032225980099b8748000c028dd5001c4c9660020030028992cc004006007003801c00e264b30013011003802c01100f1bae0014044601c0028068c02cdd5001c0050084c02800e601400491112cc004cdc3a40000091325980080146600200514a30094011009804c0260128088dd7180718061baa0058acc004cdc3a400400913233225980080246600200914a300b401900b805c02e0168098c03c004c03cc040004c030dd5002c528201240243009300a001300900130053754015149a2a660069211856616c696461746f722072657475726e65642066616c7365001365640082a660049201135f72656465656d65723a2052656465656d6572001601";
    const TREASURY_MOVEMENT_HASH: &str = "372db474c29284bbcbb4b6527c0749d81ad3f2d524a57c55c83044c8";

    // `bitcoin/treasury.treasury_info.mint` (unparameterized compiledCode) from
    // the same blueprint, and the hash `aiken blueprint apply` produces for it
    // with param `581c796609d4a6a9f0bda089817e69e56e555356b2eca684f747c91baa16`
    // (a registry policy id; itself aiken's output for spos_registry applied to
    // bootstrap_tx_id = 0xaa*32, bootstrap_output_index = 1).
    const TREASURY_INFO_CODE: &str = include_str!("../../tests/fixtures/treasury_info_code.txt");
    const REGISTRY_POLICY_FOR_VECTOR: [u8; 28] = [
        0x79, 0x66, 0x09, 0xd4, 0xa6, 0xa9, 0xf0, 0xbd, 0xa0, 0x89, 0x81, 0x7e, 0x69, 0xe5, 0x6e,
        0x55, 0x53, 0x56, 0xb2, 0xec, 0xa6, 0x84, 0xf7, 0x47, 0xc9, 0x1b, 0xaa, 0x16,
    ];
    const TREASURY_INFO_APPLIED_HASH: &str =
        "c62f114c966a2ad65ecb27a871600b5b480b08ea98b5ff65625ac627";

    // A parameterized fault-verifier compiledCode fixture. The concrete
    // validator title is supplied by the blueprint, while the apply mechanics
    // are identical across Round 1, Round 2, and equivocation policies.
    const FAULT_VERIFIER_CODE: &str = include_str!("../../tests/fixtures/fault_verifier_code.txt");
    const FAULT_VERIFIER_HASH: &str = "3b3a74a942ee06b74e56ae07b1b336c33b5257771c686e0f41293cae";

    #[test]
    fn script_hash_v3_matches_blueprint() {
        let code = hex::decode(TREASURY_MOVEMENT_CODE).unwrap();
        assert_eq!(hex::encode(script_hash_v3(&code)), TREASURY_MOVEMENT_HASH);
    }

    // `bitcoin/spo_bans.spo_bans` unapplied compiledCode + the hash
    // `aiken blueprint apply` (v1.1.21) produces for the 7-param application in
    // the test below. This pins the new bit — the `List<PolicyId>` param — which
    // must be encoded as a canonical INDEFINITE-length CBOR array (`9f..ff`, what
    // `plutus::array` emits and what the on-chain ban datum already uses). aiken
    // is NOT length-form agnostic: a definite array (`83..`) hashes differently,
    // so heimdall's encoding must match the deployment's canonical form.
    const SPO_BANS_CODE: &str = include_str!("../../tests/fixtures/spo_bans_code.txt");

    #[test]
    fn spo_bans_script_matches_aiken_blueprint_apply() {
        let blueprint = format!(
            r#"{{"validators":[{{"title":"{SPO_BANS_TITLE}","compiledCode":"{}"}}]}}"#,
            SPO_BANS_CODE.trim()
        );
        let script = spo_bans_script(
            &blueprint,
            &[0x11; 28],                           // registration_script_hash
            &[[0x21; 28], [0x22; 28], [0x23; 28]], // fault_proof_policy_ids (3 distinct)
            86_400_000,                            // base_ban_duration_ms
            3,                                     // max_faults_before_permanent
            600_000,                               // max_validity_window_ms
            &[0xbb; 32],                           // bootstrap_tx_id
            2,                                     // bootstrap_output_index
        )
        .unwrap();
        // Equal hashes ⇒ byte-identical applied program ⇒ our List<PolicyId>
        // (indefinite-array) param encoding matches `aiken blueprint apply`.
        assert_eq!(
            script.hash_hex(),
            "1f99fd037b85246d376c3985b970be82a7c417f3f95cbdd075bd3ece"
        );
    }

    // fault_verifier is parameterized by registration_script_hash: applying it
    // changes the program + policy id deterministically (the apply_params
    // byte-exactness vs `aiken blueprint apply` is pinned by the spo_bans test
    // and the full-apply-pipeline test below).
    #[test]
    fn fault_verifier_script_applies_registry_param() {
        let blueprint = format!(
            r#"{{"validators":[{{"title":"{FAULT_VERIFIER_ROUND1_TITLE}","compiledCode":"{}","hash":"{FAULT_VERIFIER_HASH}"}}]}}"#,
            FAULT_VERIFIER_CODE.trim()
        );
        // Unapplied blueprint hash.
        assert_eq!(
            hex::encode(validator_hash(&blueprint, FAULT_VERIFIER_ROUND1_TITLE).unwrap()),
            FAULT_VERIFIER_HASH
        );
        // Applying the registry param is deterministic and bakes it into the cbor.
        let reg = [0x11u8; 28];
        let s1 = fault_verifier_round1_script(&blueprint, &reg).unwrap();
        let s2 = fault_verifier_script(&blueprint, FaultVerifierKind::Round1, &reg).unwrap();
        assert_eq!(s1.hash, s2.hash);
        assert_ne!(s1.hash_hex(), FAULT_VERIFIER_HASH);
        assert_ne!(s1.cbor, hex::decode(FAULT_VERIFIER_CODE.trim()).unwrap());
        // A different registry → a different FaultProof policy id.
        let other = fault_verifier_round1_script(&blueprint, &[0x22u8; 28]).unwrap();
        assert_ne!(s1.hash, other.hash);
    }

    // The full apply pipeline reproduces `aiken blueprint apply` byte-for-byte:
    // equal hashes ⇒ equal script bytes (the hash covers the whole program).
    #[test]
    fn apply_params_matches_aiken_blueprint_apply() {
        let applied = apply_params(
            TREASURY_INFO_CODE.trim(),
            &[bytes(&REGISTRY_POLICY_FOR_VECTOR)],
        )
        .unwrap();
        assert_eq!(applied.hash_hex(), TREASURY_INFO_APPLIED_HASH);
    }

    #[test]
    fn enterprise_address_is_script_keyed() {
        let applied = apply_params(
            TREASURY_INFO_CODE.trim(),
            &[bytes(&REGISTRY_POLICY_FOR_VECTOR)],
        )
        .unwrap();
        let addr = applied.enterprise_address(Network::Testnet);
        assert!(addr.starts_with("addr_test1w"), "script address: {addr}");
        // Round-trip: the payment part is our script hash, no delegation part.
        match Address::from_bech32(&addr).unwrap() {
            Address::Shelley(s) => {
                assert_eq!(s.payment().as_hash().as_slice(), applied.hash);
                assert!(matches!(s.delegation(), ShelleyDelegationPart::Null));
            }
            other => panic!("expected shelley address, got {other:?}"),
        }
    }

    #[test]
    fn enterprise_address_mainnet_prefix() {
        let applied = apply_params(
            TREASURY_INFO_CODE.trim(),
            &[bytes(&REGISTRY_POLICY_FOR_VECTOR)],
        )
        .unwrap();
        let addr = applied.enterprise_address(Network::Mainnet);
        assert!(addr.starts_with("addr1w"), "mainnet script address: {addr}");
    }

    // reward_address: the script hash as a stake credential — the key for a
    // withdraw validator's reward withdrawal (ApplyBan on spo_bans).
    #[test]
    fn reward_address_is_script_keyed_and_network_tagged() {
        use pallas_addresses::StakePayload;
        let script = ParameterizedScript {
            cbor: vec![],
            hash: [0xAB; 28],
        };
        let testnet = script.reward_address(false);
        assert!(testnet.starts_with("stake_test1"), "{testnet}");
        // Decodes to a SCRIPT stake credential carrying our hash.
        match Address::from_bech32(&testnet).unwrap() {
            Address::Stake(s) => match s.payload() {
                StakePayload::Script(h) => assert_eq!(h.as_slice(), script.hash),
                StakePayload::Stake(_) => panic!("expected a SCRIPT stake payload"),
            },
            other => panic!("expected a stake address, got {other:?}"),
        }
        // Reward-account header byte: 0xF0 script+testnet, 0xF1 script+mainnet.
        let header = |b: &str| match Address::from_bech32(b).unwrap() {
            Address::Stake(s) => s.to_vec()[0],
            other => panic!("expected a stake address, got {other:?}"),
        };
        assert_eq!(header(&testnet), 0xF0);
        let mainnet = script.reward_address(true);
        assert!(mainnet.starts_with("stake1"), "{mainnet}");
        assert_eq!(header(&mainnet), 0xF1);
    }

    // Valid hex that is not a CBOR-wrapped UPLC program must come back as a
    // clean Err — never a panic (the uplc unwrap()s live on the params side,
    // which we encode ourselves).
    #[test]
    fn apply_params_rejects_garbage_code() {
        let err = apply_params("deadbeef", &[int_from_u64(1)]).unwrap_err();
        assert!(matches!(err, BlueprintError::Uplc(_)), "{err}");
    }

    // Full chain against the real upstream blueprint — needs the FluidTokens
    // checkout. Run with:
    //   BIFROST_PLUTUS_JSON=.../onchain/plutus.json cargo test -- --ignored
    // Expected hashes generated with `aiken blueprint apply` (aiken v1.1.21).
    #[test]
    #[ignore = "needs $BIFROST_PLUTUS_JSON (ft-bifrost-bridge checkout)"]
    fn registry_then_treasury_chain_matches_aiken() {
        let path = std::env::var("BIFROST_PLUTUS_JSON")
            .expect("set BIFROST_PLUTUS_JSON to the upstream plutus.json");
        let blueprint = std::fs::read_to_string(path).unwrap();
        let registry = spos_registry_script(&blueprint, &[0xaa; 32], 1).unwrap();
        // N10b: spos_registry references TreasuryDatum, whose shape changed (federation
        // fields + last_reset_tm_txid), so its compiled code — and this hash — moved.
        assert_eq!(
            registry.hash_hex(),
            "37df878dca019a2806def25f6befb7b0bfba6de84e192bbf68ad60ba"
        );
        // N10b: treasury_info is 2-param (registry, tm_nft). A fixed synthetic
        // tm_nft (0x11*28) makes the applied hash reproducible; because the blueprint
        // is aiken's own output and apply_params matches `aiken blueprint apply`
        // byte-for-byte, the pinned hash is aiken's 2-param application.
        let treasury = treasury_info_script(&blueprint, &registry.hash, &[0x11u8; 28]).unwrap();
        assert_eq!(
            treasury.hash_hex(),
            "e196f69aff75052cf69a9a9a68e9c58345ca4252f1321b1695a89133"
        );
    }
}
