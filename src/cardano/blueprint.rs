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

/// The contracts this build was compiled against (WI-066).
///
/// The blueprint is NOT a per-bridge value: a policy id is
/// `hash(compiled code ++ bootstrap outref)`, so the code is a build artifact of
/// a contracts RELEASE and the outref is what tells one bridge from another.
/// Asking each operator for the file meant asking for a value with exactly one
/// correct answer per heimdall version, whose wrong answers are silent — a stale
/// blueprint derives a policy id no deployment has, so the node reads an empty
/// registry and reports nothing. It has cost this project twice already.
///
/// Embedding also makes the upgrade atomic: there is no file to diverge from the
/// binary, because it IS the binary. See `assets/README.md` for its provenance
/// and the refresh procedure.
pub const EMBEDDED_BLUEPRINT: &str = include_str!("../../assets/plutus.json");

/// The upstream commit `EMBEDDED_BLUEPRINT` was taken from, for `--version` and
/// for the startup report — so a node can say which contracts it speaks without
/// anyone diffing a 400 kB file.
pub const EMBEDDED_BLUEPRINT_COMMIT: &str = "096f76c22e7e6143ec2ae26603061fc3aa32208f";

/// The rev-5.5 blueprint: the file heimdall embedded before rev 5.6, byte for
/// byte, from ft-bifrost-bridge `4d5516e`.
///
/// Carried so a heimdall of this version runs a bridge whose registry has not
/// been revised yet exactly as the previous release did — and, byte for byte,
/// because the pre-ceremony handshake compares a digest of the WHOLE file
/// (`http::compat`): with any other bytes a node on this version and one on the
/// previous would refuse each other, and a roster could not upgrade one node at
/// a time.
pub const EMBEDDED_BLUEPRINT_REV55: &str = include_str!("../../assets/plutus-rev5.5.json");

/// The upstream commit [`EMBEDDED_BLUEPRINT_REV55`] was taken from.
pub const EMBEDDED_BLUEPRINT_REV55_COMMIT: &str = "4d5516e149d76893280d06d184250f57d3c43175";

/// The ft-bifrost-bridge contracts release a bridge's REGISTRY runs.
///
/// Read from the Config rather than configured: rev 5.6 appended field #13
/// (`previous_spos_registry_policy_id`), a rev-5.6 genesis writes it empty, and
/// the governance Update that revises a rev-5.5 registry appends it. So a Config
/// with #13 names a rev-5.6 registry and one without names a rev-5.5 registry —
/// the one fact every node reads identically, with nothing to agree on.
///
/// What differs, for what heimdall derives: `spos_registry` takes the Config NFT
/// policy as a fourth parameter in rev 5.6, and `spo_bans` takes the Config NFT
/// policy where rev 5.5 took the registry policy. Both are applied BY PARAMETER
/// TITLE from the blueprint itself ([`spos_registry_script`], [`spo_bans_script`]),
/// so choosing the release is choosing the blueprint and nothing else. And the
/// registration and exit messages: rev 5.6 binds them to a nonce outpoint, which
/// this heimdall's builders produce and a rev-5.5 registry does not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractsRelease {
    Rev55,
    Rev56,
}

impl ContractsRelease {
    /// The newest release this heimdall carries — what a registry revision it
    /// prepares is compiled from.
    pub const LATEST: Self = Self::Rev56;

    /// The embedded blueprint of this release.
    #[must_use]
    pub fn embedded(self) -> &'static str {
        match self {
            Self::Rev55 => EMBEDDED_BLUEPRINT_REV55,
            Self::Rev56 => EMBEDDED_BLUEPRINT,
        }
    }

    /// The upstream commit that blueprint was taken from.
    #[must_use]
    pub fn commit(self) -> &'static str {
        match self {
            Self::Rev55 => EMBEDDED_BLUEPRINT_REV55_COMMIT,
            Self::Rev56 => EMBEDDED_BLUEPRINT_COMMIT,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Rev55 => "rev5.5",
            Self::Rev56 => "rev5.6",
        }
    }
}

/// The release the bridge this PROCESS reads runs, as its last Config read
/// said. Process-wide because the peer handshake reports it
/// (`http::compat::own_blueprint_digest`), and the handshake is answered from
/// shared state that has no Config of its own.
static RELEASE_IN_EFFECT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

/// Record the release the bridge's Config names. Called wherever the daemon
/// reads the Config, so the handshake follows a registry revision without a
/// restart.
pub fn set_release_in_effect(release: ContractsRelease) {
    let v = match release {
        ContractsRelease::Rev55 => 0,
        ContractsRelease::Rev56 => 1,
    };
    RELEASE_IN_EFFECT.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// The release [`set_release_in_effect`] last recorded — [`ContractsRelease::LATEST`]
/// before any Config has been read.
#[must_use]
pub fn release_in_effect() -> ContractsRelease {
    match RELEASE_IN_EFFECT.load(std::sync::atomic::Ordering::Relaxed) {
        0 => ContractsRelease::Rev55,
        _ => ContractsRelease::Rev56,
    }
}

/// The blueprint to derive scripts from: the operator's file when one is named,
/// the embedded copy otherwise.
///
/// `path` survives as a development escape hatch and for a bridge deployed from
/// a contracts release this heimdall predates. It is no longer the normal path,
/// and nothing requires it.
pub fn load_blueprint(path: Option<&str>) -> Result<std::borrow::Cow<'static, str>, String> {
    load_blueprint_for(ContractsRelease::LATEST, path)
}

/// [`load_blueprint`] for a given release: the operator's file when one is
/// named, the embedded blueprint of `release` otherwise.
pub fn load_blueprint_for(
    release: ContractsRelease,
    path: Option<&str>,
) -> Result<std::borrow::Cow<'static, str>, String> {
    match path.map(str::trim).filter(|p| !p.is_empty()) {
        None => Ok(std::borrow::Cow::Borrowed(release.embedded())),
        Some(p) => std::fs::read_to_string(p)
            .map(std::borrow::Cow::Owned)
            .map_err(|e| format!("read blueprint {p}: {e}")),
    }
}

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
        script_enterprise_address(&self.hash, network)
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

/// Enterprise (no stake part) bech32 address of a bare script hash.
///
/// The half of [`ParameterizedScript::enterprise_address`] that needs no compiled
/// code, for a script this node never parameterizes: the bridge Config publishes
/// the finished `spo_bans` policy id (#8) and the ban script address is a pure
/// function of it, so a node reads the ban list without a blueprint (WI-065).
#[must_use]
pub fn script_enterprise_address(hash: &[u8; 28], network: Network) -> String {
    let shelley = ShelleyAddress::new(
        network,
        ShelleyPaymentPart::script_hash((*hash).into()),
        ShelleyDelegationPart::Null,
    );
    Address::Shelley(shelley)
        .to_bech32()
        .expect("bech32 encode script address")
}

/// The parameter titles the blueprint declares for `title`, in order — or
/// `None` when it declares none (a hand-trimmed blueprint), in which case the
/// caller falls back to the newest release's order.
fn validator_parameter_titles(
    blueprint_json: &str,
    title: &str,
) -> Result<Option<Vec<String>>, BlueprintError> {
    let bp: serde_json::Value = serde_json::from_str(blueprint_json)
        .map_err(|e| BlueprintError::BadBlueprint(e.to_string()))?;
    let validator = bp["validators"]
        .as_array()
        .and_then(|vs| vs.iter().find(|v| v["title"].as_str() == Some(title)))
        .ok_or_else(|| BlueprintError::ValidatorNotFound(title.into()))?;
    let Some(params) = validator["parameters"].as_array() else {
        return Ok(None);
    };
    params
        .iter()
        .map(|p| {
            p["title"].as_str().map(str::to_owned).ok_or_else(|| {
                BlueprintError::BadBlueprint(format!("{title}: a parameter without a title"))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// Apply `title`'s parameters by NAME: each declared parameter is looked up in
/// `by_name`, in the order the blueprint declares them.
///
/// This is what lets one derivation serve two contracts releases whose
/// parameter lists differ — the blueprint says what it takes, and a parameter
/// this code has no value for is an error rather than a silent shift of every
/// value after it. `fallback` is the order used when the blueprint declares no
/// parameters at all.
fn apply_params_by_title(
    blueprint_json: &str,
    title: &str,
    by_name: &[(&str, PlutusData)],
    fallback: &[&str],
) -> Result<ParameterizedScript, BlueprintError> {
    let code = validator_compiled_code(blueprint_json, title)?;
    let titles: Vec<String> = match validator_parameter_titles(blueprint_json, title)? {
        Some(t) => t,
        None => fallback.iter().map(|s| (*s).to_string()).collect(),
    };
    let params = titles
        .iter()
        .map(|t| {
            by_name
                .iter()
                .find(|(name, _)| name == t)
                .map(|(_, v)| v.clone())
                .ok_or_else(|| {
                    BlueprintError::BadBlueprint(format!(
                        "{title}: parameter `{t}` is one this heimdall has no value for — a \
                         contracts release it does not know"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    apply_params(&code, &params)
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
/// `OutputReference`) and, since rev 5.5, the `treasury_policy_id` it pins.
/// The resulting hash is the `registry_policy_id`.
///
/// The third parameter is [REG-6]: `spos-registry.ak` locates the Treasury state
/// UTxO by redeemer index, and until rev 5.5 authenticated it not at all, so a
/// registrant could point the index at a wallet UTxO carrying a datum of the
/// right shape and satisfy the [REG-5] absence proof against a trie it chose.
///
/// It could not have been a parameter before: `treasury_info` took
/// `registry_policy_id`, which made the treasury policy a function of this one
/// and the dependency a cycle. [PRE-4] broke that by reading the registry policy
/// from the Config datum instead, so the build order is now a chain — Config
/// identity, then treasury, then registry.
///
/// Rev 5.6 appends `config_policy_id` ([PRE-3]): the `Migrate` branch reads
/// Config #13 to learn which policy a registration is being carried across
/// FROM, and the Config NFT policy id is the one identity safe to bake in,
/// since it depends only on its own one-shot outpoint. A rev-5.5 blueprint does
/// not declare it, and then it is not applied ([`ContractsRelease`]).
pub fn spos_registry_script(
    blueprint_json: &str,
    bootstrap_tx_id: &[u8; 32],
    bootstrap_output_index: u64,
    treasury_policy_id: &[u8; 28],
    config_policy_id: &[u8; 28],
) -> Result<ParameterizedScript, BlueprintError> {
    apply_params_by_title(
        blueprint_json,
        SPOS_REGISTRY_TITLE,
        &[
            ("bootstrap_tx_id", bytes(bootstrap_tx_id)),
            (
                "bootstrap_output_index",
                int_from_u64(bootstrap_output_index),
            ),
            ("treasury_policy_id", bytes(treasury_policy_id)),
            ("config_policy_id", bytes(config_policy_id)),
        ],
        &[
            "bootstrap_tx_id",
            "bootstrap_output_index",
            "treasury_policy_id",
            "config_policy_id",
        ],
    )
}

/// `treasury_info` parameterized by its OWN one-shot outpoint and the Config NFT
/// policy id — spec [PRE-1] (revised) and [PRE-3].
///
/// The one-shot outpoint is what makes the state NFT a singleton: rev 5.4 minted
/// it one-shot per OUTPOINT rather than per bridge, so anyone could mint a rival
/// state UTxO with a datum of their choosing. Baking the outpoint into the policy
/// id means only the deployer can ever mint, and the asset name becomes the
/// [CFG-4] constant `"BFRTRY"`.
///
/// It takes NO `registry_policy_id`: that parameter made the dependency a cycle
/// and so made [REG-6] impossible. `treasury.ak` reads the registry policy from
/// the Config datum at run time instead ([PRE-4]).
///
/// Every caller MUST apply the same three parameters or it computes a different
/// treasury_info hash (→ a different address, → the state UTxO is unfindable).
pub fn treasury_info_script(
    blueprint_json: &str,
    one_shot_tx_id: &[u8; 32],
    one_shot_output_index: u64,
    config_policy_id: &[u8; 28],
) -> Result<ParameterizedScript, BlueprintError> {
    let code = validator_compiled_code(blueprint_json, TREASURY_INFO_TITLE)?;
    apply_params(
        &code,
        &[
            bytes(one_shot_tx_id),
            int_from_u64(one_shot_output_index),
            bytes(config_policy_id),
        ],
    )
}

/// The registry policy, derived the rev-5.5 way: Config → treasury → registry.
///
/// One place for the ORDER, because getting it wrong is silent: every wrong
/// input yields a well-formed policy id, a well-formed address, and a UTxO set
/// that is simply empty. Rev 5.4 ran registry → treasury; the cycle that created
/// is what made the [REG-6] pin impossible.
pub fn registry_policy_from_bootstraps(
    blueprint_json: &str,
    registry_bootstrap: (&[u8; 32], u64),
    treasury_bootstrap: (&[u8; 32], u64),
    config_policy_id: &[u8; 28],
) -> Result<ParameterizedScript, BlueprintError> {
    let treasury = treasury_info_script(
        blueprint_json,
        treasury_bootstrap.0,
        treasury_bootstrap.1,
        config_policy_id,
    )?;
    spos_registry_script(
        blueprint_json,
        registry_bootstrap.0,
        registry_bootstrap.1,
        &treasury.hash,
        config_policy_id,
    )
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
/// 1. `config_policy_id` — the Config NFT policy id. REPLACED
///    `registration_script_hash` in rev 5.6 ([PRE-5]): the validator now reads
///    the registry policy from Config #9 at run time, which removes the DIRECT
///    dependency of this hash on the registry's.
///
///    Not the transitive one. Parameter 2 below is the fault-verifier policies,
///    and each of those takes the registry policy as its own compile parameter
///    — so this hash is still a function of the registry hash by way of them,
///    and a later registry revision will still move the ban policy, strand live
///    bans and need a Config #8 move. Ending that means the fault verifiers
///    reading #9 from the Config too.
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
///
/// Its first parameter is how the ban list learns the registry: the registry
/// policy itself in rev 5.5 (`registration_script_hash`), the Config NFT policy
/// in rev 5.6 (`config_policy_id`, [PRE-5]). Both are supplied, and the
/// blueprint's own parameter list picks ([`ContractsRelease`]).
#[allow(clippy::too_many_arguments)]
pub fn spo_bans_script(
    blueprint_json: &str,
    registry_policy_id: &[u8; 28],
    config_policy_id: &[u8; 28],
    fault_proof_policy_ids: &[[u8; 28]],
    base_ban_duration_ms: i64,
    max_faults_before_permanent: i64,
    max_validity_window_ms: i64,
    bootstrap_tx_id: &[u8; 32],
    bootstrap_output_index: u64,
) -> Result<ParameterizedScript, BlueprintError> {
    apply_params_by_title(
        blueprint_json,
        SPO_BANS_TITLE,
        &[
            ("registration_script_hash", bytes(registry_policy_id)),
            ("config_policy_id", bytes(config_policy_id)),
            (
                "fault_proof_policy_ids",
                array(fault_proof_policy_ids.iter().map(|p| bytes(p)).collect()),
            ),
            ("base_ban_duration_ms", int(base_ban_duration_ms)),
            (
                "max_faults_before_permanent",
                int(max_faults_before_permanent),
            ),
            ("max_validity_window_ms", int(max_validity_window_ms)),
            ("bootstrap_tx_id", bytes(bootstrap_tx_id)),
            (
                "bootstrap_output_index",
                int_from_u64(bootstrap_output_index),
            ),
        ],
        &[
            "config_policy_id",
            "fault_proof_policy_ids",
            "base_ban_duration_ms",
            "max_faults_before_permanent",
            "max_validity_window_ms",
            "bootstrap_tx_id",
            "bootstrap_output_index",
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
    // the rev-5.5 blueprint, and the hashes `aiken blueprint apply` produces for
    // it. Both are aiken's OWN output, generated by applying the params below to
    // this exact compiledCode — so an equal hash here means apply_params
    // reproduces `aiken blueprint apply` byte-for-byte, not merely that it
    // agrees with itself.
    const TREASURY_INFO_CODE: &str = include_str!("../../tests/fixtures/treasury_info_code.txt");
    /// tx0 = 0x66 * 32, the first of treasury_info's three params.
    const TX0_FOR_VECTOR: [u8; 32] = [0x66; 32];
    /// config_policy_id = 0x77 * 28, the third.
    const CONFIG_POLICY_FOR_VECTOR: [u8; 28] = [0x77; 28];
    /// aiken's hash after applying tx0 ALONE — the partial application the
    /// mechanics tests use.
    const TREASURY_INFO_ONE_PARAM_HASH: &str =
        "311ca823042e76e2388eb64fed27df20bed39f9700c1f4d0815189ee";
    /// aiken's hash after applying all three: (tx0, index0 = 0, config_policy).
    const TREASURY_INFO_APPLIED_HASH: &str =
        "e7f62420b4696ff8f260003aaa121870609d75a49892b79b79cc430b";

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
    // the test below.
    //
    // FROZEN on purpose, and NOT refreshed when `assets/plutus.json` is: what it
    // pins is that `apply_params` reproduces `aiken blueprint apply` byte for
    // byte, and a vector is only ground truth while both halves stay the ones
    // aiken actually produced together. Refreshing the code without re-running
    // aiken for the hash turns the assertion into "our encoder agrees with
    // itself". The CURRENT blueprint's derived ids are pinned separately, by
    // `the_embedded_blueprint_derives_pinned_policy_ids`.
    //
    // Rev 5.6 renamed this script's first parameter from
    // `registration_script_hash` to `config_policy_id` ([PRE-5]). Both are
    // 28-byte hashes, so the applied bytes — and therefore this vector — are
    // unaffected; only what the value MEANS changed. This pins the new bit — the `List<PolicyId>` param — which
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
            &[0x99; 28], // registry policy: not declared by this trimmed blueprint, so unused
            &[0x11; 28], // config_policy_id (rev 5.6, the fallback order)
            &[[0x21; 28], [0x22; 28], [0x23; 28]], // fault_proof_policy_ids (3 distinct)
            86_400_000,  // base_ban_duration_ms
            3,           // max_faults_before_permanent
            600_000,     // max_validity_window_ms
            &[0xbb; 32], // bootstrap_tx_id
            2,           // bootstrap_output_index
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
        let applied = apply_params(TREASURY_INFO_CODE.trim(), &[bytes(&TX0_FOR_VECTOR)]).unwrap();
        assert_eq!(applied.hash_hex(), TREASURY_INFO_ONE_PARAM_HASH);
    }

    // spec [PRE-1] (revised) / [PRE-3]: `treasury_info` takes its OWN one-shot
    // outpoint and the Config NFT policy id — and NOT `registry_policy_id`, which
    // is what made the dependency a cycle and the [REG-6] pin impossible. The pin
    // is aiken's own hash for the THREE-param application, so applying the wrong
    // count, order or values fails here.
    #[test]
    fn treasury_info_applies_one_shot_and_config_policy() {
        let blueprint = format!(
            r#"{{"validators":[{{"title":"{TREASURY_INFO_TITLE}","compiledCode":"{}"}}]}}"#,
            TREASURY_INFO_CODE.trim()
        );
        let script =
            treasury_info_script(&blueprint, &TX0_FOR_VECTOR, 0, &CONFIG_POLICY_FOR_VECTOR)
                .unwrap();
        assert_eq!(
            script.hash_hex(),
            TREASURY_INFO_APPLIED_HASH,
            "spec [PRE-3]: treasury_info is (tx0, index0, config_policy_id)"
        );
    }

    #[test]
    fn enterprise_address_is_script_keyed() {
        let applied = apply_params(TREASURY_INFO_CODE.trim(), &[bytes(&TX0_FOR_VECTOR)]).unwrap();
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
        let applied = apply_params(TREASURY_INFO_CODE.trim(), &[bytes(&TX0_FOR_VECTOR)]).unwrap();
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
        let registry =
            spos_registry_script(&blueprint, &[0xaa; 32], 1, &[0x77; 28], &[0x88; 28]).unwrap();
        // Re-pinned for rev 5.6: the nonce, the Migrate branch and the element
        // bound grew spos_registry's compiled code, and the fourth parameter
        // ([PRE-3], config_policy_id) is applied above.
        //
        // This test is #[ignore]d, so CI cannot tell you the pin went stale —
        // and the blueprint bump that stales it is exactly the change it exists
        // to validate. Re-pin it in the same commit that touches
        // `assets/plutus.json`, next to the four in
        // `the_embedded_blueprint_derives_pinned_policy_ids`.
        assert_eq!(
            registry.hash_hex(),
            "3ab8e80ab06527d85cc6be309869d9530a8f3cee710f374df61b2852"
        );
        // Both pins above and below are against the blueprint in
        // `assets/plutus.json`, which is what this test is pointed at in
        // practice even though the env var lets it read an upstream checkout.
        //
        // They had BOTH gone stale on main before rev 5.6 — the test is
        // `#[ignore]`d, so nothing runs it and nothing says so. If you refresh
        // the blueprint, refresh these in the same commit, next to the four in
        // `the_embedded_blueprint_derives_pinned_policy_ids`.
        let treasury = treasury_info_script(&blueprint, &[0x66; 32], 0, &[0x77; 28]).unwrap();
        assert_eq!(
            treasury.hash_hex(),
            "0a6b96f164ed40308251e66c01f07ff20218644ba3b139c3c250dd50"
        );
    }
}

#[cfg(test)]
mod embedded_blueprint_tests {
    use super::*;

    /// A bootstrap outref and Config policy with no meaning beyond being FIXED,
    /// so the only variable left is the embedded blueprint itself.
    const BOOTSTRAP_TX: [u8; 32] = [0x11; 32];
    const CONFIG_POLICY: [u8; 28] = [0x22; 28];

    /// The embedded blueprint decides every policy id heimdall derives, and a
    /// refresh that moves them silently is exactly the failure embedding exists
    /// to prevent — it has bitten this project twice (the preprod 3-pool DKG
    /// needed a specific blueprint pin, and the scenario configs still carry
    /// fault-verifier hashes from an older one).
    ///
    /// So the ids are pinned against fixed inputs. Replacing `assets/plutus.json`
    /// then fails HERE, with a visible diff, making a contracts upgrade a
    /// deliberate act rather than a quiet drift. Refreshing the blueprint means
    /// updating these values in the same commit — see `assets/README.md`.
    #[test]
    fn the_embedded_blueprint_derives_pinned_policy_ids() {
        let bp = EMBEDDED_BLUEPRINT;
        let treasury = treasury_info_script(bp, &BOOTSTRAP_TX, 0, &CONFIG_POLICY).unwrap();
        let registry =
            spos_registry_script(bp, &BOOTSTRAP_TX, 0, &treasury.hash, &CONFIG_POLICY).unwrap();
        let r1 = fault_verifier_round1_script(bp, &registry.hash).unwrap();
        let r2 = fault_verifier_round2_script(bp, &registry.hash).unwrap();
        let eq = fault_verifier_equivocation_script(bp, &registry.hash).unwrap();

        assert_eq!(
            treasury.hash_hex(),
            "1ee906cb4288e370dd3fe32bc02e96e147628034fdc3e5cc1d6e95f6",
            "treasury_info"
        );
        assert_eq!(
            registry.hash_hex(),
            "2910c959951a87646ca55735d907ec4943de34194ca508e7c1aa5980",
            "spos_registry"
        );
        assert_eq!(
            r1.hash_hex(),
            "54bfa34054fb9bbba4b75c95d714c87d19af3ca55d310aa9cf1a0474",
            "fault_verifier round1"
        );
        assert_eq!(
            r2.hash_hex(),
            "f657801501521f7e0fef9c5abf544a88da6033554bf0cf63dcc8d143",
            "fault_verifier round2"
        );
        assert_eq!(
            eq.hash_hex(),
            "c6d20d41007783fdfa903665f56f55cf748425c3142cad5d3de7f539",
            "fault_verifier equivocation"
        );
    }

    /// The provenance recorded beside the file is what lets an operator answer
    /// "which contracts does this binary speak?" without diffing 400 kB.
    /// Both releases, derived from the same inputs, against the ids binocular's
    /// independently written Scala derives from the same bytes
    /// (`FederationContractsTest`). The two implementations can only agree by
    /// applying the same parameters in the same order — which, across two
    /// releases whose parameter lists differ, is what applying them by title
    /// has to get right.
    #[test]
    fn both_releases_derive_the_ids_binocular_derives() {
        let one_shot = [0xbbu8; 32];
        let config = [0x77u8; 28];
        let derive = |release: ContractsRelease| {
            let bp = release.embedded();
            let t = treasury_info_script(bp, &one_shot, 2, &config).unwrap();
            let r = spos_registry_script(bp, &one_shot, 2, &t.hash, &config).unwrap();
            let f = [
                fault_verifier_round1_script(bp, &r.hash).unwrap().hash,
                fault_verifier_round2_script(bp, &r.hash).unwrap().hash,
                fault_verifier_equivocation_script(bp, &r.hash)
                    .unwrap()
                    .hash,
            ];
            let b = spo_bans_script(
                bp, &r.hash, &config, &f, 600_000, 3, 3_600_000, &one_shot, 2,
            )
            .unwrap();
            (t.hash_hex(), r.hash_hex(), f.map(hex::encode), b.hash_hex())
        };
        let (t, r, f, b) = derive(ContractsRelease::Rev55);
        assert_eq!(
            t,
            "935993611500f483c71ef16964698ebfc4f4f2ae5f92719331418db5"
        );
        assert_eq!(
            r,
            "b208953ab15d79539e36ea4362216af379dfeb00de73a918f2460740"
        );
        assert_eq!(
            f,
            [
                "f30a8f540b0f8e808186b63fab3d5da57149448addbdbccdb3298769",
                "a16e1d3b5859825d40e08c93d0d0465d907487fade7b5b1519ccc184",
                "c437d0fdf2790631761e7cda563e90e3063bfa5c7d81521ffd9c249f",
            ]
        );
        assert_eq!(
            b,
            "73980c165a6643d22daffa4f851352b8540d22112d26e7cff1234b4a"
        );

        let (t, r, f, b) = derive(ContractsRelease::Rev56);
        // treasury_info did not change between the releases.
        assert_eq!(
            t,
            "935993611500f483c71ef16964698ebfc4f4f2ae5f92719331418db5"
        );
        assert_eq!(
            r,
            "90bbf858a6d699e5a82b3b5c7e2f7ac8960c1908743cfde129496d12"
        );
        assert_eq!(
            f,
            [
                "4fecea15ff61fb722fb3f084444d671e45c7d07c8931bb6e14fce1da",
                "ae0e4fa378bf2f027dc2a146ec067e9c5c76e8431e31d4cd1d03020e",
                "84f9bac4cc2c8fc0d63fe1ea564f3c28bc49d95c06e2563efe88dae2",
            ]
        );
        assert_eq!(
            b,
            "6abf2d55cc123885a09c6c3bdcddd801f8822e827db164af736a72e0"
        );
    }

    /// The rev-5.5 blueprint must be the previous release's file byte for byte:
    /// the pre-ceremony handshake compares a digest of the whole file, and this
    /// is the digest the previous release reports. Anything else and a roster
    /// cannot upgrade one node at a time.
    #[test]
    fn the_rev55_blueprint_is_the_previous_release_byte_for_byte() {
        let digest = blake2b_simd::Params::new()
            .hash_length(32)
            .hash(EMBEDDED_BLUEPRINT_REV55.as_bytes());
        assert_eq!(hex::encode(&digest.as_bytes()[..8]), "e8987f35bc2e577f");
    }

    #[test]
    fn the_embedded_blueprint_is_parseable_and_attributed() {
        assert_eq!(EMBEDDED_BLUEPRINT_COMMIT.len(), 40, "a full git sha");
        let v: serde_json::Value = serde_json::from_str(EMBEDDED_BLUEPRINT).expect("valid JSON");
        assert_eq!(v["preamble"]["compiler"]["version"], "v1.1.23+8949565");
        assert!(
            v["validators"].as_array().is_some_and(|a| !a.is_empty()),
            "the blueprint must carry validators"
        );
    }
}
