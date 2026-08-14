//! On-chain SPO registry snapshot → epoch roster (WI-010).
//!
//! Reads the full `spos_registry.ak` linked list from the chain and turns it
//! into the [`Roster`] the epoch state machine runs DKG against:
//!
//! 1. fetch every UTxO at the registry script address, decode the element
//!    datums ([`find_registry_utxos`]) and reconstruct the integrity-checked
//!    list ([`RegistryList::from_elements`]: one root, links ascending, no
//!    orphans);
//! 2. rebuild the `bifrost_id_pk → pool_id` identity trie off-chain and
//!    require its root to equal the `treasury_info` datum's
//!    `bifrost_identity_root` — a mismatch means the registry UTxO set and
//!    the treasury state disagree (a mid-update read, a stale query layer,
//!    or corrupt state) and the snapshot MUST NOT be trusted;
//! 3. order participants lexicographically by `bifrost_id_pk` (the spec's
//!    DKG ordering — NOT the `pool_id` order the on-chain list is keyed by)
//!    and assign FROST identifiers `1..=n`.
//!
//! The snapshot functions are pure over caller-fetched UTxO sets so they are
//! testable offline; [`fetch_registry_snapshot`] / [`RegistryRosterSource`]
//! add the Blockfrost legwork for `CardanoChain::query_roster` and the
//! `show-roster` CLI.

use std::collections::{BTreeMap, BTreeSet};

use frost_secp256k1_tr::Identifier;

use crate::cardano::bf_http::{self, BfUtxo};
use crate::cardano::blueprint::{self, BlueprintError};
use crate::cardano::mpf;
use crate::cardano::register_spo::{RegisterSpoError, find_registry_utxos};
use crate::cardano::registry::{RegistryError, RegistryList};
use crate::cardano::treasury_spend::{TreasurySpendError, TreasuryStateUtxo, find_treasury_state};
use crate::epoch::state::{Roster, SpoInfo};

/// frost-core's `validate_num_of_signers` (called by `dkg::part1`) rejects
/// `min_signers < 2` and `max_signers < 2` outright, so a roster below this
/// size can never run DKG — fail at construction, not rounds later inside
/// FROST with an opaque `InvalidMinSigners`.
pub const FROST_MIN_PARTICIPANTS: u16 = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RosterError {
    /// A UTxO at the registry address is not a well-formed list element.
    Element(RegisterSpoError),
    /// The element set does not form a single well-formed chain.
    List(RegistryError),
    /// The `treasury_info` state UTxO could not be located/decoded.
    Treasury(TreasurySpendError),
    /// Rebuilding the identity trie failed.
    Mpf(mpf::MpfError),
    /// Two registrations carry the same `bifrost_id_pk`. The on-chain
    /// absence proof makes this impossible for honest state — refuse the
    /// snapshot rather than pick one.
    DuplicateIdPk(Vec<u8>),
    /// The rebuilt identity-trie root disagrees with the treasury datum.
    RootMismatch {
        datum: mpf::Hash,
        computed: mpf::Hash,
    },
    /// HTTP/Blockfrost failure fetching the UTxO sets.
    Fetch(String),
    /// Fewer registered SPOs than FROST DKG can run with
    /// ([`FROST_MIN_PARTICIPANTS`]).
    TooFew { got: usize },
    /// `bifrost_url` is not a usable base URL (peers join `"/dkg/..."` onto
    /// it verbatim, and the owner binds its local HTTP port from it).
    BadUrl { pool_id: Vec<u8>, reason: String },
    /// Two registrations share a `bifrost_url`. Today's peer transport keys
    /// payloads by URL alone (the server ignores the pool_id path segment),
    /// so a shared URL makes peers' DKG rounds time out undiagnosably —
    /// refuse loudly here instead. Can be relaxed once WI-013's
    /// pool_id-namespaced payload paths land.
    DuplicateUrl { url: String },
    /// A `min_signers` override outside `[2, max_signers]` — rejected rather
    /// than clamped, since silently altering a signing threshold masks a
    /// security-critical misconfiguration.
    BadMinSigners { requested: u16, max: u16 },
    /// More registrations than FROST identifiers (`u16`).
    TooMany(usize),
    /// Bad blueprint/bootstrap configuration for the registry source.
    Config(String),
    /// This node's locally compiled `treasury_info` hash disagrees with the one
    /// the bridge Config publishes at #10.
    ///
    /// Distinct from [`Self::Config`] because the two are opposites on the
    /// published route: a derivation that FAILS there costs only the Update-Y
    /// capability (the addresses come from the Config), while one that SUCCEEDS
    /// and disagrees means an Update-Y built here would write the key handoff to
    /// an address no other SPO reads.
    DerivedMismatch { derived: String, published: String },
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Element(e) => write!(f, "registry element: {e}"),
            Self::List(e) => write!(f, "registry list: {e}"),
            Self::Treasury(e) => write!(f, "treasury_info: {e}"),
            Self::Mpf(e) => write!(f, "identity trie: {e:?}"),
            Self::DuplicateIdPk(pk) => {
                write!(f, "duplicate bifrost_id_pk {}", hex::encode(pk))
            }
            Self::RootMismatch { datum, computed } => write!(
                f,
                "identity root mismatch: treasury datum {} != rebuilt {} \
                 (registry and treasury_info disagree — refusing the snapshot)",
                hex::encode(datum),
                hex::encode(computed)
            ),
            Self::Fetch(e) => write!(f, "fetch: {e}"),
            Self::TooFew { got } => write!(
                f,
                "only {got} registered SPO(s) — FROST DKG needs at least \
                 {FROST_MIN_PARTICIPANTS}"
            ),
            Self::BadUrl { pool_id, reason } => {
                write!(f, "bifrost_url of pool {}: {reason}", hex::encode(pool_id))
            }
            Self::DuplicateUrl { url } => {
                write!(f, "two registrations share bifrost_url {url:?}")
            }
            Self::BadMinSigners { requested, max } => write!(
                f,
                "min_signers override {requested} outside [{FROST_MIN_PARTICIPANTS}, {max}]"
            ),
            Self::TooMany(n) => write!(f, "{n} registrations exceed u16 FROST identifiers"),
            Self::Config(e) => write!(f, "registry source config: {e}"),
            Self::DerivedMismatch { derived, published } => write!(
                f,
                "this node derives treasury_info policy {derived} but the bridge Config \
                 publishes {published} (field #10) — an Update-Y built here would write the \
                 key handoff to an address no other SPO reads. Check \
                 cardano.registry_blueprint, or delete it and read the published identity \
                 — this node then cannot perform the handoff"
            ),
        }
    }
}

impl std::error::Error for RosterError {}

impl RosterError {
    /// Whether a re-read can plausibly clear the error. Network failures
    /// are transient; so are the inconsistencies a tx confirming mid-read
    /// can cause — a root mismatch between the two address fetches, or a
    /// torn paginated list whose chain links no longer resolve. Everything
    /// else is persistent state: corrupt datums, duplicate keys, bad config,
    /// and crucially `MissingRoot` — an unbootstrapped or wrong-address
    /// registry returns an empty UTxO set, which is a steady-state
    /// misconfiguration, not a tear, and must NOT burn the retry budget.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Fetch(_)
                | Self::RootMismatch { .. }
                | Self::List(
                    RegistryError::BrokenLink(_)
                        | RegistryError::NotAscending(_)
                        | RegistryError::UnreachableNodes(_)
                )
        )
    }
}

impl From<RegisterSpoError> for RosterError {
    fn from(e: RegisterSpoError) -> Self {
        Self::Element(e)
    }
}
impl From<RegistryError> for RosterError {
    fn from(e: RegistryError) -> Self {
        Self::List(e)
    }
}
impl From<TreasurySpendError> for RosterError {
    fn from(e: TreasurySpendError) -> Self {
        Self::Treasury(e)
    }
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

/// One registered SPO, with the element UTxO carrying its membership NFT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredSpo {
    /// 28-byte `blake2b_224(cold_vkey)` — the membership NFT asset name.
    pub pool_id: Vec<u8>,
    pub bifrost_id_pk: Vec<u8>,
    pub bifrost_url: Vec<u8>,
    pub tx_hash: String,
    pub output_index: u32,
}

/// A verified snapshot of the on-chain SPO registry: the list reconstructed
/// and integrity-checked, and the identity-trie root proven equal to the
/// `treasury_info` datum's `bifrost_identity_root`.
#[derive(Debug, Clone)]
pub struct RegistrySnapshot {
    /// Registered SPOs in ascending `pool_id` order (the on-chain chain order).
    pub spos: Vec<RegisteredSpo>,
    /// The cross-checked identity root (`bifrost_id_pk → pool_id` MPF).
    pub identity_root: mpf::Hash,
    /// The `treasury_info` state UTxO the root was checked against.
    pub treasury_state: TreasuryStateUtxo,
}

/// Build a verified registry snapshot from caller-fetched UTxO sets.
pub fn registry_snapshot(
    registry_utxos: &[BfUtxo],
    registry_policy_hex: &str,
    treasury_utxos: &[BfUtxo],
    treasury_policy_hex: &str,
    treasury_asset_name_hex: &str,
) -> Result<RegistrySnapshot, RosterError> {
    let elements = find_registry_utxos(registry_utxos, registry_policy_hex)?;
    let list = RegistryList::from_elements(
        elements
            .iter()
            .map(|u| (u.asset_name.clone(), u.element.clone())),
    )?;
    let treasury_state =
        find_treasury_state(treasury_utxos, treasury_policy_hex, treasury_asset_name_hex)?;

    let pairs = list.identity_pairs();
    let mut seen = BTreeSet::new();
    for (pk, _) in &pairs {
        if !seen.insert(pk.clone()) {
            return Err(RosterError::DuplicateIdPk(pk.clone()));
        }
    }
    let trie = mpf::Trie::from_pairs(pairs).map_err(RosterError::Mpf)?;
    let computed = trie.root_hash();
    if computed != treasury_state.datum.bifrost_identity_root {
        return Err(RosterError::RootMismatch {
            datum: treasury_state.datum.bifrost_identity_root,
            computed,
        });
    }

    let spos = list
        .iter()
        .map(|(pool_id, data)| {
            let u = elements
                .iter()
                .find(|u| u.asset_name == pool_id)
                .expect("every listed node came from the element set");
            RegisteredSpo {
                pool_id: pool_id.to_vec(),
                bifrost_id_pk: data.bifrost_id_pk.clone(),
                bifrost_url: data.bifrost_url.clone(),
                tx_hash: u.tx_hash.clone(),
                output_index: u.output_index,
            }
        })
        .collect();

    Ok(RegistrySnapshot {
        spos,
        identity_root: computed,
        treasury_state,
    })
}

/// Shape-check one registered `bifrost_url` (already UTF-8, trailing slashes
/// Validate one registered `bifrost_url` and return its CANONICAL form.
///
/// Peers join `"{url}/dkg/..."` onto it verbatim and both the dedup check
/// and `port_from_url` key off it, so we must validate AND canonicalize, not
/// just check. The canonical form is `url::Url`'s normalized serialization
/// (scheme + host lowercased, default ports elided) with the trailing slash
/// trimmed — so `http://H:80` and `http://h` collapse to one string and a
/// stray trailing space can't survive into a malformed fetch URL. Rejects
/// non-http(s) schemes, missing host, query/fragment, and userinfo
/// (credentials have no place in a public endpoint).
pub(crate) fn validate_bifrost_url(url: &str) -> Result<String, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("not a valid URL: {e}"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(format!(
            "scheme must be http or https, got {:?}",
            parsed.scheme()
        ));
    }
    if parsed.host_str().is_none() {
        return Err("missing host".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("query/fragment not allowed in a base URL".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("userinfo (credentials) not allowed".into());
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

/// Derive the epoch [`Roster`] from a verified snapshot.
///
/// Participants are ordered lexicographically by `bifrost_id_pk` and given
/// FROST identifiers `1..=n` in that order — the spec's canonical DKG
/// participant ordering. Each `bifrost_url` is canonicalized + validated as
/// an http(s) base URL (see [`validate_bifrost_url`]) and must be unique
/// across the roster *after canonicalization* (so case- and default-port
/// variants of one endpoint still collide); a bad registration fails here,
/// loudly naming the pool, rather than as an undiagnosable DKG poll timeout.
///
/// `min_signers` is the caller's override and must lie in
/// `[`[`FROST_MIN_PARTICIPANTS`]`, max_signers]` — out-of-range values are
/// rejected, never silently clamped. Without one a simple majority `n/2 + 1`
/// is used (always valid for `n >= 2`).
///
/// TODO(WI-012): the real threshold is stake-weighted — the smallest `t`
/// such that any `t` participants control > 51% of eligible stake — and the
/// candidate set must exclude actively banned pools (WI-011). Both replace
/// the majority default here, not this function's ordering.
pub fn roster_from_snapshot(
    snapshot: &RegistrySnapshot,
    epoch: u64,
    min_signers: Option<u16>,
) -> Result<Roster, RosterError> {
    let n = snapshot.spos.len();
    if n < usize::from(FROST_MIN_PARTICIPANTS) {
        return Err(RosterError::TooFew { got: n });
    }
    let max_signers = u16::try_from(n).map_err(|_| RosterError::TooMany(n))?;

    let mut ordered: Vec<&RegisteredSpo> = snapshot.spos.iter().collect();
    ordered.sort_by(|a, b| a.bifrost_id_pk.cmp(&b.bifrost_id_pk));

    let mut participants = BTreeMap::new();
    let mut seen_urls = BTreeSet::new();
    for (i, spo) in ordered.iter().enumerate() {
        let identifier = Identifier::try_from(u16::try_from(i + 1).expect("n fits u16"))
            .expect("1..=n is a valid FROST identifier");
        let bad_url = |reason: String| RosterError::BadUrl {
            pool_id: spo.pool_id.clone(),
            reason,
        };
        let raw =
            std::str::from_utf8(&spo.bifrost_url).map_err(|_| bad_url("not valid UTF-8".into()))?;
        // Canonical form for both dedup and storage — see validate_bifrost_url.
        let bifrost_url = validate_bifrost_url(raw).map_err(bad_url)?;
        if !seen_urls.insert(bifrost_url.clone()) {
            return Err(RosterError::DuplicateUrl { url: bifrost_url });
        }
        participants.insert(
            identifier,
            SpoInfo {
                identifier,
                pool_id: spo.pool_id.clone(),
                bifrost_url,
                bifrost_id_pk: spo.bifrost_id_pk.clone(),
            },
        );
    }

    let min_signers = match min_signers {
        None => max_signers / 2 + 1,
        Some(m) if m < FROST_MIN_PARTICIPANTS || m > max_signers => {
            return Err(RosterError::BadMinSigners {
                requested: m,
                max: max_signers,
            });
        }
        Some(m) => m,
    };
    Ok(Roster {
        epoch,
        min_signers,
        max_signers,
        participants,
    })
}

/// Fetch the registry + `treasury_info` UTxO sets from a Blockfrost-compatible
/// API and build the verified snapshot. Single attempt — callers that can
/// tolerate latency should go through [`RegistryRosterSource::fetch_snapshot`],
/// which retries transient failures.
pub async fn fetch_registry_snapshot(
    base_url: &str,
    project_id: &str,
    registry_address: &str,
    registry_policy_hex: &str,
    treasury_address: &str,
    treasury_policy_hex: &str,
    treasury_asset_name_hex: &str,
) -> Result<RegistrySnapshot, RosterError> {
    // Concurrent: also narrows the window in which a confirming register_spo
    // (which updates BOTH addresses in one tx) can tear the read.
    let (registry_utxos, treasury_utxos) = tokio::try_join!(
        bf_http::fetch_address_utxos(base_url, project_id, registry_address),
        bf_http::fetch_address_utxos(base_url, project_id, treasury_address),
    )
    .map_err(RosterError::Fetch)?;
    registry_snapshot(
        &registry_utxos,
        registry_policy_hex,
        &treasury_utxos,
        treasury_policy_hex,
        treasury_asset_name_hex,
    )
}

// ---------------------------------------------------------------------------
// Config-derived source
// ---------------------------------------------------------------------------

/// Where to read the on-chain registry: the two script addresses + policies,
/// derived from the blueprint and the registry one-shot bootstrap outref
/// (the same parameters every registry command takes).
#[derive(Debug, Clone)]
pub struct RegistryRosterSource {
    pub registry_address: String,
    pub registry_policy_hex: String,
    pub treasury_info_address: String,
    pub treasury_info_policy_hex: String,
    /// The parameterized `treasury_info` script itself, retained because
    /// SPENDING the state UTxO (the Update-Y key handoff) needs the script as a
    /// witness, not just its hash. Reading the roster only needs the address and
    /// policy above, but re-deriving the script elsewhere would mean a second
    /// blueprint read and a second copy of the parameterization rules.
    ///
    /// `None` when the source came from the Config's published identity (#9–#10)
    /// and this node has no blueprint to compile it from. That is the read/spend
    /// split: the published ids locate the roster, but a node that performs the
    /// key handoff must also be able to build the script. Update-Y says so
    /// explicitly rather than failing at witness-assembly time.
    pub treasury_info_script: Option<blueprint::ParameterizedScript>,
    /// Treasury NFT asset name (hex), fixed at K1.
    pub treasury_info_asset_name_hex: String,
    /// `Roster::min_signers` override until WI-012's stake-weighted threshold.
    pub min_signers: Option<u16>,
}

/// Parse `<cardano_tx_hash>:<index>` (the one-shot bootstrap outref form
/// shared by the registry and ban-list sources).
pub fn parse_outref(s: &str) -> Result<([u8; 32], u32), String> {
    let (h, i) = s
        .split_once(':')
        .ok_or_else(|| format!("expected <tx_hash>:<index>, got '{s}'"))?;
    let tx_id: [u8; 32] = hex::decode(h)
        .map_err(|e| format!("tx hash hex: {e}"))?
        .try_into()
        .map_err(|_| "tx hash must be 32 bytes".to_string())?;
    let index: u32 = i.parse().map_err(|e| format!("output index: {e}"))?;
    Ok((tx_id, index))
}

/// The two rev-5.5 inputs every blueprint derivation needs beyond the registry
/// bootstrap: the treasury's own one-shot outref and the Config NFT policy id.
///
/// One accessor, because the pair is required by three unrelated call paths
/// (roster, ban list, fault verifiers) and each getting it from `[cardano]`
/// separately is how one of them ends up reading a different bridge.
pub fn treasury_derivation_inputs(
    cardano: &crate::config::CardanoConfig,
) -> Result<(String, [u8; 28]), String> {
    let bootstrap = cardano
        .treasury_bootstrap
        .clone()
        .ok_or("cardano.treasury_bootstrap is required to derive the treasury policy (rev 5.5: it is a parameter of treasury_info)")?;
    let hex_str = cardano.config_nft_policy_id.as_deref().ok_or(
        "cardano.config_nft_policy_id is required to derive the treasury policy (rev 5.5 [PRE-3])",
    )?;
    let policy: [u8; 28] = hex::decode(hex_str)
        .ok()
        .and_then(|v| <[u8; 28]>::try_from(v).ok())
        .ok_or("cardano.config_nft_policy_id is not 28 bytes")?;
    Ok((bootstrap, policy))
}

impl RegistryRosterSource {
    /// Parameterize the registry + `treasury_info` scripts from the blueprint
    /// and derive their addresses. `mainnet` picks the address network tag.
    pub fn from_blueprint(
        blueprint_path: Option<&str>,
        registry_bootstrap: &str,
        treasury_bootstrap: &str,
        config_policy_id: &[u8; 28],
        mainnet: bool,
    ) -> Result<Self, RosterError> {
        let blueprint_json = crate::cardano::blueprint::load_blueprint(blueprint_path)
            .map_err(RosterError::Config)?;
        let (reg_tx_id, reg_index) = parse_outref(registry_bootstrap)
            .map_err(|e| RosterError::Config(format!("registry bootstrap outref: {e}")))?;
        let (tsy_tx_id, tsy_index) = parse_outref(treasury_bootstrap)
            .map_err(|e| RosterError::Config(format!("treasury bootstrap outref: {e}")))?;
        let err = |what: &str, e: BlueprintError| {
            RosterError::Config(format!("parameterize {what}: {e}"))
        };
        // Rev 5.5 derivation order: Config → treasury → registry. It used to run
        // the other way, which made the dependency a cycle and the [REG-6] pin
        // impossible ([PRE-3], [PRE-4]).
        let treasury = blueprint::treasury_info_script(
            &blueprint_json,
            &tsy_tx_id,
            u64::from(tsy_index),
            config_policy_id,
        )
        .map_err(|e| err("treasury_info", e))?;
        let registry = blueprint::spos_registry_script(
            &blueprint_json,
            &reg_tx_id,
            u64::from(reg_index),
            &treasury.hash,
        )
        .map_err(|e| err("spos_registry", e))?;
        let network = if mainnet {
            pallas_addresses::Network::Mainnet
        } else {
            pallas_addresses::Network::Testnet
        };
        Ok(Self {
            registry_address: registry.enterprise_address(network),
            registry_policy_hex: registry.hash_hex(),
            treasury_info_address: treasury.enterprise_address(network),
            treasury_info_policy_hex: treasury.hash_hex(),
            treasury_info_script: Some(treasury),
            treasury_info_asset_name_hex: hex::encode(
                crate::cardano::config_params::TREASURY_INFO_ASSET_NAME,
            ),
            min_signers: None,
        })
    }

    /// The published route (WI-068): both addresses come from the policy ids the
    /// Config carries at #9–#10; the state NFT's name is a protocol constant.
    ///
    /// This is also how the treasury's federation identity is reached (WI-069):
    /// the `treasury_info` UTxO located here carries `y_federation` and
    /// `federation_csv_blocks` in its datum, so the whole treasury address hangs
    /// off the one Config NFT.
    ///
    /// Nothing here reads a blueprint, an outref or the TM-NFT policy — which is
    /// the point, since `treasury_info` is parameterized by TWO values that every
    /// node must apply identically or it looks for the state UTxO at an address
    /// nobody wrote to. `treasury_info_script` is left `None`; a node that also
    /// performs the Update-Y handoff fills it in via [`Self::with_derived_script`].
    #[must_use]
    pub fn from_policy_ids(
        spos_registry_policy_id: &[u8; 28],
        treasury_info_policy_id: &[u8; 28],
        treasury_info_asset_name: &[u8],
        mainnet: bool,
    ) -> Self {
        let network = if mainnet {
            pallas_addresses::Network::Mainnet
        } else {
            pallas_addresses::Network::Testnet
        };
        Self {
            registry_address: blueprint::script_enterprise_address(
                spos_registry_policy_id,
                network,
            ),
            registry_policy_hex: hex::encode(spos_registry_policy_id),
            treasury_info_address: blueprint::script_enterprise_address(
                treasury_info_policy_id,
                network,
            ),
            treasury_info_policy_hex: hex::encode(treasury_info_policy_id),
            treasury_info_script: None,
            treasury_info_asset_name_hex: hex::encode(treasury_info_asset_name),
            min_signers: None,
        }
    }

    /// Attach the compiled `treasury_info` script to a published source, so the
    /// node can also SPEND the state UTxO (Update-Y).
    ///
    /// The derived hash must equal the published #10, and a mismatch is fatal:
    /// the parameter this compiles from is exactly what a node can get wrong,
    /// and the consequence — a handoff written to an address no other SPO reads
    /// — is the failure publishing #10 exists to prevent.
    pub fn with_derived_script(
        mut self,
        blueprint_path: Option<&str>,
        treasury_bootstrap: &str,
        config_policy_id: &[u8; 28],
    ) -> Result<Self, RosterError> {
        let blueprint_json = crate::cardano::blueprint::load_blueprint(blueprint_path)
            .map_err(RosterError::Config)?;
        let (tsy_tx_id, tsy_index) = parse_outref(treasury_bootstrap)
            .map_err(|e| RosterError::Config(format!("treasury bootstrap outref: {e}")))?;
        // Rev 5.5 [PRE-3]: the treasury script compiles from its OWN one-shot
        // outpoint and the Config NFT policy, not from the registry policy.
        let treasury = blueprint::treasury_info_script(
            &blueprint_json,
            &tsy_tx_id,
            u64::from(tsy_index),
            config_policy_id,
        )
        .map_err(|e| RosterError::Config(format!("parameterize treasury_info: {e}")))?;
        if treasury.hash_hex() != self.treasury_info_policy_hex {
            return Err(RosterError::DerivedMismatch {
                derived: treasury.hash_hex(),
                published: self.treasury_info_policy_hex.clone(),
            });
        }
        self.treasury_info_script = Some(treasury);
        Ok(self)
    }

    /// Build from `[cardano]` config: requires `registry_blueprint`,
    /// `registry_bootstrap`, `treasury_bootstrap` and `config_nft_policy_id`
    /// all set (`None` when none are — the caller falls back to its fixture
    /// roster), errors when only some are.
    ///
    /// Rev 5.5 swapped `treasury_info_asset_name` for `treasury_bootstrap` +
    /// `config_nft_policy_id`. The asset name is the [CFG-4] constant now, and
    /// the treasury script compiles from its own one-shot outpoint and the
    /// Config identity ([PRE-3]) rather than from the registry policy.
    pub fn from_config(
        cardano: &crate::config::CardanoConfig,
    ) -> Result<Option<Self>, RosterError> {
        // The blueprint is NOT among the required fields since WI-066: it is
        // embedded in the binary, so `registry_blueprint` is an override rather
        // than an input. What still identifies the BRIDGE is the pair of
        // bootstrap outrefs plus the Config policy.
        let blueprint_path = cardano.registry_blueprint.as_deref();
        let fields = (
            cardano.registry_bootstrap.as_deref(),
            cardano.treasury_bootstrap.as_deref(),
            cardano.config_nft_policy_id.as_deref(),
        );
        let (bootstrap, treasury_bootstrap, config_policy_hex) = match fields {
            (None, None, _) => return Ok(None),
            (Some(r), Some(t), Some(c)) => (r, t, c),
            _ => {
                return Err(RosterError::Config(
                    "set all of cardano.registry_blueprint, cardano.registry_bootstrap, \
                     cardano.treasury_bootstrap and cardano.config_nft_policy_id (or none of \
                     the first three, for the fixture roster)"
                        .into(),
                ));
            }
        };
        let config_policy_id: [u8; 28] = hex::decode(config_policy_hex)
            .ok()
            .and_then(|v| <[u8; 28]>::try_from(v).ok())
            .ok_or_else(|| {
                RosterError::Config("cardano.config_nft_policy_id is not 28 bytes".into())
            })?;
        let mainnet = cardano.is_mainnet().map_err(RosterError::Config)?;
        Self::from_blueprint(
            blueprint_path,
            bootstrap,
            treasury_bootstrap,
            &config_policy_id,
            mainnet,
        )
        .map(Some)
    }

    /// Resolve the roster source the way every node should: from the bridge
    /// Config when there is one to read, and only otherwise from local keys.
    ///
    /// The precedence is not a preference. `treasury_info` is parameterized by a
    /// value a node applies locally, so two nodes that disagree about it look for
    /// the roster's state UTxO at different addresses — and the one that is wrong
    /// finds nothing rather than an error. The Config is NFT-authenticated and
    /// identical for everyone, so it is the only copy that cannot diverge.
    ///
    /// A node that still carries the local keys derives from them too and CROSS-
    /// CHECKS: that is how it keeps the compiled `treasury_info` script Update-Y
    /// needs, and a disagreement is fatal rather than resolved by preference.
    ///
    /// Everything that derivation needs is OPTIONAL on this route, and a failure
    /// to produce it is not fatal — the same treatment the ban sibling gives its
    /// leftover keys. The addresses come from the Config; the compiled script buys
    /// only the ability to SPEND the state UTxO, so a node with a moved
    /// `plutus.json` or a blueprint from a newer contracts release loses the
    /// handoff and keeps the bridge. A derivation that SUCCEEDS and disagrees
    /// with #10 stays fatal: that one is a real conflict about where the handoff
    /// goes.
    pub fn resolve(
        cardano: &crate::config::CardanoConfig,
        config: Option<&crate::cardano::config_params::ConfigParams>,
    ) -> Result<Option<Self>, RosterError> {
        // Since rev 5.4 the registry identity is MANDATORY in the datum, so
        // having a Config at all means having the identity. Rev 5.5 renumbered it
        // to #9 (registry) + #10 (treasury); the asset name became a constant.
        let Some(published) = config.map(|c| &c.registry) else {
            return Self::from_config(cardano);
        };
        let mainnet = cardano.is_mainnet().map_err(RosterError::Config)?;
        // Rev 5.5 [CFG-4]: the state NFT's asset name is a protocol constant, not
        // a Config field of its own. Uniqueness comes from the one-shot outpoint baked into the
        // policy id, so the name had nothing left to say.
        let source = Self::from_policy_ids(
            &published.spos_registry_policy_id,
            &published.treasury_info_policy_id,
            crate::cardano::config_params::TREASURY_INFO_ASSET_NAME,
            mainnet,
        );
        // The blueprint is embedded (WI-066), so every node can compile the
        // treasury_info script and perform the Update-Y handoff — this used to
        // require an operator-supplied file, which meant the handoff silently
        // depended on whether someone had copied one. What is still needed is
        // the bridge's own identity: its treasury one-shot and Config policy.
        // The derivation is checked against the published #10 either way.
        let blueprint_path = cardano.registry_blueprint.as_deref();
        let (Some(treasury_bootstrap), Some(config_policy_hex)) = (
            cardano.treasury_bootstrap.as_deref(),
            cardano.config_nft_policy_id.as_deref(),
        ) else {
            return Ok(Some(source));
        };
        let Some(config_policy_id) = hex::decode(config_policy_hex)
            .ok()
            .and_then(|v| <[u8; 28]>::try_from(v).ok())
        else {
            return Ok(Some(source));
        };
        match source.clone().with_derived_script(
            blueprint_path,
            treasury_bootstrap,
            &config_policy_id,
        ) {
            Ok(with_script) => Ok(Some(with_script)),
            Err(e @ RosterError::DerivedMismatch { .. }) => Err(e),
            Err(e) => {
                tracing::warn!(
                    "[roster] the bridge Config publishes the registry identity (#9-#10), so \
                     this node reads the roster from it — but the local treasury_info script \
                     could not be compiled ({e}). Reading is unaffected; an Update-Y key \
                     handoff on this node is NOT possible until cardano.registry_blueprint \
                     resolves"
                );
                Ok(Some(source))
            }
        }
    }

    /// Whether this node can SPEND the `treasury_info` state UTxO — i.e. perform
    /// the Update-Y key handoff after a DKG. Reading the roster never needs it.
    #[must_use]
    pub fn can_hand_off_key(&self) -> bool {
        self.treasury_info_script.is_some()
    }

    /// Fetch + verify the snapshot, retrying transient failures.
    ///
    /// A registration confirming between (or during) the two address
    /// fetches tears the read — the rebuilt identity root no longer matches
    /// the treasury datum — and a Blockfrost blip fails it outright. Both
    /// clear on a re-read, and the epoch machine treats roster errors as
    /// fatal, so absorb them here instead of killing the SPO over a
    /// transient condition. Persistent errors still surface after the last
    /// attempt.
    pub async fn fetch_snapshot(
        &self,
        base_url: &str,
        project_id: &str,
    ) -> Result<RegistrySnapshot, RosterError> {
        crate::cardano::retry::retry_transient(
            &crate::cardano::retry::DEFAULT_DELAYS,
            "roster",
            RosterError::is_transient,
            || {
                fetch_registry_snapshot(
                    base_url,
                    project_id,
                    &self.registry_address,
                    &self.registry_policy_hex,
                    &self.treasury_info_address,
                    &self.treasury_info_policy_hex,
                    &self.treasury_info_asset_name_hex,
                )
            },
        )
        .await
    }

    /// Fetch + verify the snapshot (with retry) and derive the roster for
    /// `epoch`.
    pub async fn fetch_roster(
        &self,
        base_url: &str,
        project_id: &str,
        epoch: u64,
    ) -> Result<Roster, RosterError> {
        let snapshot = self.fetch_snapshot(base_url, project_id).await?;
        roster_from_snapshot(&snapshot, epoch, self.min_signers)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::bf_http::BfAmount;
    use crate::cardano::registry::{
        ElementData, REGISTRATION_ROOT_KEY, RegistrationNodeData, RegistryElement,
    };
    use crate::cardano::treasury_info::TreasuryInfoDatum;

    const REGISTRY_POLICY: &str = "11111111111111111111111111111111111111111111111111111111";
    const TREASURY_POLICY: &str = "22222222222222222222222222222222222222222222222222222222";
    const TREASURY_NFT_NAME: &str = "abcd";

    fn bf_utxo(tx_hash: &str, ix: u32, unit: &str, datum_cbor: Vec<u8>) -> BfUtxo {
        BfUtxo {
            tx_hash: tx_hash.to_string(),
            output_index: ix,
            amount: vec![
                BfAmount {
                    unit: "lovelace".into(),
                    quantity: "2000000".into(),
                },
                BfAmount {
                    unit: unit.to_string(),
                    quantity: "1".into(),
                },
            ],
            inline_datum: Some(hex::encode(datum_cbor)),
            reference_script_hash: None,
        }
    }

    fn element_utxo(tx: &str, ix: u32, asset_name: &[u8], elem: &RegistryElement) -> BfUtxo {
        let unit = format!("{REGISTRY_POLICY}{}", hex::encode(asset_name));
        bf_utxo(tx, ix, &unit, elem.to_cbor())
    }

    fn treasury_utxo(root: mpf::Hash) -> BfUtxo {
        let datum = TreasuryInfoDatum {
            bifrost_identity_root: root,
            current_spos_frost_key: vec![0xAB; 32],
        };
        let unit = format!("{TREASURY_POLICY}{TREASURY_NFT_NAME}");
        bf_utxo(&"77".repeat(32), 0, &unit, datum.to_cbor())
    }

    struct Spo {
        pool_id: [u8; 28],
        pk: [u8; 32],
        url: &'static [u8],
    }

    /// Three SPOs whose `bifrost_id_pk` order REVERSES their `pool_id` order,
    /// so the two orderings are distinguishable in assertions.
    fn three_spos() -> Vec<Spo> {
        vec![
            Spo {
                pool_id: [0xAA; 28],
                pk: [0x33; 32],
                url: b"http://spo-a.example",
            },
            Spo {
                pool_id: [0xBB; 28],
                pk: [0x22; 32],
                url: b"http://spo-b.example",
            },
            Spo {
                pool_id: [0xCC; 28],
                pk: [0x11; 32],
                url: b"http://spo-c.example",
            },
        ]
    }

    fn node(data_pk: &[u8], url: &[u8], link: Option<&[u8]>) -> RegistryElement {
        RegistryElement {
            data: ElementData::Node(RegistrationNodeData {
                bifrost_id_pk: data_pk.to_vec(),
                bifrost_url: url.to_vec(),
            }),
            link: link.map(<[u8]>::to_vec),
        }
    }

    /// Registry UTxOs for `spos` (chained ascending) + the matching treasury
    /// state UTxO (root = trie of the identity pairs).
    fn chain_utxos(spos: &[Spo]) -> (Vec<BfUtxo>, Vec<BfUtxo>) {
        let mut registry = Vec::new();
        let root_elem = RegistryElement {
            data: ElementData::Root,
            link: spos.first().map(|s| s.pool_id.to_vec()),
        };
        registry.push(element_utxo(
            &"00".repeat(32),
            0,
            REGISTRATION_ROOT_KEY,
            &root_elem,
        ));
        for (i, s) in spos.iter().enumerate() {
            let link = spos.get(i + 1).map(|n| n.pool_id.as_slice());
            registry.push(element_utxo(
                &format!("{:02x}", i + 1).repeat(32),
                0,
                &s.pool_id,
                &node(&s.pk, s.url, link),
            ));
        }
        let trie = mpf::Trie::from_pairs(spos.iter().map(|s| (s.pk.to_vec(), s.pool_id.to_vec())))
            .unwrap();
        (registry, vec![treasury_utxo(trie.root_hash())])
    }

    fn snapshot_of(spos: &[Spo]) -> Result<RegistrySnapshot, RosterError> {
        let (registry, treasury) = chain_utxos(spos);
        registry_snapshot(
            &registry,
            REGISTRY_POLICY,
            &treasury,
            TREASURY_POLICY,
            TREASURY_NFT_NAME,
        )
    }

    #[test]
    fn snapshot_verifies_root_and_keeps_chain_order() {
        let spos = three_spos();
        let snap = snapshot_of(&spos).unwrap();
        assert_eq!(snap.spos.len(), 3);
        // chain order == ascending pool_id
        let pools: Vec<&[u8]> = snap.spos.iter().map(|s| s.pool_id.as_slice()).collect();
        assert_eq!(pools, [&[0xAA; 28][..], &[0xBB; 28], &[0xCC; 28]]);
        // each entry keeps its element UTxO ref
        assert_eq!(snap.spos[0].tx_hash, "01".repeat(32));
        assert_eq!(
            snap.identity_root,
            snap.treasury_state.datum.bifrost_identity_root
        );
    }

    #[test]
    fn snapshot_rejects_root_mismatch() {
        let spos = three_spos();
        let (registry, _) = chain_utxos(&spos);
        let treasury = vec![treasury_utxo([0xEE; 32])];
        assert!(matches!(
            registry_snapshot(
                &registry,
                REGISTRY_POLICY,
                &treasury,
                TREASURY_POLICY,
                TREASURY_NFT_NAME
            ),
            Err(RosterError::RootMismatch { .. })
        ));
    }

    #[test]
    fn snapshot_rejects_duplicate_bifrost_id_pk() {
        let mut spos = three_spos();
        spos[1].pk = spos[0].pk;
        let mut reg = Vec::new();
        let root_elem = RegistryElement {
            data: ElementData::Root,
            link: Some(spos[0].pool_id.to_vec()),
        };
        reg.push(element_utxo(
            &"00".repeat(32),
            0,
            REGISTRATION_ROOT_KEY,
            &root_elem,
        ));
        for (i, s) in spos.iter().enumerate() {
            let link = spos.get(i + 1).map(|n| n.pool_id.as_slice());
            reg.push(element_utxo(
                &format!("{:02x}", i + 1).repeat(32),
                0,
                &s.pool_id,
                &node(&s.pk, s.url, link),
            ));
        }
        let treasury = vec![treasury_utxo([0xEE; 32])];
        assert!(matches!(
            registry_snapshot(
                &reg,
                REGISTRY_POLICY,
                &treasury,
                TREASURY_POLICY,
                TREASURY_NFT_NAME
            ),
            Err(RosterError::DuplicateIdPk(_))
        ));
    }

    #[test]
    fn empty_registry_snapshots_but_makes_no_roster() {
        let snap = snapshot_of(&[]).unwrap();
        assert!(snap.spos.is_empty());
        assert_eq!(
            snap.identity_root,
            mpf::Trie::empty().root_hash(),
            "empty registry must verify against the bootstrap (empty-trie) root"
        );
        assert!(matches!(
            roster_from_snapshot(&snap, 7, None),
            Err(RosterError::TooFew { got: 0 })
        ));
    }

    // frost-core's validate_num_of_signers rejects min/max < 2, so a 1-SPO
    // roster must fail at construction, not rounds later inside dkg_part1.
    #[test]
    fn roster_rejects_single_spo() {
        let spos = vec![Spo {
            pool_id: [0xAA; 28],
            pk: [0x11; 32],
            url: b"http://spo-a.example:18500",
        }];
        let snap = snapshot_of(&spos).unwrap();
        assert_eq!(snap.spos.len(), 1, "the snapshot itself is fine");
        assert!(matches!(
            roster_from_snapshot(&snap, 0, None),
            Err(RosterError::TooFew { got: 1 })
        ));
    }

    #[test]
    fn roster_orders_by_bifrost_id_pk_not_pool_id() {
        let spos = three_spos();
        let snap = snapshot_of(&spos).unwrap();
        let roster = roster_from_snapshot(&snap, 42, None).unwrap();
        assert_eq!(roster.epoch, 42);
        assert_eq!(roster.max_signers, 3);
        assert_eq!(roster.min_signers, 2, "majority default for n=3");

        // identifier 1 must be the LOWEST bifrost_id_pk — pool [0xCC] (pk 0x11),
        // i.e. the reverse of pool_id order.
        let id = |n: u16| Identifier::try_from(n).unwrap();
        assert_eq!(roster.participants[&id(1)].bifrost_id_pk, vec![0x11; 32]);
        assert_eq!(roster.participants[&id(2)].bifrost_id_pk, vec![0x22; 32]);
        assert_eq!(roster.participants[&id(3)].bifrost_id_pk, vec![0x33; 32]);
        assert_eq!(
            roster.participants[&id(1)].bifrost_url,
            "http://spo-c.example"
        );
    }

    // Out-of-range overrides are rejected, never silently clamped — a typo'd
    // threshold must not quietly become 2-of-n or n-of-n.
    #[test]
    fn roster_min_signers_override_validated_not_clamped() {
        let spos = three_spos();
        let snap = snapshot_of(&spos).unwrap();
        assert_eq!(
            roster_from_snapshot(&snap, 0, Some(3)).unwrap().min_signers,
            3
        );
        assert_eq!(
            roster_from_snapshot(&snap, 0, Some(2)).unwrap().min_signers,
            2
        );
        for bad in [0u16, 1, 4, 9] {
            assert!(
                matches!(
                    roster_from_snapshot(&snap, 0, Some(bad)),
                    Err(RosterError::BadMinSigners { requested, max: 3 }) if requested == bad
                ),
                "override {bad} must be rejected"
            );
        }
    }

    /// Two valid SPOs plus one whose URL is the case under test — bad-URL
    /// checks need n >= 2 so TooFew doesn't fire first.
    fn spos_with_url(url: &'static [u8]) -> Vec<Spo> {
        vec![
            Spo {
                pool_id: [0xAA; 28],
                pk: [0x22; 32],
                url: b"http://spo-a.example:18500",
            },
            Spo {
                pool_id: [0xBB; 28],
                pk: [0x11; 32],
                url,
            },
        ]
    }

    #[test]
    fn roster_rejects_unusable_urls() {
        for (url, what) in [
            (b"\xFF\xFEnot-utf8".as_slice(), "non-UTF-8"),
            (b"spo.example.com:18500".as_slice(), "missing scheme"),
            (b"ftp://spo.example.com:1".as_slice(), "non-http scheme"),
            (b"http://spo.example.com:1?x=1".as_slice(), "query string"),
            (b"".as_slice(), "empty"),
        ] {
            let snap = snapshot_of(&spos_with_url(url)).unwrap();
            assert!(
                matches!(
                    roster_from_snapshot(&snap, 0, None),
                    Err(RosterError::BadUrl { ref pool_id, .. }) if pool_id == &[0xBB; 28].to_vec()
                ),
                "{what} URL must be rejected and name the offending pool"
            );
        }
    }

    // A trailing slash would turn peer fetches into "...com//dkg/..." (404,
    // read as not-yet-published) — normalize it away instead of failing.
    #[test]
    fn roster_normalizes_trailing_slash() {
        let snap = snapshot_of(&spos_with_url(b"https://spo-b.example:18500/")).unwrap();
        let roster = roster_from_snapshot(&snap, 0, None).unwrap();
        let id = |n: u16| Identifier::try_from(n).unwrap();
        assert_eq!(
            roster.participants[&id(1)].bifrost_url,
            "https://spo-b.example:18500"
        );
    }

    // Today's peer transport keys payloads by URL alone, so a shared URL
    // bricks DKG with an undiagnosable poll timeout — refuse loudly instead.
    #[test]
    fn roster_rejects_duplicate_urls() {
        let snap = snapshot_of(&spos_with_url(b"http://spo-a.example:18500/")).unwrap();
        assert!(matches!(
            roster_from_snapshot(&snap, 0, None),
            Err(RosterError::DuplicateUrl { ref url }) if url == "http://spo-a.example:18500"
        ));
    }

    // Canonicalization must catch endpoints that differ only in host case or
    // an elided default port — otherwise the byte-exact dedup is bypassed and
    // the collision the check exists to prevent still happens.
    #[test]
    fn roster_dedups_url_case_and_default_port() {
        // first SPO uses host-lowercase, second the SAME host upper-cased
        let mut spos = spos_with_url(b"http://SPO-A.EXAMPLE:18500");
        spos[0].url = b"http://spo-a.example:18500";
        assert!(matches!(
            roster_from_snapshot(&snapshot_of(&spos).unwrap(), 0, None),
            Err(RosterError::DuplicateUrl { .. })
        ));
        // default port elision: "http://h:80" == "http://h"
        let mut spos = spos_with_url(b"http://spo-a.example");
        spos[0].url = b"http://spo-a.example:80";
        assert!(matches!(
            roster_from_snapshot(&snapshot_of(&spos).unwrap(), 0, None),
            Err(RosterError::DuplicateUrl { .. })
        ));
    }

    #[test]
    fn transient_errors_are_classified() {
        assert!(RosterError::Fetch("http 500".into()).is_transient());
        assert!(
            RosterError::RootMismatch {
                datum: [0; 32],
                computed: [1; 32]
            }
            .is_transient()
        );
        // torn-read list shapes retry; an empty/wrong-address registry
        // (MissingRoot) is steady-state and must NOT burn the retry budget.
        assert!(RosterError::List(RegistryError::BrokenLink(vec![1])).is_transient());
        assert!(!RosterError::List(RegistryError::MissingRoot).is_transient());
        assert!(!RosterError::TooFew { got: 1 }.is_transient());
        assert!(!RosterError::DuplicateIdPk(vec![1]).is_transient());
        assert!(!RosterError::Config("x".into()).is_transient());
    }

    #[test]
    fn parse_outref_shapes() {
        assert!(parse_outref(&format!("{}:1", "aa".repeat(32))).is_ok());
        assert!(parse_outref("aa:1").is_err());
        assert!(parse_outref(&"aa".repeat(32)).is_err());
        assert!(parse_outref(&format!("{}:x", "aa".repeat(32))).is_err());
    }

    // -- WI-068: the registry identity the bridge publishes -------------------

    /// A Config carrying the registry identity this module reads. Since rev 5.4
    /// every Config carries it — the parser refuses a datum that does not.
    fn config_publishing_registry() -> crate::cardano::config_params::ConfigParams {
        use crate::cardano::config_params::RegistryParams;
        let mut c = crate::cardano::config_params::test_config_params();
        c.registry = RegistryParams {
            spos_registry_policy_id: [0xc1; 28],
            treasury_info_policy_id: [0xc2; 28],
        };
        c
    }

    /// The acceptance property: an SPO with NOTHING registry-related in its
    /// `[cardano]` section resolves the roster, and two differently-configured
    /// nodes cannot land on different addresses because neither derives one.
    #[test]
    fn a_published_registry_identity_needs_no_registry_keys() {
        let published = config_publishing_registry();
        let bare = crate::config::CardanoConfig {
            network: Some("preprod".to_string()),
            ..Default::default()
        };
        // Control: with no keys and no published identity there is no roster at
        // all — the fixture path.
        assert!(
            RegistryRosterSource::resolve(&bare, None)
                .unwrap()
                .is_none()
        );

        let src = RegistryRosterSource::resolve(&bare, Some(&published))
            .unwrap()
            .expect("the published identity resolves a roster source");
        assert_eq!(src.registry_policy_hex, "c1".repeat(28));
        assert_eq!(src.treasury_info_policy_hex, "c2".repeat(28));
        // [CFG-4]: the constant, not a Config field.
        assert_eq!(
            src.treasury_info_asset_name_hex,
            hex::encode(crate::cardano::config_params::TREASURY_INFO_ASSET_NAME)
        );
        assert!(src.registry_address.starts_with("addr_test1"));
        assert_ne!(src.registry_address, src.treasury_info_address);
        // No blueprint, so no compiled script — reading the roster does not need
        // one; only the Update-Y handoff does, and it says so.
        assert!(src.treasury_info_script.is_none());
    }

    /// A node with NO Config to read falls back to its local keys, and a
    /// half-configured set of them is a fault rather than a silent fixture.
    ///
    /// WI-066 took the blueprint OUT of that set: it is embedded in the binary,
    /// so the three keys below are now a complete local configuration and the
    /// same input that used to be a fault resolves. That is the point of the
    /// change — the operator supplies what identifies the bridge, never a build
    /// artifact — so it is asserted rather than assumed.
    #[test]
    fn no_config_falls_back_to_local_keys_and_half_configured_keys_are_a_fault() {
        let complete = crate::config::CardanoConfig {
            registry_bootstrap: Some(format!("{}:0", "bb".repeat(32))),
            treasury_bootstrap: Some(format!("{}:0", "aa".repeat(32))),
            config_nft_policy_id: Some("77".repeat(28)),
            ..Default::default()
        };
        RegistryRosterSource::resolve(&complete, None)
            .expect("no blueprint needed: it is embedded")
            .expect("the three bridge keys are a complete local configuration");

        // Genuinely half — the bridge's own identity is incomplete.
        let half = crate::config::CardanoConfig {
            registry_bootstrap: Some(format!("{}:0", "bb".repeat(32))),
            ..Default::default()
        };
        let err = RegistryRosterSource::resolve(&half, None)
            .expect_err("half-configured registry keys are a fault, not a fixture");
        assert!(matches!(err, RosterError::Config(_)));
    }

    /// Write a blueprint carrying only `treasury_info` — the one validator the
    /// published route ever compiles.
    fn treasury_info_blueprint(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "heimdall-wi068-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plutus.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"validators":[{{"title":"{}","compiledCode":"{}"}}]}}"#,
                crate::cardano::blueprint::TREASURY_INFO_TITLE,
                include_str!("../../tests/fixtures/treasury_info_code.txt").trim()
            ),
        )
        .unwrap();
        path
    }

    /// The published policy id is the only copy that cannot diverge, so a local
    /// derivation that disagrees is fatal rather than resolved by preference.
    #[test]
    fn a_derived_treasury_info_that_disagrees_with_the_config_is_fatal() {
        let src = RegistryRosterSource::from_policy_ids(&[0xc1; 28], &[0xc2; 28], b"TMTx", false);
        let path = treasury_info_blueprint("mismatch");

        let err = src
            .clone()
            .with_derived_script(
                Some(&path.to_string_lossy()),
                &format!("{}:0", "aa".repeat(32)),
                &[0x77; 28],
            )
            .expect_err("the fixture derives some other policy than the published #10");
        let RosterError::DerivedMismatch { published, .. } = &err else {
            panic!("expected a derived-vs-published mismatch, got {err:?}");
        };
        assert_eq!(*published, "c2".repeat(28));
        // The message names the field an operator goes and reads; rev 5.5 renumbered it to #10.
        assert!(err.to_string().contains("#10"), "{err}");

        // …and when they agree, the script is attached so Update-Y can run.
        let derived = crate::cardano::blueprint::treasury_info_script(
            &std::fs::read_to_string(&path).unwrap(),
            &[0xaa; 32],
            0,
            &[0x77; 28],
        )
        .unwrap();
        let agreeing =
            RegistryRosterSource::from_policy_ids(&[0xc1; 28], &derived.hash, b"TMTx", false)
                .with_derived_script(
                    Some(&path.to_string_lossy()),
                    &format!("{}:0", "aa".repeat(32)),
                    &[0x77; 28],
                )
                .expect("matching derivation");
        assert!(agreeing.treasury_info_script.is_some());
        assert!(agreeing.can_hand_off_key());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// The published route with the local keys STILL PRESENT — the state an
    /// operator is in the moment before deleting them, and the one `resolve`'s
    /// cross-check branch exists for.
    #[test]
    fn resolve_on_the_published_path_cross_checks_local_keys_when_they_derive() {
        let path = treasury_info_blueprint("crosscheck");
        let derived = crate::cardano::blueprint::treasury_info_script(
            &std::fs::read_to_string(&path).unwrap(),
            &[0xaa; 32],
            0,
            &[0x77; 28],
        )
        .unwrap();

        let mut published = config_publishing_registry();
        published.registry.treasury_info_policy_id = derived.hash;
        let cardano = crate::config::CardanoConfig {
            network: Some("preprod".to_string()),
            registry_blueprint: Some(path.to_string_lossy().into_owned()),
            // Rev 5.5: compiling treasury_info needs its own one-shot outref and
            // the Config NFT policy, not the registry policy.
            treasury_bootstrap: Some(format!("{}:0", "aa".repeat(32))),
            config_nft_policy_id: Some("77".repeat(28)),
            ..Default::default()
        };

        // Agreement → the compiled script is attached, so this node can hand the
        // key over as well as read the roster.
        let src = RegistryRosterSource::resolve(&cardano, Some(&published))
            .unwrap()
            .expect("the published identity resolves");
        assert_eq!(src.treasury_info_policy_hex, hex::encode(derived.hash));
        assert!(
            src.can_hand_off_key(),
            "a node that CAN derive the script keeps Update-Y"
        );

        // Disagreement → fatal. Update-Y here would write the handoff to an
        // address no other SPO reads, and no fallback makes that safe.
        let mut wrong = published.clone();
        wrong.registry.treasury_info_policy_id = [0xc2; 28];
        let err = RegistryRosterSource::resolve(&cardano, Some(&wrong))
            .expect_err("a derived hash disagreeing with #10 must not be resolved by preference");
        assert!(
            matches!(err, RosterError::DerivedMismatch { .. }),
            "{err:?}"
        );

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// Everything the local derivation needs is optional on the published route:
    /// the addresses come from the Config, and the compiled script buys only the
    /// Update-Y handoff. So a node that cannot produce it loses the handoff and
    /// KEEPS THE BRIDGE — the same treatment the ban sibling gives leftover keys.
    ///
    /// Before this, an unset `tm_nft_policy_id`, a moved `plutus.json` or a
    /// blueprint from a newer contracts release each exited the daemon.
    #[test]
    fn an_undrivable_local_script_costs_the_handoff_not_the_roster() {
        let published = config_publishing_registry();
        let path = treasury_info_blueprint("undrivable");

        let cases = [
            // Rev 5.4 dropped the case this list opened with — a blueprint set
            // but `tm_nft_policy` unset. `treasury_info` no longer takes that
            // parameter, so there is nothing left to be missing: the derivation
            // now SUCCEEDS from the blueprint alone, which is the fatal
            // DerivedMismatch branch rather than a graceful degrade.
            //
            // The blueprint moved, or was never installed on this host.
            crate::config::CardanoConfig {
                network: Some("preprod".to_string()),
                registry_blueprint: Some("/nonexistent/plutus.json".to_string()),
                ..Default::default()
            },
            // A blueprint that has no treasury_info validator at all (a newer or
            // differently-built contracts release).
            crate::config::CardanoConfig {
                network: Some("preprod".to_string()),
                registry_blueprint: Some(
                    {
                        let empty = path.parent().unwrap().join("empty.json");
                        std::fs::write(&empty, r#"{"validators":[]}"#).unwrap();
                        empty
                    }
                    .to_string_lossy()
                    .into_owned(),
                ),
                ..Default::default()
            },
        ];

        for cardano in cases {
            let src = RegistryRosterSource::resolve(&cardano, Some(&published))
                .expect("an underivable local script is not fatal on the published route")
                .expect("the published identity still resolves the roster");
            assert_eq!(src.registry_policy_hex, "c1".repeat(28));
            assert_eq!(src.treasury_info_policy_hex, "c2".repeat(28));
            assert!(
                !src.can_hand_off_key(),
                "and it must not pretend it can hand the key over"
            );
        }
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}

#[cfg(test)]
mod embedded_blueprint_roster_tests {
    use super::*;

    /// WI-066's operator-visible win: a node that names the bridge but supplies
    /// NO blueprint can still perform the Update-Y key handoff, because the
    /// blueprint is in the binary.
    ///
    /// Before, `can_hand_off_key()` was false for such a node — so whether a
    /// bridge could rotate its FROST key depended on whether its operators had
    /// each copied a build artifact into place, and a node that had not said so
    /// only in a startup warning.
    #[test]
    fn a_node_with_no_blueprint_can_still_hand_off_the_key() {
        let cardano = crate::config::CardanoConfig {
            registry_bootstrap: Some(format!("{}:0", "bb".repeat(32))),
            treasury_bootstrap: Some(format!("{}:0", "aa".repeat(32))),
            config_nft_policy_id: Some("77".repeat(28)),
            network: Some("preprod".to_string()),
            ..Default::default()
        };
        assert!(
            cardano.registry_blueprint.is_none(),
            "the point of the test: nothing supplied"
        );
        let source = RegistryRosterSource::resolve(&cardano, None)
            .expect("resolves")
            .expect("configured");
        assert!(
            source.can_hand_off_key(),
            "the embedded blueprint compiles treasury_info, so the handoff is available"
        );
    }
}
