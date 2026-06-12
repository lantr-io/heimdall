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

impl RegistryRosterSource {
    /// Parameterize the registry + `treasury_info` scripts from the blueprint
    /// and derive their addresses. `mainnet` picks the address network tag.
    pub fn from_blueprint(
        blueprint_path: &str,
        registry_bootstrap: &str,
        treasury_info_asset_name_hex: &str,
        mainnet: bool,
    ) -> Result<Self, RosterError> {
        let blueprint_json = std::fs::read_to_string(blueprint_path)
            .map_err(|e| RosterError::Config(format!("read blueprint {blueprint_path}: {e}")))?;
        let (tx_id, index) = parse_outref(registry_bootstrap)
            .map_err(|e| RosterError::Config(format!("registry bootstrap outref: {e}")))?;
        let err = |what: &str, e: BlueprintError| {
            RosterError::Config(format!("parameterize {what}: {e}"))
        };
        let registry = blueprint::spos_registry_script(&blueprint_json, &tx_id, u64::from(index))
            .map_err(|e| err("spos_registry", e))?;
        let treasury = blueprint::treasury_info_script(&blueprint_json, &registry.hash)
            .map_err(|e| err("treasury_info", e))?;
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
            treasury_info_asset_name_hex: treasury_info_asset_name_hex.to_string(),
            min_signers: None,
        })
    }

    /// Build from `[cardano]` config: requires `registry_blueprint`,
    /// `registry_bootstrap` and `treasury_info_asset_name` all set (`None`
    /// when none are — the caller falls back to its fixture roster), errors
    /// when only some are.
    pub fn from_config(
        cardano: &crate::config::CardanoConfig,
    ) -> Result<Option<Self>, RosterError> {
        let fields = (
            cardano.registry_blueprint.as_deref(),
            cardano.registry_bootstrap.as_deref(),
            cardano.treasury_info_asset_name.as_deref(),
        );
        let (blueprint_path, bootstrap, asset_name_hex) = match fields {
            (None, None, None) => return Ok(None),
            (Some(b), Some(r), Some(a)) => (b, r, a),
            _ => {
                return Err(RosterError::Config(
                    "set all of cardano.registry_blueprint, cardano.registry_bootstrap and \
                     cardano.treasury_info_asset_name (or none, for the fixture roster)"
                        .into(),
                ));
            }
        };
        let mainnet = cardano
            .blockfrost_project_id
            .as_deref()
            .is_some_and(|p| p.starts_with("mainnet"));
        Self::from_blueprint(blueprint_path, bootstrap, asset_name_hex, mainnet).map(Some)
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
            current_treasury_address: b"\x51\x20treasury".to_vec(),
            current_treasury_utxo_id: b"outpoint".to_vec(),
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
}
