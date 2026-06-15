//! `spo_bans.ak` linked-list reading (WI-011).
//!
//! The on-chain ban list mirrors the SPO registry's `aiken_design_patterns`
//! linked list: one UTxO per element at the ban script address, each
//! authenticated by an NFT of the ban policy. The root's asset name is the
//! constant `"ban-root"`; a node's asset name is `"ban/" || pool_id` (4-byte
//! prefix + 28-byte pool id = 32 bytes). Per the linked-list library, the
//! element *key* is the asset name with the prefix dropped — so `link` holds
//! the bare `pool_id` of the next node, and ordering is ascending by
//! `pool_id`. Each element's inline datum is:
//!
//! ```text
//! Element     = Constr(0, [ ElementData, Link ])
//! ElementData = Constr(0, [ Constr(0, []) ])                     -- Root{BanListRootData}
//!             | Constr(1, [ Constr(0, [ban_counter, ban_until_epoch]) ])  -- Node{BanNodeData}
//! Link        = Constr(0, [ next_pool_id ])                      -- Some
//!             | Constr(1, [])                                    -- None
//! ```
//!
//! A ban is **active** for epoch `E` iff `ban_until_epoch > E`
//! (`spo-bans.ak`: first ban sets `current_epoch + 1`, a repeat ban
//! `current_epoch + 2^counter` — the read side only needs the comparison,
//! not the schedule). The roster derivation (WI-012) subtracts
//! [`BanList::active_bans`] from the registry snapshot.
//!
//! An UN-BOOTSTRAPPED list (no `"ban-root"` NFT minted yet — WI-015) is a
//! distinct, explicit error ([`BanListError::NotBootstrapped`]): it must not
//! be confused with a bootstrapped-but-empty list, which is a valid snapshot
//! with zero bans.

use std::collections::{BTreeMap, BTreeSet};

use pallas_codec::minicbor;
use pallas_primitives::PlutusData;

use crate::cardano::bf_http::{self, BfUtxo};
use crate::cardano::blueprint::{self, BlueprintError};
use crate::cardano::nft_scan;
use crate::cardano::plutus::{self, bytes, constr, int};
use crate::cardano::roster::parse_outref;

/// Asset name of the root element's NFT (`ban_root_key` in `spo_bans.ak`).
pub const BAN_ROOT_KEY: &[u8] = b"ban-root";

/// Prefix of every node's asset name (`ban_node_key_prefix`).
pub const BAN_NODE_KEY_PREFIX: &[u8] = b"ban/";

/// Max node key (pool_id) length: 32-byte asset name minus the prefix.
const MAX_NODE_KEY_LEN: usize = 32 - BAN_NODE_KEY_PREFIX.len();

/// `BanNodeData` — one pool's ban state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanNodeData {
    /// How many times this pool has been banned (>= 1, validator-enforced).
    pub ban_counter: i64,
    /// Epoch at which the ban EXPIRES: active iff `ban_until_epoch > epoch`
    /// (so the last actively-banned epoch is `ban_until_epoch - 1`). A first
    /// ban sets `current_epoch + 1` (spo-bans.ak), i.e. active for the
    /// current epoch only.
    pub ban_until_epoch: i64,
}

impl BanNodeData {
    /// Whether the ban is active for `epoch` (`ban_until_epoch > epoch`).
    #[must_use]
    pub fn active_for(&self, epoch: u64) -> bool {
        // Epochs beyond i64 are unreachable on Cardano; saturate inactive.
        i64::try_from(epoch).is_ok_and(|e| self.ban_until_epoch > e)
    }
}

/// `ElementData<BanListRootData, BanNodeData>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanElementData {
    Root,
    Node(BanNodeData),
}

/// One ban-list element datum (`BanListDatum`). The element's key is *not*
/// in the datum — it is the asset name of the NFT held by the UTxO. `link`
/// is the bare `pool_id` (no `"ban/"` prefix) of the next node in ascending
/// order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanElement {
    pub data: BanElementData,
    pub link: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum BanListError {
    // -- datum decoding --
    NotConstr,
    WrongConstructor(u64),
    FieldCount {
        expected: usize,
        got: usize,
    },
    BadField(plutus::PlutusError),
    // -- snapshot reconstruction --
    /// No ban-policy NFTs at the ban script address at all: the list was
    /// never bootstrapped (WI-015). Distinct from a bootstrapped list with
    /// zero bans, which is a valid empty snapshot.
    NotBootstrapped,
    /// Elements exist but none carries the `"ban-root"` NFT — corrupt state.
    MissingRoot,
    /// Two elements share an asset name.
    DuplicateElement(Vec<u8>),
    /// Root-keyed element holds `Node` data, or node-keyed element `Root`.
    KindMismatch(Vec<u8>),
    /// Node asset name lacks the `"ban/"` prefix, or its key (pool_id) is
    /// empty / longer than 28 bytes.
    BadNodeKey(Vec<u8>),
    /// `ban_counter < 1` or `ban_until_epoch < 0` — the validator can never
    /// produce these.
    BadNodeData {
        pool_id: Vec<u8>,
    },
    /// A link points at a pool_id not present in the snapshot.
    BrokenLink(Vec<u8>),
    /// Following the links does not visit keys in strictly ascending order.
    NotAscending(Vec<u8>),
    /// Nodes exist that the chain from the root never reaches.
    UnreachableNodes(usize),
    // -- scan / fetch / config --
    /// A UTxO carrying ban-policy assets is not a well-formed element.
    BadElementUtxo(String),
    /// HTTP/Blockfrost failure fetching the UTxO set.
    Fetch(String),
    /// Bad blueprint/bootstrap configuration for the ban-list source.
    Config(String),
}

impl std::fmt::Display for BanListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConstr => write!(f, "expected Constr"),
            Self::WrongConstructor(c) => write!(f, "unexpected constructor {c}"),
            Self::FieldCount { expected, got } => {
                write!(f, "expected {expected} field(s), got {got}")
            }
            Self::BadField(e) => write!(f, "{e}"),
            Self::NotBootstrapped => write!(
                f,
                "ban list not bootstrapped: no ban-policy NFTs at the ban script address \
                 (mint the 'ban-root' anchor first — WI-015)"
            ),
            Self::MissingRoot => {
                write!(f, "ban elements exist but none carries the ban-root NFT")
            }
            Self::DuplicateElement(k) => write!(f, "duplicate element key {}", hex::encode(k)),
            Self::KindMismatch(k) => {
                write!(
                    f,
                    "element kind does not match asset name {}",
                    hex::encode(k)
                )
            }
            Self::BadNodeKey(k) => write!(f, "bad node asset name {}", hex::encode(k)),
            Self::BadNodeData { pool_id } => write!(
                f,
                "impossible ban data for pool {} (counter < 1 or negative epoch)",
                hex::encode(pool_id)
            ),
            Self::BrokenLink(k) => write!(f, "link to absent pool {}", hex::encode(k)),
            Self::NotAscending(k) => write!(f, "chain not ascending at pool {}", hex::encode(k)),
            Self::UnreachableNodes(n) => write!(f, "{n} node(s) unreachable from root"),
            Self::BadElementUtxo(e) => write!(f, "ban element UTxO: {e}"),
            Self::Fetch(e) => write!(f, "fetch: {e}"),
            Self::Config(e) => write!(f, "ban-list source config: {e}"),
        }
    }
}

impl std::error::Error for BanListError {}

impl From<plutus::PlutusError> for BanListError {
    fn from(e: plutus::PlutusError) -> Self {
        match e {
            plutus::PlutusError::NotConstr => Self::NotConstr,
            plutus::PlutusError::WrongConstructor { got, .. } => Self::WrongConstructor(got),
            other => Self::BadField(other),
        }
    }
}

impl BanListError {
    /// Same contract as `RosterError::is_transient`: list-shape errors can
    /// be a torn paginated read; fetch errors are network. Everything else
    /// is persistent state ([`Self::NotBootstrapped`] included — retrying
    /// will not mint the root).
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Fetch(_)
                | Self::BrokenLink(_)
                | Self::NotAscending(_)
                | Self::UnreachableNodes(_)
                | Self::MissingRoot
        )
    }
}

/// Field-count guard (the shared decoder only validates field types).
fn expect_len(fields: &[PlutusData], expected: usize) -> Result<(), BanListError> {
    if fields.len() != expected {
        return Err(BanListError::FieldCount {
            expected,
            got: fields.len(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Element datum encode / decode
// ---------------------------------------------------------------------------

impl BanElement {
    /// Encode as `Constr(0, [ElementData, Link])` (canonical encoding — the
    /// write side, WI-015/WI-017, must emit byte-exact datums).
    #[must_use]
    pub fn to_plutus_data(&self) -> PlutusData {
        let data = match &self.data {
            // Root { data: BanListRootData } — BanListRootData is Constr(0, []).
            BanElementData::Root => constr(0, vec![constr(0, vec![])]),
            BanElementData::Node(n) => constr(
                1,
                vec![constr(0, vec![int(n.ban_counter), int(n.ban_until_epoch)])],
            ),
        };
        let link = match &self.link {
            Some(k) => constr(0, vec![bytes(k)]),
            None => constr(1, vec![]),
        };
        constr(0, vec![data, link])
    }

    /// CBOR bytes of the inline datum.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        minicbor::to_vec(self.to_plutus_data()).expect("PlutusData CBOR encode")
    }

    pub fn from_plutus_data(pd: &PlutusData) -> Result<Self, BanListError> {
        let fields = plutus::constr_fields(pd, 0)?;
        expect_len(fields, 2)?;

        let (data_ctor, data_fields) = plutus::as_constr(&fields[0])?;
        let data = match data_ctor {
            0 => {
                // Root { data: BanListRootData }; payload must be Constr(0, []).
                expect_len(data_fields, 1)?;
                let root_fields = plutus::constr_fields(&data_fields[0], 0)?;
                expect_len(root_fields, 0)?;
                BanElementData::Root
            }
            1 => {
                expect_len(data_fields, 1)?;
                let node_fields = plutus::constr_fields(&data_fields[0], 0)?;
                expect_len(node_fields, 2)?;
                BanElementData::Node(BanNodeData {
                    ban_counter: plutus::field_int(node_fields, 0)?,
                    ban_until_epoch: plutus::field_int(node_fields, 1)?,
                })
            }
            other => return Err(BanListError::WrongConstructor(other)),
        };

        let (link_ctor, link_fields) = plutus::as_constr(&fields[1])?;
        let link = match link_ctor {
            0 => {
                expect_len(link_fields, 1)?;
                Some(plutus::field_bytes(link_fields, 0)?)
            }
            1 => {
                expect_len(link_fields, 0)?;
                None
            }
            other => return Err(BanListError::WrongConstructor(other)),
        };

        Ok(BanElement { data, link })
    }
}

// ---------------------------------------------------------------------------
// List reconstruction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeEntry {
    data: BanNodeData,
    link: Option<Vec<u8>>,
}

/// A validated snapshot of the on-chain ban list. Construction proves the
/// snapshot is a single well-formed chain: one root, every node reachable
/// from it, pool_ids strictly ascending along the links, no impossible ban
/// data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanList {
    root_link: Option<Vec<u8>>,
    nodes: BTreeMap<Vec<u8>, NodeEntry>,
}

impl BanList {
    /// Reconstruct from `(asset_name, element)` pairs — one per UTxO at the
    /// ban script address holding a ban-policy NFT. Zero pairs means the
    /// list was never bootstrapped ([`BanListError::NotBootstrapped`]).
    pub fn from_elements<I>(elements: I) -> Result<Self, BanListError>
    where
        I: IntoIterator<Item = (Vec<u8>, BanElement)>,
    {
        let mut root_link: Option<Option<Vec<u8>>> = None;
        let mut nodes: BTreeMap<Vec<u8>, NodeEntry> = BTreeMap::new();
        let mut seen_any = false;

        for (asset_name, element) in elements {
            seen_any = true;
            if asset_name == BAN_ROOT_KEY {
                let BanElementData::Root = element.data else {
                    return Err(BanListError::KindMismatch(asset_name));
                };
                if root_link.replace(element.link).is_some() {
                    return Err(BanListError::DuplicateElement(asset_name));
                }
            } else {
                // Node asset name = "ban/" || pool_id; the chain key is the
                // bare pool_id (the library drops the prefix).
                let Some(pool_id) = asset_name.strip_prefix(BAN_NODE_KEY_PREFIX) else {
                    return Err(BanListError::BadNodeKey(asset_name));
                };
                if pool_id.is_empty() || pool_id.len() > MAX_NODE_KEY_LEN {
                    return Err(BanListError::BadNodeKey(asset_name));
                }
                let pool_id = pool_id.to_vec();
                let BanElementData::Node(data) = element.data else {
                    return Err(BanListError::KindMismatch(asset_name));
                };
                if data.ban_counter < 1 || data.ban_until_epoch < 0 {
                    return Err(BanListError::BadNodeData { pool_id });
                }
                let entry = NodeEntry {
                    data,
                    link: element.link,
                };
                if nodes.insert(pool_id.clone(), entry).is_some() {
                    return Err(BanListError::DuplicateElement(asset_name));
                }
            }
        }

        if !seen_any {
            return Err(BanListError::NotBootstrapped);
        }
        let root_link = root_link.ok_or(BanListError::MissingRoot)?;
        let list = BanList { root_link, nodes };
        list.check_chain()?;
        Ok(list)
    }

    /// Walk the links from the root: every hop must land on a known node
    /// with a strictly greater pool_id (rules out cycles), and the walk must
    /// cover all nodes (rules out orphans / forks).
    fn check_chain(&self) -> Result<(), BanListError> {
        let mut visited = 0usize;
        let mut prev: Option<&[u8]> = None;
        let mut cursor = self.root_link.as_deref();
        while let Some(key) = cursor {
            if prev.is_some_and(|p| key <= p) {
                return Err(BanListError::NotAscending(key.to_vec()));
            }
            let entry = self
                .nodes
                .get(key)
                .ok_or_else(|| BanListError::BrokenLink(key.to_vec()))?;
            visited += 1;
            prev = Some(key);
            cursor = entry.link.as_deref();
        }
        if visited != self.nodes.len() {
            return Err(BanListError::UnreachableNodes(self.nodes.len() - visited));
        }
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[must_use]
    pub fn get(&self, pool_id: &[u8]) -> Option<&BanNodeData> {
        self.nodes.get(pool_id).map(|e| &e.data)
    }

    /// All ban entries in ascending pool_id order (== chain order),
    /// including expired ones.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &BanNodeData)> {
        self.nodes.iter().map(|(k, e)| (k.as_slice(), &e.data))
    }

    /// Whether `pool_id` is banned for `epoch`.
    #[must_use]
    pub fn is_banned(&self, pool_id: &[u8], epoch: u64) -> bool {
        self.get(pool_id).is_some_and(|d| d.active_for(epoch))
    }

    /// The pool_ids actively banned for `epoch` — the set the eligible
    /// roster (WI-012) subtracts from the registry snapshot.
    #[must_use]
    pub fn active_bans(&self, epoch: u64) -> BTreeSet<Vec<u8>> {
        self.nodes
            .iter()
            .filter(|(_, e)| e.data.active_for(epoch))
            .map(|(k, _)| k.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// On-chain scan
// ---------------------------------------------------------------------------

/// One located ban element UTxO, decoded.
#[derive(Debug, Clone)]
pub struct BanUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub lovelace: u64,
    /// The element's NFT asset name (`"ban-root"` or `"ban/" || pool_id`).
    pub asset_name: Vec<u8>,
    pub element: BanElement,
}

/// Decode the ban-list elements among `utxos` (fetched from the ban script
/// address). Same shape contract as the registry scan: UTxOs without a
/// ban-policy asset are ignored, malformed element UTxOs are errors.
pub fn find_ban_utxos(utxos: &[BfUtxo], policy_id_hex: &str) -> Result<Vec<BanUtxo>, BanListError> {
    nft_scan::find_policy_nft_utxos(utxos, policy_id_hex)
        .map_err(BanListError::BadElementUtxo)?
        .into_iter()
        .map(|u| {
            let element = BanElement::from_plutus_data(&u.datum).map_err(|e| {
                BanListError::BadElementUtxo(format!(
                    "{}#{}: datum: {e}",
                    u.tx_hash, u.output_index
                ))
            })?;
            Ok(BanUtxo {
                tx_hash: u.tx_hash,
                output_index: u.output_index,
                lovelace: u.lovelace,
                asset_name: u.asset_name,
                element,
            })
        })
        .collect()
}

/// Build a validated [`BanList`] from caller-fetched UTxOs.
pub fn ban_snapshot(utxos: &[BfUtxo], policy_id_hex: &str) -> Result<BanList, BanListError> {
    let elements = find_ban_utxos(utxos, policy_id_hex)?;
    BanList::from_elements(elements.into_iter().map(|u| (u.asset_name, u.element)))
}

// ---------------------------------------------------------------------------
// Config-derived source
// ---------------------------------------------------------------------------

/// Where to read the on-chain ban list: the ban script address + policy,
/// derived from the blueprint, the registry bootstrap outref (the ban policy
/// is parameterized by the registry policy id), the parameterless
/// fault_verifier hash, and the ban list's own one-shot bootstrap outref.
#[derive(Debug, Clone)]
pub struct BanListSource {
    pub ban_address: String,
    pub ban_policy_hex: String,
}

impl BanListSource {
    /// Parameterize `spo_bans` from the blueprint and derive its address.
    pub fn from_blueprint(
        blueprint_path: &str,
        registry_bootstrap: &str,
        ban_bootstrap: &str,
        mainnet: bool,
    ) -> Result<Self, BanListError> {
        let blueprint_json = std::fs::read_to_string(blueprint_path)
            .map_err(|e| BanListError::Config(format!("read blueprint {blueprint_path}: {e}")))?;
        let (reg_tx_id, reg_index) = parse_outref(registry_bootstrap)
            .map_err(|e| BanListError::Config(format!("registry bootstrap outref: {e}")))?;
        let (ban_tx_id, ban_index) = parse_outref(ban_bootstrap)
            .map_err(|e| BanListError::Config(format!("ban bootstrap outref: {e}")))?;
        let err = |what: &str, e: BlueprintError| {
            BanListError::Config(format!("parameterize {what}: {e}"))
        };
        let registry =
            blueprint::spos_registry_script(&blueprint_json, &reg_tx_id, u64::from(reg_index))
                .map_err(|e| err("spos_registry", e))?;
        let fault_policy =
            blueprint::validator_hash(&blueprint_json, blueprint::FAULT_VERIFIER_TITLE)
                .map_err(|e| err("fault_verifier", e))?;
        let bans = blueprint::spo_bans_script(
            &blueprint_json,
            &registry.hash,
            &fault_policy,
            &ban_tx_id,
            u64::from(ban_index),
        )
        .map_err(|e| err("spo_bans", e))?;
        let network = if mainnet {
            pallas_addresses::Network::Mainnet
        } else {
            pallas_addresses::Network::Testnet
        };
        Ok(Self {
            ban_address: bans.enterprise_address(network),
            ban_policy_hex: bans.hash_hex(),
        })
    }

    /// Build from `[cardano]` config. The ban list is configured iff
    /// `ban_bootstrap` is set (`None` otherwise); it then also requires the
    /// registry fields the ban policy is parameterized by.
    pub fn from_config(
        cardano: &crate::config::CardanoConfig,
    ) -> Result<Option<Self>, BanListError> {
        let Some(ban_bootstrap) = cardano.ban_bootstrap.as_deref() else {
            return Ok(None);
        };
        let (Some(blueprint_path), Some(registry_bootstrap)) = (
            cardano.registry_blueprint.as_deref(),
            cardano.registry_bootstrap.as_deref(),
        ) else {
            return Err(BanListError::Config(
                "cardano.ban_bootstrap is set but cardano.registry_blueprint / \
                 cardano.registry_bootstrap are not — the ban policy is parameterized \
                 by the registry policy"
                    .into(),
            ));
        };
        let mainnet = cardano
            .blockfrost_project_id
            .as_deref()
            .is_some_and(|p| p.starts_with("mainnet"));
        Self::from_blueprint(blueprint_path, registry_bootstrap, ban_bootstrap, mainnet).map(Some)
    }

    /// Fetch the ban-list UTxOs and build the validated snapshot, retrying
    /// transient failures (network blips, torn paginated reads) so a ban tx
    /// confirming mid-read doesn't fail the whole roster derivation — the
    /// same absorption [`RegistryRosterSource::fetch_snapshot`] gets.
    pub async fn fetch_ban_list(
        &self,
        base_url: &str,
        project_id: &str,
    ) -> Result<BanList, BanListError> {
        crate::cardano::retry::retry_transient(
            &crate::cardano::retry::DEFAULT_DELAYS,
            "ban-list",
            BanListError::is_transient,
            || async {
                let utxos = bf_http::fetch_address_utxos(base_url, project_id, &self.ban_address)
                    .await
                    .map_err(BanListError::Fetch)?;
                ban_snapshot(&utxos, &self.ban_policy_hex)
            },
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::bf_http::BfAmount;

    const BAN_POLICY: &str = "33333333333333333333333333333333333333333333333333333333";

    fn node_data(counter: i64, until: i64) -> BanNodeData {
        BanNodeData {
            ban_counter: counter,
            ban_until_epoch: until,
        }
    }

    fn root_elem(link: Option<&[u8]>) -> (Vec<u8>, BanElement) {
        (
            BAN_ROOT_KEY.to_vec(),
            BanElement {
                data: BanElementData::Root,
                link: link.map(<[u8]>::to_vec),
            },
        )
    }

    /// Node element under asset name `"ban/" || pool_id`.
    fn node_elem(pool_id: &[u8], data: BanNodeData, link: Option<&[u8]>) -> (Vec<u8>, BanElement) {
        let mut asset = BAN_NODE_KEY_PREFIX.to_vec();
        asset.extend_from_slice(pool_id);
        (
            asset,
            BanElement {
                data: BanElementData::Node(data),
                link: link.map(<[u8]>::to_vec),
            },
        )
    }

    /// Well-formed 2-node list: pools "aa" (counter 1, until 10) and "bb"
    /// (counter 2, until 20).
    fn two_node_list() -> BanList {
        BanList::from_elements([
            node_elem(b"bb-pool", node_data(2, 20), None),
            root_elem(Some(b"aa-pool")),
            node_elem(b"aa-pool", node_data(1, 10), Some(b"bb-pool")),
        ])
        .unwrap()
    }

    #[test]
    fn element_cbor_roundtrip() {
        let cases = [
            BanElement {
                data: BanElementData::Root,
                link: None,
            },
            BanElement {
                data: BanElementData::Root,
                link: Some(b"aa-pool".to_vec()),
            },
            BanElement {
                data: BanElementData::Node(node_data(1, 295)),
                link: None,
            },
            BanElement {
                data: BanElementData::Node(node_data(7, 1_000_000)),
                link: Some(vec![0xFF; 28]),
            },
        ];
        for elem in cases {
            let cbor = elem.to_cbor();
            let decoded: PlutusData = minicbor::decode(&cbor).unwrap();
            assert_eq!(BanElement::from_plutus_data(&decoded).unwrap(), elem);
        }
    }

    #[test]
    fn element_datum_is_canonical_and_shaped_like_the_contract() {
        // Root with no link: Constr(0, [Constr(0, [Constr(0, [])]), Constr(1, [])]).
        let root = BanElement {
            data: BanElementData::Root,
            link: None,
        };
        assert_eq!(hex::encode(root.to_cbor()), "d8799fd8799fd87980ffd87a80ff");
        // Node{1, 10} link→"x": ints encoded inline.
        let node = BanElement {
            data: BanElementData::Node(node_data(1, 10)),
            link: Some(b"x".to_vec()),
        };
        assert_eq!(
            hex::encode(node.to_cbor()),
            "d8799fd87a9fd8799f010affffd8799f4178ffff"
        );
    }

    #[test]
    fn element_rejects_bad_shape() {
        let none_link = constr(1, vec![]);
        // not a Constr
        assert!(matches!(
            BanElement::from_plutus_data(&bytes(b"x")),
            Err(BanListError::NotConstr)
        ));
        // ElementData constructor out of range
        let bad = constr(0, vec![constr(2, vec![]), none_link.clone()]);
        assert!(matches!(
            BanElement::from_plutus_data(&bad),
            Err(BanListError::WrongConstructor(2))
        ));
        // BanNodeData must have 2 fields
        let bad = constr(
            0,
            vec![constr(1, vec![constr(0, vec![int(1)])]), none_link.clone()],
        );
        assert!(matches!(
            BanElement::from_plutus_data(&bad),
            Err(BanListError::FieldCount {
                expected: 2,
                got: 1
            })
        ));
        // BanNodeData fields must be Ints
        let bad = constr(
            0,
            vec![
                constr(1, vec![constr(0, vec![bytes(b"x"), int(1)])]),
                none_link,
            ],
        );
        assert!(matches!(
            BanElement::from_plutus_data(&bad),
            Err(BanListError::BadField(plutus::PlutusError::NotInt(0)))
        ));
    }

    #[test]
    fn reconstructs_list_and_reads_bans() {
        let list = two_node_list();
        assert_eq!(list.len(), 2);
        let keys: Vec<&[u8]> = list.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, [b"aa-pool", b"bb-pool"]);
        assert_eq!(list.get(b"bb-pool"), Some(&node_data(2, 20)));

        // active iff ban_until_epoch > epoch
        assert!(list.is_banned(b"aa-pool", 9));
        assert!(!list.is_banned(b"aa-pool", 10), "until == epoch is expired");
        assert!(!list.is_banned(b"zz-pool", 0), "unknown pool is not banned");
        assert_eq!(
            list.active_bans(9),
            BTreeSet::from([b"aa-pool".to_vec(), b"bb-pool".to_vec()])
        );
        assert_eq!(list.active_bans(15), BTreeSet::from([b"bb-pool".to_vec()]));
        assert!(list.active_bans(20).is_empty());
    }

    #[test]
    fn empty_list_vs_not_bootstrapped() {
        // bootstrapped, zero bans: valid empty snapshot
        let empty = BanList::from_elements([root_elem(None)]).unwrap();
        assert!(empty.is_empty());
        assert!(empty.active_bans(0).is_empty());
        // nothing at the address at all: distinct explicit error
        assert!(matches!(
            BanList::from_elements([]),
            Err(BanListError::NotBootstrapped)
        ));
        // nodes without a root: corrupt, not "unbootstrapped"
        assert!(matches!(
            BanList::from_elements([node_elem(b"aa", node_data(1, 5), None)]),
            Err(BanListError::MissingRoot)
        ));
    }

    #[test]
    fn rejects_corrupt_snapshots() {
        // node asset name without the "ban/" prefix
        assert!(matches!(
            BanList::from_elements([
                root_elem(None),
                (
                    b"aa-pool".to_vec(),
                    node_elem(b"aa-pool", node_data(1, 5), None).1
                ),
            ]),
            Err(BanListError::BadNodeKey(_))
        ));
        // node key longer than 28 bytes (asset > 32)
        assert!(matches!(
            BanList::from_elements([
                root_elem(None),
                node_elem(&[1u8; 29], node_data(1, 5), None)
            ]),
            Err(BanListError::BadNodeKey(_))
        ));
        // root-keyed element carrying Node data
        let (_, node) = node_elem(b"aa", node_data(1, 5), None);
        assert!(matches!(
            BanList::from_elements([(BAN_ROOT_KEY.to_vec(), node)]),
            Err(BanListError::KindMismatch(_))
        ));
        // impossible ban data
        assert!(matches!(
            BanList::from_elements([
                root_elem(Some(b"aa")),
                node_elem(b"aa", node_data(0, 5), None)
            ]),
            Err(BanListError::BadNodeData { .. })
        ));
        assert!(matches!(
            BanList::from_elements([
                root_elem(Some(b"aa")),
                node_elem(b"aa", node_data(1, -1), None)
            ]),
            Err(BanListError::BadNodeData { .. })
        ));
        // link to absent pool
        assert!(matches!(
            BanList::from_elements([
                root_elem(Some(b"zz")),
                node_elem(b"aa", node_data(1, 5), None)
            ]),
            Err(BanListError::BrokenLink(_))
        ));
        // chain out of order
        assert!(matches!(
            BanList::from_elements([
                root_elem(Some(b"bb")),
                node_elem(b"bb", node_data(1, 5), Some(b"aa")),
                node_elem(b"aa", node_data(1, 5), None),
            ]),
            Err(BanListError::NotAscending(_))
        ));
        // orphan node
        assert!(matches!(
            BanList::from_elements([
                root_elem(Some(b"aa")),
                node_elem(b"aa", node_data(1, 5), None),
                node_elem(b"cc", node_data(1, 5), None),
            ]),
            Err(BanListError::UnreachableNodes(1))
        ));
        // two roots
        assert!(matches!(
            BanList::from_elements([root_elem(None), root_elem(None)]),
            Err(BanListError::DuplicateElement(_))
        ));
    }

    // -- scan over BfUtxos ---------------------------------------------------

    fn ban_utxo(tx: &str, ix: u32, asset_name: &[u8], elem: &BanElement) -> BfUtxo {
        BfUtxo {
            tx_hash: tx.to_string(),
            output_index: ix,
            amount: vec![
                BfAmount {
                    unit: "lovelace".into(),
                    quantity: "2000000".into(),
                },
                BfAmount {
                    unit: format!("{BAN_POLICY}{}", hex::encode(asset_name)),
                    quantity: "1".into(),
                },
            ],
            inline_datum: Some(hex::encode(elem.to_cbor())),
            reference_script_hash: None,
        }
    }

    #[test]
    fn ban_snapshot_from_utxos() {
        let (root_name, root) = root_elem(Some(b"aa-pool"));
        let (node_name, node) = node_elem(b"aa-pool", node_data(1, 296), None);
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
        let utxos = vec![
            stray,
            ban_utxo(&"00".repeat(32), 0, &root_name, &root),
            ban_utxo(&"01".repeat(32), 0, &node_name, &node),
        ];
        let list = ban_snapshot(&utxos, BAN_POLICY).unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.is_banned(b"aa-pool", 295));
        assert!(!list.is_banned(b"aa-pool", 296));

        // address with only stray value (no ban NFTs) → NotBootstrapped
        let stray_only = vec![utxos[0].clone()];
        assert!(matches!(
            ban_snapshot(&stray_only, BAN_POLICY),
            Err(BanListError::NotBootstrapped)
        ));
    }

    // -- config plumbing -----------------------------------------------------

    #[test]
    fn source_from_config_requires_registry_fields() {
        let mut cardano = crate::config::CardanoConfig::default();
        // bans unconfigured → None
        assert!(BanListSource::from_config(&cardano).unwrap().is_none());
        // ban_bootstrap without the registry fields → explicit error
        cardano.ban_bootstrap = Some(format!("{}:0", "aa".repeat(32)));
        assert!(matches!(
            BanListSource::from_config(&cardano),
            Err(BanListError::Config(_))
        ));
    }
}
