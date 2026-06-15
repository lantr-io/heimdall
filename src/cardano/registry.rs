//! `spos_registry.ak` linked-list management (R1b).
//!
//! The on-chain SPO registry is an `aiken_design_patterns/linked_list`: one
//! UTxO per element at the registry script address, each authenticated by an
//! NFT of the registry policy. The NFT asset name is the element's key — the
//! root holds the constant `"reg-root"`, every node holds a `pool_id`
//! (`blake2b_224(cold_vkey)`, the node-key prefix is empty). Each element's
//! inline datum is:
//!
//! ```text
//! Element       = Constr(0, [ ElementData, Link ])
//! ElementData   = Constr(0, [ Constr(0, []) ])                      -- Root{ListRootData}
//!               | Constr(1, [ Constr(0, [bifrost_id_pk, bifrost_url]) ])  -- Node{RegistrationNodeData}
//! Link          = Constr(0, [ next_key ])                           -- Some
//!               | Constr(1, [])                                     -- None
//! ```
//!
//! (constructor indices confirmed against the compiled `plutus.json`
//! blueprint of `ft-bifrost-bridge`).
//!
//! `register_spo` inserts ascending: the spent **anchor** is the element with
//! the greatest key strictly below the new `pool_id` (the root anchors
//! everything below the first node). On-chain, `linked_list.insert_ascending`
//! requires the continued anchor to keep its data and point to the new key,
//! and the new node to take over the anchor's old link. This module replicates
//! that off-chain: decode the element datums, reconstruct + integrity-check
//! the list, find the predecessor anchor, and produce the two output datums
//! ([`RegistryList::plan_insert`]) for the register_spo tx builder (R1).

use std::collections::BTreeMap;

use pallas_codec::minicbor;
use pallas_primitives::PlutusData;

use crate::cardano::plutus::{self, bytes, constr};

/// Asset name of the root element's NFT (`registration_root_key` in
/// `spos_registry.ak`).
pub const REGISTRATION_ROOT_KEY: &[u8] = b"reg-root";

/// Ledger limit on asset-name length; node keys live in asset names.
const MAX_NODE_KEY_LEN: usize = 32;

/// `RegistrationNodeData` — the payload of one registered SPO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationNodeData {
    pub bifrost_id_pk: Vec<u8>,
    pub bifrost_url: Vec<u8>,
}

/// `ElementData<ListRootData, RegistrationNodeData>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElementData {
    Root,
    Node(RegistrationNodeData),
}

/// One registry element datum (`RegistrationListDatum`). The element's key is
/// *not* in the datum — it is the asset name of the NFT held by the UTxO.
/// `link` is the key (pool_id) of the next node in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryElement {
    pub data: ElementData,
    pub link: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum RegistryError {
    // -- datum decoding --
    NotConstr,
    WrongConstructor(u64),
    FieldCount {
        expected: usize,
        got: usize,
    },
    NotBytes(usize),
    // -- snapshot reconstruction --
    /// No element carries the `"reg-root"` NFT.
    MissingRoot,
    /// Two elements share an asset name (impossible for honest NFTs; a
    /// corrupt snapshot).
    DuplicateElement(Vec<u8>),
    /// Root-keyed element holds `Node` data, or node-keyed element holds
    /// `Root` data.
    KindMismatch(Vec<u8>),
    /// Node key is empty, longer than 32 bytes, or equals the root key.
    BadNodeKey(Vec<u8>),
    /// A link points at a key not present in the snapshot.
    BrokenLink(Vec<u8>),
    /// Following the links does not visit keys in strictly ascending order
    /// (also catches cycles and self-links).
    NotAscending(Vec<u8>),
    /// Nodes exist that the chain from the root never reaches.
    UnreachableNodes(usize),
    // -- insert planning --
    /// The pool_id already has a registration node.
    AlreadyRegistered,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConstr => write!(f, "expected Constr"),
            Self::WrongConstructor(c) => write!(f, "unexpected constructor {c}"),
            Self::FieldCount { expected, got } => {
                write!(f, "expected {expected} field(s), got {got}")
            }
            Self::NotBytes(i) => write!(f, "field[{i}]: expected ByteArray"),
            Self::MissingRoot => write!(f, "no element with the reg-root NFT"),
            Self::DuplicateElement(k) => write!(f, "duplicate element key {}", hex::encode(k)),
            Self::KindMismatch(k) => {
                write!(
                    f,
                    "element kind does not match asset name {}",
                    hex::encode(k)
                )
            }
            Self::BadNodeKey(k) => write!(f, "bad node key {}", hex::encode(k)),
            Self::BrokenLink(k) => write!(f, "link to absent key {}", hex::encode(k)),
            Self::NotAscending(k) => write!(f, "chain not ascending at key {}", hex::encode(k)),
            Self::UnreachableNodes(n) => write!(f, "{n} node(s) unreachable from root"),
            Self::AlreadyRegistered => write!(f, "pool_id already registered"),
        }
    }
}

impl std::error::Error for RegistryError {}

impl From<plutus::PlutusError> for RegistryError {
    fn from(e: plutus::PlutusError) -> Self {
        match e {
            plutus::PlutusError::NotConstr => Self::NotConstr,
            plutus::PlutusError::WrongConstructor { got, .. } => Self::WrongConstructor(got),
            // NotInt is unreachable for this datum shape (no Int fields).
            plutus::PlutusError::MissingField(i)
            | plutus::PlutusError::NotBytes(i)
            | plutus::PlutusError::NotInt(i) => Self::NotBytes(i),
        }
    }
}

// Plutus encode/decode (constructor tags, canonical encoding, `as_constr` /
// `constr_fields` / `field_bytes`) live in `crate::cardano::plutus`.

/// Field-count guard with this module's `FieldCount` error (the shared decoder
/// only validates field *types*, not arity).
fn expect_len(fields: &[PlutusData], expected: usize) -> Result<(), RegistryError> {
    if fields.len() != expected {
        return Err(RegistryError::FieldCount {
            expected,
            got: fields.len(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Element datum encode / decode
// ---------------------------------------------------------------------------

impl RegistryElement {
    /// Encode as `Constr(0, [ElementData, Link])`.
    #[must_use]
    pub fn to_plutus_data(&self) -> PlutusData {
        let data = match &self.data {
            // Root { data: ListRootData } — ListRootData is Constr(0, []).
            ElementData::Root => constr(0, vec![constr(0, vec![])]),
            ElementData::Node(n) => constr(
                1,
                vec![constr(
                    0,
                    vec![bytes(&n.bifrost_id_pk), bytes(&n.bifrost_url)],
                )],
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

    pub fn from_plutus_data(pd: &PlutusData) -> Result<Self, RegistryError> {
        let fields = plutus::constr_fields(pd, 0)?;
        expect_len(fields, 2)?;

        let (data_ctor, data_fields) = plutus::as_constr(&fields[0])?;
        let data = match data_ctor {
            0 => {
                // Root { data: ListRootData }; ListRootData must be Constr(0, []).
                expect_len(data_fields, 1)?;
                let root_fields = plutus::constr_fields(&data_fields[0], 0)?;
                expect_len(root_fields, 0)?;
                ElementData::Root
            }
            1 => {
                expect_len(data_fields, 1)?;
                let node_fields = plutus::constr_fields(&data_fields[0], 0)?;
                expect_len(node_fields, 2)?;
                ElementData::Node(RegistrationNodeData {
                    bifrost_id_pk: plutus::field_bytes(node_fields, 0)?,
                    bifrost_url: plutus::field_bytes(node_fields, 1)?,
                })
            }
            other => return Err(RegistryError::WrongConstructor(other)),
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
            other => return Err(RegistryError::WrongConstructor(other)),
        };

        Ok(RegistryElement { data, link })
    }
}

// ---------------------------------------------------------------------------
// List reconstruction + ascending insert
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeEntry {
    data: RegistrationNodeData,
    link: Option<Vec<u8>>,
}

/// A validated snapshot of the on-chain registry list. Construction proves
/// the snapshot is a single well-formed chain: one root, every node reachable
/// from it, keys strictly ascending along the links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryList {
    root_link: Option<Vec<u8>>,
    nodes: BTreeMap<Vec<u8>, NodeEntry>,
}

impl RegistryList {
    /// Reconstruct from `(asset_name, element)` pairs — one per UTxO at the
    /// registry script address holding a registry-policy NFT.
    pub fn from_elements<I>(elements: I) -> Result<Self, RegistryError>
    where
        I: IntoIterator<Item = (Vec<u8>, RegistryElement)>,
    {
        let mut root_link: Option<Option<Vec<u8>>> = None;
        let mut nodes: BTreeMap<Vec<u8>, NodeEntry> = BTreeMap::new();

        for (asset_name, element) in elements {
            if asset_name == REGISTRATION_ROOT_KEY {
                let ElementData::Root = element.data else {
                    return Err(RegistryError::KindMismatch(asset_name));
                };
                if root_link.replace(element.link).is_some() {
                    return Err(RegistryError::DuplicateElement(asset_name));
                }
            } else {
                if asset_name.is_empty() || asset_name.len() > MAX_NODE_KEY_LEN {
                    return Err(RegistryError::BadNodeKey(asset_name));
                }
                let ElementData::Node(data) = element.data else {
                    return Err(RegistryError::KindMismatch(asset_name));
                };
                let entry = NodeEntry {
                    data,
                    link: element.link,
                };
                if nodes.insert(asset_name.clone(), entry).is_some() {
                    return Err(RegistryError::DuplicateElement(asset_name));
                }
            }
        }

        let root_link = root_link.ok_or(RegistryError::MissingRoot)?;
        let list = RegistryList { root_link, nodes };
        list.check_chain()?;
        Ok(list)
    }

    /// Walk the links from the root: every hop must land on a known node with
    /// a strictly greater key (rules out cycles), and the walk must cover all
    /// nodes (rules out orphans / forks).
    fn check_chain(&self) -> Result<(), RegistryError> {
        let mut visited = 0usize;
        let mut prev: Option<&[u8]> = None;
        let mut cursor = self.root_link.as_deref();
        while let Some(key) = cursor {
            if prev.is_some_and(|p| key <= p) {
                return Err(RegistryError::NotAscending(key.to_vec()));
            }
            let entry = self
                .nodes
                .get(key)
                .ok_or_else(|| RegistryError::BrokenLink(key.to_vec()))?;
            visited += 1;
            prev = Some(key);
            cursor = entry.link.as_deref();
        }
        if visited != self.nodes.len() {
            return Err(RegistryError::UnreachableNodes(self.nodes.len() - visited));
        }
        Ok(())
    }

    /// Key of the first node (the root's link), if any.
    #[must_use]
    pub fn root_link(&self) -> Option<&[u8]> {
        self.root_link.as_deref()
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
    pub fn get(&self, pool_id: &[u8]) -> Option<&RegistrationNodeData> {
        self.nodes.get(pool_id).map(|e| &e.data)
    }

    /// Registered SPOs in ascending pool_id order (== chain order).
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &RegistrationNodeData)> {
        self.nodes.iter().map(|(k, e)| (k.as_slice(), &e.data))
    }

    /// `(bifrost_id_pk, pool_id)` pairs for rebuilding the
    /// `bifrost_identity_root` MPF trie (R1c's
    /// [`crate::cardano::mpf::Trie::from_pairs`]).
    #[must_use]
    pub fn identity_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.nodes
            .iter()
            .map(|(k, e)| (e.data.bifrost_id_pk.clone(), k.clone()))
            .collect()
    }

    /// Plan the ascending insert of `pool_id`: find the predecessor anchor
    /// and produce the two output datums the register_spo tx must carry.
    ///
    /// On-chain (`linked_list.insert_ascending`) the registry validator
    /// checks exactly this shape: the continued anchor keeps its data and
    /// links to `pool_id`; the new node carries the anchor's old link.
    pub fn plan_insert(
        &self,
        pool_id: &[u8],
        data: RegistrationNodeData,
    ) -> Result<RegistryInsert, RegistryError> {
        if pool_id.is_empty()
            || pool_id.len() > MAX_NODE_KEY_LEN
            || pool_id == REGISTRATION_ROOT_KEY
        {
            return Err(RegistryError::BadNodeKey(pool_id.to_vec()));
        }
        if self.nodes.contains_key(pool_id) {
            return Err(RegistryError::AlreadyRegistered);
        }

        // Predecessor anchor: the node with the greatest key < pool_id, or
        // the root when no node sorts below the new key.
        let (anchor_asset_name, anchor_data, anchor_link) = match self
            .nodes
            .range::<[u8], _>((
                std::ops::Bound::Unbounded,
                std::ops::Bound::Excluded(pool_id),
            ))
            .next_back()
        {
            Some((key, entry)) => (
                key.clone(),
                ElementData::Node(entry.data.clone()),
                entry.link.clone(),
            ),
            None => (
                REGISTRATION_ROOT_KEY.to_vec(),
                ElementData::Root,
                self.root_link.clone(),
            ),
        };
        // In a chain-checked list the anchor's successor is the next node in
        // key order, which must sort above the (absent) new key.
        debug_assert!(anchor_link.as_deref().is_none_or(|l| l > pool_id));

        Ok(RegistryInsert {
            anchor_asset_name,
            continued_anchor: RegistryElement {
                data: anchor_data,
                link: Some(pool_id.to_vec()),
            },
            new_node_asset_name: pool_id.to_vec(),
            new_node: RegistryElement {
                data: ElementData::Node(data),
                link: anchor_link,
            },
        })
    }
}

/// The linked-list half of a register_spo tx: which element UTxO to spend as
/// the anchor, and the two element datums the outputs must carry. The new
/// node's asset name is also the membership token to mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryInsert {
    /// Asset name of the anchor element's NFT ([`REGISTRATION_ROOT_KEY`] when
    /// the anchor is the root) — identifies the UTxO to spend.
    pub anchor_asset_name: Vec<u8>,
    /// Datum of the continued anchor output (data unchanged, link → new key).
    pub continued_anchor: RegistryElement,
    /// Asset name of the new node's NFT (= pool_id = minted token name).
    pub new_node_asset_name: Vec<u8>,
    /// Datum of the new registration node output.
    pub new_node: RegistryElement,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_data(i: usize) -> RegistrationNodeData {
        RegistrationNodeData {
            bifrost_id_pk: format!("pk-{i}").into_bytes(),
            bifrost_url: format!("https://spo-{i}.example").into_bytes(),
        }
    }

    fn root_elem(link: Option<&[u8]>) -> (Vec<u8>, RegistryElement) {
        (
            REGISTRATION_ROOT_KEY.to_vec(),
            RegistryElement {
                data: ElementData::Root,
                link: link.map(<[u8]>::to_vec),
            },
        )
    }

    fn node_elem(key: &[u8], i: usize, link: Option<&[u8]>) -> (Vec<u8>, RegistryElement) {
        (
            key.to_vec(),
            RegistryElement {
                data: ElementData::Node(node_data(i)),
                link: link.map(<[u8]>::to_vec),
            },
        )
    }

    /// A well-formed 3-node list (keys a < b < c), shuffled.
    fn three_node_list() -> RegistryList {
        RegistryList::from_elements([
            node_elem(b"cc-pool", 2, None),
            root_elem(Some(b"aa-pool")),
            node_elem(b"bb-pool", 1, Some(b"cc-pool")),
            node_elem(b"aa-pool", 0, Some(b"bb-pool")),
        ])
        .unwrap()
    }

    #[test]
    fn element_cbor_roundtrip() {
        let cases = [
            RegistryElement {
                data: ElementData::Root,
                link: None,
            },
            RegistryElement {
                data: ElementData::Root,
                link: Some(b"aa-pool".to_vec()),
            },
            RegistryElement {
                data: ElementData::Node(node_data(7)),
                link: None,
            },
            RegistryElement {
                data: ElementData::Node(node_data(7)),
                link: Some(vec![0xFF; 28]),
            },
        ];
        for elem in cases {
            let cbor = elem.to_cbor();
            let decoded: PlutusData = minicbor::decode(&cbor).unwrap();
            assert_eq!(RegistryElement::from_plutus_data(&decoded).unwrap(), elem);
        }
    }

    #[test]
    fn element_rejects_bad_shape() {
        let ok_node_data = constr(0, vec![bytes(b"pk"), bytes(b"url")]);
        let none_link = constr(1, vec![]);

        // not a Constr at all
        assert!(matches!(
            RegistryElement::from_plutus_data(&bytes(b"x")),
            Err(RegistryError::NotConstr)
        ));
        // Element wrapper must be constructor 0
        assert!(matches!(
            RegistryElement::from_plutus_data(&constr(1, vec![])),
            Err(RegistryError::WrongConstructor(1))
        ));
        // Element must have exactly [data, link]
        assert!(matches!(
            RegistryElement::from_plutus_data(&constr(0, vec![none_link.clone()])),
            Err(RegistryError::FieldCount {
                expected: 2,
                got: 1
            })
        ));
        // ElementData constructor out of range
        let bad = constr(0, vec![constr(2, vec![]), none_link.clone()]);
        assert!(matches!(
            RegistryElement::from_plutus_data(&bad),
            Err(RegistryError::WrongConstructor(2))
        ));
        // ListRootData must be Constr(0, [])
        let bad = constr(
            0,
            vec![constr(0, vec![constr(1, vec![])]), none_link.clone()],
        );
        assert!(matches!(
            RegistryElement::from_plutus_data(&bad),
            Err(RegistryError::WrongConstructor(1))
        ));
        // RegistrationNodeData must have 2 fields
        let bad = constr(
            0,
            vec![
                constr(1, vec![constr(0, vec![bytes(b"pk")])]),
                none_link.clone(),
            ],
        );
        assert!(matches!(
            RegistryElement::from_plutus_data(&bad),
            Err(RegistryError::FieldCount {
                expected: 2,
                got: 1
            })
        ));
        // Some-link payload must be bytes
        let bad = constr(
            0,
            vec![
                constr(1, vec![ok_node_data.clone()]),
                constr(0, vec![constr(0, vec![])]),
            ],
        );
        assert!(matches!(
            RegistryElement::from_plutus_data(&bad),
            Err(RegistryError::NotBytes(0))
        ));
        // link constructor out of range
        let bad = constr(0, vec![constr(1, vec![ok_node_data]), constr(2, vec![])]);
        assert!(matches!(
            RegistryElement::from_plutus_data(&bad),
            Err(RegistryError::WrongConstructor(2))
        ));
    }

    #[test]
    fn reconstructs_shuffled_snapshot_in_chain_order() {
        let list = three_node_list();
        assert_eq!(list.len(), 3);
        assert_eq!(list.root_link(), Some(b"aa-pool".as_slice()));
        let keys: Vec<&[u8]> = list.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, [b"aa-pool", b"bb-pool", b"cc-pool"]);
        assert_eq!(list.get(b"bb-pool"), Some(&node_data(1)));

        // an empty list is just the root with no link
        let empty = RegistryList::from_elements([root_elem(None)]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.root_link(), None);
    }

    #[test]
    fn rejects_corrupt_snapshots() {
        // no root element
        assert!(matches!(
            RegistryList::from_elements([node_elem(b"aa", 0, None)]),
            Err(RegistryError::MissingRoot)
        ));
        // two roots
        assert!(matches!(
            RegistryList::from_elements([root_elem(None), root_elem(None)]),
            Err(RegistryError::DuplicateElement(_))
        ));
        // two nodes under the same asset name
        assert!(matches!(
            RegistryList::from_elements([
                root_elem(Some(b"aa")),
                node_elem(b"aa", 0, None),
                node_elem(b"aa", 1, None),
            ]),
            Err(RegistryError::DuplicateElement(_))
        ));
        // root-keyed element carrying Node data
        let (_, node) = node_elem(b"aa", 0, None);
        assert!(matches!(
            RegistryList::from_elements([(REGISTRATION_ROOT_KEY.to_vec(), node)]),
            Err(RegistryError::KindMismatch(_))
        ));
        // node-keyed element carrying Root data
        let (_, root) = root_elem(None);
        assert!(matches!(
            RegistryList::from_elements([root_elem(None), (b"aa".to_vec(), root)]),
            Err(RegistryError::KindMismatch(_))
        ));
        // node key longer than an asset name allows
        assert!(matches!(
            RegistryList::from_elements([root_elem(None), node_elem(&[1u8; 33], 0, None)]),
            Err(RegistryError::BadNodeKey(_))
        ));
        // link to a key not in the snapshot
        assert!(matches!(
            RegistryList::from_elements([root_elem(Some(b"zz")), node_elem(b"aa", 0, None)]),
            Err(RegistryError::BrokenLink(_))
        ));
        // chain visits keys out of order (root → bb → aa)
        assert!(matches!(
            RegistryList::from_elements([
                root_elem(Some(b"bb")),
                node_elem(b"bb", 1, Some(b"aa")),
                node_elem(b"aa", 0, None),
            ]),
            Err(RegistryError::NotAscending(_))
        ));
        // self-link cycle
        assert!(matches!(
            RegistryList::from_elements(
                [root_elem(Some(b"aa")), node_elem(b"aa", 0, Some(b"aa")),]
            ),
            Err(RegistryError::NotAscending(_))
        ));
        // node not reachable from the root
        assert!(matches!(
            RegistryList::from_elements([
                root_elem(Some(b"aa")),
                node_elem(b"aa", 0, None),
                node_elem(b"cc", 2, None),
            ]),
            Err(RegistryError::UnreachableNodes(1))
        ));
    }

    /// Assert the conditions `linked_list.insert_ascending` checks on-chain
    /// (`spos_registry.ak` instantiation: empty key prefix, asset name ==
    /// key) hold for a planned insert against the pre-insert anchor element.
    fn assert_onchain_insert_ok(
        anchor_before: &RegistryElement,
        plan: &RegistryInsert,
        new_key: &[u8],
    ) {
        // validate_three_elements #4: anchor data unchanged.
        assert_eq!(plan.continued_anchor.data, anchor_before.data);
        // insert_ordered #5: continued anchor points to the new node.
        assert_eq!(plan.continued_anchor.link.as_deref(), Some(new_key));
        // insert_ordered #6: new node takes over the anchor's old link.
        assert_eq!(plan.new_node.link, anchor_before.link);
        assert_eq!(plan.new_node_asset_name, new_key);
        match &anchor_before.data {
            // #8a/#9a: root anchor — root key matches; new key sorts below
            // the root's old link, if any.
            ElementData::Root => {
                assert_eq!(plan.anchor_asset_name, REGISTRATION_ROOT_KEY);
                if let Some(l) = anchor_before.link.as_deref() {
                    assert!(new_key < l);
                }
            }
            // #9b/#10b: node anchor — anchor key < new key < anchor's old link.
            ElementData::Node(_) => {
                assert!(plan.anchor_asset_name.as_slice() < new_key);
                if let Some(l) = anchor_before.link.as_deref() {
                    assert!(new_key < l);
                }
            }
        }
    }

    #[test]
    fn plan_insert_into_empty_list_anchors_on_root() {
        let empty = RegistryList::from_elements([root_elem(None)]).unwrap();
        let plan = empty.plan_insert(b"aa-pool", node_data(0)).unwrap();
        assert_onchain_insert_ok(&root_elem(None).1, &plan, b"aa-pool");
        assert_eq!(plan.new_node.link, None);
        assert_eq!(plan.new_node.data, ElementData::Node(node_data(0)));
    }

    #[test]
    fn plan_insert_below_first_node_anchors_on_root() {
        let list = three_node_list();
        let plan = list.plan_insert(b"a0-pool", node_data(9)).unwrap();
        assert_onchain_insert_ok(&root_elem(Some(b"aa-pool")).1, &plan, b"a0-pool");
        // displaced first node becomes the new node's successor.
        assert_eq!(plan.new_node.link.as_deref(), Some(b"aa-pool".as_slice()));
    }

    #[test]
    fn plan_insert_mid_list_anchors_on_predecessor() {
        let list = three_node_list();
        let plan = list.plan_insert(b"bx-pool", node_data(9)).unwrap();
        let anchor_before = RegistryElement {
            data: ElementData::Node(node_data(1)),
            link: Some(b"cc-pool".to_vec()),
        };
        assert_onchain_insert_ok(&anchor_before, &plan, b"bx-pool");
        assert_eq!(plan.anchor_asset_name, b"bb-pool");
        assert_eq!(plan.new_node.link.as_deref(), Some(b"cc-pool".as_slice()));
    }

    #[test]
    fn plan_insert_past_last_node_appends() {
        let list = three_node_list();
        let plan = list.plan_insert(b"dd-pool", node_data(9)).unwrap();
        let anchor_before = RegistryElement {
            data: ElementData::Node(node_data(2)),
            link: None,
        };
        assert_onchain_insert_ok(&anchor_before, &plan, b"dd-pool");
        assert_eq!(plan.anchor_asset_name, b"cc-pool");
        assert_eq!(plan.new_node.link, None);
    }

    #[test]
    fn plan_insert_rejects_duplicates_and_bad_keys() {
        let list = three_node_list();
        assert!(matches!(
            list.plan_insert(b"bb-pool", node_data(9)),
            Err(RegistryError::AlreadyRegistered)
        ));
        assert!(matches!(
            list.plan_insert(b"", node_data(9)),
            Err(RegistryError::BadNodeKey(_))
        ));
        assert!(matches!(
            list.plan_insert(&[1u8; 33], node_data(9)),
            Err(RegistryError::BadNodeKey(_))
        ));
        assert!(matches!(
            list.plan_insert(REGISTRATION_ROOT_KEY, node_data(9)),
            Err(RegistryError::BadNodeKey(_))
        ));
    }

    // R1c glue: the list yields (bifrost_id_pk → pool_id) pairs the identity
    // trie is built from.
    #[test]
    fn identity_pairs_feed_the_identity_trie() {
        let list = three_node_list();
        let pairs = list.identity_pairs();
        assert_eq!(
            pairs,
            vec![
                (b"pk-0".to_vec(), b"aa-pool".to_vec()),
                (b"pk-1".to_vec(), b"bb-pool".to_vec()),
                (b"pk-2".to_vec(), b"cc-pool".to_vec()),
            ]
        );
        let trie = crate::cardano::mpf::Trie::from_pairs(pairs.iter().map(|(k, v)| (k, v))).unwrap();
        assert_eq!(trie.len(), 3);
    }
}
