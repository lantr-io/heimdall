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
//!             | Constr(1, [ Constr(0, [ban_counter, ban_until_time, permanent, evidence_hashes]) ])  -- Node{BanNodeData}
//! Link        = Constr(0, [ next_pool_id ])                      -- Some
//!             | Constr(1, [])                                    -- None
//! ```
//!
//! A ban is **active** at POSIX time `T` iff `permanent || ban_until_time > T`
//! (`spo-bans.ak`: a ban's `ban_until_time` is `start + base·2^(counter-1)`,
//! and a ban becomes `permanent` at `max_faults_before_permanent`). The roster
//! derivation (WI-012) subtracts [`BanList::active_bans`] from the registry
//! snapshot, passing the **epoch-boundary** time so every SPO agrees.
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

/// Max node key length the reader tolerates: 32-byte asset name minus the
/// prefix. Real keys are always [`POOL_ID_LEN`]; this only bounds defensive
/// parsing of arbitrary on-chain state.
const MAX_NODE_KEY_LEN: usize = 32 - BAN_NODE_KEY_PREFIX.len();

/// A pool id is `blake2b_224(cold_vkey)` = 28 bytes; `spo_bans.ak`'s
/// `is_pool_id` requires exactly this, so a first-ban [`BanList::plan_insert`]
/// must too.
const POOL_ID_LEN: usize = 28;

/// `BanNodeData` — one pool's ban state (`spo-bans.ak` evidence-bound model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanNodeData {
    /// How many times this pool has been banned (>= 1, validator-enforced).
    pub ban_counter: i64,
    /// POSIX time (ms) at which the ban EXPIRES: active iff `permanent` or
    /// `ban_until_time > T`. `spo-bans.ak` derives the comparison time from the
    /// transaction validity interval; off-chain, the eligible-roster path must
    /// pass the **epoch-boundary** time (deterministic across all SPOs, so the
    /// roster is identical), never a node clock.
    pub ban_until_time: i64,
    /// A permanent ban never expires (set once `ban_counter` reaches the
    /// validator's `max_faults_before_permanent`).
    pub permanent: bool,
    /// Fault evidence hashes already punished for this pool, newest first
    /// (`spo_bans.ak` rejects re-banning on an `evidence_hash` already here).
    pub evidence_hashes: Vec<Vec<u8>>,
}

impl BanNodeData {
    /// Whether the ban is active at POSIX time `now_ms`
    /// (`permanent || ban_until_time > now_ms`).
    #[must_use]
    pub fn active_at(&self, now_ms: i64) -> bool {
        self.permanent || self.ban_until_time > now_ms
    }

    /// First ban for a pool — mirrors `spo-bans.ak` `first_ban_data` exactly,
    /// so the ApplyBan output datum matches what the validator recomputes.
    /// `start_time_ms` is the ban-start time the validator derives from the tx
    /// validity interval; `base_ban_duration_ms` / `max_faults_before_permanent`
    /// are the ban validator's parameters.
    #[must_use]
    pub fn first_ban(
        evidence_hash: Vec<u8>,
        start_time_ms: i64,
        base_ban_duration_ms: i64,
        max_faults_before_permanent: i64,
    ) -> Self {
        let ban_counter = 1;
        Self {
            ban_counter,
            ban_until_time: start_time_ms + ban_duration(base_ban_duration_ms, ban_counter),
            permanent: ban_counter >= max_faults_before_permanent,
            evidence_hashes: vec![evidence_hash],
        }
    }

    /// Repeated-ban update — mirrors `spo-bans.ak` `repeated_ban_transition_ok`,
    /// which is the datum the validator actually requires: it calls the
    /// `repeated_ban_data` helper (whose `permanent` is a throwaway `false`)
    /// then **overrides** `permanent = new_ban_counter >= max_faults_before_permanent`.
    /// So a reban escalates to permanent exactly like a first ban — we must
    /// reproduce that, not the helper's `false`, or the output datum is rejected.
    /// The new `evidence_hash` is **prepended** (Aiken `list.push` adds to the
    /// front), keeping the on-chain list order byte-exact and the invariant
    /// `len(evidence_hashes) == ban_counter` (spo-bans.ak:31).
    #[must_use]
    pub fn repeated_ban(
        &self,
        evidence_hash: Vec<u8>,
        start_time_ms: i64,
        base_ban_duration_ms: i64,
        max_faults_before_permanent: i64,
    ) -> Self {
        let ban_counter = self.ban_counter + 1;
        let mut evidence_hashes = Vec::with_capacity(self.evidence_hashes.len() + 1);
        evidence_hashes.push(evidence_hash);
        evidence_hashes.extend_from_slice(&self.evidence_hashes);
        Self {
            ban_counter,
            ban_until_time: self
                .ban_until_time
                .max(start_time_ms)
                .saturating_add(ban_duration(base_ban_duration_ms, ban_counter)),
            permanent: ban_counter >= max_faults_before_permanent,
            evidence_hashes,
        }
    }
}

/// `base_ban_duration_ms * 2^(ban_counter - 1)` (`spo-bans.ak` `ban_duration`).
/// Saturates rather than overflowing — `ban_counter` is bounded by the
/// validator's `max_faults_before_permanent`, so this never bites in practice.
#[must_use]
pub fn ban_duration(base_ban_duration_ms: i64, ban_counter: i64) -> i64 {
    // Clamp the counter BEFORE subtracting so a non-positive `ban_counter`
    // (this is `pub`, so not shielded by the decoder's `< 1` rejection) can't
    // underflow `i64::MIN - 1`.
    let exp = u32::try_from(ban_counter.max(1) - 1).unwrap_or(u32::MAX);
    base_ban_duration_ms.saturating_mul(2i64.saturating_pow(exp))
}

/// The FaultProof token name `blake2b_256(pool_id || evidence_hash)` that
/// `fault_verifier.ak` mints and `spo_bans.ak` recomputes + burns to bind the
/// ban to a specific pool and piece of fault evidence.
#[must_use]
pub fn fault_token_name(pool_id: &[u8], evidence_hash: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(pool_id.len() + evidence_hash.len());
    buf.extend_from_slice(pool_id);
    buf.extend_from_slice(evidence_hash);
    crate::cardano::hash::blake2b_256(&buf)
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
    /// `ban_counter < 1` or `ban_until_time < 0` — the validator can never
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
    /// `plan_insert` was asked to first-ban a pool that is already banned —
    /// that path is a reban (in-place update), not a list insert.
    AlreadyBanned(Vec<u8>),
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
            Self::AlreadyBanned(k) => write!(
                f,
                "pool {} is already banned (reban, not insert)",
                hex::encode(k)
            ),
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
                vec![constr(
                    0,
                    vec![
                        int(n.ban_counter),
                        int(n.ban_until_time),
                        plutus::bool_data(n.permanent),
                        plutus::array(n.evidence_hashes.iter().map(|h| bytes(h)).collect()),
                    ],
                )],
            ),
        };
        let link = plutus::option(self.link.as_deref().map(bytes));
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
                expect_len(node_fields, 4)?;
                BanElementData::Node(BanNodeData {
                    ban_counter: plutus::field_int(node_fields, 0)?,
                    ban_until_time: plutus::field_int(node_fields, 1)?,
                    permanent: plutus::field_bool(node_fields, 2)?,
                    evidence_hashes: plutus::field_list_bytes(node_fields, 3)?,
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
                // `spo-bans.ak` enforces these on-chain, so a genuine node
                // always satisfies them; a violation means corrupt/forged state.
                // The `len == ban_counter` invariant is the validator's
                // `list.length(evidence_hashes) == ban_counter` (spo-bans.ak:31).
                if data.ban_counter < 1
                    || data.ban_until_time < 0
                    || data.evidence_hashes.len() as i64 != data.ban_counter
                {
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
        use crate::cardano::linked_list::{ChainError, validate_chain};
        validate_chain(self.root_link.as_deref(), self.nodes.len(), |k| {
            self.nodes.get(k).map(|e| e.link.as_deref())
        })
        .map_err(|e| match e {
            ChainError::NotAscending(k) => BanListError::NotAscending(k),
            ChainError::BrokenLink(k) => BanListError::BrokenLink(k),
            ChainError::Unreachable(n) => BanListError::UnreachableNodes(n),
        })
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

    /// Whether `pool_id` is banned at POSIX time `now_ms`.
    #[must_use]
    pub fn is_banned(&self, pool_id: &[u8], now_ms: i64) -> bool {
        self.get(pool_id).is_some_and(|d| d.active_at(now_ms))
    }

    /// The pool_ids actively banned at POSIX time `now_ms` — the set the
    /// eligible roster (WI-012) subtracts from the registry snapshot. Pass the
    /// **epoch-boundary** time so every SPO derives the same roster.
    #[must_use]
    pub fn active_bans(&self, now_ms: i64) -> BTreeSet<Vec<u8>> {
        self.nodes
            .iter()
            .filter(|(_, e)| e.data.active_at(now_ms))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The full element of a banned pool — its data and the bare pool_id of the
    /// next node in chain order (`link`). A reban (in-place update) keeps the
    /// same asset name + link, so it needs both. `None` if not banned.
    #[must_use]
    pub fn node(&self, pool_id: &[u8]) -> Option<(&BanNodeData, Option<&[u8]>)> {
        self.nodes
            .get(pool_id)
            .map(|e| (&e.data, e.link.as_deref()))
    }

    /// Plan a FIRST-ban linked-list insert of `pool_id` — the off-chain analog
    /// of `spo_bans.ak`'s `insert_ascending` (and a mirror of
    /// `RegistryList::plan_insert`). Find the predecessor anchor (the greatest
    /// banned pool_id `< pool_id`, or the root when none sorts below), relink it
    /// to the new node, and give the new node the anchor's old link. `node_data`
    /// is the [`BanNodeData::first_ban`] output. Errors if `pool_id` is already
    /// banned — that path is a reban (in-place update), not an insert.
    pub fn plan_insert(
        &self,
        pool_id: &[u8],
        node_data: BanNodeData,
    ) -> Result<BanInsert, BanListError> {
        // A ban node key is an accused pool_id; spo_bans.ak `is_pool_id` requires
        // EXACTLY 28 bytes (blake2b_224). Be as strict as the validator so a
        // mis-sized id is rejected here, not after fees/effort on-chain. (The
        // reader stays lenient — it must parse whatever is already on-chain — but
        // a first-ban plan is for a real, freshly-accused pool.)
        if pool_id.len() != POOL_ID_LEN {
            return Err(BanListError::BadNodeKey(pool_id.to_vec()));
        }
        if self.nodes.contains_key(pool_id) {
            return Err(BanListError::AlreadyBanned(pool_id.to_vec()));
        }
        // Predecessor anchor: greatest key < pool_id, else the root.
        let (anchor_key, anchor_data, anchor_link) = match self
            .nodes
            .range::<[u8], _>((
                std::ops::Bound::Unbounded,
                std::ops::Bound::Excluded(pool_id),
            ))
            .next_back()
        {
            Some((key, entry)) => (
                Some(key.clone()),
                BanElementData::Node(entry.data.clone()),
                entry.link.clone(),
            ),
            None => (None, BanElementData::Root, self.root_link.clone()),
        };
        // In a chain-checked list the anchor's successor sorts above the new key.
        debug_assert!(anchor_link.as_deref().is_none_or(|l| l > pool_id));
        let anchor_asset_name = match &anchor_key {
            Some(key) => [BAN_NODE_KEY_PREFIX, key].concat(),
            None => BAN_ROOT_KEY.to_vec(),
        };
        Ok(BanInsert {
            anchor_asset_name,
            continued_anchor: BanElement {
                data: anchor_data,
                link: Some(pool_id.to_vec()),
            },
            new_node_asset_name: [BAN_NODE_KEY_PREFIX, pool_id].concat(),
            new_node: BanElement {
                data: BanElementData::Node(node_data),
                link: anchor_link,
            },
        })
    }
}

/// A planned first-ban linked-list insert: which anchor element UTxO to spend,
/// the continued-anchor + new-node datums, and the new node's NFT asset name.
/// (The ban analog of `register_spo`'s `RegistryInsert`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanInsert {
    /// Asset name of the anchor element to spend (`"ban-root"` or
    /// `"ban/" || predecessor_pool_id`).
    pub anchor_asset_name: Vec<u8>,
    /// Continued anchor: data unchanged, `link` → the new pool_id.
    pub continued_anchor: BanElement,
    /// New node NFT asset name (`"ban/" || pool_id`).
    pub new_node_asset_name: Vec<u8>,
    /// New ban node: `Node(node_data)`, `link` = the anchor's old link.
    pub new_node: BanElement,
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
/// is parameterized by the registry policy id), the authorized fault-verifier
/// policy set + ban-schedule params ([`BanPolicyParams`]), and the ban list's
/// own one-shot bootstrap outref.
#[derive(Debug, Clone)]
pub struct BanListSource {
    pub ban_address: String,
    pub ban_policy_hex: String,
}

/// The `spo_bans` deployment parameters baked into the ban policy id (and which
/// an ApplyBan tx must reproduce in the `BanNodeData` it emits and its validity
/// interval). Sourced from `[cardano]` config — they must match the values the
/// deployed `spo_bans` was parameterized with, or every derived hash is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanPolicyParams {
    /// The authorized fault-verifier policies, in deployment order. The
    /// contract's `ban_config_ok` requires exactly 3 distinct ids.
    pub fault_proof_policies: Vec<[u8; 28]>,
    pub base_ban_duration_ms: i64,
    pub max_faults_before_permanent: i64,
    pub max_validity_window_ms: i64,
}

impl BanPolicyParams {
    /// Parse from `[cardano]` config. Every field is required — the values are
    /// baked into the ban policy id, so there is no safe default.
    pub fn from_config(cardano: &crate::config::CardanoConfig) -> Result<Self, BanListError> {
        if cardano.fault_proof_policies.len() != 3 {
            return Err(BanListError::Config(format!(
                "cardano.fault_proof_policies must list exactly 3 policy ids (spo_bans \
                 ban_config_ok requires 3 distinct fault verifiers); got {}",
                cardano.fault_proof_policies.len()
            )));
        }
        let fault_proof_policies = cardano
            .fault_proof_policies
            .iter()
            .map(|h| {
                hex::decode(h)
                    .ok()
                    .and_then(|v| <[u8; 28]>::try_from(v).ok())
                    .ok_or_else(|| {
                        BanListError::Config(format!(
                            "cardano.fault_proof_policies: {h} is not a 28-byte hex policy id"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        // ban_config_ok requires the 3 policies be DISTINCT; a duplicate derives
        // a policy id no real deployment has → wrong ban address → silently empty
        // ban list (banned SPOs slip into the roster). Distinctness always holds
        // on a valid deployment, so reject it here as a config typo.
        if fault_proof_policies.iter().collect::<BTreeSet<_>>().len() != fault_proof_policies.len()
        {
            return Err(BanListError::Config(
                "cardano.fault_proof_policies has a duplicate entry — spo_bans \
                 ban_config_ok requires 3 distinct fault verifiers"
                    .into(),
            ));
        }
        let req = |v: Option<i64>, name: &str| {
            v.ok_or_else(|| {
                BanListError::Config(format!(
                    "cardano.{name} is required alongside cardano.ban_bootstrap"
                ))
            })
        };
        let base_ban_duration_ms = req(cardano.base_ban_duration_ms, "base_ban_duration_ms")?;
        let max_faults_before_permanent = req(
            cardano.max_faults_before_permanent,
            "max_faults_before_permanent",
        )?;
        let max_validity_window_ms = req(cardano.max_validity_window_ms, "max_validity_window_ms")?;
        // Match ban_config_ok's bounds — the params are baked into the policy id,
        // so an out-of-range value silently derives the wrong ban address.
        if base_ban_duration_ms <= 0 {
            return Err(BanListError::Config(
                "cardano.base_ban_duration_ms must be > 0".into(),
            ));
        }
        if max_faults_before_permanent <= 0 {
            return Err(BanListError::Config(
                "cardano.max_faults_before_permanent must be > 0".into(),
            ));
        }
        if max_validity_window_ms < 0 {
            return Err(BanListError::Config(
                "cardano.max_validity_window_ms must be >= 0".into(),
            ));
        }
        Ok(Self {
            fault_proof_policies,
            base_ban_duration_ms,
            max_faults_before_permanent,
            max_validity_window_ms,
        })
    }
}

impl BanListSource {
    /// Parameterize `spo_bans` from the blueprint and derive its address. The
    /// ban policy id is the 7-param `spo_bans` hash, so `params` must carry the
    /// exact deployment values (see [`BanPolicyParams`]).
    pub fn from_blueprint(
        blueprint_path: &str,
        registry_bootstrap: &str,
        ban_bootstrap: &str,
        params: &BanPolicyParams,
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
        // Guard the most dangerous misconfig: heimdall's own fault_verifier (the
        // policy minting the FaultProofs heimdall publishes) MUST be one of the
        // authorized 3, or those proofs could never be applied — and a wrong set
        // silently derives the wrong ban address (→ an empty ban list → banned
        // SPOs slipping into the roster).
        let fault_verifier =
            blueprint::validator_hash(&blueprint_json, blueprint::FAULT_VERIFIER_TITLE)
                .map_err(|e| err("fault_verifier", e))?;
        if !params.fault_proof_policies.contains(&fault_verifier) {
            return Err(BanListError::Config(format!(
                "cardano.fault_proof_policies does not include the blueprint's fault_verifier \
                 policy {} — heimdall's own FaultProofs could never be applied",
                hex::encode(fault_verifier)
            )));
        }
        let bans = blueprint::spo_bans_script(
            &blueprint_json,
            &registry.hash,
            &params.fault_proof_policies,
            params.base_ban_duration_ms,
            params.max_faults_before_permanent,
            params.max_validity_window_ms,
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
    /// registry fields the ban policy is parameterized by, plus the
    /// fault-verifier policy set + ban-schedule params ([`BanPolicyParams`]).
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
        let params = BanPolicyParams::from_config(cardano)?;
        let mainnet = cardano
            .blockfrost_project_id
            .as_deref()
            .is_some_and(|p| p.starts_with("mainnet"));
        Self::from_blueprint(
            blueprint_path,
            registry_bootstrap,
            ban_bootstrap,
            &params,
            mainnet,
        )
        .map(Some)
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
            ban_until_time: until,
            permanent: false,
            // Satisfy the on-chain invariant len(evidence_hashes) == ban_counter.
            evidence_hashes: (0..counter.max(0)).map(|i| vec![i as u8; 32]).collect(),
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
        // Node{counter:1, until:10, permanent:false=Constr(0,[]),
        // evidence:[0u8;32]} link→"x": ban_counter and evidence_hashes length
        // match (invariant), bool as Constr(0,[]), list as Indef array.
        let node = BanElement {
            data: BanElementData::Node(node_data(1, 10)),
            link: Some(b"x".to_vec()),
        };
        assert_eq!(
            hex::encode(node.to_cbor()),
            "d8799fd87a9fd8799f010ad879809f58200000000000000000000000000000000000000000000000000000000000000000ffffffd8799f4178ffff"
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
        // BanNodeData must have 4 fields
        let bad = constr(
            0,
            vec![constr(1, vec![constr(0, vec![int(1)])]), none_link.clone()],
        );
        assert!(matches!(
            BanElement::from_plutus_data(&bad),
            Err(BanListError::FieldCount {
                expected: 4,
                got: 1
            })
        ));
        // BanNodeData field 0 (ban_counter) must be an Int
        let bad = constr(
            0,
            vec![
                constr(
                    1,
                    vec![constr(
                        0,
                        vec![
                            bytes(b"x"),
                            int(1),
                            plutus::bool_data(false),
                            plutus::array(vec![]),
                        ],
                    )],
                ),
                none_link,
            ],
        );
        assert!(matches!(
            BanElement::from_plutus_data(&bad),
            Err(BanListError::BadField(plutus::PlutusError::NotInt(0)))
        ));
    }

    #[test]
    fn ban_transitions_mirror_the_contract() {
        // first ban: counter 1, until = start + base, permanent iff 1 >= max.
        let base = 1000;
        let first = BanNodeData::first_ban(vec![0xAB; 32], 5000, base, 3);
        assert_eq!(first.ban_counter, 1);
        assert_eq!(first.ban_until_time, 5000 + base); // base * 2^0
        assert!(!first.permanent); // 1 >= 3 is false
        assert_eq!(first.evidence_hashes, vec![vec![0xAB; 32]]);
        // max_faults_before_permanent = 1 → first ban is permanent.
        assert!(BanNodeData::first_ban(vec![0u8; 32], 0, base, 1).permanent);

        // reban: counter+1, until = max(old_until, start) + base*2^(counter-1),
        // permanent = (new_counter >= max) [validator OVERRIDES the helper's
        // throwaway false], new evidence prepended. max=3, counter=2 → not yet.
        let second = first.repeated_ban(vec![0xCD; 32], 4000, base, 3);
        assert_eq!(second.ban_counter, 2);
        // max(6000, 4000) + base*2^1 = 6000 + 2000.
        assert_eq!(second.ban_until_time, 6000 + 2 * base);
        assert!(!second.permanent);
        assert_eq!(second.evidence_hashes, vec![vec![0xCD; 32], vec![0xAB; 32]]);
        // len(evidence_hashes) == ban_counter invariant (spo-bans.ak:31).
        assert_eq!(second.evidence_hashes.len() as i64, second.ban_counter);

        // A reban that REACHES max_faults_before_permanent escalates to permanent.
        let crosses = first.repeated_ban(vec![0xEE; 32], 4000, base, 2);
        assert_eq!(crosses.ban_counter, 2);
        assert!(crosses.permanent); // 2 >= 2

        assert_eq!(ban_duration(1000, 1), 1000);
        assert_eq!(ban_duration(1000, 4), 8000); // 1000 * 2^3
    }

    #[test]
    fn fault_token_name_is_blake2b_of_pool_and_evidence() {
        let pool = [0x11u8; 28];
        let evidence = [0x22u8; 32];
        let mut concat = pool.to_vec();
        concat.extend_from_slice(&evidence);
        assert_eq!(
            fault_token_name(&pool, &evidence),
            crate::cardano::hash::blake2b_256(&concat)
        );
        // 32-byte asset name, distinct per (pool, evidence).
        assert_ne!(
            fault_token_name(&pool, &evidence),
            fault_token_name(&pool, &[0x33u8; 32])
        );
    }

    #[test]
    fn active_at_uses_permanent_and_time() {
        let temp = node_data(1, 1000); // permanent=false, until=1000
        assert!(temp.active_at(999));
        assert!(!temp.active_at(1000)); // strictly greater
        let perm = BanNodeData {
            permanent: true,
            ..node_data(2, 0)
        };
        assert!(perm.active_at(i64::MAX)); // permanent never expires
    }

    #[test]
    fn reconstructs_list_and_reads_bans() {
        let list = two_node_list();
        assert_eq!(list.len(), 2);
        let keys: Vec<&[u8]> = list.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, [b"aa-pool", b"bb-pool"]);
        assert_eq!(list.get(b"bb-pool"), Some(&node_data(2, 20)));

        // active iff permanent || ban_until_time > now_ms
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

    #[test]
    fn node_accessor_returns_data_and_link() {
        // The reader tolerates short keys; node() exposes (data, link) for reban.
        let list = two_node_list();
        assert_eq!(
            list.node(b"aa-pool"),
            Some((&node_data(1, 10), Some(b"bb-pool".as_slice())))
        );
        assert_eq!(list.node(b"bb-pool"), Some((&node_data(2, 20), None)));
        assert!(list.node(b"zz").is_none());
    }

    #[test]
    fn plan_insert_links_correctly() {
        // plan_insert requires EXACTLY-28-byte pool ids (is_pool_id), so build a
        // 28-byte-keyed list: root -> lo -> hi.
        let lo = [0x10u8; 28];
        let hi = [0xf0u8; 28];
        let list = BanList::from_elements([
            root_elem(Some(&lo)),
            node_elem(&lo, node_data(1, 10), Some(&hi)),
            node_elem(&hi, node_data(2, 20), None),
        ])
        .unwrap();

        // Insert mid (lo < mid < hi): anchor = lo, mid takes lo's old link (hi).
        let mid = [0x80u8; 28];
        let data = node_data(1, 100);
        let plan = list.plan_insert(&mid, data.clone()).unwrap();
        assert_eq!(plan.anchor_asset_name, [BAN_NODE_KEY_PREFIX, &lo].concat());
        assert_eq!(
            plan.continued_anchor.data,
            BanElementData::Node(node_data(1, 10))
        );
        assert_eq!(plan.continued_anchor.link.as_deref(), Some(mid.as_slice()));
        assert_eq!(
            plan.new_node_asset_name,
            [BAN_NODE_KEY_PREFIX, &mid].concat()
        );
        assert_eq!(plan.new_node.data, BanElementData::Node(data));
        assert_eq!(plan.new_node.link.as_deref(), Some(hi.as_slice()));

        // Insert below lo: anchor = root, new node takes root's old link (lo).
        let below = [0x05u8; 28];
        let plan0 = list.plan_insert(&below, node_data(1, 5)).unwrap();
        assert_eq!(plan0.anchor_asset_name, BAN_ROOT_KEY);
        assert_eq!(plan0.continued_anchor.data, BanElementData::Root);
        assert_eq!(
            plan0.continued_anchor.link.as_deref(),
            Some(below.as_slice())
        );
        assert_eq!(plan0.new_node.link.as_deref(), Some(lo.as_slice()));

        // Already banned → AlreadyBanned (that path is a reban, not an insert).
        assert!(matches!(
            list.plan_insert(&lo, node_data(1, 5)),
            Err(BanListError::AlreadyBanned(_))
        ));
        // Not exactly 28 bytes → BadNodeKey (matches is_pool_id; was the gap).
        for bad_len in [27usize, 29] {
            assert!(
                matches!(
                    list.plan_insert(&vec![1u8; bad_len], node_data(1, 5)),
                    Err(BanListError::BadNodeKey(_))
                ),
                "len {bad_len} must be rejected"
            );
        }
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

    #[test]
    fn ban_policy_params_from_config_validates() {
        let mut c = crate::config::CardanoConfig::default();
        // no fault policies → not 3
        assert!(matches!(
            BanPolicyParams::from_config(&c),
            Err(BanListError::Config(_))
        ));
        // exactly 3 28-byte policies but ban-schedule params missing
        c.fault_proof_policies = vec!["11".repeat(28), "22".repeat(28), "33".repeat(28)];
        assert!(matches!(
            BanPolicyParams::from_config(&c),
            Err(BanListError::Config(_))
        ));
        c.base_ban_duration_ms = Some(86_400_000);
        c.max_faults_before_permanent = Some(3);
        c.max_validity_window_ms = Some(600_000);
        let p = BanPolicyParams::from_config(&c).unwrap();
        assert_eq!(
            p.fault_proof_policies,
            vec![[0x11; 28], [0x22; 28], [0x33; 28]]
        );
        assert_eq!(p.base_ban_duration_ms, 86_400_000);
        assert_eq!(p.max_faults_before_permanent, 3);
        assert_eq!(p.max_validity_window_ms, 600_000);
        // wrong count (2) → error
        c.fault_proof_policies = vec!["11".repeat(28), "22".repeat(28)];
        assert!(matches!(
            BanPolicyParams::from_config(&c),
            Err(BanListError::Config(_))
        ));
        // 3 entries but one is not 28 bytes (27) → error
        c.fault_proof_policies = vec!["11".repeat(28), "22".repeat(28), "33".repeat(27)];
        assert!(matches!(
            BanPolicyParams::from_config(&c),
            Err(BanListError::Config(_))
        ));
        // 3 entries but a DUPLICATE (count is 3, but not distinct) → error.
        c.fault_proof_policies = vec!["11".repeat(28), "22".repeat(28), "11".repeat(28)];
        assert!(matches!(
            BanPolicyParams::from_config(&c),
            Err(BanListError::Config(_))
        ));
        // Out-of-range ban-schedule params (contract bounds) → error.
        c.fault_proof_policies = vec!["11".repeat(28), "22".repeat(28), "33".repeat(28)];
        c.base_ban_duration_ms = Some(0); // must be > 0
        assert!(matches!(
            BanPolicyParams::from_config(&c),
            Err(BanListError::Config(_))
        ));
        c.base_ban_duration_ms = Some(86_400_000);
        c.max_faults_before_permanent = Some(0); // must be > 0
        assert!(matches!(
            BanPolicyParams::from_config(&c),
            Err(BanListError::Config(_))
        ));
        c.max_faults_before_permanent = Some(3);
        c.max_validity_window_ms = Some(-1); // must be >= 0
        assert!(matches!(
            BanPolicyParams::from_config(&c),
            Err(BanListError::Config(_))
        ));
    }
}
