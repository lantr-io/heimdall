//! Merkle Patricia Forestry (MPF) — Rust port of `aiken-lang/merkle-patricia-forestry` v2.x.
//!
//! Context: `treasury.ak` stores `bifrost_identity_root` (and a completed-peg-ins root) as
//! MPF roots. `register_spo` must supply a `bifrost_identity_absence_proof` (a non-membership
//! / exclusion proof) and the post-insert root; fBTC minting needs inclusion/non-inclusion
//! proofs against the completed-peg-ins trie. No Aiken-MPF-compatible Rust crate exists
//! (rs-merkle / paritytech-trie / patricia-trie use different hashing + proof formats), so we
//! port it. See internal-docs key-publication-todo.md R1a (WI-001).
//!
//! ## Phase 1 (this module): verifier + primitives
//!
//! A byte-for-byte port of the Aiken *on-chain* library: the hashing primitives
//! (`combine = blake2b_256(l ‖ r)`, the radix-16 sparse-merkle reconstruction) and the
//! `including` / `excluding` proof walk over the `Branch | Fork | Leaf` proof format. This
//! computes/verifies roots from a given proof and is validated below against the library's
//! own block-845602 test vector, so our hashing matches the on-chain validator exactly.
//!
//! ## Phase 2 (TODO, WI-001): off-chain trie + proof generation
//!
//! The part `register_spo` actually calls — maintain the full key/value trie and *generate*
//! inclusion/exclusion proofs (`Branch`/`Fork`/`Leaf` steps + neighbors). Not in the Aiken
//! on-chain lib; reference the `aiken-lang/merkle-patricia-forestry` `off-chain` (TS) package
//! or the scalus `AikenMpfData` port.

use std::cell::OnceCell;
use std::sync::LazyLock;

use pallas_crypto::hash::Hasher;

/// A 32-byte blake2b-256 digest.
pub type Hash = [u8; 32];

/// By convention, the hash of an empty trie is 32 zero bytes.
pub const NULL_HASH: Hash = [0u8; 32];

/// The on-chain digest size (blake2b-256).
const DIGEST: usize = 32;

// ---------------------------------------------------------------------------
// hashing (helpers.ak)
// ---------------------------------------------------------------------------

/// blake2b-256 of `data`.
#[must_use]
pub fn blake2b_256(data: &[u8]) -> Hash {
    (*Hasher::<256>::hash(data)).into()
}

/// `combine(l, r) = blake2b_256(l ‖ r)`.
#[must_use]
pub fn combine(left: &[u8], right: &[u8]) -> Hash {
    // Feed both slices incrementally — avoids allocating a temporary concat Vec on
    // this hot path (every merkle/sparse-merkle step calls combine several times).
    let mut hasher = Hasher::<256>::new();
    hasher.input(left);
    hasher.input(right);
    (*hasher.finalize()).into()
}

// Null sub-trees (merkling.ak `null_hash_2/4/8`) — fixed constants, computed once on
// first use rather than re-hashed on every Fork (sparse-merkle) proof step.
static NULL_HASH_2: LazyLock<Hash> = LazyLock::new(|| combine(&NULL_HASH, &NULL_HASH));
static NULL_HASH_4: LazyLock<Hash> = LazyLock::new(|| combine(&*NULL_HASH_2, &*NULL_HASH_2));
static NULL_HASH_8: LazyLock<Hash> = LazyLock::new(|| combine(&*NULL_HASH_4, &*NULL_HASH_4));

/// The `index`-th nibble of `path` (big-endian: even index = high nibble).
fn nibble(path: &[u8], index: usize) -> u8 {
    if index % 2 == 0 {
        path[index / 2] >> 4
    } else {
        path[index / 2] & 0x0f
    }
}

/// The nibbles of `path` over `[start, end)`, one nibble value per byte.
fn nibbles(path: &[u8], start: usize, end: usize) -> Vec<u8> {
    (start..end).map(|i| nibble(path, i)).collect()
}

/// The leaf-suffix encoding of `path` from `cursor` (helpers.ak `suffix`).
fn suffix(path: &[u8], cursor: usize) -> Vec<u8> {
    if cursor % 2 == 0 {
        let rest = &path[cursor / 2..];
        let mut v = Vec::with_capacity(1 + rest.len());
        v.push(0xff);
        v.extend_from_slice(rest);
        v
    } else {
        let rest = &path[(cursor + 1) / 2..];
        let mut v = Vec::with_capacity(2 + rest.len());
        v.push(0x00);
        v.push(nibble(path, cursor));
        v.extend_from_slice(rest);
        v
    }
}

// ---------------------------------------------------------------------------
// merkle_xx (merkling.ak) — full sparse-merkle reconstruction of one branch
// ---------------------------------------------------------------------------

fn merkle_16(branch: i64, root: &[u8], n8: &[u8], n4: &[u8], n2: &[u8], n1: &[u8]) -> Hash {
    if branch <= 7 {
        combine(&merkle_8(branch, root, n4, n2, n1), n8)
    } else {
        combine(n8, &merkle_8(branch - 8, root, n4, n2, n1))
    }
}

fn merkle_8(branch: i64, root: &[u8], n4: &[u8], n2: &[u8], n1: &[u8]) -> Hash {
    if branch <= 3 {
        combine(&merkle_4(branch, root, n2, n1), n4)
    } else {
        combine(n4, &merkle_4(branch - 4, root, n2, n1))
    }
}

fn merkle_4(branch: i64, root: &[u8], n2: &[u8], n1: &[u8]) -> Hash {
    if branch <= 1 {
        let inner = if branch == 0 {
            combine(root, n1)
        } else {
            combine(n1, root)
        };
        combine(&inner, n2)
    } else {
        let inner = if branch == 2 {
            combine(root, n1)
        } else {
            combine(n1, root)
        };
        combine(n2, &inner)
    }
}

// ---------------------------------------------------------------------------
// sparse_merkle_xx (merkling.ak) — two-leaf (me + neighbor) reconstruction
// ---------------------------------------------------------------------------

fn sparse_merkle_16(me: i64, me_hash: &[u8], neighbor: i64, neighbor_hash: &[u8]) -> Hash {
    let n8 = *NULL_HASH_8;
    let n4 = *NULL_HASH_4;
    let n2 = *NULL_HASH_2;
    if me <= 7 {
        if neighbor <= 7 {
            combine(&sparse_merkle_8(me, me_hash, neighbor, neighbor_hash), &n8)
        } else {
            combine(
                &merkle_8(me, me_hash, &n4, &n2, &NULL_HASH),
                &merkle_8(neighbor - 8, neighbor_hash, &n4, &n2, &NULL_HASH),
            )
        }
    } else if neighbor >= 8 {
        combine(
            &n8,
            &sparse_merkle_8(me - 8, me_hash, neighbor - 8, neighbor_hash),
        )
    } else {
        combine(
            &merkle_8(neighbor, neighbor_hash, &n4, &n2, &NULL_HASH),
            &merkle_8(me - 8, me_hash, &n4, &n2, &NULL_HASH),
        )
    }
}

fn sparse_merkle_8(me: i64, me_hash: &[u8], neighbor: i64, neighbor_hash: &[u8]) -> Hash {
    let n4 = *NULL_HASH_4;
    let n2 = *NULL_HASH_2;
    if me <= 3 {
        if neighbor <= 3 {
            combine(&sparse_merkle_4(me, me_hash, neighbor, neighbor_hash), &n4)
        } else {
            combine(
                &merkle_4(me, me_hash, &n2, &NULL_HASH),
                &merkle_4(neighbor - 4, neighbor_hash, &n2, &NULL_HASH),
            )
        }
    } else if neighbor >= 4 {
        combine(
            &n4,
            &sparse_merkle_4(me - 4, me_hash, neighbor - 4, neighbor_hash),
        )
    } else {
        combine(
            &merkle_4(neighbor, neighbor_hash, &n2, &NULL_HASH),
            &merkle_4(me - 4, me_hash, &n2, &NULL_HASH),
        )
    }
}

fn sparse_merkle_4(me: i64, me_hash: &[u8], neighbor: i64, neighbor_hash: &[u8]) -> Hash {
    let combine_me = |x: &[u8]| {
        if me % 2 == 0 {
            combine(me_hash, x)
        } else {
            combine(x, me_hash)
        }
    };
    let combine_neighbor = |x: &[u8]| {
        if neighbor % 2 == 0 {
            combine(neighbor_hash, x)
        } else {
            combine(x, neighbor_hash)
        }
    };
    let n2 = *NULL_HASH_2;
    if me <= 1 {
        if neighbor <= 1 {
            combine(&combine_me(neighbor_hash), &n2)
        } else {
            combine(&combine_me(&NULL_HASH), &combine_neighbor(&NULL_HASH))
        }
    } else if neighbor >= 2 {
        combine(&n2, &combine_me(neighbor_hash))
    } else {
        combine(&combine_neighbor(&NULL_HASH), &combine_me(&NULL_HASH))
    }
}

// ---------------------------------------------------------------------------
// Proof format (merkle-patricia-forestry.ak)
// ---------------------------------------------------------------------------

/// A neighbor node used in a Fork/Leaf proof step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub nibble: u8,
    pub prefix: Vec<u8>,
    pub root: Vec<u8>,
}

/// A single proof step. `skip` is the length of the common prefix at that level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofStep {
    /// `neighbors` is 128 bytes = 4 × 32 (neighbor_8 ‖ neighbor_4 ‖ neighbor_2 ‖ neighbor_1).
    Branch { skip: usize, neighbors: Vec<u8> },
    Fork { skip: usize, neighbor: Neighbor },
    /// `key`/`value` are the neighbor leaf's 32-byte key-hash (path) and value-hash.
    Leaf {
        skip: usize,
        key: Vec<u8>,
        value: Vec<u8>,
    },
}

/// A proof is processed left-to-right along the path to the proven element.
pub type Proof = Vec<ProofStep>;

// ---------------------------------------------------------------------------
// including / excluding
// ---------------------------------------------------------------------------

impl ProofStep {
    fn skip(&self) -> usize {
        match self {
            ProofStep::Branch { skip, .. }
            | ProofStep::Fork { skip, .. }
            | ProofStep::Leaf { skip, .. } => *skip,
        }
    }
}

/// Validate an untrusted `proof` against `path` (the 32-byte key hash) so the
/// subsequent walk cannot panic: bounds-check every cursor and field-length
/// access up front and reject anything malformed. After this returns `Ok`,
/// `do_including` / `do_excluding` index only in-range bytes.
fn validate_proof(path: &[u8], proof: &[ProofStep]) -> Result<(), MpfError> {
    let n = path.len() * 2; // nibbles in the path (64 for a 32-byte key hash)
    if proof.len() > n {
        return Err(MpfError::ProofTooDeep);
    }
    let mut cursor = 0usize;
    for step in proof {
        let next_cursor = cursor + step.skip();
        if next_cursor >= n {
            return Err(MpfError::CursorOutOfRange);
        }
        let branch = nibble(path, next_cursor);
        match step {
            ProofStep::Branch { neighbors, .. } => {
                if neighbors.len() != 4 * DIGEST {
                    return Err(MpfError::BadNeighborsLen);
                }
            }
            ProofStep::Fork { neighbor, .. } => {
                if neighbor.nibble > 15 {
                    return Err(MpfError::BadNibble);
                }
                if neighbor.root.len() != DIGEST {
                    return Err(MpfError::BadHashLen);
                }
                if branch == neighbor.nibble {
                    return Err(MpfError::InvalidFork);
                }
            }
            ProofStep::Leaf { key, value, .. } => {
                if key.len() != DIGEST || value.len() != DIGEST {
                    return Err(MpfError::BadHashLen);
                }
                if branch == nibble(key, next_cursor) {
                    return Err(MpfError::InvalidFork);
                }
            }
        }
        cursor = next_cursor + 1;
    }
    if cursor > n {
        return Err(MpfError::CursorOutOfRange);
    }
    Ok(())
}

/// Root obtained by walking `proof` with the element `(key, value)` present —
/// equals the trie root iff the element is in the trie with that value.
/// Returns `Err` on a malformed proof rather than panicking.
pub fn including(key: &[u8], value: &[u8], proof: &Proof) -> Result<Hash, MpfError> {
    let path = blake2b_256(key);
    validate_proof(&path, proof)?;
    Ok(do_including(&path, blake2b_256(value), 0, proof))
}

/// Root obtained by walking `proof` without the element — equals the trie root
/// iff `key` is absent (a non-membership / exclusion proof).
pub fn excluding(key: &[u8], proof: &Proof) -> Result<Hash, MpfError> {
    let path = blake2b_256(key);
    validate_proof(&path, proof)?;
    Ok(do_excluding(&path, 0, proof))
}

/// Verify `key → value` is included in the trie with root `expected_root`.
/// Removes the footgun of forgetting the root comparison — the treasury holds
/// two MPF roots (bifrost-identity and completed-peg-ins).
pub fn verify_inclusion(
    key: &[u8],
    value: &[u8],
    proof: &Proof,
    expected_root: &Hash,
) -> Result<(), MpfError> {
    if &including(key, value, proof)? == expected_root {
        Ok(())
    } else {
        Err(MpfError::RootMismatch)
    }
}

/// Verify `key` is absent from the trie with root `expected_root`.
pub fn verify_exclusion(key: &[u8], proof: &Proof, expected_root: &Hash) -> Result<(), MpfError> {
    if &excluding(key, proof)? == expected_root {
        Ok(())
    } else {
        Err(MpfError::RootMismatch)
    }
}

fn do_including(path: &[u8], value: Hash, cursor: usize, proof: &[ProofStep]) -> Hash {
    match proof.split_first() {
        None => combine(&suffix(path, cursor), &value),
        Some((ProofStep::Branch { skip, neighbors }, steps)) => {
            let next_cursor = cursor + skip;
            let root = do_including(path, value, next_cursor + 1, steps);
            do_branch(path, cursor, next_cursor, &root, neighbors)
        }
        Some((ProofStep::Fork { skip, neighbor }, steps)) => {
            let next_cursor = cursor + skip;
            let root = do_including(path, value, next_cursor + 1, steps);
            do_fork(path, cursor, next_cursor, &root, neighbor)
        }
        Some((
            ProofStep::Leaf {
                skip,
                key,
                value: neighbor_value,
            },
            steps,
        )) => {
            let next_cursor = cursor + skip;
            let root = do_including(path, value, next_cursor + 1, steps);
            let neighbor = Neighbor {
                prefix: suffix(key, next_cursor + 1),
                nibble: nibble(key, next_cursor),
                root: neighbor_value.clone(),
            };
            do_fork(path, cursor, next_cursor, &root, &neighbor)
        }
    }
}

fn do_excluding(path: &[u8], cursor: usize, proof: &[ProofStep]) -> Hash {
    match proof.split_first() {
        None => NULL_HASH,
        Some((ProofStep::Branch { skip, neighbors }, steps)) => {
            let next_cursor = cursor + skip;
            let root = do_excluding(path, next_cursor + 1, steps);
            do_branch(path, cursor, next_cursor, &root, neighbors)
        }
        // Terminal Fork: reconstruct the original neighbor node.
        Some((ProofStep::Fork { skip, neighbor }, steps)) if steps.is_empty() => {
            let mut neighbor_prefix = Vec::with_capacity(1 + neighbor.prefix.len());
            neighbor_prefix.push(neighbor.nibble);
            neighbor_prefix.extend_from_slice(&neighbor.prefix);
            let prefix = if *skip == 0 {
                neighbor_prefix
            } else {
                let mut p = nibbles(path, cursor, cursor + skip);
                p.extend_from_slice(&neighbor_prefix);
                p
            };
            combine(&prefix, &neighbor.root)
        }
        Some((ProofStep::Fork { skip, neighbor }, steps)) => {
            let next_cursor = cursor + skip;
            let root = do_excluding(path, next_cursor + 1, steps);
            do_fork(path, cursor, next_cursor, &root, neighbor)
        }
        // Terminal Leaf: the neighbor leaf itself becomes the root.
        Some((ProofStep::Leaf { key, value, .. }, steps)) if steps.is_empty() => {
            combine(&suffix(key, cursor), value)
        }
        Some((ProofStep::Leaf { skip, key, value }, steps)) => {
            let next_cursor = cursor + skip;
            let root = do_excluding(path, next_cursor + 1, steps);
            let neighbor = Neighbor {
                prefix: suffix(key, next_cursor + 1),
                nibble: nibble(key, next_cursor),
                root: value.clone(),
            };
            do_fork(path, cursor, next_cursor, &root, &neighbor)
        }
    }
}

fn do_branch(path: &[u8], cursor: usize, next_cursor: usize, root: &[u8], neighbors: &[u8]) -> Hash {
    let branch = nibble(path, next_cursor) as i64;
    let prefix = nibbles(path, cursor, next_cursor);
    let n8 = &neighbors[0..DIGEST];
    let n4 = &neighbors[DIGEST..2 * DIGEST];
    let n2 = &neighbors[2 * DIGEST..3 * DIGEST];
    let n1 = &neighbors[3 * DIGEST..4 * DIGEST];
    combine(&prefix, &merkle_16(branch, root, n8, n4, n2, n1))
}

fn do_fork(
    path: &[u8],
    cursor: usize,
    next_cursor: usize,
    root: &[u8],
    neighbor: &Neighbor,
) -> Hash {
    let branch = nibble(path, next_cursor) as i64;
    let prefix = nibbles(path, cursor, next_cursor);
    // Aiken `expect branch != neighbor.nibble`: a Fork must split two *distinct* nibbles.
    // `assert!` (not `debug_assert!`) so the invariant is enforced in release builds too.
    assert!(
        branch != neighbor.nibble as i64,
        "do_fork: branch must differ from neighbor nibble"
    );
    let neighbor_node = combine(&neighbor.prefix, &neighbor.root);
    combine(
        &prefix,
        &sparse_merkle_16(branch, root, neighbor.nibble as i64, &neighbor_node),
    )
}

// ===========================================================================
// Phase 2 — off-chain trie + proof generation
//
// The full key/value store that maintains the trie and *generates* the proofs
// the Phase 1 verifier (and the on-chain Aiken validator) consume. Ported from
// the scalus off-chain `MerklePatriciaForestry` (scalus-core
// crypto/trie/MerklePatriciaForestry{,Base}.scala). register_spo (R1c) calls
// `prove_non_membership` for the `bifrost_identity_absence_proof`.
//
// Validation strategy: the proofs this produces are checked end-to-end against
// the byte-exact Phase 1 verifier (`including`/`excluding`), which is itself
// validated against the Aiken library's vectors — so a self-consistent prover
// here is Aiken-compatible.
//
// NOTE (WI-007 hardening): the verifier (`including`/`excluding`) validates an
// untrusted proof up front (`validate_proof`) and returns `Result` instead of
// panicking; `do_insert` returns `Err(KeyPresent)` on a duplicate key; node
// hashes are memoised (`OnceCell`). Still deferred (WI-007): fewer per-insert
// children clones (`do_insert` deep-clones the children Vec per level — O(N²)
// build, fine for the small rosters register_spo builds; an Rc-shared node
// representation would make it O(N·depth)), `do_delete` (deregister), fixed-size
// proof types, and an iterator `from_pairs`.
// ===========================================================================

/// blake2b-256 of a key/value yields a 32-byte path → 64 nibbles deep.
const PATH_NIBBLES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpfError {
    /// A key is already present (duplicate `insert`, or `prove_non_membership` on a present key).
    KeyPresent,
    /// `prove_membership` on a key absent from the trie.
    KeyAbsent,
    /// Proof has more steps than the 64-nibble path can be deep.
    ProofTooDeep,
    /// A step's `skip` pushes the walk cursor past the 64-nibble path.
    CursorOutOfRange,
    /// A `Branch` step's `neighbors` blob is not exactly 128 bytes (4×32).
    BadNeighborsLen,
    /// A `Fork` neighbor's `nibble` is not a 4-bit value (0..=15).
    BadNibble,
    /// A 32-byte field (`Leaf` key/value, `Fork` root) has the wrong length.
    BadHashLen,
    /// A `Fork`/`Leaf` neighbor shares the path's branch nibble (impossible in a real proof).
    InvalidFork,
    /// A computed root did not equal the expected on-chain root.
    RootMismatch,
}

/// A trie node. Radix-16 Patricia with prefix (`skip`) compression.
///
/// `hash` memoises the node digest (computed once on first access, like the
/// scalus `lazy val hash`) so building/proving never re-hashes whole subtrees.
/// A cloned node carries its cached hash; only nodes rebuilt on the insert path
/// recompute. (`OnceCell` is `!Sync` but `Send`, which is all the single-thread
/// build-then-prove flow needs.)
#[derive(Clone)]
enum Node {
    Empty,
    /// `full_path = blake2b_256(key)`; `skip_start` is the cursor at creation.
    Leaf {
        skip_start: usize,
        full_path: Vec<u8>,
        value: Vec<u8>,
        hash: OnceCell<Hash>,
    },
    /// `rep_path` is any descendant leaf's full path (used to read prefix nibbles).
    Branch {
        skip_start: usize,
        skip_len: usize,
        rep_path: Vec<u8>,
        children: Vec<Node>, // length 16
        size: usize,
        hash: OnceCell<Hash>,
    },
}

fn empty_children() -> Vec<Node> {
    vec![Node::Empty; 16]
}

impl Node {
    fn leaf(skip_start: usize, full_path: Vec<u8>, value: Vec<u8>) -> Node {
        Node::Leaf {
            skip_start,
            full_path,
            value,
            hash: OnceCell::new(),
        }
    }

    fn branch(
        skip_start: usize,
        skip_len: usize,
        rep_path: Vec<u8>,
        children: Vec<Node>,
        size: usize,
    ) -> Node {
        Node::Branch {
            skip_start,
            skip_len,
            rep_path,
            children,
            size,
            hash: OnceCell::new(),
        }
    }

    fn hash(&self) -> Hash {
        match self {
            Node::Empty => NULL_HASH,
            Node::Leaf {
                skip_start,
                full_path,
                value,
                hash,
            } => *hash
                .get_or_init(|| combine(&suffix(full_path, *skip_start), &blake2b_256(value))),
            Node::Branch {
                skip_start,
                skip_len,
                rep_path,
                children,
                hash,
                ..
            } => *hash.get_or_init(|| {
                combine(
                    &nibbles(rep_path, *skip_start, *skip_start + *skip_len),
                    &merkle_root_16(children),
                )
            }),
        }
    }
}

/// Merkle root of 16 child hashes — the binary tree of `combine` that on-chain
/// `merkle_16` reconstructs (16 → 8 → 4 → 2 → 1).
fn merkle_root_16(children: &[Node]) -> Hash {
    debug_assert_eq!(children.len(), 16, "merkle_root_16 expects exactly 16 children");
    let mut level: Vec<Hash> = children.iter().map(Node::hash).collect();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| combine(&p[0], &p[1])).collect();
    }
    level[0]
}

/// The 4 sibling hashes (`neighbor8 ‖ neighbor4 ‖ neighbor2 ‖ neighbor1`, 128
/// bytes) for a Branch proof step, via bit-flip indexing (scalus `merkleProof4`).
fn merkle_proof_4(children: &[Node], branch: usize) -> Vec<u8> {
    let s1 = children[branch ^ 1].hash();

    let p = ((branch >> 1) ^ 1) << 1;
    let s2 = combine(&children[p].hash(), &children[p + 1].hash());

    let q = ((branch >> 2) ^ 1) << 2;
    let s4 = combine(
        &combine(&children[q].hash(), &children[q + 1].hash()),
        &combine(&children[q + 2].hash(), &children[q + 3].hash()),
    );

    let o = ((branch >> 3) ^ 1) << 3;
    let s8 = combine(
        &combine(
            &combine(&children[o].hash(), &children[o + 1].hash()),
            &combine(&children[o + 2].hash(), &children[o + 3].hash()),
        ),
        &combine(
            &combine(&children[o + 4].hash(), &children[o + 5].hash()),
            &combine(&children[o + 6].hash(), &children[o + 7].hash()),
        ),
    );

    let mut out = Vec::with_capacity(4 * DIGEST);
    out.extend_from_slice(&s8);
    out.extend_from_slice(&s4);
    out.extend_from_slice(&s2);
    out.extend_from_slice(&s1);
    out
}

fn common_prefix_len(a: &[u8], b: &[u8], start: usize, end: usize) -> usize {
    let mut i = start;
    while i < end && nibble(a, i) == nibble(b, i) {
        i += 1;
    }
    i - start
}

fn branch_skip_matches_path(rep_path: &[u8], skip_len: usize, path: &[u8], cursor: usize) -> bool {
    (0..skip_len).all(|i| nibble(rep_path, cursor + i) == nibble(path, cursor + i))
}

fn do_insert(node: &Node, path: &[u8], cursor: usize, value: &[u8]) -> Result<Node, MpfError> {
    match node {
        Node::Empty => Ok(Node::leaf(cursor, path.to_vec(), value.to_vec())),

        Node::Leaf {
            full_path: leaf_path,
            value: leaf_value,
            ..
        } => {
            let remaining_len = PATH_NIBBLES - cursor;
            let cp = common_prefix_len(path, leaf_path, cursor, PATH_NIBBLES);
            if cp == remaining_len {
                return Err(MpfError::KeyPresent);
            }

            let new_nibble = nibble(path, cursor + cp) as usize;
            let old_nibble = nibble(leaf_path, cursor + cp) as usize;
            let split_cursor = cursor + cp + 1;

            let mut children = empty_children();
            children[new_nibble] = Node::leaf(split_cursor, path.to_vec(), value.to_vec());
            children[old_nibble] = Node::leaf(split_cursor, leaf_path.clone(), leaf_value.clone());
            Ok(Node::branch(cursor, cp, path.to_vec(), children, 2))
        }

        Node::Branch {
            skip_start,
            skip_len,
            rep_path,
            children,
            size,
            ..
        } => {
            let cp = common_prefix_len(path, rep_path, cursor, cursor + skip_len);
            if cp < *skip_len {
                // Path diverges inside the branch's prefix → split the branch.
                let split_cursor = cursor + cp + 1;
                let new_nibble = nibble(path, cursor + cp) as usize;
                let old_nibble = nibble(rep_path, cursor + cp) as usize;

                let mut new_children = empty_children();
                new_children[new_nibble] = Node::leaf(split_cursor, path.to_vec(), value.to_vec());
                new_children[old_nibble] = Node::branch(
                    skip_start + cp + 1,
                    skip_len - cp - 1,
                    rep_path.clone(),
                    children.clone(),
                    *size,
                );
                Ok(Node::branch(cursor, cp, path.to_vec(), new_children, size + 1))
            } else {
                // Prefix matches → descend into the child.
                let child_nibble = nibble(path, cursor + skip_len) as usize;
                let child_cursor = cursor + skip_len + 1;
                let new_child = do_insert(&children[child_nibble], path, child_cursor, value)?;
                let mut new_children = children.clone();
                new_children[child_nibble] = new_child;
                Ok(Node::branch(
                    *skip_start,
                    *skip_len,
                    rep_path.clone(),
                    new_children,
                    size + 1,
                ))
            }
        }
    }
}

fn do_get(node: &Node, path: &[u8], cursor: usize) -> Option<Vec<u8>> {
    match node {
        Node::Empty => None,
        Node::Leaf {
            full_path, value, ..
        } => (full_path.as_slice() == path).then(|| value.clone()),
        Node::Branch {
            skip_len,
            rep_path,
            children,
            ..
        } => {
            if !branch_skip_matches_path(rep_path, *skip_len, path, cursor) {
                None
            } else {
                let child_nibble = nibble(path, cursor + skip_len) as usize;
                do_get(&children[child_nibble], path, cursor + skip_len + 1)
            }
        }
    }
}

/// Walk root→leaf collecting one proof step per branch (root-first order).
/// Returns `(found, steps)` where `found` is whether the leaf matches `path`.
fn do_prove(node: &Node, path: &[u8], cursor: usize) -> (bool, Vec<ProofStep>) {
    match node {
        Node::Empty => (false, Vec::new()),
        Node::Leaf { full_path, .. } => (full_path.as_slice() == path, Vec::new()),
        Node::Branch {
            skip_len, children, ..
        } => {
            let child_nibble = nibble(path, cursor + skip_len) as usize;
            let child = &children[child_nibble];
            let (found, child_steps) = match child {
                Node::Empty => (false, Vec::new()),
                _ => do_prove(child, path, cursor + skip_len + 1),
            };
            let step = make_proof_step(children, child_nibble, *skip_len);
            let mut steps = Vec::with_capacity(child_steps.len() + 1);
            steps.push(step);
            steps.extend(child_steps);
            (found, steps)
        }
    }
}

/// The most compact proof step for a branch, by sibling count (scalus
/// `makeProofStep`): ≥2 siblings → `Branch` (sparse-merkle 4-hash); exactly 1
/// → `Leaf`/`Fork`.
fn make_proof_step(children: &[Node], target_index: usize, skip: usize) -> ProofStep {
    let siblings: Vec<usize> = (0..16)
        .filter(|&i| i != target_index && !matches!(children[i], Node::Empty))
        .collect();

    if siblings.len() >= 2 {
        ProofStep::Branch {
            skip,
            neighbors: merkle_proof_4(children, target_index),
        }
    } else if siblings.len() == 1 {
        let nidx = siblings[0];
        match &children[nidx] {
            Node::Leaf {
                full_path, value, ..
            } => ProofStep::Leaf {
                skip,
                key: full_path.clone(),
                value: blake2b_256(value).to_vec(),
            },
            Node::Branch {
                skip_start,
                skip_len,
                rep_path,
                children: inner,
                ..
            } => ProofStep::Fork {
                skip,
                neighbor: Neighbor {
                    nibble: nidx as u8,
                    prefix: nibbles(rep_path, *skip_start, *skip_start + *skip_len),
                    root: merkle_root_16(inner).to_vec(),
                },
            },
            Node::Empty => unreachable!("filtered out above"),
        }
    } else {
        unreachable!("a branch always has >= 2 descendants")
    }
}

/// An off-chain Merkle Patricia Forestry trie: a key/value store that generates
/// on-chain-compatible inclusion / exclusion proofs.
#[derive(Clone)]
pub struct Trie {
    root: Node,
}

impl Default for Trie {
    fn default() -> Self {
        Self::empty()
    }
}

impl Trie {
    #[must_use]
    pub fn empty() -> Self {
        Trie { root: Node::Empty }
    }

    /// Build a trie from `(key, value)` pairs. Returns `Err(KeyPresent)` on a duplicate key.
    pub fn from_pairs(entries: &[(Vec<u8>, Vec<u8>)]) -> Result<Self, MpfError> {
        let mut t = Trie::empty();
        for (k, v) in entries {
            t = t.insert(k, v)?;
        }
        Ok(t)
    }

    /// The 32-byte root hash — compare against the on-chain `bifrost_identity_root`.
    #[must_use]
    pub fn root_hash(&self) -> Hash {
        self.root.hash()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self.root, Node::Empty)
    }

    /// Number of elements in the trie.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.root {
            Node::Empty => 0,
            Node::Leaf { .. } => 1,
            Node::Branch { size, .. } => *size,
        }
    }

    /// Insert `key → value`. Returns `Err(KeyPresent)` if `key` is already present.
    pub fn insert(&self, key: &[u8], value: &[u8]) -> Result<Trie, MpfError> {
        let path = blake2b_256(key);
        Ok(Trie {
            root: do_insert(&self.root, &path, 0, value)?,
        })
    }

    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        do_get(&self.root, &blake2b_256(key), 0)
    }

    /// A proof that `key` maps to its stored value. Verify with
    /// `including(key, value, &proof) == root_hash()`.
    pub fn prove_membership(&self, key: &[u8]) -> Result<Proof, MpfError> {
        let path = blake2b_256(key);
        let (found, steps) = do_prove(&self.root, &path, 0);
        if found {
            Ok(steps)
        } else {
            Err(MpfError::KeyAbsent)
        }
    }

    /// A proof that `key` is absent (the `bifrost_identity_absence_proof`).
    /// Verify with `excluding(key, &proof) == root_hash()`; after registering,
    /// `including(key, new_value, &proof)` is the updated root.
    pub fn prove_non_membership(&self, key: &[u8]) -> Result<Proof, MpfError> {
        // Insert under a dummy value, then prove membership in the expanded trie.
        // `insert` already errors `KeyPresent` if the key exists, so no separate
        // presence-check walk is needed. The proof carries only neighbors (not
        // the target leaf's value), so the dummy is irrelevant: `excluding`
        // rebuilds the original root, `including` the post-insert root.
        self.insert(key, &[])?.prove_membership(key)
    }
}

// ---------------------------------------------------------------------------
// tests — validated against the Aiken library's own vectors
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // helpers.ak `combine` sanity: combine is blake2b_256 of the concatenation.
    #[test]
    fn combine_is_blake2b_of_concat() {
        assert_eq!(combine(b"foo", b"bar"), blake2b_256(b"foobar"));
    }

    // merkle-patricia-forestry.ak `excluding_empty_proof`: excluding("foo", []) == empty root.
    #[test]
    fn excluding_empty_proof() {
        assert_eq!(excluding(b"foo", &vec![]).unwrap(), NULL_HASH);
    }

    // merkle-patricia-forestry.ak `including_empty_proof`:
    // including("foo","bar",[]) == combine(suffix(blake2b(foo),0), blake2b(bar)).
    #[test]
    fn including_empty_proof() {
        let path = blake2b_256(b"foo");
        let expected = combine(&suffix(&path, 0), &blake2b_256(b"bar"));
        assert_eq!(including(b"foo", b"bar", &vec![]).unwrap(), expected);
    }

    // README `insert_bitcoin_block_845602`: inserting block 845602 into a 5-branch trie.
    // Validates excluding == old root and including == new root with a real Branch-only proof.
    #[test]
    fn insert_bitcoin_block_845602() {
        let r0 = h("225a4599b804ba53745538c83bfa699ecf8077201b61484c91171f5910a4a8f9");
        let r1 = h("507c03bc4a25fd1cac2b03592befa4225c5f3488022affa0ab059ca350de2353");
        let block_hash = h("0000000000000000000261a131bf48cc5a19658ade8cfede99dc1c3933300d60");
        let block_body = h("26f711634eb26999169bb927f629870938bb4b6b4d1a078b44a6b4ec54f9e8df");

        let branch = |neighbors: &str| ProofStep::Branch {
            skip: 0,
            neighbors: h(neighbors),
        };
        let proof: Proof = vec![
            branch("bc13df27a19f8caf0bf922c900424025282a892ba8577095fd35256c9d553ca120b8645121ebc9057f7b28fa4c0032b1f49e616dfb8dbd88e4bffd7c0844d29b011b1af0993ac88158342583053094590c66847acd7890c86f6de0fde0f7ae2479eafca17f9659f252fa13ee353c879373a65ca371093525cf359fae1704cf4a"),
            branch("255753863960985679b4e752d4b133322ff567d210ffbb10ee56e51177db057460b547fe42c6f44dfef8b3ecee35dfd4aa105d28b94778a3f1bb8211cf2679d7434b40848aebdd6565b59efdc781ffb5ca8a9f2b29f95a47d0bf01a09c38fa39359515ddb9d2d37a26bccb022968ef4c8e29a95c7c82edcbe561332ff79a51af"),
            branch("9d95e34e6f74b59d4ea69943d2759c01fe9f986ff0c03c9e25ab561b23a413b77792fa78d9fbcb98922a4eed2df0ed70a2852ae8dbac8cff54b9024f229e66629136cfa60a569c464503a8b7779cb4a632ae052521750212848d1cc0ebed406e1ba4876c4fd168988c8fe9e226ed283f4d5f17134e811c3b5322bc9c494a598b"),
            branch("b93c3b90e647f90beb9608aecf714e3fbafdb7f852cfebdbd8ff435df84a4116d10ccdbe4ea303efbf0f42f45d8dc4698c3890595be97e4b0f39001bde3f2ad95b8f6f450b1e85d00dacbd732b0c5bc3e8c92fc13d43028777decb669060558821db21a9b01ba5ddf6932708cd96d45d41a1a4211412a46fe41870968389ec96"),
            branch("f89f9d06b48ecc0e1ea2e6a43a9047e1ff02ecf9f79b357091ffc0a7104bbb260908746f8e61ecc60dfe26b8d03bcc2f1318a2a95fa895e4d1aadbb917f9f2936b900c75ffe49081c265df9c7c329b9036a0efb46d5bac595a1dcb7c200e7d590000000000000000000000000000000000000000000000000000000000000000"),
        ];

        assert_eq!(&excluding(&block_hash, &proof).unwrap()[..], &r0[..], "excluding == old root");
        assert_eq!(
            &including(&block_hash, &block_body, &proof).unwrap()[..],
            &r1[..],
            "including == new root"
        );
    }

    fn branch(skip: usize, neighbors: &str) -> ProofStep {
        ProofStep::Branch {
            skip,
            neighbors: h(neighbors),
        }
    }

    fn fork(skip: usize, nibble: u8, prefix: &str, root: &str) -> ProofStep {
        ProofStep::Fork {
            skip,
            neighbor: Neighbor {
                nibble,
                prefix: h(prefix),
                root: h(root),
            },
        }
    }

    fn leaf(skip: usize, key: &str, value: &str) -> ProofStep {
        ProofStep::Leaf {
            skip,
            key: h(key),
            value: h(value),
        }
    }

    // `insert(trie, key, value, proof) == new_root` decomposes into
    // `excluding(key,proof) == old_root` ∧ `including(key,value,proof) == new_root`.
    fn check_insert(old_root: &str, key: &str, value: &str, proof: &Proof, new_root: &str) {
        assert_eq!(
            &excluding(&h(key), proof).unwrap()[..],
            &h(old_root)[..],
            "excluding must equal the old root"
        );
        assert_eq!(
            &including(&h(key), &h(value), proof).unwrap()[..],
            &h(new_root)[..],
            "including must equal the new root"
        );
    }

    // merkle-patricia-forestry.tests.ak `insert_edge_case4`: a terminal Fork with an EMPTY
    // prefix — exercises sparse_merkle_16 + the do_excluding terminal-Fork (skip>0) path.
    #[test]
    fn insert_edge_case4_fork_empty_prefix() {
        let proof = vec![
            branch(0, "d072e11c4f761d09ebe0c1df54b08d398977aa4e98e85e5e231f52dc32fdf8053861a5ea164ac3eb460e27f96ba934832bfc7b240dbf7be24d3fb7ae16f3e44fa965498aa2e219f45428bafc4f646a8f2b4d863bf730f802f81f4f713a465246cd28ad53627981fd212ebec41068fa0f4b0ae5e0e77af0143e296373c6c8f753"),
            branch(0, "6c2cf6703c1b121726899e4f1de29cf483227d9e75d5d7948b62b5904c7f1011165b8313abcd4f1c33b85a5dabf8c5096039b3aba1c1fedda2e247810090173998f6f58a03bc17874bff8ba7eda08d25623911dff348f57da60b8545044dcbb175d27abc4c3e1b9aa0a3161ea0f8067ef39885c30399c164395b181747ba4f51"),
            branch(0, "c5b1eb4266a20e13961f0b7b8f909a217141eecab5bbe3116665e382f87477fcf9a8a6a9e1e1cb7af32d1ffdf5c70643434337c3874d417de45f83e48f7c00afaf7180e918199dde712083a3f512483e89d756f25ddafe8b14b246499fe44dd3bda1f1a580cf7af9dd35c6ddfffa2ec8af0d41b00d7ca5ed25af8e54d4bef1f9"),
            fork(1, 12, "", "136bca071d530710ba622dfd66fe1afb859d4f42d45f29ce252e862a92eb10c2"),
        ];
        check_insert(
            "76ff3670f2b81017d50354ca4a78792de31adbd23f456eec41d7a8c13fcdc91b",
            "04811fc306a2021340b15ce6f025db1dc3d402f0829c7ee2100ca8fdd6ed10cd",
            "0c43c3addce8b95e49eb0fb906",
            &proof,
            "a6eb3cdf9dd3da02d9463bd5cd68555ea11d6d5a77e2ece9ceb1cf6a5a9c7b27",
        );
    }

    // `insert_edge_case7`: a terminal Fork with a NON-empty prefix ("0e") — exercises the
    // do_excluding terminal-Fork branch that prepends nibbles(path, ..) to the neighbor prefix.
    #[test]
    fn insert_edge_case7_fork_nonempty_prefix() {
        let proof = vec![
            branch(0, "7391436705a8141e333c007c5ea3e046f9b6ce3200988f4323b337f1eb4e476e300fc77899d6c430dc56965b5171ed48ae947e00cf886ed36bd508f01ecdcfd0a61383bae3451edfa124b8b4a0d6a36f9634c9dcdb9684492bc1f1962a38247ba4ea8e58b84473436d6b6fc5fd47a3abef4959544f8e57bc62ba48131198e476"),
            branch(0, "a8c0876243c8203192c45e572b91b84654915f3015e99fbf2a50d2d48bbdacf73a1077fa66a5e7159d0971ce3192d128158480293bd98923ea6614f444c91684b55f810f03a8a710183c7ffff4272817d630c6ffae2600accdedc9f656fa9283571838701edb01d0ec362c174d12243a426af448fb909d32ed51d8641c3a43b0"),
            branch(0, "72302f4a439c2294ba4f6bef321f0f7bf497bb5c24335f2e1c8d0b49237410297674c4a5f9437696d4ed2145aad20cc0ef39bc139574941c9f24a4023706e7720d1a0c3d36e6748cabab8c24cb83a17b4a771f536a9fd361e1416f673ed43708b61ff685cecf3bd4a6118e3994e36e41e8dcaee8b47b2ea947968c0afca65b6e"),
            branch(0, "f226865e02694067e1d0a17b3cb0f6c3d7e5186642a3ff1d8299573e3cac04673fced676fe9af960d3ed3d1e6138952993109b7ec62a3f38eae39fb89a06f04436b86983490a9c2488d8b690074fb3b6a487049f21b6de07dd27b8cfb6243fc3ab5d438a30e24aee9016ffb83a2c23ed7f316efac775c6c2eec64f41967e63c2"),
            fork(1, 11, "0e", "8ffc29f174b749ee61bc9048cb600b4b7b9379227cf690a9268ffa26c5973738"),
        ];
        check_insert(
            "5032a544857633269c915dd4fb665d79a041d6d75ca795e24fc17a285cc1dece",
            "daa708d4b3fcf81fdfb8fce2ec5ff61fa38ff02fb4f4d9a218c158b2de170b20",
            "9fb48cf6f576d74b1d7d8917",
            &proof,
            "b4b1446e07f17da9643a597e5b3a805bc75307aec8a40edde1e41b22ffb90442",
        );
    }

    // `insert_edge_case2`: two Leaf steps — exercises do_including Leaf and both do_excluding Leaf
    // branches (non-terminal Leaf{skip:1} then terminal Leaf{skip:0}).
    #[test]
    fn insert_edge_case2_leaf_steps() {
        let proof = vec![
            branch(0, "4c54bfc322fb7bc2e49ae21bf5fa560632e3ca42b5267eb115142e291e8ada4ecd0c58152bf064f0c7834dd72f69d12651739b32caaa3c986a87937f125b500f1426fccf2a456bce3c25b43206d9b429d56515580d086a959ca730325411b3aada6ac4d7221f787b97e1ce677fdadc412e824a9816281b1259b91addeb37bb2c"),
            branch(0, "098745f495c99b7627f559ac8ed8165e2392e2261ef8990291f13705adf78fcf3dcca881d4b45aabe746e7041f743baaa831029e7890df9587858d8be5dce648e02f31fe2936417a393df8def15d7d0c021a66cdb33c3fdda941ae70614913cb116fd5e6c499b71e229b88f5106975cbe83a8c44d3619541d7ddd7eae0a355bc"),
            branch(0, "9732c3266e468dd27c4bd16af5a6e60c1f556bf91700f51554cfa33aa26b8d30f33c27ab7c5c85ef006c78f56ecd7e8c77c5fadd7910e9b178801d554f244977026104fc4aede0864d405db792691c4e4534b06ae7f58366b640f13ecfa549afa046a157d2e9b6c0793a506942eb8ff50dfeb7c5e7a2a51814c4b3a4d6af6fa0"),
            branch(0, "5f3065e998b5fa89bb33d9204546c5dba2b075adc542688dcc1773a490fa739ac69ff52c5f575e9f1912664c1ebef2f9498775350b0077a6b59fe012861c3715657146a239aaea12b3091054e5846771bba6f721b1835d025fa08d1fc5c9b1c40000000000000000000000000000000000000000000000000000000000000000"),
            leaf(1, "2b5b0ba7a99e17d9fde58f14dee61cccda9e3e9627b2ba2732ebed551ea9eaa4", "3657998959985b7b75c734eb5b49d18cae9b353d00d811cb2c24ed6ed17b23d9"),
            leaf(0, "2b5b063719f4b7644c71adef1439c9aa78d34e684677dd61db0adffcc21797ec", "4e397303e05277d98701446ee62f6f02bc013721fc12efba7300fb51ea935f9f"),
        ];
        check_insert(
            "00489b47aa866ff55da4f24fa4801a6948871258fab39f22354f35b7c4f94412",
            "198d70e41146654a69e08c6682310a8c35816c8584431915a0eee4a62d39eda0",
            "9e36f867a374be",
            &proof,
            "b76dd0926602d6e9d28a0b3707db4622184d59c7392f5a0469bf775d9aa05f33",
        );
    }

    // ----- Phase 2: off-chain trie / proof generation -----

    fn sample_pairs(n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        (0..n)
            .map(|i| {
                (
                    format!("spo-{i}").into_bytes(),
                    format!("pool-{i}").into_bytes(),
                )
            })
            .collect()
    }

    #[test]
    fn trie_empty_root_is_null() {
        assert!(Trie::empty().is_empty());
        assert_eq!(Trie::empty().root_hash(), NULL_HASH);
    }

    // A one-leaf trie's root must equal the verifier's empty-proof inclusion —
    // cross-checks the prover's root against the Aiken-validated verifier.
    #[test]
    fn trie_single_element_matches_empty_proof() {
        let t = Trie::empty().insert(b"spo-0", b"pool-0").unwrap();
        assert_eq!(t.root_hash(), including(b"spo-0", b"pool-0", &vec![]).unwrap());
        assert_eq!(t.get(b"spo-0"), Some(b"pool-0".to_vec()));
        assert_eq!(t.get(b"spo-1"), None);
        assert_eq!(t.prove_membership(b"spo-0"), Ok(vec![]));
    }

    // Every membership proof must verify under `including` against the root —
    // 30 keys exercise Branch / Fork / Leaf proof steps as they arise.
    #[test]
    fn trie_membership_proofs_verify_for_all_keys() {
        let pairs = sample_pairs(30);
        let t = Trie::from_pairs(&pairs).unwrap();
        assert_eq!(t.len(), 30);
        assert_eq!(t.get(b"spo-7"), Some(b"pool-7".to_vec()));
        for (k, v) in &pairs {
            let proof = t.prove_membership(k).expect("key present");
            assert_eq!(
                including(k, v, &proof).unwrap(),
                t.root_hash(),
                "inclusion proof for {k:?} must rebuild the root"
            );
        }
    }

    // The absence proof: `excluding` rebuilds the original root, `including`
    // (with the real value) the post-insert root — exactly the register_spo flow.
    #[test]
    fn trie_non_membership_proof_round_trips() {
        let t = Trie::from_pairs(&sample_pairs(30)).unwrap();
        let key = b"spo-new";
        let value = b"pool-new";
        assert!(t.get(key).is_none());

        let proof = t.prove_non_membership(key).expect("key absent");
        assert_eq!(excluding(key, &proof).unwrap(), t.root_hash(), "exclusion == old root");
        assert_eq!(
            including(key, value, &proof).unwrap(),
            t.insert(key, value).unwrap().root_hash(),
            "inclusion == new root after registering key→value"
        );
    }

    #[test]
    fn trie_prove_error_cases() {
        let t = Trie::from_pairs(&sample_pairs(5)).unwrap();
        assert_eq!(t.prove_membership(b"spo-absent"), Err(MpfError::KeyAbsent));
        assert_eq!(t.prove_non_membership(b"spo-0"), Err(MpfError::KeyPresent));
    }

    // make_proof_step's Fork arm (single sibling that is itself a Branch) only
    // arises in larger tries — the 30-key tests produce none. Exercise it
    // explicitly so the prover-side Fork construction (which register_spo's
    // absence proof relies on for deeper rosters) is covered end-to-end.
    #[test]
    fn trie_large_trie_exercises_fork_steps() {
        let pairs = sample_pairs(200);
        let t = Trie::from_pairs(&pairs).unwrap();
        assert_eq!(t.len(), 200);
        let mut fork_seen = false;
        for (k, v) in &pairs {
            let proof = t.prove_membership(k).expect("key present");
            assert_eq!(including(k, v, &proof).unwrap(), t.root_hash(), "inclusion for {k:?}");
            fork_seen |= proof.iter().any(|s| matches!(s, ProofStep::Fork { .. }));
        }
        assert!(
            fork_seen,
            "a 200-key trie should generate at least one Fork proof step"
        );
    }

    // ----- WI-007 hardening: malformed input returns Err, never panics -----

    #[test]
    fn verifier_rejects_malformed_proofs_without_panicking() {
        let key = b"spo-0";
        // Branch step whose neighbors blob is not 128 bytes.
        let short = vec![ProofStep::Branch {
            skip: 0,
            neighbors: vec![0u8; 64],
        }];
        assert_eq!(excluding(key, &short), Err(MpfError::BadNeighborsLen));

        // skip pushing the cursor past the 64-nibble path.
        let deep_skip = vec![ProofStep::Branch {
            skip: 100,
            neighbors: vec![0u8; 128],
        }];
        assert_eq!(excluding(key, &deep_skip), Err(MpfError::CursorOutOfRange));

        // proof longer than the path can be deep.
        let too_deep: Proof = (0..65)
            .map(|_| ProofStep::Branch {
                skip: 0,
                neighbors: vec![0u8; 128],
            })
            .collect();
        assert_eq!(excluding(key, &too_deep), Err(MpfError::ProofTooDeep));

        // Fork neighbor nibble out of the 0..=15 range.
        let bad_nibble = vec![ProofStep::Fork {
            skip: 0,
            neighbor: Neighbor {
                nibble: 200,
                prefix: vec![],
                root: vec![0u8; 32],
            },
        }];
        assert_eq!(excluding(key, &bad_nibble), Err(MpfError::BadNibble));

        // Leaf step with a non-32-byte key.
        let short_leaf = vec![ProofStep::Leaf {
            skip: 0,
            key: vec![0u8; 8],
            value: vec![0u8; 32],
        }];
        assert_eq!(excluding(key, &short_leaf), Err(MpfError::BadHashLen));
    }

    // do_insert no longer panics on a duplicate key — it returns Err(KeyPresent).
    #[test]
    fn duplicate_key_insert_returns_err() {
        let t = Trie::empty().insert(b"k", b"v1").unwrap();
        assert!(matches!(t.insert(b"k", b"v2"), Err(MpfError::KeyPresent)));

        let dup = vec![
            (b"a".to_vec(), b"1".to_vec()),
            (b"a".to_vec(), b"2".to_vec()),
        ];
        assert!(matches!(Trie::from_pairs(&dup), Err(MpfError::KeyPresent)));
    }

    // The verify_* helpers do the root comparison for the caller.
    #[test]
    fn verify_helpers_compare_against_expected_root() {
        let t = Trie::from_pairs(&sample_pairs(30)).unwrap();
        let key = b"spo-new";
        let proof = t.prove_non_membership(key).unwrap();
        // Exclusion against the real root succeeds; against a wrong root, RootMismatch.
        assert_eq!(verify_exclusion(key, &proof, &t.root_hash()), Ok(()));
        assert_eq!(
            verify_exclusion(key, &proof, &NULL_HASH),
            Err(MpfError::RootMismatch)
        );
        let new_root = t.insert(key, b"pool-new").unwrap().root_hash();
        assert_eq!(verify_inclusion(key, b"pool-new", &proof, &new_root), Ok(()));
    }
}
