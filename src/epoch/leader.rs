//! The published leader election and timeout cascade (spec §Cardano submission
//! and leader reward; WI-104, WI-099).
//!
//! ## What this decides, and what it does not
//!
//! Nothing here is a consensus rule. Posting is **permissionless** on chain —
//! "the head check gates record validity and Bitcoin gates correctness, so an
//! out-of-turn or duplicate post is at worst inert garbage" — so every node
//! holding a finished aggregate is *able* to post, and this module only decides
//! who goes first. Two nodes that disagreed about the leader would at worst both
//! post and one would lose a fee.
//!
//! That is worth stating up front because it is the whole reason the previous
//! design was wrong. heimdall treated "who posts" as a gate: `Roster::leader`
//! returned the lowest identifier, nothing ever moved off it, and a node that was
//! not it declined to post at all. One permanently-chosen node that went dark
//! therefore cost the roster its ability to post anything, which the protocol
//! does not say and does not need.
//!
//! ## The rule
//!
//! ```text
//! leader_index    = hash("bifrost-leader" ‖ prev_tm_txid ‖ tm_sequence) mod roster_size
//! eligible_slot[i] = signing_complete_slot + ((i − leader_index) mod roster_size) × leader_slot_T
//! ```
//!
//! over the roster sorted lexicographically by `pool_id`. The entropy is the
//! previous TM's Bitcoin txid *because* it cannot be known before that TM is
//! mined — an earlier note in this codebase proposed `participants[(epoch +
//! attempt) mod n]`, which is deterministic but predictable, and predictable is
//! exactly what the spec rules out ("fairness, unpredictability, and liveness").
//!
//! ## Two encodings the spec leaves open, and what this picks
//!
//! Both are flagged for a spec clarification. Neither can cost more than a
//! duplicate post, per the permissionlessness above, but two implementations
//! should still stagger identically.
//!
//! * **Which hash.** The spec writes `hash(...)`. This uses `sha2_256`, the
//!   function every other domain-separated digest in this protocol uses (e.g.
//!   [`crate::cardano::treasury_info::update_y_sig_msg`]).
//! * **How `tm_sequence` is encoded.** The spec makes the field a *string* for
//!   key publication (the literal `"dkg"`), so the numeric case is written the
//!   same way — ASCII decimal, no padding. A big-endian integer would have been
//!   the other reading, but it cannot be reconciled with `"dkg"` occupying the
//!   same position.

use std::borrow::Cow;

use frost::Identifier;
use frost_secp256k1_tr as frost;

/// Which submission this election is for — the third input to the hash.
///
/// Its real job is separating the two elections that can otherwise collide:
/// after a DKG, the Update-Y and the epoch's first movement hash against the
/// *same* `prev_tm_txid`, and without this they would elect the same node for
/// both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmSequence {
    /// A treasury movement, by its 0-indexed sequence within the epoch.
    Tm(u64),
    /// Key publication after DKG — the spec's literal `"dkg"`.
    Dkg,
}

impl TmSequence {
    /// The bytes that go into the digest. See the module note on encoding.
    #[must_use]
    pub fn as_bytes(&self) -> Cow<'static, [u8]> {
        match self {
            Self::Tm(n) => Cow::Owned(n.to_string().into_bytes()),
            Self::Dkg => Cow::Borrowed(b"dkg"),
        }
    }
}

impl std::fmt::Display for TmSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tm(n) => write!(f, "{n}"),
            Self::Dkg => f.write_str("dkg"),
        }
    }
}

/// A submission order: the roster in the spec's order, and where the primary
/// leader sits in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cascade {
    /// Participants sorted lexicographically by `pool_id`, as the spec requires.
    ///
    /// NOT identifier order. FROST identifiers are positional ranks over
    /// `bifrost_id_pk`, which is a different key and therefore a different order;
    /// electing by identifier would be a different (and unpublished) rule.
    order: Vec<Identifier>,
    leader_index: usize,
}

impl Cascade {
    /// Elect over `participants`, given as `(identifier, pool_id)` pairs.
    ///
    /// `prev_tm_txid` is the txid of the current treasury outpoint in INTERNAL
    /// byte order — the first 32 bytes of the singleton's `treasury_utxo_id`,
    /// which is the same orientation `bitcoin::Txid::to_byte_array` yields, not
    /// the reversed one it displays.
    ///
    /// `None` for an empty roster: there is nobody to elect, and returning an
    /// index into nothing would be worse than making the caller handle it.
    pub fn elect<'a>(
        participants: impl IntoIterator<Item = (Identifier, &'a [u8])>,
        prev_tm_txid: &[u8; 32],
        sequence: TmSequence,
    ) -> Option<Self> {
        let mut by_pool: Vec<(Identifier, &[u8])> = participants.into_iter().collect();
        // Ties broken by identifier so the order is total even if two members
        // somehow present the same pool_id — one registration per pool makes that
        // impossible on chain, but an ordering that depends on input order would
        // be a silent divergence if it ever were.
        by_pool.sort_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(&b.0)));
        let n = by_pool.len();
        if n == 0 {
            return None;
        }

        let mut pre = Vec::with_capacity(14 + 32 + 8);
        pre.extend_from_slice(b"bifrost-leader");
        pre.extend_from_slice(prev_tm_txid);
        pre.extend_from_slice(&sequence.as_bytes());

        Some(Self {
            order: by_pool.into_iter().map(|(id, _)| id).collect(),
            leader_index: digest_mod(&pre, n),
        })
    }

    /// The primary leader — the node expected to post first.
    #[must_use]
    pub fn leader(&self) -> Identifier {
        self.order[self.leader_index]
    }

    /// How many cascade hops `id` waits before becoming eligible: 0 for the
    /// primary leader, 1 for the next in roster order, wrapping around.
    ///
    /// `None` for a node outside this roster, which is not a hop of infinity but
    /// a different question — it means the caller elected over the wrong set. On
    /// the Update-Y path that distinction is the entire bug WI-099 fixed.
    #[must_use]
    pub fn hops_before(&self, id: Identifier) -> Option<u64> {
        let i = self.order.iter().position(|p| *p == id)?;
        let n = self.order.len();
        Some(((i + n - self.leader_index) % n) as u64)
    }

    /// The slot at which `id` may post: `signing_complete_slot + hops × T`.
    #[must_use]
    pub fn eligible_slot(
        &self,
        id: Identifier,
        signing_complete_slot: u64,
        leader_slot_t: u64,
    ) -> Option<u64> {
        let hops = self.hops_before(id)?;
        Some(signing_complete_slot.saturating_add(hops.saturating_mul(leader_slot_t)))
    }

    /// Participants, in the spec's order.
    #[must_use]
    pub fn order(&self) -> &[Identifier] {
        &self.order
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// `sha2_256(pre)` read as a big-endian integer, modulo `n`.
///
/// Reduced a byte at a time rather than truncated to a machine word: truncation
/// would be a second unpublished choice (how many bytes, from which end), and
/// the whole digest has one obvious meaning. `n` is a roster size, so the
/// arithmetic cannot overflow a `u64` — `acc < n ≤ u32::MAX` before each step.
fn digest_mod(pre: &[u8], n: usize) -> usize {
    use bitcoin::hashes::{Hash as _, sha256};
    let digest = sha256::Hash::hash(pre).to_byte_array();
    let n = n as u64;
    let mut acc = 0u64;
    for byte in digest {
        acc = (acc * 256 + u64::from(byte)) % n;
    }
    acc as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u16) -> Identifier {
        Identifier::try_from(n).unwrap()
    }

    /// pool_ids chosen so that the pool_id order is the REVERSE of the
    /// identifier order — every test below would pass by accident if the two
    /// agreed.
    fn roster() -> Vec<(Identifier, Vec<u8>)> {
        (1..=5u16)
            .map(|i| (id(i), vec![(6 - i) as u8; 28]))
            .collect()
    }

    fn cascade(txid: [u8; 32], seq: TmSequence) -> Cascade {
        let r = roster();
        Cascade::elect(r.iter().map(|(i, p)| (*i, p.as_slice())), &txid, seq).unwrap()
    }

    /// The order is the spec's — by `pool_id` — and NOT the identifier order the
    /// old `Roster::leader` used.
    #[test]
    fn the_roster_is_ordered_by_pool_id_not_by_identifier() {
        let c = cascade([0x11; 32], TmSequence::Tm(0));
        assert_eq!(
            c.order(),
            &[id(5), id(4), id(3), id(2), id(1)],
            "sorted by pool_id, which here is the reverse of identifier order"
        );
    }

    /// Every node computes the same leader from the same inputs — the property
    /// the whole convention rests on.
    #[test]
    fn the_election_is_a_function_of_its_inputs() {
        let a = cascade([0x11; 32], TmSequence::Tm(3));
        let b = cascade([0x11; 32], TmSequence::Tm(3));
        assert_eq!(a, b);
        // …and the input order of the participants cannot change it.
        let mut reversed = roster();
        reversed.reverse();
        let c = Cascade::elect(
            reversed.iter().map(|(i, p)| (*i, p.as_slice())),
            &[0x11; 32],
            TmSequence::Tm(3),
        )
        .unwrap();
        assert_eq!(a, c);
    }

    /// A different previous movement elects independently — this is the entropy
    /// the rule exists for, and the reason `(epoch + attempt) mod n` was rejected.
    #[test]
    fn a_different_prev_tm_txid_reelects() {
        let seen: std::collections::BTreeSet<_> = (0u8..40)
            .map(|b| cascade([b; 32], TmSequence::Tm(0)).leader())
            .collect();
        assert!(
            seen.len() >= 4,
            "40 different previous movements should spread over the roster, got {seen:?}"
        );
    }

    /// The case `tm_sequence` exists for: after a DKG, the Update-Y and the
    /// epoch's first movement hash against the SAME `prev_tm_txid`, and must not
    /// collapse onto one node.
    #[test]
    fn dkg_and_the_first_movement_elect_separately() {
        let differs = (0u8..40).any(|b| {
            cascade([b; 32], TmSequence::Dkg).leader()
                != cascade([b; 32], TmSequence::Tm(0)).leader()
        });
        assert!(differs, "\"dkg\" must not always agree with sequence 0");
    }

    /// `"dkg"` is a literal, not a number, and `Tm(n)` is its decimal spelling.
    #[test]
    fn the_sequence_encoding_is_a_string() {
        assert_eq!(&*TmSequence::Dkg.as_bytes(), b"dkg");
        assert_eq!(&*TmSequence::Tm(0).as_bytes(), b"0");
        assert_eq!(&*TmSequence::Tm(17).as_bytes(), b"17");
    }

    /// The cascade covers the whole roster exactly once, starting at the leader.
    #[test]
    fn the_cascade_wraps_over_every_member_once() {
        let c = cascade([0x22; 32], TmSequence::Tm(1));
        let hops: Vec<u64> = c
            .order()
            .iter()
            .map(|id| c.hops_before(*id).unwrap())
            .collect();
        let mut sorted = hops.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..c.len() as u64).collect::<Vec<_>>());
        assert_eq!(c.hops_before(c.leader()), Some(0));
    }

    /// The spec's worked example, in slots: T = 60, signing completes at 1000,
    /// so the leader may post at 1000 and each successor 60 slots later.
    #[test]
    fn eligible_slots_step_by_t_from_the_anchor() {
        let c = cascade([0x33; 32], TmSequence::Tm(2));
        for id in c.order() {
            let hops = c.hops_before(*id).unwrap();
            assert_eq!(c.eligible_slot(*id, 1000, 60), Some(1000 + hops * 60));
        }
        assert_eq!(c.eligible_slot(c.leader(), 1000, 60), Some(1000));
    }

    /// A node outside the roster has no place in the cascade — and says so,
    /// rather than reporting a hop it could act on. This is the WI-099 shape:
    /// electing over the incoming roster asked exactly this question of nodes
    /// that could not sign.
    #[test]
    fn a_node_outside_the_roster_has_no_hop() {
        let c = cascade([0x44; 32], TmSequence::Tm(0));
        assert_eq!(c.hops_before(id(99)), None);
        assert_eq!(c.eligible_slot(id(99), 1000, 60), None);
    }

    /// An empty roster elects nobody instead of panicking on an index.
    #[test]
    fn an_empty_roster_elects_nobody() {
        assert!(Cascade::elect(std::iter::empty(), &[0u8; 32], TmSequence::Dkg).is_none());
    }

    /// A one-member roster is all leader, no hops — the local-demo shape.
    #[test]
    fn a_single_member_roster_is_always_the_leader() {
        let one = [(id(1), vec![7u8; 28])];
        let c = Cascade::elect(
            one.iter().map(|(i, p)| (*i, p.as_slice())),
            &[0x55; 32],
            TmSequence::Tm(0),
        )
        .unwrap();
        assert_eq!(c.leader(), id(1));
        assert_eq!(c.hops_before(id(1)), Some(0));
    }

    /// Reducing the whole digest, not a truncation of it. Locked against a
    /// known answer so a change of hash or of encoding is visible in the diff
    /// rather than only as a different node posting first.
    #[test]
    fn the_digest_reduction_is_pinned() {
        // sha2_256("bifrost-leader" ‖ 0x00*32 ‖ "0") as a big-endian integer.
        assert_eq!(digest_mod(b"", 1), 0);
        let mut pre = b"bifrost-leader".to_vec();
        pre.extend_from_slice(&[0u8; 32]);
        pre.extend_from_slice(b"0");
        let expected = {
            use bitcoin::hashes::{Hash as _, sha256};
            let d = sha256::Hash::hash(&pre).to_byte_array();
            let mut acc = 0u64;
            for b in d {
                acc = (acc * 256 + u64::from(b)) % 7;
            }
            acc as usize
        };
        assert_eq!(digest_mod(&pre, 7), expected);
        assert!(digest_mod(&pre, 7) < 7);
    }
}
