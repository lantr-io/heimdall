//! The typed-in federation roster: who the members are, and how many of them it
//! takes to sign.
//!
//! This is the one participant list in heimdall with no chain behind it, for the
//! reason the [module docs](super) give: `Y_federation` precedes the bridge, so
//! there is nothing to read it from. What replaces the registry's guarantees:
//!
//! - **Ordering.** Members are sorted lexicographically by `bifrost_id_pk` and
//!   given FROST identifiers `1..=n` in that order — the same rule
//!   [`crate::cardano::roster::roster_from_snapshot`] applies to the registry. It
//!   is what lets every node derive the identical numbering from the same set
//!   without agreeing on a file's line order.
//! - **Addressing.** The authenticated transport keys payloads (and their URL
//!   paths) by a 28-byte member id. A federation member need not be a Cardano SPO
//!   and there is no registry to look a `pool_id` up in, so the id is
//!   `blake2b_224(bifrost_id_pk)` — derived from the list rather than typed
//!   beside it, so it cannot be typed wrong.
//! - **Uniqueness.** Duplicate keys or duplicate endpoints are refused at
//!   construction. Two members sharing a key would collide in every map the
//!   ceremony keeps; two sharing a URL means one of them is unreachable, which
//!   surfaces as an unattributable poll timeout an hour later.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use bitcoin::key::UntweakedPublicKey;
use frost_secp256k1_tr::Identifier;

use crate::cardano::hash::{blake2b_224, blake2b_256};
use crate::cardano::roster::{FROST_MIN_PARTICIPANTS, validate_bifrost_url};
use crate::config::FederationConfig;
use crate::epoch::state::{Roster, SpoInfo};

/// Domain tag of [`FederationRoster::digest`].
const DIGEST_TAG: &[u8] = b"bifrost-federation-roster-v1";

/// One federation member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationMember {
    /// FROST index, `1..=n`, assigned by `bifrost_id_pk` order.
    pub identifier: Identifier,
    /// The member's x-only secp256k1 identity key. Every payload it publishes is
    /// BIP-340 signed under this key, and Round 2 shares are ECDH-encrypted to it.
    pub bifrost_id_pk: [u8; 32],
    /// Canonicalized base URL its ceremony payloads are fetched from.
    pub bifrost_url: String,
}

impl FederationMember {
    /// The 28-byte transport address: `blake2b_224(bifrost_id_pk)`.
    ///
    /// It occupies the `pool_id` slot of the wire format ([`SpoInfo::pool_id`]),
    /// which is a 28-byte *member address* everywhere below the roster — the wire
    /// never asks it to be a Cardano pool id, and a federation member may not
    /// have one.
    #[must_use]
    pub fn address(&self) -> [u8; 28] {
        blake2b_224(&self.bifrost_id_pk)
    }

    /// `#<index> <first 4 bytes of key> <url>` — how a member is named in logs
    /// and in the `--signers` table.
    #[must_use]
    pub fn label(&self) -> String {
        format!(
            "#{} {} {}",
            crate::frost::identifier_u16(self.identifier),
            hex::encode(&self.bifrost_id_pk[..4]),
            self.bifrost_url
        )
    }
}

/// The federation, as every member's config describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationRoster {
    /// FROST threshold `t`: how many members it takes to sign.
    ///
    /// Baked into the key at generation — changing it later means a new key, a
    /// new treasury address and moving the funds — which is why it is a required
    /// config value rather than one with a default. `t = n - 1` is the
    /// recommendation: one dark member must not brick the path that exists
    /// *because* members can go dark, and it still takes nearly everyone to move
    /// the treasury. See [`Self::threshold_is_minority`] for the other end.
    pub min_signers: u16,
    /// Members in identifier order (`members[i].identifier == i + 1`).
    pub members: Vec<FederationMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterError {
    /// `[federation].members` is empty — no federation is configured.
    NoMembers,
    /// Fewer members than FROST DKG can run with.
    TooFew { got: usize },
    /// `[federation].min_signers` is unset.
    MissingThreshold { n: usize },
    /// A threshold FROST cannot use, or one exceeding the membership.
    BadThreshold { t: u16, n: u16 },
    /// A member's `bifrost_id_pk` is not a 32-byte x-only secp256k1 key.
    BadKey { url: String, reason: String },
    /// A member's `bifrost_url` is not a usable http(s) base URL.
    BadUrl { key: String, reason: String },
    /// Two members share an identity key.
    DuplicateKey { key: String },
    /// Two members share an endpoint (after canonicalization).
    DuplicateUrl { url: String },
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMembers => write!(
                f,
                "[federation].members is empty. The federation roster is typed in, not read \
                 from a chain — Y_federation is an input to genesis, so there is nothing to \
                 read it from. List every member's bifrost_id_pk + bifrost_url, including \
                 this node's own"
            ),
            Self::TooFew { got } => write!(
                f,
                "a federation of {got} cannot run FROST DKG: frost-core rejects fewer than \
                 {FROST_MIN_PARTICIPANTS} participants. A one-member federation is the single \
                 seed this ceremony exists to replace"
            ),
            Self::MissingThreshold { n } => write!(
                f,
                "[federation].min_signers is unset. It is how many of the {n} members it takes \
                 to sign a recovery spend, and it is baked into the key at generation — \
                 changing it later means a new key, a new treasury address and moving the \
                 funds. There is deliberately no default: set it to {} unless you have a \
                 reason not to",
                n.saturating_sub(1).max(usize::from(FROST_MIN_PARTICIPANTS)),
            ),
            Self::BadThreshold { t, n } => write!(
                f,
                "[federation].min_signers = {t} is not usable with {n} member(s): it must be \
                 at least {FROST_MIN_PARTICIPANTS} (frost-core refuses less) and at most {n} \
                 (a threshold above the membership can never be met, so the recovery path \
                 would be unspendable)"
            ),
            Self::BadKey { url, reason } => write!(
                f,
                "federation member {url}: bifrost_id_pk is not a 32-byte x-only secp256k1 \
                 key: {reason}"
            ),
            Self::BadUrl { key, reason } => write!(
                f,
                "federation member {key}: bifrost_url {reason}. Peers join \"/dkg/…\" onto it \
                 verbatim, and this node binds its own listen port from it"
            ),
            Self::DuplicateKey { key } => write!(
                f,
                "federation member key {key} is listed twice — one member cannot hold two \
                 FROST indices"
            ),
            Self::DuplicateUrl { url } => write!(
                f,
                "federation endpoint {url} is listed twice (after canonicalization). Two \
                 members cannot publish to one endpoint: the second's payloads would be \
                 unreachable, and the ceremony would stall with nothing naming the cause"
            ),
        }
    }
}

impl std::error::Error for RosterError {}

impl FederationRoster {
    /// Build the roster from `[federation]`, validating everything the ceremony
    /// will later depend on.
    ///
    /// Fails loudly rather than degrading: every condition checked here shows up
    /// otherwise as an unattributable timeout in the middle of a ceremony that
    /// cannot be resumed, on a key that decides where the treasury lives.
    pub fn from_config(cfg: &FederationConfig) -> Result<Self, RosterError> {
        if cfg.members.is_empty() {
            return Err(RosterError::NoMembers);
        }
        let n = cfg.members.len();
        if n < usize::from(FROST_MIN_PARTICIPANTS) {
            return Err(RosterError::TooFew { got: n });
        }
        let n_u16 = u16::try_from(n).map_err(|_| RosterError::BadThreshold {
            t: u16::MAX,
            n: u16::MAX,
        })?;
        let min_signers = cfg.min_signers.ok_or(RosterError::MissingThreshold { n })?;
        if min_signers < FROST_MIN_PARTICIPANTS || min_signers > n_u16 {
            return Err(RosterError::BadThreshold {
                t: min_signers,
                n: n_u16,
            });
        }

        // Parse first, order second: the ordering rule is over the KEYS, so it
        // cannot be applied to a member whose key does not parse.
        let mut parsed: Vec<([u8; 32], String)> = Vec::with_capacity(n);
        for m in &cfg.members {
            let key = parse_xonly(&m.bifrost_id_pk).map_err(|reason| RosterError::BadKey {
                url: m.bifrost_url.clone(),
                reason,
            })?;
            let url = validate_bifrost_url(m.bifrost_url.trim()).map_err(|reason| {
                RosterError::BadUrl {
                    key: m.bifrost_id_pk.clone(),
                    reason,
                }
            })?;
            parsed.push((key, url));
        }
        parsed.sort_by_key(|(key, _)| *key);

        let mut seen_urls: BTreeSet<&str> = BTreeSet::new();
        for w in parsed.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(RosterError::DuplicateKey {
                    key: hex::encode(w[0].0),
                });
            }
        }
        for (_, url) in &parsed {
            if !seen_urls.insert(url.as_str()) {
                return Err(RosterError::DuplicateUrl { url: url.clone() });
            }
        }

        let members = parsed
            .into_iter()
            .enumerate()
            .map(|(i, (bifrost_id_pk, bifrost_url))| {
                // i < n <= u16::MAX by the check above, so the index fits.
                let identifier = Identifier::try_from(i as u16 + 1)
                    .expect("1..=n is a valid FROST identifier range");
                FederationMember {
                    identifier,
                    bifrost_id_pk,
                    bifrost_url,
                }
            })
            .collect();

        Ok(Self {
            min_signers,
            members,
        })
    }

    /// Number of members, `n`.
    #[must_use]
    pub fn len(&self) -> u16 {
        // `from_config` bounds the membership to u16.
        self.members.len() as u16
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Whether a MINORITY of members can move the treasury (`2t <= n`).
    ///
    /// Not refused — a deployment may deliberately weight availability over
    /// custody, and this key exists for the case where members are unreachable —
    /// but it is the one property of the threshold worth saying out loud before
    /// it is baked into a key: below this line, fewer than half the federation
    /// can sweep the whole treasury once the CSV delay passes.
    #[must_use]
    pub fn threshold_is_minority(&self) -> bool {
        u32::from(self.min_signers) * 2 <= u32::from(self.len())
    }

    /// This node's own member entry, located by its bifrost identity key.
    ///
    /// `None` must abort rather than fall back to an index: a node that is not in
    /// the list it is running the ceremony from would take a share nobody
    /// addressed to it.
    #[must_use]
    pub fn own(&self, bifrost_id_pk: &[u8; 32]) -> Option<&FederationMember> {
        self.members
            .iter()
            .find(|m| &m.bifrost_id_pk == bifrost_id_pk)
    }

    #[must_use]
    pub fn member(&self, identifier: Identifier) -> Option<&FederationMember> {
        self.members.iter().find(|m| m.identifier == identifier)
    }

    /// The roster in the shape the transport and the FROST rounds consume.
    ///
    /// `epoch` is 0 because there is none — the ceremony's namespace separation
    /// comes from [`crate::http::canonical::THRESHOLD_FEDERATION`], not from an
    /// epoch number this ceremony does not have.
    #[must_use]
    pub fn to_roster(&self) -> Roster {
        let participants: BTreeMap<Identifier, SpoInfo> = self
            .members
            .iter()
            .map(|m| {
                (
                    m.identifier,
                    SpoInfo {
                        identifier: m.identifier,
                        pool_id: m.address().to_vec(),
                        bifrost_url: m.bifrost_url.clone(),
                        bifrost_id_pk: m.bifrost_id_pk.to_vec(),
                    },
                )
            })
            .collect();
        Roster {
            epoch: 0,
            min_signers: self.min_signers,
            max_signers: self.len(),
            participants,
        }
    }

    /// Every member's identifier.
    #[must_use]
    pub fn ids(&self) -> BTreeSet<Identifier> {
        self.members.iter().map(|m| m.identifier).collect()
    }

    /// Resolve `--signers 1,3,4` to identifiers, refusing an index outside the
    /// roster or a set below the threshold.
    pub fn signers_from_indices(&self, indices: &[u16]) -> Result<BTreeSet<Identifier>, String> {
        let mut out = BTreeSet::new();
        for &i in indices {
            let id = Identifier::try_from(i).map_err(|e| format!("signer index {i}: {e}"))?;
            if self.member(id).is_none() {
                return Err(format!(
                    "signer index {i} is not a federation member — the roster has {} \
                     (indices 1..={})",
                    self.len(),
                    self.len()
                ));
            }
            out.insert(id);
        }
        if out.len() < usize::from(self.min_signers) {
            return Err(format!(
                "{} signer(s) named but the federation key is {}-of-{} — aggregation needs at \
                 least {} shares",
                out.len(),
                self.min_signers,
                self.len(),
                self.min_signers
            ));
        }
        Ok(out)
    }

    /// A stable digest of the CRYPTOGRAPHIC content of the roster: the threshold
    /// and the member keys, in identifier order.
    ///
    /// Endpoints are deliberately NOT in it. A member moving to a new URL keeps
    /// the same share of the same key, so binding the persisted state to its URL
    /// would report a routine operational edit as a changed federation — and the
    /// alarm that fires for everything is the one nobody reads. What this DOES
    /// catch is a member added, removed or re-keyed after the ceremony, which
    /// invalidates every share.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(DIGEST_TAG.len() + 4 + self.members.len() * 32);
        buf.extend_from_slice(DIGEST_TAG);
        buf.extend_from_slice(&self.min_signers.to_be_bytes());
        buf.extend_from_slice(&self.len().to_be_bytes());
        for m in &self.members {
            buf.extend_from_slice(&m.bifrost_id_pk);
        }
        blake2b_256(&buf)
    }

    /// The index assignment, for the operator to check against their peers'.
    /// Printed by every command that acts on the federation, because the FROST
    /// index is what `--signers` names and it is derived, never typed.
    #[must_use]
    pub fn table(&self) -> String {
        let mut out = format!(
            "federation: {}-of-{} (digest {})\n",
            self.min_signers,
            self.len(),
            hex::encode(&self.digest()[..8])
        );
        for m in &self.members {
            out.push_str(&format!(
                "  #{:<3} {}  {}\n",
                crate::frost::identifier_u16(m.identifier),
                hex::encode(m.bifrost_id_pk),
                m.bifrost_url
            ));
        }
        out
    }
}

/// Parse a 32-byte hex x-only key, checking it is actually a curve point.
///
/// Not every 32 bytes is one, and the ones that are not fail much later —
/// inside an ECDH the transport performs against this key — with an error that
/// names neither the member nor the config key it came from.
fn parse_xonly(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("not valid hex: {e}"))?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("must be 32 bytes, got {}", bytes.len()))?;
    UntweakedPublicKey::from_slice(&key).map_err(|e| format!("not a valid x-only point: {e}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FederationMemberConfig;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    /// A deterministic member key: secret `[byte; 32]`.
    fn key(byte: u8) -> [u8; 32] {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
            .x_only_public_key()
            .0
            .serialize()
    }

    fn member(byte: u8, url: &str) -> FederationMemberConfig {
        FederationMemberConfig {
            bifrost_id_pk: hex::encode(key(byte)),
            bifrost_url: url.to_string(),
        }
    }

    fn cfg(min_signers: Option<u16>, members: Vec<FederationMemberConfig>) -> FederationConfig {
        FederationConfig {
            min_signers,
            members,
        }
    }

    fn three() -> Vec<FederationMemberConfig> {
        vec![
            member(0x11, "http://a.example:8080"),
            member(0x22, "http://b.example:8080"),
            member(0x33, "http://c.example:8080"),
        ]
    }

    /// Indices follow `bifrost_id_pk` order, not the order the file lists members
    /// in — that is what makes every member's node compute the same numbering.
    #[test]
    fn indices_come_from_key_order_not_file_order() {
        let forward = FederationRoster::from_config(&cfg(Some(2), three())).expect("valid");
        let mut shuffled = three();
        shuffled.reverse();
        let reversed = FederationRoster::from_config(&cfg(Some(2), shuffled)).expect("valid");
        assert_eq!(forward, reversed);

        let mut keys: Vec<[u8; 32]> = forward.members.iter().map(|m| m.bifrost_id_pk).collect();
        let sorted = {
            let mut k = keys.clone();
            k.sort();
            k
        };
        assert_eq!(keys, sorted, "members must be in key order");
        keys.dedup();
        assert_eq!(keys.len(), 3);
        for (i, m) in forward.members.iter().enumerate() {
            assert_eq!(m.identifier, Identifier::try_from(i as u16 + 1).unwrap());
        }
    }

    /// The threshold is baked into the key, so it is required rather than
    /// defaulted — the failure mode of a default is a federation nobody chose.
    #[test]
    fn the_threshold_is_required_and_bounded() {
        let missing = FederationRoster::from_config(&cfg(None, three())).unwrap_err();
        assert!(
            matches!(missing, RosterError::MissingThreshold { n: 3 }),
            "got {missing:?}"
        );
        // The remedy names the recommendation (n - 1).
        assert!(missing.to_string().contains("set it to 2"));

        for bad in [0, 1, 4] {
            let e = FederationRoster::from_config(&cfg(Some(bad), three())).unwrap_err();
            assert!(
                matches!(e, RosterError::BadThreshold { n: 3, .. }),
                "t={bad}: got {e:?}"
            );
        }
        // t = n is allowed: a unanimous federation is a deliberate choice.
        assert!(FederationRoster::from_config(&cfg(Some(3), three())).is_ok());
    }

    /// `2t <= n` is legal but reported: below that line a minority can sweep the
    /// whole treasury once the CSV delay passes.
    #[test]
    fn a_minority_threshold_is_flagged_not_refused() {
        let minority = FederationRoster::from_config(&cfg(Some(2), four())).expect("valid");
        assert!(minority.threshold_is_minority(), "2 of 4 is a minority");
        let majority = FederationRoster::from_config(&cfg(Some(3), four())).expect("valid");
        assert!(!majority.threshold_is_minority(), "3 of 4 is not");
    }

    fn four() -> Vec<FederationMemberConfig> {
        let mut m = three();
        m.push(member(0x44, "http://d.example:8080"));
        m
    }

    #[test]
    fn a_federation_needs_members_and_at_least_two_of_them() {
        assert!(matches!(
            FederationRoster::from_config(&cfg(Some(2), vec![])).unwrap_err(),
            RosterError::NoMembers
        ));
        assert!(matches!(
            FederationRoster::from_config(&cfg(Some(2), vec![member(0x11, "http://a:1")]))
                .unwrap_err(),
            RosterError::TooFew { got: 1 }
        ));
    }

    #[test]
    fn duplicate_keys_and_endpoints_are_refused() {
        let dup_key = vec![
            member(0x11, "http://a.example:8080"),
            member(0x11, "http://b.example:8080"),
        ];
        assert!(matches!(
            FederationRoster::from_config(&cfg(Some(2), dup_key)).unwrap_err(),
            RosterError::DuplicateKey { .. }
        ));

        // Canonicalization collapses the default port and host case, so these
        // two spellings are one endpoint.
        let dup_url = vec![
            member(0x11, "http://A.example:80"),
            member(0x22, "http://a.example"),
        ];
        assert!(matches!(
            FederationRoster::from_config(&cfg(Some(2), dup_url)).unwrap_err(),
            RosterError::DuplicateUrl { .. }
        ));
    }

    #[test]
    fn malformed_keys_and_urls_name_the_member() {
        let bad_key = vec![
            FederationMemberConfig {
                bifrost_id_pk: "ff".repeat(32), // 32 bytes, but not a curve point
                bifrost_url: "http://a.example:8080".into(),
            },
            member(0x22, "http://b.example:8080"),
        ];
        let e = FederationRoster::from_config(&cfg(Some(2), bad_key)).unwrap_err();
        assert!(matches!(e, RosterError::BadKey { .. }), "got {e:?}");
        assert!(e.to_string().contains("a.example"), "{e}");

        let bad_url = vec![
            member(0x11, "ftp://a.example"),
            member(0x22, "http://b.example:8080"),
        ];
        let e = FederationRoster::from_config(&cfg(Some(2), bad_url)).unwrap_err();
        assert!(matches!(e, RosterError::BadUrl { .. }), "got {e:?}");
    }

    /// The transport address is derived from the key, so it cannot be mistyped —
    /// and it is what the ceremony's URLs and canonical bytes are keyed by.
    #[test]
    fn member_addresses_are_derived_from_the_key() {
        let roster = FederationRoster::from_config(&cfg(Some(2), three())).expect("valid");
        let spo_roster = roster.to_roster();
        assert_eq!(spo_roster.epoch, 0);
        assert_eq!(spo_roster.min_signers, 2);
        assert_eq!(spo_roster.max_signers, 3);
        for m in &roster.members {
            let info = &spo_roster.participants[&m.identifier];
            assert_eq!(info.pool_id, blake2b_224(&m.bifrost_id_pk).to_vec());
            assert_eq!(info.pool_id.len(), 28);
            assert_eq!(info.bifrost_id_pk, m.bifrost_id_pk.to_vec());
        }
    }

    /// The digest binds the threshold and the membership — the facts a persisted
    /// share depends on — and deliberately not the endpoints, which a member may
    /// change without invalidating anything.
    #[test]
    fn the_digest_covers_membership_and_threshold_but_not_urls() {
        let base = FederationRoster::from_config(&cfg(Some(2), three())).expect("valid");

        let moved = {
            let mut m = three();
            m[0].bifrost_url = "https://relocated.example".into();
            FederationRoster::from_config(&cfg(Some(2), m)).expect("valid")
        };
        assert_eq!(
            base.digest(),
            moved.digest(),
            "a URL change is not a re-key"
        );

        let retuned = FederationRoster::from_config(&cfg(Some(3), three())).expect("valid");
        assert_ne!(base.digest(), retuned.digest(), "threshold is in the key");

        let grown = FederationRoster::from_config(&cfg(Some(2), four())).expect("valid");
        assert_ne!(base.digest(), grown.digest(), "membership is in the key");
    }

    #[test]
    fn own_locates_this_node_by_its_key() {
        let roster = FederationRoster::from_config(&cfg(Some(2), three())).expect("valid");
        let me = roster.own(&key(0x22)).expect("member");
        assert_eq!(me.bifrost_id_pk, key(0x22));
        assert!(
            roster.own(&key(0x99)).is_none(),
            "a non-member is not found"
        );
    }

    #[test]
    fn signer_indices_are_checked_against_the_roster_and_the_threshold() {
        let roster = FederationRoster::from_config(&cfg(Some(2), three())).expect("valid");
        let set = roster.signers_from_indices(&[1, 3]).expect("valid pair");
        assert_eq!(set.len(), 2);

        let too_few = roster.signers_from_indices(&[2]).unwrap_err();
        assert!(too_few.contains("2-of-3"), "{too_few}");
        let unknown = roster.signers_from_indices(&[1, 9]).unwrap_err();
        assert!(unknown.contains("not a federation member"), "{unknown}");
    }
}
