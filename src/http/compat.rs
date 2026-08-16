//! What a peer must agree with this node about before a ceremony (WI-067).
//!
//! ## Why a version is a protocol value here
//!
//! heimdall's version decides bytes every SPO must produce identically — the TM
//! batch weights and the byte budget they feed, the leader election and its
//! cascade, the canonical payload layouts, and the embedded blueprint from which
//! every policy id is derived. Two nodes on different minors can therefore
//! compute different rosters, different addresses, or different signed bytes,
//! and the failure is the one this codebase keeps meeting: no error anywhere,
//! just a ceremony that never converges and no log line naming the cause.
//!
//! ## The rule, and its limit
//!
//! **`major.minor` must match; `patch` is free.** heimdall is `0.x`, where semver
//! puts the breaking position at MINOR — so "0.1 and 0.2 differ, 0.1.3 and 0.1.9
//! agree" is both the correct reading and what is wanted.
//!
//! That is a *convention*, and it is only as good as the discipline that no
//! consensus constant moves in a patch release. So a second value travels beside
//! it: the digest of the embedded blueprint, which is an exact fact rather than a
//! promise — a differing blueprint means differing policy ids, i.e. a different
//! bridge, whatever the version says.
//!
//! **What is deliberately NOT here is a digest over "the protocol constants".**
//! It was considered and rejected: such a digest is only correct if the list of
//! constants is complete, and a hand-maintained list that must be complete is the
//! same class of defect it is meant to catch — it would fail silently, in the
//! direction of saying two incompatible nodes agree. The blueprint digest is
//! mechanical (it hashes a file), the version is a human promise, and neither
//! pretends to be the other.

use serde::{Deserialize, Serialize};

/// This build's version — `major.minor.patch` from Cargo.
#[must_use]
pub fn own_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// First 16 hex chars of `blake2b_256` over the embedded CIP-57 blueprint.
///
/// Truncated because it is an equality check between peers, not a commitment
/// anybody signs: 64 bits is far past what a misconfiguration collides on, and a
/// short digest is one an operator can compare by eye in two log lines.
#[must_use]
pub fn own_blueprint_digest() -> String {
    blueprint_digest(crate::cardano::blueprint::EMBEDDED_BLUEPRINT)
}

fn blueprint_digest(blueprint: &str) -> String {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(blueprint.as_bytes());
    hex::encode(&hash.as_bytes()[..8])
}

/// What `/health` reports about the software behind it.
///
/// Both fields are `Option` on the reading side because a peer running a build
/// that predates this reports neither — see [`Compatibility::of`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerBuild {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub blueprint_digest: Option<String>,
}

impl PeerBuild {
    /// This node's own answer.
    #[must_use]
    pub fn own() -> Self {
        Self {
            version: Some(own_version().to_string()),
            blueprint_digest: Some(own_blueprint_digest()),
        }
    }
}

/// The verdict on one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    /// Same `major.minor` and same blueprint. Safe to run a ceremony with.
    Compatible,
    /// The peer reports no version at all — a build older than this check.
    ///
    /// ALLOWED, deliberately. Refusing here would make the very upgrade that
    /// introduces the check an outage: every node would reject every peer until
    /// the last one restarted. Revisit once no supported release omits it.
    Unknown,
    /// A definite mismatch, with both sides named so either log line is enough
    /// to diagnose it.
    Incompatible { reason: String },
}

impl Compatibility {
    /// Compare a peer's reported build against this node's.
    #[must_use]
    pub fn of(peer: &PeerBuild) -> Self {
        Self::between(peer, &PeerBuild::own())
    }

    /// Pure form, for tests: compare `peer` against `own`.
    #[must_use]
    pub fn between(peer: &PeerBuild, own: &PeerBuild) -> Self {
        let Some(theirs) = peer.version.as_deref() else {
            return Self::Unknown;
        };
        let ours = own.version.as_deref().unwrap_or_default();
        if minor_series(theirs) != minor_series(ours) {
            return Self::Incompatible {
                reason: format!("version {theirs} against our {ours}"),
            };
        }
        // Only compared when BOTH report one: a peer new enough to send a
        // version but not a digest is not a bridge mismatch, it is a gap in what
        // it reports, and `Unknown` is reserved for the version.
        if let (Some(t), Some(o)) = (
            peer.blueprint_digest.as_deref(),
            own.blueprint_digest.as_deref(),
        ) && t != o
        {
            return Self::Incompatible {
                reason: format!(
                    "same version {theirs}, but blueprint {t} against our {o} — \
                     different contracts, so a different bridge"
                ),
            };
        }
        Self::Compatible
    }

    #[must_use]
    pub fn is_incompatible(&self) -> bool {
        matches!(self, Self::Incompatible { .. })
    }
}

/// `major.minor` of a semver string, as text.
///
/// Text rather than parsed numbers so an unparseable version compares unequal to
/// everything except an identical one — the safe direction. A build reporting
/// nonsense should be excluded, not silently treated as `0.0`.
fn minor_series(v: &str) -> &str {
    let mut parts = v.match_indices('.');
    match (parts.next(), parts.next()) {
        (Some(_), Some((second, _))) => &v[..second],
        // Fewer than two dots: no patch position to ignore, so the whole string
        // is the series.
        _ => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(v: &str, d: &str) -> PeerBuild {
        PeerBuild {
            version: Some(v.into()),
            blueprint_digest: Some(d.into()),
        }
    }

    /// The rule the item asks for, on 0.x where MINOR is the breaking position.
    #[test]
    fn patch_is_free_and_minor_is_not() {
        assert_eq!(
            Compatibility::between(&build("0.1.3", "aa"), &build("0.1.9", "aa")),
            Compatibility::Compatible
        );
        assert!(
            Compatibility::between(&build("0.2.0", "aa"), &build("0.1.0", "aa")).is_incompatible()
        );
        assert!(
            Compatibility::between(&build("1.1.0", "aa"), &build("0.1.0", "aa")).is_incompatible()
        );
    }

    /// Both sides are named, so whichever node's log an operator reads first is
    /// enough to diagnose it. The excluded node runs the same comparison from its
    /// own side, so it learns why it was dropped rather than seeing silence.
    #[test]
    fn a_mismatch_names_both_versions() {
        let Compatibility::Incompatible { reason } =
            Compatibility::between(&build("0.2.5", "aa"), &build("0.1.0", "aa"))
        else {
            panic!("expected a mismatch");
        };
        assert!(reason.contains("0.2.5"), "{reason}");
        assert!(reason.contains("0.1.0"), "{reason}");
    }

    /// The blueprint catches what the version convention cannot: a patch release
    /// that moved the contracts.
    #[test]
    fn the_same_version_over_a_different_blueprint_is_incompatible() {
        let v = Compatibility::between(&build("0.1.0", "aaaa"), &build("0.1.0", "bbbb"));
        assert!(v.is_incompatible(), "{v:?}");
        let Compatibility::Incompatible { reason } = v else {
            unreachable!()
        };
        assert!(reason.contains("different bridge"), "{reason}");
    }

    /// A build predating this check reports nothing and is ALLOWED — otherwise
    /// the upgrade introducing the check is itself the outage.
    #[test]
    fn a_peer_reporting_no_version_is_unknown_not_incompatible() {
        assert_eq!(
            Compatibility::of(&PeerBuild::default()),
            Compatibility::Unknown
        );
        assert!(!Compatibility::of(&PeerBuild::default()).is_incompatible());
    }

    /// A version but no digest is a reporting gap, not a bridge mismatch.
    #[test]
    fn a_version_without_a_digest_is_compatible_on_the_version_alone() {
        let peer = PeerBuild {
            version: Some("0.1.0".into()),
            blueprint_digest: None,
        };
        assert_eq!(
            Compatibility::between(&peer, &build("0.1.7", "aa")),
            Compatibility::Compatible
        );
    }

    /// An unparseable version matches only itself — excluded rather than
    /// silently read as some default.
    #[test]
    fn an_unparseable_version_matches_only_itself() {
        assert_eq!(minor_series("weird"), "weird");
        assert_eq!(minor_series("0.1"), "0.1");
        assert_eq!(minor_series("0.1.2"), "0.1");
        assert_eq!(minor_series("0.1.2-rc.1"), "0.1");
        assert!(
            Compatibility::between(&build("weird", "aa"), &build("0.1.0", "aa")).is_incompatible()
        );
    }

    /// This node's own answer compares equal to itself — the property every
    /// healthy roster depends on.
    #[test]
    fn own_build_is_compatible_with_itself() {
        assert_eq!(
            Compatibility::of(&PeerBuild::own()),
            Compatibility::Compatible
        );
        assert_eq!(own_blueprint_digest().len(), 16);
    }

    /// The digest tracks the blueprint, which is the whole point of carrying it.
    #[test]
    fn the_digest_changes_with_the_blueprint() {
        assert_ne!(blueprint_digest("{}"), blueprint_digest("{ }"));
        assert_eq!(blueprint_digest("{}"), blueprint_digest("{}"));
    }
}
