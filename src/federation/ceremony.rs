//! The federation DKG: FROST rounds 1 → 2 → 3 over a typed-in roster, with no
//! chain state of any kind.
//!
//! ## What this deliberately does NOT do
//!
//! The epoch ceremony ([`crate::epoch::dkg`]) exists to survive a hostile,
//! changing candidate set: it freezes a live subset at a schedule-anchored
//! deadline, puts the survivors through a stake-weighted quorum gate, reruns over
//! a reduced set under a fresh attempt namespace, and turns provable misbehaviour
//! into on-chain fault proofs. Every one of those needs something this ceremony
//! does not have — an epoch boundary to anchor to, stake to weight by, a registry
//! to reduce within, a ban list to publish to.
//!
//! So this driver is the small one: **wait for everybody, then run the rounds**.
//! No subset, no rerun, no gate. That is not a simplification of the epoch rule,
//! it is a different rule for a different situation — a member absent from THIS
//! ceremony is a member who can never sign the resulting key, so proceeding
//! without them does not degrade the federation, it forms a different one.
//!
//! ## What it does check
//!
//! The roster is typed into `n` separate config files, so the failure this
//! ceremony actually meets is not a Byzantine member — it is two members whose
//! files disagree. Two disagreements are worth naming precisely, because both
//! otherwise present as an unattributable stall:
//!
//! - **A different threshold.** A Round-1 package carries exactly `t` commitment
//!   points, so a member running another `[federation].min_signers` is visible
//!   directly in its payload — [`check_thresholds_agree`] names it, rather than
//!   letting `dkg_part2` fail later with "Incorrect number of commitments".
//! - **A different member list.** That changes the index assignment, so the
//!   member's payloads are signed under an identifier nobody expects, the
//!   transport refuses them, and it simply never arrives. It cannot be
//!   distinguished from absence here — so the timeout error says so.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Identifier;
use rand_core::{CryptoRng, RngCore};
use tracing::{info, warn};

use crate::epoch::state::{EpochError, GroupKeys, SpoInfo};
use crate::epoch::traits::PeerNetwork;
use crate::federation::roster::FederationRoster;
use crate::frost::participant;
use crate::http::frost_bridge;
use crate::http::wire::DkgNamespace;

/// How often to restate who the ceremony is still waiting for. A federation
/// forming across time zones can wait hours; a silent process for hours is
/// indistinguishable from a hung one.
const PROGRESS_EVERY: Duration = Duration::from_secs(30);

/// Timing knobs of one ceremony.
#[derive(Debug, Clone, Copy)]
pub struct CeremonyLimits {
    /// Gap between polls of the peers that have not answered yet.
    pub poll_interval: Duration,
    /// Optional per-phase deadline. `None` — the default and the intended
    /// production setting — waits indefinitely, because a forming federation has
    /// no deadline to be late for: there is no epoch boundary to miss and
    /// nothing downstream is blocked on giving up. A deadline is for tests and
    /// for an operator who wants the command to return rather than sit.
    pub phase_timeout: Option<Duration>,
}

impl CeremonyLimits {
    /// Wait for as long as it takes.
    #[must_use]
    pub fn unbounded(poll_interval: Duration) -> Self {
        Self {
            poll_interval,
            phase_timeout: None,
        }
    }

    /// Give up on any one phase after `timeout`, naming who was missing.
    #[must_use]
    pub fn bounded(poll_interval: Duration, timeout: Duration) -> Self {
        Self {
            poll_interval,
            phase_timeout: Some(timeout),
        }
    }
}

#[derive(Debug)]
pub enum CeremonyError {
    /// The peer transport failed (not a peer being absent — that is
    /// [`Self::Incomplete`]).
    Transport(EpochError),
    /// FROST refused the material.
    Frost(String),
    /// A phase deadline passed with members still missing.
    Incomplete {
        phase: &'static str,
        missing: Vec<String>,
    },
    /// This node holds a share, but the pinned signer set does not include it.
    NotASigner { me: u16 },
    /// A member published a Round-1 package for a different threshold, i.e. its
    /// `[federation].min_signers` differs from ours.
    ThresholdMismatch {
        member: String,
        theirs: usize,
        ours: u16,
    },
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "federation ceremony transport: {e}"),
            Self::Frost(e) => write!(f, "federation ceremony: {e}"),
            Self::NotASigner { me } => write!(
                f,
                "this node is member #{me}, which the signer set does not name. Every \
                 participant in a signing session runs it with the SAME --signers list, and a \
                 node outside that list has no share to contribute — either add #{me} to the \
                 list every member passes, or run the command on one of the members it does \
                 name"
            ),
            Self::Incomplete { phase, missing } => write!(
                f,
                "federation {phase} incomplete: still waiting for {}. Every listed member must \
                 attend — a member absent from the ceremony can never sign the key it produces, \
                 so there is no reduced set to fall back to. Note that a member running a \
                 DIFFERENT [federation].members list is indistinguishable from an absent one \
                 here: the list decides the FROST index, so its payloads are published under an \
                 index nobody expects and are refused. Check that every member's list and \
                 min_signers match, then run the ceremony again",
                missing.join(", ")
            ),
            Self::ThresholdMismatch {
                member,
                theirs,
                ours,
            } => write!(
                f,
                "federation member {member} published a Round-1 package for a {theirs}-of-n key \
                 but this node is running {ours}-of-n. [federation].min_signers must be \
                 identical in every member's config — it is baked into the key, so two values \
                 cannot both be right"
            ),
        }
    }
}

impl std::error::Error for CeremonyError {}

impl From<EpochError> for CeremonyError {
    fn from(e: EpochError) -> Self {
        Self::Transport(e)
    }
}

/// Run the federation DKG and return this node's share of `federation_setup_Y`.
///
/// `me` is this node's identifier in `roster` — located by its own bifrost key,
/// never assumed, because the index is derived from the member list and a node
/// running the wrong one would take a share nobody addressed to it.
pub async fn run_dkg(
    peers: &Arc<dyn PeerNetwork>,
    roster: &FederationRoster,
    me: Identifier,
    rng: &mut (impl RngCore + CryptoRng),
    limits: &CeremonyLimits,
) -> Result<GroupKeys, CeremonyError> {
    let ns = DkgNamespace::federation();
    let spo_roster = roster.to_roster();
    let n = roster.len();
    let t = roster.min_signers;
    let peer_infos: Vec<SpoInfo> = spo_roster.peers_of(me).into_iter().cloned().collect();

    info!(
        "[federation] ceremony starting: {t}-of-{n}, this node is #{}",
        crate::frost::identifier_u16(me)
    );
    if roster.threshold_is_minority() {
        warn!(
            "[federation] min_signers {t} of {n} is a MINORITY: fewer than half the federation \
             will be able to move the whole treasury once federation_csv_blocks have passed. \
             This is baked into the key — stop now if it was not deliberate"
        );
    }

    await_presence(peers, &peer_infos, limits).await?;

    // ── Round 1 ────────────────────────────────────────────────────────
    info!("[federation] round 1: generating this node's polynomial and commitments");
    let (round1_secret, round1_mine) = participant::dkg_part1(me, n, t, rng)
        .map_err(|e| CeremonyError::Frost(format!("dkg_part1: {e}")))?;
    peers.publish_dkg_round1(ns, me, &round1_mine).await?;

    let mut round1: BTreeMap<Identifier, frost::keys::dkg::round1::Package> =
        BTreeMap::from([(me, round1_mine)]);
    poll_all(
        peers,
        "round 1",
        &peer_infos,
        limits,
        &mut round1,
        |peer| async move { peers.fetch_dkg_round1(ns, &peer).await },
    )
    .await?;
    check_thresholds_agree(roster, &round1)?;

    // ── Round 2 ────────────────────────────────────────────────────────
    info!("[federation] round 2: encrypting one secret share per member");
    let peer_round1: BTreeMap<_, _> = round1
        .iter()
        .filter(|(id, _)| **id != me)
        .map(|(id, pkg)| (*id, pkg.clone()))
        .collect();
    let (round2_secret, round2_mine) = participant::dkg_part2(round1_secret, &peer_round1)
        .map_err(|e| CeremonyError::Frost(format!("dkg_part2: {e}")))?;

    let recipients: Vec<(SpoInfo, _)> = round2_mine
        .into_iter()
        .map(|(rid, pkg)| {
            spo_roster
                .participants
                .get(&rid)
                .cloned()
                .map(|info| (info, pkg))
                .ok_or_else(|| {
                    CeremonyError::Frost(format!("round 2 recipient {rid:?} is not in the roster"))
                })
        })
        .collect::<Result<_, _>>()?;
    let my_commitments = own_commitments(&round1, me)?;
    peers
        .publish_dkg_round2(ns, me, &my_commitments, &recipients)
        .await?;

    let mut round2: BTreeMap<Identifier, frost::keys::dkg::round2::Package> = BTreeMap::new();
    let commitments_by_sender = commitments_by_sender(&round1)?;
    poll_all(peers, "round 2", &peer_infos, limits, &mut round2, |peer| {
        let sender = commitments_by_sender
            .get(&peer.identifier)
            .cloned()
            .unwrap_or_default();
        async move { peers.fetch_dkg_round2(ns, &peer, me, &sender).await }
    })
    .await?;

    // ── Part 3 ─────────────────────────────────────────────────────────
    info!("[federation] part 3: verifying every share and deriving the group key");
    let (key_package, public_key_package) =
        participant::dkg_part3(&round2_secret, &peer_round1, &round2)
            .map_err(|e| CeremonyError::Frost(format!("dkg_part3: {e}")))?;
    // The same coherence check the epoch ceremony makes, for the same reason and
    // with more at stake: this key does not rotate, so an incoherent output would
    // lock the recovery path behind material nobody can sign with.
    crate::epoch::dkg::check_dkg_output_coherent(me, &key_package, &public_key_package)
        .map_err(|e| CeremonyError::Frost(e.to_string()))?;

    Ok(GroupKeys {
        verifying_key: *public_key_package.verifying_key(),
        public_key_package,
        key_package,
    })
}

/// Wait until every other member answers `/health`.
///
/// Advisory — a member healthy now can vanish before Round 1 — but it turns the
/// common case (somebody has not started their node yet) into a message naming
/// them, before any secret material is generated.
async fn await_presence(
    peers: &Arc<dyn PeerNetwork>,
    peer_infos: &[SpoInfo],
    limits: &CeremonyLimits,
) -> Result<(), CeremonyError> {
    let started = Instant::now();
    let mut last_report = Instant::now();
    let mut announced = false;
    loop {
        let mut missing = Vec::new();
        for peer in peer_infos {
            if !peers.check_health(peer).await {
                missing.push(peer.bifrost_url.clone());
            }
        }
        if missing.is_empty() {
            info!(
                "[federation] all {} other member(s) are online",
                peer_infos.len()
            );
            return Ok(());
        }
        if !announced || last_report.elapsed() >= PROGRESS_EVERY {
            info!(
                "[federation] waiting for {} of {} member(s) to come online: {}",
                missing.len(),
                peer_infos.len(),
                missing.join(", ")
            );
            last_report = Instant::now();
            announced = true;
        }
        if let Some(timeout) = limits.phase_timeout
            && started.elapsed() >= timeout
        {
            return Err(CeremonyError::Incomplete {
                phase: "presence check",
                missing,
            });
        }
        tokio::time::sleep(limits.poll_interval).await;
    }
}

/// Poll every peer for one round's payload until ALL have delivered.
///
/// The n-of-n rule lives here: unlike [`crate::epoch::dkg`]'s pollers, which
/// return a partial set for the caller to gate, this one only returns when the
/// set is complete, or fails naming who is missing.
/// `fetch` takes the peer BY VALUE: a future that borrowed the `&SpoInfo` it was
/// built from would need a lifetime the generic `Fut` cannot express (the same
/// wall [`crate::epoch::signing::poll_sign_round`] met and answered with a
/// trait). Cloning a member per poll costs nothing beside the HTTP round trip it
/// precedes.
pub(crate) async fn poll_all<T, F, Fut>(
    peers: &Arc<dyn PeerNetwork>,
    phase: &'static str,
    peer_infos: &[SpoInfo],
    limits: &CeremonyLimits,
    out: &mut BTreeMap<Identifier, T>,
    fetch: F,
) -> Result<(), CeremonyError>
where
    F: Fn(SpoInfo) -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>, EpochError>>,
{
    let started = Instant::now();
    let mut last_report = Instant::now();
    loop {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(payload) = fetch(peer.clone()).await? {
                info!(
                    "[federation] {phase}: received from {} ({}/{})",
                    peer.bifrost_url,
                    out.len() + 1,
                    peer_infos.len() + 1
                );
                out.insert(peer.identifier, payload);
            }
        }
        let missing: Vec<&SpoInfo> = peer_infos
            .iter()
            .filter(|p| !out.contains_key(&p.identifier))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        if last_report.elapsed() >= PROGRESS_EVERY {
            info!(
                "[federation] {phase}: still waiting for {}",
                missing
                    .iter()
                    .map(|p| p.bifrost_url.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            last_report = Instant::now();
        }
        if let Some(timeout) = limits.phase_timeout
            && started.elapsed() >= timeout
        {
            return Err(CeremonyError::Incomplete {
                phase,
                missing: diagnose_missing(peers, &missing).await,
            });
        }
        tokio::time::sleep(limits.poll_interval).await;
    }
}

/// Why each still-missing member is missing, as far as this node can tell.
///
/// The transport cannot distinguish a 404 from a refused connection — both are
/// "nothing to fetch" ([`crate::http::peer_network`]'s `fetch_raw`) — and the two
/// have opposite remedies: a member whose endpoint is dead has exited or was
/// never started, while one that answers but publishes nothing is on a different
/// member list, a different threshold, or stuck earlier in its own ceremony. One
/// health check per missing member at the deadline separates them, which is worth
/// far more than it costs on a path that has already waited minutes.
async fn diagnose_missing(peers: &Arc<dyn PeerNetwork>, missing: &[&SpoInfo]) -> Vec<String> {
    let mut out = Vec::with_capacity(missing.len());
    for peer in missing {
        let note = if peers.check_health(peer).await {
            "reachable, but published nothing for this round"
        } else {
            "unreachable — not started, or its process has already exited"
        };
        out.push(format!("{} ({note})", peer.bifrost_url));
    }
    out
}

/// Refuse a ceremony whose members disagree about `t`.
///
/// A Round-1 package's commitment vector is exactly `t` points long, so this
/// reads the peer's configured threshold straight off its payload — the one
/// cross-config disagreement that IS directly observable, as opposed to a
/// differing member list, which only shows up as absence.
fn check_thresholds_agree(
    roster: &FederationRoster,
    round1: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
) -> Result<(), CeremonyError> {
    for (id, pkg) in round1 {
        let (commitments, _sigma) = frost_bridge::round1_fields(pkg)
            .map_err(|e| CeremonyError::Frost(format!("round1 fields: {e}")))?;
        if commitments.len() != usize::from(roster.min_signers) {
            return Err(CeremonyError::ThresholdMismatch {
                member: roster.member(*id).map_or_else(
                    || format!("{id:?}"),
                    crate::federation::FederationMember::label,
                ),
                theirs: commitments.len(),
                ours: roster.min_signers,
            });
        }
    }
    Ok(())
}

/// This node's own commitment vector, which Round 2 publishes alongside the
/// encrypted shares so a recipient can verify each share against it.
fn own_commitments(
    round1: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
    me: Identifier,
) -> Result<Vec<[u8; crate::http::canonical::POINT_LEN]>, CeremonyError> {
    let mine = round1
        .get(&me)
        .ok_or_else(|| CeremonyError::Frost("this node's own round 1 package is missing".into()))?;
    let (commitments, _sigma) = frost_bridge::round1_fields(mine)
        .map_err(|e| CeremonyError::Frost(format!("round1 fields: {e}")))?;
    Ok(commitments)
}

/// Every sender's commitment vector, so a Round-2 fetch can verify the share it
/// receives against the polynomial its sender committed to in Round 1.
fn commitments_by_sender(
    round1: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
) -> Result<BTreeMap<Identifier, Vec<[u8; crate::http::canonical::POINT_LEN]>>, CeremonyError> {
    round1
        .iter()
        .map(|(id, pkg)| {
            frost_bridge::round1_fields(pkg)
                .map(|(commitments, _sigma)| (*id, commitments))
                .map_err(|e| CeremonyError::Frost(format!("round1 fields: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FederationConfig, FederationMemberConfig};
    use crate::epoch::mocks::{MockPeerHub, MockPeerNetwork, OsRngSource};
    use crate::epoch::traits::RngSource;
    use crate::frost::xonly::group_xonly;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    fn member_key(byte: u8) -> String {
        let secp = Secp256k1::new();
        hex::encode(
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
                .x_only_public_key()
                .0
                .serialize(),
        )
    }

    fn roster(min_signers: u16, n: u8) -> FederationRoster {
        FederationRoster::from_config(&FederationConfig {
            min_signers: Some(min_signers),
            members: (1..=n)
                .map(|b| FederationMemberConfig {
                    bifrost_id_pk: member_key(b),
                    bifrost_url: format!("http://m{b}.example:8080"),
                })
                .collect(),
        })
        .expect("valid roster")
    }

    fn limits() -> CeremonyLimits {
        CeremonyLimits::bounded(Duration::from_millis(5), Duration::from_secs(20))
    }

    /// Run one member's ceremony against a shared hub. `roster` is that member's
    /// OWN view of the federation, so a test can give one member a different one.
    fn spawn(
        hub: Arc<MockPeerHub>,
        roster: FederationRoster,
        me: Identifier,
        limits: CeremonyLimits,
    ) -> tokio::task::JoinHandle<Result<GroupKeys, CeremonyError>> {
        tokio::spawn(async move {
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, hub));
            let mut rng = OsRngSource.rng(b"federation-dkg");
            run_dkg(&peers, &roster, me, &mut rng, &limits).await
        })
    }

    fn id(n: u16) -> Identifier {
        Identifier::try_from(n).unwrap()
    }

    /// The acceptance property: a ceremony run from a typed-in peer list, with no
    /// chain state of any kind, and every member derives the SAME Y_federation —
    /// which is what gets published at Config #11 and hashed into both Taproot
    /// trees, so a single disagreeing member would mean a different treasury.
    #[tokio::test]
    async fn every_member_derives_the_same_federation_key() {
        let roster = roster(2, 3);
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for i in 1..=3u16 {
            handles.push(spawn(hub.clone(), roster.clone(), id(i), limits()));
        }
        let mut keys = Vec::new();
        for h in handles {
            keys.push(h.await.unwrap().expect("ceremony completes"));
        }

        let y0 = group_xonly(&keys[0].verifying_key).unwrap().xonly;
        for k in &keys[1..] {
            assert_eq!(
                group_xonly(&k.verifying_key).unwrap().xonly,
                y0,
                "every member must derive the same Y_federation"
            );
        }
        // Each member holds its own share of that one key, at its own index.
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(*k.key_package.identifier(), id(i as u16 + 1));
            assert_eq!(k.key_package.min_signers(), &2);
        }
    }

    /// Presence is n-of-n. Unlike the epoch ceremony — which gates the survivors
    /// on stake and reruns over a reduced set — a missing member here is fatal
    /// and named: it could never sign the key the others would have formed.
    #[tokio::test]
    async fn a_missing_member_is_fatal_and_named_never_reduced_away() {
        let roster = roster(2, 3);
        let hub = MockPeerHub::new();
        let short = CeremonyLimits::bounded(Duration::from_millis(5), Duration::from_millis(50));
        // Member 3 never starts, even though 2 of 3 would clear any threshold.
        let handles = vec![
            spawn(hub.clone(), roster.clone(), id(1), short),
            spawn(hub.clone(), roster.clone(), id(2), short),
        ];
        for h in handles {
            match h.await.unwrap() {
                Err(CeremonyError::Incomplete { missing, .. }) => {
                    // Named AND diagnosed: the mock answers health checks, so the
                    // absent member reads as "published nothing" rather than
                    // "unreachable" — the two point at different remedies.
                    assert_eq!(missing.len(), 1);
                    assert!(
                        missing[0].starts_with("http://m3.example:8080"),
                        "{missing:?}"
                    );
                    assert!(missing[0].contains("published nothing"), "{missing:?}");
                }
                other => panic!(
                    "expected Incomplete naming the absent member, got {:?}",
                    other.map(|_| "ok")
                ),
            }
        }
    }

    /// Two members whose `[federation].min_signers` disagree: the commitment
    /// vector length gives it away in Round 1, so it is reported as the config
    /// mismatch it is rather than surfacing as an opaque `dkg_part2` failure.
    #[tokio::test]
    async fn a_member_running_a_different_threshold_is_named() {
        let hub = MockPeerHub::new();
        let ours = roster(2, 3);
        let theirs = roster(3, 3);
        let short = CeremonyLimits::bounded(Duration::from_millis(5), Duration::from_secs(5));
        let mine = spawn(hub.clone(), ours.clone(), id(1), short);
        let _peer2 = spawn(hub.clone(), ours, id(2), short);
        let _peer3 = spawn(hub.clone(), theirs, id(3), short);

        match mine.await.unwrap() {
            Err(CeremonyError::ThresholdMismatch { theirs, ours, .. }) => {
                assert_eq!((theirs, ours), (3, 2));
            }
            other => panic!("expected ThresholdMismatch, got {:?}", other.map(|_| "ok")),
        }
    }
}
