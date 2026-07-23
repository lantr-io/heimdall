//! DKG Round 0: the eligible roster, stake-weighted threshold, and
//! participant ordering (WI-012).
//!
//! At the epoch boundary the candidate set for the epoch's DKG is
//!
//! ```text
//! eligible(E) = registered SPOs (WI-010)
//!             − pools actively banned for E (WI-011)
//!             − pools with an unusable / duplicate bifrost_url
//! ```
//!
//! and the FROST threshold is **stake-weighted**: `t` = the smallest `k`
//! such that the combined active stake of the `k` LOWEST-stake eligible SPOs
//! exceeds [`SECURITY_THRESHOLD_PERCENT`]% of the total eligible stake. If
//! even the weakest `k` exceed it, then ANY `k` signers do — so any `t`-of-n
//! quorum controls a majority of stake (the spec's Y_51 guarantee).
//!
//! Participants are ordered lexicographically by `bifrost_id_pk` (the spec's
//! DKG ordering — distinct from the on-chain list's `pool_id` order) and
//! assigned FROST identifiers `1..=n`.
//!
//! ## Two deliberate departures from the original WI-012 sketch
//!
//! - **Exclude-the-offender, not reject-all.** A pool whose registered
//!   `bifrost_url` is unusable or collides with another's is dropped from
//!   the eligible set (recorded in [`DkgContext::excluded`]), not allowed to
//!   brick the whole roster. On-chain registration is permissionless and
//!   doesn't validate URLs, so a bad URL is expected adversarial input; all
//!   nodes see the same chain data and compute the identical reduced set, so
//!   consensus holds. (Ban and stake filtering are eligibility decisions in
//!   the same spirit.)
//! - **No `t = 1`.** frost-core rejects `min_signers < 2`, and for `n >= 2`
//!   the smallest single stake is `<= 50%`, so the stake-weighted `t` is
//!   always `>= 2` anyway. A roster below [`FROST_MIN_PARTICIPANTS`] is a
//!   hard [`DkgRosterError::TooFew`] — solo testing needs two instances.

use std::collections::{BTreeMap, BTreeSet};

use frost_secp256k1_tr::Identifier;

use crate::cardano::ban_list::{BanListError, BanListSource};
use crate::cardano::bf_http;
use crate::cardano::hash::pool_id_bech32;
use crate::cardano::roster::{
    FROST_MIN_PARTICIPANTS, RegistryRosterSource, RegistrySnapshot, RosterError,
    validate_bifrost_url,
};
use crate::cardano::stake::{StakeSource, fetch_pool_stake_src};
use crate::epoch::state::{Roster, SpoInfo};

/// Security threshold as a percentage of total eligible stake: any `t`
/// signers must control STRICTLY MORE than this (spec: Y_51 → 51%).
pub const SECURITY_THRESHOLD_PERCENT: u128 = 51;

#[derive(Debug)]
pub enum DkgRosterError {
    /// Fewer eligible SPOs than FROST DKG can run with.
    TooFew { got: usize },
    /// More eligible SPOs than FROST identifiers (`u16`).
    TooMany(usize),
    /// No stake provided for an eligible pool — cannot compute `t` honestly,
    /// so the whole attempt is void (spec: stake failure is fatal).
    MissingStake { pool_id: Vec<u8> },
    /// Total eligible stake is zero — `t` is undefined (would need every
    /// signer). Real eligible pools always have delegated stake; zero means
    /// the candidates aren't actually registered Cardano SPOs.
    ZeroStake,
}

impl std::fmt::Display for DkgRosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFew { got } => write!(
                f,
                "only {got} eligible SPO(s) after bans/URL filtering — FROST DKG needs at \
                 least {FROST_MIN_PARTICIPANTS}"
            ),
            Self::TooMany(n) => write!(f, "{n} eligible SPOs exceed u16 FROST identifiers"),
            Self::MissingStake { pool_id } => {
                write!(f, "no stake for eligible pool {}", hex::encode(pool_id))
            }
            Self::ZeroStake => write!(f, "total eligible stake is zero — cannot derive threshold"),
        }
    }
}

impl std::error::Error for DkgRosterError {}

/// Why a registered SPO was dropped from the eligible set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExclusionReason {
    /// Actively banned for this epoch (WI-011).
    Banned,
    /// `bifrost_url` is not a usable http(s) base URL.
    BadUrl(String),
    /// `bifrost_url` (canonicalized) is shared with another registration.
    DuplicateUrl(String),
}

impl std::fmt::Display for ExclusionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Banned => write!(f, "banned"),
            Self::BadUrl(why) => write!(f, "bad bifrost_url: {why}"),
            Self::DuplicateUrl(url) => write!(f, "duplicate bifrost_url {url:?}"),
        }
    }
}

/// A dropped registration plus the reason (for diagnostics / fault tracking).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedSpo {
    pub pool_id: Vec<u8>,
    pub reason: ExclusionReason,
}

/// One eligible DKG participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgParticipant {
    /// FROST index `1..=n` (== `identifier` as `u16`), by `bifrost_id_pk` order.
    pub index: u16,
    pub identifier: Identifier,
    pub pool_id: Vec<u8>,
    pub bifrost_id_pk: Vec<u8>,
    /// Canonicalized base URL (see [`validate_bifrost_url`]).
    pub bifrost_url: String,
    /// Epoch-snapshot active stake (lovelace).
    pub active_stake: u64,
}

/// The resolved Round-0 context for one epoch's DKG attempt.
#[derive(Debug, Clone)]
pub struct DkgContext {
    pub epoch: u64,
    pub attempt: u32,
    /// FROST threshold `t` (`>= FROST_MIN_PARTICIPANTS`).
    pub threshold: u16,
    /// Sum of eligible active stake (lovelace).
    pub total_stake: u64,
    /// Eligible participants, ordered by `bifrost_id_pk`.
    pub participants: Vec<DkgParticipant>,
    /// Registered SPOs dropped from the eligible set, with reasons.
    pub excluded: Vec<ExcludedSpo>,
    /// Wall-clock anchor (Unix ms) for the ceremony's round schedule. The
    /// fetch path sets it to the epoch boundary from the chain schedule; the
    /// epoch machine then re-anchors it to the ceremony window's grid line
    /// before entering DKG (N21). The ceremony anchors its Round 1/2
    /// deadlines to this so every node freezes the live/qualified subsets at
    /// the same chain-time instant (WI-014 #6). `None` for the mock /
    /// no-registry fallback → relative per-round timeouts instead.
    pub schedule_anchor_ms: Option<i64>,
    /// Chain posix-time (ms) of the latest block when this context was read from
    /// the chain — the freshness stamp for [`ChainView`]. Carried forward
    /// unchanged by `reduced_to` (a rerun uses the same read). `0` on the
    /// mock/fixture path, which has no chain.
    pub read_time_ms: i64,
}

/// A node's view of the on-chain candidate set. Published UNSIGNED alongside
/// each DKG payload so a peer can tell a genuine cross-view disagreement (both
/// honest, different chain reads near a ban) from a corrupt payload, and
/// schedule a settling re-read instead of blindly retrying. It is a hint, never
/// authoritative: the chain stays the only source of truth, and a lying peer
/// only gets its own payload dropped.
///
/// NOT part of `canonical_bytes` and NOT compared in the equivocation check —
/// two payloads with identical signed content but different `ChainView` are the
/// same payload, not an equivocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainView {
    /// `blake2b_256` of the eligible `pool_id`s in ceremony (bifrost-key) order.
    /// Two nodes on the same candidate set have the same digest; a ban that one
    /// has seen and the other hasn't flips it.
    pub digest: [u8; 32],
    /// Eligible participant count — a cheap, human-legible discriminator.
    pub n: u16,
    /// Chain posix-time (ms) of the latest block this view was read from — a
    /// **freshness** marker, deliberately finer than the epoch. On a digest
    /// disagreement, the node with the OLDER `read_time_ms` is behind (it read
    /// the chain before the disagreeing event, e.g. a ban, settled into its
    /// view) and is the one that should re-read. This is what makes the
    /// reconcile directional instead of a blind wait, and it distinguishes
    /// states WITHIN one epoch — exactly where the ban-settlement disagreement
    /// lives. Chain-derived (a block time), never a local clock, so it is
    /// comparable across nodes.
    pub read_time_ms: i64,
}

impl DkgContext {
    /// This node's chain-view for the current context.
    #[must_use]
    pub fn chain_view(&self) -> ChainView {
        let mut buf = Vec::with_capacity(self.participants.len() * 28);
        for p in &self.participants {
            buf.extend_from_slice(&p.pool_id);
        }
        ChainView {
            digest: crate::cardano::hash::blake2b_256(&buf),
            n: u16::try_from(self.participants.len()).unwrap_or(u16::MAX),
            read_time_ms: self.read_time_ms,
        }
    }
}

/// A registered SPO that survived ban + URL filtering (pre-stake).
struct Eligible {
    pool_id: Vec<u8>,
    bifrost_id_pk: Vec<u8>,
    bifrost_url: String,
}

/// Apply ban + URL eligibility to a registry snapshot. Pure and stake-free
/// so the fetch path can learn which pools need a stake query. Returns the
/// survivors (in snapshot order) and the exclusions.
fn filter_eligible(
    snapshot: &RegistrySnapshot,
    active_bans: &BTreeSet<Vec<u8>>,
) -> (Vec<Eligible>, Vec<ExcludedSpo>) {
    let mut excluded = Vec::new();
    // First pass: drop banned + bad-URL, canonicalizing the rest.
    let mut url_valid: Vec<Eligible> = Vec::new();
    for spo in &snapshot.spos {
        if active_bans.contains(&spo.pool_id) {
            excluded.push(ExcludedSpo {
                pool_id: spo.pool_id.clone(),
                reason: ExclusionReason::Banned,
            });
            continue;
        }
        match std::str::from_utf8(&spo.bifrost_url)
            .map_err(|_| "not valid UTF-8".to_string())
            .and_then(validate_bifrost_url)
        {
            Ok(url) => url_valid.push(Eligible {
                pool_id: spo.pool_id.clone(),
                bifrost_id_pk: spo.bifrost_id_pk.clone(),
                bifrost_url: url,
            }),
            Err(why) => excluded.push(ExcludedSpo {
                pool_id: spo.pool_id.clone(),
                reason: ExclusionReason::BadUrl(why),
            }),
        }
    }
    // Second pass: drop ALL members of any URL-collision group — we can't
    // tell which registration is the honest one, and the peer transport keys
    // payloads by URL alone (see RosterError::DuplicateUrl).
    let mut url_counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in &url_valid {
        *url_counts.entry(e.bifrost_url.clone()).or_insert(0) += 1;
    }
    let mut eligible = Vec::new();
    for e in url_valid {
        if url_counts[&e.bifrost_url] > 1 {
            let url = e.bifrost_url.clone();
            excluded.push(ExcludedSpo {
                pool_id: e.pool_id.clone(),
                reason: ExclusionReason::DuplicateUrl(url),
            });
        } else {
            eligible.push(e);
        }
    }
    (eligible, excluded)
}

/// The pool ids that survive ban + URL filtering — the set the fetch path
/// must query stake for.
#[must_use]
pub fn eligible_pool_ids(
    snapshot: &RegistrySnapshot,
    active_bans: &BTreeSet<Vec<u8>>,
) -> Vec<Vec<u8>> {
    filter_eligible(snapshot, active_bans)
        .0
        .into_iter()
        .map(|e| e.pool_id)
        .collect()
}

/// Stake-weighted FROST threshold: smallest `k` such that the `k` lowest
/// stakes sum to STRICTLY MORE than [`SECURITY_THRESHOLD_PERCENT`]% of
/// `total`. `stakes` need not be sorted. Caller guarantees `total > 0` and
/// `total == stakes.sum()`; the result is clamped up to
/// [`FROST_MIN_PARTICIPANTS`] (a no-op for `n >= 2` with real stake, but
/// defends the degenerate single-whale case).
fn stake_weighted_threshold(stakes: &[u64], total: u64) -> u16 {
    let mut ascending: Vec<u64> = stakes.to_vec();
    ascending.sort_unstable();
    // Need bottom_k * 100 > total * PERCENT (u128 to avoid overflow).
    let target = u128::from(total) * SECURITY_THRESHOLD_PERCENT;
    let mut acc: u128 = 0;
    let mut k: u16 = 0;
    for s in ascending {
        acc += u128::from(s) * 100;
        k += 1;
        if acc > target {
            break;
        }
    }
    k.max(FROST_MIN_PARTICIPANTS)
}

/// Derive the Round-0 [`DkgContext`] from a registry snapshot, the active-ban
/// set, and a `pool_id → active_stake` map covering every eligible pool.
///
/// Pure over its inputs (the fetch path supplies bans + stakes), so the
/// eligibility and threshold logic is exhaustively testable offline.
pub fn derive_dkg_context(
    snapshot: &RegistrySnapshot,
    active_bans: &BTreeSet<Vec<u8>>,
    stakes: &BTreeMap<Vec<u8>, u64>,
    epoch: u64,
    attempt: u32,
) -> Result<DkgContext, DkgRosterError> {
    let (mut eligible, excluded) = filter_eligible(snapshot, active_bans);
    if eligible.len() < usize::from(FROST_MIN_PARTICIPANTS) {
        return Err(DkgRosterError::TooFew {
            got: eligible.len(),
        });
    }
    let n = u16::try_from(eligible.len()).map_err(|_| DkgRosterError::TooMany(eligible.len()))?;

    // Stake for every eligible pool, then the threshold over those stakes.
    let mut stake_of: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    let mut total: u64 = 0;
    for e in &eligible {
        let s = *stakes
            .get(&e.pool_id)
            .ok_or_else(|| DkgRosterError::MissingStake {
                pool_id: e.pool_id.clone(),
            })?;
        total = total.saturating_add(s);
        stake_of.insert(e.pool_id.clone(), s);
    }
    if total == 0 {
        return Err(DkgRosterError::ZeroStake);
    }
    let stake_vals: Vec<u64> = stake_of.values().copied().collect();
    let threshold = stake_weighted_threshold(&stake_vals, total);

    // Order by bifrost_id_pk and assign identifiers 1..=n.
    eligible.sort_by(|a, b| a.bifrost_id_pk.cmp(&b.bifrost_id_pk));
    let participants = eligible
        .into_iter()
        .enumerate()
        .map(|(i, e)| {
            let index = u16::try_from(i + 1).expect("n fits u16");
            DkgParticipant {
                index,
                identifier: Identifier::try_from(index).expect("1..=n is a valid FROST identifier"),
                active_stake: stake_of[&e.pool_id],
                pool_id: e.pool_id,
                bifrost_id_pk: e.bifrost_id_pk,
                bifrost_url: e.bifrost_url,
            }
        })
        .collect();

    Ok(DkgContext {
        epoch,
        attempt,
        threshold: threshold.min(n),
        total_stake: total,
        participants,
        excluded,
        // The schedule anchor is supplied by `fetch_dkg_context` (it already
        // fetches the boundary time); the pure derivation leaves it unset.
        schedule_anchor_ms: None,
        read_time_ms: 0,
    })
}

impl DkgContext {
    /// The epoch-machine [`Roster`]: `min_signers` = the stake-weighted
    /// threshold, `max_signers` = eligible count, participants keyed by
    /// identifier.
    #[must_use]
    pub fn to_roster(&self) -> Roster {
        let participants = self
            .participants
            .iter()
            .map(|p| {
                (
                    p.identifier,
                    SpoInfo {
                        identifier: p.identifier,
                        pool_id: p.pool_id.clone(),
                        bifrost_url: p.bifrost_url.clone(),
                        bifrost_id_pk: p.bifrost_id_pk.clone(),
                    },
                )
            })
            .collect();
        Roster {
            epoch: self.epoch,
            min_signers: self.threshold,
            max_signers: u16::try_from(self.participants.len()).expect("n fits u16"),
            participants,
        }
    }

    /// This node's eligible participant, located by its `bifrost_id_pk` —
    /// the identity-safe replacement for a positional `--index`. `None` if
    /// the local key isn't in the eligible set (not registered, banned, or
    /// URL-excluded). Callers MUST abort if their own key is absent rather
    /// than assume an index.
    #[must_use]
    pub fn own_participant(&self, bifrost_id_pk: &[u8]) -> Option<&DkgParticipant> {
        self.participants
            .iter()
            .find(|p| p.bifrost_id_pk == bifrost_id_pk)
    }

    /// Whether a qualified subset `Q` clears the DKG security gate: it must hold
    /// at least `threshold` participants AND control strictly more than 51% of
    /// the eligible stake. Mirrors WI-014 part 3 — the attempt aborts iff
    /// `|Q| < t` OR `stake(Q) <= 51%` of [`Self::total_stake`]. Identifiers in
    /// `qualified` that are not eligible participants are ignored. Stake is
    /// summed in `u128` (lovelace × 100 overflows `u64` at realistic supply).
    #[must_use]
    pub fn quorum_ok(&self, qualified: &BTreeSet<Identifier>) -> bool {
        let q: Vec<&DkgParticipant> = self
            .participants
            .iter()
            .filter(|p| qualified.contains(&p.identifier))
            .collect();
        let stake: u128 = q.iter().map(|p| u128::from(p.active_stake)).sum();
        // |Q| >= t (enough for a t-of-n key) AND stake(Q) > 51% of the eligible
        // total (honest-majority DKG completion). Integer-exact, same bound and
        // constant as `stake_weighted_threshold`; count in `usize` so a huge set
        // can't wrap.
        q.len() >= usize::from(self.threshold)
            && stake * 100 > u128::from(self.total_stake) * SECURITY_THRESHOLD_PERCENT
    }

    /// Build the candidate context for the NEXT attempt after a failed
    /// ceremony, keeping only the `survivors` (the participants who completed
    /// the round that aborted — `L1` after Round 1, `Q` after Round 2). The
    /// threshold and total stake are re-derived over the survivors alone (a
    /// fresh stake-weighted `t`), and `attempt` is bumped by one so every rerun
    /// payload is re-namespaced. Returns `None` when the survivors are below
    /// [`FROST_MIN_PARTICIPANTS`] or carry no stake — there is nothing left to
    /// rerun and the epoch's DKG is dead.
    ///
    /// Each survivor KEEPS its original FROST [`Identifier`] (a field element —
    /// frost-core does not require contiguous `1..=n`, only `max_signers`
    /// distinct ones), so all honest nodes that observed the same survivor set
    /// derive the identical reduced context. The positional [`DkgParticipant::index`]
    /// is left as-is and so may become non-contiguous; `identifier` is the
    /// source of truth for the ceremony, `index` is a display hint only.
    ///
    /// NOTE: the `> 51%` arm of [`Self::quorum_ok`] on the reduced context is
    /// relative to the survivors' total, not the original epoch stake — the
    /// spec's "restart DKG with the reduced candidate set after slashing"
    /// re-bases the honest-majority requirement on whoever remains eligible.
    #[must_use]
    pub fn reduced_to(&self, survivors: &BTreeSet<Identifier>) -> Option<DkgContext> {
        let kept: Vec<DkgParticipant> = self
            .participants
            .iter()
            .filter(|p| survivors.contains(&p.identifier))
            .cloned()
            .collect();
        if kept.len() < usize::from(FROST_MIN_PARTICIPANTS) {
            return None;
        }
        let total: u64 = kept.iter().map(|p| p.active_stake).sum();
        if total == 0 {
            return None;
        }
        let n = u16::try_from(kept.len()).ok()?;
        let stakes: Vec<u64> = kept.iter().map(|p| p.active_stake).collect();
        let threshold = stake_weighted_threshold(&stakes, total).min(n);
        Some(DkgContext {
            epoch: self.epoch,
            attempt: self.attempt + 1,
            threshold,
            total_stake: total,
            participants: kept,
            // Carry the prior exclusions forward for diagnostics; the dropped
            // survivors (this attempt's absent/faulty peers) are tracked as
            // fault evidence by the ceremony, not re-derived here.
            excluded: self.excluded.clone(),
            // Same anchor → same anchored schedule for the rerun.
            schedule_anchor_ms: self.schedule_anchor_ms,
            read_time_ms: self.read_time_ms,
        })
    }

    /// Synthesize a context from a static [`Roster`] with EQUAL per-participant
    /// stake (1 each), for the requested `(epoch, attempt)` — used by the
    /// mock/fixture demo and the no-registry fallback, where real chain stake is
    /// unavailable. `threshold` is the roster's configured FROST `min_signers`
    /// (so the solo `1-of-1` path is preserved). NOTE the quorum gate's `> 51%`
    /// stake arm is a SEPARATE honest-majority DKG-completion requirement: for
    /// `n` where `min_signers <= 51%` (e.g. 2-of-4) completing the ceremony still
    /// needs a stake majority (3) even though the resulting key signs at
    /// `min_signers`. `index` is positional and equals `identifier as u16` only
    /// while the roster's identifiers are the contiguous `1..=n` (true for the
    /// fixture/fallback). Real deployments build the context from chain stake via
    /// [`fetch_dkg_context`].
    #[must_use]
    pub fn from_roster_equal_stake(roster: &Roster, epoch: u64, attempt: u32) -> Self {
        let participants = roster
            .participants
            .iter()
            .enumerate()
            .map(|(i, (id, info))| DkgParticipant {
                index: (i as u16) + 1,
                identifier: *id,
                pool_id: info.pool_id.clone(),
                bifrost_id_pk: info.bifrost_id_pk.clone(),
                bifrost_url: info.bifrost_url.clone(),
                active_stake: 1,
            })
            .collect::<Vec<_>>();
        let total_stake = participants.len() as u64;
        DkgContext {
            epoch,
            attempt,
            threshold: roster.min_signers,
            total_stake,
            participants,
            excluded: vec![],
            // Mock / no-registry fallback has no chain schedule → relative
            // per-round timeouts.
            schedule_anchor_ms: None,
            read_time_ms: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Fetch orchestration
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum DkgFetchError {
    Registry(RosterError),
    Ban(BanListError),
    /// The epoch-boundary time query (`/epochs/{n}`) failed — distinct from a
    /// ban-list problem so an `/epochs` outage isn't misdiagnosed as one.
    EpochTime(String),
    /// A stake query for an eligible pool failed — fatal: `t` can't be
    /// computed honestly, so the attempt is void.
    Stake(String),
    Derive(DkgRosterError),
}

impl std::fmt::Display for DkgFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry(e) => write!(f, "registry: {e}"),
            Self::Ban(e) => write!(f, "ban list: {e}"),
            Self::EpochTime(e) => write!(f, "epoch time: {e}"),
            Self::Stake(e) => write!(f, "stake: {e}"),
            Self::Derive(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DkgFetchError {}

/// Active bans for `epoch` from a ban source. A not-yet-bootstrapped ban list
/// (WI-015 pending) is treated as "no bans" — the correct reading, and it
/// lets the bridge run before the ban infrastructure is deployed.
pub async fn fetch_active_bans(
    bans: Option<&BanListSource>,
    base_url: &str,
    project_id: &str,
    now_ms: i64,
) -> Result<BTreeSet<Vec<u8>>, BanListError> {
    match bans {
        None => Ok(BTreeSet::new()),
        Some(src) => match src.fetch_ban_list(base_url, project_id).await {
            Ok(list) => Ok(list.active_bans(now_ms)),
            Err(BanListError::NotBootstrapped) => Ok(BTreeSet::new()),
            Err(e) => Err(e),
        },
    }
}

/// Active stake (lovelace) for each pool id (28-byte). Fails on the first
/// query error — a missing stake makes the threshold uncomputable.
pub async fn fetch_eligible_stakes(
    base_url: &str,
    project_id: &str,
    pool_ids: &[Vec<u8>],
    source: StakeSource,
    epoch: u64,
    // DEMO-ONLY: when true, a pool whose stake can't be resolved is skipped
    // (omitted from the map) instead of failing the whole fetch. The caller
    // then excludes those pools from the roster. Default false in production.
    exclude_unstaked: bool,
) -> Result<BTreeMap<Vec<u8>, u64>, String> {
    let mut stakes = BTreeMap::new();
    for pool_id in pool_ids {
        let arr: [u8; 28] = pool_id
            .as_slice()
            .try_into()
            .map_err(|_| format!("pool_id is not 28 bytes: {}", hex::encode(pool_id)))?;
        match fetch_pool_stake_src(source, base_url, project_id, epoch, &pool_id_bech32(&arr)).await
        {
            Ok(stake) => {
                stakes.insert(pool_id.clone(), stake.active_stake);
            }
            Err(e) if exclude_unstaked => {
                eprintln!(
                    "[demo] excluding pool {} from roster: stake unresolved ({e})",
                    pool_id_bech32(&arr)
                );
            }
            Err(e) => return Err(e),
        }
    }
    Ok(stakes)
}

/// Fetch everything Round 0 needs and derive the [`DkgContext`] for `epoch`:
/// the registry snapshot (retried), the active bans (retried;
/// not-bootstrapped → none), and the active stake of each eligible pool
/// (fatal on failure). Used by the epoch machine's `query_roster`.
pub async fn fetch_dkg_context(
    registry: &RegistryRosterSource,
    bans: Option<&BanListSource>,
    base_url: &str,
    project_id: &str,
    stake_source: StakeSource,
    epoch: u64,
    attempt: u32,
    // DEMO-ONLY: exclude eligible pools whose stake can't be resolved instead of
    // failing the whole roster (`MissingStake`). Default false in production.
    exclude_unstaked: bool,
) -> Result<DkgContext, DkgFetchError> {
    // The registry snapshot and the epoch-boundary time are independent — fetch
    // them concurrently. Ban activity is checked at that boundary time
    // (chain-derived, not a node clock) so every SPO subtracts the same set and
    // derives the same roster.
    let (snapshot, epoch_start_ms) = tokio::try_join!(
        async {
            registry
                .fetch_snapshot(base_url, project_id)
                .await
                .map_err(DkgFetchError::Registry)
        },
        async {
            bf_http::fetch_epoch_start_ms(base_url, project_id, epoch)
                .await
                .map_err(DkgFetchError::EpochTime)
        },
    )?;
    let active_bans = fetch_active_bans(bans, base_url, project_id, epoch_start_ms)
        .await
        .map_err(DkgFetchError::Ban)?;
    let eligible = eligible_pool_ids(&snapshot, &active_bans);
    // TRACE (2026-07-23): the chain view this node derived, so the SAME line from
    // every node can be diffed to see WHEN each first saw the ban. The ban list is
    // read at the current tip (fetch_active_bans → fetch_ban_list), so a ban
    // landing near a boundary is seen by some nodes an epoch before others — the
    // suspected root of the transitional recovery churn.
    {
        let short = |v: &[u8]| hex::encode(&v[..4.min(v.len())]);
        let bans_short: Vec<String> = active_bans.iter().map(|b| short(b)).collect();
        let elig_short: Vec<String> = eligible.iter().map(|e| short(e)).collect();
        eprintln!(
            "[chain-view] epoch={epoch} attempt={attempt} epoch_start_ms={epoch_start_ms} \
             registered={} active_bans=[{}] eligible=[{}]",
            snapshot.spos.len(),
            bans_short.join(","),
            elig_short.join(",")
        );
    }
    let stakes = fetch_eligible_stakes(
        base_url,
        project_id,
        &eligible,
        stake_source,
        epoch,
        exclude_unstaked,
    )
    .await
    .map_err(DkgFetchError::Stake)?;
    // DEMO-ONLY: pools whose stake was skipped above are dropped from the roster
    // by adding them to the exclusion (ban) set, so the derivation sees only
    // resolvable-stake pools rather than erroring on `MissingStake`.
    let mut bans = active_bans;
    if exclude_unstaked {
        for pid in &eligible {
            if !stakes.contains_key(pid) {
                bans.insert(pid.clone());
            }
        }
    }
    let mut ctx = derive_dkg_context(&snapshot, &bans, &stakes, epoch, attempt)
        .map_err(DkgFetchError::Derive)?;
    // Anchor the ceremony's round deadlines to the chain epoch boundary (WI-014
    // #6), so every node freezes L1/Q at the same chain-time instant.
    ctx.schedule_anchor_ms = Some(epoch_start_ms);
    // Freshness stamp for the published ChainView: the chain time this view was
    // read at. A node that read the chain later saw more of it, so on a
    // candidate-set disagreement the OLDER read_time_ms marks the stale node.
    // Best-effort — a failed tip read leaves it 0 (treated as "oldest"), which
    // is safe: it only ever makes THIS node the one that re-reads.
    ctx.read_time_ms = bf_http::fetch_latest_block_time(base_url, project_id)
        .await
        .map(|secs| secs * 1000)
        .unwrap_or(0);
    Ok(ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::roster::RegisteredSpo;
    use crate::cardano::treasury_info::TreasuryInfoDatum;
    use crate::cardano::treasury_spend::TreasuryStateUtxo;

    fn snapshot(spos: Vec<RegisteredSpo>) -> RegistrySnapshot {
        RegistrySnapshot {
            spos,
            identity_root: [0u8; 32],
            treasury_state: TreasuryStateUtxo {
                tx_hash: "00".repeat(32),
                output_index: 0,
                lovelace: 2_000_000,
                asset_name_hex: "ab".into(),
                datum: TreasuryInfoDatum {
                    bifrost_identity_root: [0u8; 32],
                    current_treasury_address: vec![],
                    current_treasury_utxo_id: vec![],
                    current_spos_frost_key: vec![],
                },
            },
        }
    }

    fn spo(pool: u8, pk: u8, url: &str) -> RegisteredSpo {
        RegisteredSpo {
            pool_id: vec![pool; 28],
            bifrost_id_pk: vec![pk; 32],
            bifrost_url: url.as_bytes().to_vec(),
            tx_hash: format!("{pool:02x}").repeat(32),
            output_index: 0,
        }
    }

    fn stakes(pairs: &[(u8, u64)]) -> BTreeMap<Vec<u8>, u64> {
        pairs.iter().map(|(p, s)| (vec![*p; 28], *s)).collect()
    }

    // ---- threshold maths -------------------------------------------------

    #[test]
    fn threshold_needs_strictly_more_than_51_percent_of_weakest() {
        // 50/50: bottom-1 = 50% (not > 51%) → need both.
        assert_eq!(stake_weighted_threshold(&[50, 50], 100), 2);
        // 60/40: bottom-1 = 40% → need both.
        assert_eq!(stake_weighted_threshold(&[60, 40], 100), 2);
        // 30/30/40: bottom-2 = 60% > 51% → t=2.
        assert_eq!(stake_weighted_threshold(&[30, 30, 40], 100), 2);
        // 10/10/80: weakest-2 = 20% < 51%, only all three guarantee it → t=3.
        assert_eq!(stake_weighted_threshold(&[10, 10, 80], 100), 3);
        // unsorted input is handled.
        assert_eq!(stake_weighted_threshold(&[80, 10, 10], 100), 3);
    }

    #[test]
    fn threshold_never_below_frost_min() {
        // One whale at 99% would give bottom-1 > 51% → k=1, but clamp to 2.
        assert_eq!(stake_weighted_threshold(&[1, 99], 100), 2);
    }

    #[test]
    fn threshold_no_overflow_at_realistic_lovelace() {
        // ~22.5B ADA each in lovelace; product fits u128, not u64.
        let big = 22_500_000_000_000_000u64;
        assert_eq!(stake_weighted_threshold(&[big, big], big * 2), 2);
    }

    // ---- quorum gate (|Q| >= t AND stake(Q) > 51%) -----------------------

    fn ctx_with(stakes: &[u64], threshold: u16) -> DkgContext {
        let total: u64 = stakes.iter().sum();
        let participants = stakes
            .iter()
            .enumerate()
            .map(|(i, &s)| {
                let ix = (i + 1) as u16;
                DkgParticipant {
                    index: ix,
                    identifier: Identifier::try_from(ix).unwrap(),
                    pool_id: vec![ix as u8; 28],
                    bifrost_id_pk: vec![ix as u8; 32],
                    bifrost_url: format!("http://localhost:{}", 18500 + ix),
                    active_stake: s,
                }
            })
            .collect();
        DkgContext {
            epoch: 1,
            attempt: 0,
            threshold,
            total_stake: total,
            participants,
            excluded: vec![],
            schedule_anchor_ms: None,
            read_time_ms: 0,
        }
    }

    fn qset(ids: &[u16]) -> BTreeSet<Identifier> {
        ids.iter()
            .map(|&i| Identifier::try_from(i).unwrap())
            .collect()
    }

    #[test]
    fn quorum_gate_requires_threshold_count() {
        // 40/40/20, t=2: any 2 clear 51% of stake, isolating the count gate.
        let ctx = ctx_with(&[40, 40, 20], 2);
        assert!(ctx.quorum_ok(&qset(&[1, 2, 3]))); // full set
        assert!(ctx.quorum_ok(&qset(&[1, 2]))); // 2 >= t, 80% stake
        assert!(!ctx.quorum_ok(&qset(&[1]))); // 1 < t → abort
        assert!(!ctx.quorum_ok(&qset(&[]))); // empty → abort
        assert!(!ctx.quorum_ok(&qset(&[1, 99]))); // unknown ids ignored → 1 < t
    }

    #[test]
    fn quorum_gate_requires_strictly_more_than_51_percent_stake() {
        // 50/30/20, t=2.
        let ctx = ctx_with(&[50, 30, 20], 2);
        assert!(!ctx.quorum_ok(&qset(&[2, 3]))); // count ok, 50% <= 51% → abort
        assert!(ctx.quorum_ok(&qset(&[1, 3]))); // 70% > 51% → ok
        assert!(ctx.quorum_ok(&qset(&[1, 2]))); // 80% > 51% → ok

        // Exactly 51% must ABORT (the bound is strict >).
        let tie = ctx_with(&[51, 49], 1);
        assert!(!tie.quorum_ok(&qset(&[1]))); // 51% is not > 51%
        assert!(tie.quorum_ok(&qset(&[1, 2]))); // 100% → ok
    }

    #[test]
    fn quorum_gate_stake_arm_is_independent_of_threshold() {
        // Equal stake n=4, t=2: the count gate (|Q| >= 2) and the stake gate
        // (> 51% → >= 3 of 4) are INDEPENDENT. A set of exactly 2 meets t but is
        // only 50% of stake → abort; honest-majority DKG completion needs 3.
        let ctx = ctx_with(&[1, 1, 1, 1], 2);
        assert!(!ctx.quorum_ok(&qset(&[1, 2]))); // count 2 >= t, but 50% <= 51%
        assert!(ctx.quorum_ok(&qset(&[1, 2, 3]))); // 3, 75% > 51% → ok

        // Degenerate: an empty eligible set never clears the gate.
        let empty = ctx_with(&[], 2);
        assert!(!empty.quorum_ok(&qset(&[1])));
        assert!(!empty.quorum_ok(&qset(&[])));
    }

    #[test]
    fn from_roster_equal_stake_drives_majority_gate() {
        let mut participants = BTreeMap::new();
        for i in 1u16..=3 {
            let id = Identifier::try_from(i).unwrap();
            participants.insert(
                id,
                SpoInfo {
                    identifier: id,
                    pool_id: vec![i as u8; 28],
                    bifrost_url: format!("http://localhost:{}", 18500 + i),
                    bifrost_id_pk: vec![i as u8; 32],
                },
            );
        }
        let roster = Roster {
            epoch: 9,
            min_signers: 2,
            max_signers: 3,
            participants,
        };

        // Uses the REQUESTED epoch (500), not the roster's own epoch (9).
        let ctx = DkgContext::from_roster_equal_stake(&roster, 500, 4);
        assert_eq!(ctx.epoch, 500);
        assert_eq!(ctx.attempt, 4);
        assert_eq!(ctx.threshold, 2);
        assert_eq!(ctx.total_stake, 3);
        assert!(ctx.participants.iter().all(|p| p.active_stake == 1));
        // Equal stake → the gate is a >51%-by-count majority that also meets t.
        assert!(ctx.quorum_ok(&qset(&[1, 2]))); // 2/3 = 66% > 51%, count 2 >= t
        assert!(!ctx.quorum_ok(&qset(&[1]))); // count 1 < t (and 33% < 51%)
    }

    // ---- reduced_to (failed-attempt rerun candidate set) ----------------

    #[test]
    fn reduced_to_drops_non_survivors_and_bumps_attempt() {
        // 40/40/20, t=2, attempt 3. Survivors {1,3} (peer 2 absent/faulty).
        let ctx = ctx_with(&[40, 40, 20], 2);
        let ctx = DkgContext { attempt: 3, ..ctx };
        let reduced = ctx
            .reduced_to(&qset(&[1, 3]))
            .expect("2 survivors >= FROST_MIN");
        assert_eq!(reduced.attempt, 4); // bumped
        assert_eq!(reduced.epoch, ctx.epoch); // epoch unchanged
        assert_eq!(reduced.participants.len(), 2);
        assert_eq!(reduced.total_stake, 60); // 40 + 20, re-based on survivors
        // Original identifiers kept (1 and 3), NOT renumbered to 1,2. The
        // positional `index` rides along unchanged, so it stays non-contiguous.
        let ids: Vec<Identifier> = reduced.participants.iter().map(|p| p.identifier).collect();
        assert_eq!(
            ids,
            vec![
                Identifier::try_from(1u16).unwrap(),
                Identifier::try_from(3u16).unwrap()
            ]
        );
        let idxs: Vec<u16> = reduced.participants.iter().map(|p| p.index).collect();
        assert_eq!(idxs, vec![1, 3]);
        // Threshold re-derived over survivors' stake (40,20 of 60: weakest-1=20
        // = 33% <= 51% → need both → t=2).
        assert_eq!(reduced.threshold, 2);
        // The reduced full set clears its own (re-based) gate.
        assert!(reduced.quorum_ok(&qset(&[1, 3])));
    }

    #[test]
    fn reduced_to_below_frost_min_is_dead() {
        let ctx = ctx_with(&[40, 40, 20], 2);
        // A single survivor cannot run FROST DKG → None (epoch DKG is dead).
        assert!(ctx.reduced_to(&qset(&[1])).is_none());
        assert!(ctx.reduced_to(&qset(&[])).is_none());
        // An unknown id is simply not a survivor.
        assert!(ctx.reduced_to(&qset(&[1, 99])).is_none());
    }

    #[test]
    fn reduced_to_recomputes_threshold_on_survivor_stake() {
        // 10/10/80, t=3. Survivors {1,2} (the whale dropped): 10/10 of 20, the
        // weakest-1 = 50% <= 51% → both needed → t=2 (was 3).
        let ctx = ctx_with(&[10, 10, 80], 3);
        let reduced = ctx.reduced_to(&qset(&[1, 2])).unwrap();
        assert_eq!(reduced.threshold, 2);
        assert_eq!(reduced.total_stake, 20);
    }

    // ---- eligibility + context ------------------------------------------

    #[test]
    fn derives_context_ordered_by_pk_with_stake_threshold() {
        // pool order AA<BB<CC, but pk order is reversed (3>2>1).
        let snap = snapshot(vec![
            spo(0xAA, 0x33, "http://a.example:18500"),
            spo(0xBB, 0x22, "http://b.example:18500"),
            spo(0xCC, 0x11, "http://c.example:18500"),
        ]);
        let ctx = derive_dkg_context(
            &snap,
            &BTreeSet::new(),
            &stakes(&[(0xAA, 10), (0xBB, 10), (0xCC, 80)]),
            42,
            0,
        )
        .unwrap();

        assert_eq!(ctx.epoch, 42);
        assert_eq!(ctx.total_stake, 100);
        // weakest-2 = 20% < 51% → t = 3.
        assert_eq!(ctx.threshold, 3);
        // identifiers assigned in pk order, not pool order.
        let pks: Vec<&[u8]> = ctx
            .participants
            .iter()
            .map(|p| p.bifrost_id_pk.as_slice())
            .collect();
        assert_eq!(pks, [&[0x11; 32][..], &[0x22; 32], &[0x33; 32]]);
        assert_eq!(ctx.participants[0].index, 1);
        assert_eq!(ctx.participants[0].pool_id, vec![0xCC; 28]); // pk 0x11
        assert_eq!(ctx.participants[0].active_stake, 80);

        // to_roster threads the threshold into min_signers.
        let roster = ctx.to_roster();
        assert_eq!(roster.min_signers, 3);
        assert_eq!(roster.max_signers, 3);
        assert_eq!(roster.epoch, 42);
    }

    #[test]
    fn excludes_banned_pools() {
        let snap = snapshot(vec![
            spo(0xAA, 0x11, "http://a.example:18500"),
            spo(0xBB, 0x22, "http://b.example:18500"),
            spo(0xCC, 0x33, "http://c.example:18500"),
        ]);
        let bans = BTreeSet::from([vec![0xBBu8; 28]]);
        let ctx =
            derive_dkg_context(&snap, &bans, &stakes(&[(0xAA, 40), (0xCC, 60)]), 7, 0).unwrap();
        assert_eq!(ctx.participants.len(), 2);
        assert!(ctx.participants.iter().all(|p| p.pool_id != vec![0xBB; 28]));
        assert_eq!(
            ctx.excluded,
            vec![ExcludedSpo {
                pool_id: vec![0xBB; 28],
                reason: ExclusionReason::Banned,
            }]
        );
        // eligible_pool_ids agrees (and drives the stake fetch).
        assert_eq!(
            eligible_pool_ids(&snap, &bans),
            vec![vec![0xAA; 28], vec![0xCC; 28]]
        );
    }

    #[test]
    fn excludes_bad_url_offender_not_whole_roster() {
        let snap = snapshot(vec![
            spo(0xAA, 0x11, "http://a.example:18500"),
            spo(0xBB, 0x22, "not-a-url"), // no scheme → excluded
            spo(0xCC, 0x33, "http://c.example:18500"),
        ]);
        let ctx = derive_dkg_context(
            &snap,
            &BTreeSet::new(),
            &stakes(&[(0xAA, 40), (0xCC, 60)]),
            0,
            0,
        )
        .unwrap();
        assert_eq!(ctx.participants.len(), 2);
        assert!(matches!(
            ctx.excluded.as_slice(),
            [ExcludedSpo { pool_id, reason: ExclusionReason::BadUrl(_) }] if *pool_id == vec![0xBB; 28]
        ));
    }

    #[test]
    fn excludes_all_members_of_a_url_collision() {
        // AA and CC share a URL (after canonicalization) → both dropped; BB
        // is the only survivor → TooFew.
        let snap = snapshot(vec![
            spo(0xAA, 0x11, "http://dup.example:18500"),
            spo(0xBB, 0x22, "http://b.example:18500"),
            spo(0xCC, 0x33, "http://DUP.example:18500/"), // canonicalizes equal
        ]);
        let err =
            derive_dkg_context(&snap, &BTreeSet::new(), &stakes(&[(0xBB, 100)]), 0, 0).unwrap_err();
        assert!(matches!(err, DkgRosterError::TooFew { got: 1 }));
        // The collision is recorded for both.
        let (_, excluded) = filter_eligible(&snap, &BTreeSet::new());
        let dup: Vec<&Vec<u8>> = excluded
            .iter()
            .filter(|e| matches!(e.reason, ExclusionReason::DuplicateUrl(_)))
            .map(|e| &e.pool_id)
            .collect();
        assert_eq!(dup, vec![&vec![0xAA; 28], &vec![0xCC; 28]]);
    }

    #[test]
    fn too_few_after_filtering() {
        let snap = snapshot(vec![spo(0xAA, 0x11, "http://a.example:18500")]);
        assert!(matches!(
            derive_dkg_context(&snap, &BTreeSet::new(), &stakes(&[(0xAA, 1)]), 0, 0),
            Err(DkgRosterError::TooFew { got: 1 })
        ));
    }

    #[test]
    fn missing_or_zero_stake_is_fatal() {
        let snap = snapshot(vec![
            spo(0xAA, 0x11, "http://a.example:18500"),
            spo(0xBB, 0x22, "http://b.example:18500"),
        ]);
        // BB's stake absent → MissingStake.
        assert!(matches!(
            derive_dkg_context(&snap, &BTreeSet::new(), &stakes(&[(0xAA, 5)]), 0, 0),
            Err(DkgRosterError::MissingStake { .. })
        ));
        // both zero → ZeroStake.
        assert!(matches!(
            derive_dkg_context(
                &snap,
                &BTreeSet::new(),
                &stakes(&[(0xAA, 0), (0xBB, 0)]),
                0,
                0
            ),
            Err(DkgRosterError::ZeroStake)
        ));
    }

    #[test]
    fn own_participant_located_by_pk() {
        let snap = snapshot(vec![
            spo(0xAA, 0x33, "http://a.example:18500"),
            spo(0xBB, 0x11, "http://b.example:18500"),
        ]);
        let ctx = derive_dkg_context(
            &snap,
            &BTreeSet::new(),
            &stakes(&[(0xAA, 50), (0xBB, 50)]),
            0,
            0,
        )
        .unwrap();
        // pk 0x11 is identifier 1 (lowest pk), pk 0x33 is identifier 2.
        assert_eq!(ctx.own_participant(&[0x11; 32]).unwrap().index, 1);
        assert_eq!(ctx.own_participant(&[0x33; 32]).unwrap().index, 2);
        // a key not in the eligible set → None (caller must abort).
        assert!(ctx.own_participant(&[0x99; 32]).is_none());
    }
}
