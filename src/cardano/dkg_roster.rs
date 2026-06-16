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
use crate::cardano::stake::fetch_pool_stake;
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
) -> Result<BTreeMap<Vec<u8>, u64>, String> {
    let mut stakes = BTreeMap::new();
    for pool_id in pool_ids {
        let arr: [u8; 28] = pool_id
            .as_slice()
            .try_into()
            .map_err(|_| format!("pool_id is not 28 bytes: {}", hex::encode(pool_id)))?;
        let stake = fetch_pool_stake(base_url, project_id, &pool_id_bech32(&arr)).await?;
        stakes.insert(pool_id.clone(), stake.active_stake);
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
    epoch: u64,
    attempt: u32,
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
    let stakes = fetch_eligible_stakes(base_url, project_id, &eligible)
        .await
        .map_err(DkgFetchError::Stake)?;
    derive_dkg_context(&snapshot, &active_bans, &stakes, epoch, attempt)
        .map_err(DkgFetchError::Derive)
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
