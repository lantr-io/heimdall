//! Trait abstractions over external systems.
//!
//! `CardanoChain` models the *chain-hosted oracle views* the epoch
//! state machine consumes: the SPO registry snapshot (roster), the
//! current treasury UTxO (delivered by a watchtower-maintained oracle,
//! NOT by a Bitcoin node directly), and pending peg-out requests. The
//! peg-in discovery path is separate — `CardanoPegInSource` in the
//! `cardano` module polls a real Cardano node via pallas N2C.
//!
//! `PeerNetwork` is the pull-only HTTP surface between SPOs, used for
//! DKG and signing round data.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::keys::dkg::{round1, round2};

use crate::circuits::fault_evidence::{
    EquivocationEvidence, Round1PokFaultEvidence, Round2ShareFaultEvidence,
};
use crate::epoch::state::{EpochResult, Roster, SpoInfo};
use crate::http::canonical::POINT_LEN;
use crate::http::payloads::{Sign1Payload, Sign2Payload};
use crate::http::wire::DkgNamespace;

// ---------------------------------------------------------------------------
// CardanoChain
// ---------------------------------------------------------------------------

/// Notification that a new epoch boundary has been observed on Cardano.
#[derive(Debug, Clone)]
pub struct EpochBoundaryEvent {
    pub epoch: u64,
}

/// A pending peg-out request.
#[derive(Debug, Clone)]
pub struct PegOutRequestUtxo {
    pub script_pubkey: bitcoin::ScriptBuf,
    pub amount: bitcoin::Amount,
}

/// The current treasury UTxO state, as reported by the Cardano-side
/// oracle (Binocular / watchtower). The SPO never queries Bitcoin
/// directly for this — a trusted oracle UTxO on Cardano carries the
/// outpoint, value, and fee parameters, and the SPO reads it from
/// there.
///
/// `y_51` is the internal key of the *current* treasury — the key it
/// was locked under. `BuildTm` uses `y_51` for the treasury *input*
/// spend info, and the new FROST group key for the *change output*.
/// At bootstrap `y_51 = y_fed`; after `publish_group_key` it is the
/// active FROST group key.
#[derive(Debug, Clone)]
pub struct TreasuryUtxo {
    pub outpoint: bitcoin::OutPoint,
    pub value: bitcoin::Amount,
    /// The Taproot internal key of the *current* treasury (the Y_51 it
    /// was locked under). At bootstrap this equals `y_fed`; after the
    /// first DKG it is the previous epoch's FROST group x-only key.
    pub y_51: bitcoin::key::UntweakedPublicKey,
    /// The Taproot script-tree leaf key for the federation fallback.
    pub y_fed: bitcoin::key::UntweakedPublicKey,
    pub federation_csv_blocks: u32,
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee: bitcoin::Amount,
    /// Whether it is safe to begin the NEXT treasury movement off this UTxO.
    /// A new movement can only begin once the previous one is confirmed, so the
    /// Blockfrost impl (WI-028) sets this false when an Unconfirmed TM (or an
    /// in-flight TM it could not read) is already spending this tip; the mock
    /// reports a simple always-confirmed treasury.
    pub btc_confirmed: bool,
}

/// Provable DKG misbehavior captured by the peer transport.
///
/// Missing peers are not faults by themselves. These variants are only returned
/// when the transport can show either a signed invalid payload or two conflicting
/// signed payloads from the same `(epoch, threshold, attempt, round, pool_id)`
/// namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgFaultEvidence {
    Round1InvalidPayload(Round1PokFaultEvidence),
    Round2InvalidPayload(Round2ShareFaultEvidence),
    Equivocation(EquivocationEvidence),
}

impl DkgFaultEvidence {
    #[must_use]
    pub fn accused_pool_id(&self) -> &[u8; 28] {
        match self {
            Self::Round1InvalidPayload(ev) => &ev.accused_pool_id,
            Self::Round2InvalidPayload(ev) => &ev.accused_pool_id,
            Self::Equivocation(ev) => &ev.accused_pool_id,
        }
    }

    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Round1InvalidPayload(_) => "round1-invalid-payload",
            Self::Round2InvalidPayload(_) => "round2-invalid-payload",
            Self::Equivocation(_) => "equivocation",
        }
    }
}

#[async_trait]
pub trait CardanoChain: Send + Sync {
    /// Block until the next epoch boundary is observed. The mock returns
    /// immediately on first call so the demo runs exactly one cycle.
    async fn await_epoch_boundary(&self) -> EpochResult<EpochBoundaryEvent>;

    /// The current chain epoch (non-blocking) — used to namespace the DKG
    /// ceremony and to query the bootstrap roster at the right epoch. Unlike
    /// [`Self::await_epoch_boundary`] it does not wait for a boundary.
    async fn current_epoch(&self) -> EpochResult<u64>;

    /// Snapshot the SPO registry and produce the roster for `epoch`.
    /// In v0.2 the mock returns a hardcoded roster.
    async fn query_roster(&self, epoch: u64) -> EpochResult<Roster>;

    /// Resolve the eligible DKG context (candidate set + per-participant stake +
    /// stake-weighted threshold) for `(epoch, attempt)` — the stake-aware input
    /// the ceremony's quorum gate needs. The mock / no-registry fallback
    /// synthesize it from the static roster with equal stake.
    async fn query_dkg_context(
        &self,
        epoch: u64,
        attempt: u32,
    ) -> EpochResult<crate::cardano::dkg_roster::DkgContext>;

    /// Current treasury UTxO state, as reported by the Cardano oracle.
    async fn query_treasury(&self) -> EpochResult<TreasuryUtxo>;

    /// Pending peg-out requests to fulfil.
    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>>;

    /// A pool's stake, for the off-chain min-stake gate (register_spo R2): the
    /// contract can't read stake, so SPOs query it and require `active_stake >=
    /// min_stake` before building register_spo and before admitting the SPO to
    /// the DKG candidate set. `pool_id` is the bech32 pool id; see
    /// [`crate::cardano::stake`] for the threshold check.
    async fn query_pool_stake(
        &self,
        pool_id: &str,
    ) -> EpochResult<crate::cardano::stake::PoolStake>;

    /// Publish the new FROST group key after DKG. The key becomes the
    /// internal key (Y_51) of the next treasury Taproot address.
    ///
    /// In the mock this updates the treasury Y_51 so subsequent
    /// `query_treasury` calls return a treasury the FROST group can
    /// sign for. In production this posts the key to the on-chain
    /// treasury oracle.
    async fn publish_group_key(&self, y_51: bitcoin::key::UntweakedPublicKey) -> EpochResult<()>;

    /// Publish a DKG fault proof and apply the corresponding SPO ban.
    ///
    /// Implementations must only return `Ok(())` after the fault has been
    /// submitted to the configured ban flow or recorded by an explicit test
    /// double. DKG calls this only for provable evidence supplied by
    /// [`PeerNetwork`]; absent peers are reduced out of the candidate set but
    /// are not banned.
    async fn publish_dkg_fault_and_apply_ban(&self, evidence: DkgFaultEvidence) -> EpochResult<()>;

    /// Submit a Bitcoin tx (in v0.2 the mock just records it).
    ///
    /// TODO: misleading name — this lives on `CardanoChain` but it
    /// actually submits a *Bitcoin* transaction (the signed treasury
    /// movement) to a Bitcoin node/broadcaster, not to Cardano. A real
    /// impl will need two separate sinks: one for broadcasting the
    /// signed BTC tx, and another for posting the resulting Cardano
    /// side-effects (minting fBTC, closing peg-out requests).
    async fn submit_signed_tm(&self, tx_bytes: &[u8]) -> EpochResult<()>;
}

// ---------------------------------------------------------------------------
// PeerNetwork
// ---------------------------------------------------------------------------

/// Pull-only peer protocol surface.
///
/// All `publish_*` calls write to *this* SPO's local state — peers
/// fetch from us; we never push. The `fetch_*` calls poll a specific
/// peer's endpoint.
///
/// DKG payloads cross this boundary as plain FROST packages: the
/// implementation is responsible for the spec wire format — building +
/// BIP-340 signing on publish, and verifying (against the peer's
/// `bifrost_id_pk`/`pool_id`) + decrypting on fetch — so callers never
/// touch the canonical bytes or identity keys. A `fetch_*` that returns
/// `Some` has already been authenticated; `None` means "not published
/// yet". A payload that fails verification is dropped (and retained as
/// fault evidence by the implementation), surfaced as `Ok(None)` so the
/// poll loop keeps waiting rather than aborting the epoch.
#[async_trait]
pub trait PeerNetwork: Send + Sync {
    /// Whether `peer` is currently reachable (its `/health` endpoint answers).
    /// Used by the pre-ceremony health gate (N21) so a staggered-start roster
    /// converges on one DKG instead of freezing divergent live subsets. Purely
    /// advisory — a `true` here guarantees nothing about later rounds, and the
    /// gate is time-bounded, so implementations should answer quickly (a
    /// couple of seconds), never retry internally. Defaults to healthy for
    /// implementations without a liveness signal.
    async fn check_health(&self, _peer: &SpoInfo) -> bool {
        true
    }

    async fn publish_dkg_round1(
        &self,
        ns: DkgNamespace,
        identifier: Identifier,
        package: &round1::Package,
    ) -> EpochResult<()>;
    /// Publish Round 2: one encrypted share per recipient. Each entry pairs
    /// a recipient's `SpoInfo` (for its `pool_id` + `bifrost_id_pk`) with
    /// the FROST package addressed to it.
    async fn publish_dkg_round2(
        &self,
        ns: DkgNamespace,
        sender_identifier: Identifier,
        sender_commitments: &[[u8; POINT_LEN]],
        recipients: &[(SpoInfo, round2::Package)],
    ) -> EpochResult<()>;
    async fn publish_sign_round1(&self, payload: Sign1Payload) -> EpochResult<()>;
    async fn publish_sign_round2(&self, payload: Sign2Payload) -> EpochResult<()>;

    async fn fetch_dkg_round1(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Option<round1::Package>>;
    async fn fetch_dkg_round2(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
        recipient_identifier: Identifier,
        sender_commitments: &[[u8; POINT_LEN]],
    ) -> EpochResult<Option<round2::Package>>;
    /// Return provable Round 1 faults retained while fetching `peer`'s payload.
    async fn dkg_round1_fault_evidence(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Vec<DkgFaultEvidence>>;
    /// Return provable Round 2 faults retained while fetching `peer`'s payload.
    async fn dkg_round2_fault_evidence(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
        recipient_identifier: Identifier,
        sender_commitments: &[[u8; POINT_LEN]],
    ) -> EpochResult<Vec<DkgFaultEvidence>>;
    async fn fetch_sign_round1(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        input_index: u32,
    ) -> EpochResult<Option<Sign1Payload>>;
    async fn fetch_sign_round2(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        input_index: u32,
    ) -> EpochResult<Option<Sign2Payload>>;
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// Abstraction over time for testability. Real impl is `SystemClock`,
/// fake is `FakeClock`. (Both live in `mocks.rs`.)
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn deadline(&self, duration: Duration) -> Instant {
        self.now() + duration
    }
}

/// Factory for fresh cryptographic RNGs, one per call site.
///
/// `context` is a byte tag naming the call site (e.g. `b"dkg1"`,
/// `b"sign1:input=0"`). The seeded impl derives a stream from
/// `hash(seed || context)`, so different call sites never collide
/// and reordering code cannot silently reshuffle nonces. `OsRngSource`
/// ignores `context`.
///
/// Returns a concrete [`CycleRng`] (not a boxed trait object) because
/// `frost-secp256k1-tr`'s `round1::commit` requires `Sized`.
pub trait RngSource: Send + Sync {
    fn rng(&self, context: &[u8]) -> CycleRng;
}

/// Concrete RNG handed out by [`RngSource`]. Either wraps `OsRng`
/// directly, or a seeded `ChaCha20Rng` for deterministic demo runs.
pub enum CycleRng {
    Os(rand::rngs::OsRng),
    Seeded(rand_chacha::ChaCha20Rng),
}

impl rand_core::RngCore for CycleRng {
    fn next_u32(&mut self) -> u32 {
        match self {
            CycleRng::Os(r) => r.next_u32(),
            CycleRng::Seeded(r) => r.next_u32(),
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self {
            CycleRng::Os(r) => r.next_u64(),
            CycleRng::Seeded(r) => r.next_u64(),
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            CycleRng::Os(r) => r.fill_bytes(dest),
            CycleRng::Seeded(r) => r.fill_bytes(dest),
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            CycleRng::Os(r) => r.try_fill_bytes(dest),
            CycleRng::Seeded(r) => r.try_fill_bytes(dest),
        }
    }
}

impl rand_core::CryptoRng for CycleRng {}
