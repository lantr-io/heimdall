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

use crate::epoch::state::{EpochResult, Roster, SpoInfo};
use crate::http::payloads::{Dkg1Payload, Dkg2Payload, Sign1Payload, Sign2Payload};

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
    /// The Taproot script-tree leaf key for the 67%-quorum script path.
    pub y_67: bitcoin::key::UntweakedPublicKey,
    /// The Taproot script-tree leaf key for the federation fallback.
    pub y_fed: bitcoin::key::UntweakedPublicKey,
    pub federation_csv_blocks: u32,
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee: bitcoin::Amount,
    /// Whether the Bitcoin transaction in the oracle datum has been
    /// confirmed on Bitcoin. A new treasury movement can only begin once the previous one is confirmed.
    pub btc_confirmed: bool,
}

#[async_trait]
pub trait CardanoChain: Send + Sync {
    /// Block until the next epoch boundary is observed. The mock returns
    /// immediately on first call so the demo runs exactly one cycle.
    async fn await_epoch_boundary(&self) -> EpochResult<EpochBoundaryEvent>;

    /// Snapshot the SPO registry and produce the roster for `epoch`.
    /// In v0.2 the mock returns a hardcoded roster.
    async fn query_roster(&self, epoch: u64) -> EpochResult<Roster>;

    /// Current treasury UTxO state, as reported by the Cardano oracle.
    async fn query_treasury(&self) -> EpochResult<TreasuryUtxo>;

    /// Pending peg-out requests to fulfil.
    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>>;

    /// Publish the new FROST group key after DKG. The key becomes the
    /// internal key (Y_51) of the next treasury Taproot address.
    ///
    /// In the mock this updates the treasury Y_51 so subsequent
    /// `query_treasury` calls return a treasury the FROST group can
    /// sign for. In production this posts the key to the on-chain
    /// treasury oracle.
    async fn publish_group_key(&self, y_51: bitcoin::key::UntweakedPublicKey) -> EpochResult<()>;

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
#[async_trait]
pub trait PeerNetwork: Send + Sync {
    async fn publish_dkg_round1(&self, payload: Dkg1Payload) -> EpochResult<()>;
    async fn publish_dkg_round2(&self, payload: Dkg2Payload) -> EpochResult<()>;
    async fn publish_sign_round1(&self, payload: Sign1Payload) -> EpochResult<()>;
    async fn publish_sign_round2(&self, payload: Sign2Payload) -> EpochResult<()>;

    async fn fetch_dkg_round1(
        &self,
        epoch: u64,
        peer: &SpoInfo,
    ) -> EpochResult<Option<Dkg1Payload>>;
    async fn fetch_dkg_round2(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        my_id: Identifier,
    ) -> EpochResult<Option<Dkg2Payload>>;
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
