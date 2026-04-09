//! Trait abstractions over external systems.
//!
//! `CardanoChain` and `PeerNetwork` are the seams the state machine
//! tests against. Today the codebase only ships mock implementations
//! plus an HTTP-backed peer network; a real Cardano N2C-backed chain
//! will slot in behind `CardanoChain` later without touching the state
//! machine.

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

/// A peg-in UTxO ready to sweep into the treasury.
///
/// Carries raw leaf material rather than a built `TaprootSpendInfo`
/// because the internal key (`Y_51`) is only known after DKG — the
/// `BuildTm` phase assembles the spend info from `group_keys`
/// and these fields.
#[derive(Debug, Clone)]
pub struct PegInUtxo {
    pub outpoint: bitcoin::OutPoint,
    pub value: bitcoin::Amount,
}

/// A pending peg-out request.
#[derive(Debug, Clone)]
pub struct PegOutRequestUtxo {
    pub script_pubkey: bitcoin::ScriptBuf,
    pub amount: bitcoin::Amount,
}

/// The current treasury UTxO controlled by the previous epoch's roster.
///
/// Like `PegInUtxo`, the Taproot spend info is reconstructed in
/// `BuildTm` from the group key — v0.2's bootstrap has no prior
/// epoch so the "current treasury" is synthetic and reuses the
/// newly-derived group key as its internal key.
///
/// TODO: in steady state the treasury input is controlled by epoch
/// N-1's group key, not epoch N's just-derived key. The state machine
/// needs to remember (or query) the previous epoch's `Y_51` to build
/// the spend info for the *input* while using the new key for the
/// *change output*. This is the treasury handoff problem.
#[derive(Debug, Clone)]
pub struct TreasuryUtxo {
    pub outpoint: bitcoin::OutPoint,
    pub value: bitcoin::Amount,
    /// The Taproot script-tree leaf key for the 67%-quorum script path.
    pub y_67: bitcoin::key::UntweakedPublicKey,
    /// The Taproot script-tree leaf key for the federation fallback.
    pub y_fed: bitcoin::key::UntweakedPublicKey,
    pub federation_csv_blocks: u32,
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee: bitcoin::Amount,
}

#[async_trait]
pub trait CardanoChain: Send + Sync {
    /// Block until the next epoch boundary is observed. The mock returns
    /// immediately on first call so the demo runs exactly one cycle.
    async fn await_epoch_boundary(&self) -> EpochResult<EpochBoundaryEvent>;

    /// Snapshot the SPO registry and produce the roster for `epoch`.
    /// In v0.2 the mock returns a hardcoded roster.
    async fn query_roster(&self, epoch: u64) -> EpochResult<Roster>;

    /// Current treasury UTxO state.
    async fn query_treasury(&self) -> EpochResult<TreasuryUtxo>;

    /// Confirmed peg-in deposits to sweep.
    async fn query_pegin_requests(&self) -> EpochResult<Vec<PegInUtxo>>;

    /// Pending peg-out requests to fulfil.
    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>>;

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
