//! Epoch state machine for the Heimdall SPO.
//!
//! An enum-based state machine that drives one Cardano epoch from
//! registry snapshot through DKG, TM construction, per-input FROST
//! signing, and a final witnessed Bitcoin transaction. Each `EpochPhase`
//! variant carries all data needed to resume that phase; transitions
//! happen inside `run_epoch_loop`'s match arm.

pub mod dkg;
pub mod fixture;
pub mod log;
pub mod machine;
pub mod mocks;
pub mod signing;
pub mod state;
pub mod traits;

pub use machine::run_epoch_loop;

pub use state::{
    CascadeLevel, DkgCollected, DkgRound, EpochConfig, EpochError, EpochPhase, EpochResult,
    GroupKeys, Roster, SignCollected, SigningRound, SpoIdentity, SpoInfo, TreasuryMovement,
};
pub use traits::{CardanoChain, Clock, EpochBoundaryEvent, PeerNetwork};
