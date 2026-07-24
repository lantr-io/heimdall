//! Cardano integration: peg-in request discovery.
//!
//! Splits cleanly into a trait (`pegin_source`), a datum parser
//! (`pegin_datum`) shared by all implementations, an in-memory mock
//! (`mock`) used by tests, and a real pallas-backed N2C implementation
//! (`pallas_source`).
//!
//! The rest of the epoch state machine talks to this module exclusively
//! through the `CardanoPegInSource` trait, so swapping mock ↔ real is
//! a one-line change at the demo entry point.

pub mod always_ok;
pub mod apply_ban;
pub mod ban_list;
pub mod bf_http;
pub mod blockfrost_chain;
pub mod blockfrost_source;
pub mod blueprint;
pub mod btc_rpc;
pub mod dkg_roster;
pub mod fault_proof;
pub mod federation_reset;
pub mod hash;
pub mod init_scripts;
pub mod linked_list;
pub mod local_eval;
pub mod mock;
pub mod mpf;
pub mod nft_scan;
pub mod pallas_source;
pub mod pegin_datum;
pub mod pegin_source;
pub mod pegout_datum;
pub mod plutus;
pub mod publish;
pub mod register_pool;
pub mod register_spo;
pub mod registry;
pub mod retry;
pub mod roster;
pub mod stake;
pub mod tm_chain;
pub mod treasury_bootstrap;
pub mod treasury_datum;
pub mod treasury_info;
pub mod treasury_spend;
pub mod tx_common;
pub mod update_y;
pub mod wallet;

pub use pegin_source::{CardanoOutRef, CardanoPegInRequest, CardanoPegInSource};
