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

pub mod mock;
pub mod pallas_source;
pub mod pegin_datum;
pub mod pegin_source;

pub use pegin_source::{CardanoOutRef, CardanoPegInRequest, CardanoPegInSource};
