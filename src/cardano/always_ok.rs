//! TEST FIXTURES ONLY: a hardcoded Plutus V3 always-succeeds script.
//!
//! The production scaffold that minted TM posts under this policy is GONE
//! (rev 5.4: `publish.rs` requires the real TreasuryMovementValidator CBOR).
//! These constants survive solely as stand-in scripts for tx-composition
//! tests (`fault_proof`, `treasury_spend`), where any accepted V3 script and
//! any well-formed redeemer will do.

/// CBOR hex of a minimal Plutus V3 always-succeeds script (bytes(5) wrapping a
/// flat-encoded UPLC program at version 1.1.0, with a salt constant).
pub const ALWAYS_OK_PLUTUS_CBOR_HEX: &str =
    "582b010100322499220120a7f3e82b1c49d056f7a3b9c124d8e05f6a2b7c9d3e4f0a1b2c3d4e5f6a7b8c900001";

/// Redeemer for an always-succeeds Plutus script: unit `()` encoded as
/// `Constr(0, [])` = CBOR tag 121, empty array = `d87980`.
pub const UNIT_REDEEMER_HEX: &str = "d87980";
