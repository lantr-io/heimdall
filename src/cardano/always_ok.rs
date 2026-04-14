//! Hardcoded Plutus V3 always-succeeds script used as the treasury
//! oracle minting policy.

/// CBOR hex of the minimal Plutus V3 always-succeeds script used as
/// the treasury oracle minting policy. Encoding: bytes(5) wrapping a
/// flat-encoded UPLC program at version 1.1.0.
pub const ALWAYS_OK_PLUTUS_CBOR_HEX: &str = "582b010100322499220120a7f3e82b1c49d056f7a3b9c124d8e05f6a2b7c9d3e4f0a1b2c3d4e5f6a7b8c900001";

/// Redeemer for an always-succeeds Plutus script: unit `()` encoded as
/// `Constr(0, [])` = CBOR tag 121, empty array = `d87980`.
pub const UNIT_REDEEMER_HEX: &str = "d87980";
