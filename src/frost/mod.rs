pub mod dkg;
pub mod participant;
pub mod signing;
pub mod types;
pub mod xonly;

use frost_secp256k1_tr::Identifier;

/// The small integer a FROST `Identifier` was constructed from — its participant
/// index in the ceremony order.
///
/// Identifiers serialize as 32-byte big-endian scalars and heimdall only ever
/// builds them from a `u16`, so the last two bytes carry the whole value.
///
/// This is not merely cosmetic: the index is bound into the canonical bytes of
/// both the DKG and the signing rounds ([`crate::http::canonical`]), so the wire
/// layer and the log layer must agree on it exactly. Hence one definition here
/// rather than a copy in each.
#[must_use]
pub fn identifier_u16(id: Identifier) -> u16 {
    let bytes = id.serialize();
    let n = bytes.len();
    u16::from_be_bytes([bytes[n - 2], bytes[n - 1]])
}
