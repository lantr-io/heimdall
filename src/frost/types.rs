/// Re-exports of FROST types that are serializable over the wire.
///
/// All types from `frost-secp256k1-tr` implement `serde::Serialize` and
/// `serde::Deserialize` when the `serialization` feature is enabled.
/// This module serves as documentation of which types travel over HTTP.
pub use frost_secp256k1_tr::{
    Identifier, Signature, SigningPackage,
    keys::{
        KeyPackage, PublicKeyPackage,
        dkg::{round1, round2},
    },
    round1::SigningCommitments,
    round2::SignatureShare,
};
