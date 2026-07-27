//! JSON payloads exchanged between SPOs during signing.

use frost::Identifier;
use frost_secp256k1_tr as frost;
use serde::{Deserialize, Serialize};

/// Signing Round 1: nonce commitments for one TM input in one epoch.
/// Each input runs an independent FROST session — `input_index`
/// disambiguates them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sign1Payload {
    pub epoch: u64,
    pub identifier: Identifier,
    pub input_index: u32,
    pub commitments: frost::round1::SigningCommitments,
}

/// Signing Round 2: the signature share for one TM input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sign2Payload {
    pub epoch: u64,
    pub identifier: Identifier,
    pub input_index: u32,
    pub share: frost::round2::SignatureShare,
}
