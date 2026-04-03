use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost::Identifier;
use serde::{Deserialize, Serialize};

/// DKG Round 1 payload: SPO publishes its commitment package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dkg1Payload {
    pub epoch: u64,
    pub identifier: Identifier,
    pub package: frost::keys::dkg::round1::Package,
}

/// DKG Round 2 payload: SPO publishes its secret shares (one per peer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dkg2Payload {
    pub epoch: u64,
    pub identifier: Identifier,
    pub packages: BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
}

/// Signing Round 1 payload: SPO publishes nonce commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sign1Payload {
    pub epoch: u64,
    pub identifier: Identifier,
    pub commitments: frost::round1::SigningCommitments,
}

/// Signing Round 2 payload: SPO publishes its signature share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sign2Payload {
    pub epoch: u64,
    pub identifier: Identifier,
    pub share: frost::round2::SignatureShare,
}
