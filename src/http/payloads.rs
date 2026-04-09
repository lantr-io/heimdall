//! JSON payloads exchanged between SPOs during DKG and signing.

use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost::Identifier;
use serde::{Deserialize, Serialize};

/// DKG Round 1: an SPO's commitment package broadcast to every peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dkg1Payload {
    pub epoch: u64,
    pub identifier: Identifier,
    pub package: frost::keys::dkg::round1::Package,
}

/// DKG Round 2: an SPO's secret shares, one per recipient peer.
///
/// FIXME: confidentiality bug — `packages` is published as plaintext
/// JSON, so any peer can read every share, not just the one addressed
/// to them. RFC 9591 / Bifrost spec require per-recipient ECDH
/// encryption under `SpoInfo::bifrost_id_pk`. The FROST core is
/// unaffected (each recipient still gets the package `part3` expects),
/// but the transport leaks enough to reconstruct the group secret.
/// Fix together with the BIP-340 payload-auth TODO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dkg2Payload {
    pub epoch: u64,
    pub identifier: Identifier,
    pub packages: BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
}

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
