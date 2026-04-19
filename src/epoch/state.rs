//! Epoch state machine types.
//!
//! `EpochPhase` + its supporting data types. Everything that is safe
//! to persist derives `Serialize`/`Deserialize` so a future version
//! can write phase state to disk without touching the enum shape.
//! In-memory-only material (FROST secret packages, key packages,
//! nonces) is deliberately excluded from that contract.

use std::collections::BTreeMap;
use std::time::Duration;

use frost_secp256k1_tr as frost;
use frost::Identifier;
use serde::{Deserialize, Serialize};

use crate::cardano::pegin_datum::ParsedPegIn;

// ---------------------------------------------------------------------------
// Roster
// ---------------------------------------------------------------------------

/// One SPO's published identity from the on-chain registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpoInfo {
    pub identifier: Identifier,
    pub bifrost_url: String,
    /// Reserved for BIP-340 payload authentication. Not enforced in v0.2.
    ///
    /// TODO: every DKG/sign payload delivered over the HTTP peer
    /// protocol should be signed under this key (BIP-340 Schnorr over
    /// secp256k1) and verified on receipt. Today publish/fetch accept
    /// unauthenticated JSON — a MITM or a dishonest peer can inject
    /// arbitrary commitments.
    /// FIXME: also need replay protection — payloads should bind to
    /// `(epoch, round, input_index)` under the signature so an old
    /// payload can't be replayed into a new session.
    #[serde(default)]
    pub bifrost_id_pk: Vec<u8>,
}

/// Snapshot of registered SPOs at an epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roster {
    pub epoch: u64,
    pub min_signers: u16,
    pub max_signers: u16,
    pub participants: BTreeMap<Identifier, SpoInfo>,
}

impl Roster {
    pub fn ids(&self) -> Vec<Identifier> {
        self.participants.keys().copied().collect()
    }

    pub fn peers_of(&self, of: Identifier) -> Vec<&SpoInfo> {
        self.participants
            .iter()
            .filter(|(id, _)| **id != of)
            .map(|(_, info)| info)
            .collect()
    }

    /// Designated leader for the given attempt. Today this is just the
    /// lowest-identifier participant; future cuts will rotate on
    /// `leader_attempt` so a stuck leader can be replaced.
    ///
    /// TODO: real leader rotation. The right rule is something like
    /// `participants[(epoch + attempt) mod n]` so a stuck leader is
    /// deterministically replaced after `leader_timeout`. The signature
    /// already takes `attempt` so callers don't need to change.
    pub fn leader(&self, _attempt: u8) -> Identifier {
        *self
            .participants
            .keys()
            .next()
            .expect("roster has at least one participant")
    }
}

// ---------------------------------------------------------------------------
// Group keys (output of DKG)
// ---------------------------------------------------------------------------

/// FROST DKG output, held by a single SPO. Not serialized in v0.2 since
/// `KeyPackage` does not derive serde without the `serialization` feature
/// flag exposed at this layer; treated as in-memory only.
#[derive(Debug, Clone)]
pub struct GroupKeys {
    /// The internal key (untweaked) — used as Y_51 in the Taproot tree.
    pub verifying_key: frost::VerifyingKey,
    pub public_key_package: frost::keys::PublicKeyPackage,
    /// This SPO's signing share.
    pub key_package: frost::keys::KeyPackage,
}

// ---------------------------------------------------------------------------
// Treasury Movement (output of BuildTm)
// ---------------------------------------------------------------------------

/// The unsigned-or-signed Treasury Movement transaction the epoch is
/// driving towards. Held in memory; not serialized.
#[derive(Debug, Clone)]
pub struct TreasuryMovement {
    /// txid of the unsigned tx; stable across all SPOs.
    pub txid: bitcoin::Txid,
    /// Raw unsigned transaction (no witnesses).
    pub unsigned_tx: bitcoin::Transaction,
    /// Prevouts in input order, needed for sighash recomputation.
    pub prevouts: Vec<bitcoin::TxOut>,
    /// Per-input Taproot spend info — `.merkle_root()` is the BIP-341
    /// tweak input, `.output_key()` is the on-chain script pubkey.
    pub input_spend_info: Vec<bitcoin::taproot::TaprootSpendInfo>,
    /// BIP-341 key-path sighashes, one per input.
    pub sighashes: Vec<[u8; 32]>,
    /// Final aggregated Schnorr signature per input, populated after Sign.
    pub signatures: Vec<Option<frost::Signature>>,
}

impl TreasuryMovement {
    pub fn num_inputs(&self) -> usize {
        self.unsigned_tx.input.len()
    }

    /// Per-input Taproot merkle root, encoded as `Option<Vec<u8>>` for the
    /// `frost::*_with_tweak` API which takes `Option<&[u8]>`.
    pub fn merkle_root_bytes(&self, input_index: usize) -> Option<Vec<u8>> {
        self.input_spend_info[input_index]
            .merkle_root()
            .map(|h| {
                use bitcoin::hashes::Hash;
                h.as_byte_array().to_vec()
            })
    }
}

// ---------------------------------------------------------------------------
// DKG progress
// ---------------------------------------------------------------------------

/// Sub-round of the DKG phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DkgRound {
    Round1,
    Round2,
    Part3,
}

/// In-progress DKG state. The secret packages are produced by `frost`
/// without serde support — they live in this struct between rounds and
/// must not be persisted in v0.2.
//
// TODO (v0.3): add `sled`-backed persistence around `DkgCollected` so a
// crash mid-DKG can resume without restarting the protocol from Round1.
// The secret packages from `frost` are not `Serialize` today; v0.3 needs
// either a wrapper that stores the raw polynomial coefficients or a
// patch upstream.
#[derive(Debug, Default)]
pub struct DkgCollected {
    pub round1_mine: Option<frost::keys::dkg::round1::SecretPackage>,
    pub round1_peers: BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
    pub round2_mine: Option<frost::keys::dkg::round2::SecretPackage>,
    pub round2_peers: BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
}

// ---------------------------------------------------------------------------
// Signing progress
// ---------------------------------------------------------------------------

/// Sub-round of the Sign phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SigningRound {
    Round1,
    Round2,
}

/// Signing cascade level (only `Quorum67` exercised in v0.2 first cycle).
///
/// TODO: implement the `Quorum51` and `Federation` fallback paths. When
/// `Quorum67` fails to collect a threshold of signatures within
/// `EpochConfig::quorum67_timeout`, `sign_phase` should transition to
/// `Quorum51`, and finally to `Federation` (script-path spend using the
/// federation fallback leaf after `federation_csv_blocks`). Today the
/// cascade is a type-level placeholder; `sign_phase` never demotes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CascadeLevel {
    Quorum67,
    Quorum51,
    Federation,
}

/// In-progress signing state. Per-input maps because each TM input
/// runs an independent FROST session in parallel — sighashes and
/// taproot tweaks differ per input.
#[derive(Debug, Default)]
pub struct SignCollected {
    pub round1: BTreeMap<u32, BTreeMap<Identifier, frost::round1::SigningCommitments>>,
    pub round2: BTreeMap<u32, BTreeMap<Identifier, frost::round2::SignatureShare>>,
    /// This SPO's per-input nonces. Memory-only; v0.3 adds persistence.
    ///
    /// FIXME: nonces MUST survive process restarts and MUST NEVER be
    /// reused across signing attempts on different messages — reusing a
    /// FROST nonce across two sighashes leaks the signing share. Today
    /// a crash between Round1 and Round2 would lose the nonces and a
    /// naive restart could produce a fresh nonce for the same session.
    /// v0.3 needs atomic `sled` persistence of `(epoch, input, nonces)`
    /// keyed such that a second Round1 attempt on the same input loads
    /// the existing nonces instead of generating new ones.
    pub nonces: BTreeMap<u32, frost::round1::SigningNonces>,
}

// ---------------------------------------------------------------------------
// Phase enum
// ---------------------------------------------------------------------------

/// The main epoch state machine. Each variant carries the data needed to
/// resume that phase. Variant transitions happen in `machine::run_epoch_loop`.
#[derive(Debug)]
pub enum EpochPhase {
    Idle,
    EpochStart {
        epoch: u64,
    },
    Dkg {
        epoch: u64,
        round: DkgRound,
        roster: Roster,
        collected: DkgCollected,
    },
    PublishKeys {
        epoch: u64,
        roster: Roster,
        group_keys: GroupKeys,
    },
    /// Poll the Cardano peg-in source over a collection window, then
    /// freeze the observed set and advance to `BuildTm`.
    CollectPegins {
        epoch: u64,
        roster: Roster,
        group_keys: GroupKeys,
    },
    BuildTm {
        epoch: u64,
        roster: Roster,
        group_keys: GroupKeys,
        /// Frozen peg-in set from `CollectPegins`. Every SPO consumes
        /// the same list to build byte-identical unsigned TM bytes.
        frozen_pegins: Vec<ParsedPegIn>,
    },
    Sign {
        epoch: u64,
        roster: Roster,
        cascade: CascadeLevel,
        group_keys: GroupKeys,
        tm: TreasuryMovement,
        round: SigningRound,
        collected: SignCollected,
    },
    Submit {
        epoch: u64,
        roster: Roster,
        tm: TreasuryMovement,
        /// Which leader-rotation attempt this is. `Roster::leader` maps
        /// it to the designated submitter for the round.
        ///
        /// TODO: a `leader_timeout`-driven rotation is not implemented:
        /// today the leader is always `Roster::leader(0)` and a stuck
        /// leader is not replaced. Bumping `leader_attempt` is the
        /// right knob, but nothing currently bumps it.
        leader_attempt: u8,
    },
    AwaitConfirm {
        epoch: u64,
        tm: TreasuryMovement,
        cardano_tx_id: Vec<u8>,
    },
}

impl EpochPhase {
    /// Short human-readable phase name for tracing.
    pub fn name(&self) -> &'static str {
        match self {
            EpochPhase::Idle => "Idle",
            EpochPhase::EpochStart { .. } => "EpochStart",
            EpochPhase::Dkg { round: DkgRound::Round1, .. } => "Dkg(Round1)",
            EpochPhase::Dkg { round: DkgRound::Round2, .. } => "Dkg(Round2)",
            EpochPhase::Dkg { round: DkgRound::Part3, .. } => "Dkg(Part3)",
            EpochPhase::PublishKeys { .. } => "PublishKeys",
            EpochPhase::CollectPegins { .. } => "CollectPegins",
            EpochPhase::BuildTm { .. } => "BuildTm",
            EpochPhase::Sign { round: SigningRound::Round1, .. } => "Sign(Round1)",
            EpochPhase::Sign { round: SigningRound::Round2, .. } => "Sign(Round2)",
            EpochPhase::Submit { .. } => "Submit",
            EpochPhase::AwaitConfirm { .. } => "AwaitConfirm",
        }
    }
}

// ---------------------------------------------------------------------------
// Identity + config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SpoIdentity {
    pub identifier: Identifier,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct EpochConfig {
    pub dkg_round_timeout: Duration,
    pub poll_interval: Duration,
    pub quorum67_timeout: Duration,
    pub quorum51_timeout: Duration,
    pub federation_timeout: Duration,
    pub leader_timeout: Duration,
    pub identity: SpoIdentity,
    /// Cardano policy ID (script hash) identifying peg-in request UTxOs.
    pub pegin_policy_id: [u8; 28],
    /// How long `CollectPegins` polls the peg-in source before freezing.
    pub pegin_collection_window: Duration,
    /// Interval between successive peg-in polls inside the window.
    pub pegin_poll_interval: Duration,
    /// Depositor refund timelock (BTC blocks) baked into the peg-in
    /// Taproot's depositor refund leaf. Spec default is 4320 (~30 days);
    /// testnet4/preprod typically use a smaller value.
    pub pegin_refund_timeout_blocks: u16,
}

impl EpochConfig {
    /// Tight timeouts suitable for in-process demo runs.
    ///
    /// TODO: these values are placeholders — a real deployment needs
    /// timeouts derived from Cardano slot length and measured P2P
    /// round-trip times, not arbitrary 30s picks.
    pub fn demo_default(identity: SpoIdentity) -> Self {
        Self {
            dkg_round_timeout: Duration::from_secs(300),
            poll_interval: Duration::from_millis(5000),
            quorum67_timeout: Duration::from_secs(300),
            quorum51_timeout: Duration::from_secs(300),
            federation_timeout: Duration::from_secs(300),
            leader_timeout: Duration::from_secs(10000),
            identity,
            pegin_policy_id: [0u8; 28],
            pegin_collection_window: Duration::from_secs(5),
            pegin_poll_interval: Duration::from_millis(1000),
            pegin_refund_timeout_blocks: 4320,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum EpochError {
    Frost(String),
    TmBuild(String),
    // TODO: track which peers failed to deliver so the cascade / slashing
    // path can identify the misbehaving party. Today `PollTimeout` only
    // carries aggregate counts.
    PollTimeout { got: usize, need: usize },
    Peer(String),
    Chain(String),
    Transition(String),
    SignatureVerify(usize, String),
}

impl std::fmt::Display for EpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frost(s) => write!(f, "FROST: {s}"),
            Self::TmBuild(s) => write!(f, "Bitcoin tx build failed: {s}"),
            Self::PollTimeout { got, need } => {
                write!(f, "peer poll timed out: got {got}, need {need}")
            }
            Self::Peer(s) => write!(f, "peer network: {s}"),
            Self::Chain(s) => write!(f, "chain: {s}"),
            Self::Transition(s) => write!(f, "invalid phase transition: {s}"),
            Self::SignatureVerify(i, s) => {
                write!(f, "signature verification failed for input {i}: {s}")
            }
        }
    }
}

impl std::error::Error for EpochError {}

pub type EpochResult<T> = Result<T, EpochError>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_roundtrip_serde() {
        let mut participants = BTreeMap::new();
        participants.insert(
            Identifier::try_from(1u16).unwrap(),
            SpoInfo {
                identifier: Identifier::try_from(1u16).unwrap(),
                bifrost_url: "http://localhost:18500".to_string(),
                bifrost_id_pk: vec![],
            },
        );
        let r = Roster {
            epoch: 42,
            min_signers: 2,
            max_signers: 3,
            participants,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Roster = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn dkg_round_serde() {
        for r in [DkgRound::Round1, DkgRound::Round2, DkgRound::Part3] {
            let s = serde_json::to_string(&r).unwrap();
            let back: DkgRound = serde_json::from_str(&s).unwrap();
            assert_eq!(r, back);
        }
    }
}
