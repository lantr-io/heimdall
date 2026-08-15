//! Epoch state machine types.
//!
//! `EpochPhase` + its supporting data types. Everything that is safe
//! to persist derives `Serialize`/`Deserialize` so a future version
//! can write phase state to disk without touching the enum shape.
//! In-memory-only material (FROST secret packages, key packages,
//! nonces) is deliberately excluded from that contract.

use std::collections::BTreeMap;
use std::time::Duration;

use frost::Identifier;
use frost_secp256k1_tr as frost;
use serde::{Deserialize, Serialize};

use crate::cardano::dkg_roster::DkgContext;
use crate::cardano::pegin_datum::ParsedPegIn;

// ---------------------------------------------------------------------------
// Roster
// ---------------------------------------------------------------------------

/// One SPO's published identity from the on-chain registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpoInfo {
    pub identifier: Identifier,
    /// 28-byte `blake2b_224(cold_vkey)` membership id — the spec `pool_id`.
    /// Distinct from `identifier` (the 1..n DKG index): the spec URLs and
    /// canonical-byte layouts are keyed by this, not the index. Empty only
    /// in legacy fixtures predating WI-013.
    #[serde(default)]
    pub pool_id: Vec<u8>,
    pub bifrost_url: String,
    /// BIP-340 identity key used to authenticate peer payloads.
    ///
    /// DKG HTTP payloads are signed under this key and bind their replay
    /// namespace in the canonical bytes. Signing payloads still need the same
    /// end-to-end treatment before signing-share fault proofs are implemented.
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

    /// Locate this node's own entry by its bifrost identity key (the spec's
    /// `own_participant`): returns its FROST identifier + info, or `None` when
    /// the key is not in the roster (not registered / banned / URL-excluded).
    /// A `None` return must abort the ceremony rather than assume an index.
    pub fn own_participant(&self, bifrost_id_pk: &[u8]) -> Option<(Identifier, &SpoInfo)> {
        self.participants
            .iter()
            .find(|(_, info)| info.bifrost_id_pk.as_slice() == bifrost_id_pk)
            .map(|(id, info)| (*id, info))
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

/// This node's federation signing material: the typed-in membership plus its
/// share of `Y_federation`.
///
/// Phase 1 of the rollout runs with no DKG at all. The K1 bootstrap seeds the
/// Treasury state's `current_spos_frost_key` with `Y_federation` (spec §Rollout
/// Phases), so the treasury is locked under the federation key and the
/// federation is the **key-path** signer — an ordinary movement, no CSV wait, no
/// script path. There is no registry to run a ceremony over yet and no key to
/// rotate to, so the epoch machine skips `Dkg`/`PublishKeys` and signs with
/// this. See [`crate::epoch::machine`].
///
/// Deliberately the same shape the DKG produces, which is why no phase below
/// `EpochStart` needs to know which phase it is in: `CollectPegins`, `BuildTm`
/// and `Sign` take a [`GroupKeys`] and a [`Roster`] and cannot tell the two
/// apart. Phase 1 is an entry condition, not a mode.
///
/// Not to be confused with [`crate::federation::spend`], which signs with the
/// same key on the **script** path (the CSV recovery leaf) and therefore uses
/// the untweaked rounds. Same key, different spend path, different tweak.
#[derive(Debug, Clone)]
pub struct Phase1Signer {
    /// The federation membership in the shape the transport and the FROST
    /// rounds consume ([`crate::federation::roster::FederationRoster::to_roster`]).
    /// Addressed by `blake2b_224(bifrost_id_pk)` rather than a Cardano pool id,
    /// since a federation member need not be an SPO.
    pub roster: Roster,
    /// This node's share of `Y_federation`, as `federation-dkg` produced it.
    pub group_keys: GroupKeys,
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
    /// The peg-outs this TM fulfils, in payment-output order. Drives three
    /// things: the cpo_root the tx's BTMR1 output commits, the co-signer's
    /// pre-signing root check, and the `fulfilled_por_outpoints` hint
    /// `publish.rs` writes.
    pub fulfilled: Vec<crate::bitcoin::tm_builder::FulfilledPegOut>,
    /// The completed-peg-outs root this TM commits — the same 32 bytes
    /// `committed_cpo_root(&unsigned_tx)` reads back out of the BTMR1
    /// commitment output (script bytes [39, 71)).
    pub cpo_root: [u8; 32],
    /// The swept peg-ins root this TM commits: the builder's SPI trie advanced
    /// by every tx input except input 0 ([SPI-1], [SPI-3]). The same 32 bytes
    /// `committed_spi_root(&unsigned_tx)` reads back out of the BTMR1
    /// commitment output (script bytes [7, 39)); carried here so sign_phase
    /// can enforce the [SPI-2] co-signer gate and `advance_spi_trie` can
    /// cross-check before persisting.
    pub spi_root: [u8; 32],
}

impl TreasuryMovement {
    pub fn num_inputs(&self) -> usize {
        self.unsigned_tx.input.len()
    }

    /// Every tx input's previous outpoint, input order, in the 36-byte
    /// `tm_chain::outpoint_bytes` encoding – the exact `inputs` argument the
    /// swept peg-ins trie ([SPI-1], [SPI-2]) takes.
    pub fn input_outpoints(&self) -> Vec<[u8; 36]> {
        self.unsigned_tx
            .input
            .iter()
            .map(|i| crate::cardano::tm_chain::outpoint_bytes(&i.previous_output))
            .collect()
    }

    /// Per-input Taproot merkle root, encoded as `Option<Vec<u8>>` for the
    /// `frost::*_with_tweak` API which takes `Option<&[u8]>`.
    pub fn merkle_root_bytes(&self, input_index: usize) -> Option<Vec<u8>> {
        self.input_spend_info[input_index].merkle_root().map(|h| {
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

/// The active SPO threshold path for a signing session.
///
/// One variant on purpose, and it is not a stub. The spec keeps `mode` in the
/// signing namespace with a single value today "so that adding a future
/// threshold mode does not change any byte layout" (§Signing namespaces), so
/// the type stays even though it cannot vary.
///
/// **There is deliberately no `Federation` variant.** An earlier comment here
/// said `sign_phase` should demote to a federation script-path spend on
/// `quorum51_timeout`; that describes work the SPO program must never do. Per
/// §Threshold failover, "federation mode does not use the SPO HTTP endpoints…
/// it is an on-chain and Bitcoin-level emergency fallback", and per §Signing
/// namespaces it "has no signing namespace at all: it uses no SPO endpoints and
/// no FROST rounds". The federation signs out of band with `Y_federation` via
/// the CSV leaf, and the signed TM is posted permissionlessly like any other —
/// heimdall observes the result as an ordinary TM and plays no part in
/// producing it.
///
/// Nor is there an inter-mode timer to add: "the overall bound for the cascade
/// is therefore implicit… with no extra inter-mode timer" (§Threshold failover).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CascadeLevel {
    Quorum51,
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
    /// The DKG ceremony for one `(epoch, attempt)`. Carries the stake-aware
    /// [`DkgContext`] (not just a [`Roster`]) because the abort/rerun gate is
    /// stake-weighted: `ctx.epoch`/`ctx.attempt` namespace the payloads,
    /// `ctx.to_roster()` drives the FROST parameters, and `ctx.quorum_ok` /
    /// `ctx.reduced_to` decide whether an incomplete round reruns over a
    /// reduced candidate set or aborts the epoch.
    Dkg {
        round: DkgRound,
        ctx: DkgContext,
        collected: DkgCollected,
    },
    PublishKeys {
        epoch: u64,
        roster: Roster,
        group_keys: GroupKeys,
    },
    /// Wait for this epoch's next TM batch opportunity `B_i`, then freeze the
    /// observed peg-in set and advance to `BuildTm`.
    ///
    /// This is where the epoch's *batch* loop begins and ends: a confirmed
    /// movement returns here rather than to `Idle`, because the ceremony that
    /// produced `group_keys` runs once per EPOCH while the spec puts treasury
    /// movements on a slot grid *within* it (§TM batches and the protocol
    /// schedule). Re-entering `EpochStart` per movement would run a DKG and an
    /// Update-Y per batch, rotating the treasury key continuously.
    CollectPegins {
        epoch: u64,
        roster: Roster,
        group_keys: GroupKeys,
    },
    BuildTm {
        epoch: u64,
        roster: Roster,
        group_keys: GroupKeys,
        /// The batch opportunity `CollectPegins` froze at, and therefore the
        /// membership cutoff `C_i` this TM's peg-outs are selected against.
        ///
        /// Carried rather than re-derived: `BuildTm` reads its own chain snapshot
        /// (for the fee parameters and chain "now"), and a node that took the
        /// batch from THAT read would select against whichever opportunity was
        /// open by then — a different one whenever the read lands after `B_i`'s
        /// interval ends. One opportunity, decided once.
        ///
        /// `None` is a chain with no grid: no cutoff applies, as before N19.
        batch: Option<crate::epoch::batch::BatchSlot>,
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
        /// Carried, not used: `Submit` and `RecordMovement` are the last two hops
        /// before the machine returns to `CollectPegins` for the epoch's next
        /// batch, and it must arrive there holding the same ceremony output. The
        /// two phases used to drop it (`Submit` the keys, `RecordMovement` the
        /// roster as well), which is why a completed movement could only be
        /// followed by a fresh `EpochStart`.
        group_keys: GroupKeys,
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
    /// Write down what was just posted, so the fold that a confirmation owes the
    /// two tries survives this process.
    ///
    /// It does NOT wait for the confirmation. That wait is hours long — ~100
    /// Bitcoin confirmations plus the oracle's challenge-aging window — and
    /// blocking here made the fold depend on one process staying awake for all of
    /// it (WI-032). The waiting the protocol actually calls for is the batch
    /// gate's: at each `B_i`, an in-flight movement means the opportunity passes
    /// unused. The fold happens where the head is OBSERVED, in `CollectPegins`.
    RecordMovement {
        epoch: u64,
        /// See [`EpochPhase::Submit::group_keys`] — both ride through to the next
        /// batch's `CollectPegins`.
        roster: Roster,
        group_keys: GroupKeys,
        tm: TreasuryMovement,
    },
}

impl EpochPhase {
    /// Short human-readable phase name for tracing.
    pub fn name(&self) -> &'static str {
        match self {
            EpochPhase::Idle => "Idle",
            EpochPhase::EpochStart { .. } => "EpochStart",
            EpochPhase::Dkg {
                round: DkgRound::Round1,
                ..
            } => "Dkg(Round1)",
            EpochPhase::Dkg {
                round: DkgRound::Round2,
                ..
            } => "Dkg(Round2)",
            EpochPhase::Dkg {
                round: DkgRound::Part3,
                ..
            } => "Dkg(Part3)",
            EpochPhase::PublishKeys { .. } => "PublishKeys",
            EpochPhase::CollectPegins { .. } => "CollectPegins",
            EpochPhase::BuildTm { .. } => "BuildTm",
            EpochPhase::Sign {
                round: SigningRound::Round1,
                ..
            } => "Sign(Round1)",
            EpochPhase::Sign {
                round: SigningRound::Round2,
                ..
            } => "Sign(Round2)",
            EpochPhase::Submit { .. } => "Submit",
            EpochPhase::RecordMovement { .. } => "RecordMovement",
        }
    }
}

// ---------------------------------------------------------------------------
// Identity + config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SpoIdentity {
    /// This node's index in the roster, resolved ONCE at startup. It is a
    /// STARTING value only: the FROST index is positional (rank in the sorted
    /// eligible set), so it changes whenever the set does — e.g. a ban removes
    /// an earlier member and everyone after it shifts up. The epoch loop
    /// therefore re-derives the live index each epoch from the current context
    /// (see `epoch_start_phase`); this field is used only as the fixture/demo
    /// fallback when no `bifrost_id_pk` is configured.
    pub identifier: Identifier,
    /// This node's stable identity — its x-only bifrost key. Unlike `identifier`
    /// this never changes, so the loop looks itself up by this in each epoch's
    /// context to recompute its current index. Empty in the `--index` fixture
    /// demo, which has no key and trusts the configured `identifier`.
    pub bifrost_id_pk: Vec<u8>,
    pub port: u16,
}

/// Attempt-namespace budget per ceremony window (N21): the ceremony joining
/// grid window `k` uses wire attempts `k·A .. (k+1)·A`, so packages from
/// different windows can never collide (a late or re-entered node must never
/// mix a stale round-1 package into a fresh ceremony), and an in-window
/// reduction chain aborts rather than spilling into the next window's
/// namespace.
pub const DKG_ATTEMPTS_PER_WINDOW: u32 = 16;

#[derive(Debug, Clone)]
pub struct EpochConfig {
    /// Relative per-round DKG poll window, used as the deadline when the chain
    /// epoch boundary time is unknown (mock / no-registry fallback). When the
    /// boundary IS known, the schedule-anchored [`Self::dkg_round1_offset`] /
    /// [`Self::dkg_round2_offset`] take over.
    pub dkg_round_timeout: Duration,
    /// Ceremony-window grid pitch (N21). When the chain schedule anchor is
    /// known, a node entering DKG first sleeps to the next grid line
    /// (`epoch_boundary + k·dkg_window`), so every node — however late it
    /// started, or re-entering after an aborted attempt — runs the ceremony
    /// on the same schedule and under the same per-window attempt namespace.
    /// MUST exceed `dkg_round2_offset` by more than the retry backoff (~2 s):
    /// a node that aborts a window has to reach the very next grid line, or
    /// two cohorts that entered one line apart can cycle phase-locked and
    /// never merge.
    pub dkg_window: Duration,
    /// Upper bound on the pre-ceremony health gate (N21): how long a node
    /// waits for every roster peer to answer `/health` before proceeding
    /// without the missing ones. Bounds the wait only — liveness never
    /// depends on a peer coming up; an absent peer is then excluded by the
    /// normal quorum-gated reduction.
    pub dkg_join_wait: Duration,
    /// Round 1 deadline as an offset from the epoch boundary (WI-014 #6). All
    /// nodes anchor to the same chain-time instant, so they freeze the live
    /// subset L1 together regardless of when each locally started the round.
    pub dkg_round1_offset: Duration,
    /// Round 2 deadline as an offset from the epoch boundary (> round 1).
    pub dkg_round2_offset: Duration,
    /// Settling back-off used INSTEAD of the blind exponential when a failed DKG
    /// was accompanied by a detected chain-view disagreement on which THIS node
    /// was the stale side (older blockchain read-time). Because the real chain's
    /// `await_epoch_boundary` returns the current epoch immediately, the retry
    /// back-off IS the chain re-read cadence — so waiting a settling interval
    /// here makes the re-read land AFTER the disagreeing event (e.g. a ban)
    /// settles into this node's view, converging in one step instead of churning
    /// at 2/4/8 s against the still-unsettled tip. Bounded and self-terminating:
    /// once views reconcile there is no disagreement to re-arm it.
    pub dkg_reconcile_backoff: Duration,
    pub poll_interval: Duration,
    pub quorum51_timeout: Duration,
    pub leader_timeout: Duration,
    /// Ceiling on the retriable-error backoff. Not an operator key: it paces
    /// re-reads and nothing else, and a per-operator value could only make one
    /// node give up on a handoff sooner than another. Compiled in via
    /// `config::RETRY_BACKOFF_MAX`; tests shrink it so a bounded retry budget is
    /// observable in milliseconds rather than minutes.
    pub retry_backoff_max: Duration,
    pub identity: SpoIdentity,
    /// Cardano policy ID (script hash) identifying peg-in request UTxOs.
    pub pegin_policy_id: [u8; 28],
    /// Upper bound on how long the batch loop sleeps between grid checks.
    ///
    /// NOT a protocol value and deliberately not an operator key: it decides read
    /// rate, never TM bytes. The loop sleeps `min(slots until the next
    /// opportunity, this)` in BOTH waiting states — before `B_1` and after
    /// serving one — and because that hop shrinks as the opportunity approaches,
    /// the final sleep lands on it whatever this value is. The ceiling only bounds
    /// how stale a waiting node's view of the grid may get.
    ///
    /// The distinction matters more than it looks: a flat poll here would have
    /// each node notice `B_i` at its own offset past it, and `CollectPegins` reads
    /// the peg-in source once at that moment — so the offsets would become
    /// differences in what gets frozen.
    pub batch_poll_ceiling: Duration,
    /// Depositor refund timelock (BTC blocks) baked into the peg-in
    /// Taproot's depositor refund leaf. Spec default is 4320 (~30 days);
    /// testnet4/preprod typically use a smaller value.
    pub pegin_refund_timeout_blocks: u16,
    /// Directory for 0600 DKG-state persistence so the signing share survives
    /// process restarts for the epoch (WI-014 #5). `None` → in-memory only (the
    /// share is lost on restart and DKG re-runs next boundary).
    pub state_dir: Option<std::path::PathBuf>,
    /// The federation signing seed (`bitcoin.y_fed_seed_hex`), when this node
    /// has one. Used for exactly one thing: authorizing the BOOTSTRAP Update-Y,
    /// while the treasury is still keyed to `y_federation` and no roster exists
    /// to sign its own succession.
    ///
    /// Holding a seed grants nothing on its own —
    /// [`crate::epoch::rotation`] signs with it only when its x-only key IS the
    /// treasury's `current_spos_frost_key`. After the first handoff the key is
    /// the roster's and this seed stops matching, permanently.
    pub y_fed_seed: Option<[u8; 32]>,
    /// This node's federation share + membership, when it has run
    /// `federation-dkg` and the share is on disk ([`FederationSigner`]).
    ///
    /// `None` is not an error on its own: a node that is not a federation member
    /// is perfectly normal on a Phase-2 bridge, and merely idle on a Phase-1 one.
    /// Which of those it is depends on chain state, so the machine decides, not
    /// the loader.
    pub phase1_signer: Option<Phase1Signer>,
    /// Demo-only DKG fault injection (never set in production). Makes THIS node
    /// misbehave so the fault-detection + ban flow can be exercised live.
    pub inject_fault: Option<InjectFault>,
}

/// Demo-only fault-injection kinds (see [`EpochConfig::inject_fault`]). Present so
/// the fault-proof / SPO-ban flow can be exercised live in the scenario harness;
/// an honest deployment never sets this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectFault {
    /// Publish two distinct Round-1 DKG packages (equivocation). Honest peers'
    /// confirmatory re-fetch retains both, and the equivocation fault is reported
    /// against this node even though it also published a usable package.
    EquivocateRound1,
}

impl std::str::FromStr for InjectFault {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "equivocate-round1" | "equivocate_round1" => Ok(InjectFault::EquivocateRound1),
            other => Err(format!(
                "unknown --inject-fault kind '{other}' (expected: equivocate-round1)"
            )),
        }
    }
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
            dkg_window: Duration::from_secs(600),
            dkg_join_wait: Duration::from_secs(300),
            dkg_round1_offset: Duration::from_secs(120),
            dkg_round2_offset: Duration::from_secs(240),
            dkg_reconcile_backoff: Duration::from_secs(30),
            poll_interval: Duration::from_millis(5000),
            quorum51_timeout: Duration::from_secs(300),
            leader_timeout: Duration::from_secs(10000),
            retry_backoff_max: Duration::from_secs(60),
            identity,
            pegin_policy_id: [0u8; 28],
            batch_poll_ceiling: Duration::from_secs(300),
            pegin_refund_timeout_blocks: 4320,
            state_dir: None,
            y_fed_seed: None,
            phase1_signer: None,
            inject_fault: None,
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
    PollTimeout {
        got: usize,
        need: usize,
    },
    /// A DKG attempt could not complete (a peer was absent or provably faulty,
    /// so the qualified set can't run `dkg_part2`/`part3`) AND the surviving
    /// subset fails the quorum gate (`|Q| < t` or `stake(Q) <= 51%`) or is too
    /// small to rerun. Fatal for this epoch's DKG — the caller backs off to the
    /// next epoch boundary rather than killing the process.
    DkgAborted {
        epoch: u64,
        attempt: u32,
        qualified: usize,
        eligible: usize,
        reason: String,
    },
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
            Self::DkgAborted {
                epoch,
                attempt,
                qualified,
                eligible,
                reason,
            } => write!(
                f,
                "DKG aborted at epoch {epoch} attempt {attempt}: {qualified}/{eligible} qualified \
                 ({reason})"
            ),
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

// NOTE: `EpochError::is_retriable` used to split these into "back off" vs
// "kill the loop". It was removed on 2026-07-22: the epoch loop now backs off
// and re-enters `Idle` on EVERY error, because the fatal half of that split was
// a liveness bug. A peer on a different candidate set produced a FROST error,
// which the allowlist called fatal, which permanently terminated an honest
// node's loop — leaving it frozen on a stale roster with no way back, since
// re-deriving the roster is exactly what the loop does. Conditions that truly
// cannot be retried belong to startup validation, before the loop runs.

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
                pool_id: vec![],
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
    fn own_participant_locates_self_by_bifrost_key() {
        let mut participants = BTreeMap::new();
        for i in 1u16..=3 {
            let id = Identifier::try_from(i).unwrap();
            participants.insert(
                id,
                SpoInfo {
                    identifier: id,
                    pool_id: vec![i as u8; 28],
                    bifrost_url: format!("http://localhost:{}", 18500 + i),
                    // distinct per-participant bifrost key
                    bifrost_id_pk: vec![0xB0 + i as u8; 32],
                },
            );
        }
        let r = Roster {
            epoch: 7,
            min_signers: 2,
            max_signers: 3,
            participants,
        };

        // Found by its bifrost key → correct identifier + entry.
        let (id, info) = r.own_participant(&vec![0xB2; 32]).expect("self in roster");
        assert_eq!(id, Identifier::try_from(2u16).unwrap());
        assert_eq!(info.pool_id, vec![2u8; 28]);

        // An unknown key (not registered / banned / excluded) → None (must abort).
        assert!(r.own_participant(&vec![0xFF; 32]).is_none());
        // An empty key (legacy fixture) never matches a real entry.
        assert!(r.own_participant(&[]).is_none());
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
