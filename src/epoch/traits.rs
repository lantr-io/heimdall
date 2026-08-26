//! Trait abstractions over external systems.
//!
//! `CardanoChain` models the *chain-hosted oracle views* the epoch
//! state machine consumes: the SPO registry snapshot (roster), the
//! current treasury UTxO (delivered by a watchtower-maintained oracle,
//! NOT by a Bitcoin node directly), and pending peg-out requests. The
//! peg-in discovery path is separate — `CardanoPegInSource` in the
//! `cardano` module polls a real Cardano node via pallas N2C.
//!
//! `PeerNetwork` is the pull-only HTTP surface between SPOs, used for
//! DKG and signing round data.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::keys::dkg::{round1, round2};

use crate::circuits::fault_evidence::{
    EquivocationEvidence, Round1PokFaultEvidence, Round2ShareFaultEvidence,
};
use crate::epoch::state::{EpochResult, Roster, SpoInfo};
use crate::http::canonical::POINT_LEN;
use crate::http::wire::{DkgNamespace, SignNamespace};

// ---------------------------------------------------------------------------
// CardanoChain
// ---------------------------------------------------------------------------

/// Notification that a new epoch boundary has been observed on Cardano.
#[derive(Debug, Clone)]
pub struct EpochBoundaryEvent {
    pub epoch: u64,
}

/// A pending peg-out request.
///
/// Carries everything the rev-5.1 builder needs: the payment, the request's own
/// datum-pinned fee and `created` time, and its identity (`por_id` = the
/// completed-peg-outs trie key, `outpoint` = the TM datum's hint entry).
#[derive(Debug, Clone)]
pub struct PegOutRequestUtxo {
    pub script_pubkey: bitcoin::ScriptBuf,
    /// Gross locked fBTC.
    pub amount: bitcoin::Amount,
    /// `per_pegout_fee` from this request's own datum. The TM pays
    /// `amount − per_pegout_fee`.
    pub per_pegout_fee: bitcoin::Amount,
    /// `created` (POSIX ms) from the datum — the freshness filter's input.
    pub created: i64,
    /// `sha256(serialise_data(OutputReference))` of the request UTxO.
    pub por_id: [u8; 32],
    /// The request's Cardano outpoint, 36 bytes (tx hash ‖ output index LE).
    pub outpoint: [u8; 36],
    /// Absolute Cardano slot this request UTxO was created at — the TM batch
    /// cutoff's input, and the leading component of the FIFO order (see
    /// [`crate::epoch::batch`]). NOT the datum's requester-set `created`, which
    /// anyone may backdate. `None` = unresolved, which defers the request.
    pub created_slot: Option<u64>,
}

/// The current treasury UTxO state, as reported by the Cardano-side
/// oracle (Binocular / watchtower). The SPO never queries Bitcoin
/// directly for this — a trusted oracle UTxO on Cardano carries the
/// outpoint and value, and the SPO reads it from there.
///
/// It carries no fee parameters: those are the Config UTxO's operational
/// parameters, read per batch as [`BatchSnapshot::tm_params`] (WI-040). They used
/// to ride along here, sourced from each node's own `heimdall.toml` — a
/// per-operator value in a computation every SPO must agree on byte-for-byte.
///
/// `y_51` is the internal key of the *current* treasury — the key it
/// was locked under. `BuildTm` uses `y_51` for the treasury *input*
/// spend info, and the new FROST group key for the *change output*.
/// At bootstrap `y_51 = y_fed`; after `publish_group_key` it is the
/// active FROST group key.
#[derive(Debug, Clone)]
pub struct TreasuryUtxo {
    pub outpoint: bitcoin::OutPoint,
    pub value: bitcoin::Amount,
    /// The Taproot internal key of the *current* treasury (the Y_51 it
    /// was locked under). At bootstrap this equals `y_fed`; after the
    /// first DKG it is the previous epoch's FROST group x-only key.
    ///
    /// **This is the field that decides who can SIGN a movement, and only this
    /// one.** A movement is a key-path spend of the head, so it is authorized by
    /// a signature under this key and by nothing else — the datum's
    /// [`Self::authorized_key`] is a Cardano statement of intent that Bitcoin
    /// never reads. The two agree except for the one movement after an Update-Y,
    /// and that movement is precisely the one a node must not decline on the
    /// strength of the datum.
    pub y_51: bitcoin::key::UntweakedPublicKey,
    /// The federation leaf key of the TREASURY tree — chosen by matching the head's
    /// scriptPubKey against the candidates, so on a bridge still using the collapsed
    /// `Y_fed = Y_51` convention this reports `y_51`. Correct for rebuilding the treasury
    /// tree; WRONG for anything a depositor must agree with, which is why the peg-in tree
    /// takes `config_y_fed` instead.
    pub y_fed: bitcoin::key::UntweakedPublicKey,
    /// The federation key the bridge PUBLISHES (Config `y_federation`) — the value a
    /// depositor is told to build their deposit under, and therefore the one the peg-in
    /// tree's emergency-sweep leaf must use. Equal to `y_fed` on a bridge whose treasury
    /// head is locked under the published key; different while one is mid-rotation.
    pub config_y_fed: bitcoin::key::UntweakedPublicKey,
    /// `current_spos_frost_key` from the treasury_info datum — the key the bridge
    /// AUTHORIZES to move the treasury right now.
    ///
    /// Distinct from [`Self::y_51`], which is what the head UTxO is LOCKED under.
    /// The two agree except in the window between an Update-Y and the handoff
    /// movement that acts on it: Cardano rotates the datum immediately, but the
    /// BTC stays under the old key until a movement spends it there and pays the
    /// change to the new address.
    ///
    /// This is the field that decides the ROLLOUT PHASE, and where a movement's
    /// change output PAYS — and only those. §Rollout Phases: "there is no phase
    /// flag anywhere — the transition *is* the first Update-Y", so
    /// `authorized_key == config_y_fed` is precisely the statement that no
    /// Update-Y has ever landed. Comparing `y_51` instead would answer a
    /// different question and get it wrong for a whole movement's worth of the
    /// handoff.
    ///
    /// It does NOT decide who signs. That is [`Self::y_51`], because a share is
    /// authority over the key its own ceremony produced and the head is locked
    /// under that key whatever the datum says. Reading this field as "who may
    /// move the treasury" deadlocks the handoff: the roster the datum names
    /// cannot spend the head, and the party that can believes it is retired.
    pub authorized_key: bitcoin::key::UntweakedPublicKey,
    pub federation_csv_blocks: u16,
    /// The peg-in refund leaf's CSV delay, Config `params[8]` ([CFG-9]) — carried
    /// beside the federation delay because the peg-in tree needs both, and both
    /// must come from the bridge rather than from each node's own file.
    pub pegin_refund_timeout_blocks: u16,
    /// Internal keys this bridge has published and moved PAST — neither the head's
    /// nor the datum's — newest first.
    ///
    /// They buy exactly one thing: the ability to NAME a deposit the bridge is no
    /// longer sweeping. A movement is signed with a single key package, so it can
    /// only spend inputs under the head's internal key; once the head has moved on,
    /// nothing signs under these again, and the deposit's own tree — the
    /// federation's sweep leaf first, the depositor's refund after it — is the way
    /// back. Recognising the address turns that from silence into a warning.
    ///
    /// "Nothing signs under these again" describes this implementation, not the
    /// protocol: the retired ceremony's key package is still on disk, and one
    /// Bitcoin transaction may spend inputs under several keys. WI-GC1FV weighs
    /// signing them in a second FROST session.
    ///
    /// Unlike its neighbours this is NOT a bridge-wide value: it comes from what
    /// this node persisted plus the published federation key, so two nodes can
    /// legitimately disagree about it. That is only sound because it cannot change
    /// batch membership in either direction — a `Retired` match and a match against
    /// nothing at all are both refused, so the set a movement is built from is
    /// identical whatever this field holds. Do not give it a consensus job. Empty
    /// is always a safe answer: it costs a warning, not a coin.
    pub retired_internal_keys: Vec<bitcoin::key::UntweakedPublicKey>,
    /// Whether it is safe to begin the NEXT treasury movement off this UTxO.
    /// A new movement can only begin once the previous one is confirmed, so the
    /// Blockfrost impl (WI-028) sets this false when an Unconfirmed TM (or an
    /// in-flight TM it could not read) is already spending this tip; the mock
    /// reports a simple always-confirmed treasury.
    pub btc_confirmed: bool,
}

/// Where a peg-in tree's INTERNAL key comes from — which decides what a node may
/// do with a deposit sitting under it.
///
/// The distinction exists because a movement is a set of key-path spends signed
/// with ONE key package (`signing::sign_phase` passes the same one for every
/// input, varying only the Taproot merkle root). So a movement can only take
/// inputs whose internal key is the key that spends the head, and "which address
/// does a deposit sit at" and "can this bridge ever sweep it" are two questions,
/// not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeginKeyOrigin {
    /// The datum's key and the head's key at once — the steady state, in which the
    /// address the bridge publishes is also the one it can sweep.
    Current,
    /// [`TreasuryUtxo::authorized_key`] alone: the address the bridge publishes,
    /// while the head is still locked under the key it supersedes. A depositor
    /// building from the chain lands here for the whole handoff window (spec
    /// §Rollout Phases step 5: from the Update-Y on, depositors derive peg-in
    /// addresses from the new key). Nothing can sweep it until the handoff
    /// confirms — a deferral, not a loss.
    Published,
    /// [`TreasuryUtxo::y_51`] alone: the address depositors were given BEFORE the
    /// Update-Y. The movement that spends the current head is the last one that
    /// takes these, because no later movement signs under this key — a limit of
    /// how movements are signed here (one key package for every input), not of
    /// Bitcoin, which is content with a transaction whose inputs sit under
    /// different keys. See WI-GC1FV.
    Head,
    /// A ceremony the bridge has moved past. No movement signs under it any more,
    /// so nothing sweeps it as things stand — recoverable in principle by signing
    /// with the retired key package, which is still on disk (WI-GC1FV), and in
    /// practice by the deposit's own tree: the federation's sweep leaf first, the
    /// depositor's refund after it.
    Retired,
}

impl PeginKeyOrigin {
    /// Whether a movement built against the CURRENT head can spend a deposit under
    /// this key — i.e. whether this is the head's key.
    #[must_use]
    pub fn sweepable(self) -> bool {
        matches!(self, Self::Current | Self::Head)
    }

    /// Short label for logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Published => "published",
            Self::Head => "head",
            Self::Retired => "retired",
        }
    }
}

impl TreasuryUtxo {
    /// The peg-in Taproot tree this bridge PUBLISHES — the canonical answer to "what
    /// address does a deposit land at", for every reader that can see the oracle.
    ///
    /// It exists because the mapping is not obvious and getting it wrong is silent. Both
    /// keys are the ones the bridge publishes rather than the ones its head happens to be
    /// locked under:
    ///
    /// - the INTERNAL key is [`Self::authorized_key`], the `current_spos_frost_key` the
    ///   treasury_info datum names. Spec §Rollout Phases step 5 is explicit that from the
    ///   Update-Y onward "depositors derive peg-in addresses from `Y_51'`", and §Peg-in
    ///   Taproot tree sources both keys from `treasury.ak` — the state UTxO, not the head's
    ///   scriptPubKey, which no Cardano-only reader can compute at all;
    /// - the federation LEAF key is [`Self::config_y_fed`], NOT [`Self::y_fed`], which is
    ///   whichever candidate reproduces the HEAD's scriptPubKey and equals `y_51` on a
    ///   bridge still using the collapsed convention.
    ///
    /// Everything here is an `UntweakedPublicKey` or a `u16`, so nothing but this function
    /// stands between a caller and a well-formed address holding nothing.
    ///
    /// This is the address to PUBLISH. It is not necessarily one this bridge can sweep
    /// today — see [`Self::pegin_trees`], which is what a node parses against.
    ///
    /// Fails when the published pair breaks the spec's ordering rule; that is a
    /// misconfiguration of the bridge, not an invariant a node may assume.
    pub fn pegin_tree(&self) -> Result<crate::bitcoin::taproot::PeginTreeParams, String> {
        self.pegin_tree_for(self.authorized_key)
    }

    /// The peg-in tree for one internal key. Everything else in the tree is
    /// bridge-wide, so this is the only axis a caller may vary.
    fn pegin_tree_for(
        &self,
        internal: bitcoin::key::UntweakedPublicKey,
    ) -> Result<crate::bitcoin::taproot::PeginTreeParams, String> {
        let tree = crate::bitcoin::taproot::PeginTreeParams {
            y_51: internal,
            y_federation: self.config_y_fed,
            federation_csv_blocks: self.federation_csv_blocks,
            refund_timeout: self.pegin_refund_timeout_blocks,
        };
        tree.validate()?;
        Ok(tree)
    }

    /// Every peg-in tree a node must RECOGNISE, most current first, each tagged with
    /// what it is.
    ///
    /// A single tree is not enough, and which single tree it should be is not a
    /// question with a stable answer. During a handoff the bridge publishes one
    /// address and can sweep a different one: deposits keep arriving at the old
    /// address for as long as depositors hold a stale view, and spec-compliant
    /// deposits arrive at the new one from the Update-Y onward. Parsing against one
    /// tree drops the other half with a `warn!` — deposits the bridge is holding
    /// and can see.
    ///
    /// Recognising them all costs one extra Taproot derivation per tree per request
    /// — and only that, because the tree-independent half of the parse is done once
    /// (`pegin_datum::decode_pegin_request`). Where the datum and the head agree and
    /// nothing has been superseded there is exactly one tree; on a bridge that has
    /// rotated even once there is one more per retired key it still recognises. What a node may DO with each match is
    /// [`PeginKeyOrigin::sweepable`]'s answer, not this one's.
    ///
    /// KNOWN LIMIT: only the internal key varies across these trees. The other
    /// three tap-tweak inputs — the published federation key, its CSV delay and the
    /// refund timeout — are one value each, applied to every tree including the
    /// retired ones. They are now the values the CURRENT BATCH pinned rather than
    /// the ones this process booted with, so a governance move of `y_federation`,
    /// `params[7]` or `params[8]` is followed from the next batch and every
    /// co-signer follows it together. What is still not covered is HISTORY: a
    /// deposit made before such a move reconstructs under none of these trees and
    /// falls back to being dropped, because covering it needs the whole
    /// `(internal, leaf, csv, timeout)` tuple that was live at deposit time and a
    /// list of internal keys cannot express one.
    pub fn pegin_trees(
        &self,
    ) -> Result<Vec<(PeginKeyOrigin, crate::bitcoin::taproot::PeginTreeParams)>, String> {
        let mut out = Vec::with_capacity(2 + self.retired_internal_keys.len());
        if self.authorized_key == self.y_51 {
            out.push((PeginKeyOrigin::Current, self.pegin_tree()?));
        } else {
            // Published first: it is the address the bridge tells depositors to use,
            // so it is the one a growing share of requests will match.
            out.push((PeginKeyOrigin::Published, self.pegin_tree()?));
            out.push((PeginKeyOrigin::Head, self.pegin_tree_for(self.y_51)?));
        }
        for k in &self.retired_internal_keys {
            if *k == self.authorized_key || *k == self.y_51 {
                continue;
            }
            out.push((PeginKeyOrigin::Retired, self.pegin_tree_for(*k)?));
        }
        Ok(out)
    }
}

/// The consensus inputs a TM batch is frozen against, all read at ONE chain point
/// (spec §Operational parameters, determinism rule; WI-040).
///
/// Both fields decide TM bytes — `now_ms` through the peg-out freshness filter,
/// `tm_params` through the miner fee and the two selection floors — so they are
/// taken together rather than polled independently: a node that read its fee rate
/// at one slot and its "now" at another has no single moment it can claim to have
/// built for. Today the point is the chain tip when the batch is frozen; the batch
/// grid (plan N19) will make it a shared grid slot, at which point every SPO reads
/// the identical snapshot by construction.
#[derive(Debug, Clone)]
pub struct BatchSnapshot {
    /// Chain "now", POSIX milliseconds — the tip block's time. A CHAIN time
    /// converges across nodes; a local wall clock does not.
    pub now_ms: i64,
    /// Absolute Cardano slot of the snapshot.
    pub slot: u64,
    /// Where this snapshot stands on the TM batch grid (spec §TM batches).
    /// `Open` carries the membership cutoff; `Closed` means the opportunity passes
    /// unused; `NoGrid` is the dev/mock case, where no cutoff is applied at all.
    /// FIFO order and the capacity caps are pure and apply in every case.
    pub batch: crate::epoch::batch::BatchWindow,
    /// Operational parameters in force at the snapshot — the Config's `params[1..=3]`. (`params[0]`, the
    /// schedule, is not here: nothing in TM construction consumes it. It is decoded
    /// by `cardano::config_params` and reported by `show-config-params` / the
    /// mover's startup banner, and drives the batch grid when plan N19 lands.)
    pub tm_params: crate::bitcoin::tm_builder::TmParams,
    /// Cardano's `max_tx_size` for the epoch this snapshot falls in (WI-107,
    /// spec rev 5.6). A HOST protocol parameter, read from the chain per epoch —
    /// Conway governance can change it, so a hardcoded 16 384 would eventually
    /// either refuse batches the chain could carry or sign ones it cannot post.
    pub max_tx_size: u64,
    /// `E`: the Post-TM bytes that do not scale with the batch. Derived from the
    /// deployment (chiefly whether the TM validator rides inline), not
    /// configured — see [`crate::epoch::batch::TmBudget`].
    pub post_tm_envelope: u64,
    /// `leader_slot_T` — the cascade hop, in slots (Config `params[0].leader_slot_t`,
    /// spec §Cardano submission and leader reward; WI-104).
    ///
    /// Here rather than in `[protocol]` because every SPO must step through the
    /// roster together: a per-operator hop would have each node decide on its own
    /// when its turn began, so two of them would post at once and one would burn a
    /// fee. It rides in this snapshot for the same reason the fee rate does — it is
    /// a published value read at one chain point.
    pub leader_slot_t: u64,
    /// `sign_r1_window` / `sign_r2_window` — the FROST round deadlines, in slots,
    /// measured from the batch opportunity `B_i` (Config `params[0]`, spec §TM
    /// batches; WI-077).
    ///
    /// These decide MEMBERSHIP of the signing subset `S1`, so they cannot be a
    /// per-operator timeout: two operators on different values disagree about a
    /// peer that answers between them, build different `SigningPackage`s, and
    /// their shares never aggregate. That is exactly why they are read here and
    /// not from `[protocol].quorum51_timeout_secs`.
    pub sign_r1_window: u64,
    pub sign_r2_window: u64,
    /// Absolute slot of this epoch's `update_y_deadline`, when the deployment has
    /// an epoch anchor to measure it from.
    ///
    /// The rotation ceremony is not per-batch and has no `B_i`, so this is what
    /// it closes against instead. `None` where there is no grid at all.
    pub update_y_close_slot: Option<u64>,
    /// Config UTxO the parameters came from, or the local-override reason.
    pub source: crate::cardano::config_params::ParamSource,
}

impl BatchSnapshot {
    /// A snapshot whose parameters came from this node's own config rather than
    /// the chain — mocks, offline CLI paths, and Config-less deployments.
    ///
    /// `max_tx_size` falls back to the value every Cardano network has carried
    /// since Alonzo. That is a guess, and a guessed consensus value is exactly
    /// what this codebase must not ship silently — which is why it is reachable
    /// only through this constructor, whose whole purpose is to stamp
    /// [`ParamSource::LocalOverride`] on the result so the reason travels with it.
    ///
    /// [`ParamSource::LocalOverride`]: crate::cardano::config_params::ParamSource::LocalOverride
    #[must_use]
    pub fn local_override(
        now_ms: i64,
        tm_params: crate::bitcoin::tm_builder::TmParams,
        why: &'static str,
    ) -> Self {
        Self {
            now_ms,
            slot: 0,
            batch: crate::epoch::batch::BatchWindow::NoGrid,
            tm_params,
            max_tx_size: DEFAULT_MAX_TX_SIZE,
            post_tm_envelope: POST_TM_ENVELOPE_WITHOUT_SCRIPT,
            leader_slot_t: DEFAULT_LEADER_SLOT_T,
            sign_r1_window: DEFAULT_SIGN_WINDOW,
            sign_r2_window: DEFAULT_SIGN_WINDOW,
            update_y_close_slot: None,
            source: crate::cardano::config_params::ParamSource::LocalOverride(why),
        }
    }

    /// The batch capacity rule in force at this snapshot.
    #[must_use]
    pub fn budget(&self) -> crate::epoch::batch::TmBudget {
        crate::epoch::batch::TmBudget {
            max_tx_size: self.max_tx_size,
            envelope: self.post_tm_envelope,
            // heimdall builds key-path (51% FROST) movements; the federation
            // script path is the emergency single-input spend and carries no
            // batch at all.
            variant: crate::epoch::batch::SpendVariant::KeyPath,
        }
    }
}

/// `max_tx_size` on every Cardano network since Alonzo. Used ONLY where no chain
/// answer is available (mocks, offline CLI paths); the daemon reads the live
/// parameter per epoch.
pub const DEFAULT_MAX_TX_SIZE: u64 = 16_384;

/// `E` minus the TM validator script: the Post-TM's body, mint, redeemer and
/// exec units, collateral and collateral return, script-data hash, change,
/// vkey witness, and the `UnconfirmedTm` datum's non-batch fields.
///
/// Summing those from the Conway CBOR shapes `cardano::publish` builds gives
/// ≈700 bytes; this constant holds ≈45 % of margin over that, in the direction
/// that shrinks a batch rather than the one that posts a movement the chain
/// rejects. The script is added on top by the chain adapter, because its size is
/// a deployment fact — inline or reference script — and it dominates.
pub const POST_TM_ENVELOPE_WITHOUT_SCRIPT: u64 = 1_024;

/// `leader_slot_T` where no Config publishes one — mocks and offline CLI paths.
/// The spec's own worked example (60 slots ≈ 1 minute).
pub const DEFAULT_LEADER_SLOT_T: u64 = 60;

/// `sign_r1_window` / `sign_r2_window` where no Config publishes them — mocks and
/// offline CLI paths. The spec's worked example is 30 minutes each; this is far
/// shorter because the only deployments that reach it have no schedule to respect
/// and no peers to stay in step with.
pub const DEFAULT_SIGN_WINDOW: u64 = 300;

/// Everything the epoch machine needs to authorize an on-chain Update-Y — the
/// key handoff that makes a completed DKG the treasury's actual controller.
///
/// `treasury.ak`'s `UpdateY` branch is gated purely on a BIP-340 signature by
/// the *spent* datum's `current_spos_frost_key` over a message pinned to the
/// spent outpoint, so the outgoing roster authorizes its own succession and
/// nobody else can. Everything here is read off-chain by
/// [`CardanoChain::plan_update_y`]; the machine's only job is to produce the
/// signature and hand the plan back to [`CardanoChain::submit_update_y`].
#[derive(Debug, Clone)]
pub struct UpdateYPlan {
    /// The epoch the rotation is stamped with (part of the signed message).
    pub epoch: u64,
    /// The datum's current (outgoing) `current_spos_frost_key`, x-only. The
    /// authorizing signature must verify under exactly this key.
    pub current_key: bitcoin::key::UntweakedPublicKey,
    /// The incoming key this rotation installs — the just-derived Y_51.
    pub new_key: bitcoin::key::UntweakedPublicKey,
    /// The exact 32-byte message the outgoing key signs:
    /// `sha2_256("bifrost-update-y" ‖ spent_txid ‖ vout LE ‖ epoch BE ‖ new_key)`.
    /// Pinned to the spent state UTxO, so a signature cannot be replayed
    /// against a later one.
    pub sig_msg: [u8; 32],
    /// The `treasury_info` state UTxO being spent, `<cardano_txid>:<vout>` — for
    /// logs and for detecting that the plan went stale under us.
    pub state_outpoint: String,
}

/// Provable DKG misbehavior captured by the peer transport.
///
/// Missing peers are not faults by themselves. These variants are only returned
/// when the transport can show either a signed invalid payload or two conflicting
/// signed payloads from the same `(epoch, threshold, attempt, round, pool_id)`
/// namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgFaultEvidence {
    Round1InvalidPayload(Round1PokFaultEvidence),
    Round2InvalidPayload(Round2ShareFaultEvidence),
    Equivocation(EquivocationEvidence),
}

impl DkgFaultEvidence {
    #[must_use]
    pub fn accused_pool_id(&self) -> &[u8; 28] {
        match self {
            Self::Round1InvalidPayload(ev) => &ev.accused_pool_id,
            Self::Round2InvalidPayload(ev) => &ev.accused_pool_id,
            Self::Equivocation(ev) => &ev.accused_pool_id,
        }
    }

    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Round1InvalidPayload(_) => "round1-invalid-payload",
            Self::Round2InvalidPayload(_) => "round2-invalid-payload",
            Self::Equivocation(_) => "equivocation",
        }
    }
}

/// Both attested roots read from the bridge state singleton in ONE fetch, by
/// name per [LIB-1] (field 0 is `spi_root`, field 1 `cpo_root`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeRoots {
    pub spi_root: [u8; 32],
    pub cpo_root: [u8; 32],
}

#[async_trait]
pub trait CardanoChain: Send + Sync {
    /// Block until the next epoch boundary is observed. The mock returns
    /// immediately on first call so the demo runs exactly one cycle.
    async fn await_epoch_boundary(&self) -> EpochResult<EpochBoundaryEvent>;

    /// The current chain epoch (non-blocking) — used to namespace the DKG
    /// ceremony and to query the bootstrap roster at the right epoch. Unlike
    /// [`Self::await_epoch_boundary`] it does not wait for a boundary.
    async fn current_epoch(&self) -> EpochResult<u64>;

    /// Snapshot the SPO registry and produce the roster for `epoch`.
    /// In v0.2 the mock returns a hardcoded roster.
    async fn query_roster(&self, epoch: u64) -> EpochResult<Roster>;

    /// Resolve the eligible DKG context (candidate set + per-participant stake +
    /// stake-weighted threshold) for `(epoch, attempt)` — the stake-aware input
    /// the ceremony's quorum gate needs. The mock / no-registry fallback
    /// synthesize it from the static roster with equal stake.
    async fn query_dkg_context(
        &self,
        epoch: u64,
        attempt: u32,
    ) -> EpochResult<crate::cardano::dkg_roster::DkgContext>;

    /// Current treasury UTxO state, as reported by the Cardano oracle.
    async fn query_treasury(&self) -> EpochResult<TreasuryUtxo>;

    // NOTE: there is deliberately no `is_tm_confirmed`. The machine used to block
    // on one, which is why it wedged (WI-032): the answer is hours away and a
    // waiting process is not what makes the answer arrive. What replaced it reads
    // `query_treasury` — the head IS the confirmation, and a caller that has the
    // head can also tell WHICH movement confirmed, which a bool cannot.

    /// Open peg-out requests at the `peg_out.ak` address — INCLUDING ones an earlier TM already
    /// paid (a request UTxO is spent by its owner's Complete tx, which lags the payment by hours or
    /// never happens). What filters the already-paid ones is the completed-peg-outs trie,
    /// keyed by `por_id` — see `build_tm`'s `AlreadyCompleted` skip. (Before WI-031 an
    /// identity-free `(destination, net sat)` multiset ran first; it could not tell a
    /// long-completed withdrawal from an unpaid one, because a `Confirmed` TM datum records
    /// only `{scriptPubKey, amount}`.)
    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>>;

    /// Freeze this batch's consensus inputs: the chain time the peg-out freshness
    /// filter compares against, and the operational parameters TM construction
    /// reads (the Config's `params[1..=3]`), both **as of one chain point**.
    ///
    /// Every field of the result feeds bytes that all SPOs must produce
    /// identically, so all of it is chain-derived and read once, together — see
    /// [`BatchSnapshot`]. The default is the local clock plus no parameters at all,
    /// correct only for mocks and single-node demos; the caller supplies its local
    /// fee-rate override for that case.
    async fn query_batch_snapshot(&self) -> EpochResult<BatchSnapshot> {
        Ok(BatchSnapshot::local_override(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            crate::bitcoin::tm_builder::TmParams::fee_rate_only(1),
            "mock chain",
        ))
    }

    /// Both attested roots held by the on-chain bridge state singleton, when
    /// this node is configured to locate it (`cardano.cpo_policy_id` — the
    /// `bridge_state_policy`, Config field 3).
    ///
    /// This is the tripwire for a persisted `cpo-trie.json` OR `spi-trie.json`
    /// that has fallen out of sync with the chain — most sharply after a
    /// re-bootstrap, which mints a FRESH zero-root singleton while the node's
    /// state directory still holds the previous deployment's populated tries,
    /// and after a roster-wide state restore, where [SPI-2]'s peer recomputation
    /// passes because every co-signer recomputes from the SAME stale trie.
    /// `BuildTm` compares these against its local roots and refuses to attest on
    /// a mismatch: a TM built on a stale trie commits a root the chain does not
    /// hold.
    ///
    /// `None` means "not configured / cannot be checked", never "empty tries".
    /// The empty trie has a real root (32 zero bytes), and reporting it here
    /// would turn an unconfigured node into one that rejects every non-genesis
    /// trie.
    async fn query_bridge_roots(&self) -> EpochResult<Option<BridgeRoots>> {
        Ok(None)
    }

    /// A pool's stake, for the off-chain min-stake gate (register_spo R2): the
    /// contract can't read stake, so SPOs query it and require `active_stake >=
    /// min_stake` before building register_spo and before admitting the SPO to
    /// the DKG candidate set. `pool_id` is the bech32 pool id; see
    /// [`crate::cardano::stake`] for the threshold check.
    async fn query_pool_stake(
        &self,
        pool_id: &str,
    ) -> EpochResult<crate::cardano::stake::PoolStake>;

    /// Locate the live `treasury_info` state and describe the Update-Y that
    /// would install `new_y_51` as `current_spos_frost_key` for `epoch`.
    ///
    /// `Ok(None)` means "nothing to rotate": either this backend has no
    /// `treasury_info` state to spend (the mock / an unconfigured node), or the
    /// datum already holds `new_y_51` — a re-run of the same epoch's ceremony,
    /// or a roster that re-derived the key it already had.
    ///
    /// This only *reads*. Producing the authorizing signature needs the
    /// outgoing roster's key material, which lives in the epoch machine, not
    /// here; [`Self::submit_update_y`] takes the result back.
    /// Required, not defaulted: a backend that silently answered "nothing to
    /// rotate" would be indistinguishable from a treasury that is already up to
    /// date, which is precisely the failure this method exists to prevent.
    async fn plan_update_y(
        &self,
        epoch: u64,
        new_y_51: bitcoin::key::UntweakedPublicKey,
    ) -> EpochResult<Option<UpdateYPlan>>;

    /// Submit the Update-Y transaction described by `plan`, authorized by a
    /// 64-byte BIP-340 `signature` under `plan.current_key` over
    /// `plan.sig_msg`. Returns the Cardano tx id.
    ///
    /// The signature is the whole authorization — `treasury.ak`'s `UpdateY`
    /// branch is permissionless — so any node may submit, and every node but
    /// the leader normally declines to.
    ///
    /// Implementations must re-locate the state UTxO and refuse if it has moved
    /// since the plan was made: the signature is pinned to the spent outpoint,
    /// so a moved state means the signature is worthless and building on it
    /// would only produce a transaction that cannot validate. A rotation
    /// already submitted but not yet confirmed still reads as unspent, so a
    /// retry in that window re-submits and is rejected by the node — noisy, but
    /// the next `plan_update_y` sees the settled datum and reports nothing to
    /// rotate.
    async fn submit_update_y(
        &self,
        plan: &UpdateYPlan,
        signature: &[u8; 64],
    ) -> EpochResult<String>;

    /// Record the new FROST group key locally after DKG. The key becomes the
    /// internal key (Y_51) of the next treasury Taproot address, so subsequent
    /// `query_treasury` calls return a treasury the new FROST group can sign
    /// for.
    ///
    /// This is the node's own view, NOT the on-chain publication — that is
    /// [`Self::plan_update_y`] + [`Self::submit_update_y`], which rotate the
    /// `treasury_info` datum under the outgoing roster's signature.
    async fn publish_group_key(&self, y_51: bitcoin::key::UntweakedPublicKey) -> EpochResult<()>;

    /// Publish a DKG fault proof and apply the corresponding SPO ban.
    ///
    /// Implementations must only return `Ok(())` after the fault has been
    /// submitted to the configured ban flow or recorded by an explicit test
    /// double. DKG calls this only for provable evidence supplied by
    /// [`PeerNetwork`]; absent peers are reduced out of the candidate set but
    /// are not banned.
    async fn publish_dkg_fault_and_apply_ban(&self, evidence: DkgFaultEvidence) -> EpochResult<()>;

    /// Submit a Bitcoin tx (in v0.2 the mock just records it).
    ///
    /// TODO: misleading name — this lives on `CardanoChain` but it
    /// actually submits a *Bitcoin* transaction (the signed treasury
    /// movement) to a Bitcoin node/broadcaster, not to Cardano. A real
    /// impl will need two separate sinks: one for broadcasting the
    /// signed BTC tx, and another for posting the resulting Cardano
    /// side-effects (minting fBTC, closing peg-out requests).
    /// Broadcast the signed BTC tx and post the Unconfirmed TM record to Cardano.
    ///
    /// `fulfilled_por_outpoints` is the rev-5.1 data-availability hint written into
    /// the posted datum's 6th field: the Cardano outpoints (36 bytes each) of the
    /// peg-out requests this TM fulfils. Nothing on-chain reads it; it exists so a
    /// cold-starting SPO can rebuild the completed-peg-outs trie from chain data.
    async fn submit_signed_tm(
        &self,
        tx_bytes: &[u8],
        fulfilled_por_outpoints: &[[u8; 36]],
    ) -> EpochResult<()>;
}

// ---------------------------------------------------------------------------
// PeerNetwork
// ---------------------------------------------------------------------------

/// What one `/health` probe learned about a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHealth {
    /// Its `/health` answered.
    pub reachable: bool,
    /// What it reports running, when it answered. Absent for an unreachable
    /// peer, and empty for one whose build predates WI-067.
    pub build: crate::http::compat::PeerBuild,
    /// `(epoch, attempt)` of the most recent DKG Round 1 this peer has
    /// published (WI-113). A HINT for a third party auditing the ceremony: the
    /// attempt is `window * DKG_ATTEMPTS_PER_WINDOW` counted from whenever that
    /// node entered, so nobody else can compute it. Trusting it is unnecessary —
    /// the reader fetches that namespace and verifies every signature in it,
    /// which a wrong answer cannot survive.
    pub published_dkg: Option<(u64, u64)>,
}

impl PeerHealth {
    #[must_use]
    pub fn unreachable() -> Self {
        Self {
            reachable: false,
            build: crate::http::compat::PeerBuild::default(),
            published_dkg: None,
        }
    }

    /// Reachable, with nothing said about the software — the answer for a mock
    /// or any implementation with no liveness signal.
    #[must_use]
    pub fn reachable_unknown_build() -> Self {
        Self {
            reachable: true,
            build: crate::http::compat::PeerBuild::default(),
            published_dkg: None,
        }
    }

    /// The compatibility verdict on this peer, against what THIS node runs and
    /// is configured with.
    ///
    /// `own` is a parameter rather than read from a global because the
    /// deployment half of it ([`crate::http::compat::NodeFacts`]) includes the
    /// `t` this node just derived, which is live ceremony state — the caller has
    /// it, and nothing here should go looking for it.
    #[must_use]
    pub fn compatibility(
        &self,
        own: crate::http::compat::NodeFacts,
    ) -> crate::http::compat::Compatibility {
        crate::http::compat::Compatibility::of(&self.build, own)
    }
}

/// Pull-only peer protocol surface.
///
/// All `publish_*` calls write to *this* SPO's local state — peers
/// fetch from us; we never push. The `fetch_*` calls poll a specific
/// peer's endpoint.
///
/// DKG payloads cross this boundary as plain FROST packages: the
/// implementation is responsible for the spec wire format — building +
/// BIP-340 signing on publish, and verifying (against the peer's
/// `bifrost_id_pk`/`pool_id`) + decrypting on fetch — so callers never
/// touch the canonical bytes or identity keys. A `fetch_*` that returns
/// `Some` has already been authenticated; `None` means "not published
/// yet". A payload that fails verification is dropped (and retained as
/// fault evidence by the implementation), surfaced as `Ok(None)` so the
/// poll loop keeps waiting rather than aborting the epoch.
#[async_trait]
pub trait PeerNetwork: Send + Sync {
    /// Whether `peer` is reachable, and what software it is running.
    ///
    /// Used by the pre-ceremony health gate (N21) so a staggered-start roster
    /// converges on one DKG instead of freezing divergent live subsets, and
    /// since WI-067 to compare the peer's build against ours before entering a
    /// ceremony with it — `/health` carries both, so this stays one round trip.
    ///
    /// Reachability is purely advisory: a reachable answer guarantees nothing
    /// about later rounds, and the gate is time-bounded, so implementations
    /// should answer quickly (a couple of seconds) and never retry internally.
    /// The BUILD is not advisory — see [`crate::http::compat`].
    ///
    /// Defaults to reachable-with-an-unknown-build, which is the answer for an
    /// implementation with no liveness signal at all.
    async fn check_health(&self, _peer: &SpoInfo) -> PeerHealth {
        PeerHealth::reachable_unknown_build()
    }

    /// Record this node's chain-view for the ceremony it is entering.
    /// [`Self::publish_dkg_round1`] attaches it (UNSIGNED) to each Round-1
    /// payload and [`Self::fetch_dkg_round1`] compares it against peers' — so a
    /// node can tell a genuine cross-view disagreement (both honest, different
    /// chain reads near a ban) from a corrupt payload. Called once per ceremony
    /// entry (each attempt), before publishing. Default no-op: a transport with
    /// no wire view (the mock) ignores it and [`Self::is_view_stale`] stays
    /// `false`.
    async fn set_chain_view(&self, _view: crate::cardano::dkg_roster::ChainView) {}

    /// Record what this node will run the ceremony with, for peers to read off
    /// its `/health` before entering one with it.
    ///
    /// The counterpart of [`Self::set_chain_view`], and deliberately a separate
    /// channel: a chain-view rides on a Round-1 payload, so it is only ever seen
    /// by a peer that already fetched from the same DKG namespace. These values
    /// decide the namespace itself, so they must travel somewhere un-namespaced
    /// and be readable before anything is published — see
    /// [`crate::http::compat`]. Called at each ceremony entry, before the health
    /// gate. Default no-op for a transport with no health surface (the mock).
    async fn set_node_facts(&self, _facts: crate::http::compat::NodeFacts) {}

    /// Whether, during the ceremony since the last [`Self::set_chain_view`], this
    /// node observed a peer whose chain-view differed AND whose blockchain
    /// read-time was NEWER — i.e. THIS node is the STALE side and should re-read
    /// after the disagreeing event (e.g. a ban) settles. The epoch loop reads
    /// this after a failed DKG to back off a settling interval instead of the
    /// blind exponential, making the reconcile directional. Default `false`.
    async fn is_view_stale(&self) -> bool {
        false
    }

    async fn publish_dkg_round1(
        &self,
        ns: DkgNamespace,
        identifier: Identifier,
        package: &round1::Package,
    ) -> EpochResult<()>;
    /// Publish Round 2: one encrypted share per recipient. Each entry pairs
    /// a recipient's `SpoInfo` (for its `pool_id` + `bifrost_id_pk`) with
    /// the FROST package addressed to it.
    async fn publish_dkg_round2(
        &self,
        ns: DkgNamespace,
        sender_identifier: Identifier,
        sender_commitments: &[[u8; POINT_LEN]],
        recipients: &[(SpoInfo, round2::Package)],
    ) -> EpochResult<()>;
    /// Publish this node's signing Round 1 nonce commitments for one session.
    ///
    /// Like the DKG rounds, the CONTENT crosses this boundary and the transport
    /// owns the wire form — building the canonical bytes and BIP-340 signing
    /// them under this node's `bifrost_id_pk` (WI-038). Callers never touch a
    /// signature.
    async fn publish_sign_round1(
        &self,
        ns: SignNamespace,
        identifier: Identifier,
        commitments: frost_secp256k1_tr::round1::SigningCommitments,
    ) -> EpochResult<()>;
    /// Publish this node's signature share for one session. See
    /// [`Self::publish_sign_round1`].
    async fn publish_sign_round2(
        &self,
        ns: SignNamespace,
        identifier: Identifier,
        share: frost_secp256k1_tr::round2::SignatureShare,
    ) -> EpochResult<()>;

    async fn fetch_dkg_round1(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Option<round1::Package>>;
    async fn fetch_dkg_round2(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
        recipient_identifier: Identifier,
        sender_commitments: &[[u8; POINT_LEN]],
    ) -> EpochResult<Option<round2::Package>>;
    /// Who `peer`'s Round 2 payload for `ns` is ADDRESSED to, if it published a
    /// correctly signed one (WI-113).
    ///
    /// No share is decrypted: the caller is a third party auditing a ceremony it
    /// took no part in and holds no recipient key, which is why
    /// [`Self::fetch_dkg_round2`] cannot answer this — that needs this node to BE
    /// a recipient. The recipient list is public, and it is the participant set
    /// the sender believed it was running with, so comparing it across members
    /// detects a ceremony that finished over a narrowed subset.
    ///
    /// Defaults to `None`, the fail-closed direction: a transport that has not
    /// implemented this reports no evidence of completion, and the succession
    /// rule refuses rather than approving on an unanswered question.
    async fn dkg_round2_recipients(
        &self,
        _ns: DkgNamespace,
        _peer: &SpoInfo,
    ) -> EpochResult<Option<std::collections::BTreeSet<Vec<u8>>>> {
        Ok(None)
    }
    /// Return provable Round 1 faults retained while fetching `peer`'s payload.
    async fn dkg_round1_fault_evidence(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Vec<DkgFaultEvidence>>;
    /// Return provable Round 2 faults retained while fetching `peer`'s payload.
    async fn dkg_round2_fault_evidence(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
        recipient_identifier: Identifier,
        sender_commitments: &[[u8; POINT_LEN]],
    ) -> EpochResult<Vec<DkgFaultEvidence>>;
    /// Fetch `peer`'s Round 1 commitments for `ns`.
    ///
    /// A `Some` has been AUTHENTICATED: the payload carried a BIP-340 signature
    /// under the peer's registry-bound `bifrost_id_pk` over canonical bytes
    /// covering `ns` (epoch, session, and the message being signed) and the
    /// peer's own `pool_id`/identifier. That is why the commitments come back
    /// bare — the caller files them under `peer.identifier`, never under an
    /// identifier the payload claimed for itself.
    ///
    /// `None` means "not published yet" OR "published but did not verify"; an
    /// unverifiable payload is dropped with a log line rather than aborting the
    /// poll, matching the DKG fetch path.
    async fn fetch_sign_round1(
        &self,
        ns: SignNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Option<frost_secp256k1_tr::round1::SigningCommitments>>;
    /// Fetch `peer`'s signature share for `ns`. Authenticated exactly as
    /// [`Self::fetch_sign_round1`].
    async fn fetch_sign_round2(
        &self,
        ns: SignNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Option<frost_secp256k1_tr::round2::SignatureShare>>;
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// Abstraction over time for testability. Real impl is `SystemClock`,
/// fake is `FakeClock`. (Both live in `mocks.rs`.)
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn deadline(&self, duration: Duration) -> Instant {
        self.now() + duration
    }
}

/// Factory for fresh cryptographic RNGs, one per call site.
///
/// `context` is a byte tag naming the call site (e.g. `b"dkg1"`,
/// `b"sign1:input=0"`). The seeded impl derives a stream from
/// `hash(seed || context)`, so different call sites never collide
/// and reordering code cannot silently reshuffle nonces. `OsRngSource`
/// ignores `context`.
///
/// Returns a concrete [`CycleRng`] (not a boxed trait object) because
/// `frost-secp256k1-tr`'s `round1::commit` requires `Sized`.
pub trait RngSource: Send + Sync {
    fn rng(&self, context: &[u8]) -> CycleRng;

    /// Randomness for a FROST SIGNING nonce. Always the OS, never the seed.
    ///
    /// A signing nonce may be used once. Sign twice under one `(d, e)` with
    /// different challenges and the signing share is algebraically recoverable —
    /// so a nonce that a second run, or a retry, can reproduce is a key-recovery
    /// hazard rather than a reproducibility feature. `--deterministic` derives its
    /// stream from `hash(seed || context)` with a context that is constant within
    /// an epoch, and since WI-047 a phase can be re-entered inside that epoch, so
    /// the two attempts would share a nonce and differ in their signing set.
    ///
    /// `--deterministic` loses nothing it is for: a Taproot key-path witness is
    /// not covered by the txid, so the movement's bytes, the group key and every
    /// derived address stay reproducible. Only the signature itself varies, which
    /// is what it means for a signature to be safe.
    fn signing_nonce_rng(&self) -> CycleRng {
        CycleRng::Os(rand::rngs::OsRng)
    }
}

/// Concrete RNG handed out by [`RngSource`]. Either wraps `OsRng`
/// directly, or a seeded `ChaCha20Rng` for deterministic demo runs.
pub enum CycleRng {
    Os(rand::rngs::OsRng),
    Seeded(rand_chacha::ChaCha20Rng),
}

impl rand_core::RngCore for CycleRng {
    fn next_u32(&mut self) -> u32 {
        match self {
            CycleRng::Os(r) => r.next_u32(),
            CycleRng::Seeded(r) => r.next_u32(),
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self {
            CycleRng::Os(r) => r.next_u64(),
            CycleRng::Seeded(r) => r.next_u64(),
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            CycleRng::Os(r) => r.fill_bytes(dest),
            CycleRng::Seeded(r) => r.fill_bytes(dest),
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        match self {
            CycleRng::Os(r) => r.try_fill_bytes(dest),
            CycleRng::Seeded(r) => r.try_fill_bytes(dest),
        }
    }
}

impl rand_core::CryptoRng for CycleRng {}

#[cfg(test)]
mod pegin_tree_tests {
    use super::*;

    fn xonly(b: u8) -> bitcoin::key::UntweakedPublicKey {
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
    }

    /// A treasury standing wherever the caller puts it: `y_51` is the key the HEAD
    /// is locked under, `authorized` the one the datum names. Passing the same
    /// value for both is the steady state.
    fn utxo(y_51: u8, head_y_fed: u8, published_y_fed: u8, authorized: u8) -> TreasuryUtxo {
        TreasuryUtxo {
            outpoint: bitcoin::OutPoint::null(),
            value: bitcoin::Amount::ZERO,
            y_51: xonly(y_51),
            y_fed: xonly(head_y_fed),
            config_y_fed: xonly(published_y_fed),
            authorized_key: xonly(authorized),
            federation_csv_blocks: 144,
            pegin_refund_timeout_blocks: 720,
            retired_internal_keys: Vec::new(),
            btc_confirmed: true,
        }
    }

    /// The whole reason this constructor exists: the leaf key is the PUBLISHED federation
    /// key, not the one the treasury head happens to be locked under. On a bridge
    /// mid-rotation the two differ, and picking the wrong one derives an address every
    /// depositor misses — silently, because both are valid keys.
    #[test]
    fn the_leaf_key_is_the_published_one_not_the_head_derived_one() {
        let u = utxo(0x11, 0x22, 0x33, 0x11);
        let tree = u.pegin_tree().expect("valid");
        assert_eq!(tree.y_federation, u.config_y_fed);
        assert_ne!(tree.y_federation, u.y_fed);
        assert_eq!(tree.y_51, u.y_51);
    }

    /// The INTERNAL key follows the same rule as the leaf: publish, do not infer.
    ///
    /// Spec §Rollout Phases step 5 — "from this point depositors derive peg-in
    /// addresses from `Y_51'`" — puts the switch at the Update-Y, so for the whole
    /// handoff window the address a depositor builds is the datum's, not the one
    /// the head is still locked under. Deriving from the head here would quote an
    /// address no depositor uses, and no Cardano-only reader can even compute it.
    #[test]
    fn the_published_address_follows_the_datum_not_the_head() {
        let u = utxo(0x11, 0x22, 0x33, 0x44);
        let tree = u.pegin_tree().expect("valid");
        assert_eq!(tree.y_51, u.authorized_key);
        assert_ne!(tree.y_51, u.y_51);
    }

    /// In the steady state there is nothing to disambiguate, so there is one tree
    /// and one extra parse attempt is not paid.
    #[test]
    fn a_settled_bridge_has_exactly_one_pegin_tree() {
        let u = utxo(0x11, 0x22, 0x33, 0x11);
        let trees = u.pegin_trees().expect("valid");
        assert_eq!(trees.len(), 1);
        assert_eq!(trees[0].0, PeginKeyOrigin::Current);
        assert!(trees[0].0.sweepable());
        assert_eq!(trees[0].1.y_51, u.y_51);
    }

    /// Inside the window a node must recognise BOTH addresses — and they mean
    /// different things. The published one is where spec-compliant deposits land
    /// from the Update-Y onward and no movement can take it until the handoff
    /// confirms; the head's is where deposits built before the Update-Y land, and
    /// the handoff movement is the LAST one that can ever take those.
    #[test]
    fn the_handoff_window_has_a_published_tree_and_a_sweepable_one() {
        let u = utxo(0x11, 0x22, 0x33, 0x44);
        let trees = u.pegin_trees().expect("valid");
        assert_eq!(trees.len(), 2);

        assert_eq!(trees[0].0, PeginKeyOrigin::Published);
        assert_eq!(trees[0].1.y_51, u.authorized_key);
        assert!(
            !trees[0].0.sweepable(),
            "the address the bridge publishes is NOT the one the head can spend during a \
             handoff — a movement signs with one key package and the head is under the other \
             key"
        );

        assert_eq!(trees[1].0, PeginKeyOrigin::Head);
        assert_eq!(trees[1].1.y_51, u.y_51);
        assert!(trees[1].0.sweepable());
    }

    /// A superseded ceremony key is recognised but never sweepable: no movement
    /// will sign under it again, so the only thing a node can do with a deposit
    /// there is name it.
    #[test]
    fn a_retired_key_is_recognised_and_never_sweepable() {
        let mut u = utxo(0x11, 0x22, 0x33, 0x11);
        u.retired_internal_keys = vec![xonly(0x55), xonly(0x66)];
        let trees = u.pegin_trees().expect("valid");
        assert_eq!(trees.len(), 3);
        for (origin, tree) in &trees[1..] {
            assert_eq!(*origin, PeginKeyOrigin::Retired);
            assert!(!origin.sweepable());
            assert_eq!(
                tree.y_federation, u.config_y_fed,
                "only the internal key varies"
            );
        }
        assert_eq!(
            trees[1].1.y_51,
            xonly(0x55),
            "newest retired ceremony first"
        );
    }

    /// A key that is still live must not also be offered as retired: it would
    /// derive the same address twice, and the second copy would carry the wrong
    /// verdict about whether it can be swept.
    #[test]
    fn a_live_key_is_never_repeated_as_retired() {
        let mut u = utxo(0x11, 0x22, 0x33, 0x44);
        u.retired_internal_keys = vec![xonly(0x11), xonly(0x44), xonly(0x55)];
        let trees = u.pegin_trees().expect("valid");
        assert_eq!(
            trees.len(),
            3,
            "published, head, and the one genuinely retired key"
        );
        assert_eq!(trees[2].1.y_51, xonly(0x55));
    }

    /// A bridge publishing a refund window that opens before its own sweep window is
    /// refused, rather than each deriver rediscovering it one deposit at a time.
    #[test]
    fn a_bridge_whose_refund_opens_first_is_refused() {
        let mut u = utxo(0x11, 0x22, 0x33, 0x11);
        u.pegin_refund_timeout_blocks = 100;
        let err = u.pegin_tree().unwrap_err();
        assert!(err.contains("must exceed federation_csv_blocks"), "{err}");
        let err = u.pegin_trees().unwrap_err();
        assert!(err.contains("must exceed federation_csv_blocks"), "{err}");
    }
}
