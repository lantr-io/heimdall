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
    /// This is the field that decides the ROLLOUT PHASE, and only this one.
    /// §Rollout Phases: "there is no phase flag anywhere — the transition *is*
    /// the first Update-Y", so `authorized_key == config_y_fed` is precisely the
    /// statement that no Update-Y has ever landed and the federation is still the
    /// key-path signer. Comparing `y_51` instead would answer a different
    /// question and get it wrong for a whole movement's worth of the handoff.
    pub authorized_key: bitcoin::key::UntweakedPublicKey,
    pub federation_csv_blocks: u16,
    /// The peg-in refund leaf's CSV delay, Config `params[8]` ([CFG-9]) — carried
    /// beside the federation delay because the peg-in tree needs both, and both
    /// must come from the bridge rather than from each node's own file.
    pub pegin_refund_timeout_blocks: u16,
    /// Whether it is safe to begin the NEXT treasury movement off this UTxO.
    /// A new movement can only begin once the previous one is confirmed, so the
    /// Blockfrost impl (WI-028) sets this false when an Unconfirmed TM (or an
    /// in-flight TM it could not read) is already spending this tip; the mock
    /// reports a simple always-confirmed treasury.
    pub btc_confirmed: bool,
}

impl TreasuryUtxo {
    /// The peg-in Taproot tree this bridge publishes — the canonical answer to "what
    /// address does a deposit land at", for every reader that can see the oracle.
    ///
    /// It exists because the mapping is not obvious and getting it wrong is silent. The
    /// federation LEAF key is [`Self::config_y_fed`], the value the Config publishes and a
    /// depositor builds against — NOT [`Self::y_fed`], which is whichever candidate
    /// reproduces the treasury HEAD's scriptPubKey and is `y_51` on a bridge still using the
    /// collapsed convention. Both are `UntweakedPublicKey`, so nothing but this function
    /// stands between a caller and a well-formed address holding nothing.
    ///
    /// Fails when the published pair breaks the spec's ordering rule; that is a
    /// misconfiguration of the bridge, not an invariant a node may assume.
    pub fn pegin_tree(&self) -> Result<crate::bitcoin::taproot::PeginTreeParams, String> {
        let tree = crate::bitcoin::taproot::PeginTreeParams {
            y_51: self.y_51,
            y_federation: self.config_y_fed,
            federation_csv_blocks: self.federation_csv_blocks,
            refund_timeout: self.pegin_refund_timeout_blocks,
        };
        tree.validate()?;
        Ok(tree)
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
    /// Whether `peer` is currently reachable (its `/health` endpoint answers).
    /// Used by the pre-ceremony health gate (N21) so a staggered-start roster
    /// converges on one DKG instead of freezing divergent live subsets. Purely
    /// advisory — a `true` here guarantees nothing about later rounds, and the
    /// gate is time-bounded, so implementations should answer quickly (a
    /// couple of seconds), never retry internally. Defaults to healthy for
    /// implementations without a liveness signal.
    async fn check_health(&self, _peer: &SpoInfo) -> bool {
        true
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

    fn utxo(y_51: u8, head_y_fed: u8, published_y_fed: u8) -> TreasuryUtxo {
        TreasuryUtxo {
            outpoint: bitcoin::OutPoint::null(),
            value: bitcoin::Amount::ZERO,
            y_51: xonly(y_51),
            y_fed: xonly(head_y_fed),
            config_y_fed: xonly(published_y_fed),
            authorized_key: xonly(y_51),
            federation_csv_blocks: 144,
            pegin_refund_timeout_blocks: 720,
            btc_confirmed: true,
        }
    }

    /// The whole reason this constructor exists: the leaf key is the PUBLISHED federation
    /// key, not the one the treasury head happens to be locked under. On a bridge
    /// mid-rotation the two differ, and picking the wrong one derives an address every
    /// depositor misses — silently, because both are valid keys.
    #[test]
    fn the_leaf_key_is_the_published_one_not_the_head_derived_one() {
        let u = utxo(0x11, 0x22, 0x33);
        let tree = u.pegin_tree().expect("valid");
        assert_eq!(tree.y_federation, u.config_y_fed);
        assert_ne!(tree.y_federation, u.y_fed);
        assert_eq!(tree.y_51, u.y_51);
    }

    /// A bridge publishing a refund window that opens before its own sweep window is
    /// refused, rather than each deriver rediscovering it one deposit at a time.
    #[test]
    fn a_bridge_whose_refund_opens_first_is_refused() {
        let mut u = utxo(0x11, 0x22, 0x33);
        u.pegin_refund_timeout_blocks = 100;
        let err = u.pegin_tree().unwrap_err();
        assert!(err.contains("must exceed federation_csv_blocks"), "{err}");
    }
}
