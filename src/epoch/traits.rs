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
    /// The Taproot script-tree leaf key for the federation fallback.
    pub y_fed: bitcoin::key::UntweakedPublicKey,
    pub federation_csv_blocks: u32,
    /// Whether it is safe to begin the NEXT treasury movement off this UTxO.
    /// A new movement can only begin once the previous one is confirmed, so the
    /// Blockfrost impl (WI-028) sets this false when an Unconfirmed TM (or an
    /// in-flight TM it could not read) is already spending this tip; the mock
    /// reports a simple always-confirmed treasury.
    pub btc_confirmed: bool,
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
    /// Operational parameters in force at the snapshot — Config #12–#14. (#16, the
    /// schedule, is not here: nothing in TM construction consumes it. It is decoded
    /// by `cardano::config_params` and reported by `show-config-params` / the
    /// mover's startup banner, and drives the batch grid when plan N19 lands.)
    pub tm_params: crate::bitcoin::tm_builder::TmParams,
    /// Config UTxO the parameters came from, or the local-override reason.
    pub source: crate::cardano::config_params::ParamSource,
}

impl BatchSnapshot {
    /// A snapshot whose parameters came from this node's own config rather than
    /// the chain — mocks, offline CLI paths, and Config-less deployments.
    #[must_use]
    pub fn local_override(
        now_ms: i64,
        tm_params: crate::bitcoin::tm_builder::TmParams,
        why: &'static str,
    ) -> Self {
        Self {
            now_ms,
            tm_params,
            source: crate::cardano::config_params::ParamSource::LocalOverride(why),
        }
    }
}

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

    /// Whether the specific treasury movement is now the confirmed chain tip.
    /// Mock implementations use the default immediate-success behavior;
    /// live implementations must verify the observed tip txid and its
    /// confirmation state.
    async fn is_tm_confirmed(&self, _txid: &bitcoin::Txid) -> EpochResult<bool> {
        Ok(true)
    }

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
    /// reads (Config #12–#14), both **as of one chain point**.
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

    /// The root held by the on-chain completed-peg-outs singleton, when this
    /// node is configured to locate it (`cardano.cpo_policy_id`).
    ///
    /// This is the tripwire for a persisted `cpo-trie.json` that has fallen out
    /// of sync with the chain — most sharply after a re-bootstrap, which mints a
    /// FRESH zero-root CPO singleton while the node's state directory still holds
    /// the previous deployment's populated trie. `BuildTm` compares this against
    /// its local root and refuses to attest on a mismatch: a TM built on a stale
    /// trie commits a root the chain does not hold, so every honest peer rejects
    /// it, and a quorum of equally stale nodes would attest it anyway.
    ///
    /// `None` means "not configured / cannot be checked", never "empty trie". The
    /// empty trie has a real root (32 zero bytes), and reporting it here would
    /// turn an unconfigured node into one that rejects every non-genesis trie.
    async fn query_cpo_root(&self) -> EpochResult<Option<[u8; 32]>> {
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
