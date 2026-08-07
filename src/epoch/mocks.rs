//! Mock implementations of `CardanoChain`, `PeerNetwork`, and `Clock`
//! for in-process tests and the `demo` subcommand.
//!
//! `MockCardanoChain` fires the epoch boundary exactly once then blocks
//! forever, so a demo loop runs a single cycle. `MockPeerHub` is a
//! shared blackboard all in-process `MockPeerNetwork` instances read
//! and write through — bypassing HTTP entirely so unit tests stay fast
//! and deterministic.
//!
//! TODO: this entire module is provisional. The whole `CardanoChain`
//! impl needs to be replaced by a real Cardano N2C / Ogmios-backed
//! follower that queries a live node for the SPO registry, treasury
//! UTXO, peg-in/peg-out requests, and submits transactions for real.
//! `MockPeerNetwork` and `MockPeerHub` will continue to live here as
//! a unit-test seam (the `HttpPeerNetwork` is the production wire), but
//! everything Cardano-shaped in this file is throw-away.
//!
//! FIXME: `MockPeerHub` bypasses HTTP entirely, so it does not exercise
//! the (still-missing) BIP-340 payload authentication / replay
//! protection that the real wire layer will need.

use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::keys::dkg::{round1, round2};
use tokio::sync::Notify;

use crate::cardano::btc_rpc::{BtcRpcConfig, broadcast_btc_tx};
use crate::epoch::state::{EpochError, EpochResult, Roster, SpoInfo};
use crate::epoch::traits::{
    CardanoChain, Clock, CycleRng, DkgFaultEvidence, EpochBoundaryEvent, PeerNetwork,
    PegOutRequestUtxo, RngSource, TreasuryUtxo, UpdateYPlan,
};
use crate::http::wire::{DkgNamespace, SignNamespace};

/// A stand-in `por_id` for a fixture peg-out.
///
/// A fixture peg-out has no Cardano UTxO, so it has no real
/// `hash_output_ref(outpoint)`. Deriving one from the payment keeps it unique per
/// `(destination, amount)`, stable across runs (so mock TMs stay deterministic),
/// and domain-separated from any real por_id, which hashes a Plutus-encoded
/// `OutputReference` rather than this tag.
pub(crate) fn fixture_por_id(spk: &bitcoin::ScriptBuf, amount: bitcoin::Amount) -> [u8; 32] {
    use bitcoin::hashes::{Hash as _, HashEngine, sha256};
    let mut eng = sha256::Hash::engine();
    eng.input(b"heimdall-mock-por-id-v1");
    eng.input(spk.as_bytes());
    eng.input(&amount.to_sat().to_le_bytes());
    sha256::Hash::from_engine(eng).to_byte_array()
}

// ---------------------------------------------------------------------------
// Clocks
// ---------------------------------------------------------------------------

/// Real wall-clock implementation backed by `std::time::Instant`.
#[derive(Debug, Default, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Controllable clock for unit tests.
#[derive(Debug, Clone)]
pub struct FakeClock {
    inner: Arc<Mutex<Instant>>,
}

impl FakeClock {
    pub fn new(start: Instant) -> Self {
        Self {
            inner: Arc::new(Mutex::new(start)),
        }
    }

    pub fn advance(&self, by: Duration) {
        let mut g = self.inner.lock().unwrap();
        *g += by;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.inner.lock().unwrap()
    }
}

// ---------------------------------------------------------------------------
// RngSources
// ---------------------------------------------------------------------------

/// Production `RngSource` — hands out `OsRng` and ignores `context`.
#[derive(Debug, Default, Clone)]
pub struct OsRngSource;

impl RngSource for OsRngSource {
    fn rng(&self, _context: &[u8]) -> CycleRng {
        CycleRng::Os(rand::rngs::OsRng)
    }
}

/// Demo-only deterministic `RngSource`. Each call derives a fresh
/// `ChaCha20Rng` from `sha256(seed || context)`, so different call
/// sites get different streams and the cycle is bit-for-bit
/// reproducible from the seed.
#[derive(Debug, Clone)]
pub struct SeededRngSource {
    seed: [u8; 32],
}

impl SeededRngSource {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

impl RngSource for SeededRngSource {
    fn rng(&self, context: &[u8]) -> CycleRng {
        use bitcoin::hashes::{Hash, HashEngine, sha256};
        use rand_core::SeedableRng;
        let mut eng = sha256::Hash::engine();
        eng.input(&self.seed);
        eng.input(context);
        let stream_seed: [u8; 32] = sha256::Hash::from_engine(eng).to_byte_array();
        CycleRng::Seeded(rand_chacha::ChaCha20Rng::from_seed(stream_seed))
    }
}

// ---------------------------------------------------------------------------
// MockCardanoChain
// ---------------------------------------------------------------------------

/// In-process Cardano mock. `await_epoch_boundary` fires once then blocks
/// forever, so the demo loop runs exactly one cycle.
pub struct MockCardanoChain {
    fixture: crate::epoch::fixture::StaticFixture,
    boundary_fired: Mutex<bool>,
    submitted_txs: Arc<Mutex<Vec<Vec<u8>>>>,
    /// After DKG, `publish_group_key` stores the FROST group key here.
    /// `query_treasury` returns this as Y_51 so the FROST group can
    /// sign the treasury input.
    treasury_y_51: Mutex<Option<bitcoin::key::UntweakedPublicKey>>,
    /// Optional Bitcoin RPC config. When set, `submit_signed_tm` also
    /// broadcasts the signed BTC tx to the node via `sendrawtransaction`.
    btc_rpc: Option<BtcRpcConfig>,
    dkg_faults: Arc<Mutex<Vec<DkgFaultEvidence>>>,
    /// Optional wall-clock schedule anchor (Unix ms) stamped onto the DKG
    /// context, enabling the ceremony window grid (N21) in tests. `None` (the
    /// default) keeps the mock on relative per-round timeouts.
    schedule_anchor_ms: Option<i64>,
    tm_confirmed: Arc<AtomicBool>,
    /// The root the mock reports as the on-chain completed-peg-outs singleton's.
    /// `None` (the default) is the unconfigured chain: `BuildTm` skips the
    /// cross-check instead of treating it as the empty trie.
    cpo_root: Option<[u8; 32]>,
    /// In-memory stand-in for the `treasury_info` state UTxO. `None` (the
    /// default) is a chain with nothing to rotate, so `plan_update_y` reports
    /// no handoff.
    ///
    /// Shared behind an `Arc` because it models CHAIN state: a multi-node test
    /// gives each node its own `MockCardanoChain` (they must each see the epoch
    /// boundary) but they all rotate the one treasury.
    treasury_info: Option<Arc<Mutex<MockTreasuryInfo>>>,
}

/// The `treasury_info` datum + its outpoint, enforcing the one rule that
/// matters: `treasury.ak` rotates the key only for a valid BIP-340 signature
/// under the key being replaced, over the message pinned to the spent outpoint.
#[derive(Debug, Clone)]
pub struct MockTreasuryInfo {
    /// The datum's `current_spos_frost_key`.
    pub current_key: bitcoin::key::UntweakedPublicKey,
    /// The state UTxO the next rotation must be pinned to.
    pub txid: [u8; 32],
    pub vout: u32,
    /// Accepted rotations, in order: `(epoch, new_key, signature)`.
    pub rotations: Vec<(u64, bitcoin::key::UntweakedPublicKey, [u8; 64])>,
}

impl MockCardanoChain {
    pub fn new(fixture: crate::epoch::fixture::StaticFixture) -> Self {
        Self {
            fixture,
            boundary_fired: Mutex::new(false),
            submitted_txs: Arc::new(Mutex::new(Vec::new())),
            treasury_y_51: Mutex::new(None),
            btc_rpc: None,
            dkg_faults: Arc::new(Mutex::new(Vec::new())),
            schedule_anchor_ms: None,
            tm_confirmed: Arc::new(AtomicBool::new(true)),
            cpo_root: None,
            treasury_info: None,
        }
    }

    /// A fresh `treasury_info` state keyed to `current_key`, on the UTxO `txid`
    /// the first Update-Y signature will be pinned to. Share the handle across
    /// every node's chain with [`Self::with_treasury_info`].
    pub fn treasury_info_state(
        current_key: bitcoin::key::UntweakedPublicKey,
        txid: [u8; 32],
    ) -> Arc<Mutex<MockTreasuryInfo>> {
        Arc::new(Mutex::new(MockTreasuryInfo {
            current_key,
            txid,
            vout: 0,
            rotations: Vec::new(),
        }))
    }

    /// Give this chain a `treasury_info` state, so a completed DKG has something
    /// to hand the treasury over to.
    pub fn with_treasury_info(mut self, state: Arc<Mutex<MockTreasuryInfo>>) -> Self {
        self.treasury_info = Some(state);
        self
    }

    /// Report `root` as the on-chain completed-peg-outs singleton's root, so a
    /// test can drive `BuildTm`'s stale-trie refusal from both sides.
    pub fn with_cpo_root(mut self, root: [u8; 32]) -> Self {
        self.cpo_root = Some(root);
        self
    }

    /// Anchor the DKG schedule to `anchor_ms` (Unix wall-clock ms), turning
    /// the ceremony window grid on for this mock chain.
    pub fn with_schedule_anchor_ms(mut self, anchor_ms: i64) -> Self {
        self.schedule_anchor_ms = Some(anchor_ms);
        self
    }

    /// Configure direct Bitcoin RPC broadcast. When set,
    /// `submit_signed_tm` sends the signed BTC tx to bitcoind via
    /// `sendrawtransaction` in addition to storing it locally.
    pub fn with_btc_rpc(
        mut self,
        url: impl Into<String>,
        user: Option<String>,
        pass: Option<String>,
    ) -> Self {
        self.btc_rpc = Some(BtcRpcConfig {
            url: url.into(),
            user,
            pass,
        });
        self
    }

    /// Construct a demo mock chain that synthesizes its roster /
    /// treasury / peg-ins / peg-outs from the built-in static fixture.
    /// The demo binary uses this so `main.rs` doesn't have to know
    /// anything about fixture construction — it just asks for a chain.
    pub fn demo(min_signers: u16, max_signers: u16, base_port: u16) -> Self {
        Self::new(crate::epoch::fixture::demo_static_fixture(
            min_signers,
            max_signers,
            base_port,
        ))
    }

    pub fn submitted_txs(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
        self.submitted_txs.clone()
    }

    /// Shared test control for whether `AwaitConfirm` may complete.
    pub fn confirmation_signal(&self) -> Arc<AtomicBool> {
        self.tm_confirmed.clone()
    }

    pub fn dkg_faults(&self) -> Arc<Mutex<Vec<DkgFaultEvidence>>> {
        self.dkg_faults.clone()
    }
}

#[async_trait]
impl CardanoChain for MockCardanoChain {
    async fn await_epoch_boundary(&self) -> EpochResult<EpochBoundaryEvent> {
        let already_fired = {
            let mut fired = self.boundary_fired.lock().unwrap();
            let prev = *fired;
            *fired = true;
            prev
        };
        if already_fired {
            // Park forever after first call: the demo runs one cycle.
            std::future::pending::<()>().await;
            unreachable!();
        }
        Ok(EpochBoundaryEvent {
            epoch: self.fixture.roster.epoch,
        })
    }

    async fn current_epoch(&self) -> EpochResult<u64> {
        Ok(self.fixture.roster.epoch)
    }

    async fn query_roster(&self, _epoch: u64) -> EpochResult<Roster> {
        Ok(self.fixture.roster.clone())
    }

    async fn query_dkg_context(
        &self,
        epoch: u64,
        attempt: u32,
    ) -> EpochResult<crate::cardano::dkg_roster::DkgContext> {
        let mut ctx = crate::cardano::dkg_roster::DkgContext::from_roster_equal_stake(
            &self.fixture.roster,
            epoch,
            attempt,
        );
        ctx.schedule_anchor_ms = self.schedule_anchor_ms;
        Ok(ctx)
    }

    async fn query_treasury(&self) -> EpochResult<TreasuryUtxo> {
        let maybe_key = *self.treasury_y_51.lock().unwrap();
        let y_51 = maybe_key.unwrap_or(self.fixture.y_51);
        // After DKG: Y_fed = Y_51 = FROST group key (same key everywhere).
        let y_fed = maybe_key.unwrap_or(self.fixture.y_fed);
        Ok(TreasuryUtxo {
            outpoint: self.fixture.treasury_outpoint,
            value: self.fixture.treasury_value,
            y_51,
            y_fed,
            federation_csv_blocks: self.fixture.federation_csv_blocks,
            fee_rate_sat_per_vb: self.fixture.fee_rate_sat_per_vb,
            per_pegout_fee: self.fixture.per_pegout_fee,
            btc_confirmed: true,
        })
    }

    async fn is_tm_confirmed(&self, _txid: &bitcoin::Txid) -> EpochResult<bool> {
        Ok(self.tm_confirmed.load(Ordering::Acquire))
    }

    async fn query_cpo_root(&self) -> EpochResult<Option<[u8; 32]>> {
        Ok(self.cpo_root)
    }

    async fn plan_update_y(
        &self,
        epoch: u64,
        new_y_51: bitcoin::key::UntweakedPublicKey,
    ) -> EpochResult<Option<UpdateYPlan>> {
        let Some(state) = &self.treasury_info else {
            return Ok(None);
        };
        let state = state.lock().unwrap();
        if state.current_key == new_y_51 {
            return Ok(None);
        }
        Ok(Some(UpdateYPlan {
            epoch,
            current_key: state.current_key,
            new_key: new_y_51,
            sig_msg: crate::cardano::treasury_info::update_y_sig_msg(
                &state.txid,
                state.vout,
                epoch,
                &new_y_51.serialize(),
            ),
            state_outpoint: format!("{}:{}", hex::encode(state.txid), state.vout),
        }))
    }

    /// Applies `treasury.ak`'s `UpdateY` gate for real: the rotation lands only
    /// if `signature` is a valid BIP-340 signature under the key being replaced,
    /// over the message pinned to THIS state UTxO. A test that stubs this out
    /// would prove nothing about the handoff.
    async fn submit_update_y(
        &self,
        plan: &UpdateYPlan,
        signature: &[u8; 64],
    ) -> EpochResult<String> {
        let state = self
            .treasury_info
            .as_ref()
            .ok_or_else(|| EpochError::Chain("mock has no treasury_info".into()))?;
        let mut state = state.lock().unwrap();

        if state.current_key != plan.current_key {
            return Err(EpochError::Chain(
                "treasury_info key changed since the plan was made".into(),
            ));
        }
        let expected = crate::cardano::treasury_info::update_y_sig_msg(
            &state.txid,
            state.vout,
            plan.epoch,
            &plan.new_key.serialize(),
        );
        if expected != plan.sig_msg {
            return Err(EpochError::Chain(
                "update-y message is not pinned to the spent state UTxO".into(),
            ));
        }
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(signature)
            .map_err(|e| EpochError::Chain(format!("update-y signature: {e}")))?;
        secp.verify_schnorr(
            &sig,
            &bitcoin::secp256k1::Message::from_digest(expected),
            &state.current_key,
        )
        .map_err(|e| {
            EpochError::Chain(format!("update-y signature rejected by the treasury: {e}"))
        })?;

        state.current_key = plan.new_key;
        state.rotations.push((plan.epoch, plan.new_key, *signature));
        // The state moves to a new UTxO, as a real spend would — so a replayed
        // signature no longer matches the outpoint it is pinned to.
        let mut next = [0u8; 32];
        next[..8].copy_from_slice(&(state.rotations.len() as u64).to_be_bytes());
        next[8..].copy_from_slice(&plan.new_key.serialize()[..24]);
        state.txid = next;
        Ok(hex::encode(next))
    }

    async fn publish_group_key(&self, y_51: bitcoin::key::UntweakedPublicKey) -> EpochResult<()> {
        *self.treasury_y_51.lock().unwrap() = Some(y_51);
        Ok(())
    }

    async fn publish_dkg_fault_and_apply_ban(&self, evidence: DkgFaultEvidence) -> EpochResult<()> {
        self.dkg_faults.lock().unwrap().push(evidence);
        Ok(())
    }

    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>> {
        Ok(self
            .fixture
            .pegouts
            .iter()
            .map(|p| PegOutRequestUtxo {
                script_pubkey: p.script_pubkey.clone(),
                amount: p.amount,
                per_pegout_fee: self.fixture.per_pegout_fee,
                // The fixture has no Cardano UTxO behind it, so the request
                // identity is derived from the payment itself: unique per
                // (destination, amount), stable across runs, and never colliding
                // with a real por_id (which hashes a real 32-byte tx hash).
                created: p.created,
                por_id: fixture_por_id(&p.script_pubkey, p.amount),
                outpoint: [0u8; 36],
            })
            .collect())
    }

    async fn submit_signed_tm(
        &self,
        tx_bytes: &[u8],
        _fulfilled_por_outpoints: &[[u8; 36]],
    ) -> EpochResult<()> {
        self.submitted_txs.lock().unwrap().push(tx_bytes.to_vec());
        if let Some(rpc) = &self.btc_rpc {
            broadcast_btc_tx(rpc, tx_bytes).await?;
        }
        Ok(())
    }

    async fn query_pool_stake(
        &self,
        _pool_id: &str,
    ) -> EpochResult<crate::cardano::stake::PoolStake> {
        // Demo: a stake comfortably above any realistic threshold, so the mock
        // roster always clears the min-stake gate.
        Ok(crate::cardano::stake::PoolStake {
            active_stake: 100_000_000_000_000,
            live_stake: 100_000_000_000_000,
        })
    }
}

// ---------------------------------------------------------------------------
// MockPeerNetwork
// ---------------------------------------------------------------------------

/// Per-SPO published payloads. Shared across all SPOs in the same process
/// via the `MockPeerHub`.
#[derive(Debug, Default)]
struct PeerSlot {
    /// This SPO's Round 1 package + the namespace it was published under.
    dkg1: Option<(DkgNamespace, round1::Package)>,
    /// Round 2 shares this SPO published, keyed by recipient identifier.
    dkg2: BTreeMap<Identifier, (DkgNamespace, round2::Package)>,
    /// Signing Round 1 commitments, keyed by the session namespace they were
    /// published under. Keyed by the WHOLE namespace (not just the session
    /// index) so the mock enforces the same domain separation the HTTP wire
    /// gets from the canonical bytes: a payload published for one message is
    /// never served for another.
    sign1: BTreeMap<SignNamespace, frost_secp256k1_tr::round1::SigningCommitments>,
    sign2: BTreeMap<SignNamespace, frost_secp256k1_tr::round2::SignatureShare>,
}

type MockFaultKey = (u64, u64, u64, u8, Identifier);

/// Shared blackboard that all in-process `MockPeerNetwork`s read/write.
#[derive(Debug, Default)]
pub struct MockPeerHub {
    slots: Mutex<BTreeMap<Identifier, PeerSlot>>,
    dkg_faults: Mutex<BTreeMap<MockFaultKey, Vec<DkgFaultEvidence>>>,
    notify: Notify,
    /// In-process presence for the health gate (N21). An EMPTY set means
    /// presence tracking is unused and every peer reports healthy (so tests
    /// that don't stagger starts are unaffected); once any node registers via
    /// [`Self::set_online`], only registered nodes are healthy.
    online: Mutex<std::collections::BTreeSet<Identifier>>,
}

impl MockPeerHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn push_round1_fault_evidence(
        &self,
        ns: DkgNamespace,
        accused: Identifier,
        evidence: DkgFaultEvidence,
    ) {
        self.push_fault_evidence(ns, 1, accused, evidence);
    }

    pub fn push_round2_fault_evidence(
        &self,
        ns: DkgNamespace,
        accused: Identifier,
        evidence: DkgFaultEvidence,
    ) {
        self.push_fault_evidence(ns, 2, accused, evidence);
    }

    fn push_fault_evidence(
        &self,
        ns: DkgNamespace,
        round: u8,
        accused: Identifier,
        evidence: DkgFaultEvidence,
    ) {
        self.dkg_faults
            .lock()
            .unwrap()
            .entry((ns.epoch, ns.threshold, ns.attempt, round, accused))
            .or_default()
            .push(evidence);
    }

    fn fault_evidence(
        &self,
        ns: DkgNamespace,
        round: u8,
        accused: Identifier,
    ) -> Vec<DkgFaultEvidence> {
        self.dkg_faults
            .lock()
            .unwrap()
            .get(&(ns.epoch, ns.threshold, ns.attempt, round, accused))
            .cloned()
            .unwrap_or_default()
    }

    /// Mark a node as up. Call at spawn (before its epoch loop) in tests that
    /// exercise staggered starts.
    pub fn set_online(&self, id: Identifier) {
        self.online.lock().unwrap().insert(id);
    }

    fn is_online(&self, id: Identifier) -> bool {
        let online = self.online.lock().unwrap();
        online.is_empty() || online.contains(&id)
    }
}

/// One SPO's view of the in-process peer hub.
#[derive(Clone)]
pub struct MockPeerNetwork {
    me: Identifier,
    hub: Arc<MockPeerHub>,
}

impl MockPeerNetwork {
    pub fn new(me: Identifier, hub: Arc<MockPeerHub>) -> Self {
        Self { me, hub }
    }
}

fn with_slot<R>(hub: &MockPeerHub, id: Identifier, f: impl FnOnce(&mut PeerSlot) -> R) -> R {
    let mut slots = hub.slots.lock().unwrap();
    let slot = slots.entry(id).or_default();
    f(slot)
}

#[async_trait]
impl PeerNetwork for MockPeerNetwork {
    async fn check_health(&self, peer: &SpoInfo) -> bool {
        self.hub.is_online(peer.identifier)
    }

    async fn publish_dkg_round1(
        &self,
        ns: DkgNamespace,
        _identifier: Identifier,
        package: &round1::Package,
    ) -> EpochResult<()> {
        let pkg = package.clone();
        with_slot(&self.hub, self.me, |s| s.dkg1 = Some((ns, pkg)));
        self.hub.notify.notify_waiters();
        Ok(())
    }

    async fn publish_dkg_round2(
        &self,
        ns: DkgNamespace,
        _sender_identifier: Identifier,
        _sender_commitments: &[[u8; crate::http::canonical::POINT_LEN]],
        recipients: &[(SpoInfo, round2::Package)],
    ) -> EpochResult<()> {
        with_slot(&self.hub, self.me, |s| {
            for (info, pkg) in recipients {
                s.dkg2.insert(info.identifier, (ns, pkg.clone()));
            }
        });
        self.hub.notify.notify_waiters();
        Ok(())
    }

    async fn publish_sign_round1(
        &self,
        ns: SignNamespace,
        _identifier: Identifier,
        commitments: frost_secp256k1_tr::round1::SigningCommitments,
    ) -> EpochResult<()> {
        with_slot(&self.hub, self.me, |s| {
            s.sign1.insert(ns, commitments);
        });
        self.hub.notify.notify_waiters();
        Ok(())
    }

    async fn publish_sign_round2(
        &self,
        ns: SignNamespace,
        _identifier: Identifier,
        share: frost_secp256k1_tr::round2::SignatureShare,
    ) -> EpochResult<()> {
        with_slot(&self.hub, self.me, |s| {
            s.sign2.insert(ns, share);
        });
        self.hub.notify.notify_waiters();
        Ok(())
    }

    async fn fetch_dkg_round1(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Option<round1::Package>> {
        Ok(with_slot(&self.hub, peer.identifier, |s| {
            s.dkg1
                .as_ref()
                .filter(|(slot_ns, _)| *slot_ns == ns)
                .map(|(_, pkg)| pkg.clone())
        }))
    }

    async fn fetch_dkg_round2(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
        _recipient_identifier: Identifier,
        _sender_commitments: &[[u8; crate::http::canonical::POINT_LEN]],
    ) -> EpochResult<Option<round2::Package>> {
        // Return the share `peer` addressed to us (self.me) in this namespace.
        Ok(with_slot(&self.hub, peer.identifier, |s| {
            s.dkg2
                .get(&self.me)
                .filter(|(slot_ns, _)| *slot_ns == ns)
                .map(|(_, pkg)| pkg.clone())
        }))
    }

    async fn dkg_round1_fault_evidence(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Vec<DkgFaultEvidence>> {
        Ok(self.hub.fault_evidence(ns, 1, peer.identifier))
    }

    async fn dkg_round2_fault_evidence(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
        _recipient_identifier: Identifier,
        _sender_commitments: &[[u8; crate::http::canonical::POINT_LEN]],
    ) -> EpochResult<Vec<DkgFaultEvidence>> {
        Ok(self.hub.fault_evidence(ns, 2, peer.identifier))
    }

    async fn fetch_sign_round1(
        &self,
        ns: SignNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Option<frost_secp256k1_tr::round1::SigningCommitments>> {
        Ok(with_slot(&self.hub, peer.identifier, |s| {
            s.sign1.get(&ns).copied()
        }))
    }

    async fn fetch_sign_round2(
        &self,
        ns: SignNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Option<frost_secp256k1_tr::round2::SignatureShare>> {
        Ok(with_slot(&self.hub, peer.identifier, |s| {
            s.sign2.get(&ns).copied()
        }))
    }
}

// Suppress unused-field warning when no test exercises errors.
#[allow(dead_code)]
fn _assert_error_used() -> EpochError {
    EpochError::Peer("unused".into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::participant;

    #[tokio::test]
    async fn mock_peer_hub_publish_fetch_roundtrip() {
        let hub = MockPeerHub::new();
        let id1 = Identifier::try_from(1u16).unwrap();
        let id2 = Identifier::try_from(2u16).unwrap();
        let net1 = MockPeerNetwork::new(id1, hub.clone());
        let net2 = MockPeerNetwork::new(id2, hub.clone());

        let mut rng = rand::thread_rng();
        let (_, pkg) = participant::dkg_part1(id1, 3, 2, &mut rng).unwrap();
        let ns = DkgNamespace::new(0);
        net1.publish_dkg_round1(ns, id1, &pkg).await.unwrap();

        let info1 = SpoInfo {
            identifier: id1,
            pool_id: vec![],
            bifrost_url: String::new(),
            bifrost_id_pk: vec![],
        };
        let fetched = net2.fetch_dkg_round1(ns, &info1).await.unwrap().unwrap();
        // The mock returns the package verbatim (no crypto in-process).
        assert_eq!(fetched, pkg);
        // A different namespace must not match.
        assert!(
            net2.fetch_dkg_round1(DkgNamespace::new(1), &info1)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fake_clock_advances() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        assert_eq!(clock.now(), start);
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now(), start + Duration::from_secs(5));
    }
}
