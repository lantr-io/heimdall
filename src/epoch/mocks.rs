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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use frost_secp256k1_tr::Identifier;
use tokio::sync::Notify;

use crate::epoch::state::{EpochError, EpochResult, Roster, SpoInfo};
use crate::epoch::traits::{
    CardanoChain, Clock, CycleRng, EpochBoundaryEvent, PegInUtxo, PegOutRequestUtxo, PeerNetwork,
    RngSource, TreasuryUtxo,
};
use crate::http::payloads::{Dkg1Payload, Dkg2Payload, Sign1Payload, Sign2Payload};

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
        use bitcoin::hashes::{sha256, Hash, HashEngine};
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
}

impl MockCardanoChain {
    pub fn new(fixture: crate::epoch::fixture::StaticFixture) -> Self {
        Self {
            fixture,
            boundary_fired: Mutex::new(false),
            submitted_txs: Arc::new(Mutex::new(Vec::new())),
        }
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

    async fn query_roster(&self, _epoch: u64) -> EpochResult<Roster> {
        Ok(self.fixture.roster.clone())
    }

    async fn query_treasury(&self) -> EpochResult<TreasuryUtxo> {
        Ok(TreasuryUtxo {
            outpoint: self.fixture.treasury_outpoint,
            value: self.fixture.treasury_value,
            y_67: self.fixture.y_67,
            y_fed: self.fixture.y_fed,
            federation_csv_blocks: self.fixture.federation_csv_blocks,
            fee_rate_sat_per_vb: self.fixture.fee_rate_sat_per_vb,
            per_pegout_fee: self.fixture.per_pegout_fee,
        })
    }

    async fn query_pegin_requests(&self) -> EpochResult<Vec<PegInUtxo>> {
        Ok(self
            .fixture
            .pegins
            .iter()
            .map(|p| PegInUtxo {
                outpoint: p.outpoint,
                value: p.value,
            })
            .collect())
    }

    async fn query_pegout_requests(&self) -> EpochResult<Vec<PegOutRequestUtxo>> {
        Ok(self
            .fixture
            .pegouts
            .iter()
            .map(|p| PegOutRequestUtxo {
                script_pubkey: p.script_pubkey.clone(),
                amount: p.amount,
            })
            .collect())
    }

    async fn submit_signed_tm(&self, tx_bytes: &[u8]) -> EpochResult<()> {
        self.submitted_txs.lock().unwrap().push(tx_bytes.to_vec());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MockPeerNetwork
// ---------------------------------------------------------------------------

/// Per-SPO published payloads. Shared across all SPOs in the same process
/// via the `MockPeerHub`.
#[derive(Debug, Default)]
struct PeerSlot {
    dkg1: Option<Dkg1Payload>,
    dkg2: Option<Dkg2Payload>,
    sign1: BTreeMap<u32, Sign1Payload>,
    sign2: BTreeMap<u32, Sign2Payload>,
}

/// Shared blackboard that all in-process `MockPeerNetwork`s read/write.
#[derive(Debug, Default)]
pub struct MockPeerHub {
    slots: Mutex<BTreeMap<Identifier, PeerSlot>>,
    notify: Notify,
}

impl MockPeerHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
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
    async fn publish_dkg_round1(&self, payload: Dkg1Payload) -> EpochResult<()> {
        with_slot(&self.hub, self.me, |s| s.dkg1 = Some(payload));
        self.hub.notify.notify_waiters();
        Ok(())
    }

    async fn publish_dkg_round2(&self, payload: Dkg2Payload) -> EpochResult<()> {
        with_slot(&self.hub, self.me, |s| s.dkg2 = Some(payload));
        self.hub.notify.notify_waiters();
        Ok(())
    }

    async fn publish_sign_round1(&self, payload: Sign1Payload) -> EpochResult<()> {
        let idx = payload.input_index;
        with_slot(&self.hub, self.me, |s| {
            s.sign1.insert(idx, payload);
        });
        self.hub.notify.notify_waiters();
        Ok(())
    }

    async fn publish_sign_round2(&self, payload: Sign2Payload) -> EpochResult<()> {
        let idx = payload.input_index;
        with_slot(&self.hub, self.me, |s| {
            s.sign2.insert(idx, payload);
        });
        self.hub.notify.notify_waiters();
        Ok(())
    }

    async fn fetch_dkg_round1(
        &self,
        epoch: u64,
        peer: &SpoInfo,
    ) -> EpochResult<Option<Dkg1Payload>> {
        Ok(with_slot(&self.hub, peer.identifier, |s| {
            s.dkg1.as_ref().filter(|p| p.epoch == epoch).cloned()
        }))
    }

    async fn fetch_dkg_round2(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        _my_id: Identifier,
    ) -> EpochResult<Option<Dkg2Payload>> {
        Ok(with_slot(&self.hub, peer.identifier, |s| {
            s.dkg2.as_ref().filter(|p| p.epoch == epoch).cloned()
        }))
    }

    async fn fetch_sign_round1(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        input_index: u32,
    ) -> EpochResult<Option<Sign1Payload>> {
        Ok(with_slot(&self.hub, peer.identifier, |s| {
            s.sign1
                .get(&input_index)
                .filter(|p| p.epoch == epoch)
                .cloned()
        }))
    }

    async fn fetch_sign_round2(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        input_index: u32,
    ) -> EpochResult<Option<Sign2Payload>> {
        Ok(with_slot(&self.hub, peer.identifier, |s| {
            s.sign2
                .get(&input_index)
                .filter(|p| p.epoch == epoch)
                .cloned()
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
        net1.publish_dkg_round1(Dkg1Payload {
            epoch: 0,
            identifier: id1,
            package: pkg.clone(),
        })
        .await
        .unwrap();

        let info1 = SpoInfo {
            identifier: id1,
            bifrost_url: String::new(),
            bifrost_id_pk: vec![],
        };
        let fetched = net2.fetch_dkg_round1(0, &info1).await.unwrap().unwrap();
        assert_eq!(fetched.identifier, id1);
        assert_eq!(fetched.package, pkg);
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
