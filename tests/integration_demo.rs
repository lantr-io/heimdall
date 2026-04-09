//! End-to-end integration test over real HTTP.
//!
//! Spins up 3 SPOs in one process, each with its own `HttpPeerNetwork`
//! and axum server bound to a localhost port. Drives `run_epoch_loop`
//! on three tasks and asserts they all converge on the same signed
//! Treasury Movement, going through the same JSON/HTTP wire path that
//! the `demo` subcommand uses in production.

use std::sync::Arc;
use std::time::Duration;

use frost_secp256k1_tr::Identifier;

use heimdall::cardano::mock::MockCardanoPegInSource;
use heimdall::cardano::pegin_source::CardanoPegInSource;
use heimdall::epoch::fixture::demo_static_fixture;
use heimdall::epoch::mocks::{MockCardanoChain, OsRngSource, SystemClock};
use heimdall::epoch::run_epoch_loop;
use heimdall::epoch::state::{EpochConfig, SpoIdentity};
use heimdall::epoch::traits::{CardanoChain, Clock, PeerNetwork, RngSource};
use heimdall::http::peer_network::HttpPeerNetwork;
use heimdall::http::server::router;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_cycle_3_spos_over_http() {
    let min_signers = 2u16;
    let max_signers = 3u16;
    let base_port = 18460u16; // distinct from other test files

    let fixture = demo_static_fixture(min_signers, max_signers, base_port);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);

    // Build per-SPO HTTP layer + spawn the axum server.
    let mut nets: Vec<Arc<HttpPeerNetwork>> = Vec::with_capacity(max_signers as usize);
    for i in 0..max_signers {
        let net = Arc::new(HttpPeerNetwork::new());
        let port = base_port + i;
        let app = router(net.shared_state());
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        nets.push(net);
    }
    // Give servers a beat to start accepting connections.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Spawn one epoch loop per SPO. Each gets its own MockCardanoChain
    // (the mock's "fire boundary once" flag is per-instance).
    let mut handles = Vec::with_capacity(max_signers as usize);
    for (i, net) in nets.into_iter().enumerate() {
        let id = Identifier::try_from((i as u16) + 1).unwrap();
        let port = base_port + i as u16;
        let chain: Arc<dyn CardanoChain> =
            Arc::new(MockCardanoChain::new(fixture.clone()));
        let pegin_source: Arc<dyn CardanoPegInSource> =
            Arc::new(MockCardanoPegInSource::new());
        let clock = clock.clone();
        let peers: Arc<dyn PeerNetwork> = net;
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
        handles.push(tokio::spawn(async move {
            let mut config = EpochConfig::demo_default(SpoIdentity {
                identifier: id,
                port,
            });
            config.pegin_collection_window = Duration::from_millis(100);
            config.pegin_poll_interval = Duration::from_millis(20);
            run_epoch_loop(chain, pegin_source, peers, clock, rng, &config).await
        }));
    }

    let mut tms = Vec::with_capacity(max_signers as usize);
    for h in handles {
        tms.push(h.await.unwrap().expect("epoch loop"));
    }

    // All SPOs must have agreed on the same txid.
    let txid0 = tms[0].txid;
    for tm in &tms[1..] {
        assert_eq!(tm.txid, txid0, "txid mismatch across SPOs");
    }

    // Witnessed Bitcoin tx must be a valid BIP-341 key-path spend on
    // every input: 1-element witness, 64-byte schnorr sig (default
    // sighash).
    let tm = &tms[0];
    for (i, txin) in tm.unsigned_tx.input.iter().enumerate() {
        assert_eq!(txin.witness.len(), 1, "input {i} witness should have 1 element");
        let elem = txin.witness.iter().next().unwrap();
        assert_eq!(elem.len(), 64, "input {i} witness should be 64-byte schnorr sig");
    }
}
