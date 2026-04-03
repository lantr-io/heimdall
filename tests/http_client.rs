use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use frost_secp256k1_tr::Identifier;
use heimdall::frost::participant;
use heimdall::http::client::{PeerClient, PeerInfo};
use heimdall::http::payloads::*;
use heimdall::http::server::{AppState, SharedState, router};
use tokio::sync::RwLock;

/// Spawn an SPO server on a random port, return (shared_state, base_url).
async fn spawn_spo(id: Identifier, dkg1: Dkg1Payload) -> (SharedState, String) {
    let state: SharedState = Arc::new(RwLock::new(AppState {
        dkg1: Some(dkg1),
        ..Default::default()
    }));
    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let _ = id;
    (state, format!("http://{addr}"))
}

#[tokio::test]
async fn test_client_fetches_dkg1_from_two_peers() {
    let mut rng = rand::thread_rng();
    let id1 = Identifier::try_from(1u16).unwrap();
    let id2 = Identifier::try_from(2u16).unwrap();

    let (_, pkg1) = participant::dkg_part1(id1, 3, 2, &mut rng).unwrap();
    let (_, pkg2) = participant::dkg_part1(id2, 3, 2, &mut rng).unwrap();

    let payload1 = Dkg1Payload {
        epoch: 1,
        identifier: id1,
        package: pkg1.clone(),
    };
    let payload2 = Dkg1Payload {
        epoch: 1,
        identifier: id2,
        package: pkg2.clone(),
    };

    let (_, url1) = spawn_spo(id1, payload1).await;
    let (_, url2) = spawn_spo(id2, payload2).await;

    let client = PeerClient::new(vec![
        PeerInfo {
            identifier: id1,
            base_url: url1,
        },
        PeerInfo {
            identifier: id2,
            base_url: url2,
        },
    ]);

    let packages = client
        .fetch_dkg1_packages(Duration::from_secs(5))
        .await
        .unwrap();

    assert_eq!(packages.len(), 2);
    assert_eq!(packages[&id1], pkg1);
    assert_eq!(packages[&id2], pkg2);
}

#[tokio::test]
async fn test_client_fetches_dkg2_packages_for_me() {
    let mut rng = rand::thread_rng();
    let ids: Vec<Identifier> = (1..=3u16)
        .map(|i| Identifier::try_from(i).unwrap())
        .collect();

    // Run DKG round 1+2 to get real round2 data
    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for &id in &ids {
        let (secret, package) = participant::dkg_part1(id, 3, 2, &mut rng).unwrap();
        round1_secrets.insert(id, secret);
        round1_packages.insert(id, package);
    }

    let mut round2_per_sender = BTreeMap::new();
    for &id in &ids {
        let others: BTreeMap<_, _> = round1_packages
            .iter()
            .filter(|&(&k, _)| k != id)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let secret = round1_secrets.remove(&id).unwrap();
        let (_, packages2) = participant::dkg_part2(secret, &others).unwrap();
        round2_per_sender.insert(id, packages2);
    }

    // SPO 3 wants to fetch from SPOs 1 and 2
    let my_id = ids[2]; // SPO 3

    // Set up servers for SPO 1 and SPO 2
    let state1: SharedState = Arc::new(RwLock::new(AppState {
        dkg1: Some(Dkg1Payload {
            epoch: 1,
            identifier: ids[0],
            package: round1_packages[&ids[0]].clone(),
        }),
        dkg2: Some(Dkg2Payload {
            epoch: 1,
            identifier: ids[0],
            packages: round2_per_sender[&ids[0]].clone(),
        }),
        ..Default::default()
    }));
    let app1 = router(state1);
    let listener1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();
    tokio::spawn(async { axum::serve(listener1, app1).await.unwrap() });

    let state2: SharedState = Arc::new(RwLock::new(AppState {
        dkg1: Some(Dkg1Payload {
            epoch: 1,
            identifier: ids[1],
            package: round1_packages[&ids[1]].clone(),
        }),
        dkg2: Some(Dkg2Payload {
            epoch: 1,
            identifier: ids[1],
            packages: round2_per_sender[&ids[1]].clone(),
        }),
        ..Default::default()
    }));
    let app2 = router(state2);
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    tokio::spawn(async { axum::serve(listener2, app2).await.unwrap() });

    let client = PeerClient::new(vec![
        PeerInfo {
            identifier: ids[0],
            base_url: format!("http://{addr1}"),
        },
        PeerInfo {
            identifier: ids[1],
            base_url: format!("http://{addr2}"),
        },
    ]);

    let packages = client
        .fetch_dkg2_packages(my_id, Duration::from_secs(5))
        .await
        .unwrap();

    assert_eq!(packages.len(), 2);
    // Each package should be the one addressed to my_id
    assert_eq!(packages[&ids[0]], round2_per_sender[&ids[0]][&my_id]);
    assert_eq!(packages[&ids[1]], round2_per_sender[&ids[1]][&my_id]);
}

#[tokio::test]
async fn test_client_retries_until_data_available() {
    let mut rng = rand::thread_rng();
    let id1 = Identifier::try_from(1u16).unwrap();

    let (_, pkg1) = participant::dkg_part1(id1, 3, 2, &mut rng).unwrap();

    // Start server with empty state
    let state: SharedState = Arc::new(RwLock::new(AppState::default()));
    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });

    let client = PeerClient::new(vec![PeerInfo {
        identifier: id1,
        base_url: format!("http://{addr}"),
    }]);

    // Publish data after 200ms
    let state2 = state.clone();
    let pkg_clone = pkg1.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut s = state2.write().await;
        s.dkg1 = Some(Dkg1Payload {
            epoch: 1,
            identifier: id1,
            package: pkg_clone,
        });
    });

    let packages = client
        .fetch_dkg1_packages(Duration::from_secs(5))
        .await
        .unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[&id1], pkg1);
}
