use std::collections::BTreeMap;
use std::sync::Arc;

use frost_secp256k1_tr::Identifier;
use heimdall::frost::participant;
use heimdall::http::payloads::*;
use heimdall::http::server::{AppState, SharedState, router};
use tokio::sync::RwLock;

fn make_shared_state() -> SharedState {
    Arc::new(RwLock::new(AppState::default()))
}

/// Spawn the server on a random available port, return base URL.
async fn spawn_server(state: SharedState) -> String {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn test_health_endpoint() {
    let state = make_shared_state();
    let base = spawn_server(state).await;
    let resp = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_dkg1_not_found_then_found() {
    let state = make_shared_state();
    let base = spawn_server(state.clone()).await;

    // Not published yet -> 404
    let resp = reqwest::get(format!("{base}/dkg/round1")).await.unwrap();
    assert_eq!(resp.status(), 404);

    // Publish DKG round 1 data
    let mut rng = rand::thread_rng();
    let id = Identifier::try_from(1u16).unwrap();
    let (_, package) = participant::dkg_part1(id, 3, 2, &mut rng).unwrap();
    let payload = Dkg1Payload {
        epoch: 1,
        identifier: id,
        package,
    };
    {
        let mut s = state.write().await;
        s.dkg1 = Some(payload.clone());
    }

    // Now should return 200
    let resp = reqwest::get(format!("{base}/dkg/round1")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let back: Dkg1Payload = resp.json().await.unwrap();
    assert_eq!(back.epoch, payload.epoch);
    assert_eq!(back.identifier, payload.identifier);
    assert_eq!(back.package, payload.package);
}

#[tokio::test]
async fn test_dkg2_not_found_then_found() {
    let state = make_shared_state();
    let base = spawn_server(state.clone()).await;

    let resp = reqwest::get(format!("{base}/dkg/round2")).await.unwrap();
    assert_eq!(resp.status(), 404);

    // Generate real DKG round 2 data
    let mut rng = rand::thread_rng();
    let ids: Vec<Identifier> = (1..=3u16)
        .map(|i| Identifier::try_from(i).unwrap())
        .collect();
    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for &id in &ids {
        let (secret, package) = participant::dkg_part1(id, 3, 2, &mut rng).unwrap();
        round1_secrets.insert(id, secret);
        round1_packages.insert(id, package);
    }
    let id = ids[0];
    let others: BTreeMap<_, _> = round1_packages
        .iter()
        .filter(|&(&k, _)| k != id)
        .map(|(&k, v)| (k, v.clone()))
        .collect();
    let (_, packages2) =
        participant::dkg_part2(round1_secrets.remove(&id).unwrap(), &others).unwrap();

    let payload = Dkg2Payload {
        epoch: 1,
        identifier: id,
        packages: packages2,
    };
    {
        let mut s = state.write().await;
        s.dkg2 = Some(payload.clone());
    }

    let resp = reqwest::get(format!("{base}/dkg/round2")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let back: Dkg2Payload = resp.json().await.unwrap();
    assert_eq!(back.epoch, 1);
    assert_eq!(back.identifier, id);
    assert_eq!(back.packages, payload.packages);
}

#[tokio::test]
async fn test_sign_endpoints_404_when_empty() {
    let state = make_shared_state();
    let base = spawn_server(state).await;

    let resp = reqwest::get(format!("{base}/sign/round1")).await.unwrap();
    assert_eq!(resp.status(), 404);

    let resp = reqwest::get(format!("{base}/sign/round2")).await.unwrap();
    assert_eq!(resp.status(), 404);
}
