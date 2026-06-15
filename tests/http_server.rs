use std::sync::Arc;

use heimdall::http::server::{AppState, DkgRoundKey, SharedState, router};
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
async fn test_dkg_spec_route_serves_stored_json() {
    // The DKG server is a dumb blob store keyed by (epoch, threshold,
    // attempt, round); the publisher signs the canonical bytes. Here we
    // store a payload directly and check the spec URL scheme + pool_id gate.
    let pool_hex = hex::encode([7u8; 28]);
    let state = make_shared_state();
    {
        let mut s = state.write().await;
        s.own_pool_id_hex = pool_hex.clone();
        s.dkg.insert(
            (1, 51, 0, DkgRoundKey::Round1),
            r#"{"hello":"world"}"#.to_string(),
        );
    }
    let base = spawn_server(state).await;

    // Correct spec path returns the stored JSON verbatim.
    let resp = reqwest::get(format!("{base}/dkg/1/51/0/round1/{pool_hex}.json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), r#"{"hello":"world"}"#);

    // A pool_id that is not ours -> 404.
    let other = hex::encode([9u8; 28]);
    let resp = reqwest::get(format!("{base}/dkg/1/51/0/round1/{other}.json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // A round that was never published -> 404.
    let resp = reqwest::get(format!("{base}/dkg/1/51/0/round2/{pool_hex}.json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_sign_endpoints_404_when_empty() {
    let state = make_shared_state();
    let base = spawn_server(state).await;

    let resp = reqwest::get(format!("{base}/sign/0/round1/0/1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let resp = reqwest::get(format!("{base}/sign/0/round2/0/1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
