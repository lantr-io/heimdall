use std::sync::Arc;

use heimdall::http::server::{AppState, RoundKey, SharedState, router};
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
            (1, 51, 0, RoundKey::Round1),
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

/// The signing routes follow the same scheme as the DKG ones (WI-038): keyed by
/// `(epoch, session)`, served verbatim so the bytes the peer verifies are the
/// bytes the publisher signed, and gated on the `<pool_id>.json` naming THIS
/// server.
#[tokio::test]
async fn test_sign_routes_serve_stored_json_and_gate_on_pool_id() {
    let pool_hex = hex::encode([7u8; 28]);
    let state = make_shared_state();
    {
        let mut s = state.write().await;
        s.own_pool_id_hex = pool_hex.clone();
        s.sign
            .insert((4, 1, 0, RoundKey::Round1), r#"{"round":1}"#.to_string());
        s.sign
            .insert((4, 1, 0, RoundKey::Round2), r#"{"round":2}"#.to_string());
    }
    let base = spawn_server(state).await;

    for (round, body) in [("round1", r#"{"round":1}"#), ("round2", r#"{"round":2}"#)] {
        let resp = reqwest::get(format!("{base}/sign/4/1/{round}/0/{pool_hex}.json"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), body);
    }

    // Another pool's id -> 404: a server only ever holds its own payloads.
    let other = hex::encode([9u8; 28]);
    let resp = reqwest::get(format!("{base}/sign/4/1/round1/0/{other}.json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // A session that was never published -> 404.
    let resp = reqwest::get(format!("{base}/sign/4/1/round1/1/{pool_hex}.json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // The next ATTEMPT at the same session -> 404. The sequence is a path
    // segment, so a retried movement cannot be served the previous attempt's
    // blob even though everything else about it is identical (WI-W8ZC4).
    let resp = reqwest::get(format!("{base}/sign/4/2/round1/0/{pool_hex}.json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_sign_endpoints_404_when_empty() {
    let pool_hex = hex::encode([7u8; 28]);
    let state = make_shared_state();
    {
        state.write().await.own_pool_id_hex = pool_hex.clone();
    }
    let base = spawn_server(state).await;

    for round in ["round1", "round2"] {
        let resp = reqwest::get(format!("{base}/sign/0/1/{round}/0/{pool_hex}.json"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }
}
