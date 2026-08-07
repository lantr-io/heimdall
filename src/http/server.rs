//! HTTP server exposing one SPO's published protocol payloads.
//!
//! Each SPO runs this server at its `bifrost_url`. Peers fetch DKG and
//! signing material from it; nothing is ever pushed. DKG routes follow
//! the spec scheme
//! `…/dkg/<epoch>/<threshold>/<attempt>/round{1,2}/<pool_id>.json` and
//! serve the pre-built, BIP-340-signed JSON verbatim (the publisher signs
//! the canonical bytes; the server is a dumb blob store). A server only
//! ever holds its own payloads, so the `<pool_id>` segment must match
//! `own_pool_id_hex` — a mismatch is a 404.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use tokio::sync::RwLock;

/// Which DKG round a stored payload belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DkgRoundKey {
    Round1,
    Round2,
}

/// Shared state the FROST engine writes to and HTTP handlers read from.
#[derive(Debug, Default)]
pub struct AppState {
    /// This server's own `pool_id`, hex — the only one it serves.
    pub own_pool_id_hex: String,
    /// Published DKG payload JSON, keyed by `(epoch, threshold, attempt, round)`.
    pub dkg: BTreeMap<(u64, u64, u64, DkgRoundKey), String>,
    /// Published signing payload JSON, keyed by `(epoch, session)` — one FROST
    /// session per TM input, plus the reserved rotation session. Stored as the
    /// pre-signed JSON string for the same reason DKG payloads are: the
    /// publisher signs canonical bytes, and the server must hand back exactly
    /// what was signed rather than a re-serialization of it.
    pub sign1: BTreeMap<(u64, u32), String>,
    pub sign2: BTreeMap<(u64, u32), String>,
}

pub type SharedState = Arc<RwLock<AppState>>;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/dkg/{epoch}/{threshold}/{attempt}/round1/{file}",
            get(get_dkg1),
        )
        .route(
            "/dkg/{epoch}/{threshold}/{attempt}/round2/{file}",
            get(get_dkg2),
        )
        .route("/sign/{epoch}/round1/{session}/{file}", get(get_sign1))
        .route("/sign/{epoch}/round2/{session}/{file}", get(get_sign2))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

/// Strip the `.json` suffix and confirm the requested pool_id is ours.
fn check_pool_id(file: &str, own: &str) -> Result<(), StatusCode> {
    let pool_id = file.strip_suffix(".json").ok_or(StatusCode::NOT_FOUND)?;
    if pool_id.eq_ignore_ascii_case(own) {
        Ok(())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn serve_dkg(
    state: SharedState,
    epoch: u64,
    threshold: u64,
    attempt: u64,
    round: DkgRoundKey,
    file: String,
) -> Result<impl IntoResponse, StatusCode> {
    let s = state.read().await;
    check_pool_id(&file, &s.own_pool_id_hex)?;
    let body = s
        .dkg
        .get(&(epoch, threshold, attempt, round))
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body))
}

async fn get_dkg1(
    State(state): State<SharedState>,
    Path((epoch, threshold, attempt, file)): Path<(u64, u64, u64, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_dkg(state, epoch, threshold, attempt, DkgRoundKey::Round1, file).await
}

async fn get_dkg2(
    State(state): State<SharedState>,
    Path((epoch, threshold, attempt, file)): Path<(u64, u64, u64, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_dkg(state, epoch, threshold, attempt, DkgRoundKey::Round2, file).await
}

/// Serve one signing-round blob. Like the DKG routes, the `<pool_id>.json`
/// segment must name THIS server — it only ever holds its own payloads, so any
/// other pool_id is a 404 rather than someone else's bytes under the wrong name.
async fn serve_sign(
    state: SharedState,
    round: DkgRoundKey,
    epoch: u64,
    session: u32,
    file: String,
) -> Result<impl IntoResponse, StatusCode> {
    let s = state.read().await;
    check_pool_id(&file, &s.own_pool_id_hex)?;
    let map = match round {
        DkgRoundKey::Round1 => &s.sign1,
        DkgRoundKey::Round2 => &s.sign2,
    };
    let body = map
        .get(&(epoch, session))
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body))
}

async fn get_sign1(
    State(state): State<SharedState>,
    Path((epoch, session, file)): Path<(u64, u32, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_sign(state, DkgRoundKey::Round1, epoch, session, file).await
}

async fn get_sign2(
    State(state): State<SharedState>,
    Path((epoch, session, file)): Path<(u64, u32, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_sign(state, DkgRoundKey::Round2, epoch, session, file).await
}
