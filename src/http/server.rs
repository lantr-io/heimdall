//! HTTP server exposing one SPO's published protocol payloads.
//!
//! Each SPO runs this server at its `bifrost_url`. Peers fetch DKG and
//! signing material from it; nothing is ever pushed. Routes carry
//! `epoch` and `pool_id` so clients disambiguate traffic across epochs
//! and peers; `pool_id` is the `u16` encoding of a FROST `Identifier`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use tokio::sync::RwLock;

use super::payloads::*;

/// Shared state that the FROST engine writes to and HTTP handlers read from.
///
/// `sign1`/`sign2` are keyed by `(epoch, input_index)` because each TM
/// input runs its own FROST signing session in parallel.
#[derive(Debug, Default)]
pub struct AppState {
    pub dkg1: BTreeMap<u64, Dkg1Payload>,
    pub dkg2: BTreeMap<u64, Dkg2Payload>,
    pub sign1: BTreeMap<(u64, u32), Sign1Payload>,
    pub sign2: BTreeMap<(u64, u32), Sign2Payload>,
}

pub type SharedState = Arc<RwLock<AppState>>;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/dkg/{epoch}/round1/{pool_id}", get(get_dkg1))
        .route("/dkg/{epoch}/round2/{pool_id}", get(get_dkg2))
        .route(
            "/sign/{epoch}/round1/{input_index}/{pool_id}",
            get(get_sign1),
        )
        .route(
            "/sign/{epoch}/round2/{input_index}/{pool_id}",
            get(get_sign2),
        )
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn get_dkg1(
    State(state): State<SharedState>,
    Path((epoch, _pool_id)): Path<(u64, u16)>,
) -> Result<Json<Dkg1Payload>, StatusCode> {
    let s = state.read().await;
    s.dkg1.get(&epoch).cloned().map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn get_dkg2(
    State(state): State<SharedState>,
    Path((epoch, _pool_id)): Path<(u64, u16)>,
) -> Result<Json<Dkg2Payload>, StatusCode> {
    let s = state.read().await;
    s.dkg2.get(&epoch).cloned().map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn get_sign1(
    State(state): State<SharedState>,
    Path((epoch, input_index, _pool_id)): Path<(u64, u32, u16)>,
) -> Result<Json<Sign1Payload>, StatusCode> {
    let s = state.read().await;
    s.sign1
        .get(&(epoch, input_index))
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_sign2(
    State(state): State<SharedState>,
    Path((epoch, input_index, _pool_id)): Path<(u64, u32, u16)>,
) -> Result<Json<Sign2Payload>, StatusCode> {
    let s = state.read().await;
    s.sign2
        .get(&(epoch, input_index))
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
