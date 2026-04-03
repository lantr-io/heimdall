use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use tokio::sync::RwLock;

use super::payloads::*;

/// Shared state that the FROST engine writes to and HTTP handlers read from.
#[derive(Debug, Default)]
pub struct AppState {
    pub dkg1: Option<Dkg1Payload>,
    pub dkg2: Option<Dkg2Payload>,
    pub sign1: Option<Sign1Payload>,
    pub sign2: Option<Sign2Payload>,
}

pub type SharedState = Arc<RwLock<AppState>>;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/dkg/round1", get(get_dkg1))
        .route("/dkg/round2", get(get_dkg2))
        .route("/sign/round1", get(get_sign1))
        .route("/sign/round2", get(get_sign2))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn get_dkg1(
    State(state): State<SharedState>,
) -> Result<Json<Dkg1Payload>, StatusCode> {
    let s = state.read().await;
    s.dkg1.clone().map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn get_dkg2(
    State(state): State<SharedState>,
) -> Result<Json<Dkg2Payload>, StatusCode> {
    let s = state.read().await;
    s.dkg2.clone().map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn get_sign1(
    State(state): State<SharedState>,
) -> Result<Json<Sign1Payload>, StatusCode> {
    let s = state.read().await;
    s.sign1.clone().map(Json).ok_or(StatusCode::NOT_FOUND)
}

async fn get_sign2(
    State(state): State<SharedState>,
) -> Result<Json<Sign2Payload>, StatusCode> {
    let s = state.read().await;
    s.sign2.clone().map(Json).ok_or(StatusCode::NOT_FOUND)
}
