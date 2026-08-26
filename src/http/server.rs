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

/// Which of a two-round protocol's rounds a stored payload belongs to. Shared
/// by the DKG and the signing ceremony — both are two-round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoundKey {
    Round1,
    Round2,
}

/// Shared state the FROST engine writes to and HTTP handlers read from.
#[derive(Debug, Default)]
pub struct AppState {
    /// This server's own `pool_id`, hex — the only one it serves.
    pub own_pool_id_hex: String,
    /// Published DKG payload JSON, keyed by `(epoch, threshold, attempt, round)`.
    pub dkg: BTreeMap<(u64, u64, u64, RoundKey), String>,
    /// Published signing payload JSON, keyed by `(epoch, sequence, session,
    /// round)` — one FROST session per TM input, plus the reserved rotation
    /// session. Folds the round into the key exactly as `dkg` above does, so
    /// serving needs no branch. Stored as the pre-signed JSON string for the
    /// same reason DKG payloads are: the publisher signs canonical bytes, and
    /// the server must hand back exactly what was signed, not a
    /// re-serialization of it.
    ///
    /// `sequence` is in the key for the same reason `attempt` is in `dkg`'s: a
    /// retried movement is byte-identical, so without it the second attempt
    /// reads the first's commitments (WI-W8ZC4).
    pub sign: BTreeMap<(u64, u64, u32, RoundKey), String>,
    /// What this deployment runs with, for peers to compare before entering a
    /// ceremony with it (WI-VMP6J). Written at each ceremony entry by
    /// `PeerNetwork::set_node_facts`; empty until the first one, which readers
    /// treat as "has not entered a ceremony yet" rather than as a disagreement.
    pub facts: crate::http::compat::NodeFacts,
    /// `protocol.state_dir` – where the epoch machine persists this node's
    /// swept peg-ins trie (`spi-trie.json`). The [SPI-4] proof route loads the
    /// trie from here at the point of use (the CpoTrie idiom), so it always
    /// serves the state the last confirmed TM left behind, never a stale
    /// in-memory snapshot. `None` means this node keeps no trie, and the route
    /// answers 503 rather than serving proofs against a trie nothing maintains.
    pub state_dir: Option<std::path::PathBuf>,
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
        .route(
            "/sign/{epoch}/{sequence}/round1/{session}/{file}",
            get(get_sign1),
        )
        .route(
            "/sign/{epoch}/{sequence}/round2/{session}/{file}",
            get(get_sign2),
        )
        .with_state(state)
}

/// Liveness AND compatibility (WI-067).
///
/// `status` stays exactly where it was so a peer running a build that predates
/// the extra fields still parses this; the additions are what a peer compares
/// before entering a ceremony with us. See [`crate::http::compat`].
async fn health(State(state): State<SharedState>) -> Json<serde_json::Value> {
    // The DKG namespace this node most recently published a Round 1 under
    // (WI-113). Derived from what is actually SERVED rather than from separate
    // bookkeeping, so it cannot advertise a ceremony whose payloads are not
    // here — and a reader treats it as a hint regardless: it fetches that
    // namespace and verifies the signatures, which a wrong answer cannot pass.
    //
    // It exists because the attempt is not derivable by an outsider. It is
    // `window * DKG_ATTEMPTS_PER_WINDOW` where the window counts from the epoch
    // boundary to whenever this node happened to enter, so a node started
    // mid-epoch publishes under an attempt nobody else can compute — our own
    // preprod nodes joined window 522. Without this a third party auditing the
    // ceremony (the federation, for the Phase-1 handoff) can only guess, and
    // guessing wrong is indistinguishable from a roster that published nothing.
    let (published, facts) = {
        let st = state.read().await;
        let published = st
            .dkg
            .keys()
            .filter(|(_, _, _, round)| *round == RoundKey::Round1)
            .map(|(epoch, _, attempt, _)| (*epoch, *attempt))
            .max();
        (published, st.facts)
    };
    // Serialized from `PeerBuild` itself rather than hand-written, so the
    // published field names cannot drift from the ones the reader parses. The
    // deployment values skip when absent, which keeps a production node's
    // `/health` reading exactly as it did before they existed.
    let mut body = serde_json::to_value(crate::http::compat::PeerBuild::own(facts))
        .unwrap_or_else(|_| serde_json::json!({}));
    body["status"] = serde_json::json!("ok");
    if let Some((epoch, attempt)) = published {
        body["dkg_epoch"] = serde_json::json!(epoch);
        body["dkg_attempt"] = serde_json::json!(attempt);
    }
    Json(body)
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
    round: RoundKey,
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
    serve_dkg(state, epoch, threshold, attempt, RoundKey::Round1, file).await
}

async fn get_dkg2(
    State(state): State<SharedState>,
    Path((epoch, threshold, attempt, file)): Path<(u64, u64, u64, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_dkg(state, epoch, threshold, attempt, RoundKey::Round2, file).await
}

/// Serve one signing-round blob. Like the DKG routes, the `<pool_id>.json`
/// segment must name THIS server — it only ever holds its own payloads, so any
/// other pool_id is a 404 rather than someone else's bytes under the wrong name.
async fn serve_sign(
    state: SharedState,
    round: RoundKey,
    epoch: u64,
    sequence: u64,
    session: u32,
    file: String,
) -> Result<impl IntoResponse, StatusCode> {
    let s = state.read().await;
    check_pool_id(&file, &s.own_pool_id_hex)?;
    let body = s
        .sign
        .get(&(epoch, sequence, session, round))
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body))
}

async fn get_sign1(
    State(state): State<SharedState>,
    Path((epoch, sequence, session, file)): Path<(u64, u64, u32, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_sign(state, RoundKey::Round1, epoch, sequence, session, file).await
}

async fn get_sign2(
    State(state): State<SharedState>,
    Path((epoch, sequence, session, file)): Path<(u64, u64, u32, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_sign(state, RoundKey::Round2, epoch, sequence, session, file).await
}
