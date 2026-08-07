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

use crate::cardano::spi_trie::{self, Outpoint, SpiTrie};

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
    /// Published signing payload JSON, keyed by `(epoch, session, round)` — one
    /// FROST session per TM input, plus the reserved rotation session. Folds the
    /// round into the key exactly as `dkg` above does, so serving needs no
    /// branch. Stored as the pre-signed JSON string for the same reason DKG
    /// payloads are: the publisher signs canonical bytes, and the server must
    /// hand back exactly what was signed, not a re-serialization of it.
    pub sign: BTreeMap<(u64, u32, RoundKey), String>,
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
        .route("/sign/{epoch}/round1/{session}/{file}", get(get_sign1))
        .route("/sign/{epoch}/round2/{session}/{file}", get(get_sign2))
        .route("/spi/proof/{peg_in_utxo_id}", get(get_spi_proof))
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
    session: u32,
    file: String,
) -> Result<impl IntoResponse, StatusCode> {
    let s = state.read().await;
    check_pool_id(&file, &s.own_pool_id_hex)?;
    let body = s
        .sign
        .get(&(epoch, session, round))
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body))
}

async fn get_sign1(
    State(state): State<SharedState>,
    Path((epoch, session, file)): Path<(u64, u32, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_sign(state, RoundKey::Round1, epoch, session, file).await
}

async fn get_sign2(
    State(state): State<SharedState>,
    Path((epoch, session, file)): Path<(u64, u32, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    serve_sign(state, RoundKey::Round2, epoch, session, file).await
}

/// [SPI-4]: serve a swept peg-ins membership (or non-membership) proof for a
/// 36-byte `peg_in_utxo_id`, hex-encoded in the path. Unauthenticated, like
/// every other route here. Wire shape: DecisionsLog.md DEC-023.
///
/// The trie is loaded from `state_dir` per request (the CpoTrie idiom – compare
/// `verify_cpo_root` / `advance_cpo_trie`), so the response reflects whatever
/// the last confirmed TM persisted. An ABSENT file is the genesis state (empty
/// trie, nothing swept yet) and answers honestly; an ABSENT `state_dir` means
/// this node keeps no trie at all, so it must not answer – 503, because an
/// exclusion proof against a trie nothing maintains would present "was never
/// swept" as authoritative.
///
/// A path segment that is not exactly 36 bytes of hex is a 400 — it cannot
/// name a peg-in outpoint, so "not a member" would be misleading.
async fn get_spi_proof(
    State(state): State<SharedState>,
    Path(peg_in_utxo_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let key: Outpoint = hex::decode(&peg_in_utxo_id)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let dir = state
        .read()
        .await
        .state_dir
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let trie = SpiTrie::load(&dir)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or_default();
    // The recorded value is present exactly when the outpoint is a member, so
    // it decides both `member` and which of the two proofs to serve.
    let value = trie.get(&key).map(hex::encode);
    let proof = match value {
        Some(_) => trie.prove_membership(&key),
        None => trie.prove_non_membership(&key),
    }
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut body = serde_json::json!({
        "member": value.is_some(),
        "peg_in_utxo_id": hex::encode(key),
        "root": hex::encode(trie.root()),
        "proof": spi_trie::proof_to_json(&proof),
    });
    if let Some(value) = value {
        body["value"] = serde_json::Value::String(value);
    }
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::mpf;
    use crate::cardano::spi_trie::SpiTrie;

    /// A 36-byte outpoint: txid internal order (32 bytes of `b`) ++ vout LE.
    fn op(b: u8, vout: u32) -> [u8; 36] {
        let mut o = [b; 36];
        o[32..].copy_from_slice(&vout.to_le_bytes());
        o
    }

    /// Spawn the router on a random port, return the base URL.
    async fn spawn(state: SharedState) -> String {
        let app = router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// Decode the wire proof back into an [`mpf::Proof`].
    ///
    /// Wire shape (see DecisionsLog.md): `proof` is an array of steps, one
    /// object per step, all byte fields hex-encoded:
    /// - `{"type":"branch","skip":n,"neighbors":"<hex, 128 bytes>"}`
    /// - `{"type":"fork","skip":n,"neighbor":{"nibble":n,"prefix":"<hex>","root":"<hex>"}}`
    /// - `{"type":"leaf","skip":n,"key":"<hex>","value":"<hex>"}`
    fn proof_from_json(v: &serde_json::Value) -> mpf::Proof {
        v.as_array()
            .expect("proof is a JSON array")
            .iter()
            .map(|s| {
                let skip = s["skip"].as_u64().expect("skip") as usize;
                match s["type"].as_str().expect("step type") {
                    "branch" => mpf::ProofStep::Branch {
                        skip,
                        neighbors: hex::decode(s["neighbors"].as_str().expect("neighbors"))
                            .expect("neighbors hex"),
                    },
                    "fork" => mpf::ProofStep::Fork {
                        skip,
                        neighbor: mpf::Neighbor {
                            nibble: s["neighbor"]["nibble"].as_u64().expect("nibble") as u8,
                            prefix: hex::decode(s["neighbor"]["prefix"].as_str().expect("prefix"))
                                .expect("prefix hex"),
                            root: hex::decode(s["neighbor"]["root"].as_str().expect("root"))
                                .expect("root hex"),
                        },
                    },
                    "leaf" => mpf::ProofStep::Leaf {
                        skip,
                        key: hex::decode(s["key"].as_str().expect("key")).expect("key hex"),
                        value: hex::decode(s["value"].as_str().expect("value")).expect("value hex"),
                    },
                    other => panic!("unknown proof step type {other:?}"),
                }
            })
            .collect()
    }

    // [SPI-4]: an unauthenticated GET serves a swept peg-ins membership (and
    // non-membership) proof for a given peg_in_utxo_id, verifiable against the
    // trie root via mpf::verify_inclusion / mpf::verify_exclusion.
    //
    // The proofs come from the trie PERSISTED in `state_dir` – the same file the
    // epoch machine advances on every confirmed TM – loaded at the point of use
    // (the CpoTrie idiom), never from an in-memory snapshot that nothing updates.
    #[tokio::test]
    async fn spi_proof_route_serves_a_verifiable_proof() {
        let dir = std::env::temp_dir().join(format!("spi-route-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let t = op(0xaa, 0); // the sweeping TM's input-0 outpoint
        let a = op(0x01, 0); // a swept deposit
        let b = op(0x02, 3); // another swept deposit
        let mut spi = SpiTrie::empty();
        spi.insert_for_confirmed_tm(&[t, a, b]).unwrap();
        let root = spi.root();
        spi.save(&dir).unwrap();

        let state: SharedState = Arc::new(RwLock::new(AppState {
            state_dir: Some(dir.clone()),
            ..AppState::default()
        }));
        let base = spawn(state).await;

        // Membership: the response carries the root, the value (the sweeping
        // TM's input-0 outpoint), and a proof that verifies via
        // mpf::verify_inclusion.
        let resp = reqwest::get(format!("{base}/spi/proof/{}", hex::encode(a)))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["member"], serde_json::json!(true));
        assert_eq!(body["peg_in_utxo_id"].as_str().unwrap(), hex::encode(a));
        assert_eq!(body["root"].as_str().unwrap(), hex::encode(root));
        assert_eq!(body["value"].as_str().unwrap(), hex::encode(t));
        let proof = proof_from_json(&body["proof"]);
        mpf::verify_inclusion(&a, &t, &proof, &root)
            .expect("served membership proof verifies against the trie root");

        // Non-membership: an unswept outpoint gets member=false and an
        // exclusion proof that verifies via mpf::verify_exclusion.
        let absent = op(0x7f, 9);
        let resp = reqwest::get(format!("{base}/spi/proof/{}", hex::encode(absent)))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["member"], serde_json::json!(false));
        assert_eq!(body["root"].as_str().unwrap(), hex::encode(root));
        let proof = proof_from_json(&body["proof"]);
        mpf::verify_exclusion(&absent, &proof, &root)
            .expect("served non-membership proof verifies against the trie root");

        // A peg_in_utxo_id that is not 36 bytes of hex is a client error, not
        // a proof.
        let resp = reqwest::get(format!("{base}/spi/proof/zz")).await.unwrap();
        assert_eq!(resp.status(), 400);

        // The route serves the CURRENT persisted trie, not a boot-time snapshot:
        // after another confirmed TM advances the file on disk, the same route
        // answers with the NEW root and a proof for the new entry.
        let c = op(0x03, 1);
        let t2 = op(0xbb, 0);
        let mut spi2 = SpiTrie::load(&dir).unwrap().expect("persisted trie");
        spi2.insert_for_confirmed_tm(&[t2, c]).unwrap();
        spi2.save(&dir).unwrap();
        let resp = reqwest::get(format!("{base}/spi/proof/{}", hex::encode(c)))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["member"], serde_json::json!(true));
        assert_eq!(body["root"].as_str().unwrap(), hex::encode(spi2.root()));
        let proof = proof_from_json(&body["proof"]);
        mpf::verify_inclusion(&c, &t2, &proof, &spi2.root())
            .expect("proof for an entry persisted after boot verifies");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // A node with no `state_dir` keeps no swept peg-ins trie, so it must not
    // answer proof queries at all: an exclusion proof against a trie the node
    // never maintains would present "was never swept" as authoritative.
    #[tokio::test]
    async fn spi_proof_route_without_state_dir_is_unavailable() {
        let state: SharedState = Arc::new(RwLock::new(AppState::default()));
        let base = spawn(state).await;
        let resp = reqwest::get(format!("{base}/spi/proof/{}", hex::encode(op(0x01, 0))))
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
    }
}
