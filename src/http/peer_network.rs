//! `PeerNetwork` adapter backed by real HTTP.
//!
//! Publishes write to this SPO's own `SharedState` (which its axum
//! server serves back to peers). Fetches call the individual peer's
//! endpoint directly via `reqwest`. The `fetch_*` methods here are
//! *single-shot* and return `Ok(None)` on 404 — the polling loop lives
//! in the `epoch::dkg`/`epoch::signing` phase code, not here.

use std::sync::Arc;

use async_trait::async_trait;
use frost_secp256k1_tr::Identifier;
use tokio::sync::RwLock;

use super::client::identifier_to_pool_id;
use super::payloads::{Dkg1Payload, Dkg2Payload, Sign1Payload, Sign2Payload};
use super::server::{AppState, SharedState};
use crate::epoch::state::{EpochError, EpochResult, SpoInfo};
use crate::epoch::traits::PeerNetwork;

/// HTTP-backed `PeerNetwork`. One instance per SPO.
pub struct HttpPeerNetwork {
    state: SharedState,
    client: reqwest::Client,
}

impl HttpPeerNetwork {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(AppState::default())),
            client: reqwest::Client::new(),
        }
    }

    /// Expose the shared state so the axum server can read from it.
    pub fn shared_state(&self) -> SharedState {
        self.state.clone()
    }
}

impl Default for HttpPeerNetwork {
    fn default() -> Self {
        Self::new()
    }
}

fn peer_err(e: impl std::fmt::Display) -> EpochError {
    EpochError::Peer(e.to_string())
}

#[async_trait]
impl PeerNetwork for HttpPeerNetwork {
    async fn publish_dkg_round1(&self, payload: Dkg1Payload) -> EpochResult<()> {
        let mut s = self.state.write().await;
        s.dkg1.insert(payload.epoch, payload);
        Ok(())
    }

    async fn publish_dkg_round2(&self, payload: Dkg2Payload) -> EpochResult<()> {
        let mut s = self.state.write().await;
        s.dkg2.insert(payload.epoch, payload);
        Ok(())
    }

    async fn publish_sign_round1(&self, payload: Sign1Payload) -> EpochResult<()> {
        let key = (payload.epoch, payload.input_index);
        let mut s = self.state.write().await;
        s.sign1.insert(key, payload);
        Ok(())
    }

    async fn publish_sign_round2(&self, payload: Sign2Payload) -> EpochResult<()> {
        let key = (payload.epoch, payload.input_index);
        let mut s = self.state.write().await;
        s.sign2.insert(key, payload);
        Ok(())
    }

    async fn fetch_dkg_round1(
        &self,
        epoch: u64,
        peer: &SpoInfo,
    ) -> EpochResult<Option<Dkg1Payload>> {
        let pool_id = identifier_to_pool_id(peer.identifier);
        let url = format!("{}/dkg/{}/round1/{}", peer.bifrost_url, epoch, pool_id);
        fetch_optional::<Dkg1Payload>(&self.client, &url, "dkg1").await
    }

    async fn fetch_dkg_round2(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        _my_id: Identifier,
    ) -> EpochResult<Option<Dkg2Payload>> {
        let pool_id = identifier_to_pool_id(peer.identifier);
        let url = format!("{}/dkg/{}/round2/{}", peer.bifrost_url, epoch, pool_id);
        fetch_optional::<Dkg2Payload>(&self.client, &url, "dkg2").await
    }

    async fn fetch_sign_round1(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        input_index: u32,
    ) -> EpochResult<Option<Sign1Payload>> {
        let pool_id = identifier_to_pool_id(peer.identifier);
        let url = format!(
            "{}/sign/{}/round1/{}/{}",
            peer.bifrost_url, epoch, input_index, pool_id
        );
        fetch_optional::<Sign1Payload>(&self.client, &url, "sign1").await
    }

    async fn fetch_sign_round2(
        &self,
        epoch: u64,
        peer: &SpoInfo,
        input_index: u32,
    ) -> EpochResult<Option<Sign2Payload>> {
        let pool_id = identifier_to_pool_id(peer.identifier);
        let url = format!(
            "{}/sign/{}/round2/{}/{}",
            peer.bifrost_url, epoch, input_index, pool_id
        );
        fetch_optional::<Sign2Payload>(&self.client, &url, "sign2").await
    }
}

/// GET `url`, treating connection errors and 404s as "not yet
/// published" (`Ok(None)`) and everything else as a peer error.
async fn fetch_optional<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    what: &str,
) -> EpochResult<Option<T>> {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(peer_err(format!("{what} fetch status {}", resp.status())));
    }
    let payload = resp.json::<T>().await.map_err(peer_err)?;
    Ok(Some(payload))
}
