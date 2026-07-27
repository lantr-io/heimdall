//! `PeerNetwork` adapter backed by real HTTP — the production wire.
//!
//! This adapter owns the spec wire format end to end. On publish it
//! builds + BIP-340-signs the payload (and ECDH-encrypts Round 2 shares)
//! and stores the JSON for its own server to serve. On fetch it retrieves
//! a peer's JSON, **retains the raw bytes** (equivocation evidence), then
//! verifies the BIP-340 signature against the expected peer's
//! `bifrost_id_pk` over the reconstructed canonical bytes before handing
//! back a FROST package — so the epoch driver only ever sees authenticated
//! material and never touches identity keys.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{All, Keypair, Secp256k1};
use frost_secp256k1_tr::keys::dkg::{round1, round2};
use tokio::sync::RwLock;

use super::canonical::POOL_ID_LEN;
use super::client::identifier_to_pool_id;
use super::payloads::{Sign1Payload, Sign2Payload};
use super::server::{AppState, DkgRoundKey, SharedState};
use super::wire::{self, ChainViewWire, Dkg1Wire, Dkg2Wire, DkgNamespace, Round2Recipient};
use crate::cardano::dkg_roster::ChainView;
use crate::epoch::state::{EpochError, EpochResult, SpoInfo};
use crate::epoch::traits::{DkgFaultEvidence, PeerNetwork};

/// Wall-clock bound past which a persistent chain-view disagreement with one
/// peer is flagged (the reconcile design's "impossible-case" tripwire). Under
/// honest-majority + chain liveness two honest nodes reading one canonical
/// chain always reconcile once the disagreeing event settles, so this must stay
/// silent. Set clear of even the pre-reconcile churn (which recovered in ~1–2
/// bench epochs ≈ 360 s) so only genuine permanent divergence trips it, never a
/// merely-slow-but-converging recovery — the recovery-*time* win is measured
/// separately, by when the reduced DKG completes.
const DIVERGENCE_ALARM: Duration = Duration::from_secs(300);

/// This node's chain-view plus the reconcile / divergence bookkeeping the fetch
/// path maintains against it. Behind a plain mutex: every access is a short
/// critical section with no `.await` held across the lock.
#[derive(Debug, Default)]
struct ViewState {
    /// This node's view for the current ceremony, set at each ceremony entry.
    own: Option<ChainView>,
    /// Set when a fetched peer's view differed AND its blockchain read-time was
    /// NEWER (this node is the stale side). Read by the epoch loop to pick a
    /// settling backoff; reset at the next `set_chain_view`.
    stale: bool,
    /// Per-peer `pool_id` → the instant a still-unresolved view disagreement was
    /// first observed: the divergence tripwire's clock. Cleared when the peer's
    /// view matches ours again; NOT reset by `set_chain_view`, since one
    /// disagreement can span several attempts.
    divergence_since: BTreeMap<Vec<u8>, Instant>,
}

/// Key under which a fetched peer payload's raw bytes are retained for
/// equivocation evidence: a re-fetch returning *different* bytes for the
/// same key is itself the proof of a double-publish.
type EvidenceKey = (u64, u64, u64, DkgRoundKey, Vec<u8>);

#[derive(Debug, Clone)]
struct RetainedDkgPayloads {
    first: Vec<u8>,
    conflicts: Vec<Vec<u8>>,
}

impl RetainedDkgPayloads {
    fn distinct_payloads(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + self.conflicts.len());
        out.push(self.first.clone());
        for payload in &self.conflicts {
            if !out.iter().any(|seen| seen == payload) {
                out.push(payload.clone());
            }
        }
        out
    }
}

/// HTTP-backed `PeerNetwork`. One instance per SPO; holds this SPO's
/// bifrost identity keypair (to sign publishes / decrypt shares) and its
/// own `pool_id` (the path it serves under).
pub struct HttpPeerNetwork {
    state: SharedState,
    client: reqwest::Client,
    secp: Secp256k1<All>,
    keypair: Keypair,
    my_pool_id: [u8; POOL_ID_LEN],
    evidence: Arc<Mutex<BTreeMap<EvidenceKey, RetainedDkgPayloads>>>,
    views: Arc<Mutex<ViewState>>,
}

impl HttpPeerNetwork {
    pub fn new(secp: Secp256k1<All>, keypair: Keypair, my_pool_id: [u8; POOL_ID_LEN]) -> Self {
        let state = AppState {
            own_pool_id_hex: hex::encode(my_pool_id),
            ..AppState::default()
        };
        Self {
            state: Arc::new(RwLock::new(state)),
            client: reqwest::Client::new(),
            secp,
            keypair,
            my_pool_id,
            evidence: Arc::new(Mutex::new(BTreeMap::new())),
            views: Arc::new(Mutex::new(ViewState::default())),
        }
    }

    /// Compare a fetched peer's chain-view against our own (the reconcile
    /// design's detect step). Called on every Round-1 fetch, independent of
    /// whether the payload itself verifies — a cross-view peer's package is
    /// dropped downstream by the commitment-count filter, but the *view* is what
    /// tells us WHY, and who should re-read.
    ///
    /// Records three things: (a) a one-line diagnosis at the start of each
    /// disagreement episode, replacing the opaque `poseidon_commit mismatch` as
    /// the first thing a log shows; (b) `stale = true` iff our blockchain
    /// read-time is older than the peer's, so the epoch loop settles+re-reads
    /// rather than blind-retrying; (c) the per-peer divergence timer that trips
    /// [`DIVERGENCE_ALARM`] if a pair never reconciles. A view is only ever a
    /// hint here — nothing adopts the peer's value; the chain stays the truth.
    fn compare_view(&self, peer_pool_id: &[u8], peer_view: Option<&ChainViewWire>) {
        let mut v = self.views.lock().expect("views mutex");
        let Some(own) = v.own else {
            return; // no own view yet (mock / pre-entry) → nothing to compare
        };
        let peer = match peer_view.map(ChainViewWire::to_view) {
            Some(Ok(p)) => p,
            // Peer published no view (mock / older payload) or a malformed one:
            // can't compare → treat as "not disagreeing" and clear any timer.
            _ => {
                v.divergence_since.remove(peer_pool_id);
                return;
            }
        };
        if peer.digest == own.digest {
            if v.divergence_since.remove(peer_pool_id).is_some() {
                eprintln!(
                    "[chain-view] peer {} reconciled to our view (n={})",
                    hex::encode(peer_pool_id),
                    own.n
                );
            }
            return;
        }

        // Genuine cross-view disagreement.
        let older = own.read_time_ms < peer.read_time_ms;
        if !v.divergence_since.contains_key(peer_pool_id) {
            eprintln!(
                "[chain-view] disagreement with peer {}: mine=(n={} digest={} read_time_ms={}) \
                 theirs=(n={} digest={} read_time_ms={}) — we are the {} side",
                hex::encode(peer_pool_id),
                own.n,
                hex::encode(&own.digest[..4]),
                own.read_time_ms,
                peer.n,
                hex::encode(&peer.digest[..4]),
                peer.read_time_ms,
                if older {
                    "STALE (will re-read after settling)"
                } else {
                    "fresher (the peer re-reads)"
                },
            );
            v.divergence_since
                .insert(peer_pool_id.to_vec(), Instant::now());
        } else if let Some(since) = v.divergence_since.get(peer_pool_id) {
            let elapsed = since.elapsed();
            if elapsed >= DIVERGENCE_ALARM {
                eprintln!(
                    "DIVERGENCE: peer {} differs for >{}s — two honest nodes on one chain must \
                     reconcile once the event settles; this tripwire should never fire",
                    hex::encode(peer_pool_id),
                    elapsed.as_secs(),
                );
            }
        }
        // Directional: only the stale side re-reads. Set every disagreeing poll
        // (not just the first), because `set_chain_view` clears it each attempt
        // and the epoch loop wants the latest attempt's verdict.
        if older {
            v.stale = true;
        }
    }

    /// Expose the shared state so the axum server can read from it.
    pub fn shared_state(&self) -> SharedState {
        self.state.clone()
    }

    /// Retain the raw bytes of a fetched payload. If the same namespace
    /// key already has *different* bytes, that is equivocation — flagged
    /// here; the first-seen bytes are kept (the conflict is the evidence).
    fn retain_evidence(&self, key: EvidenceKey, bytes: &[u8], peer_pool_id: &[u8]) {
        let mut ev = self.evidence.lock().expect("evidence mutex");
        match ev.get_mut(&key) {
            Some(prev) if prev.first.as_slice() != bytes => {
                eprintln!(
                    "EQUIVOCATION: peer {} published two distinct payloads for \
                     (epoch={}, threshold={}, attempt={}, round={:?})",
                    hex::encode(peer_pool_id),
                    key.0,
                    key.1,
                    key.2,
                    key.3
                );
                if !prev
                    .conflicts
                    .iter()
                    .any(|stored| stored.as_slice() == bytes)
                {
                    prev.conflicts.push(bytes.to_vec());
                }
            }
            Some(_) => {}
            None => {
                ev.insert(
                    key,
                    RetainedDkgPayloads {
                        first: bytes.to_vec(),
                        conflicts: Vec::new(),
                    },
                );
            }
        }
    }

    fn retained_payloads(
        &self,
        ns: DkgNamespace,
        round: DkgRoundKey,
        peer_pool_id: &[u8],
    ) -> Vec<Vec<u8>> {
        let key = (
            ns.epoch,
            ns.threshold,
            ns.attempt,
            round,
            peer_pool_id.to_vec(),
        );
        self.evidence
            .lock()
            .expect("evidence mutex")
            .get(&key)
            .map(RetainedDkgPayloads::distinct_payloads)
            .unwrap_or_default()
    }
}

fn peer_err(e: impl std::fmt::Display) -> EpochError {
    EpochError::Peer(e.to_string())
}

fn pool_id_arr(pool_id: &[u8]) -> EpochResult<[u8; POOL_ID_LEN]> {
    wire::pool_id_array(pool_id).map_err(peer_err)
}

fn push_round1_faults_from_payloads(
    out: &mut Vec<DkgFaultEvidence>,
    ns: DkgNamespace,
    peer: &SpoInfo,
    peer_pool: &[u8; POOL_ID_LEN],
    payloads: &[Vec<u8>],
) {
    for bytes in payloads {
        let Ok(wire) = serde_json::from_slice::<Dkg1Wire>(bytes) else {
            continue;
        };
        let Ok(evidence) = wire::round1_fault_evidence(
            peer_pool,
            &peer.bifrost_id_pk,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            super::client::identifier_to_pool_id(peer.identifier),
            &wire,
        ) else {
            continue;
        };
        if matches!(evidence.is_fault(), Ok(true)) {
            out.push(DkgFaultEvidence::Round1InvalidPayload(evidence));
        }
    }
}

fn push_round2_faults_from_payloads(
    net: &HttpPeerNetwork,
    out: &mut Vec<DkgFaultEvidence>,
    ns: DkgNamespace,
    peer: &SpoInfo,
    peer_pool: &[u8; POOL_ID_LEN],
    recipient_identifier: frost_secp256k1_tr::Identifier,
    sender_commitments: &[[u8; crate::http::canonical::POINT_LEN]],
    payloads: &[Vec<u8>],
) {
    let round1_signed_payload = net
        .retained_payloads(ns, DkgRoundKey::Round1, &peer.pool_id)
        .into_iter()
        .find_map(|bytes| {
            let wire = serde_json::from_slice::<Dkg1Wire>(&bytes).ok()?;
            wire::round1_signed_payload(
                peer_pool,
                &peer.bifrost_id_pk,
                ns.epoch,
                ns.threshold,
                ns.attempt,
                &wire,
            )
            .ok()
        });
    for bytes in payloads {
        let Ok(wire) = serde_json::from_slice::<Dkg2Wire>(bytes) else {
            continue;
        };
        let round1_signed_payload = round1_signed_payload
            .as_ref()
            .map(|(payload, signature)| (payload.as_slice(), signature));
        let Ok(evidence) = wire::round2_fault_evidence(
            &net.secp,
            peer_pool,
            &peer.bifrost_id_pk,
            &net.my_pool_id,
            super::client::identifier_to_pool_id(recipient_identifier),
            &net.keypair.secret_key(),
            sender_commitments,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            round1_signed_payload,
            &wire,
        ) else {
            continue;
        };
        if matches!(evidence.is_fault(), Ok(true)) {
            out.push(DkgFaultEvidence::Round2InvalidPayload(evidence));
        }
    }
}

fn push_round1_equivocations(
    out: &mut Vec<DkgFaultEvidence>,
    ns: DkgNamespace,
    peer: &SpoInfo,
    peer_pool: &[u8; POOL_ID_LEN],
    payloads: &[Vec<u8>],
) {
    let Some((first, rest)) = payloads.split_first() else {
        return;
    };
    let Ok(first_wire) = serde_json::from_slice::<Dkg1Wire>(first) else {
        return;
    };
    for bytes in rest {
        let Ok(other_wire) = serde_json::from_slice::<Dkg1Wire>(bytes) else {
            continue;
        };
        if let Ok(evidence) = wire::round1_equivocation_evidence(
            peer_pool,
            &peer.bifrost_id_pk,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            &first_wire,
            &other_wire,
        ) {
            out.push(DkgFaultEvidence::Equivocation(evidence));
        }
    }
}

fn push_round2_equivocations(
    net: &HttpPeerNetwork,
    out: &mut Vec<DkgFaultEvidence>,
    ns: DkgNamespace,
    peer: &SpoInfo,
    peer_pool: &[u8; POOL_ID_LEN],
    payloads: &[Vec<u8>],
) {
    let Some((first, rest)) = payloads.split_first() else {
        return;
    };
    let Ok(first_wire) = serde_json::from_slice::<Dkg2Wire>(first) else {
        return;
    };
    for bytes in rest {
        let Ok(other_wire) = serde_json::from_slice::<Dkg2Wire>(bytes) else {
            continue;
        };
        if let Ok(evidence) = wire::round2_equivocation_evidence(
            &net.secp,
            peer_pool,
            &peer.bifrost_id_pk,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            &first_wire,
            &other_wire,
        ) {
            out.push(DkgFaultEvidence::Equivocation(evidence));
        }
    }
}

/// Drop served DKG blobs that can no longer belong to a live ceremony: past
/// epochs, and same-epoch attempts more than ~2 grid windows behind the one
/// being published (N21). A stale round-1 package fetched into a later
/// ceremony poisons it — a late node would see a phantom participant and wait
/// a full round for shares that never come.
fn gc_dkg_blobs(
    dkg: &mut std::collections::BTreeMap<(u64, u64, u64, DkgRoundKey), String>,
    ns: DkgNamespace,
) {
    let keep_from = ns
        .attempt
        .saturating_sub(u64::from(2 * crate::epoch::state::DKG_ATTEMPTS_PER_WINDOW));
    dkg.retain(|k, _| k.0 >= ns.epoch && (k.0 > ns.epoch || k.2 >= keep_from));
}

#[async_trait]
impl PeerNetwork for HttpPeerNetwork {
    async fn check_health(&self, peer: &SpoInfo) -> bool {
        let url = format!("{}/health", peer.bifrost_url.trim_end_matches('/'));
        match self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    async fn set_chain_view(&self, view: ChainView) {
        let mut v = self.views.lock().expect("views mutex");
        v.own = Some(view);
        v.stale = false; // fresh ceremony entry → clear the per-attempt verdict
    }

    async fn is_view_stale(&self) -> bool {
        self.views.lock().expect("views mutex").stale
    }

    async fn publish_dkg_round1(
        &self,
        ns: DkgNamespace,
        identifier: frost_secp256k1_tr::Identifier,
        package: &round1::Package,
    ) -> EpochResult<()> {
        // Attach our own chain-view (UNSIGNED) so peers can detect a genuine
        // cross-view disagreement — `None` before the first `set_chain_view`.
        let own_view = self.views.lock().expect("views mutex").own;
        let wire = wire::build_round1(
            &self.secp,
            &self.keypair,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            &self.my_pool_id,
            identifier_to_pool_id(identifier),
            package,
            own_view.as_ref(),
        )
        .map_err(peer_err)?;
        let json = serde_json::to_string(&wire).map_err(peer_err)?;
        let mut s = self.state.write().await;
        s.dkg.insert(
            (ns.epoch, ns.threshold, ns.attempt, DkgRoundKey::Round1),
            json,
        );
        gc_dkg_blobs(&mut s.dkg, ns);
        Ok(())
    }

    async fn publish_dkg_round2(
        &self,
        ns: DkgNamespace,
        _sender_identifier: frost_secp256k1_tr::Identifier,
        sender_commitments: &[[u8; crate::http::canonical::POINT_LEN]],
        recipients: &[(SpoInfo, round2::Package)],
    ) -> EpochResult<()> {
        let mut recips: Vec<Round2Recipient> = Vec::with_capacity(recipients.len());
        for (info, pkg) in recipients {
            recips.push(Round2Recipient {
                pool_id: pool_id_arr(&info.pool_id)?,
                identifier: identifier_to_pool_id(info.identifier),
                bifrost_id_pk: &info.bifrost_id_pk,
                package: pkg,
            });
        }
        let wire = wire::build_round2(
            &self.secp,
            &self.keypair,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            &self.my_pool_id,
            sender_commitments,
            &recips,
            &mut OsRng,
        )
        .map_err(peer_err)?;
        let json = serde_json::to_string(&wire).map_err(peer_err)?;
        let mut s = self.state.write().await;
        s.dkg.insert(
            (ns.epoch, ns.threshold, ns.attempt, DkgRoundKey::Round2),
            json,
        );
        gc_dkg_blobs(&mut s.dkg, ns);
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
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Option<round1::Package>> {
        let pool_hex = hex::encode(&peer.pool_id);
        let url = format!(
            "{}/dkg/{}/{}/{}/round1/{}.json",
            peer.bifrost_url, ns.epoch, ns.threshold, ns.attempt, pool_hex
        );
        let Some(bytes) = fetch_raw(&self.client, &url).await? else {
            return Ok(None);
        };
        self.retain_evidence(
            (
                ns.epoch,
                ns.threshold,
                ns.attempt,
                DkgRoundKey::Round1,
                peer.pool_id.clone(),
            ),
            &bytes,
            &peer.pool_id,
        );
        let wire: Dkg1Wire = serde_json::from_slice(&bytes).map_err(peer_err)?;
        // Detect a genuine cross-view disagreement BEFORE verification: a
        // cross-view peer's package fails the downstream commitment-count filter
        // as "absent, not faulty", but its published view is what names the
        // disagreement and decides who re-reads.
        self.compare_view(&peer.pool_id, wire.view.as_ref());
        let peer_pool = pool_id_arr(&peer.pool_id)?;
        match wire::verify_round1(
            &self.secp,
            &peer_pool,
            &peer.bifrost_id_pk,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            identifier_to_pool_id(peer.identifier),
            &wire,
        ) {
            Ok(pkg) => Ok(Some(pkg)),
            Err(e) => {
                // Invalid payload: drop it (evidence already retained) and keep
                // polling — the deadline, not a single bad fetch, bounds liveness.
                eprintln!(
                    "dropping invalid round1 from {}: {e}",
                    hex::encode(&peer.pool_id)
                );
                Ok(None)
            }
        }
    }

    async fn fetch_dkg_round2(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
        recipient_identifier: frost_secp256k1_tr::Identifier,
        sender_commitments: &[[u8; crate::http::canonical::POINT_LEN]],
    ) -> EpochResult<Option<round2::Package>> {
        let pool_hex = hex::encode(&peer.pool_id);
        let url = format!(
            "{}/dkg/{}/{}/{}/round2/{}.json",
            peer.bifrost_url, ns.epoch, ns.threshold, ns.attempt, pool_hex
        );
        let Some(bytes) = fetch_raw(&self.client, &url).await? else {
            return Ok(None);
        };
        self.retain_evidence(
            (
                ns.epoch,
                ns.threshold,
                ns.attempt,
                DkgRoundKey::Round2,
                peer.pool_id.clone(),
            ),
            &bytes,
            &peer.pool_id,
        );
        let wire: Dkg2Wire = serde_json::from_slice(&bytes).map_err(peer_err)?;
        let peer_pool = pool_id_arr(&peer.pool_id)?;
        match wire::verify_round2(
            &self.secp,
            &peer_pool,
            &peer.bifrost_id_pk,
            &self.my_pool_id,
            identifier_to_pool_id(recipient_identifier),
            &self.keypair.secret_key(),
            sender_commitments,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            &wire,
        ) {
            Ok(pkg) => Ok(Some(pkg)),
            Err(e) => {
                eprintln!(
                    "dropping invalid round2 from {}: {e}",
                    hex::encode(&peer.pool_id)
                );
                Ok(None)
            }
        }
    }

    async fn dkg_round1_fault_evidence(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> EpochResult<Vec<DkgFaultEvidence>> {
        let peer_pool = pool_id_arr(&peer.pool_id)?;
        let payloads = self.retained_payloads(ns, DkgRoundKey::Round1, &peer.pool_id);
        let mut out = Vec::new();
        push_round1_faults_from_payloads(&mut out, ns, peer, &peer_pool, &payloads);
        push_round1_equivocations(&mut out, ns, peer, &peer_pool, &payloads);
        Ok(out)
    }

    async fn dkg_round2_fault_evidence(
        &self,
        ns: DkgNamespace,
        peer: &SpoInfo,
        recipient_identifier: frost_secp256k1_tr::Identifier,
        sender_commitments: &[[u8; crate::http::canonical::POINT_LEN]],
    ) -> EpochResult<Vec<DkgFaultEvidence>> {
        let peer_pool = pool_id_arr(&peer.pool_id)?;
        let payloads = self.retained_payloads(ns, DkgRoundKey::Round2, &peer.pool_id);
        let mut out = Vec::new();
        push_round2_faults_from_payloads(
            self,
            &mut out,
            ns,
            peer,
            &peer_pool,
            recipient_identifier,
            sender_commitments,
            &payloads,
        );
        push_round2_equivocations(self, &mut out, ns, peer, &peer_pool, &payloads);
        Ok(out)
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

/// GET `url`, returning the raw body bytes, or `None` on connection error
/// / 404 ("not published yet").
async fn fetch_raw(client: &reqwest::Client, url: &str) -> EpochResult<Option<Vec<u8>>> {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(peer_err(format!("fetch status {}", resp.status())));
    }
    Ok(Some(resp.bytes().await.map_err(peer_err)?.to_vec()))
}

/// GET `url`, JSON-decoding `T`; 404 / connection error → `Ok(None)`.
async fn fetch_optional<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    what: &str,
) -> EpochResult<Option<T>> {
    match fetch_raw(client, url).await? {
        None => Ok(None),
        Some(bytes) => {
            let v = serde_json::from_slice::<T>(&bytes)
                .map_err(|e| peer_err(format!("{what} decode: {e}")))?;
            Ok(Some(v))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use frost_secp256k1_tr::Identifier;
    use frost_secp256k1_tr::keys::dkg;

    fn id(n: u16) -> Identifier {
        Identifier::try_from(n).unwrap()
    }

    /// (keypair, pool_id[28], x-only bifrost_id_pk bytes)
    fn identity(secp: &Secp256k1<All>, pool_byte: u8) -> (Keypair, [u8; POOL_ID_LEN], Vec<u8>) {
        let (sk, _pk) = secp.generate_keypair(&mut OsRng);
        let kp = Keypair::from_secret_key(secp, &sk);
        let xonly = kp.x_only_public_key().0.serialize().to_vec();
        (kp, [pool_byte; POOL_ID_LEN], xonly)
    }

    async fn serve(net: &HttpPeerNetwork) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::http::server::router(net.shared_state());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn peer_info(id_n: u16, pool: &[u8; POOL_ID_LEN], url: &str, pk: &[u8]) -> SpoInfo {
        SpoInfo {
            identifier: id(id_n),
            pool_id: pool.to_vec(),
            bifrost_url: url.to_string(),
            bifrost_id_pk: pk.to_vec(),
        }
    }

    async fn fetch_r1_retrying(
        net: &HttpPeerNetwork,
        ns: DkgNamespace,
        peer: &SpoInfo,
    ) -> Option<round1::Package> {
        for _ in 0..50 {
            if let Some(p) = net.fetch_dkg_round1(ns, peer).await.unwrap() {
                return Some(p);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        None
    }

    #[tokio::test]
    async fn round1_over_http_signs_serves_fetches_verifies() {
        let secp = Secp256k1::new();
        let (kp1, pool1, pk1) = identity(&secp, 1);
        let (kp2, pool2, _pk2) = identity(&secp, 2);

        let net1 = HttpPeerNetwork::new(Secp256k1::new(), kp1, pool1);
        let net2 = HttpPeerNetwork::new(Secp256k1::new(), kp2, pool2);
        let url1 = serve(&net1).await;

        // net1 publishes its real Round 1 package (signed inside publish).
        let ns = DkgNamespace::new(7);
        let (_secret, pkg1) = dkg::part1(id(1), 3, 2, OsRng).unwrap();
        net1.publish_dkg_round1(ns, id(1), &pkg1).await.unwrap();

        // net2 fetches over real HTTP, verifying against net1's identity key.
        let peer1 = peer_info(1, &pool1, &url1, &pk1);
        let got = fetch_r1_retrying(&net2, ns, &peer1)
            .await
            .expect("verified package");
        assert_eq!(
            got, pkg1,
            "fetched+verified package must equal the published one"
        );

        // Wrong expected key → verification fails → None (kept polling).
        let (_kpx, _poolx, wrong_pk) = identity(&secp, 9);
        let peer1_wrongkey = peer_info(1, &pool1, &url1, &wrong_pk);
        assert!(
            net2.fetch_dkg_round1(ns, &peer1_wrongkey)
                .await
                .unwrap()
                .is_none(),
            "a payload signed by a different key must not verify"
        );

        // Wrong namespace → server 404 → None.
        assert!(
            net2.fetch_dkg_round1(DkgNamespace::new(8), &peer1)
                .await
                .unwrap()
                .is_none(),
            "a different epoch must not resolve"
        );
    }

    /// The reconcile design's directional property: on a chain-view
    /// disagreement, ONLY the node whose blockchain read-time is older flags
    /// itself stale (it read before the event settled), so only it re-reads —
    /// the fresher-read node does not. Verified through the real fetch path.
    #[tokio::test]
    async fn only_the_older_read_node_flags_itself_stale() {
        let secp = Secp256k1::new();
        let (kp1, pool1, pk1) = identity(&secp, 1);
        let (kp2, pool2, pk2) = identity(&secp, 2);
        let net1 = HttpPeerNetwork::new(Secp256k1::new(), kp1, pool1);
        let net2 = HttpPeerNetwork::new(Secp256k1::new(), kp2, pool2);
        let url1 = serve(&net1).await;
        let url2 = serve(&net2).await;
        let ns = DkgNamespace::new(7);

        // net1 read the chain EARLIER (older read_time) and still sees 4 members;
        // net2 read later and already sees the 3-member post-ban set. Distinct
        // candidate-set digests ⇒ a genuine cross-view disagreement.
        net1.set_chain_view(ChainView {
            digest: [0xA1; 32],
            n: 4,
            read_time_ms: 100,
        })
        .await;
        net2.set_chain_view(ChainView {
            digest: [0xB2; 32],
            n: 3,
            read_time_ms: 200,
        })
        .await;

        // Each publishes its Round-1 payload (carrying its own view), then fetches
        // the other's.
        let (_s1, pkg1) = dkg::part1(id(1), 3, 2, OsRng).unwrap();
        let (_s2, pkg2) = dkg::part1(id(2), 3, 2, OsRng).unwrap();
        net1.publish_dkg_round1(ns, id(1), &pkg1).await.unwrap();
        net2.publish_dkg_round1(ns, id(2), &pkg2).await.unwrap();

        let peer1 = peer_info(1, &pool1, &url1, &pk1);
        let peer2 = peer_info(2, &pool2, &url2, &pk2);
        let _ = fetch_r1_retrying(&net1, ns, &peer2).await; // net1 sees net2's fresher view
        let _ = fetch_r1_retrying(&net2, ns, &peer1).await; // net2 sees net1's staler view

        assert!(
            net1.is_view_stale().await,
            "the older-read node must flag itself as the stale side"
        );
        assert!(
            !net2.is_view_stale().await,
            "the fresher-read node must NOT re-read — it already saw the settled view"
        );

        // A fresh ceremony entry clears the per-attempt verdict.
        net1.set_chain_view(ChainView {
            digest: [0xB2; 32],
            n: 3,
            read_time_ms: 300,
        })
        .await;
        assert!(
            !net1.is_view_stale().await,
            "set_chain_view resets the stale flag for the new attempt"
        );
    }

    #[tokio::test]
    async fn round2_over_http_encrypts_serves_decrypts_verifies() {
        let secp = Secp256k1::new();
        let (kp1, pool1, pk1) = identity(&secp, 1);
        let (kp2, pool2, pk2) = identity(&secp, 2);
        let net1 = HttpPeerNetwork::new(Secp256k1::new(), kp1, pool1);
        let net2 = HttpPeerNetwork::new(Secp256k1::new(), kp2, pool2);
        let url1 = serve(&net1).await;
        let ns = DkgNamespace::new(7);

        // Real frost round2 package from sender 1 addressed to peer 2.
        let (s1, p1) = dkg::part1(id(1), 2, 2, OsRng).unwrap();
        let (_s2, p2) = dkg::part1(id(2), 2, 2, OsRng).unwrap();
        let (sender_commitments, _sigma_i) =
            crate::http::frost_bridge::round1_fields(&p1).expect("round1 fields");
        let mut r1 = std::collections::BTreeMap::new();
        r1.insert(id(2), p2);
        let (_s1r2, pkgs) = dkg::part2(s1, &r1).unwrap();
        let pkg_for_2 = pkgs.get(&id(2)).unwrap().clone();

        // net1 publishes the encrypted share addressed to net2's identity.
        let recip2 = peer_info(2, &pool2, "", &pk2);
        net1.publish_dkg_round2(
            ns,
            id(1),
            &sender_commitments,
            &[(recip2, pkg_for_2.clone())],
        )
        .await
        .unwrap();

        // net2 fetches, verifies net1's signature, decrypts its share.
        let peer1 = peer_info(1, &pool1, &url1, &pk1);
        let mut got = None;
        for _ in 0..50 {
            if let Some(p) = net2
                .fetch_dkg_round2(ns, &peer1, id(2), &sender_commitments)
                .await
                .unwrap()
            {
                got = Some(p);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(got.expect("decrypted share"), pkg_for_2);
    }
}
