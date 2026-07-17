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

use async_trait::async_trait;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::{All, Keypair, Secp256k1};
use frost_secp256k1_tr::keys::dkg::{round1, round2};
use tokio::sync::RwLock;

use super::canonical::POOL_ID_LEN;
use super::client::identifier_to_pool_id;
use super::payloads::{Sign1Payload, Sign2Payload};
use super::server::{AppState, DkgRoundKey, SharedState};
use super::wire::{self, Dkg1Wire, Dkg2Wire, DkgNamespace, Round2Recipient};
use crate::epoch::state::{EpochError, EpochResult, SpoInfo};
use crate::epoch::traits::PeerNetwork;

/// Key under which a fetched peer payload's raw bytes are retained for
/// equivocation evidence: a re-fetch returning *different* bytes for the
/// same key is itself the proof of a double-publish.
type EvidenceKey = (u64, u64, u64, DkgRoundKey, Vec<u8>);

/// HTTP-backed `PeerNetwork`. One instance per SPO; holds this SPO's
/// bifrost identity keypair (to sign publishes / decrypt shares) and its
/// own `pool_id` (the path it serves under).
pub struct HttpPeerNetwork {
    state: SharedState,
    client: reqwest::Client,
    secp: Secp256k1<All>,
    keypair: Keypair,
    my_pool_id: [u8; POOL_ID_LEN],
    evidence: Arc<Mutex<BTreeMap<EvidenceKey, Vec<u8>>>>,
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
        match ev.get(&key) {
            Some(prev) if prev.as_slice() != bytes => {
                eprintln!(
                    "EQUIVOCATION: peer {} published two distinct payloads for \
                     (epoch={}, threshold={}, attempt={}, round={:?})",
                    hex::encode(peer_pool_id),
                    key.0,
                    key.1,
                    key.2,
                    key.3
                );
            }
            Some(_) => {}
            None => {
                ev.insert(key, bytes.to_vec());
            }
        }
    }
}

fn peer_err(e: impl std::fmt::Display) -> EpochError {
    EpochError::Peer(e.to_string())
}

fn pool_id_arr(pool_id: &[u8]) -> EpochResult<[u8; POOL_ID_LEN]> {
    wire::pool_id_array(pool_id).map_err(peer_err)
}

#[async_trait]
impl PeerNetwork for HttpPeerNetwork {
    async fn publish_dkg_round1(
        &self,
        ns: DkgNamespace,
        identifier: frost_secp256k1_tr::Identifier,
        package: &round1::Package,
    ) -> EpochResult<()> {
        let wire = wire::build_round1(
            &self.secp,
            &self.keypair,
            ns.epoch,
            ns.threshold,
            ns.attempt,
            &self.my_pool_id,
            identifier_to_pool_id(identifier),
            package,
        )
        .map_err(peer_err)?;
        let json = serde_json::to_string(&wire).map_err(peer_err)?;
        let mut s = self.state.write().await;
        s.dkg.insert(
            (ns.epoch, ns.threshold, ns.attempt, DkgRoundKey::Round1),
            json,
        );
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
