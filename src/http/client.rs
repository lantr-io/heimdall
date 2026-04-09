//! HTTP client used by one SPO to pull protocol payloads from peers.
//!
//! The protocol is pull-only: each SPO publishes to its own server and
//! peers poll. These helpers retry each peer until every peer in the
//! roster has responded or `timeout` is hit.

use std::collections::BTreeMap;
use std::time::Duration;

use frost_secp256k1_tr as frost;
use frost::Identifier;

use super::payloads::*;

/// Info about a peer SPO.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub identifier: Identifier,
    pub base_url: String,
}

/// Pool identifier in the URL space: the u16 the `Identifier` was
/// constructed from. FROST serializes to 32 big-endian bytes; the last
/// two recover the u16.
pub fn identifier_to_pool_id(id: Identifier) -> u16 {
    let bytes = id.serialize();
    let n = bytes.len();
    u16::from_be_bytes([bytes[n - 2], bytes[n - 1]])
}

/// HTTP client that polls peer SPO endpoints.
#[derive(Debug, Clone)]
pub struct PeerClient {
    client: reqwest::Client,
    peers: Vec<PeerInfo>,
}

impl PeerClient {
    pub fn new(peers: Vec<PeerInfo>) -> Self {
        Self {
            client: reqwest::Client::new(),
            peers,
        }
    }

    /// Poll all peers for DKG round 1 packages, retrying until all respond or timeout.
    pub async fn fetch_dkg1_packages(
        &self,
        epoch: u64,
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, frost::keys::dkg::round1::Package>, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut results = BTreeMap::new();

        while results.len() < self.peers.len() {
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timeout: got {}/{} DKG round 1 packages",
                    results.len(),
                    self.peers.len()
                ));
            }

            for peer in &self.peers {
                if results.contains_key(&peer.identifier) {
                    continue;
                }
                let url = format!(
                    "{}/dkg/{}/round1/{}",
                    peer.base_url,
                    epoch,
                    identifier_to_pool_id(peer.identifier)
                );
                if let Ok(resp) = self.client.get(&url).send().await {
                    if resp.status().is_success() {
                        if let Ok(payload) = resp.json::<Dkg1Payload>().await {
                            results.insert(payload.identifier, payload.package);
                        }
                    }
                }
            }

            if results.len() < self.peers.len() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(results)
    }

    /// Poll all peers for DKG round 2 packages addressed to us.
    pub async fn fetch_dkg2_packages(
        &self,
        epoch: u64,
        my_id: Identifier,
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, frost::keys::dkg::round2::Package>, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut results = BTreeMap::new();

        while results.len() < self.peers.len() {
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timeout: got {}/{} DKG round 2 packages",
                    results.len(),
                    self.peers.len()
                ));
            }

            for peer in &self.peers {
                if results.contains_key(&peer.identifier) {
                    continue;
                }
                let url = format!(
                    "{}/dkg/{}/round2/{}",
                    peer.base_url,
                    epoch,
                    identifier_to_pool_id(peer.identifier)
                );
                if let Ok(resp) = self.client.get(&url).send().await {
                    if resp.status().is_success() {
                        if let Ok(payload) = resp.json::<Dkg2Payload>().await {
                            // Extract only the package addressed to us
                            if let Some(pkg) = payload.packages.get(&my_id) {
                                results.insert(payload.identifier, pkg.clone());
                            }
                        }
                    }
                }
            }

            if results.len() < self.peers.len() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(results)
    }

    /// Poll all signing peers for round 1 commitments for a given TM input index.
    pub async fn fetch_sign1_commitments(
        &self,
        epoch: u64,
        input_index: u32,
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, frost::round1::SigningCommitments>, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut results = BTreeMap::new();

        while results.len() < self.peers.len() {
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timeout: got {}/{} signing round 1 commitments for input {input_index}",
                    results.len(),
                    self.peers.len()
                ));
            }

            for peer in &self.peers {
                if results.contains_key(&peer.identifier) {
                    continue;
                }
                let url = format!(
                    "{}/sign/{}/round1/{}/{}",
                    peer.base_url,
                    epoch,
                    input_index,
                    identifier_to_pool_id(peer.identifier)
                );
                if let Ok(resp) = self.client.get(&url).send().await {
                    if resp.status().is_success() {
                        if let Ok(payload) = resp.json::<Sign1Payload>().await {
                            results.insert(payload.identifier, payload.commitments);
                        }
                    }
                }
            }

            if results.len() < self.peers.len() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(results)
    }

    /// Poll all signing peers for round 2 signature shares for a given TM input index.
    pub async fn fetch_sign2_shares(
        &self,
        epoch: u64,
        input_index: u32,
        timeout: Duration,
    ) -> Result<BTreeMap<Identifier, frost::round2::SignatureShare>, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut results = BTreeMap::new();

        while results.len() < self.peers.len() {
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timeout: got {}/{} signing round 2 shares for input {input_index}",
                    results.len(),
                    self.peers.len()
                ));
            }

            for peer in &self.peers {
                if results.contains_key(&peer.identifier) {
                    continue;
                }
                let url = format!(
                    "{}/sign/{}/round2/{}/{}",
                    peer.base_url,
                    epoch,
                    input_index,
                    identifier_to_pool_id(peer.identifier)
                );
                if let Ok(resp) = self.client.get(&url).send().await {
                    if resp.status().is_success() {
                        if let Ok(payload) = resp.json::<Sign2Payload>().await {
                            results.insert(payload.identifier, payload.share);
                        }
                    }
                }
            }

            if results.len() < self.peers.len() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_to_pool_id_roundtrip() {
        for v in [1u16, 2, 3, 42, 1000, 65535] {
            let id = Identifier::try_from(v).unwrap();
            assert_eq!(identifier_to_pool_id(id), v);
        }
    }
}
