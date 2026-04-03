use std::sync::Arc;
use std::time::Duration;

use frost_secp256k1_tr as frost;
use frost::Identifier;
use tokio::sync::RwLock;

use crate::frost::participant;
use crate::http::client::{PeerClient, PeerInfo};
use crate::http::payloads::*;
use crate::http::server::{AppState, SharedState, router};

/// Drives one SPO through the full FROST protocol over HTTP.
pub struct SpoOrchestrator {
    pub identifier: Identifier,
    pub state: SharedState,
    pub peer_client: PeerClient,
    pub port: u16,
    // DKG state
    key_package: Option<frost::keys::KeyPackage>,
    pubkey_package: Option<frost::keys::PublicKeyPackage>,
}

impl SpoOrchestrator {
    pub fn new(
        identifier: Identifier,
        port: u16,
        peers: Vec<PeerInfo>,
    ) -> Self {
        let state: SharedState = Arc::new(RwLock::new(AppState::default()));
        Self {
            identifier,
            state,
            peer_client: PeerClient::new(peers),
            port,
            key_package: None,
            pubkey_package: None,
        }
    }

    /// Start the HTTP server. Returns the JoinHandle.
    pub async fn start_server(&self) -> tokio::task::JoinHandle<()> {
        let app = router(self.state.clone());
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", self.port))
            .await
            .expect("failed to bind");
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        })
    }

    /// Run the full DKG protocol.
    pub async fn run_dkg(
        &mut self,
        min_signers: u16,
        max_signers: u16,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut rng = rand::rngs::OsRng;

        // Round 1: generate our package and publish it
        let (round1_secret, round1_package) =
            participant::dkg_part1(self.identifier, max_signers, min_signers, &mut rng)
                .map_err(|e| format!("DKG part1 failed: {e}"))?;

        {
            let mut s = self.state.write().await;
            s.dkg1 = Some(Dkg1Payload {
                epoch: 0,
                identifier: self.identifier,
                package: round1_package.clone(),
            });
        }

        // Fetch peers' round 1 packages
        let peer_round1 = self.peer_client.fetch_dkg1_packages(timeout).await?;

        // Round 2: generate shares for each peer
        let (round2_secret, round2_packages) =
            participant::dkg_part2(round1_secret, &peer_round1)
                .map_err(|e| format!("DKG part2 failed: {e}"))?;

        {
            let mut s = self.state.write().await;
            s.dkg2 = Some(Dkg2Payload {
                epoch: 0,
                identifier: self.identifier,
                packages: round2_packages,
            });
        }

        // Fetch peers' round 2 packages (only those addressed to us)
        let peer_round2 = self
            .peer_client
            .fetch_dkg2_packages(self.identifier, timeout)
            .await?;

        // Round 3: derive key package
        let (key_package, pubkey_package) =
            participant::dkg_part3(&round2_secret, &peer_round1, &peer_round2)
                .map_err(|e| format!("DKG part3 failed: {e}"))?;

        self.key_package = Some(key_package);
        self.pubkey_package = Some(pubkey_package);

        Ok(())
    }

    /// Get the group public key (after DKG).
    pub fn group_public_key(&self) -> Option<frost::VerifyingKey> {
        self.pubkey_package.as_ref().map(|p| *p.verifying_key())
    }

    /// Run the signing protocol for a message. All orchestrators in `signers` must participate.
    pub async fn run_signing(
        &mut self,
        message: &[u8],
        timeout: Duration,
    ) -> Result<frost::Signature, String> {
        let key_package = self
            .key_package
            .as_ref()
            .ok_or("DKG not completed")?;
        let pubkey_package = self
            .pubkey_package
            .as_ref()
            .ok_or("DKG not completed")?;

        let mut rng = rand::rngs::OsRng;

        // Round 1: generate nonces and publish commitments
        let (nonces, commitments) = participant::sign_round1(key_package, &mut rng);
        {
            let mut s = self.state.write().await;
            s.sign1 = Some(Sign1Payload {
                epoch: 0,
                identifier: self.identifier,
                commitments,
            });
        }

        // Fetch peers' commitments
        let peer_commitments = self.peer_client.fetch_sign1_commitments(timeout).await?;

        // Build signing package with all commitments (ours + peers')
        let mut all_commitments = peer_commitments;
        all_commitments.insert(self.identifier, commitments);
        let signing_package = frost::SigningPackage::new(all_commitments, message);

        // Round 2: compute our signature share and publish
        let share = participant::sign_round2(&signing_package, &nonces, key_package)
            .map_err(|e| format!("sign round2 failed: {e}"))?;
        {
            let mut s = self.state.write().await;
            s.sign2 = Some(Sign2Payload {
                epoch: 0,
                identifier: self.identifier,
                share: share.clone(),
            });
        }

        // Fetch peers' shares
        let peer_shares = self.peer_client.fetch_sign2_shares(timeout).await?;

        // Aggregate
        let mut all_shares = peer_shares;
        all_shares.insert(self.identifier, share);
        let signature = participant::sign_aggregate(&signing_package, &all_shares, pubkey_package)
            .map_err(|e| format!("aggregate failed: {e}"))?;

        Ok(signature)
    }
}
