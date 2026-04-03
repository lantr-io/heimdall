use std::time::Duration;

use frost_secp256k1_tr::Identifier;
use heimdall::demo::orchestrator::SpoOrchestrator;
use heimdall::http::client::PeerInfo;

fn make_spo(index: u16, port: u16, all_ports: &[(u16, u16)]) -> SpoOrchestrator {
    let id = Identifier::try_from(index).unwrap();
    let peers: Vec<PeerInfo> = all_ports
        .iter()
        .filter(|(idx, _)| *idx != index)
        .map(|(idx, p)| PeerInfo {
            identifier: Identifier::try_from(*idx).unwrap(),
            base_url: format!("http://127.0.0.1:{p}"),
        })
        .collect();
    SpoOrchestrator::new(id, port, peers)
}

#[tokio::test]
async fn test_3_spo_dkg_over_http() {
    let ports = [(1u16, 18470u16), (2, 18471), (3, 18472)];
    let mut spo1 = make_spo(1, 18470, &ports);
    let mut spo2 = make_spo(2, 18471, &ports);
    let mut spo3 = make_spo(3, 18472, &ports);

    // Start all servers
    let _h1 = spo1.start_server().await;
    let _h2 = spo2.start_server().await;
    let _h3 = spo3.start_server().await;

    let timeout = Duration::from_secs(10);

    // Run DKG concurrently
    let (r1, r2, r3) = tokio::join!(
        spo1.run_dkg(2, 3, timeout),
        spo2.run_dkg(2, 3, timeout),
        spo3.run_dkg(2, 3, timeout),
    );
    r1.unwrap();
    r2.unwrap();
    r3.unwrap();

    // All 3 must derive the same group public key
    let gk1 = spo1.group_public_key().unwrap();
    let gk2 = spo2.group_public_key().unwrap();
    let gk3 = spo3.group_public_key().unwrap();
    assert_eq!(gk1, gk2);
    assert_eq!(gk2, gk3);
    println!("DKG complete. Group public key: {:?}", gk1);
}

#[tokio::test]
async fn test_3_spo_dkg_and_signing_over_http() {
    let ports = [(1u16, 18480u16), (2, 18481), (3, 18482)];
    let mut spo1 = make_spo(1, 18480, &ports);
    let mut spo2 = make_spo(2, 18481, &ports);
    let mut spo3 = make_spo(3, 18482, &ports);

    let _h1 = spo1.start_server().await;
    let _h2 = spo2.start_server().await;
    let _h3 = spo3.start_server().await;

    let timeout = Duration::from_secs(10);

    // DKG
    let (r1, r2, r3) = tokio::join!(
        spo1.run_dkg(2, 3, timeout),
        spo2.run_dkg(2, 3, timeout),
        spo3.run_dkg(2, 3, timeout),
    );
    r1.unwrap();
    r2.unwrap();
    r3.unwrap();

    let group_key = spo1.group_public_key().unwrap();

    // Signing: all 3 SPOs sign (3-of-3 satisfies 2-of-3 threshold)
    let message = b"bifrost treasury handoff tx";
    let (s1, s2, s3) = tokio::join!(
        spo1.run_signing(message, timeout),
        spo2.run_signing(message, timeout),
        spo3.run_signing(message, timeout),
    );
    let sig1 = s1.unwrap();
    let sig2 = s2.unwrap();
    let sig3 = s3.unwrap();

    // All must produce the same signature
    assert_eq!(sig1, sig2);
    assert_eq!(sig2, sig3);

    // Verify the signature
    group_key.verify(message, &sig1).expect("signature must verify against group public key");
    println!("Signing complete. Signature verified.");
}
