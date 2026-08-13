//! Signing with the federation key — the second signing path.
//!
//! Once the federation key is a `t`-of-`n` FROST key, everything that used to
//! sign with the single seed becomes a distributed session: the treasury's CSV
//! recovery spend (`federation-spend`), and any other message the federation
//! authorizes as itself.
//!
//! This module signs with the key by the name the CHAIN gives it —
//! `y_federation`, Config #11 — because by the time anything is signed the bridge
//! exists and the published value is what the treasury was locked with. The
//! ceremony's `federation_setup_Y` ([`crate::federation`]) is the same key before
//! that point.
//!
//! **This path must work precisely when the epoch machinery does not.** It is the
//! recovery route for a dark FROST group, so it depends on no chain read, no
//! registry, no Config UTxO and no epoch state — only the typed-in roster
//! ([`crate::federation::roster`]), the persisted share
//! ([`crate::federation::persist`]) and the same authenticated HTTP transport the
//! ceremony used. Nothing here may acquire a dependency on the epoch loop.
//!
//! ## The signer set is pinned, never raced
//!
//! FROST's Round 2 binds each share to the *exact* set of Round-1 commitments the
//! signer saw: two participants that froze different sets compute different
//! binding factors, and the aggregate is simply invalid. A `t`-of-`n` session
//! therefore has to agree on WHICH `t` before it starts.
//!
//! The epoch machine can afford to derive that from chain state. This path
//! cannot, and a deadline-and-take-whoever-answered rule would let two members
//! freeze different sets from the same network — a race whose only symptom is an
//! invalid signature after the whole session. So the set is an INPUT: every
//! member runs the command with the same signer list (defaulting to the whole
//! federation), and a member that has not arrived by the deadline fails the
//! session by name instead of being silently dropped. That is the honest shape
//! for a manual recovery procedure whose participants are already coordinating
//! out of band.
//!
//! ## No Taproot tweak
//!
//! The recovery leaf is spent by SCRIPT path, and a script-path signature is
//! verified against the key pushed in the leaf — `y_federation` itself — not
//! against the tweaked output key. So this session uses the UNTWEAKED FROST
//! rounds, and the result verifies under the group key's BIP-340 x-only form
//! (see [`crate::frost::xonly`], which pins that property for both parities).
//!
//! Note that `sign_round2_with_tweak(.., None)` is NOT the untweaked round:
//! `None` there means the BIP-341 tweak of a key-only output, which yields a
//! third key that is neither the group key nor the treasury's output key.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::{Message, Secp256k1, schnorr};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Identifier;
use rand_core::{CryptoRng, RngCore};
use tracing::info;

use crate::epoch::state::{GroupKeys, SpoInfo};
use crate::epoch::traits::PeerNetwork;
use crate::federation::ceremony::{CeremonyError, CeremonyLimits, poll_all};
use crate::federation::roster::FederationRoster;
use crate::frost::participant;
use crate::frost::xonly::group_xonly;
use crate::http::wire::SignNamespace;

/// Session index reserved for federation signing.
///
/// The signing-session space is shared with the TM inputs (numbered from 0) and
/// the Update-Y rotation ([`crate::http::wire::UPDATE_Y_SESSION`] = `u32::MAX`),
/// so this takes the next value down. A transaction cannot have this many
/// inputs, so it can never collide with a per-input session — and the message
/// being signed is in the namespace too, which is what makes each individual
/// federation spend its own replay domain.
pub const FEDERATION_SESSION: u32 = u32::MAX - 1;

/// Produce a `t`-of-`n` BIP-340 signature over `message` under `y_federation`.
///
/// `signers` must be identical on every participating node — see the module
/// docs. `keys` is this node's persisted share; its identifier is authoritative
/// for who this node is in the session (the same rule
/// [`crate::epoch::signing::sign_phase`] follows), because that is the index the
/// share was actually generated under.
pub async fn frost_sign(
    peers: &Arc<dyn PeerNetwork>,
    roster: &FederationRoster,
    keys: &GroupKeys,
    message: [u8; 32],
    signers: &BTreeSet<Identifier>,
    rng: &mut (impl RngCore + CryptoRng),
    limits: &CeremonyLimits,
) -> Result<[u8; 64], CeremonyError> {
    let me = *keys.key_package.identifier();
    if !signers.contains(&me) {
        return Err(CeremonyError::NotASigner {
            me: crate::frost::identifier_u16(me),
        });
    }
    let ns = SignNamespace::new(0, FEDERATION_SESSION, message);
    let spo_roster = roster.to_roster();
    let co_signers: Vec<SpoInfo> = signers
        .iter()
        .filter(|id| **id != me)
        .filter_map(|id| spo_roster.participants.get(id).cloned())
        .collect();

    info!(
        "[federation] signing session over message {} with {} of {} member(s): {}",
        hex::encode(message),
        signers.len(),
        roster.len(),
        signer_labels(roster, signers).join(", ")
    );

    // ── Round 1: nonce commitments ─────────────────────────────────────
    let (nonces, my_commitments) = participant::sign_round1(&keys.key_package, rng);
    peers.publish_sign_round1(ns, me, my_commitments).await?;
    let mut commitments: BTreeMap<Identifier, frost::round1::SigningCommitments> =
        BTreeMap::from([(me, my_commitments)]);
    poll_all(
        peers,
        "signing round 1",
        &co_signers,
        limits,
        &mut commitments,
        |peer| async move { peers.fetch_sign_round1(ns, &peer).await },
    )
    .await?;

    // Every signer builds this from the same pinned set, so every signer's
    // binding factors match — the property the pinned set exists to give.
    let signing_package = frost::SigningPackage::new(commitments, &message);

    // ── Round 2: signature shares ──────────────────────────────────────
    // The UNTWEAKED round, not `sign_round2_with_tweak(.., None)`: in
    // frost-secp256k1-tr `None` does not mean "no tweak", it means the BIP-341
    // tweak for a key-only output (`t = H_TapTweak(P)`), which is a different
    // key again. A script-path signature is checked against the key the leaf
    // pushes — `Y_federation` itself — so no tweak of any kind belongs here.
    // This is the same shape the Update-Y authorization signs in.
    let my_share = participant::sign_round2(&signing_package, &nonces, &keys.key_package)
        .map_err(|e| CeremonyError::Frost(format!("sign_round2: {e}")))?;
    peers.publish_sign_round2(ns, me, my_share).await?;
    let mut shares: BTreeMap<Identifier, frost::round2::SignatureShare> =
        BTreeMap::from([(me, my_share)]);
    poll_all(
        peers,
        "signing round 2",
        &co_signers,
        limits,
        &mut shares,
        |peer| async move { peers.fetch_sign_round2(ns, &peer).await },
    )
    .await?;

    let signature =
        participant::sign_aggregate(&signing_package, &shares, &keys.public_key_package)
            .map_err(|e| CeremonyError::Frost(format!("aggregate: {e}")))?;
    let bytes: [u8; 64] = signature
        .serialize()
        .map_err(|e| CeremonyError::Frost(format!("signature serialize: {e}")))?
        .try_into()
        .map_err(|v: Vec<u8>| {
            CeremonyError::Frost(format!("signature is {} bytes, want 64", v.len()))
        })?;

    // Verify before handing it back. Aggregation can succeed over shares that do
    // not actually satisfy the group key, and the caller is about to put these
    // bytes in a transaction witness — a signature that fails here is a session
    // to re-run, while one that fails on Bitcoin is a broadcast that burned the
    // operator's coordination window and told them nothing.
    let y_fed = verifying_key(keys)?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &schnorr::Signature::from_slice(&bytes)
                .map_err(|e| CeremonyError::Frost(format!("schnorr signature: {e}")))?,
            &Message::from_digest(message),
            &y_fed,
        )
        .map_err(|e| {
            CeremonyError::Frost(format!(
                "the aggregated signature does not verify under y_federation {}: {e}",
                hex::encode(y_fed.serialize())
            ))
        })?;

    info!("[federation] signature aggregated and verified under y_federation");
    Ok(bytes)
}

/// `y_federation` in the x-only form the recovery leaf pushes.
pub fn verifying_key(keys: &GroupKeys) -> Result<UntweakedPublicKey, CeremonyError> {
    group_xonly(&keys.verifying_key)
        .map(|g| g.xonly)
        .map_err(CeremonyError::Frost)
}

fn signer_labels(roster: &FederationRoster, signers: &BTreeSet<Identifier>) -> Vec<String> {
    signers
        .iter()
        .map(|id| {
            roster.member(*id).map_or_else(
                || format!("{id:?}"),
                crate::federation::FederationMember::label,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FederationConfig, FederationMemberConfig};
    use crate::epoch::mocks::{MockPeerHub, MockPeerNetwork, OsRngSource};
    use crate::epoch::traits::RngSource;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use std::time::Duration;

    fn member_key(byte: u8) -> String {
        let secp = Secp256k1::new();
        hex::encode(
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
                .x_only_public_key()
                .0
                .serialize(),
        )
    }

    fn roster(min_signers: u16, n: u8) -> FederationRoster {
        FederationRoster::from_config(&FederationConfig {
            min_signers: Some(min_signers),
            members: (1..=n)
                .map(|b| FederationMemberConfig {
                    bifrost_id_pk: member_key(b),
                    bifrost_url: format!("http://m{b}.example:8080"),
                })
                .collect(),
        })
        .expect("valid roster")
    }

    /// Deal a `t`-of-`n` group, so the signing session under test is exercised
    /// without also re-running a ceremony (which `ceremony` tests cover).
    fn dealt(t: u16, n: u16) -> BTreeMap<Identifier, GroupKeys> {
        let mut rng = rand::thread_rng();
        let (shares, pkp) =
            frost::keys::generate_with_dealer(n, t, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        shares
            .into_iter()
            .map(|(id, s)| {
                (
                    id,
                    GroupKeys {
                        verifying_key: *pkp.verifying_key(),
                        public_key_package: pkp.clone(),
                        key_package: frost::keys::KeyPackage::try_from(s).unwrap(),
                    },
                )
            })
            .collect()
    }

    fn limits() -> CeremonyLimits {
        CeremonyLimits::bounded(Duration::from_millis(5), Duration::from_secs(10))
    }

    /// A THRESHOLD of members — not all of them — produces a signature that
    /// verifies under y_federation, with no tweak: the acceptance property of
    /// the federation spend path.
    #[tokio::test]
    async fn a_threshold_of_members_signs_under_y_federation() {
        let roster = roster(2, 3);
        let keys = dealt(2, 3);
        let hub = MockPeerHub::new();
        let message = [0x5au8; 32];
        let signers: BTreeSet<Identifier> = roster
            .signers_from_indices(&[1, 3])
            .expect("a valid pair of signers");

        let mut handles = Vec::new();
        for id in &signers {
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(*id, hub.clone()));
            let roster = roster.clone();
            let keys = keys[id].clone();
            let signers = signers.clone();
            handles.push(tokio::spawn(async move {
                // `OsRng` via the epoch RngSource, not `thread_rng`: the latter is
                // `!Send`, so it cannot be held across an await in a spawned task.
                let mut rng = OsRngSource.rng(b"federation-sign");
                frost_sign(
                    &peers,
                    &roster,
                    &keys,
                    message,
                    &signers,
                    &mut rng,
                    &limits(),
                )
                .await
            }));
        }
        let mut sigs = Vec::new();
        for h in handles {
            sigs.push(h.await.unwrap().expect("session completes"));
        }

        // Both signers aggregate to the same signature, and it verifies against
        // the key the recovery leaf pushes — untweaked.
        assert_eq!(sigs[0], sigs[1]);
        let y_fed = verifying_key(&keys[&Identifier::try_from(1u16).unwrap()]).unwrap();
        Secp256k1::verification_only()
            .verify_schnorr(
                &schnorr::Signature::from_slice(&sigs[0]).unwrap(),
                &Message::from_digest(message),
                &y_fed,
            )
            .expect("script-path signature must verify under y_federation");
    }

    /// The WI-087 acceptance property, end to end: a THRESHOLD of federation
    /// members produces a valid script-path spend of the treasury's CSV recovery
    /// leaf — the thing a single seed used to do alone.
    ///
    /// This composes the two halves that are otherwise tested apart: the leaf
    /// spend built by [`crate::bitcoin::tm_builder::federation_leaf_spend`], and
    /// the distributed signature over its sighash. The check that matters is the
    /// last one — the witness signature verifies against the key the REVEALED
    /// LEAF pushes, under the tapscript sighash, which is exactly what
    /// `OP_CHECKSIG` will do on Bitcoin.
    #[tokio::test]
    async fn a_threshold_of_members_spends_the_treasury_recovery_leaf() {
        use crate::bitcoin::taproot::{build_csv_checksig_script, treasury_spend_info};
        use crate::bitcoin::tm_builder::{
            Freshness, TmParams, TreasuryInput, build_tm, federation_leaf_spend,
        };
        use bitcoin::hashes::Hash;
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};
        use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};

        const CSV: u16 = 144;
        let secp = Secp256k1::new();
        let roster = roster(2, 3);
        let keys = dealt(2, 3);
        let y_fed = verifying_key(&keys[&Identifier::try_from(1u16).unwrap()]).unwrap();

        // A treasury locked with the federation's DKG'd key in its recovery leaf.
        // Y_51 is an unrelated internal key: this spend never touches it.
        let y_51 = bitcoin::key::UntweakedPublicKey::from_slice(
            &SecretKey::from_slice(&[0x51; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0
                .serialize(),
        )
        .unwrap();
        let spend_info = treasury_spend_info(&secp, y_51, y_fed, CSV);
        let treasury_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
        let unsigned = build_tm(
            TreasuryInput {
                outpoint: OutPoint {
                    txid: Txid::from_byte_array([0xAA; 32]),
                    vout: 0,
                },
                value: Amount::from_sat(1_000_000),
                spend_info,
            },
            vec![],
            vec![],
            treasury_spk,
            &TmParams::fee_rate_only(1),
            &Freshness {
                now_ms: 0,
                margin_ms: 0,
            },
            &crate::cardano::cpo_trie::CpoTrie::empty(),
            &crate::cardano::spi_trie::SpiTrie::empty(),
        )
        .expect("build the federation spend");
        let leaf_spend = federation_leaf_spend(&unsigned, y_fed, CSV).expect("leaf is in the tree");

        // Members #1 and #3 sign it; #2 is dark, which is the situation this key
        // exists for.
        let signers = roster.signers_from_indices(&[1, 3]).unwrap();
        let hub = MockPeerHub::new();
        let mut handles = Vec::new();
        for id in &signers {
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(*id, hub.clone()));
            let roster = roster.clone();
            let keys = keys[id].clone();
            let signers = signers.clone();
            let sighash = leaf_spend.sighash;
            handles.push(tokio::spawn(async move {
                let mut rng = OsRngSource.rng(b"federation-sign");
                frost_sign(
                    &peers,
                    &roster,
                    &keys,
                    sighash,
                    &signers,
                    &mut rng,
                    &limits(),
                )
                .await
            }));
        }
        let mut sigs = Vec::new();
        for h in handles {
            sigs.push(h.await.unwrap().expect("session completes"));
        }
        assert_eq!(
            sigs[0], sigs[1],
            "both signers aggregate the same signature"
        );

        let tx = leaf_spend.finish(sigs[0]).expect("witnessed transaction");
        assert_eq!(
            tx.input[0].witness.len(),
            3,
            "script-path witness: signature, leaf, control block"
        );
        assert_eq!(tx.input[0].sequence, bitcoin::Sequence::from_height(CSV));

        // What Bitcoin will check: the witness signature against the key inside
        // the revealed leaf, under this input's tapscript sighash.
        let leaf = build_csv_checksig_script(CSV, y_fed);
        assert_eq!(tx.input[0].witness.nth(1).unwrap(), leaf.as_bytes());
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&unsigned.prevouts),
                TapLeafHash::from_script(&leaf, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap();
        let sig =
            schnorr::Signature::from_slice(tx.input[0].witness.nth(0).unwrap()).expect("64 bytes");
        secp.verify_schnorr(&sig, &Message::from_digest(sighash.to_byte_array()), &y_fed)
            .expect("the federation quorum's signature must satisfy the recovery leaf");
    }

    /// A node holding a share but left out of the pinned set refuses rather than
    /// publishing material into a session it is not part of.
    #[tokio::test]
    async fn a_node_outside_the_pinned_signer_set_refuses() {
        let roster = roster(2, 3);
        let keys = dealt(2, 3);
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(
            Identifier::try_from(2u16).unwrap(),
            MockPeerHub::new(),
        ));
        let signers = roster.signers_from_indices(&[1, 3]).unwrap();
        let mut rng = rand::thread_rng();
        let e = frost_sign(
            &peers,
            &roster,
            &keys[&Identifier::try_from(2u16).unwrap()],
            [0u8; 32],
            &signers,
            &mut rng,
            &limits(),
        )
        .await
        .expect_err("must refuse");
        assert!(matches!(e, CeremonyError::NotASigner { me: 2 }), "{e:?}");
    }

    /// A named signer that never shows up fails the session BY NAME. Silently
    /// continuing with fewer would freeze a different set than the co-signers
    /// did, and produce an invalid aggregate with nothing pointing at why.
    #[tokio::test]
    async fn a_missing_named_signer_fails_the_session_by_name() {
        let roster = roster(2, 3);
        let keys = dealt(2, 3);
        let me = Identifier::try_from(1u16).unwrap();
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(me, MockPeerHub::new()));
        let signers = roster.signers_from_indices(&[1, 2]).unwrap();
        let mut rng = rand::thread_rng();
        let e = frost_sign(
            &peers,
            &roster,
            &keys[&me],
            [0u8; 32],
            &signers,
            &mut rng,
            &CeremonyLimits::bounded(Duration::from_millis(5), Duration::from_millis(50)),
        )
        .await
        .expect_err("must not complete without the second signer");
        match e {
            CeremonyError::Incomplete { phase, missing } => {
                assert_eq!(phase, "signing round 1");
                // Diagnosed, not merely named: the mock reports healthy, so the
                // message says "published nothing" rather than "unreachable" —
                // the two have opposite remedies.
                assert_eq!(missing.len(), 1);
                assert!(
                    missing[0].starts_with("http://m2.example:8080"),
                    "{missing:?}"
                );
                assert!(missing[0].contains("published nothing"), "{missing:?}");
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }
}
