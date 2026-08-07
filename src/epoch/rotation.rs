//! Update-Y authorization: getting the OUTGOING roster to sign the incoming
//! roster's succession (spec-compliance-plan N10c / N-b).
//!
//! A completed DKG produces `Y_51'`, but the treasury does not change hands
//! until `treasury_info`'s `current_spos_frost_key` says so. `treasury.ak`'s
//! `UpdateY` branch is permissionless in *submission* and strict in
//! *authorization*: it verifies a BIP-340 signature under the key being
//! replaced, over a message pinned to the state UTxO being spent. So the only
//! thing that can hand the treasury over is the outgoing roster itself, and a
//! signature it produced cannot be replayed against a different state UTxO or a
//! different successor.
//!
//! That leaves one question for this module: who holds the outgoing key?
//!
//! - **Bootstrap.** The first treasury is keyed to `y_federation`, whose secret
//!   is a configured seed. If (and only if) that seed's x-only key *is* the
//!   datum's current key, this node signs the handoff locally. This is the
//!   Phase-1 path the `update-y` CLI already takes, and it is what turns the
//!   very first DKG into a real roster.
//!
//! - **Steady state.** The outgoing key is a previous epoch's FROST group key,
//!   held as `t`-of-`n` shares. The signature is then produced by a FROST
//!   ceremony among the OUTGOING roster — recovered from the persisted DKG
//!   state ([`crate::epoch::persist`]) written at the end of that epoch — over
//!   the same 32-byte message. The ceremony is UNTWEAKED: the message is signed
//!   under the group key itself, not under a Taproot output key, so it uses
//!   plain `sign`/`aggregate` rather than the `_with_tweak` variants the TM
//!   inputs need.
//!
//! Both paths end at the same place: 64 bytes that verify under the datum's
//! current key. The caller verifies before submitting.
//!
//! ## Session namespacing
//!
//! The rotation ceremony rides the existing signing wire unchanged. Signing
//! payloads are keyed by `(epoch, input_index)` end-to-end — the HTTP route,
//! the server's map, the peer fetch — with no interpretation of the index
//! beyond identity, so [`UPDATE_Y_SESSION`] (an index no TM can ever have)
//! gives the rotation its own session alongside the TM's per-input ones. The
//! epoch is the INCOMING one, which every node agrees on.
//!
//! ## Known limits of the steady-state path
//!
//! The ceremony is driven from the incoming epoch's `PublishKeys`, so only
//! outgoing-roster members that are ALSO in the incoming roster reach it. An
//! SPO dropped at the boundary still holds a share but never contributes, and
//! (like `sign_phase`) the poll waits for every peer rather than stopping at
//! `min_signers` — so a roster that lost members between epochs times out
//! instead of proceeding on a threshold subset. Both are the same missing
//! piece: a threshold-aware poll. Until then a failed rotation is not fatal —
//! no Update-Y is posted, the old roster carries over, and the next boundary
//! retries, exactly as the spec prescribes for a failed ceremony.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use bitcoin::secp256k1::{Message, Secp256k1};
use frost::Identifier;
use frost_secp256k1_tr as frost;

use crate::epoch::log::id_short;
use crate::epoch::persist::{PersistedDkg, read_dkg_state};
use crate::epoch::state::{EpochConfig, EpochError, EpochResult, Roster};
use crate::epoch::traits::{Clock, PeerNetwork, RngSource, UpdateYPlan};
use crate::frost::participant;
use crate::frost::xonly::group_xonly;
use crate::http::payloads::{Sign1Payload, Sign2Payload};

/// Signing-session index reserved for the Update-Y message.
///
/// TM inputs are numbered from 0 and a transaction can never have `u32::MAX` of
/// them, so this cannot collide with a per-input session. It shares the epoch
/// namespace with them deliberately: all nodes agree on the incoming epoch
/// number, including nodes whose only role in it is to sign the handoff.
pub const UPDATE_Y_SESSION: u32 = u32::MAX;

/// How the authorizing signature was obtained — reported so the operator can
/// see, in the log, whether a handoff was federation-authorized (bootstrap) or
/// roster-authorized (steady state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateYAuthority {
    /// Signed locally with the configured federation seed, which matched the
    /// treasury's current key. Only possible while the treasury is still keyed
    /// to `y_federation`.
    Federation,
    /// Signed by a FROST ceremony among the outgoing roster of `epoch`.
    OutgoingRoster { epoch: u64, min_signers: u16 },
}

impl std::fmt::Display for UpdateYAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Federation => write!(f, "federation seed (bootstrap handoff)"),
            Self::OutgoingRoster { epoch, min_signers } => write!(
                f,
                "outgoing roster of epoch {epoch} ({min_signers}-of-n FROST)"
            ),
        }
    }
}

/// Produce the signature that authorizes `plan`, and verify it under the
/// outgoing key before returning — a bad signature must fail here, on the node
/// that made it, rather than as an opaque `CekError` at submission.
pub async fn authorize_update_y(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    me: Identifier,
    plan: &UpdateYPlan,
) -> EpochResult<([u8; 64], UpdateYAuthority)> {
    let (signature, authority) = match federation_signature(config, plan)? {
        Some(sig) => (sig, UpdateYAuthority::Federation),
        None => {
            let outgoing = load_outgoing_dkg(config, plan)?;
            let keys = outgoing.to_group_keys()?;
            let authority = UpdateYAuthority::OutgoingRoster {
                epoch: outgoing.epoch,
                min_signers: outgoing.roster.min_signers,
            };
            crate::epoch_log!(
                me,
                plan.epoch,
                "Update-Y: outgoing key is the epoch-{} FROST group key — running a rotation \
                 signing ceremony with that roster ({} participant(s))",
                outgoing.epoch,
                outgoing.roster.participants.len()
            );
            let sig = frost_sign_message(
                peers,
                clock,
                rng,
                config,
                plan.epoch,
                *keys.key_package.identifier(),
                &outgoing.roster,
                &keys,
                &plan.sig_msg,
            )
            .await?;
            (sig, authority)
        }
    };

    // Verify before anyone spends a fee on it.
    let secp = Secp256k1::new();
    let schnorr = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
        .map_err(|e| EpochError::Frost(format!("update-y signature: {e}")))?;
    secp.verify_schnorr(
        &schnorr,
        &Message::from_digest(plan.sig_msg),
        &plan.current_key,
    )
    .map_err(|e| {
        EpochError::Frost(format!(
            "update-y signature does not verify under the treasury's current key {}: {e}",
            hex::encode(plan.current_key.serialize())
        ))
    })?;

    Ok((signature, authority))
}

/// The bootstrap path: sign locally iff the configured federation seed's x-only
/// key IS the treasury's current key.
///
/// The equality check is the whole safety argument. `y_fed_seed` has a
/// well-known demo default, so "we have a seed" means nothing; "the seed
/// controls the key the datum names" means this node genuinely holds the
/// outgoing authority.
fn federation_signature(config: &EpochConfig, plan: &UpdateYPlan) -> EpochResult<Option<[u8; 64]>> {
    let Some(seed) = config.y_fed_seed else {
        return Ok(None);
    };
    let secp = Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&seed)
        .map_err(|e| EpochError::Frost(format!("y_fed seed: {e}")))?;
    let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
    if kp.x_only_public_key().0 != plan.current_key {
        return Ok(None);
    }
    Ok(Some(
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(plan.sig_msg), &kp)
            .serialize(),
    ))
}

/// Find the persisted DKG whose group key is the treasury's current key — the
/// ceremony that produced the outgoing roster.
///
/// Searching by KEY rather than by `epoch - 1` is deliberate: an epoch whose
/// DKG failed posts no Update-Y and the old roster simply carries over, so the
/// outgoing key can be several epochs old. The datum names the key; the state
/// dir is asked which ceremony produced it.
fn load_outgoing_dkg(config: &EpochConfig, plan: &UpdateYPlan) -> EpochResult<PersistedDkg> {
    let Some(dir) = config.state_dir.as_deref() else {
        return Err(EpochError::Frost(format!(
            "cannot authorize Update-Y: the treasury's current key {} is not the federation key \
             and protocol.state_dir is unset, so no outgoing DKG share was ever persisted",
            hex::encode(plan.current_key.serialize())
        )));
    };
    for epoch in persisted_epochs(dir)? {
        let Some(state) = read_dkg_state(dir, epoch)? else {
            continue;
        };
        let keys = state.to_group_keys()?;
        let g = group_xonly(&keys.verifying_key).map_err(EpochError::Frost)?;
        if g.xonly == plan.current_key {
            return Ok(state);
        }
    }
    Err(EpochError::Frost(format!(
        "cannot authorize Update-Y: no persisted DKG in {} has group key {} (the treasury's \
         current_spos_frost_key), and it is not the federation key — this node cannot have taken \
         part in the outgoing roster's ceremony",
        dir.display(),
        hex::encode(plan.current_key.serialize())
    )))
}

/// Epochs with a `dkg-epoch-<n>.json` in `dir`, newest first — the outgoing
/// roster is far more likely to be the most recent ceremony than the oldest.
fn persisted_epochs(dir: &Path) -> EpochResult<Vec<u64>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(EpochError::Chain(format!(
                "read state dir {}: {e}",
                dir.display()
            )));
        }
    };
    let mut epochs: Vec<u64> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_prefix("dkg-epoch-"))
                .and_then(|n| n.strip_suffix(".json"))
                .and_then(|n| n.parse().ok())
        })
        .collect();
    epochs.sort_unstable_by(|a, b| b.cmp(a));
    Ok(epochs)
}

/// One untweaked two-round FROST signing session over `msg`, among `roster`,
/// under `keys`.
///
/// Mirrors `sign_phase`'s structure for a single session, minus the Taproot
/// tweak: the Update-Y message is signed under the group key as-is, which is
/// what `verify_schnorr_signature(current_spos_frost_key, …)` checks on-chain.
#[allow(clippy::too_many_arguments)]
async fn frost_sign_message(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    rng: &Arc<dyn RngSource>,
    config: &EpochConfig,
    epoch: u64,
    me: Identifier,
    roster: &Roster,
    keys: &crate::epoch::state::GroupKeys,
    msg: &[u8; 32],
) -> EpochResult<[u8; 64]> {
    let mut sign_rng = rng.rng(format!("update-y:epoch={epoch}").as_bytes());
    let (nonces, commitments) = participant::sign_round1(&keys.key_package, &mut sign_rng);

    let mut round1: BTreeMap<Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
    round1.insert(me, commitments);
    peers
        .publish_sign_round1(Sign1Payload {
            epoch,
            identifier: me,
            input_index: UPDATE_Y_SESSION,
            commitments,
        })
        .await?;

    let peer_infos = roster.peers_of(me);
    crate::epoch_log!(
        me,
        epoch,
        "Update-Y round1: published commitments, waiting for {} outgoing peer(s)",
        peer_infos.len()
    );
    poll_round1(peers, clock, config, epoch, me, &peer_infos, &mut round1).await?;

    let package = frost::SigningPackage::new(round1, msg);
    let share = participant::sign_round2(&package, &nonces, &keys.key_package)
        .map_err(|e| EpochError::Frost(format!("update-y sign_round2: {e}")))?;
    let mut round2: BTreeMap<Identifier, frost::round2::SignatureShare> = BTreeMap::new();
    round2.insert(me, share);
    peers
        .publish_sign_round2(Sign2Payload {
            epoch,
            identifier: me,
            input_index: UPDATE_Y_SESSION,
            share,
        })
        .await?;

    crate::epoch_log!(
        me,
        epoch,
        "Update-Y round2: published share, waiting for {} outgoing peer(s)",
        peer_infos.len()
    );
    poll_round2(peers, clock, config, epoch, me, &peer_infos, &mut round2).await?;

    let signature = participant::sign_aggregate(&package, &round2, &keys.public_key_package)
        .map_err(|e| EpochError::Frost(format!("update-y aggregate: {e}")))?;
    signature
        .serialize()
        .map_err(|e| EpochError::Frost(format!("update-y sig serialize: {e}")))?
        .try_into()
        .map_err(|_| EpochError::Frost("update-y signature is not 64 bytes".into()))
}

async fn poll_round1(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    me: Identifier,
    peer_infos: &[&crate::epoch::state::SpoInfo],
    out: &mut BTreeMap<Identifier, frost::round1::SigningCommitments>,
) -> EpochResult<()> {
    let need = peer_infos.len() + out.len();
    let deadline = clock.deadline(config.quorum51_timeout);
    while out.len() < need {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(p) = peers
                .fetch_sign_round1(epoch, peer, UPDATE_Y_SESSION)
                .await?
            {
                crate::epoch_log!(
                    me,
                    epoch,
                    "  Update-Y round1 commitments from spo={} ({}/{})",
                    id_short(p.identifier),
                    out.len() + 1,
                    need
                );
                out.insert(p.identifier, p.commitments);
            }
        }
        if out.len() >= need {
            break;
        }
        if clock.now() >= deadline {
            return Err(EpochError::PollTimeout {
                got: out.len(),
                need,
            });
        }
        tokio::time::sleep(config.poll_interval).await;
    }
    Ok(())
}

async fn poll_round2(
    peers: &Arc<dyn PeerNetwork>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    me: Identifier,
    peer_infos: &[&crate::epoch::state::SpoInfo],
    out: &mut BTreeMap<Identifier, frost::round2::SignatureShare>,
) -> EpochResult<()> {
    let need = peer_infos.len() + out.len();
    let deadline = clock.deadline(config.quorum51_timeout);
    while out.len() < need {
        for peer in peer_infos {
            if out.contains_key(&peer.identifier) {
                continue;
            }
            if let Some(p) = peers
                .fetch_sign_round2(epoch, peer, UPDATE_Y_SESSION)
                .await?
            {
                crate::epoch_log!(
                    me,
                    epoch,
                    "  Update-Y round2 share from spo={} ({}/{})",
                    id_short(p.identifier),
                    out.len() + 1,
                    need
                );
                out.insert(p.identifier, p.share);
            }
        }
        if out.len() >= need {
            break;
        }
        if clock.now() >= deadline {
            return Err(EpochError::PollTimeout {
                got: out.len(),
                need,
            });
        }
        tokio::time::sleep(config.poll_interval).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::treasury_info::update_y_sig_msg;
    use crate::epoch::mocks::{MockPeerHub, MockPeerNetwork, OsRngSource, SystemClock};
    use crate::epoch::persist::write_dkg_state;
    use crate::epoch::state::{GroupKeys, SpoIdentity, SpoInfo};
    use bitcoin::key::UntweakedPublicKey;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "heimdall-rotation-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn roster_of(n: u16, t: u16) -> Roster {
        let mut participants = BTreeMap::new();
        for i in 1..=n {
            let id = Identifier::try_from(i).unwrap();
            participants.insert(
                id,
                SpoInfo {
                    identifier: id,
                    pool_id: vec![i as u8; 28],
                    bifrost_url: String::new(),
                    bifrost_id_pk: vec![],
                },
            );
        }
        Roster {
            epoch: 7,
            min_signers: t,
            max_signers: n,
            participants,
        }
    }

    /// Trivial n-of-n DKG via the frost dealer, so the tests don't need the
    /// interactive ceremony.
    fn dealt_keys(n: u16, t: u16) -> (BTreeMap<Identifier, GroupKeys>, UntweakedPublicKey) {
        let mut rng = rand::thread_rng();
        let (shares, pkp) =
            frost::keys::generate_with_dealer(n, t, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let mut out = BTreeMap::new();
        for (id, share) in shares {
            let kp = frost::keys::KeyPackage::try_from(share).unwrap();
            out.insert(
                id,
                GroupKeys {
                    verifying_key: *pkp.verifying_key(),
                    public_key_package: pkp.clone(),
                    key_package: kp,
                },
            );
        }
        let xonly = group_xonly(pkp.verifying_key()).unwrap().xonly;
        (out, xonly)
    }

    fn config_with(state_dir: Option<std::path::PathBuf>, seed: Option<[u8; 32]>) -> EpochConfig {
        let mut cfg = EpochConfig::demo_default(SpoIdentity {
            identifier: Identifier::try_from(1u16).unwrap(),
            bifrost_id_pk: Vec::new(),
            port: 0,
        });
        cfg.state_dir = state_dir;
        cfg.y_fed_seed = seed;
        cfg.poll_interval = std::time::Duration::from_millis(10);
        cfg.quorum51_timeout = std::time::Duration::from_secs(10);
        cfg
    }

    fn plan_for(current: UntweakedPublicKey, new: UntweakedPublicKey) -> UpdateYPlan {
        let txid = [0xa7u8; 32];
        UpdateYPlan {
            epoch: 12,
            current_key: current,
            new_key: new,
            sig_msg: update_y_sig_msg(&txid, 0, 12, &new.serialize()),
            state_outpoint: format!("{}:0", hex::encode(txid)),
        }
    }

    fn xonly_of(seed: [u8; 32]) -> UntweakedPublicKey {
        let secp = Secp256k1::new();
        bitcoin::secp256k1::SecretKey::from_slice(&seed)
            .unwrap()
            .x_only_public_key(&secp)
            .0
    }

    /// Bootstrap handoff: the treasury is still keyed to y_federation, so the
    /// node signs locally and the signature verifies under the datum's key.
    #[tokio::test]
    async fn federation_seed_authorizes_the_bootstrap_handoff() {
        let seed = [0x11u8; 32];
        let plan = plan_for(xonly_of(seed), xonly_of([0x22u8; 32]));
        let config = config_with(None, Some(seed));
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(
            config.identity.identifier,
            MockPeerHub::new(),
        ));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);

        let (sig, authority) = authorize_update_y(
            &peers,
            &clock,
            &rng,
            &config,
            config.identity.identifier,
            &plan,
        )
        .await
        .unwrap();

        assert_eq!(authority, UpdateYAuthority::Federation);
        // `authorize_update_y` verifies internally; re-assert here so the test
        // fails on the signature rather than on a missing error path.
        let secp = Secp256k1::new();
        secp.verify_schnorr(
            &bitcoin::secp256k1::schnorr::Signature::from_slice(&sig).unwrap(),
            &Message::from_digest(plan.sig_msg),
            &plan.current_key,
        )
        .unwrap();
    }

    /// A seed that is NOT the treasury's key must not be used to sign: with no
    /// persisted outgoing DKG either, authorization fails loudly.
    #[tokio::test]
    async fn a_foreign_federation_seed_does_not_authorize() {
        let plan = plan_for(xonly_of([0x33u8; 32]), xonly_of([0x44u8; 32]));
        let config = config_with(None, Some([0x11u8; 32]));
        let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(
            config.identity.identifier,
            MockPeerHub::new(),
        ));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);

        let err = authorize_update_y(
            &peers,
            &clock,
            &rng,
            &config,
            config.identity.identifier,
            &plan,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err}").contains("state_dir is unset"),
            "expected the no-outgoing-share error, got: {err}"
        );
    }

    /// Steady state: the outgoing key is a previous epoch's FROST group key.
    /// Every member of the OUTGOING roster runs the rotation ceremony, and the
    /// aggregated signature verifies under the treasury's current key — the
    /// outgoing roster authorizing its own succession.
    #[tokio::test]
    async fn the_outgoing_roster_frost_signs_its_own_succession() {
        let (keys, outgoing_xonly) = dealt_keys(3, 3);
        let roster = roster_of(3, 3);
        let dir = tmp_dir("outgoing");
        // Each node persisted its own share from the epoch-9 ceremony.
        for (id, k) in &keys {
            let mut per_node = dir.clone();
            per_node.push(format!("spo-{}", id_short(*id)));
            write_dkg_state(
                &per_node,
                &PersistedDkg::from_output(9, 0, &roster, k).unwrap(),
            )
            .unwrap();
        }

        let plan = plan_for(outgoing_xonly, xonly_of([0x77u8; 32]));
        let hub = MockPeerHub::new();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

        let mut handles = Vec::new();
        for id in keys.keys().copied() {
            let mut per_node = dir.clone();
            per_node.push(format!("spo-{}", id_short(id)));
            let mut config = config_with(Some(per_node), None);
            config.identity.identifier = id;
            let peers: Arc<dyn PeerNetwork> = Arc::new(MockPeerNetwork::new(id, hub.clone()));
            let clock = clock.clone();
            let rng: Arc<dyn RngSource> = Arc::new(OsRngSource);
            let plan = plan.clone();
            handles.push(tokio::spawn(async move {
                authorize_update_y(&peers, &clock, &rng, &config, id, &plan).await
            }));
        }

        let secp = Secp256k1::new();
        for h in handles {
            let (sig, authority) = h.await.unwrap().unwrap();
            assert_eq!(
                authority,
                UpdateYAuthority::OutgoingRoster {
                    epoch: 9,
                    min_signers: 3
                }
            );
            secp.verify_schnorr(
                &bitcoin::secp256k1::schnorr::Signature::from_slice(&sig).unwrap(),
                &Message::from_digest(plan.sig_msg),
                &plan.current_key,
            )
            .expect("the outgoing roster's FROST signature must authorize the rotation");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The persisted ceremony is found by KEY, not by `epoch - 1`: a treasury
    /// still keyed to an older roster (because the intervening DKG produced no
    /// Update-Y) is still authorizable.
    #[tokio::test]
    async fn the_outgoing_ceremony_is_located_by_key_not_by_epoch() {
        let (stale_keys, _) = dealt_keys(2, 2);
        let (live_keys, live_xonly) = dealt_keys(2, 2);
        let roster = roster_of(2, 2);
        let dir = tmp_dir("bykey");
        let id1 = Identifier::try_from(1u16).unwrap();
        // Epoch 9 holds the key the treasury actually names; epoch 10 is a later
        // ceremony whose Update-Y never landed.
        write_dkg_state(
            &dir,
            &PersistedDkg::from_output(9, 0, &roster, &live_keys[&id1]).unwrap(),
        )
        .unwrap();
        write_dkg_state(
            &dir,
            &PersistedDkg::from_output(10, 0, &roster, &stale_keys[&id1]).unwrap(),
        )
        .unwrap();

        let plan = plan_for(live_xonly, xonly_of([0x99u8; 32]));
        let config = config_with(Some(dir.clone()), None);
        let found = load_outgoing_dkg(&config, &plan).unwrap();
        assert_eq!(found.epoch, 9, "must pick the ceremony that owns the key");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
