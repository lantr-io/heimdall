//! Local persistence of DKG output so the signing share survives process
//! restarts for the whole epoch (WI-014 #5).
//!
//! FROST DKG runs once per epoch and is an expensive, multi-round, interactive
//! ceremony. A crash between DKG and the (5+ day) signing window must NOT force
//! a re-run or — worse — lose the share so the SPO can no longer sign the
//! treasury handoff. The [`KeyPackage`] (this node's secret signing share), the
//! [`PublicKeyPackage`] (the group), and the resolved roster are written to a
//! `0600` file under a configurable state dir, and reloaded at the next
//! `EpochStart` to skip straight past DKG into the signing pipeline.
//!
//! SECURITY: this writes the long-lived SIGNING SHARE to disk in the clear. The
//! `0600` perms + an operator-controlled state dir are the only protection; a
//! production deployment should layer encryption-at-rest / an OS keystore on
//! top. The raw per-peer Round 1/2 payloads are NOT persisted here — they are
//! only needed to re-derive the share (which we instead reload directly) or to
//! build fault proofs (WI-019, which reads the transport's own evidence store).

use std::path::{Path, PathBuf};

use frost_secp256k1_tr as frost;
use serde::{Deserialize, Serialize};

use crate::epoch::state::{EpochError, EpochResult, GroupKeys, Roster};

/// The on-disk DKG result for one epoch. `KeyPackage`/`PublicKeyPackage` are
/// stored as hex of their canonical frost serialization (they don't derive
/// serde at this layer); the roster rides along so the resumed cycle has the
/// signing set without re-querying the chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedDkg {
    pub epoch: u64,
    pub attempt: u32,
    pub roster: Roster,
    /// frost `KeyPackage::serialize`, hex — this node's secret signing share.
    pub key_package_hex: String,
    /// frost `PublicKeyPackage::serialize`, hex — the group public key package.
    pub public_key_package_hex: String,
}

impl PersistedDkg {
    /// Capture a completed DKG for `(epoch, attempt)`.
    pub fn from_output(
        epoch: u64,
        attempt: u32,
        roster: &Roster,
        keys: &GroupKeys,
    ) -> EpochResult<Self> {
        let kp = keys
            .key_package
            .serialize()
            .map_err(|e| EpochError::Frost(format!("serialize KeyPackage: {e}")))?;
        let pkp = keys
            .public_key_package
            .serialize()
            .map_err(|e| EpochError::Frost(format!("serialize PublicKeyPackage: {e}")))?;
        Ok(Self {
            epoch,
            attempt,
            roster: roster.clone(),
            key_package_hex: hex::encode(kp),
            public_key_package_hex: hex::encode(pkp),
        })
    }

    /// Rebuild the in-memory [`GroupKeys`] from the persisted bytes.
    pub fn to_group_keys(&self) -> EpochResult<GroupKeys> {
        let kp_bytes = hex::decode(&self.key_package_hex)
            .map_err(|e| EpochError::Frost(format!("KeyPackage hex: {e}")))?;
        let pkp_bytes = hex::decode(&self.public_key_package_hex)
            .map_err(|e| EpochError::Frost(format!("PublicKeyPackage hex: {e}")))?;
        let key_package = frost::keys::KeyPackage::deserialize(&kp_bytes)
            .map_err(|e| EpochError::Frost(format!("deserialize KeyPackage: {e}")))?;
        let public_key_package = frost::keys::PublicKeyPackage::deserialize(&pkp_bytes)
            .map_err(|e| EpochError::Frost(format!("deserialize PublicKeyPackage: {e}")))?;
        Ok(GroupKeys {
            verifying_key: *public_key_package.verifying_key(),
            public_key_package,
            key_package,
        })
    }
}

/// `<state_dir>/dkg-epoch-<epoch>.json`.
#[must_use]
pub fn dkg_state_path(state_dir: &Path, epoch: u64) -> PathBuf {
    state_dir.join(format!("dkg-epoch-{epoch}.json"))
}

/// Atomically persist the DKG state: the dir is created `0700`, the file is
/// written `0600` to a sibling `.tmp` and renamed into place so a crash mid-
/// write never leaves a torn file.
pub fn write_dkg_state(state_dir: &Path, state: &PersistedDkg) -> EpochResult<()> {
    create_dir_0700(state_dir)?;
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| EpochError::Frost(format!("serialize DKG state: {e}")))?;
    let path = dkg_state_path(state_dir, state.epoch);
    let tmp = path.with_extension("tmp");
    write_file_0600(&tmp, &json)?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| EpochError::Chain(format!("rename DKG state into place: {e}")))?;
    Ok(())
}

/// Read the persisted DKG state for `epoch`, if any. A missing file → `Ok(None)`
/// (no prior run). A present-but-wrong-epoch file is an error, not a silent
/// mismatch.
pub fn read_dkg_state(state_dir: &Path, epoch: u64) -> EpochResult<Option<PersistedDkg>> {
    let path = dkg_state_path(state_dir, epoch);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let state: PersistedDkg = serde_json::from_slice(&bytes)
                .map_err(|e| EpochError::Frost(format!("parse DKG state {path:?}: {e}")))?;
            if state.epoch != epoch {
                return Err(EpochError::Frost(format!(
                    "DKG state {path:?} is for epoch {} not {epoch}",
                    state.epoch
                )));
            }
            Ok(Some(state))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(EpochError::Chain(format!("read DKG state {path:?}: {e}"))),
    }
}

#[cfg(unix)]
fn create_dir_0700(dir: &Path) -> EpochResult<()> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| EpochError::Chain(format!("create state dir {dir:?}: {e}")))
}

#[cfg(not(unix))]
fn create_dir_0700(dir: &Path) -> EpochResult<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| EpochError::Chain(format!("create state dir {dir:?}: {e}")))
}

#[cfg(unix)]
fn write_file_0600(path: &Path, bytes: &[u8]) -> EpochResult<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| EpochError::Chain(format!("open {path:?}: {e}")))?;
    // mode() only applies on create; force 0600 in case the tmp pre-existed.
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|e| EpochError::Chain(format!("chmod {path:?}: {e}")))?;
    f.write_all(bytes)
        .map_err(|e| EpochError::Chain(format!("write {path:?}: {e}")))?;
    f.sync_all().ok();
    Ok(())
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, bytes: &[u8]) -> EpochResult<()> {
    std::fs::write(path, bytes).map_err(|e| EpochError::Chain(format!("write {path:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::state::{GroupKeys, SpoInfo};
    use frost::Identifier;
    use std::collections::BTreeMap;

    /// Run a tiny 2-of-2 DKG and return one node's GroupKeys + a roster.
    fn sample_output() -> (GroupKeys, Roster) {
        use crate::frost::participant;
        let id1 = Identifier::try_from(1u16).unwrap();
        let id2 = Identifier::try_from(2u16).unwrap();
        let mut rng = rand::thread_rng();
        let (s1, p1) = participant::dkg_part1(id1, 2, 2, &mut rng).unwrap();
        let (s2, p2) = participant::dkg_part1(id2, 2, 2, &mut rng).unwrap();
        let r1_1: BTreeMap<_, _> = [(id2, p2)].into_iter().collect();
        let r1_2: BTreeMap<_, _> = [(id1, p1)].into_iter().collect();
        let (s1r2, _) = participant::dkg_part2(s1, &r1_1).unwrap();
        let (_, pk2) = participant::dkg_part2(s2, &r1_2).unwrap();
        let r2_1: BTreeMap<_, _> = [(id2, pk2.get(&id1).unwrap().clone())]
            .into_iter()
            .collect();
        let (kp, pkp) = participant::dkg_part3(&s1r2, &r1_1, &r2_1).unwrap();
        let keys = GroupKeys {
            verifying_key: *pkp.verifying_key(),
            public_key_package: pkp,
            key_package: kp,
        };
        let mut participants = BTreeMap::new();
        for i in 1u16..=2 {
            let id = Identifier::try_from(i).unwrap();
            participants.insert(
                id,
                SpoInfo {
                    identifier: id,
                    pool_id: vec![i as u8; 28],
                    bifrost_url: format!("http://127.0.0.1:{}", 18600 + i),
                    bifrost_id_pk: vec![i as u8; 32],
                },
            );
        }
        let roster = Roster {
            epoch: 11,
            min_signers: 2,
            max_signers: 2,
            participants,
        };
        (keys, roster)
    }

    #[test]
    fn persist_roundtrip_recovers_the_share_and_group_key() {
        let (keys, roster) = sample_output();
        let saved = PersistedDkg::from_output(11, 3, &roster, &keys).unwrap();

        let dir =
            std::env::temp_dir().join(format!("heimdall-persist-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_dkg_state(&dir, &saved).unwrap();

        // 0600 file under the state dir.
        let path = dkg_state_path(&dir, 11);
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "DKG state must be 0600");
        }

        // Reload and recover identical bytes + the same group/signing keys.
        let loaded = read_dkg_state(&dir, 11).unwrap().expect("state present");
        assert_eq!(loaded, saved);
        let recovered = loaded.to_group_keys().unwrap();
        assert_eq!(recovered.verifying_key, keys.verifying_key);
        assert_eq!(
            recovered.key_package.signing_share(),
            keys.key_package.signing_share(),
            "the reloaded signing share must match the original"
        );
        assert_eq!(loaded.roster, roster);

        // A different epoch has no state.
        assert!(read_dkg_state(&dir, 99).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
