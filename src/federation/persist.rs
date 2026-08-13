//! The federation share on disk.
//!
//! `Y_federation` is generated ONCE, before the bridge exists, and never
//! rotates with an epoch. That makes losing a share categorically worse than
//! losing an epoch share ([`crate::epoch::persist`]): there is no next boundary
//! to re-derive it at, and the members cannot re-run the ceremony without
//! producing a DIFFERENT key — which means a different treasury address, so the
//! BTC already in the old one stays behind the old key. Below the signing
//! threshold in surviving shares, the recovery path is gone for good.
//!
//! So the file is written the same way an epoch share is — `0600`, under a
//! `0700` state dir, via a `.tmp` + rename so a crash cannot tear it — and it
//! carries one thing the epoch state does not need: a digest of the roster it
//! was generated for ([`FederationRoster::digest`]). A share is only meaningful
//! against the exact membership and threshold that produced it, and a config
//! edited afterwards is the likeliest way to end up holding one that is not.
//!
//! SECURITY: like the epoch state, this is the signing secret in the clear. The
//! file mode and the operator's state dir are the only protection.

use std::path::{Path, PathBuf};

use bitcoin::key::UntweakedPublicKey;
use serde::{Deserialize, Serialize};

use crate::epoch::persist::{
    create_dir_0700, group_keys_from_hex, group_keys_to_hex, write_file_0600,
};
use crate::epoch::state::GroupKeys;
use crate::federation::roster::FederationRoster;
use crate::frost::xonly::group_xonly;

/// `<state_dir>/federation-key.json`.
const FEDERATION_STATE_FILE: &str = "federation-key.json";

/// This node's share of the federation key, plus what it is a share OF.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederationKeyState {
    /// [`FederationRoster::digest`] of the ceremony that produced this share,
    /// hex. Checked on every load: a share does not survive a change of
    /// membership or threshold.
    pub roster_digest: String,
    pub min_signers: u16,
    pub max_signers: u16,
    /// The group key's x-only form: the **federation setup key**,
    /// `federation_setup_Y`.
    ///
    /// One value, two names, on purpose. Here it is what the ceremony PRODUCED —
    /// a key that exists before the bridge does and is not yet anybody's to read.
    /// It becomes `y_federation` the moment genesis publishes it at Config #11,
    /// and from then on that is the name for it: every node reads it from the
    /// chain, and only a member holding a share still has this local copy. The
    /// setup name keeps the two situations apart while both are true.
    ///
    /// Derivable from `public_key_package_hex`, and stored anyway: it is the one
    /// field an operator reads, compares against the deployment notes and pastes
    /// into `binocular`'s `bridge.y-federation-hex`.
    /// [`Self::federation_setup_y`] re-derives it and refuses a file where the
    /// two disagree.
    pub federation_setup_y: String,
    /// frost `KeyPackage::serialize`, hex — this node's secret signing share.
    pub key_package_hex: String,
    /// frost `PublicKeyPackage::serialize`, hex — the group.
    pub public_key_package_hex: String,
}

#[derive(Debug)]
pub enum StateError {
    Io(String),
    /// The file is not readable as a federation state.
    Parse(String),
    /// The stored share was generated for a different federation.
    RosterChanged {
        stored: String,
        configured: String,
    },
    /// The frost material, or the key derived from it, is not usable.
    Keys(String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "federation key state: {e}"),
            Self::Parse(e) => write!(f, "federation key state: {e}"),
            Self::RosterChanged { stored, configured } => write!(
                f,
                "the persisted federation share was generated for roster {stored} but \
                 [federation] now describes {configured}. A share is only valid for the exact \
                 membership and threshold that produced it, so this share cannot sign for the \
                 configured federation. Either restore the member list and threshold the \
                 ceremony ran with, or — if the federation really has changed — run the \
                 ceremony again, which produces a DIFFERENT Y_federation and therefore a \
                 different treasury address that the existing funds are not in"
            ),
            Self::Keys(e) => write!(f, "federation key state: {e}"),
        }
    }
}

impl std::error::Error for StateError {}

impl FederationKeyState {
    /// Capture a completed federation ceremony.
    pub fn from_output(roster: &FederationRoster, keys: &GroupKeys) -> Result<Self, StateError> {
        let (key_package_hex, public_key_package_hex) =
            group_keys_to_hex(keys).map_err(|e| StateError::Keys(e.to_string()))?;
        let y = group_xonly(&keys.verifying_key).map_err(StateError::Keys)?;
        Ok(Self {
            roster_digest: hex::encode(roster.digest()),
            min_signers: roster.min_signers,
            max_signers: roster.len(),
            federation_setup_y: hex::encode(y.xonly.serialize()),
            key_package_hex,
            public_key_package_hex,
        })
    }

    /// Rebuild the in-memory [`GroupKeys`].
    pub fn to_group_keys(&self) -> Result<GroupKeys, StateError> {
        group_keys_from_hex(&self.key_package_hex, &self.public_key_package_hex)
            .map_err(|e| StateError::Keys(e.to_string()))
    }

    /// The federation setup key, re-derived from the group package rather than
    /// trusted from the `federation_setup_y` field — and the two must agree.
    ///
    /// The stored field is a convenience for humans; the key that decides an
    /// ADDRESS is not something to read from the convenience copy. A file whose
    /// two halves disagree has been edited or corrupted, and the direction of
    /// the error matters: derive from the material this node actually signs
    /// with.
    pub fn federation_setup_y(&self) -> Result<UntweakedPublicKey, StateError> {
        let keys = self.to_group_keys()?;
        let derived = group_xonly(&keys.verifying_key).map_err(StateError::Keys)?;
        let stored = hex::decode(self.federation_setup_y.trim())
            .map_err(|e| StateError::Parse(format!("federation_setup_y is not hex: {e}")))?;
        if stored != derived.xonly.serialize() {
            return Err(StateError::Keys(format!(
                "federation_setup_y {} does not derive from the stored group package (which \
                 yields {}) — the file has been edited or corrupted",
                self.federation_setup_y,
                hex::encode(derived.xonly.serialize())
            )));
        }
        Ok(derived.xonly)
    }

    /// Refuse a share that belongs to a different federation than the one
    /// configured now.
    pub fn check_roster(&self, roster: &FederationRoster) -> Result<(), StateError> {
        let configured = hex::encode(roster.digest());
        if self.roster_digest != configured {
            return Err(StateError::RosterChanged {
                stored: format!(
                    "{}-of-{} ({})",
                    self.min_signers,
                    self.max_signers,
                    short(&self.roster_digest)
                ),
                configured: format!(
                    "{}-of-{} ({})",
                    roster.min_signers,
                    roster.len(),
                    short(&configured)
                ),
            });
        }
        Ok(())
    }
}

fn short(digest_hex: &str) -> &str {
    &digest_hex[..digest_hex.len().min(16)]
}

/// Where the federation share lives under `state_dir`.
#[must_use]
pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(FEDERATION_STATE_FILE)
}

/// Persist the share atomically (`0600` under a `0700` dir, via `.tmp` +
/// rename).
///
/// Unlike an epoch share, a failure here is NOT survivable by carrying on in
/// memory — the caller must treat it as fatal and say so, because the process
/// exiting is the end of the only copy of a key that never regenerates.
pub fn write(state_dir: &Path, state: &FederationKeyState) -> Result<(), StateError> {
    create_dir_0700(state_dir).map_err(|e| StateError::Io(e.to_string()))?;
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| StateError::Parse(format!("serialize: {e}")))?;
    let path = state_path(state_dir);
    let tmp = path.with_extension("tmp");
    write_file_0600(&tmp, &json).map_err(|e| StateError::Io(e.to_string()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| StateError::Io(format!("rename {} into place: {e}", path.display())))?;
    Ok(())
}

/// Read the persisted share, if there is one. A missing file is `Ok(None)` —
/// a node that has not run the ceremony has no share, which is a state, not an
/// error. An unreadable or unparseable one IS an error: "we could not tell"
/// must never read as "there is none".
pub fn read(state_dir: &Path) -> Result<Option<FederationKeyState>, StateError> {
    let path = state_path(state_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let state: FederationKeyState = serde_json::from_slice(&bytes)
                .map_err(|e| StateError::Parse(format!("parse {}: {e}", path.display())))?;
            Ok(Some(state))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StateError::Io(format!("read {}: {e}", path.display()))),
    }
}

/// The PUBLIC half alone: the federation setup key, if this node holds a share.
///
/// This is what the federation-identity resolution
/// ([`crate::cardano::federation::resolve`]) needs — it cross-checks the
/// published key against what this node holds and never touches the secret. No
/// `state_dir` configured → `None`, the same as no ceremony having been run.
pub fn group_key(state_dir: Option<&Path>) -> Result<Option<UntweakedPublicKey>, StateError> {
    let Some(dir) = state_dir else {
        return Ok(None);
    };
    read(dir)?.map(|s| s.federation_setup_y()).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FederationConfig, FederationMemberConfig};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use frost_secp256k1_tr as frost;
    use frost_secp256k1_tr::Identifier;
    use std::collections::BTreeMap;

    fn member_key(byte: u8) -> String {
        let secp = Secp256k1::new();
        hex::encode(
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
                .x_only_public_key()
                .0
                .serialize(),
        )
    }

    fn roster(min_signers: u16, members: &[u8]) -> FederationRoster {
        FederationRoster::from_config(&FederationConfig {
            min_signers: Some(min_signers),
            members: members
                .iter()
                .map(|b| FederationMemberConfig {
                    bifrost_id_pk: member_key(*b),
                    bifrost_url: format!("http://m{b}.example:8080"),
                })
                .collect(),
        })
        .expect("valid roster")
    }

    /// A real (dealt) 2-of-2 group: the persistence layer only cares that the
    /// material round-trips, so an interactive ceremony would cost 40× here.
    fn group_keys() -> GroupKeys {
        let mut rng = rand::thread_rng();
        let (shares, pkp) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let kps: BTreeMap<Identifier, frost::keys::KeyPackage> = shares
            .into_iter()
            .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
            .collect();
        GroupKeys {
            verifying_key: *pkp.verifying_key(),
            public_key_package: pkp,
            key_package: kps.into_values().next().unwrap(),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("heimdall-fed-persist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn roundtrip_recovers_the_share_and_the_published_key() {
        let dir = temp_dir("roundtrip");
        let roster = roster(2, &[0x11, 0x22]);
        let keys = group_keys();
        let state = FederationKeyState::from_output(&roster, &keys).expect("capture");
        write(&dir, &state).expect("write");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(state_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the federation share must be 0600");
        }

        let loaded = read(&dir).expect("read").expect("present");
        assert_eq!(loaded, state);
        loaded.check_roster(&roster).expect("same federation");
        let recovered = loaded.to_group_keys().expect("group keys");
        assert_eq!(recovered.verifying_key, keys.verifying_key);
        assert_eq!(
            recovered.key_package.signing_share(),
            keys.key_package.signing_share()
        );

        // The public read used by the federation-identity resolution agrees.
        let published = group_key(Some(dir.as_path())).expect("read").expect("some");
        assert_eq!(
            hex::encode(published.serialize()),
            loaded.federation_setup_y
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A share is only valid for the federation that produced it: adding a
    /// member (or moving the threshold) must be refused, not silently used.
    #[test]
    fn a_share_from_another_federation_is_refused() {
        let state = FederationKeyState::from_output(&roster(2, &[0x11, 0x22]), &group_keys())
            .expect("capture");

        state
            .check_roster(&roster(3, &[0x11, 0x22, 0x33]))
            .expect_err("a grown federation invalidates the share");
        state
            .check_roster(&roster(2, &[0x11, 0x33]))
            .expect_err("a re-keyed member invalidates the share");

        // …but a member simply moving endpoint does not: same key, same share.
        let mut moved = FederationConfig {
            min_signers: Some(2),
            members: vec![
                FederationMemberConfig {
                    bifrost_id_pk: member_key(0x11),
                    bifrost_url: "https://relocated.example".into(),
                },
                FederationMemberConfig {
                    bifrost_id_pk: member_key(0x22),
                    bifrost_url: "http://m34.example:8080".into(),
                },
            ],
        };
        moved.members[1].bifrost_url = "http://m34.example:8080".into();
        let moved = FederationRoster::from_config(&moved).expect("valid");
        state
            .check_roster(&moved)
            .expect("a URL change is not a re-key");
    }

    /// The convenience copy of the setup key never overrides the material the
    /// node signs with — a file whose halves disagree is refused.
    #[test]
    fn an_edited_setup_key_field_is_refused() {
        let mut state = FederationKeyState::from_output(&roster(2, &[0x11, 0x22]), &group_keys())
            .expect("capture");
        state.federation_setup_y().expect("consistent as written");
        state.federation_setup_y = member_key(0x77);
        let e = state.federation_setup_y().expect_err("must refuse");
        assert!(e.to_string().contains("does not derive"), "{e}");
    }

    /// "No ceremony has run" and "we could not read the file" have different
    /// right answers; only the first is `None`.
    #[test]
    fn a_missing_file_is_none_but_a_broken_one_is_an_error() {
        let dir = temp_dir("missing");
        assert!(read(&dir).expect("missing dir is not an error").is_none());
        assert!(group_key(None).expect("no state dir").is_none());

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(state_path(&dir), b"{ not json").unwrap();
        assert!(
            read(&dir).is_err(),
            "a corrupt file must not read as absent"
        );
        assert!(group_key(Some(dir.as_path())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
