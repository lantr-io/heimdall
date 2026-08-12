//! Where the treasury's federation identity comes from (WI-069).
//!
//! `Y_federation` and the recovery leaf's CSV delay decide the Bitcoin treasury
//! ADDRESS. `Y_51` rotates every epoch with the DKG and reaches each SPO over the
//! authenticated wire, but the federation leaf does not rotate: every node
//! rebuilds the Taproot tree locally from these two constants. A node holding a
//! different value for either derives a different scriptPubKey, signs a different
//! BIP-341 sighash, and contributes a FROST share over a message no other signer
//! produced. Nothing errors, because the address it derived is perfectly
//! well-formed — it is just not the one the BTC is in.
//!
//! Before WI-069 both were hand-copied from a bridge's deployment notes into
//! every operator's `heimdall.toml`, which is the [`crate::cardano::ban_list`] /
//! [`crate::cardano::roster`] failure mode with the treasury behind it instead of
//! the roster. [CFG-4] publishes them at Config #15–#16, so this module answers
//! one question: given what the bridge publishes and what the operator typed,
//! which values does this node use — and when do they disagree badly enough to
//! refuse to run?
//!
//! ## The seed is not the published value
//!
//! `bitcoin.y_fed_seed_hex` is a SPENDING SECRET: `federation-spend` signs the
//! treasury's recovery path with it. The Config carries only the derived x-only
//! public key. So a node holding the seed can do something no other reader can —
//! check that the published key derives from its seed — and that check is the
//! whole point of keeping the local key around after the value is published.

use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

use crate::cardano::config_params::FederationParams;
use crate::config::BitcoinConfig;

/// Where a resolved federation identity came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationOrigin {
    /// Config #15–#16. Nothing to configure, nothing to mistype.
    Published,
    /// Config #15–#16, and the local seed derives the same key — the strongest
    /// state: the value is published AND this node can spend the recovery path.
    PublishedAndHeld,
    /// The operator's own `[bitcoin]` keys, on a bridge deployed before [CFG-4].
    LocalConfig,
}

impl std::fmt::Display for FederationOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Published => write!(f, "published at Config #15-#16"),
            Self::PublishedAndHeld => {
                write!(f, "published at Config #15-#16, and the local seed matches")
            }
            Self::LocalConfig => write!(f, "local [bitcoin] config — the bridge publishes neither"),
        }
    }
}

/// The federation identity this node builds the treasury tree from.
#[derive(Debug, Clone)]
pub struct FederationIdentity {
    pub y_fed: UntweakedPublicKey,
    pub csv_blocks: u32,
    pub origin: FederationOrigin,
}

#[derive(Debug)]
pub enum FederationError {
    /// Neither the Config nor the operator supplies the value. Refusing beats
    /// guessing: any default derives a well-formed address that holds nothing.
    Unconfigured(&'static str),
    /// The local seed is not 32 bytes of hex, or is not a valid secp256k1 key.
    BadSeed(String),
    /// The published key is not a valid x-only point.
    BadPublishedKey(String),
    /// The seed this node holds derives a DIFFERENT key than the bridge
    /// publishes. Fatal: one of the two is wrong about which treasury this is,
    /// and continuing means signing for an address nobody else is using.
    KeyMismatch { derived: String, published: String },
    /// The operator's CSV delay contradicts the published one. Same reasoning —
    /// it is an input to the same address.
    CsvMismatch { local: u32, published: u32 },
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconfigured(what) => write!(
                f,
                "no federation {what}: this bridge's Config does not publish one (it predates \
                 [CFG-4]) and bitcoin.{what} is unset. It is an input to the treasury ADDRESS, \
                 so there is no safe default — copy it from the bridge's deployment notes"
            ),
            Self::BadSeed(e) => write!(f, "bitcoin.y_fed_seed_hex: {e}"),
            Self::BadPublishedKey(e) => write!(f, "config #15 (y_federation_pubkey): {e}"),
            Self::KeyMismatch { derived, published } => write!(
                f,
                "bitcoin.y_fed_seed_hex derives {derived} but the bridge publishes {published} \
                 at Config #15. These build DIFFERENT treasury addresses, so one of them is not \
                 this bridge — refusing to sign for an address the other SPOs are not using. \
                 Remove the seed to use the published key, or point this node at the bridge the \
                 seed belongs to"
            ),
            Self::CsvMismatch { local, published } => write!(
                f,
                "bitcoin.federation_csv_blocks is {local} but the bridge publishes {published} \
                 at Config #16. The delay is an input to the treasury address, so these build \
                 different ones — remove the local value to use what the bridge publishes"
            ),
        }
    }
}

impl std::error::Error for FederationError {}

/// Derive the x-only federation public key from a 32-byte hex seed.
pub fn y_fed_from_seed_hex(seed_hex: &str) -> Result<UntweakedPublicKey, FederationError> {
    let bytes = hex::decode(seed_hex.trim())
        .map_err(|e| FederationError::BadSeed(format!("not valid hex: {e}")))?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| FederationError::BadSeed(format!("must be 32 bytes, got {}", bytes.len())))?;
    let sk = SecretKey::from_slice(&seed)
        .map_err(|e| FederationError::BadSeed(format!("not a valid secp256k1 key: {e}")))?;
    let secp = Secp256k1::new();
    Ok(sk.x_only_public_key(&secp).0)
}

/// Decide which federation identity this node uses.
///
/// The published value WINS wherever both exist; the local one becomes a
/// cross-check, and a disagreement is fatal rather than silently resolved. That
/// is the [WI-068] shape, and for the same reason: a value that must match
/// across every SPO has no business being decided per-operator, and the failure
/// it produces is invisible — a well-formed address holding nothing.
pub fn resolve(
    cfg: &BitcoinConfig,
    published: Option<&FederationParams>,
) -> Result<FederationIdentity, FederationError> {
    let local_key = cfg
        .y_fed_seed_hex
        .as_deref()
        .map(y_fed_from_seed_hex)
        .transpose()?;

    match published {
        Some(p) => {
            let y_fed = UntweakedPublicKey::from_slice(&p.y_federation_pubkey).map_err(|e| {
                FederationError::BadPublishedKey(format!(
                    "not a valid x-only point ({}): {e}",
                    hex::encode(p.y_federation_pubkey)
                ))
            })?;
            // The one check only a seed-holder can make. A node without the seed
            // cannot verify the published key against anything — there is
            // nothing to compare it to — which is exactly why the seed stays
            // useful after the key is published.
            let origin = match local_key {
                Some(derived) if derived != y_fed => {
                    return Err(FederationError::KeyMismatch {
                        derived: hex::encode(derived.serialize()),
                        published: hex::encode(y_fed.serialize()),
                    });
                }
                Some(_) => FederationOrigin::PublishedAndHeld,
                None => FederationOrigin::Published,
            };
            if let Some(local_csv) = cfg.federation_csv_blocks
                && local_csv != p.federation_csv_blocks
            {
                return Err(FederationError::CsvMismatch {
                    local: local_csv,
                    published: p.federation_csv_blocks,
                });
            }
            Ok(FederationIdentity {
                y_fed,
                csv_blocks: p.federation_csv_blocks,
                origin,
            })
        }
        None => Ok(FederationIdentity {
            y_fed: local_key.ok_or(FederationError::Unconfigured("y_fed_seed_hex"))?,
            csv_blocks: cfg
                .federation_csv_blocks
                .ok_or(FederationError::Unconfigured("federation_csv_blocks"))?,
            origin: FederationOrigin::LocalConfig,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seed and the x-only key it derives. Fixed so the tests state a real
    /// secp256k1 relationship rather than a made-up pair.
    fn seed_and_key(byte: u8) -> (String, [u8; 32]) {
        let seed = hex::encode([byte; 32]);
        let key = y_fed_from_seed_hex(&seed).expect("valid seed").serialize();
        (seed, key)
    }

    fn cfg(seed: Option<&str>, csv: Option<u32>) -> BitcoinConfig {
        BitcoinConfig {
            y_fed_seed_hex: seed.map(str::to_string),
            federation_csv_blocks: csv,
            ..BitcoinConfig::default()
        }
    }

    fn published(key: [u8; 32], csv: u32) -> FederationParams {
        FederationParams {
            y_federation_pubkey: key,
            federation_csv_blocks: csv,
        }
    }

    #[test]
    fn published_alone_needs_no_local_config() {
        let (_, key) = seed_and_key(0x11);
        let id = resolve(&cfg(None, None), Some(&published(key, 144))).expect("resolves");
        assert_eq!(id.y_fed.serialize(), key);
        assert_eq!(id.csv_blocks, 144);
        assert_eq!(id.origin, FederationOrigin::Published);
    }

    /// The acceptance condition of WI-069: an SPO joining a published bridge
    /// configures NEITHER value.
    #[test]
    fn a_seed_holder_that_agrees_is_the_strongest_state() {
        let (seed, key) = seed_and_key(0x22);
        let id = resolve(&cfg(Some(&seed), Some(144)), Some(&published(key, 144))).expect("agrees");
        assert_eq!(id.origin, FederationOrigin::PublishedAndHeld);
        assert_eq!(id.y_fed.serialize(), key);
    }

    /// The whole reason the local seed is kept as a cross-check: only a node
    /// holding it can tell that the bridge it is pointed at is not its bridge.
    #[test]
    fn a_seed_deriving_another_key_is_fatal_not_a_warning() {
        let (seed, _) = seed_and_key(0x33);
        let (_, other) = seed_and_key(0x44);
        let e = resolve(&cfg(Some(&seed), None), Some(&published(other, 144)))
            .expect_err("must refuse");
        assert!(
            matches!(e, FederationError::KeyMismatch { .. }),
            "got {e:?}"
        );
        assert!(e.to_string().contains("DIFFERENT treasury addresses"));
    }

    #[test]
    fn a_contradicting_csv_delay_is_fatal_too() {
        let (seed, key) = seed_and_key(0x55);
        let e = resolve(&cfg(Some(&seed), Some(1000)), Some(&published(key, 144)))
            .expect_err("must refuse");
        assert!(
            matches!(
                e,
                FederationError::CsvMismatch {
                    local: 1000,
                    published: 144
                }
            ),
            "got {e:?}"
        );
    }

    /// A bridge deployed before [CFG-4] keeps working off local config.
    #[test]
    fn unpublished_falls_back_to_the_local_values() {
        let (seed, key) = seed_and_key(0x66);
        let id = resolve(&cfg(Some(&seed), Some(288)), None).expect("resolves");
        assert_eq!(id.origin, FederationOrigin::LocalConfig);
        assert_eq!(id.y_fed.serialize(), key);
        assert_eq!(id.csv_blocks, 288);
    }

    /// No published value and no local one: the case that used to silently
    /// derive a well-formed treasury address nobody else uses, because
    /// `y_fed_seed_hex` defaulted to 0xFE×32 and `federation_csv_blocks` to 144.
    #[test]
    fn nothing_anywhere_is_an_error_never_a_default() {
        let e = resolve(&cfg(None, None), None).expect_err("must refuse");
        assert!(
            matches!(e, FederationError::Unconfigured("y_fed_seed_hex")),
            "got {e:?}"
        );
        let (seed, _) = seed_and_key(0x77);
        let e = resolve(&cfg(Some(&seed), None), None).expect_err("must refuse");
        assert!(
            matches!(e, FederationError::Unconfigured("federation_csv_blocks")),
            "got {e:?}"
        );
    }

    #[test]
    fn a_malformed_seed_is_named_not_ignored() {
        for bad in ["nothex", "aabb", ""] {
            let e = resolve(&cfg(Some(bad), Some(144)), None).expect_err("must refuse");
            assert!(matches!(e, FederationError::BadSeed(_)), "{bad}: got {e:?}");
        }
    }

    /// x-only keys are 32 bytes but not every 32 bytes is a curve point.
    #[test]
    fn a_published_key_that_is_not_a_point_is_refused() {
        let e = resolve(&cfg(None, Some(144)), Some(&published([0xFF; 32], 144)))
            .expect_err("must refuse");
        assert!(
            matches!(e, FederationError::BadPublishedKey(_)),
            "got {e:?}"
        );
    }
}
