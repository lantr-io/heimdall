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
//! Both used to be hand-copied from a bridge's deployment notes into every
//! operator's `heimdall.toml`, which is the [`crate::cardano::ban_list`] /
//! [`crate::cardano::roster`] failure mode with the treasury behind it instead of
//! the roster.
//!
//! ## They were already on chain
//!
//! Rev 5.4 published both in the `treasury_info` state datum, at fields #2/#3.
//! Rev 5.5 moved them to the **Config** datum ([CFG-6]: an identity or a key is a
//! top-level Config field, a tunable number lives in `params`):
//!
//! ```text
//! config NFT → its datum → #11  y_federation
//!                        → params[7] federation_csv_blocks
//! ```
//!
//! which is a strictly shorter path than the rev-5.4 one — heimdall reads the
//! Config on every startup regardless, so the federation identity now costs no
//! query at all, not merely no EXTRA query.
//!
//! **The load-bearing invariant moved with them, and got weaker in a good way.**
//! Under rev 5.4 these lived in state that every Update-Y spent and recreated, so
//! the treasury ADDRESS depended on two validators preserving them verbatim
//! across every rotation. In the Config they are governance data: an Update
//! rotates them deliberately, and no rotation of the FROST key can touch them by
//! accident. That is also what finally makes federation-key rotation a real
//! operation rather than a row in a permission matrix nothing implemented.
//!
//! ## The seed is not the published value
//!
//! `bitcoin.y_fed_seed_hex` is a SPENDING SECRET: `federation-spend` signs the
//! treasury's recovery path with it, and the chain carries only the derived
//! x-only public key. So a node holding the seed can do something no other reader
//! can — check that the published key derives from its seed — and that check is
//! the whole reason to keep the local key after the value is read from chain.

use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

use crate::cardano::config_params::ConfigParams;
use crate::config::BitcoinConfig;

/// Where a resolved federation identity came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationOrigin {
    /// The Config datum. Nothing to configure, nothing to mistype.
    Published,
    /// The `treasury_info` datum, and the local seed derives the same key — the
    /// strongest state: the value is published AND this node can spend the
    /// recovery path.
    PublishedAndHeld,
    /// The operator's own `[bitcoin]` keys, on a deployment with no readable
    /// `treasury_info` (the fixture-roster demo).
    LocalConfig,
}

impl std::fmt::Display for FederationOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Published => write!(f, "published in the treasury_info datum"),
            Self::PublishedAndHeld => write!(
                f,
                "published in the treasury_info datum, and the local seed matches"
            ),
            Self::LocalConfig => write!(f, "local [bitcoin] config — no treasury_info to read"),
        }
    }
}

/// The federation identity this node builds the treasury tree from.
#[derive(Debug, Clone)]
pub struct FederationIdentity {
    pub y_fed: UntweakedPublicKey,
    /// Validated to fit `u16` at construction. The relative-timelock encoding is
    /// 16-bit and every consumer casts to it, so a wider value would truncate
    /// silently into a different Taproot tree — which is exactly the class of
    /// failure this module exists to prevent. Checked once, here, where the value
    /// enters the system.
    pub csv_blocks: u16,
    /// The peg-in refund leaf's CSV delay — Config `params[8]` ([CFG-9]). Carried
    /// here because it is the same kind of value as `csv_blocks`: a block count
    /// hashed into a Taproot tree, so it decides an address and must be unanimous.
    /// Published-wins with the same fatal cross-check against a local override.
    pub pegin_refund_timeout_blocks: u16,
    pub origin: FederationOrigin,
}

#[derive(Debug)]
pub enum FederationError {
    /// Nothing published and nothing configured. Refusing beats guessing: any
    /// default derives a well-formed address that holds nothing.
    Unconfigured(&'static str),
    /// The local seed is not 32 bytes of hex, or is not a valid secp256k1 key.
    BadSeed(String),
    /// The published key is not a valid x-only point.
    BadPublishedKey(String),
    /// A CSV delay outside the 16-bit relative-timelock encoding, or zero.
    BadCsvBlocks { value: i64, source: &'static str },
    /// The seed this node holds derives a DIFFERENT key than the chain
    /// publishes. Fatal: one of the two is wrong about which treasury this is,
    /// and continuing means signing for an address nobody else uses.
    KeyMismatch { derived: String, published: String },
    /// The operator's CSV delay contradicts the published one. Same reasoning —
    /// it is an input to the same address.
    CsvMismatch { local: u32, published: u16 },
    /// A local `pegin_refund_timeout_blocks` disagrees with the Config's [CFG-9]
    /// value. Fatal for the same reason as `CsvMismatch`: it is an input to every
    /// deposit address, so the two produce different peg-in sets.
    RefundTimeoutMismatch { local: u16, published: u16 },
    /// The refund window would open before the federation's sweep, letting a
    /// depositor take the deposit back while the federation is still recovering it.
    RefundTimeoutTooShort { refund: u16, csv: u16 },
}

impl FederationError {
    /// What the operator should actually do — per variant, because the right
    /// action differs sharply: `Unconfigured` needs the keys SET, a mismatch
    /// needs them removed or the node repointed.
    #[must_use]
    pub fn fix(&self) -> String {
        match self {
            Self::Unconfigured(what) => format!(
                "no Config datum was readable and bitcoin.{what} is unset. Either point \
                 this node at a bridge whose Config publishes the federation identity (#11 and \
                 params[7]), or set bitcoin.{what} to the value \
                 this treasury was locked with. There is no default: it is an input to the \
                 treasury ADDRESS, so a guess yields a well-formed address holding nothing"
            ),
            Self::BadSeed(_) => "bitcoin.y_fed_seed_hex must be 32 bytes of hex. Only a node \
                 that performs federation SPENDS needs it at all — every other node reads the \
                 public key from the Config datum, so the fix may be to remove the key"
                .to_string(),
            Self::BadPublishedKey(_) | Self::BadCsvBlocks { .. } => {
                "the Config datum on chain does not carry a usable federation identity. \
                 This is bridge state, not operator config — check that cardano.config_address \
                 and cardano.config_nft_policy_id name the bridge you meant to join"
                    .to_string()
            }
            Self::KeyMismatch { .. }
            | Self::CsvMismatch { .. }
            | Self::RefundTimeoutMismatch { .. } => {
                "remove bitcoin.y_fed_seed_hex / bitcoin.federation_csv_blocks / \
                 bitcoin.pegin_refund_timeout_blocks to use what the bridge publishes, or point \
                 this node at the bridge those values belong to. Keep the seed ONLY if this \
                 node performs federation spends, in which case it must be the seed for THIS \
                 treasury"
                    .to_string()
            }
            Self::RefundTimeoutTooShort { .. } => {
                "the peg-in refund window must open AFTER the federation's sweep window, or a \
                 depositor can take the deposit back while the federation is still recovering \
                 it. Raise bitcoin.pegin_refund_timeout_blocks above \
                 bitcoin.federation_csv_blocks — or unset both and use what the bridge publishes"
                    .to_string()
            }
        }
    }
}

impl std::fmt::Display for FederationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconfigured(what) => write!(
                f,
                "no federation {what}: nothing published, nothing configured"
            ),
            Self::BadSeed(e) => write!(f, "bitcoin.y_fed_seed_hex: {e}"),
            Self::BadPublishedKey(e) => write!(f, "Config #11 y_federation: {e}"),
            Self::BadCsvBlocks { value, source } => write!(
                f,
                "federation_csv_blocks {value} ({source}) is not a usable relative timelock — \
                 it must be 1..={}. A wider value truncates into a different Taproot tree",
                u16::MAX
            ),
            Self::KeyMismatch { derived, published } => write!(
                f,
                "bitcoin.y_fed_seed_hex derives {derived} but the Config publishes \
                 {published}. These build DIFFERENT treasury addresses, so one of them is not \
                 this bridge — refusing to sign for an address the other SPOs are not using"
            ),
            Self::CsvMismatch { local, published } => write!(
                f,
                "bitcoin.federation_csv_blocks is {local} but the Config publishes \
                 {published}. The delay is an input to the treasury address, so these build \
                 different ones"
            ),
            Self::RefundTimeoutMismatch { local, published } => write!(
                f,
                "bitcoin.pegin_refund_timeout_blocks is {local} but the Config publishes \
                 {published}. The delay is hashed into every peg-in deposit address, so these \
                 reconstruct different ones and freeze different peg-in sets"
            ),
            Self::RefundTimeoutTooShort { refund, csv } => write!(
                f,
                "pegin_refund_timeout_blocks ({refund}) must exceed federation_csv_blocks \
                 ({csv}): the federation's sweep window has to open before the depositor's \
                 refund does"
            ),
        }
    }
}

impl std::error::Error for FederationError {}

/// Parse a 32-byte hex seed into its secp256k1 keypair.
///
/// The single parser for this value: `federation-spend`, `bootstrap-treasury`,
/// the depositor demo and the cross-check below all route through it, so a fix
/// to the parsing (the `trim`, say) cannot reach some callers and miss others.
pub fn keypair_from_seed_hex(seed_hex: &str) -> Result<Keypair, FederationError> {
    let bytes = hex::decode(seed_hex.trim())
        .map_err(|e| FederationError::BadSeed(format!("not valid hex: {e}")))?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| FederationError::BadSeed(format!("must be 32 bytes, got {}", bytes.len())))?;
    let sk = SecretKey::from_slice(&seed)
        .map_err(|e| FederationError::BadSeed(format!("not a valid secp256k1 key: {e}")))?;
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &sk))
}

/// Derive the x-only federation public key from a 32-byte hex seed.
pub fn y_fed_from_seed_hex(seed_hex: &str) -> Result<UntweakedPublicKey, FederationError> {
    Ok(keypair_from_seed_hex(seed_hex)?.x_only_public_key().0)
}

/// The operator's configured seed, treating blank as ABSENT.
///
/// A commented-out template line uncommented to `""` is the likeliest way to end
/// up here, and it means "I did not set this", not "here is a zero-length seed".
fn configured_seed(cfg: &BitcoinConfig) -> Option<&str> {
    cfg.y_fed_seed_hex
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn csv_u16(value: i64, source: &'static str) -> Result<u16, FederationError> {
    if value <= 0 {
        return Err(FederationError::BadCsvBlocks { value, source });
    }
    u16::try_from(value).map_err(|_| FederationError::BadCsvBlocks { value, source })
}

/// Decide which federation identity this node uses.
///
/// The published value WINS wherever both exist; the local one becomes a
/// cross-check, and a disagreement is fatal rather than silently resolved. That
/// is the WI-068 shape, for the same reason: a value that must match across every
/// SPO has no business being decided per-operator, and the failure it produces is
/// invisible — a well-formed address holding nothing.
///
/// `published` is `None` only when there is genuinely no Config to read (the
/// fixture-roster demo). A FAILED read must never be passed as `None`: "the
/// bridge publishes nothing" and "we could not ask" have different right answers,
/// and taking the local value on the second reintroduces exactly the per-operator
/// divergence this replaces.
pub fn resolve(
    cfg: &BitcoinConfig,
    published: Option<&ConfigParams>,
) -> Result<FederationIdentity, FederationError> {
    let local_key = configured_seed(cfg).map(y_fed_from_seed_hex).transpose()?;

    match published {
        Some(c) => {
            let y_fed = UntweakedPublicKey::from_slice(&c.y_federation).map_err(|e| {
                FederationError::BadPublishedKey(format!(
                    "not a valid x-only point ({}): {e}",
                    hex::encode(c.y_federation)
                ))
            })?;
            // The one check only a seed-holder can make. A node without the seed
            // has nothing to compare the published key against — which is
            // precisely why the seed stays useful after the key is on chain.
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
            let published_csv = c.tunables.federation_csv_blocks;
            if let Some(local_csv) = cfg.federation_csv_blocks
                && u32::from(published_csv) != local_csv
            {
                return Err(FederationError::CsvMismatch {
                    local: local_csv,
                    published: published_csv,
                });
            }
            let published_refund = c.tunables.pegin_refund_timeout_blocks;
            if let Some(local_refund) = cfg.pegin_refund_timeout_blocks
                && local_refund != published_refund
            {
                return Err(FederationError::RefundTimeoutMismatch {
                    local: local_refund,
                    published: published_refund,
                });
            }
            // parse_config_datum already refused a zero or out-of-range value, and
            // enforced refund > csv, so no second check is needed here.
            Ok(FederationIdentity {
                y_fed,
                csv_blocks: published_csv,
                pegin_refund_timeout_blocks: published_refund,
                origin,
            })
        }
        None => {
            let y_fed = local_key.ok_or(FederationError::Unconfigured("y_fed_seed_hex"))?;
            let csv = cfg
                .federation_csv_blocks
                .ok_or(FederationError::Unconfigured("federation_csv_blocks"))?;
            let csv_blocks = csv_u16(i64::from(csv), "bitcoin.federation_csv_blocks")?;
            let refund = cfg
                .pegin_refund_timeout_blocks
                .ok_or(FederationError::Unconfigured("pegin_refund_timeout_blocks"))?;
            if refund <= csv_blocks {
                return Err(FederationError::RefundTimeoutTooShort {
                    refund,
                    csv: csv_blocks,
                });
            }
            Ok(FederationIdentity {
                y_fed,
                csv_blocks,
                pegin_refund_timeout_blocks: refund,
                origin: FederationOrigin::LocalConfig,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_and_key(byte: u8) -> (String, [u8; 32]) {
        let seed = hex::encode([byte; 32]);
        let key = y_fed_from_seed_hex(&seed).expect("valid seed").serialize();
        (seed, key)
    }

    fn cfg(seed: Option<&str>, csv: Option<u32>) -> BitcoinConfig {
        BitcoinConfig {
            y_fed_seed_hex: seed.map(str::to_string),
            federation_csv_blocks: csv,
            // The unpublished path needs it locally, and it must exceed `csv`.
            pegin_refund_timeout_blocks: csv.map(|c| (c as u16).saturating_add(576)),
            ..BitcoinConfig::default()
        }
    }

    /// A Config publishing the federation identity: #11 `y_federation` and
    /// `params[7]` `federation_csv_blocks`. Rev 5.5 moved both here from the
    /// `treasury_info` datum ([CFG-6]).
    fn datum(key: &[u8], csv: u16) -> ConfigParams {
        let mut c = crate::cardano::config_params::test_config_params();
        c.y_federation = key.try_into().expect("32-byte x-only key");
        c.tunables.federation_csv_blocks = csv;
        c
    }

    /// The acceptance condition of WI-069: an SPO joining a bridge whose
    /// treasury_info is readable configures NEITHER value.
    #[test]
    fn published_alone_needs_no_local_config() {
        let (_, key) = seed_and_key(0x11);
        let id = resolve(&cfg(None, None), Some(&datum(&key, 144))).expect("resolves");
        assert_eq!(id.y_fed.serialize(), key);
        assert_eq!(id.csv_blocks, 144);
        assert_eq!(id.origin, FederationOrigin::Published);
    }

    #[test]
    fn a_seed_holder_that_agrees_is_the_strongest_state() {
        let (seed, key) = seed_and_key(0x22);
        let id = resolve(&cfg(Some(&seed), Some(144)), Some(&datum(&key, 144))).expect("agrees");
        assert_eq!(id.origin, FederationOrigin::PublishedAndHeld);
        assert_eq!(id.y_fed.serialize(), key);
    }

    /// The whole reason the local seed is kept: only a node holding it can tell
    /// that the bridge it is pointed at is not its bridge.
    #[test]
    fn a_seed_deriving_another_key_is_fatal_not_a_warning() {
        let (seed, _) = seed_and_key(0x33);
        let (_, other) = seed_and_key(0x44);
        let e =
            resolve(&cfg(Some(&seed), None), Some(&datum(&other, 144))).expect_err("must refuse");
        assert!(
            matches!(e, FederationError::KeyMismatch { .. }),
            "got {e:?}"
        );
        assert!(e.to_string().contains("DIFFERENT treasury addresses"));
    }

    #[test]
    fn a_contradicting_csv_delay_is_fatal_too() {
        let (seed, key) = seed_and_key(0x55);
        let e = resolve(&cfg(Some(&seed), Some(1000)), Some(&datum(&key, 144)))
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

    /// A deployment with no readable treasury_info (the fixture demo) keeps
    /// working off local config.
    #[test]
    fn unpublished_falls_back_to_the_local_values() {
        let (seed, key) = seed_and_key(0x66);
        let id = resolve(&cfg(Some(&seed), Some(288)), None).expect("resolves");
        assert_eq!(id.origin, FederationOrigin::LocalConfig);
        assert_eq!(id.y_fed.serialize(), key);
        assert_eq!(id.csv_blocks, 288);
        assert_eq!(id.pegin_refund_timeout_blocks, 864);
    }

    /// A local refund delay that disagrees with the published one is FATAL, for the same
    /// reason a CSV mismatch is: it is hashed into every deposit address, so the two nodes
    /// reconstruct different ones and freeze different peg-in sets.
    #[test]
    fn a_local_refund_timeout_that_contradicts_the_published_one_is_fatal() {
        let (seed, key) = seed_and_key(0x66);
        let mut c = cfg(Some(&seed), Some(144));
        c.pegin_refund_timeout_blocks = Some(999);
        let published = datum(&key, 144);
        let e = resolve(&c, Some(&published)).unwrap_err();
        assert!(
            matches!(e, FederationError::RefundTimeoutMismatch { local: 999, .. }),
            "got {e:?}"
        );
    }

    /// A refund window opening before the federation's sweep is refused outright.
    #[test]
    fn a_refund_window_that_opens_before_the_federation_sweep_is_refused() {
        let (seed, _) = seed_and_key(0x66);
        let mut c = cfg(Some(&seed), Some(720));
        c.pegin_refund_timeout_blocks = Some(144);
        let e = resolve(&c, None).unwrap_err();
        assert!(
            matches!(
                e,
                FederationError::RefundTimeoutTooShort {
                    refund: 144,
                    csv: 720
                }
            ),
            "got {e:?}"
        );
    }

    /// The case that used to silently derive a well-formed treasury address
    /// nobody else uses, because `y_fed_seed_hex` defaulted to 0xFE×32 and
    /// `federation_csv_blocks` to 144.
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

    /// A blank value is the shape an operator gets by uncommenting the template's
    /// own `#y_fed_seed_hex = ""` line. It means unset, not "a zero-length seed".
    #[test]
    fn a_blank_seed_reads_as_unset_not_as_a_bad_seed() {
        let (_, key) = seed_and_key(0x88);
        let id = resolve(&cfg(Some("   "), None), Some(&datum(&key, 144))).expect("resolves");
        assert_eq!(id.origin, FederationOrigin::Published);
        let e = resolve(&cfg(Some(""), None), None).expect_err("must refuse");
        assert!(
            matches!(e, FederationError::Unconfigured("y_fed_seed_hex")),
            "got {e:?}"
        );
    }

    #[test]
    fn a_malformed_seed_is_named_not_ignored() {
        for bad in ["nothex", "aabb"] {
            let e = resolve(&cfg(Some(bad), Some(144)), None).expect_err("must refuse");
            assert!(matches!(e, FederationError::BadSeed(_)), "{bad}: got {e:?}");
        }
    }

    /// x-only keys are 32 bytes, but not every 32 bytes is a curve point.
    #[test]
    fn a_published_key_that_is_not_a_point_is_refused() {
        let e = resolve(&cfg(None, Some(144)), Some(&datum(&[0xFF; 32], 144)))
            .expect_err("must refuse");
        assert!(
            matches!(e, FederationError::BadPublishedKey(_)),
            "got {e:?}"
        );
    }

    /// The 16-bit range check moved to where the value now ENTERS: rev 5.5
    /// publishes `federation_csv_blocks` in the Config datum, so
    /// `parse_config_datum` refuses a zero or truncating value and this function
    /// receives a `u16` that is already known good. The tests moved with it —
    /// see `config_params::tests::a_csv_delay_that_would_truncate_is_refused`.
    #[test]
    fn a_published_csv_delay_is_already_range_checked() {
        let (_, key) = seed_and_key(0x99);
        let id = resolve(&cfg(None, None), Some(&datum(&key, 65_535))).expect("resolves");
        assert_eq!(id.csv_blocks, 65_535);
    }

    /// Every variant carries its own remedy. The `Unconfigured` one is the trap:
    /// the fix there is to SET the keys, the opposite of the mismatch fixes.
    #[test]
    fn the_fix_text_matches_the_variant() {
        let unconfigured = resolve(&cfg(None, None), None).expect_err("refuses");
        assert!(
            unconfigured.fix().contains("set bitcoin."),
            "{}",
            unconfigured.fix()
        );
        assert!(!unconfigured.fix().contains("remove bitcoin."));

        let (seed, _) = seed_and_key(0xBB);
        let (_, other) = seed_and_key(0xCC);
        let mismatch =
            resolve(&cfg(Some(&seed), None), Some(&datum(&other, 144))).expect_err("refuses");
        assert!(
            mismatch.fix().contains("remove bitcoin."),
            "{}",
            mismatch.fix()
        );
    }
}
