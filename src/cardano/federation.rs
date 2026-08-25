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
    /// The Config datum, and the local seed derives the same key — the strongest
    /// state for a single-key federation: the value is published AND this node
    /// can spend the recovery path by itself.
    PublishedAndHeld,
    /// The Config datum, and this node holds a SHARE of that key from the
    /// federation ceremony (WI-087). The strongest state there is: the value is
    /// published, and this node can contribute to a recovery spend — which no
    /// single member can perform alone.
    PublishedAndShared,
    /// The operator's own `[bitcoin]` keys, on a deployment with no readable
    /// Config (the fixture-roster demo).
    LocalConfig,
    /// `federation_setup_Y` — the local ceremony's group key, with no Config to
    /// read. The state a federation is in BEFORE genesis: the key exists, and the
    /// bridge that will publish it as #11 does not yet. This is the ONE window in
    /// which a local copy is authoritative; see [`crate::federation`].
    LocalDkg,
}

impl std::fmt::Display for FederationOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Published => write!(f, "published in the Config datum"),
            Self::PublishedAndHeld => write!(
                f,
                "published in the Config datum, and the local seed matches"
            ),
            Self::PublishedAndShared => write!(
                f,
                "published in the Config datum, and this node holds a share of it"
            ),
            Self::LocalConfig => write!(f, "local [bitcoin] config — no Config datum to read"),
            Self::LocalDkg => write!(
                f,
                "federation_setup_Y from the local ceremony — no Config datum to read yet"
            ),
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

impl FederationIdentity {
    /// The peg-in Taproot tree, for the paths that resolve the federation directly rather
    /// than through the treasury oracle (the CLI mover). The leaf key, its CSV delay and
    /// the refund timeout are the same published values
    /// [`crate::epoch::traits::TreasuryUtxo::pegin_tree`] uses — this exists so that
    /// mapping is written once per source, not once per call site.
    ///
    /// The INTERNAL key is where the two now differ, and deliberately: the oracle path
    /// takes it from the treasury_info datum (`authorized_key`), which is what the spec
    /// tells depositors to derive from, while this one takes the caller's because the
    /// mover derives it from the demo DKG rather than reading it off the chain.
    ///
    /// The caller is expected to build TWO trees from this — one under its own `y_51` and
    /// one under `y_fed` — because a Phase-1 bridge's peg-in address is keyed to the
    /// federation and deposits keep arriving there through a handoff. Recognising the
    /// second does not make it SWEEPABLE from a roster mover (one movement signs every
    /// input with one key package), but it is the difference between telling an operator
    /// the bridge is holding a deposit it cannot move and telling them it belongs to
    /// someone else. What neither tree covers is a rotation this path cannot see, since
    /// it never reads `authorized_key` — see WI-MA9BA. It is a demo/offline path; a mover
    /// that must not miss those should read the oracle.
    pub fn pegin_tree(
        &self,
        y_51: UntweakedPublicKey,
    ) -> Result<crate::bitcoin::taproot::PeginTreeParams, String> {
        let tree = crate::bitcoin::taproot::PeginTreeParams {
            y_51,
            y_federation: self.y_fed,
            federation_csv_blocks: self.csv_blocks,
            refund_timeout: self.pegin_refund_timeout_blocks,
        };
        tree.validate()?;
        Ok(tree)
    }
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
    /// The key this node holds is a DIFFERENT key than the chain publishes.
    /// Fatal: one of the two is wrong about which treasury this is, and
    /// continuing means signing for an address nobody else uses.
    KeyMismatch {
        source: &'static str,
        derived: String,
        published: String,
    },
    /// This node holds BOTH a `y_fed_seed_hex` and a federation ceremony share.
    /// They are different keys, so the node has two answers to "which treasury
    /// is this" — and the wrong one builds a well-formed address holding
    /// nothing.
    TwoLocalKeys { seed: String, share: String },
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
            Self::Unconfigured("y_fed_seed_hex") => {
                "no Config datum was readable and this node holds no federation key. Either \
                 point it at a bridge whose Config publishes the federation identity (#11 and \
                 params[7]); or, if you are STANDING A BRIDGE UP, run `heimdall federation-dkg` \
                 so the members generate the key together; or set bitcoin.y_fed_seed_hex to the \
                 single seed this treasury was locked with. There is no default: it is an input \
                 to the treasury ADDRESS, so a guess yields a well-formed address holding \
                 nothing"
                    .to_string()
            }
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
                 treasury. If the key came from a federation ceremony share instead, this node \
                 is pointed at a bridge some OTHER federation locked"
                    .to_string()
            }
            Self::TwoLocalKeys { .. } => {
                "a node holds ONE federation key. Either remove bitcoin.y_fed_seed_hex (the \
                 single-key federation this ceremony replaces), or point protocol.state_dir at \
                 a directory without a federation-key.json — whichever of the two belongs to \
                 the bridge this node is joining"
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
            Self::KeyMismatch {
                source,
                derived,
                published,
            } => write!(
                f,
                "{source} gives {derived} but the Config publishes {published}. These build \
                 DIFFERENT treasury addresses, so one of them is not this bridge — refusing to \
                 sign for an address the other SPOs are not using"
            ),
            Self::TwoLocalKeys { seed, share } => write!(
                f,
                "this node holds two federation keys: bitcoin.y_fed_seed_hex derives {seed} and \
                 the persisted federation ceremony share is of {share}. They lock different \
                 treasuries, so exactly one of them belongs to this bridge and nothing here can \
                 tell which"
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
    local_share_key: Option<UntweakedPublicKey>,
    published: Option<&ConfigParams>,
) -> Result<FederationIdentity, FederationError> {
    let (local_key, held) = local_key(cfg, local_share_key)?;

    match published {
        Some(c) => {
            let y_fed = UntweakedPublicKey::from_slice(&c.y_federation).map_err(|e| {
                FederationError::BadPublishedKey(format!(
                    "not a valid x-only point ({}): {e}",
                    hex::encode(c.y_federation)
                ))
            })?;
            // The one check only a key-holder can make. A node holding neither
            // the seed nor a share has nothing to compare the published key
            // against — which is precisely why what this node holds stays useful
            // after the key is on chain.
            let origin = match local_key {
                Some(derived) if derived != y_fed => {
                    return Err(FederationError::KeyMismatch {
                        source: held.source(),
                        derived: hex::encode(derived.serialize()),
                        published: hex::encode(y_fed.serialize()),
                    });
                }
                Some(_) => held.published_origin(),
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
                origin: held.local_origin(),
            })
        }
    }
}

/// Which of the two ways a node can hold the federation key it holds it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeldBy {
    /// Nothing local — this node only reads the published value.
    Nothing,
    /// `bitcoin.y_fed_seed_hex`: the whole key, in one place.
    Seed,
    /// A share from the federation ceremony (WI-087). This node can contribute
    /// to a recovery spend; it cannot make one alone, which is the point.
    Share,
}

impl HeldBy {
    fn source(self) -> &'static str {
        match self {
            Self::Nothing => "no local federation key",
            Self::Seed => "bitcoin.y_fed_seed_hex",
            Self::Share => "the persisted federation ceremony share",
        }
    }

    fn published_origin(self) -> FederationOrigin {
        match self {
            Self::Share => FederationOrigin::PublishedAndShared,
            _ => FederationOrigin::PublishedAndHeld,
        }
    }

    fn local_origin(self) -> FederationOrigin {
        match self {
            Self::Share => FederationOrigin::LocalDkg,
            _ => FederationOrigin::LocalConfig,
        }
    }
}

/// The federation key this node holds locally, and how.
///
/// Holding BOTH is refused rather than ranked. They are different keys — a
/// ceremony key is not derivable from an operator's seed — so a preference order
/// would silently pick a treasury, and the wrong pick is invisible: a
/// well-formed address that holds nothing. This is the same rule the
/// published-vs-local cross-check below applies, one level earlier.
fn local_key(
    cfg: &BitcoinConfig,
    share_key: Option<UntweakedPublicKey>,
) -> Result<(Option<UntweakedPublicKey>, HeldBy), FederationError> {
    let seed_key = configured_seed(cfg).map(y_fed_from_seed_hex).transpose()?;
    match (seed_key, share_key) {
        (Some(seed), Some(share)) => Err(FederationError::TwoLocalKeys {
            seed: hex::encode(seed.serialize()),
            share: hex::encode(share.serialize()),
        }),
        (Some(seed), None) => Ok((Some(seed), HeldBy::Seed)),
        (None, Some(share)) => Ok((Some(share), HeldBy::Share)),
        (None, None) => Ok((None, HeldBy::Nothing)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed-and-published cases, which is what most of these tests are
    /// about. A node holding a federation ceremony SHARE instead goes through
    /// `super::resolve`'s middle argument, exercised by the tests that call it
    /// directly at the bottom of this module.
    fn resolve(
        cfg: &BitcoinConfig,
        published: Option<&ConfigParams>,
    ) -> Result<FederationIdentity, FederationError> {
        super::resolve(cfg, None, published)
    }

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

    /// WI-087: a node holding a SHARE of a DKG'd federation key cross-checks the
    /// published value exactly as a seed-holder does — and reports itself as a
    /// share-holder, which is a materially different capability (it can
    /// contribute to a recovery spend, not perform one).
    #[test]
    fn a_ceremony_share_cross_checks_the_published_key_too() {
        let (_, key) = seed_and_key(0xA1);
        let share = UntweakedPublicKey::from_slice(&key).unwrap();
        let id = super::resolve(&cfg(None, None), Some(share), Some(&datum(&key, 144)))
            .expect("resolves");
        assert_eq!(id.origin, FederationOrigin::PublishedAndShared);
        assert_eq!(id.y_fed.serialize(), key);

        let (_, other) = seed_and_key(0xA2);
        let e = super::resolve(&cfg(None, None), Some(share), Some(&datum(&other, 144)))
            .expect_err("must refuse");
        assert!(
            matches!(
                e,
                FederationError::KeyMismatch {
                    source: "the persisted federation ceremony share",
                    ..
                }
            ),
            "got {e:?}"
        );
    }

    /// Before genesis there is no Config to read, and the ceremony's group key is
    /// the whole of what this node knows — the state `bootstrap-treasury` derives
    /// the genesis address in.
    #[test]
    fn a_ceremony_share_alone_is_the_pre_genesis_state() {
        let (_, key) = seed_and_key(0xA3);
        let share = UntweakedPublicKey::from_slice(&key).unwrap();
        let id = super::resolve(&cfg(None, Some(144)), Some(share), None).expect("resolves");
        assert_eq!(id.origin, FederationOrigin::LocalDkg);
        assert_eq!(id.y_fed.serialize(), key);
        assert_eq!(id.csv_blocks, 144);
    }

    /// A node holds ONE federation key. A seed beside a ceremony share is two
    /// answers to which treasury this is, and no preference order can be right —
    /// picking wrong builds a well-formed address holding nothing.
    #[test]
    fn a_seed_beside_a_ceremony_share_is_refused_not_ranked() {
        let (seed, _) = seed_and_key(0xA4);
        let (_, other) = seed_and_key(0xA5);
        let share = UntweakedPublicKey::from_slice(&other).unwrap();
        let e = super::resolve(&cfg(Some(&seed), Some(144)), Some(share), None)
            .expect_err("must refuse");
        assert!(
            matches!(e, FederationError::TwoLocalKeys { .. }),
            "got {e:?}"
        );
        assert!(
            e.fix().contains("remove bitcoin.y_fed_seed_hex"),
            "{}",
            e.fix()
        );
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
