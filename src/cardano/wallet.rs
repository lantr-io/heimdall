//! The node's Cardano wallet: one signing key and the address its funds are at.
//!
//! Two ways in, and exactly one must resolve — see [`resolve_wallet`].
//!
//! - a **BIP-39 mnemonic**, from which the external payment key
//!   (`m/1852'/1815'/0'/0/0`) and staking key (`m/1852'/1815'/0'/2/0`) are
//!   derived Icarus-style, and the CIP-1852 base address built from both. The
//!   key is an **extended** ed25519 key, as every Cardano HD wallet uses.
//! - a **cardano-cli `payment.skey`** plus the address to use it at. The
//!   signing key is whatever the envelope holds — a plain 32-byte ed25519
//!   secret or the extended BIP32 form — and the address is the operator's,
//!   checked against the key rather than trusted.
//!
//! The network tag comes from the config, through `is_mainnet()`, and not from
//! a constant here. Every other address this node derives already honours it;
//! the wallet address was the one that did not, which made mainnet impossible.

use pallas_addresses::{
    Address, Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart,
};
use pallas_wallet::{PrivateKey, hd::Bip32PrivateKey};

use crate::cardano::hash::blake2b_224;
use zeroize::Zeroizing;

use crate::config::CardanoConfig;

/// The node's wallet: what signs, where the funds are, and which config key
/// said so.
pub struct Wallet {
    pub key: PrivateKey,
    /// Bech32. Every builder spends from it, pays change back to it, and every
    /// UTxO query reads it.
    pub address: String,
    /// Which config key supplied the signing key. `doctor` and preflight step
    /// 1 report it, so an operator can see WHICH of the two ways in is live
    /// rather than inferring it.
    pub source: &'static str,
}

/// Redacts the key. `pallas_wallet::PrivateKey` is deliberately not `Debug`,
/// and a wrapper that quietly restored it would put a signing key one
/// `{:?}` away from the journal.
impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("key", &"<redacted>")
            .field("address", &self.address)
            .field("source", &self.source)
            .finish()
    }
}

/// Resolve the node's wallet from config, or say precisely what is missing.
///
/// The single funnel: `resolve_mnemonic` + `derive_payment_key` +
/// `wallet_address_from_mnemonic` used to be repeated at every call site, and
/// preflight answered "where is the wallet from" with a second implementation.
/// Two answers to that question is how they drift apart.
///
/// The "both are set" case is refused earlier, at config load, where it is
/// static. This is where "neither" surfaces, because `$HEIMDALL_MNEMONIC` is
/// invisible to the TOML parser and plenty of commands need no wallet at all.
pub fn resolve_wallet(cfg: &CardanoConfig) -> Result<Wallet, String> {
    resolve_wallet_from(cfg, std::env::var("HEIMDALL_MNEMONIC").ok())
}

/// The resolver proper, with the environment passed IN rather than read.
///
/// The seam exists for the tests. `$HEIMDALL_MNEMONIC` is process-global and
/// cargo runs tests on parallel threads, so a test that removed it to assert
/// "no wallet key" raced every other test reading it — and `set_var` /
/// `remove_var` beside a concurrent `var` is undefined behaviour, not merely
/// flaky. Passing the value makes every test deterministic on a box where an
/// operator has the variable exported, which on an SPO host is the norm.
pub fn resolve_wallet_from(
    cfg: &CardanoConfig,
    env_mnemonic: Option<String>,
) -> Result<Wallet, String> {
    // The authoritative "exactly one" check. `refuse_ambiguous_wallet_key`
    // makes the same call at config load, which is where an operator wants to
    // hear it — but the load-time check sees only the TOML, and `run-spo`
    // injects `--cardano-mnemonic` and `$HEIMDALL_MNEMONIC` into the config
    // AFTER it. Without this, migrating to a skey while leaving the mnemonic
    // in /etc/default/heimdall silently resolved to the skey.
    let mnemonic = mnemonic_from(cfg, env_mnemonic);
    let skey_path = cfg
        .payment_skey_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    if let (Some(path), Some((_, src))) = (skey_path, mnemonic.as_ref()) {
        return Err(format!(
            "two wallet keys: cardano.payment_skey_path ({path}) and a mnemonic from {src}. \
             They are alternatives — heimdall has one wallet, and choosing by precedence \
             would sign from an address you were not expecting. Remove one"
        ));
    }

    if let Some(path) = skey_path {
        let key = payment_key_from_skey_file(path)?;
        let address = cfg.wallet_address.clone().ok_or_else(|| {
            "cardano.payment_skey_path is set but cardano.wallet_address is not — a \
             signing key does not say where the funds are, and an SPO's usually sit at a \
             base address whose stake half is not in the key"
                .to_string()
        })?;
        // No `is_mainnet()` here: this path never derives an address, so a
        // config that cannot resolve its network is still perfectly usable.
        // The address carries its own tag, and `network_from_address` is what
        // the builders read downstream — but check it against the config where
        // the config has an opinion, since a testnet address on a mainnet node
        // would silently retag every script address derived from it.
        let address = checked_address(cfg, &address, &key)?;
        return Ok(Wallet {
            key,
            address,
            source: "cardano.payment_skey_path",
        });
    }

    let (mnemonic, source) = mnemonic.ok_or_else(|| {
        "no wallet key: set cardano.payment_skey_path (with cardano.wallet_address), \
         or cardano.mnemonic, or $HEIMDALL_MNEMONIC"
            .to_string()
    })?;
    let key = derive_payment_key(&mnemonic)?;
    // Deriving DOES need the network, and guessing is the bug this replaced.
    let network = if cfg.is_mainnet()? {
        Network::Mainnet
    } else {
        Network::Testnet
    };
    let derived = wallet_address_from_mnemonic(&mnemonic, network)?;
    // A configured address alongside a mnemonic is a cross-check, not an
    // override: it must be the SAME address. Accepting any address with a
    // matching payment credential would let an enterprise address — which
    // `cardano-cli address build` happily produces from payment.vkey alone —
    // move the node off the base address holding its funds.
    // Canonicalize before comparing, so an uppercase paste of the RIGHT
    // address is not reported as the wrong one.
    if let Some(addr) = cfg.wallet_address.as_deref() {
        let canonical = checked_address(cfg, addr, &key)?;
        if canonical != derived {
            return Err(format!(
                "cardano.wallet_address {addr} is not the address this mnemonic derives \
                 ({derived}). With a mnemonic the key is a cross-check, not an override — \
                 an address over the same payment key but a different (or absent) stake \
                 part is a different wallet, and it is not the one holding your funds"
            ));
        }
    }
    Ok(Wallet {
        key,
        address: derived,
        source,
    })
}

/// The mnemonic and which key supplied it. `cardano.mnemonic` wins over the
/// environment, as it always has.
///
/// An EMPTY value is no value, on both branches. The shipped
/// `deploy/debian/heimdall.toml` offers `#mnemonic = ""` as the line to
/// uncomment, so an operator who uncomments it and then configures a key file
/// would otherwise be refused for setting "two wallet keys", one of which is
/// a blank string.
fn mnemonic_from(
    cfg: &CardanoConfig,
    env_mnemonic: Option<String>,
) -> Option<(String, &'static str)> {
    if let Some(m) = cfg.mnemonic.clone()
        && !m.trim().is_empty()
    {
        return Some((m, "cardano.mnemonic"));
    }
    match env_mnemonic {
        Some(v) if !v.trim().is_empty() => Some((v, "$HEIMDALL_MNEMONIC")),
        _ => None,
    }
}

/// Check a configured `wallet_address` against the key and the network, and
/// return it CANONICALIZED.
///
/// Canonical matters as much as the checks. Bech32 is case-insensitive and
/// pallas parses an uppercase address happily, but everything downstream
/// decides the network by string prefix — `is_testnet_address` is
/// `starts_with("addr_test")` — so an uppercase testnet address reads as
/// MAINNET there and silently retags the registry, the ban list and every
/// other derived script address. Re-encoding from the parsed address is what
/// makes the rest of the codebase's cheap prefix tests correct.
///
/// The payment check is what makes a pasted address safe at all: without it,
/// naming the wrong `payment.skey` — easy, they are all called `payment.skey`
/// — gives a well-formed address for a wallet the operator cannot spend from,
/// and the symptom is "no UTxOs" somewhere much later. It checks the PAYMENT
/// part only, so a base address and an enterprise address over the same key
/// both pass: the delegation half says who earns the rewards, not who can
/// spend.
fn checked_address(cfg: &CardanoConfig, address: &str, key: &PrivateKey) -> Result<String, String> {
    let parsed = Address::from_bech32(address)
        .map_err(|e| format!("cardano.wallet_address is not a bech32 address: {e}"))?;
    let Address::Shelley(sh) = parsed else {
        return Err(format!(
            "cardano.wallet_address {address} is not a Shelley address — Byron and \
             reward addresses cannot be spent from here"
        ));
    };

    let want = pub_key_hash_hex(key);
    match sh.payment() {
        ShelleyPaymentPart::Key(h) => {
            let got = hex::encode(h.as_ref());
            if got != want {
                return Err(format!(
                    "cardano.wallet_address {address} has payment key hash {got}, but the \
                     key hashes to {want} — the address and the signing key are not a pair, \
                     so nothing at that address could be spent"
                ));
            }
        }
        ShelleyPaymentPart::Script(_) => {
            return Err(format!(
                "cardano.wallet_address {address} is script-locked — heimdall signs with a \
                 payment key and cannot spend it"
            ));
        }
    }

    // The DECODED tag, not the prefix: see above.
    let addr_mainnet = matches!(sh.network(), Network::Mainnet);
    // `is_mainnet()` fails two different ways and they deserve different
    // answers. When `cardano.network` is SET, the operator stated a network:
    // honour it, and let an unknown spelling refuse — swallowing that is how
    // `network = "Mainnet"` would sail past this check, which is the bug
    // preflight's sibling guard documents. When it is UNSET the network is
    // merely inferred, and an address that cannot be cross-checked is not a
    // reason to reject an otherwise valid one.
    let configured = match cfg.network.as_deref() {
        Some(_) => Some(cfg.is_mainnet()?),
        None => cfg.is_mainnet().ok(),
    };
    if let Some(mainnet) = configured
        && addr_mainnet != mainnet
    {
        return Err(format!(
            "cardano.wallet_address {address} is {}, but this node is configured for {} — \
             every script address is tagged from this one, so the registry and the ban list \
             would resolve to valid-looking addresses holding nothing",
            if addr_mainnet { "mainnet" } else { "a testnet" },
            if mainnet { "mainnet" } else { "a testnet" }
        ));
    }

    Address::Shelley(sh)
        .to_bech32()
        .map_err(|e| format!("cardano.wallet_address {address} does not re-encode: {e}"))
}

/// Refuse a signing key any other user can read.
///
/// The whole argument for pointing at a file instead of an environment
/// variable is that the file's permissions are the protection — so a key at
/// 0644 makes the feature worse than the mnemonic it replaced, not better.
/// `cardano-cli` does not always create these 0600, and a `cp` from the pool
/// directory rarely preserves it. The bifrost identity key is held to the same
/// rule (`ConfigError::KeyPermsTooOpen`).
fn refuse_open_perms(path: &str) -> Result<(), String> {
    crate::config::refuse_group_readable(std::path::Path::new(path)).map_err(|(path, mode)| {
        format!(
            "cardano.payment_skey_path {path} is mode {mode:04o} — group- or world-readable. \
             This is a wallet signing key and the file's permissions are the only thing \
             protecting it: chmod 600 it"
        )
    })
}

/// Load a cardano-cli text-envelope signing key.
///
/// Accepts the plain Shelley payment key (32-byte ed25519 secret) and its
/// extended BIP32 form, whose payload cardano-cli writes as 128 bytes —
/// 64-byte extended key, 32-byte chain code, 32-byte public key — of which
/// only the leading 64 are needed to sign. Every other envelope `type` is
/// refused BY NAME: a stake or cold key here would produce a perfectly valid
/// signature for the wrong credential, which is worse than an error.
pub fn payment_key_from_skey_file(path: &str) -> Result<PrivateKey, String> {
    refuse_open_perms(path)?;
    // Every intermediate holds the secret, and the argument for using a file
    // at all is that the key is protected. A `String` and a `Vec` dropped
    // without wiping leave the key in freed heap, where a core dump or a
    // later allocation in a long-lived daemon can still find it — so each is
    // wiped on the way out. The `[u8; 32]` handed to pallas is zeroized by
    // its own type.
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| format!("cardano.payment_skey_path {path}: {e}"))?,
    );
    let env: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{path} is not a text envelope: {e}"))?;
    let kind = env
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("{path} has no \"type\" field — not a cardano-cli key file"))?;
    let cbor_hex = env
        .get("cborHex")
        .and_then(|c| c.as_str())
        .ok_or_else(|| format!("{path} has no \"cborHex\" field"))?;
    let cbor =
        Zeroizing::new(hex::decode(cbor_hex.trim()).map_err(|e| format!("{path} cborHex: {e}"))?);
    let raw = Zeroizing::new(
        pallas_codec::minicbor::decode::<pallas_codec::utils::Bytes>(&cbor)
            .map(|b| b.to_vec())
            .map_err(|e| format!("{path} cborHex is not a CBOR byte string: {e}"))?,
    );

    match kind {
        "PaymentSigningKeyShelley_ed25519" => {
            let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                format!(
                    "{path}: expected a 32-byte ed25519 secret, got {}",
                    raw.len()
                )
            })?;
            Ok(PrivateKey::from(
                pallas_crypto::key::ed25519::SecretKey::from(seed),
            ))
        }
        "PaymentExtendedSigningKeyShelley_ed25519_bip32" => {
            let extended: [u8; 64] =
                raw.get(..64)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| {
                        format!(
                            "{path}: expected >= 64 bytes of extended key, got {}",
                            raw.len()
                        )
                    })?;
            let key = pallas_crypto::key::ed25519::SecretKeyExtended::from_bytes(extended)
                .map_err(|e| format!("{path}: not a valid extended ed25519 key: {e:?}"))?;
            Ok(PrivateKey::from(key))
        }
        other => Err(format!(
            "{path} is a {other:?}. heimdall's wallet key must be a payment key — \
             \"PaymentSigningKeyShelley_ed25519\" or \
             \"PaymentExtendedSigningKeyShelley_ed25519_bip32\". A stake or cold key here \
             would sign perfectly well for the wrong credential"
        )),
    }
}

/// CIP-1852 hardened offset: `n'` = `0x8000_0000 | n`.
const HARDENED: u32 = 0x8000_0000;

/// Derive the external payment key (`m/1852'/1815'/0'/0/0`) from a
/// BIP-39 mnemonic. Passphrase is empty (matches the common
/// Daedalus/Yoroi "no passphrase" default).
pub fn derive_payment_key(mnemonic: &str) -> Result<PrivateKey, String> {
    let root = Bip32PrivateKey::from_bip39_mnenomic(mnemonic.to_string(), String::new())
        .map_err(|e| format!("mnemonic parse: {e:?}"))?;
    let key = root
        .derive(HARDENED | 1852) // purpose
        .derive(HARDENED | 1815) // coin_type (ADA)
        .derive(HARDENED | 0) // account #0
        .derive(0) // external chain
        .derive(0) // address index #0
        .to_ed25519_private_key();
    Ok(key)
}

/// Derive the full CIP-1852 base address from a mnemonic:
/// payment key at `m/1852'/1815'/0'/0/0` + staking key at
/// `m/1852'/1815'/0'/2/0`. This matches what Daedalus/Yoroi/cardano-cli
/// show as the wallet's receive address.
pub fn wallet_address_from_mnemonic(mnemonic: &str, network: Network) -> Result<String, String> {
    let root = Bip32PrivateKey::from_bip39_mnenomic(mnemonic.to_string(), String::new())
        .map_err(|e| format!("mnemonic parse: {e:?}"))?;

    let payment_key = root
        .derive(HARDENED | 1852)
        .derive(HARDENED | 1815)
        .derive(HARDENED | 0)
        .derive(0)
        .derive(0)
        .to_ed25519_private_key();

    let staking_key = root
        .derive(HARDENED | 1852)
        .derive(HARDENED | 1815)
        .derive(HARDENED | 0)
        .derive(2) // staking chain
        .derive(0)
        .to_ed25519_private_key();

    let pay_pk: [u8; 32] = payment_key.public_key().into();
    let pkh = blake2b_224(&pay_pk);

    let stk_pk: [u8; 32] = staking_key.public_key().into();
    let skh = blake2b_224(&stk_pk);

    let shelley = ShelleyAddress::new(
        network,
        ShelleyPaymentPart::key_hash(pkh.into()),
        ShelleyDelegationPart::key_hash(skh.into()),
    );
    Ok(Address::Shelley(shelley)
        .to_bech32()
        .expect("bech32 encode wallet address"))
}

/// Enterprise (no staking part) bech32 address for a payment key, on the
/// given network. Used where only the payment key is available.
pub fn wallet_address(key: &PrivateKey, network: Network) -> String {
    let pk_bytes: [u8; 32] = key.public_key().into();
    let pkh = blake2b_224(&pk_bytes);
    let shelley = ShelleyAddress::new(
        network,
        ShelleyPaymentPart::key_hash(pkh.into()),
        ShelleyDelegationPart::Null,
    );
    Address::Shelley(shelley)
        .to_bech32()
        .expect("bech32 encode wallet address")
}

/// 28-byte pub key hash of the payment key, hex encoded. Used for
/// `required_signers` in the tx body.
pub fn pub_key_hash_hex(key: &PrivateKey) -> String {
    let pk_bytes: [u8; 32] = key.public_key().into();
    hex::encode(blake2b_224(&pk_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard BIP-39 test vector mnemonic. Same input must produce
    // the same address every time.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about";

    #[test]
    fn derive_payment_key_is_deterministic() {
        let k1 = derive_payment_key(TEST_MNEMONIC).unwrap();
        let k2 = derive_payment_key(TEST_MNEMONIC).unwrap();
        assert_eq!(
            wallet_address(&k1, Network::Testnet),
            wallet_address(&k2, Network::Testnet)
        );
    }

    #[test]
    fn wallet_address_is_testnet_enterprise() {
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key, pallas_addresses::Network::Testnet);
        assert!(addr.starts_with("addr_test1"), "got {addr}");
    }

    #[test]
    fn wallet_address_from_mnemonic_is_base_address() {
        let addr = wallet_address_from_mnemonic(TEST_MNEMONIC, pallas_addresses::Network::Testnet)
            .unwrap();
        // Base address prefix for testnet is addr_test1q
        assert!(addr.starts_with("addr_test1q"), "got {addr}");
    }

    /// A cardano-cli text envelope for a given 32-byte secret. Named per
    /// test so a parallel run cannot have two of them collide.
    fn skey_file(name: &str, kind: &str, cbor_hex: &str) -> String {
        let dir = std::env::temp_dir().join(format!("heimdall-skey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.skey"));
        std::fs::write(
            &path,
            format!(
                r#"{{"type":"{kind}","description":"Payment Signing Key","cborHex":"{cbor_hex}"}}"#
            ),
        )
        .unwrap();
        // 0600, as the loader now insists a real one is.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path.to_string_lossy().into_owned()
    }

    fn cardano_cfg() -> crate::config::CardanoConfig {
        crate::config::HeimdallConfig::default().cardano
    }

    /// The point of the feature: a plain cardano-cli payment key signs, and
    /// the address the operator gave is used as-is.
    #[test]
    fn a_payment_skey_and_an_address_make_a_wallet() {
        let seed = [7u8; 32];
        let key = PrivateKey::from(pallas_crypto::key::ed25519::SecretKey::from(seed));
        let addr = wallet_address(&key, Network::Testnet);

        let mut cfg = cardano_cfg();
        cfg.payment_skey_path = Some(skey_file(
            "skey-and-address",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode(seed)),
        ));
        cfg.wallet_address = Some(addr.clone());

        let w = resolve_wallet_from(&cfg, None).expect("resolves");
        assert_eq!(w.address, addr);
        assert_eq!(w.source, "cardano.payment_skey_path");
        assert_eq!(pub_key_hash_hex(&w.key), pub_key_hash_hex(&key));
    }

    /// Naming the wrong `payment.skey` — they are all called `payment.skey` —
    /// must not produce a wallet nothing can spend from.
    #[test]
    fn an_address_that_is_not_the_keys_is_refused() {
        let other = PrivateKey::from(pallas_crypto::key::ed25519::SecretKey::from([9u8; 32]));

        let mut cfg = cardano_cfg();
        cfg.payment_skey_path = Some(skey_file(
            "address-mismatch",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        ));
        cfg.wallet_address = Some(wallet_address(&other, Network::Testnet));

        let err = resolve_wallet_from(&cfg, None).expect_err("not a pair");
        assert!(err.contains("not a pair"), "{err}");
    }

    /// A stake or cold key here would sign perfectly well for the wrong
    /// credential, so the envelope type is refused by name.
    #[test]
    fn only_a_payment_key_envelope_is_accepted() {
        let path = skey_file(
            "stake-in-payment-slot",
            "StakeSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        );
        let err = payment_key_from_skey_file(&path)
            .err()
            .expect("a stake key must be refused");
        assert!(err.contains("StakeSigningKeyShelley_ed25519"), "{err}");
        assert!(err.contains("must be a payment key"), "{err}");
    }

    #[test]
    fn a_skey_without_an_address_says_why_one_is_needed() {
        let mut cfg = cardano_cfg();
        cfg.payment_skey_path = Some(skey_file(
            "no-address",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        ));
        let err = resolve_wallet_from(&cfg, None).expect_err("no address");
        assert!(err.contains("cardano.wallet_address"), "{err}");
    }

    /// "Neither" is resolved here, not at config load: $HEIMDALL_MNEMONIC is
    /// invisible to the TOML parser.
    ///
    /// The variable is cleared for the duration, because on an SPO box — the
    /// setup the operator guide recommends — it is exported, and the test
    /// would pass a wallet back instead of the error it is asserting on.
    #[test]
    fn no_key_at_all_names_both_ways_in() {
        let err = resolve_wallet_from(&cardano_cfg(), None).expect_err("nothing configured");
        assert!(err.contains("payment_skey_path"), "{err}");
        assert!(err.contains("mnemonic"), "{err}");
    }

    /// Two wallet keys is refused HERE too, not only at config load. `run-spo`
    /// injects `--cardano-mnemonic` and `$HEIMDALL_MNEMONIC` into the config
    /// after the loader has had its look, so the loader's check alone let a
    /// migrated operator silently keep signing with the skey.
    #[test]
    fn two_keys_are_refused_even_when_the_loader_never_saw_both() {
        let mut cfg = cardano_cfg();
        cfg.payment_skey_path = Some(skey_file(
            "two-keys",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        ));
        cfg.mnemonic = Some(TEST_MNEMONIC.to_string());
        let err = resolve_wallet_from(&cfg, None).expect_err("alternatives");
        assert!(err.contains("two wallet keys"), "{err}");
    }

    /// The address is read back by `network_from_address` to tag every script
    /// address, so one on the wrong network is not a cosmetic mismatch.
    #[test]
    fn an_address_on_the_wrong_network_is_refused() {
        let key = PrivateKey::from(pallas_crypto::key::ed25519::SecretKey::from([7u8; 32]));
        let mut cfg = cardano_cfg();
        cfg.payment_skey_path = Some(skey_file(
            "wrong-network",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        ));
        cfg.wallet_address = Some(wallet_address(&key, Network::Testnet));
        cfg.network = Some("mainnet".into());
        let err = resolve_wallet_from(&cfg, None).expect_err("testnet address on a mainnet node");
        assert!(err.contains("configured for mainnet"), "{err}");
    }

    /// The environment is a mnemonic source, and an empty one is not.
    #[test]
    fn the_environment_supplies_a_mnemonic_and_is_labelled_as_such() {
        let cfg = cardano_cfg();
        let w = resolve_wallet_from(&cfg, Some(TEST_MNEMONIC.to_string())).expect("resolves");
        assert_eq!(w.source, "$HEIMDALL_MNEMONIC");

        assert!(
            resolve_wallet_from(&cfg, Some("   ".to_string())).is_err(),
            "blank is not a mnemonic"
        );
    }

    /// `deploy/debian/heimdall.toml` offers `#mnemonic = ""` as the line to
    /// uncomment, so an operator can easily end up with a blank one beside a
    /// real key file. That must not read as "two wallet keys".
    #[test]
    fn an_empty_mnemonic_is_not_a_second_wallet_key() {
        let key = PrivateKey::from(pallas_crypto::key::ed25519::SecretKey::from([7u8; 32]));
        let mut cfg = cardano_cfg();
        cfg.payment_skey_path = Some(skey_file(
            "empty-mnemonic",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        ));
        cfg.wallet_address = Some(wallet_address(&key, Network::Testnet));
        cfg.mnemonic = Some(String::new());

        let w = resolve_wallet_from(&cfg, None).expect("a blank mnemonic is no mnemonic");
        assert_eq!(w.source, "cardano.payment_skey_path");
    }

    /// Bech32 is case-insensitive and pallas parses an uppercase address
    /// happily — but `is_testnet_address` is a prefix test, so an uppercase
    /// TESTNET address read as MAINNET downstream and retagged every script
    /// address. Validation uses the decoded tag, and the address is stored
    /// canonicalized so the cheap prefix tests elsewhere stay correct.
    #[test]
    fn an_uppercase_address_is_still_checked_and_is_stored_canonical() {
        let key = PrivateKey::from(pallas_crypto::key::ed25519::SecretKey::from([7u8; 32]));
        let lower = wallet_address(&key, Network::Testnet);

        let mut cfg = cardano_cfg();
        cfg.payment_skey_path = Some(skey_file(
            "uppercase",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        ));
        cfg.wallet_address = Some(lower.to_uppercase());

        // Accepted, but normalized — otherwise network_from_address says mainnet.
        cfg.network = Some("preprod".into());
        let w = resolve_wallet_from(&cfg, None).expect("uppercase is a valid bech32 address");
        assert_eq!(w.address, lower, "stored canonical, not as pasted");
        assert!(crate::cardano::tx_common::is_testnet_address(&w.address));

        // And the network check is no longer silently skipped for it.
        cfg.network = Some("mainnet".into());
        let err = resolve_wallet_from(&cfg, None).expect_err("uppercase testnet on a mainnet node");
        assert!(err.contains("configured for mainnet"), "{err}");
    }

    /// A key file anyone can read defeats the reason for using a file at all.
    #[cfg(unix)]
    #[test]
    fn a_group_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = skey_file(
            "open-perms",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = payment_key_from_skey_file(&path).err().expect("0644");
        assert!(err.contains("0644"), "{err}");
        assert!(err.contains("chmod 600"), "{err}");
    }

    /// With a mnemonic the address is a cross-check, not an override. An
    /// enterprise address over the same payment key passes the credential
    /// test and is still the wrong wallet — `cardano-cli address build` makes
    /// one from payment.vkey alone, so this is an easy paste to get wrong.
    #[test]
    fn an_address_that_is_not_the_mnemonics_own_is_refused() {
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let mut cfg = cardano_cfg();
        cfg.mnemonic = Some(TEST_MNEMONIC.to_string());
        cfg.wallet_address = Some(wallet_address(&key, Network::Testnet));
        let err = resolve_wallet_from(&cfg, None).expect_err("enterprise != base");
        assert!(
            err.contains("is not the address this mnemonic derives"),
            "{err}"
        );

        cfg.wallet_address =
            Some(wallet_address_from_mnemonic(TEST_MNEMONIC, Network::Testnet).unwrap());
        assert!(
            resolve_wallet_from(&cfg, None).is_ok(),
            "its own address is fine"
        );
    }

    /// The skey path never derives an address, so it must not need a network
    /// it does not consult — `blockfrost_url` without `network` is a config
    /// that loads today and worked before this change.
    #[test]
    fn a_skey_needs_no_resolvable_network() {
        let key = PrivateKey::from(pallas_crypto::key::ed25519::SecretKey::from([7u8; 32]));
        let mut cfg = cardano_cfg();
        cfg.payment_skey_path = Some(skey_file(
            "no-network",
            "PaymentSigningKeyShelley_ed25519",
            &format!("5820{}", hex::encode([7u8; 32])),
        ));
        cfg.wallet_address = Some(wallet_address(&key, Network::Testnet));
        cfg.blockfrost_url = Some("http://localhost:8080/api/v1".into());
        assert!(
            cfg.is_mainnet().is_err(),
            "the fixture must be unresolvable"
        );
        assert!(
            resolve_wallet_from(&cfg, None).is_ok(),
            "and the skey path must not care"
        );
    }

    /// The wallet address was the last derivation taking its network tag from
    /// a constant, which is why mainnet could not work.
    #[test]
    fn the_network_tag_comes_from_the_config() {
        let mut cfg = cardano_cfg();
        cfg.mnemonic = Some(TEST_MNEMONIC.to_string());
        cfg.blockfrost_project_id = Some("preprod_xxx".into());
        assert!(
            resolve_wallet_from(&cfg, None)
                .unwrap()
                .address
                .starts_with("addr_test1")
        );

        cfg.network = Some("mainnet".into());
        let addr = resolve_wallet_from(&cfg, None).unwrap().address;
        assert!(addr.starts_with("addr1"), "got {addr}");
    }

    /// A mnemonic-configured node is untouched by any of this.
    #[test]
    fn a_mnemonic_still_resolves_to_its_base_address() {
        let mut cfg = cardano_cfg();
        cfg.mnemonic = Some(TEST_MNEMONIC.to_string());
        let w = resolve_wallet_from(&cfg, None).expect("resolves");
        assert_eq!(w.source, "cardano.mnemonic");
        assert_eq!(
            w.address,
            wallet_address_from_mnemonic(TEST_MNEMONIC, Network::Testnet).unwrap()
        );
    }

    #[test]
    fn bad_mnemonic_fails() {
        assert!(derive_payment_key("not a real mnemonic at all").is_err());
    }
}
