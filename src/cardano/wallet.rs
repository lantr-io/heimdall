//! BIP-39 mnemonic → Cardano payment key derivation (CIP-1852).
//!
//! Derives the external payment key at path
//! `m/1852'/1815'/0'/0/0` using the Icarus (V2) scheme, via
//! `pallas_wallet::hd::Bip32PrivateKey`. The resulting key is an
//! **extended** ed25519 key (64 bytes), as used by all Cardano HD
//! wallets.
//!
//! We derive:
//! - the `PrivateKey` used to sign the oracle-update transaction, and
//! - the testnet enterprise bech32 address for querying wallet UTxOs.

use pallas_addresses::{Address, Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_crypto::hash::Hasher;
use pallas_wallet::{hd::Bip32PrivateKey, PrivateKey};

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
        .derive(HARDENED | 0)    // account #0
        .derive(0)               // external chain
        .derive(0)               // address index #0
        .to_ed25519_private_key();
    Ok(key)
}

/// Testnet enterprise (no staking part) bech32 address for a payment
/// key.
pub fn wallet_address(key: &PrivateKey) -> String {
    let pk_bytes: [u8; 32] = key.public_key().into();
    let hash = Hasher::<224>::hash(&pk_bytes);
    let pkh: [u8; 28] = (*hash).into();
    let shelley = ShelleyAddress::new(
        Network::Testnet,
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
    let hash = Hasher::<224>::hash(&pk_bytes);
    let pkh: [u8; 28] = (*hash).into();
    hex::encode(pkh)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard BIP-39 test vector mnemonic. Same input must produce
    // the same address every time.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about";

    #[test]
    fn derive_payment_key_is_deterministic() {
        let k1 = derive_payment_key(TEST_MNEMONIC).unwrap();
        let k2 = derive_payment_key(TEST_MNEMONIC).unwrap();
        assert_eq!(wallet_address(&k1), wallet_address(&k2));
    }

    #[test]
    fn wallet_address_is_testnet_enterprise() {
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        assert!(addr.starts_with("addr_test1"), "got {addr}");
    }

    #[test]
    fn bad_mnemonic_fails() {
        assert!(derive_payment_key("not a real mnemonic at all").is_err());
    }
}
