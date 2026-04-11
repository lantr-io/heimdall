//! Hardcoded "always-true" Cardano native script used as the demo
//! peg-in policy and script address.
//!
//! The script is `NativeScript::ScriptAll(vec![])` — an empty
//! conjunction, which trivially succeeds. We use it for the v0.2 demo
//! so that the SPO program has a real Cardano script address + policy
//! ID to query against without requiring any on-chain Bifrost contract
//! deployment.
//!
//! Cardano script hashing rules: `hash = blake2b_224(tag || cbor)` where
//! `tag` is `0x00` for native scripts. The same 28-byte hash is the
//! policy ID (for minting) and the script-payment-credential (for the
//! address).
//!
//! TODO: replace with the real `peg_in.ak` Plutus script hash + address
//! once the Bifrost Cardano contracts are available.

use std::sync::OnceLock;

use pallas_addresses::{Address, Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart};
use pallas_codec::minicbor;
use pallas_crypto::hash::Hasher;
use pallas_primitives::alonzo::NativeScript;

/// CBOR encoding of `NativeScript::ScriptAll(vec![])`. Computed lazily
/// because `minicbor::to_vec` is not const.
pub fn always_ok_script_cbor() -> &'static [u8] {
    static CBOR: OnceLock<Vec<u8>> = OnceLock::new();
    CBOR.get_or_init(|| {
        let script = NativeScript::ScriptAll(vec![]);
        minicbor::to_vec(&script).expect("encode always-ok native script")
    })
}

/// Cardano script hash of the always-OK native script. This is also
/// the policy ID for minting under it.
pub fn always_ok_script_hash() -> [u8; 28] {
    static HASH: OnceLock<[u8; 28]> = OnceLock::new();
    *HASH.get_or_init(|| {
        let mut hasher = Hasher::<224>::new();
        // Native-script type tag.
        hasher.input(&[0x00]);
        hasher.input(always_ok_script_cbor());
        let digest = hasher.finalize();
        let bytes: [u8; 28] = (*digest).into();
        bytes
    })
}

/// Bech32 testnet enterprise address of the always-OK script (no
/// staking part). Use this as the peg-in script address in demo runs.
pub fn always_ok_testnet_address_bech32() -> &'static str {
    static ADDR: OnceLock<String> = OnceLock::new();
    ADDR.get_or_init(|| {
        let hash = always_ok_script_hash();
        let shelley = ShelleyAddress::new(
            Network::Testnet,
            ShelleyPaymentPart::script_hash(hash.into()),
            ShelleyDelegationPart::Null,
        );
        Address::Shelley(shelley)
            .to_bech32()
            .expect("bech32 encode")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_hash_is_28_bytes_and_stable() {
        let h1 = always_ok_script_hash();
        let h2 = always_ok_script_hash();
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_eq!(h1.len(), 28);
    }

    #[test]
    fn testnet_address_is_addr_test_prefixed() {
        let addr = always_ok_testnet_address_bech32();
        assert!(addr.starts_with("addr_test1"), "got {addr}");
    }

    #[test]
    fn cbor_is_3_bytes() {
        // ScriptAll(vec![]) → CBOR array(2) of [1, []] → 0x82 0x01 0x80
        let cbor = always_ok_script_cbor();
        assert_eq!(cbor, &[0x82, 0x01, 0x80]);
    }
}
