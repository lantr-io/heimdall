//! Taproot address derivation for treasury and peg-in UTXOs.
//!
//! Each function builds a `TaprootSpendInfo` describing the internal key and
//! script tree. The caller derives the on-chain address from `output_key()` and
//! passes the spend info to the sighash computation for correct tweaking.

use bitcoin::key::UntweakedPublicKey;
use bitcoin::opcodes::all::*;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{script, ScriptBuf};

// ---------------------------------------------------------------------------
// Script builders
// ---------------------------------------------------------------------------

/// `<pubkey> OP_CHECKSIG`
fn build_checksig_script(pubkey: UntweakedPublicKey) -> ScriptBuf {
    script::Builder::new()
        .push_x_only_key(&pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// `<timeout> OP_CSV OP_DROP <pubkey> OP_CHECKSIG`
fn build_csv_checksig_script(timeout: u16, pubkey: UntweakedPublicKey) -> ScriptBuf {
    script::Builder::new()
        .push_int(timeout as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// `OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIGVERIFY <timeout> OP_CSV`
fn build_depositor_refund_script(pubkey_hash: [u8; 20], timeout: u16) -> ScriptBuf {
    script::Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(pubkey_hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_int(timeout as i64)
        .push_opcode(OP_CSV)
        .into_script()
}

// ---------------------------------------------------------------------------
// Treasury Taproot tree
// ---------------------------------------------------------------------------

/// Build the treasury `TaprootSpendInfo`.
///
/// ```text
/// Internal key: Y_51 (51% quorum — key-path spend)
/// Script tree:
///   Leaf 1 (depth 1): <Y_67> OP_CHECKSIG
///   Leaf 2 (depth 1): <federation_timeout> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG
/// ```
pub fn treasury_spend_info(
    secp: &Secp256k1<All>,
    y_51: UntweakedPublicKey,
    y_67: UntweakedPublicKey,
    y_federation: UntweakedPublicKey,
    federation_timeout: u16,
) -> TaprootSpendInfo {
    let leaf1 = build_checksig_script(y_67);
    let leaf2 = build_csv_checksig_script(federation_timeout, y_federation);

    bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(1, leaf1)
        .expect("valid leaf")
        .add_leaf(1, leaf2)
        .expect("valid leaf")
        .finalize(secp, y_51)
        .expect("finalizable tree")
}

/// Build the peg-in `TaprootSpendInfo` for a specific depositor.
///
/// ```text
/// Internal key: Y_51 (51% quorum — key-path spend for SPO sweep)
/// Script tree:
///   Leaf 1 (depth 1): <federation_timeout> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG
///   Leaf 2 (depth 1): OP_DUP OP_HASH160 <depositor_pubkey_hash> OP_EQUALVERIFY
///                      OP_CHECKSIGVERIFY <depositor_refund_timeout> OP_CSV
/// ```
pub fn pegin_spend_info(
    secp: &Secp256k1<All>,
    y_51: UntweakedPublicKey,
    y_federation: UntweakedPublicKey,
    federation_timeout: u16,
    depositor_pubkey_hash: [u8; 20],
    depositor_refund_timeout: u16,
) -> TaprootSpendInfo {
    let leaf1 = build_csv_checksig_script(federation_timeout, y_federation);
    let leaf2 = build_depositor_refund_script(depositor_pubkey_hash, depositor_refund_timeout);

    bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(1, leaf1)
        .expect("valid leaf")
        .add_leaf(1, leaf2)
        .expect("valid leaf")
        .finalize(secp, y_51)
        .expect("finalizable tree")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    /// Generate a deterministic x-only public key from a 32-byte seed.
    fn xonly_from_seed(seed: [u8; 32]) -> UntweakedPublicKey {
        use bitcoin::hashes::{sha256, Hash as _};
        let secp = Secp256k1::new();
        let hash = sha256::Hash::hash(&seed);
        let sk = bitcoin::secp256k1::SecretKey::from_slice(hash.as_ref()).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        kp.x_only_public_key().0
    }

    fn test_keys() -> (UntweakedPublicKey, UntweakedPublicKey, UntweakedPublicKey) {
        let y_51 = xonly_from_seed([1u8; 32]);
        let y_67 = xonly_from_seed([2u8; 32]);
        let y_fed = xonly_from_seed([3u8; 32]);
        (y_51, y_67, y_fed)
    }

    #[test]
    fn test_treasury_spend_info_deterministic() {
        let secp = Secp256k1::new();
        let (y_51, y_67, y_fed) = test_keys();

        let si1 = treasury_spend_info(&secp, y_51, y_67, y_fed, 144);
        let si2 = treasury_spend_info(&secp, y_51, y_67, y_fed, 144);

        assert_eq!(si1.output_key(), si2.output_key());
        assert_eq!(si1.merkle_root(), si2.merkle_root());
    }

    #[test]
    fn test_pegin_spend_info_deterministic() {
        let secp = Secp256k1::new();
        let (y_51, _, y_fed) = test_keys();
        let depositor_hash = [0xABu8; 20];

        let si1 = pegin_spend_info(&secp, y_51, y_fed, 144, depositor_hash, 4320);
        let si2 = pegin_spend_info(&secp, y_51, y_fed, 144, depositor_hash, 4320);

        assert_eq!(si1.output_key(), si2.output_key());
        assert_eq!(si1.merkle_root(), si2.merkle_root());
    }

    #[test]
    fn test_treasury_vs_pegin_different() {
        let secp = Secp256k1::new();
        let (y_51, y_67, y_fed) = test_keys();
        let depositor_hash = [0xABu8; 20];

        let treasury = treasury_spend_info(&secp, y_51, y_67, y_fed, 144);
        let pegin = pegin_spend_info(&secp, y_51, y_fed, 144, depositor_hash, 4320);

        assert_ne!(treasury.output_key(), pegin.output_key());
    }

    #[test]
    fn test_treasury_script_leaves() {
        let secp = Secp256k1::new();
        let (y_51, y_67, y_fed) = test_keys();
        let si = treasury_spend_info(&secp, y_51, y_67, y_fed, 144);

        // Verify that both expected scripts are present in the script map
        let checksig = build_checksig_script(y_67);
        let csv_checksig = build_csv_checksig_script(144, y_fed);

        let script_map = si.script_map();
        assert!(
            script_map.keys().any(|(s, _)| *s == checksig),
            "checksig leaf not found in script map"
        );
        assert!(
            script_map.keys().any(|(s, _)| *s == csv_checksig),
            "csv+checksig leaf not found in script map"
        );
        assert_eq!(script_map.len(), 2, "expected exactly 2 script leaves");
    }

    #[test]
    fn test_pegin_script_leaves() {
        let secp = Secp256k1::new();
        let (y_51, _, y_fed) = test_keys();
        let depositor_hash = [0xABu8; 20];
        let si = pegin_spend_info(&secp, y_51, y_fed, 144, depositor_hash, 4320);

        let csv_checksig = build_csv_checksig_script(144, y_fed);
        let refund = build_depositor_refund_script(depositor_hash, 4320);

        let script_map = si.script_map();
        assert!(
            script_map.keys().any(|(s, _)| *s == csv_checksig),
            "csv+checksig leaf not found in script map"
        );
        assert!(
            script_map.keys().any(|(s, _)| *s == refund),
            "depositor refund leaf not found in script map"
        );
        assert_eq!(script_map.len(), 2, "expected exactly 2 script leaves");
    }
}
