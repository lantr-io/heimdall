//! Taproot address derivation for treasury and peg-in UTXOs.
//!
//! Each function builds a `TaprootSpendInfo` describing the internal key and
//! script tree. The caller derives the on-chain address from `output_key()` and
//! passes the spend info to the sighash computation for correct tweaking.

use bitcoin::key::UntweakedPublicKey;
use bitcoin::opcodes::all::*;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{ScriptBuf, script};

// ---------------------------------------------------------------------------
// Script builders
// ---------------------------------------------------------------------------

/// `<timeout> OP_CSV OP_DROP <pubkey> OP_CHECKSIG` — the CSV-timelock+checksig
/// leaf shared by the treasury federation tree and the peg-in refund tree.
/// Public so the script-path (federation-leaf) spender can rebuild the exact
/// leaf it must reveal + sign against (see `tm_builder::sign_tm_federation_leaf`).
pub fn build_csv_checksig_script(timeout: u16, pubkey: UntweakedPublicKey) -> ScriptBuf {
    script::Builder::new()
        .push_int(timeout as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&pubkey)
        .push_opcode(OP_CHECKSIG)
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
///   Leaf 1 (depth 0): <federation_timeout> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG
/// ```
pub fn treasury_spend_info(
    secp: &Secp256k1<All>,
    y_51: UntweakedPublicKey,
    y_federation: UntweakedPublicKey,
    federation_timeout: u16,
) -> TaprootSpendInfo {
    let leaf = build_csv_checksig_script(federation_timeout, y_federation);

    bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(0, leaf)
        .expect("valid leaf")
        .finalize(secp, y_51)
        .expect("finalizable tree")
}

/// The bridge-wide half of the peg-in tree: everything except the depositor.
///
/// A struct rather than four positional arguments because `y_51` and `y_federation` are
/// the same type and adjacent, and swapping them is silent — it derives a well-formed
/// address holding nothing. Naming them at every call site is the cheapest guard there is.
#[derive(Debug, Clone, Copy)]
pub struct PeginTreeParams {
    /// The FROST group key: Taproot INTERNAL key, spent by the 51% quorum's key path.
    pub y_51: UntweakedPublicKey,
    /// The federation fallback key, in the emergency-sweep LEAF — never the internal key.
    pub y_federation: UntweakedPublicKey,
    pub federation_csv_blocks: u16,
    pub refund_timeout: u16,
}

/// Build the peg-in `TaprootSpendInfo` — spec § Peg-in Taproot tree.
///
/// ```text
/// Internal key: Y_51 (51% FROST quorum — key-path sweep, the main line)
/// Script tree (2 leaves, depth 1 each):
///   Leaf 1: <federation_csv_blocks> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG
///   Leaf 2: <refund_timeout>        OP_CSV OP_DROP <Q_auth>       OP_CHECKSIG
/// ```
///
/// The federation leaf is the bridge's recovery path for a deposit the quorum
/// cannot sweep; without it a stuck deposit has nowhere to go but the depositor's
/// refund, which is why WI-081 restored it. `demo_simplifications.md` blessed a
/// one-leaf tree for a while, and it hid behind that file pinning `Y_federation`
/// to the FROST key's own value — which made "internal key = Y_fed" and "internal
/// key = Y_51" the same bytes.
///
/// `Q_auth` is the depositor's Taproot OUTPUT key — the same key their `BFR`
/// beacon carries and the same key their BIP-322 completion signs under. The
/// leaf holds the output key rather than a raw internal key so that an ordinary
/// wallet can take the refund path with its DEFAULT signer (WI-045/WI-072).
///
/// Every input decides the ADDRESS, so a wrong one yields a well-formed P2TR
/// holding nothing rather than an error. `refund_timeout` must exceed
/// `federation_csv_blocks` (spec) — the federation's window has to open first, or
/// a depositor can take the deposit back while the federation is still recovering
/// it. That is checked here rather than left to hold by luck.
pub fn pegin_spend_info(
    secp: &Secp256k1<All>,
    params: &PeginTreeParams,
    depositor_outputkey: UntweakedPublicKey,
) -> TaprootSpendInfo {
    let PeginTreeParams {
        y_51,
        y_federation,
        federation_csv_blocks,
        refund_timeout,
    } = *params;
    assert!(
        refund_timeout > federation_csv_blocks,
        "refund_timeout ({refund_timeout}) must exceed federation_csv_blocks \
         ({federation_csv_blocks}): the federation's sweep window must open before the \
         depositor's refund does"
    );
    let federation_leaf = build_csv_checksig_script(federation_csv_blocks, y_federation);
    let refund_leaf = build_csv_checksig_script(refund_timeout, depositor_outputkey);
    // Both at depth 1. `TaprootBuilder` hashes the pair into a BIP-341 TapBranch with the
    // children in lexicographic order, so which one is added first does not move the root.
    bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(1, federation_leaf)
        .expect("valid federation leaf")
        .add_leaf(1, refund_leaf)
        .expect("valid refund leaf")
        .finalize(secp, y_51)
        .expect("finalizable tree")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    /// Generate a deterministic x-only public key from a 32-byte seed.
    fn xonly_from_seed(seed: [u8; 32]) -> UntweakedPublicKey {
        use bitcoin::hashes::{Hash as _, sha256};
        let secp = Secp256k1::new();
        let hash = sha256::Hash::hash(&seed);
        let sk = bitcoin::secp256k1::SecretKey::from_slice(hash.as_ref()).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        kp.x_only_public_key().0
    }

    fn test_keys() -> (UntweakedPublicKey, UntweakedPublicKey) {
        let y_51 = xonly_from_seed([1u8; 32]);
        let y_fed = xonly_from_seed([3u8; 32]);
        (y_51, y_fed)
    }

    fn test_pegin_params() -> PeginTreeParams {
        let (y_51, y_federation) = test_keys();
        PeginTreeParams {
            y_51,
            y_federation,
            federation_csv_blocks: 144,
            refund_timeout: 720,
        }
    }

    #[test]
    fn test_treasury_spend_info_deterministic() {
        let secp = Secp256k1::new();
        let (y_51, y_fed) = test_keys();

        let si1 = treasury_spend_info(&secp, y_51, y_fed, 144);
        let si2 = treasury_spend_info(&secp, y_51, y_fed, 144);

        assert_eq!(si1.output_key(), si2.output_key());
        assert_eq!(si1.merkle_root(), si2.merkle_root());
    }

    #[test]
    fn test_pegin_spend_info_deterministic() {
        let secp = Secp256k1::new();
        let depositor = xonly_from_seed([0xAB; 32]);
        let params = test_pegin_params();

        let si1 = pegin_spend_info(&secp, &params, depositor);
        let si2 = pegin_spend_info(&secp, &params, depositor);

        assert_eq!(si1.output_key(), si2.output_key());
        assert_eq!(si1.merkle_root(), si2.merkle_root());
    }

    #[test]
    fn test_treasury_vs_pegin_different() {
        let secp = Secp256k1::new();
        let (y_51, y_fed) = test_keys();
        let depositor = xonly_from_seed([0xAB; 32]);

        let treasury = treasury_spend_info(&secp, y_51, y_fed, 144);
        let pegin = pegin_spend_info(&secp, &test_pegin_params(), depositor);

        assert_ne!(treasury.output_key(), pegin.output_key());
    }

    #[test]
    fn test_treasury_script_leaves() {
        let secp = Secp256k1::new();
        let (y_51, y_fed) = test_keys();
        let si = treasury_spend_info(&secp, y_51, y_fed, 144);

        let csv_checksig = build_csv_checksig_script(144, y_fed);

        let script_map = si.script_map();
        assert!(
            script_map.keys().any(|(s, _)| *s == csv_checksig),
            "csv+checksig leaf not found in script map"
        );
        assert_eq!(script_map.len(), 1, "expected exactly 1 script leaf");
    }

    #[test]
    fn test_pegin_script_leaves() {
        let secp = Secp256k1::new();
        let depositor = xonly_from_seed([0xAB; 32]);
        let params = test_pegin_params();
        let si = pegin_spend_info(&secp, &params, depositor);

        // BOTH leaves, and the federation one is the point of WI-081: a one-leaf tree left a
        // deposit the quorum cannot sweep with nowhere to go but the depositor's refund.
        let refund_leaf = build_csv_checksig_script(params.refund_timeout, depositor);
        let federation_leaf =
            build_csv_checksig_script(params.federation_csv_blocks, params.y_federation);
        let script_map = si.script_map();
        assert!(
            script_map.keys().any(|(s, _)| *s == refund_leaf),
            "depositor refund leaf not found in script map"
        );
        assert!(
            script_map.keys().any(|(s, _)| *s == federation_leaf),
            "federation emergency-sweep leaf not found in script map"
        );
        assert_eq!(script_map.len(), 2, "expected exactly 2 script leaves");
    }

    /// The internal key is Y_51, NOT Y_federation. Swapping them is the silent failure
    /// `PeginTreeParams` exists to prevent, so pin that it actually changes the address.
    #[test]
    fn pegin_internal_key_is_y51_not_y_federation() {
        let secp = Secp256k1::new();
        let depositor = xonly_from_seed([0xAB; 32]);
        let params = test_pegin_params();
        let swapped = PeginTreeParams {
            y_51: params.y_federation,
            y_federation: params.y_51,
            ..params
        };
        assert_ne!(
            pegin_spend_info(&secp, &params, depositor).output_key(),
            pegin_spend_info(&secp, &swapped, depositor).output_key()
        );
    }

    /// The spec requires the federation's window to open before the depositor's refund.
    #[test]
    #[should_panic(expected = "must exceed federation_csv_blocks")]
    fn pegin_refuses_a_refund_that_opens_before_the_federation_sweep() {
        let secp = Secp256k1::new();
        let depositor = xonly_from_seed([0xAB; 32]);
        let bad = PeginTreeParams {
            refund_timeout: 144,
            federation_csv_blocks: 720,
            ..test_pegin_params()
        };
        let _ = pegin_spend_info(&secp, &bad, depositor);
    }
}
