//! ApplyBan transaction support (`spo_bans.ak`, WI-018 part 4).
//!
//! Applying a ban consumes a published FaultProof and writes a ban-list node.
//! Unlike register_spo (a mint + spends), the action is authorized by a
//! **zero-amount reward withdrawal** from the `spo_bans` *stake* credential:
//! `spo_bans.ak` has a `withdraw(ApplyBan{..})` handler, and its `mint`
//! (`MintBanNode`) and `spend` (`BanListAction`) branches only check that the
//! ApplyBan withdrawal is present (via a `withdraw_redeemer_index`). So one tx
//! carries up to three `spo_bans` script uses (withdraw + spend the anchor +
//! mint the node) plus a `fault_verifier.BurnProof` mint that burns the proof.
//!
//! Two shapes (the validator branches on `existing_ban_input_index`):
//! - **first ban** (`None`): linked-list `insert_ascending` — spend the anchor
//!   element, output the continued anchor + the new `"ban/"||pool_id` node, and
//!   MINT the node NFT. Plan it with [`super::ban_list::BanList::plan_insert`].
//! - **reban** (`Some`): `spend_for_updating_elements_data` — spend the
//!   existing node and reproduce it with updated [`BanNodeData`] (same asset
//!   name + link), and mint NO ban-policy token.
//!
//! This module currently provides the byte-exact redeemer encoders and the
//! script reward-address helper the (forthcoming) tx builder sits on. The
//! on-chain shapes (confirmed against the compiled `spo_bans` blueprint schema):
//!
//! ```text
//! SpoBansWithdrawRedeemer = ApplyBan Constr(0, [ fault_input_index, registration_ref_input_index,
//!                                                accused_pool_id, evidence_hash,
//!                                                ban_anchor_input_index, ban_anchor_output_index,
//!                                                existing_ban_input_index: Option<Int>,
//!                                                ban_node_output_index ])
//! SpoBansMintRedeemer     = Bootstrap   Constr(0, [ OutputReference ])
//!                         | MintBanNode Constr(1, [ withdraw_redeemer_index, pool_id ])
//! SpoBansSpendRedeemer    = BanListAction Constr(0, [ withdraw_redeemer_index ])
//! Option<Int>             = Some Constr(0, [ Int ]) | None Constr(1, [])
//! ```
//!
//! The FaultProof burn uses [`super::fault_proof::burn_proof_redeemer`].

use pallas_addresses::{
    Address, Network, ShelleyAddress, ShelleyDelegationPart, ShelleyPaymentPart, StakeAddress,
};
use pallas_primitives::PlutusData;

use crate::cardano::plutus::{bytes, constr, int};

// ---------------------------------------------------------------------------
// Redeemer encoders
// ---------------------------------------------------------------------------

/// `Option<Int>` — `Some(i)` = `Constr(0, [int(i)])`, `None` = `Constr(1, [])`
/// (the standard Aiken `Option` encoding).
#[must_use]
pub fn option_int(v: Option<i64>) -> PlutusData {
    match v {
        Some(i) => constr(0, vec![int(i)]),
        None => constr(1, vec![]),
    }
}

/// `SpoBansWithdrawRedeemer::ApplyBan` — constructor 0, the 8 fields in the
/// order `spo_bans.ak` declares them. The index fields point into the built
/// tx's (ledger-sorted) input / reference-input / output lists; the builder
/// computes them.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn apply_ban_redeemer(
    fault_input_index: i64,
    registration_ref_input_index: i64,
    accused_pool_id: &[u8],
    evidence_hash: &[u8],
    ban_anchor_input_index: i64,
    ban_anchor_output_index: i64,
    existing_ban_input_index: Option<i64>,
    ban_node_output_index: i64,
) -> PlutusData {
    constr(
        0,
        vec![
            int(fault_input_index),
            int(registration_ref_input_index),
            bytes(accused_pool_id),
            bytes(evidence_hash),
            int(ban_anchor_input_index),
            int(ban_anchor_output_index),
            option_int(existing_ban_input_index),
            int(ban_node_output_index),
        ],
    )
}

/// `SpoBansMintRedeemer::MintBanNode` — constructor 1 (constructor 0 is
/// `Bootstrap`). `withdraw_redeemer_index` points at the ApplyBan withdrawal in
/// the tx's reward-withdrawal list; `pool_id` is the accused pool (the node's
/// asset name is `"ban/" || pool_id`).
#[must_use]
pub fn mint_ban_node_redeemer(withdraw_redeemer_index: i64, pool_id: &[u8]) -> PlutusData {
    constr(1, vec![int(withdraw_redeemer_index), bytes(pool_id)])
}

/// `SpoBansSpendRedeemer::BanListAction` — constructor 0, the redeemer for
/// spending a ban-list element (the anchor on a first ban, the existing node on
/// a reban). Carries the same `withdraw_redeemer_index`.
#[must_use]
pub fn ban_list_action_redeemer(withdraw_redeemer_index: i64) -> PlutusData {
    constr(0, vec![int(withdraw_redeemer_index)])
}

// ---------------------------------------------------------------------------
// Script reward (stake) address
// ---------------------------------------------------------------------------

/// The bech32 reward address (`stake_test1…` / `stake1…`) of a script stake
/// credential — the key for the ApplyBan withdrawal. The reward account bytes
/// are a header byte (`0xF0` script+testnet / `0xF1` script+mainnet) followed
/// by the 28-byte script hash; we build it via a Shelley address whose
/// *delegation* part is the script hash (`StakeAddress` is derived from that).
#[must_use]
pub fn script_reward_address(script_hash: &[u8; 28], network: Network) -> String {
    let shelley = ShelleyAddress::new(
        network,
        // Payment part is unused by the StakeAddress derivation; reuse the hash.
        ShelleyPaymentPart::script_hash((*script_hash).into()),
        ShelleyDelegationPart::script_hash((*script_hash).into()),
    );
    StakeAddress::try_from(shelley)
        .expect("script delegation part → StakeAddress")
        .to_bech32()
        .expect("bech32 encode reward address")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::plutus::{self, as_constr};
    use pallas_addresses::StakePayload;
    use pallas_codec::minicbor;

    #[test]
    fn apply_ban_redeemer_shape() {
        // first ban: existing_ban_input_index = None.
        let pool = [0x11u8; 28];
        let ev = [0x22u8; 32];
        let r = apply_ban_redeemer(1, 0, &pool, &ev, 2, 0, None, 1);
        let f = plutus::constr_fields(&r, 0).unwrap();
        assert_eq!(f.len(), 8);
        assert_eq!(plutus::field_int(f, 0).unwrap(), 1); // fault_input_index
        assert_eq!(plutus::field_int(f, 1).unwrap(), 0); // registration_ref_input_index
        assert_eq!(plutus::field_bytes(f, 2).unwrap(), pool);
        assert_eq!(plutus::field_bytes(f, 3).unwrap(), ev);
        assert_eq!(plutus::field_int(f, 4).unwrap(), 2); // ban_anchor_input_index
        assert_eq!(plutus::field_int(f, 5).unwrap(), 0); // ban_anchor_output_index
        // existing_ban_input_index = None = Constr(1, []).
        let (oc, of) = as_constr(&f[6]).unwrap();
        assert_eq!((oc, of.len()), (1, 0));
        assert_eq!(plutus::field_int(f, 7).unwrap(), 1); // ban_node_output_index

        // reban: existing_ban_input_index = Some(3) = Constr(0, [3]).
        let r2 = apply_ban_redeemer(1, 0, &pool, &ev, 0, 0, Some(3), 2);
        let f2 = plutus::constr_fields(&r2, 0).unwrap();
        let (sc, sf) = as_constr(&f2[6]).unwrap();
        assert_eq!(sc, 0);
        assert_eq!(plutus::field_int(sf, 0).unwrap(), 3);
    }

    #[test]
    fn mint_and_spend_redeemer_shapes() {
        // MintBanNode = Constr(1, [idx, pool_id]).
        let pool = [0xAAu8; 28];
        let m = mint_ban_node_redeemer(0, &pool);
        let mf = plutus::constr_fields(&m, 1).unwrap();
        assert_eq!(mf.len(), 2);
        assert_eq!(plutus::field_int(mf, 0).unwrap(), 0);
        assert_eq!(plutus::field_bytes(mf, 1).unwrap(), pool);

        // BanListAction = Constr(0, [idx]).
        let s = ban_list_action_redeemer(0);
        let sf = plutus::constr_fields(&s, 0).unwrap();
        assert_eq!(sf.len(), 1);
        assert_eq!(plutus::field_int(sf, 0).unwrap(), 0);

        // Both round-trip through canonical CBOR.
        for pd in [m, s] {
            let cbor = minicbor::to_vec(&pd).unwrap();
            let back: PlutusData = minicbor::decode(&cbor).unwrap();
            assert_eq!(back, pd);
        }
    }

    #[test]
    fn reward_address_is_script_keyed_and_network_tagged() {
        let h = [0xABu8; 28];
        let addr = script_reward_address(&h, Network::Testnet);
        assert!(addr.starts_with("stake_test1"), "{addr}");
        // Round-trip: it decodes to a script stake credential with our hash,
        // and the reward-account header byte is 0xF0 (script + testnet).
        let testnet_header = reward_account_header(&addr);
        match Address::from_bech32(&addr).unwrap() {
            Address::Stake(s) => match s.payload() {
                StakePayload::Script(hash) => assert_eq!(hash.as_slice(), h),
                StakePayload::Stake(_) => panic!("expected a SCRIPT stake payload"),
            },
            other => panic!("expected a stake address, got {other:?}"),
        }
        assert_eq!(testnet_header, 0xF0);
        // Mainnet flips the network bit → 0xF1.
        let main = script_reward_address(&h, Network::Mainnet);
        assert!(main.starts_with("stake1"), "{main}");
        assert_eq!(reward_account_header(&main), 0xF1);
    }

    /// First byte of the reward account (header) decoded from a bech32 reward
    /// address, via the generic `Address` (StakeAddress has no `from_bech32`).
    fn reward_account_header(bech32: &str) -> u8 {
        match Address::from_bech32(bech32).unwrap() {
            Address::Stake(s) => s.to_vec()[0],
            other => panic!("expected a stake address, got {other:?}"),
        }
    }
}
