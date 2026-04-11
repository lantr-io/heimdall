//! Static demo fixture: roster + pre-seeded treasury state.
//!
//! The treasury's Taproot internal key (`Y_51`) is not known until
//! after DKG has run, so the fixture doesn't bake the treasury
//! `TaprootSpendInfo` in. Instead it holds the placeholder leaf keys
//! (`Y_67`, `Y_fed`) and the UTxO parameters; the `BuildTm` phase
//! computes the final spend info using the DKG output's verifying key.
//!
//! TODO: this whole file is throw-away. Once a real `CardanoChain`
//! impl exists, the demo will pull the roster, treasury UTXO,
//! peg-ins, peg-outs, and fee parameters from a live node — none of
//! the values constructed here are valid on a real network.

use std::collections::BTreeMap;

use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, UntweakedPublicKey};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use frost_secp256k1_tr::Identifier;

use crate::epoch::state::{Roster, SpoInfo};

/// Everything the demo `MockCardanoChain` needs to answer chain queries.
#[derive(Debug, Clone)]
pub struct StaticFixture {
    pub roster: Roster,
    /// Placeholder Y_67 x-only key — not used for key-path spends but
    /// committed to in the Taproot script tree.
    pub y_67: UntweakedPublicKey,
    /// Placeholder Y_federation x-only key.
    pub y_fed: UntweakedPublicKey,
    /// Timeout (in Bitcoin blocks) before the federation fallback leaf
    /// becomes spendable. Must match what the on-chain treasury commits to.
    pub federation_csv_blocks: u32,
    /// Current treasury outpoint and amount. For the first cycle this
    /// is synthetic.
    pub treasury_outpoint: OutPoint,
    pub treasury_value: Amount,
    /// Peg-in UTxOs waiting to be swept.
    pub pegins: Vec<StaticPegIn>,
    /// Peg-out requests waiting to be paid out.
    pub pegouts: Vec<StaticPegOut>,
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee: Amount,
}

#[derive(Debug, Clone)]
pub struct StaticPegIn {
    pub outpoint: OutPoint,
    pub value: Amount,
}

#[derive(Debug, Clone)]
pub struct StaticPegOut {
    pub script_pubkey: ScriptBuf,
    pub amount: Amount,
}

/// Build a demo fixture with `max_signers` SPOs, `min_signers` threshold,
/// listening on `base_port .. base_port + max_signers - 1`.
pub fn demo_static_fixture(
    min_signers: u16,
    max_signers: u16,
    base_port: u16,
) -> StaticFixture {
    let secp = Secp256k1::new();

    let mut participants = BTreeMap::new();
    for i in 1..=max_signers {
        let id = Identifier::try_from(i).unwrap();
        let port = base_port + (i - 1);
        participants.insert(
            id,
            SpoInfo {
                identifier: id,
                bifrost_url: format!("http://127.0.0.1:{port}"),
                bifrost_id_pk: vec![],
            },
        );
    }
    let roster = Roster {
        epoch: 0,
        min_signers,
        max_signers,
        participants,
    };

    // Deterministic placeholder leaf keys.
    let y_67 = UntweakedPublicKey::from_slice(
        &SecretKey::from_slice(&[0x67u8; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0
            .serialize(),
    )
    .unwrap();
    let y_fed = UntweakedPublicKey::from_slice(
        &SecretKey::from_slice(&[0xFEu8; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0
            .serialize(),
    )
    .unwrap();

    StaticFixture {
        roster,
        y_67,
        y_fed,
        federation_csv_blocks: 144,
        treasury_outpoint: OutPoint {
            txid: Txid::from_byte_array([0xAA; 32]),
            vout: 0,
        },
        treasury_value: Amount::from_sat(10_000_000),
        pegins: vec![],
        pegouts: vec![],
        fee_rate_sat_per_vb: 1,
        per_pegout_fee: Amount::from_sat(1_000),
    }
}
