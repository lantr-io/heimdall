//! Static demo fixture: roster + pre-seeded treasury state.
//!
//! At bootstrap the treasury's internal key `y_51` is set to `y_fed`
//! (the federation key). After DKG, `publish_group_key` replaces it
//! with the FROST group key so the signing phase can produce valid
//! key-path signatures.

use std::collections::BTreeMap;

use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, UntweakedPublicKey};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use frost_secp256k1_tr::Identifier;

use crate::config::HeimdallConfig;
use crate::epoch::state::{Roster, SpoInfo};

/// Everything the demo `MockCardanoChain` needs to answer chain queries.
#[derive(Debug, Clone)]
pub struct StaticFixture {
    pub roster: Roster,
    /// Internal key (Y_51) of the current treasury. At bootstrap this
    /// equals `y_fed`.
    pub y_51: UntweakedPublicKey,
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
        y_51: y_fed, // bootstrap: internal key = federation
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

/// Build a demo fixture from the merged `HeimdallConfig`.
pub fn demo_static_fixture_from_config(cfg: &HeimdallConfig) -> StaticFixture {
    let secp = Secp256k1::new();

    let y_67_seed: [u8; 32] = hex::decode(&cfg.bitcoin.y_67_seed_hex)
        .expect("bitcoin.y_67_seed_hex must be valid hex")
        .try_into()
        .expect("bitcoin.y_67_seed_hex must be 32 bytes");
    let y_fed_seed: [u8; 32] = hex::decode(&cfg.bitcoin.y_fed_seed_hex)
        .expect("bitcoin.y_fed_seed_hex must be valid hex")
        .try_into()
        .expect("bitcoin.y_fed_seed_hex must be 32 bytes");

    let y_67 = UntweakedPublicKey::from_slice(
        &SecretKey::from_slice(&y_67_seed)
            .unwrap()
            .x_only_public_key(&secp)
            .0
            .serialize(),
    )
    .unwrap();
    let y_fed = UntweakedPublicKey::from_slice(
        &SecretKey::from_slice(&y_fed_seed)
            .unwrap()
            .x_only_public_key(&secp)
            .0
            .serialize(),
    )
    .unwrap();

    let mut participants = BTreeMap::new();
    for i in 1..=cfg.demo.max_signers {
        let id = Identifier::try_from(i).unwrap();
        let port = cfg.http.base_port + (i - 1);
        participants.insert(
            id,
            SpoInfo {
                identifier: id,
                bifrost_url: format!("http://{}:{}", cfg.http.bind_address, port),
                bifrost_id_pk: vec![],
            },
        );
    }

    StaticFixture {
        roster: Roster {
            epoch: 0,
            min_signers: cfg.demo.min_signers,
            max_signers: cfg.demo.max_signers,
            participants,
        },
        y_51: y_fed, // bootstrap: internal key = federation
        y_67,
        y_fed,
        federation_csv_blocks: cfg.bitcoin.federation_csv_blocks,
        treasury_outpoint: OutPoint {
            txid: Txid::from_byte_array([0xAA; 32]),
            vout: 0,
        },
        treasury_value: Amount::from_sat(10_000_000),
        pegins: vec![],
        pegouts: vec![],
        fee_rate_sat_per_vb: cfg.bitcoin.fee_rate_sat_per_vb,
        per_pegout_fee: Amount::from_sat(cfg.bitcoin.per_pegout_fee_sat),
    }
}
