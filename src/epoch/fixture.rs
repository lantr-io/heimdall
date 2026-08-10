//! Static demo fixture: roster + pre-seeded treasury state.
//!
//! At bootstrap the treasury's internal key `y_51` is set to `y_fed`
//! (the federation key). After DKG, `publish_group_key` replaces it
//! with the FROST group key so the signing phase can produce valid
//! key-path signatures.

use std::collections::BTreeMap;

use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, UntweakedPublicKey};
use bitcoin::secp256k1::{Keypair, SecretKey};
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
    /// The mock bridge's operational parameters — what the Config UTxO's fields
    /// #12–#14 are on a real chain (see `cardano::config_params`). One fixture is
    /// shared by every node of a test, which is the property that matters: TM bytes
    /// must not depend on who built them.
    pub fee_rate_sat_per_vb: u64,
    /// The fee a fixture peg-out request pins in its (imaginary) datum — NOT the
    /// Config #13 floor, which is [`Self::per_pegout_fee_floor`].
    pub per_pegout_fee: Amount,
    /// Config #13 — floor for a request's datum fee. Zero disables the skip.
    pub per_pegout_fee_floor: Amount,
    /// Config #14 — minimum fBTC a request may lock. Zero disables the skip.
    pub min_peg_out_fbtc: Amount,
    /// Per-SPO bifrost identity keypairs, so the HTTP demo can construct
    /// each `HttpPeerNetwork` with the secret matching the `bifrost_id_pk`
    /// in `roster`. Empty for the config-driven fixture (real deployments
    /// load each node's key from its own `[bifrost].skey_path`).
    pub bifrost_keypairs: BTreeMap<Identifier, Keypair>,
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
    /// Cardano slot this request was created at — the TM batch cutoff's input
    /// (`cardano::pegout_datum::PegOutRequestData::created_slot` on a real chain).
    /// 0 = older than any cutoff, so fixture peg-outs are eligible for every batch
    /// unless a test says otherwise.
    pub created_slot: u64,
    /// The datum's `created` (POSIX ms) — the fulfillment freshness filter's input. A plain
    /// `i64` with no default: `build_tm` skips a request whose `created` is in the future or
    /// within the margin of `created + PEG_OUT_CANCEL_TIMEOUT_MS`, so a fixture that let this
    /// default to 0 would make every peg-out silently unpayable against a real chain clock —
    /// which is exactly what the hardcoded `created: 0` in the mock used to do.
    pub created: i64,
}

/// Build a demo fixture with `max_signers` SPOs, `min_signers` threshold,
/// listening on `base_port .. base_port + max_signers - 1`.
pub fn demo_static_fixture(min_signers: u16, max_signers: u16, base_port: u16) -> StaticFixture {
    let secp = Secp256k1::new();

    let mut participants = BTreeMap::new();
    let mut bifrost_keypairs = BTreeMap::new();
    for i in 1..=max_signers {
        let id = Identifier::try_from(i).unwrap();
        let port = base_port + (i - 1);
        // Deterministic per-SPO bifrost identity: secret = [0x11..,i], so the
        // roster's bifrost_id_pk matches the keypair each HttpPeerNetwork holds.
        let mut seed = [0x11u8; 32];
        seed[31] = i as u8;
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&seed).unwrap());
        let bifrost_id_pk = keypair.x_only_public_key().0.serialize().to_vec();
        participants.insert(
            id,
            SpoInfo {
                identifier: id,
                pool_id: vec![i as u8; 28],
                bifrost_url: format!("http://127.0.0.1:{port}"),
                bifrost_id_pk,
            },
        );
        bifrost_keypairs.insert(id, keypair);
    }
    let roster = Roster {
        epoch: 0,
        min_signers,
        max_signers,
        participants,
    };

    // Deterministic placeholder leaf key.
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
        // The demo bridge enforces neither floor: its peg-outs are synthetic, and
        // the point of the fixture is the DKG/signing path, not selection bounds.
        per_pegout_fee_floor: Amount::ZERO,
        min_peg_out_fbtc: Amount::ZERO,
        bifrost_keypairs,
    }
}

/// Build a demo fixture from the merged `HeimdallConfig`.
pub fn demo_static_fixture_from_config(cfg: &HeimdallConfig) -> StaticFixture {
    let secp = Secp256k1::new();

    let y_fed_seed: [u8; 32] = hex::decode(&cfg.bitcoin.y_fed_seed_hex)
        .expect("bitcoin.y_fed_seed_hex must be valid hex")
        .try_into()
        .expect("bitcoin.y_fed_seed_hex must be 32 bytes");

    let y_fed = UntweakedPublicKey::from_slice(
        &SecretKey::from_slice(&y_fed_seed)
            .unwrap()
            .x_only_public_key(&secp)
            .0
            .serialize(),
    )
    .unwrap();

    // Deterministic per-SPO identities (WI-023): the no-registry demo runs
    // `max_signers` real processes that talk over the authenticated HTTP
    // transport, which addresses peers by `bifrost_url` and verifies them by
    // `pool_id` / `bifrost_id_pk`. Populate those (and the matching secret
    // keypairs) the same way `demo_static_fixture` does — secret = [0x11..,i],
    // pool_id = [i;28] — so every node computes the identical roster and each
    // can load the key matching its own `--index`. (Empty placeholders here
    // used to panic `run_demo`'s 28-byte pool_id check.)
    let mut participants = BTreeMap::new();
    let mut bifrost_keypairs = BTreeMap::new();
    for i in 1..=cfg.demo.max_signers {
        let id = Identifier::try_from(i).unwrap();
        let port = cfg.demo.base_port + (i - 1);
        let mut seed = [0x11u8; 32];
        seed[31] = i as u8;
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&seed).unwrap());
        let bifrost_id_pk = keypair.x_only_public_key().0.serialize().to_vec();
        participants.insert(
            id,
            SpoInfo {
                identifier: id,
                pool_id: vec![i as u8; 28],
                // A wildcard bind address says where to LISTEN; it is not somewhere a
                // peer can connect TO. The fixture's URLs are fetched, so map it back
                // to loopback — every process in this demo is on one machine anyway.
                bifrost_url: format!(
                    "http://{}:{}",
                    fixture_url_host(&cfg.http.bind_address),
                    port
                ),
                bifrost_id_pk,
            },
        );
        bifrost_keypairs.insert(id, keypair);
    }

    StaticFixture {
        roster: Roster {
            epoch: 0,
            min_signers: cfg.demo.min_signers,
            max_signers: cfg.demo.max_signers,
            participants,
        },
        y_51: y_fed, // bootstrap: internal key = federation
        y_fed,
        federation_csv_blocks: cfg.bitcoin.federation_csv_blocks,
        // Demo mock treasury. The real treasury is resolved on-chain: the Config UTxO's
        // anchor (field 11) + the Confirmed TM chain (see cardano::tm_chain).
        treasury_outpoint: OutPoint {
            txid: Txid::from_byte_array([0xAA; 32]),
            vout: 0,
        },
        treasury_value: Amount::from_sat(10_000_000),
        pegins: vec![],
        pegouts: vec![],
        fee_rate_sat_per_vb: cfg.bitcoin.fee_rate_sat_per_vb,
        per_pegout_fee: Amount::from_sat(cfg.bitcoin.per_pegout_fee_sat),
        per_pegout_fee_floor: Amount::ZERO,
        min_peg_out_fbtc: Amount::ZERO,
        // WI-023: the no-registry demo derives each node's key from `--index`
        // via these fixture keypairs. A real on-chain-registry deployment
        // ignores them and loads each node's key from its own
        // [bifrost].skey_path (matched to the registered bifrost_id_pk).
        bifrost_keypairs,
    }
}

/// Host to put in a fixture peer URL for a given bind address. `0.0.0.0` and `::`
/// mean "every interface" to `bind(2)` and nothing at all to a client.
fn fixture_url_host(bind_address: &str) -> &str {
    match bind_address {
        "0.0.0.0" | "::" | "[::]" | "" => "127.0.0.1",
        other => other,
    }
}

#[cfg(test)]
mod url_host_tests {
    use super::fixture_url_host;

    #[test]
    fn wildcard_bind_addresses_are_not_used_as_url_hosts() {
        // `bind_address` defaults to 0.0.0.0 so a real SPO is reachable; the demo
        // reads the same key to build URLs its peers FETCH, and no client can
        // connect to a wildcard.
        assert_eq!(fixture_url_host("0.0.0.0"), "127.0.0.1");
        assert_eq!(fixture_url_host("::"), "127.0.0.1");
        assert_eq!(fixture_url_host("[::]"), "127.0.0.1");
        assert_eq!(fixture_url_host(""), "127.0.0.1");
    }

    #[test]
    fn a_specific_address_is_left_alone() {
        assert_eq!(fixture_url_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(fixture_url_host("10.0.0.5"), "10.0.0.5");
    }
}
