//! Parse a `CardanoPegInRequest` into a validated `ParsedPegIn`.
//!
//! PegInRequest UTxOs on Cardano are permissionless — anyone can post
//! one that references any confirmed BTC tx. The SPO's job at
//! collection time is to verify the referenced tx is actually a
//! Bifrost peg-in per the technical spec:
//!
//! 1. The Cardano datum is `Constr 0 [...]` matching the Aiken
//!    `PegInDatum` record; field index 1 is the raw BTC tx. All other
//!    datum fields are attacker-controlled noise and are ignored —
//!    they will be removed from the spec later.
//! 2. The BTC tx has exactly one `OP_RETURN "BFR" || depositor_pkh`
//!    beacon output (spec § Peg-in deposit). This is how watchtowers
//!    and SPOs recover the depositor's pubkey hash.
//! 3. Using the current `Y_51` and `Y_fed` from the on-chain treasury
//!    state, the protocol-constant `federation_timeout`, and
//!    `refund_timeout` (4320 blocks ≈ 30 days per spec, overridable
//!    per-network), we reconstruct the expected peg-in Taproot address
//!    Q via `pegin_spend_info`.
//! 4. Exactly one tx output must pay to that Q; that output's
//!    `(txid, vout, value)` becomes the TM input.

use bitcoin::consensus::encode::deserialize;
use bitcoin::key::{Secp256k1, UntweakedPublicKey};
use bitcoin::{Amount, ScriptBuf, Transaction, Txid};
use pallas_primitives::PlutusData;

use crate::bitcoin::taproot::pegin_spend_info;
use crate::cardano::pegin_source::{CardanoOutRef, CardanoPegInRequest};

/// Dust threshold for P2TR outputs; must match `tm_builder::DUST_THRESHOLD`.
const DUST_THRESHOLD: Amount = Amount::from_sat(330);

/// 3-byte beacon marker `"BFR"` that prefixes the OP_RETURN payload on
/// every Bifrost peg-in tx.
const BEACON_MARKER: &[u8; 3] = b"BFR";

/// Full scriptPubKey length of the beacon OP_RETURN:
/// OP_RETURN (1) + push-23 (1) + "BFR" (3) + pkh (20) = 25 bytes.
const BEACON_SCRIPT_LEN: usize = 25;

/// A peg-in that has been parsed out of a Cardano datum and resolved
/// to a concrete Bitcoin `(outpoint, value)` paying to the
/// spec-derived peg-in Taproot address.
#[derive(Debug, Clone)]
pub struct ParsedPegIn {
    pub btc_tx: Transaction,
    pub btc_txid: Txid,
    pub btc_vout: u32,
    pub value: Amount,
    pub cardano_utxo: CardanoOutRef,
    /// HASH160 of the depositor's BTC x-only pubkey, recovered from
    /// the OP_RETURN beacon. Needed later to reconstruct the peg-in
    /// script tree for FROST-signing the TM input.
    pub depositor_pkh: [u8; 20],
}

#[derive(Debug)]
pub enum ParseError {
    /// Datum is not `Constr 0` or has the wrong field count / field
    /// types. Only field[1] (BoundedBytes = raw BTC tx) is inspected.
    BadDatumShape(String),
    /// Field[1] did not decode as a valid Bitcoin transaction.
    InvalidBtcTx(String),
    /// No `OP_RETURN "BFR"||pkh` output in the BTC tx. Either not a
    /// Bifrost peg-in, or the depositor built the tx incorrectly.
    NoBeacon,
    /// More than one beacon output — ambiguous; reject.
    AmbiguousBeacon,
    /// No tx output pays to the spec-derived peg-in Taproot address
    /// for the (Y_51, Y_fed, timeouts, depositor_pkh) tuple. Either
    /// the depositor used a stale `Y_51`, or the attacker fabricated
    /// the PegInRequest over an unrelated BTC tx.
    NoPegInOutput,
    /// More than one output pays to the peg-in Taproot — ambiguous;
    /// reject rather than guess a `vout`.
    AmbiguousPegInOutput,
    /// The matching peg-in output was below dust (330 sat).
    DustOutput,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadDatumShape(s) => write!(f, "bad datum shape: {s}"),
            Self::InvalidBtcTx(s) => write!(f, "invalid bitcoin tx: {s}"),
            Self::NoBeacon => write!(f, "no OP_RETURN BFR beacon"),
            Self::AmbiguousBeacon => write!(f, "multiple OP_RETURN BFR beacons"),
            Self::NoPegInOutput => write!(f, "no output pays to the peg-in Taproot"),
            Self::AmbiguousPegInOutput => {
                write!(f, "multiple outputs pay to the peg-in Taproot")
            }
            Self::DustOutput => write!(f, "peg-in output below dust"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Decode the Cardano peg-in datum and return field[1] (raw BTC tx
/// bytes). The datum is the Aiken `PegInDatum` record — 7 fields,
/// Constr tag 0 (CBOR tag 121). We only read field[1]; the other six
/// are untrusted / slated for removal.
pub fn extract_raw_btc_tx(data: &PlutusData) -> Result<Vec<u8>, ParseError> {
    let (tag, fields) = match data {
        PlutusData::Constr(c) => (c.tag, &c.fields),
        _ => return Err(ParseError::BadDatumShape("top level not Constr".into())),
    };

    // Plutus `Constr 0` encodes as CBOR tag 121.
    if tag != 121 {
        return Err(ParseError::BadDatumShape(format!(
            "expected Constr 0 (tag 121), got tag {tag}"
        )));
    }

    // Aiken PegInDatum has exactly 7 fields (see onchain/lib/bifrost/types/peg-in.ak).
    if fields.len() != 7 {
        return Err(ParseError::BadDatumShape(format!(
            "expected 7 fields, got {}",
            fields.len()
        )));
    }

    match &fields[1] {
        PlutusData::BoundedBytes(b) => Ok(b.clone().into()),
        _ => Err(ParseError::BadDatumShape(
            "field[1] (source_chain_peg_in_raw_tx) is not BoundedBytes".into(),
        )),
    }
}

/// Scan a BTC tx for the Bifrost beacon OP_RETURN output and return
/// the 20-byte depositor pubkey hash. Exactly one beacon must exist.
///
/// ScriptPubKey shape (25 bytes):
/// ```text
/// 6a 17 42 46 52 <20-byte-pkh>
/// ^^ ^^ ^^^^^^^^
/// |  |  "BFR"
/// |  push-23 (0x17)
/// OP_RETURN
/// ```
pub fn parse_beacon(tx: &Transaction) -> Result<[u8; 20], ParseError> {
    let mut found: Option<[u8; 20]> = None;
    for out in &tx.output {
        let bytes = out.script_pubkey.as_bytes();
        if bytes.len() != BEACON_SCRIPT_LEN {
            continue;
        }
        // OP_RETURN, push-23 (0x17), "BFR"
        if bytes[0] != 0x6a || bytes[1] != 0x17 || &bytes[2..5] != BEACON_MARKER {
            continue;
        }
        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&bytes[5..25]);
        if found.is_some() {
            return Err(ParseError::AmbiguousBeacon);
        }
        found = Some(pkh);
    }
    found.ok_or(ParseError::NoBeacon)
}

/// Parse and validate a raw Cardano peg-in request.
///
/// `y_51` / `y_fed` come from the current on-chain treasury state;
/// `federation_timeout` and `refund_timeout` are protocol parameters
/// (the latter overridable per-network for testnet4/preprod).
pub fn parse_pegin_request(
    req: &CardanoPegInRequest,
    y_51: UntweakedPublicKey,
    y_fed: UntweakedPublicKey,
    federation_timeout: u16,
    refund_timeout: u16,
) -> Result<ParsedPegIn, ParseError> {
    // 1. Decode the Cardano datum: we only trust field[1] (raw tx).
    let plutus: PlutusData = pallas_codec::minicbor::decode(&req.datum_cbor)
        .map_err(|e| ParseError::BadDatumShape(format!("cbor: {e}")))?;
    let btc_tx_bytes = extract_raw_btc_tx(&plutus)?;

    // 2. Deserialize the referenced BTC tx.
    let btc_tx: Transaction = deserialize(&btc_tx_bytes)
        .map_err(|e| ParseError::InvalidBtcTx(e.to_string()))?;
    let btc_txid = btc_tx.compute_txid();

    // 3. Recover the depositor pkh from the OP_RETURN beacon.
    let depositor_pkh = parse_beacon(&btc_tx)?;

    // 4. Reconstruct the spec-defined peg-in Taproot address and find
    //    the unique output paying to it.
    let secp = Secp256k1::new();
    let spend_info = pegin_spend_info(
        &secp,
        y_51,
        y_fed,
        federation_timeout,
        depositor_pkh,
        refund_timeout,
    );
    let expected_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    let mut matches = btc_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, out)| out.script_pubkey == expected_spk);

    let (vout, txout) = matches.next().ok_or(ParseError::NoPegInOutput)?;
    if matches.next().is_some() {
        return Err(ParseError::AmbiguousPegInOutput);
    }

    if txout.value < DUST_THRESHOLD {
        return Err(ParseError::DustOutput);
    }

    Ok(ParsedPegIn {
        btc_tx: btc_tx.clone(),
        btc_txid,
        btc_vout: vout as u32,
        value: txout.value,
        cardano_utxo: req.cardano_utxo.clone(),
        depositor_pkh,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::{hash160, Hash as _};
    use bitcoin::opcodes::all::OP_RETURN;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use bitcoin::{
        absolute, script, transaction, Amount, OutPoint, Sequence, TxIn, TxOut, Witness,
    };
    use pallas_primitives::conway::Constr;
    use pallas_primitives::{BigInt, BoundedBytes, MaybeIndefArray};

    // ------ Helpers ------------------------------------------------------

    const FED_TIMEOUT: u16 = 144;
    const REFUND_TIMEOUT: u16 = 4320;

    fn xonly_from_seed(seed: [u8; 32]) -> UntweakedPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&seed).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        kp.x_only_public_key().0
    }

    fn depositor_keys() -> ([u8; 32], [u8; 20]) {
        let seed = [0xABu8; 32];
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&seed).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let xonly_bytes = xonly.serialize();
        let pkh = hash160::Hash::hash(&xonly_bytes).to_byte_array();
        (xonly_bytes, pkh)
    }

    fn test_keys() -> (UntweakedPublicKey, UntweakedPublicKey) {
        (xonly_from_seed([0x51u8; 32]), xonly_from_seed([0xFEu8; 32]))
    }

    fn pegin_spk(depositor_pkh: [u8; 20]) -> ScriptBuf {
        let secp = Secp256k1::new();
        let (y_51, y_fed) = test_keys();
        let si = pegin_spend_info(
            &secp,
            y_51,
            y_fed,
            FED_TIMEOUT,
            depositor_pkh,
            REFUND_TIMEOUT,
        );
        ScriptBuf::new_p2tr_tweaked(si.output_key())
    }

    fn beacon_spk(pkh: [u8; 20]) -> ScriptBuf {
        let mut payload = Vec::with_capacity(23);
        payload.extend_from_slice(BEACON_MARKER);
        payload.extend_from_slice(&pkh);
        script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(payload.as_slice()).unwrap())
            .into_script()
    }

    /// Build a peg-in BTC tx with: 1 input (dummy P2WPKH), 1 P2TR peg-in
    /// output at `amount`, 1 OP_RETURN beacon, 1 change output.
    fn build_pegin_tx(depositor_pkh: [u8; 20], amount: Amount) -> Transaction {
        let change_script =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x33; 20]));
        build_tx_with_outputs(vec![
            TxOut {
                value: amount,
                script_pubkey: pegin_spk(depositor_pkh),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(depositor_pkh),
            },
            TxOut {
                value: Amount::from_sat(500_000),
                script_pubkey: change_script,
            },
        ])
    }

    fn build_tx_with_outputs(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x55; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::default(),
            }],
            output: outputs,
        }
    }

    /// Build a full Aiken `PegInDatum` Constr with the raw tx in field[1].
    /// Other fields are filler — production SPOs must ignore them.
    fn build_datum_bytes(raw_tx: Vec<u8>) -> Vec<u8> {
        // Filler `AuthorizationMethod::CardanoSignature { hash: .. }`:
        // Constr(0, [BoundedBytes(28-byte hash)]) = tag 121.
        let owner_auth = PlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![PlutusData::BoundedBytes(BoundedBytes::from(
                vec![0u8; 28],
            ))]),
        });
        let int_zero = PlutusData::BigInt(BigInt::Int(0.into()));
        let empty_bytes = PlutusData::BoundedBytes(BoundedBytes::from(vec![]));

        let datum = PlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![
                owner_auth,
                PlutusData::BoundedBytes(BoundedBytes::from(raw_tx)),
                int_zero.clone(),
                empty_bytes.clone(), // peg_in_utxo_id (ignored)
                empty_bytes.clone(), // source_chain_treasury_utxo_id (ignored)
                int_zero,            // peg_in_amount (ignored)
                empty_bytes,         // user_source_chain_pub_key (ignored)
            ]),
        });
        pallas_codec::minicbor::to_vec(&datum).unwrap()
    }

    fn make_request(datum_bytes: Vec<u8>) -> CardanoPegInRequest {
        CardanoPegInRequest {
            cardano_utxo: CardanoOutRef {
                tx_hash: [0xAA; 32],
                output_index: 7,
            },
            datum_cbor: datum_bytes,
        }
    }

    fn parse(req: &CardanoPegInRequest) -> Result<ParsedPegIn, ParseError> {
        let (y_51, y_fed) = test_keys();
        parse_pegin_request(req, y_51, y_fed, FED_TIMEOUT, REFUND_TIMEOUT)
    }

    // ------ Happy path --------------------------------------------------

    #[test]
    fn parse_happy_path() {
        let (_, pkh) = depositor_keys();
        let tx = build_pegin_tx(pkh, Amount::from_sat(1_234_567));
        let expected_txid = tx.compute_txid();

        let req = make_request(build_datum_bytes(serialize(&tx)));
        let parsed = parse(&req).expect("should parse");

        assert_eq!(parsed.btc_txid, expected_txid);
        assert_eq!(parsed.btc_vout, 0);
        assert_eq!(parsed.value, Amount::from_sat(1_234_567));
        assert_eq!(parsed.cardano_utxo.tx_hash, [0xAA; 32]);
        assert_eq!(parsed.cardano_utxo.output_index, 7);
        assert_eq!(parsed.depositor_pkh, pkh);
    }

    #[test]
    fn parse_happy_path_pegin_not_first_output() {
        // Beacon first, then peg-in — vout should be 1.
        let (_, pkh) = depositor_keys();
        let change_script =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x33; 20]));
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(pkh),
            },
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(pkh),
            },
            TxOut {
                value: Amount::from_sat(500_000),
                script_pubkey: change_script,
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        let parsed = parse(&req).expect("should parse");
        assert_eq!(parsed.btc_vout, 1);
    }

    // ------ Datum-shape failures ----------------------------------------

    #[test]
    fn datum_raw_garbage() {
        let req = make_request(vec![0xFF, 0xFF, 0xFF]);
        assert!(matches!(parse(&req).unwrap_err(), ParseError::BadDatumShape(_)));
    }

    #[test]
    fn datum_wrong_constr_tag() {
        // Constr 1 = tag 122 — wrong.
        let datum = PlutusData::Constr(Constr {
            tag: 122,
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![
                PlutusData::BoundedBytes(BoundedBytes::from(vec![0u8; 28])),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
                PlutusData::BigInt(BigInt::Int(0.into())),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
                PlutusData::BigInt(BigInt::Int(0.into())),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
            ]),
        });
        let bytes = pallas_codec::minicbor::to_vec(&datum).unwrap();
        let req = make_request(bytes);
        assert!(matches!(parse(&req).unwrap_err(), ParseError::BadDatumShape(_)));
    }

    #[test]
    fn datum_wrong_field_count() {
        // Only 3 fields instead of 7.
        let datum = PlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
            ]),
        });
        let bytes = pallas_codec::minicbor::to_vec(&datum).unwrap();
        let req = make_request(bytes);
        assert!(matches!(parse(&req).unwrap_err(), ParseError::BadDatumShape(_)));
    }

    #[test]
    fn datum_field1_wrong_type() {
        // field[1] is Int, not Bytes.
        let datum = PlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![
                PlutusData::BoundedBytes(BoundedBytes::from(vec![0u8; 28])),
                PlutusData::BigInt(BigInt::Int(0.into())), // <-- wrong type
                PlutusData::BigInt(BigInt::Int(0.into())),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
                PlutusData::BigInt(BigInt::Int(0.into())),
                PlutusData::BoundedBytes(BoundedBytes::from(vec![])),
            ]),
        });
        let bytes = pallas_codec::minicbor::to_vec(&datum).unwrap();
        let req = make_request(bytes);
        assert!(matches!(parse(&req).unwrap_err(), ParseError::BadDatumShape(_)));
    }

    // ------ BTC tx parsing failures -------------------------------------

    #[test]
    fn btc_tx_garbage() {
        // Valid datum, but field[1] is not a valid BTC tx.
        let req = make_request(build_datum_bytes(vec![0xFF, 0xFF, 0xFF]));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::InvalidBtcTx(_)));
    }

    // ------ Beacon failures ---------------------------------------------

    #[test]
    fn no_beacon_output() {
        let (_, pkh) = depositor_keys();
        let tx = build_tx_with_outputs(vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: pegin_spk(pkh),
        }]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::NoBeacon));
    }

    #[test]
    fn beacon_wrong_prefix() {
        // OP_RETURN push-23 "FOO" + pkh — not "BFR".
        let (_, pkh) = depositor_keys();
        let mut payload = Vec::with_capacity(23);
        payload.extend_from_slice(b"FOO");
        payload.extend_from_slice(&pkh);
        let wrong_beacon = script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(payload.as_slice()).unwrap())
            .into_script();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(pkh),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: wrong_beacon,
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::NoBeacon));
    }

    #[test]
    fn beacon_wrong_length() {
        // OP_RETURN push-3 "BFR" — no pkh payload; total 5 bytes.
        let (_, pkh) = depositor_keys();
        let short_beacon = script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(&b"BFR"[..]).unwrap())
            .into_script();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(pkh),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: short_beacon,
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::NoBeacon));
    }

    #[test]
    fn beacon_ambiguous() {
        let (_, pkh) = depositor_keys();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(pkh),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(pkh),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(pkh), // second beacon
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::AmbiguousBeacon));
    }

    // ------ Taproot-match failures --------------------------------------

    #[test]
    fn beacon_pkh_does_not_match_taproot() {
        // Beacon says pkh_A, but the P2TR output was derived from pkh_B.
        let (_, pkh_a) = depositor_keys();
        let pkh_b = [0xCCu8; 20];
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(pkh_b), // wrong depositor
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(pkh_a),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::NoPegInOutput));
    }

    #[test]
    fn no_pegin_output_only_beacon() {
        let (_, pkh) = depositor_keys();
        let tx = build_tx_with_outputs(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: beacon_spk(pkh),
        }]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::NoPegInOutput));
    }

    #[test]
    fn no_pegin_output_wrong_y51() {
        // Build the peg-in address from a *different* Y_51 than the
        // parser will use. parse() uses test_keys()'s Y_51; we use a
        // stale one here.
        let (_, pkh) = depositor_keys();
        let stale_y_51 = xonly_from_seed([0x99u8; 32]);
        let (_, y_fed) = test_keys();
        let secp = Secp256k1::new();
        let stale_si = pegin_spend_info(
            &secp,
            stale_y_51,
            y_fed,
            FED_TIMEOUT,
            pkh,
            REFUND_TIMEOUT,
        );
        let stale_spk = ScriptBuf::new_p2tr_tweaked(stale_si.output_key());

        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: stale_spk,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(pkh),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::NoPegInOutput));
    }

    #[test]
    fn ambiguous_pegin_outputs() {
        // Two outputs paying the correct peg-in Taproot.
        let (_, pkh) = depositor_keys();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(pkh),
            },
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(pkh),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(pkh),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::AmbiguousPegInOutput));
    }

    #[test]
    fn dust_output() {
        let (_, pkh) = depositor_keys();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(329), // one below dust
                script_pubkey: pegin_spk(pkh),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(pkh),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::DustOutput));
    }

    // ------ Raw beacon parser tests -------------------------------------

    #[test]
    fn beacon_parser_direct_happy() {
        let (_, pkh) = depositor_keys();
        let tx = build_pegin_tx(pkh, Amount::from_sat(50_000));
        assert_eq!(parse_beacon(&tx).unwrap(), pkh);
    }

    #[test]
    fn beacon_parser_direct_missing() {
        let tx = build_tx_with_outputs(vec![TxOut {
            value: Amount::from_sat(100),
            script_pubkey: ScriptBuf::new(),
        }]);
        assert!(matches!(parse_beacon(&tx).unwrap_err(), ParseError::NoBeacon));
    }
}
