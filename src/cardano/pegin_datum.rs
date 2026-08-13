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
//! 2. The BTC tx has exactly one `OP_RETURN "BFR" || Q_auth` beacon
//!    output (spec § Peg-in deposit). `Q_auth` is the depositor's Taproot
//!    OUTPUT key and it does two jobs: the deposit's refund leaf commits
//!    it, and the BIP-322 peg-in completion is signed under it. Reading
//!    the beacon therefore hands an SPO the refund key outright.
//! 3. From the on-chain treasury oracle — the group key `Y_51`, the
//!    federation key `Y_fed` and its CSV delay — plus the `refund_timeout`
//!    protocol parameter, we reconstruct the expected peg-in Taproot address
//!    Q via `pegin_spend_info`. The tree has two leaves: the federation's
//!    emergency sweep and the depositor's refund.
//! 4. Exactly one tx output must pay to that Q; that output's
//!    `(txid, vout, value)` becomes the TM input.

use bitcoin::consensus::encode::deserialize;
use bitcoin::key::{Secp256k1, UntweakedPublicKey};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Amount, ScriptBuf, Transaction, Txid};
use pallas_primitives::PlutusData;

use crate::bitcoin::taproot::{PeginTreeParams, pegin_spend_info};
use crate::cardano::pegin_source::{CardanoOutRef, CardanoPegInRequest};

/// Dust threshold for P2TR outputs; must match `tm_builder::DUST_THRESHOLD`.
const DUST_THRESHOLD: Amount = Amount::from_sat(330);

/// 3-byte beacon marker `"BFR"` that prefixes the OP_RETURN payload on
/// every Bifrost peg-in tx.
const BEACON_MARKER: &[u8; 3] = b"BFR";

/// Full scriptPubKey length of the beacon OP_RETURN:
/// OP_RETURN (1) + push-35 (1) + "BFR" (3) + Q_auth (32) = 37 bytes.
const BEACON_SCRIPT_LEN: usize = 37;

/// Push-opcode value matching the 35-byte payload ("BFR" || Q_auth).
/// The retired 67-byte form (0x43) is not accepted: it carried a separate refund
/// key `D` only because the refund leaf committed `D`. The leaf commits `Q_auth`
/// now, so the second key has nothing left to name — and accepting both widths
/// would keep alive the refund-key search this format removes (WI-037, WI-073).
const BEACON_PUSH_OPCODE: u8 = 0x23; // OP_PUSHBYTES_35

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
    /// The `BFR` beacon payload: the depositor's Taproot **output key**
    /// `Q_auth`, the only depositor key the protocol has. It is the key in the
    /// peg-in tree's `<refund_timeout> OP_CSV OP_DROP <Q_auth> OP_CHECKSIG`
    /// leaf — so it is the merkle-root input, needed to compute the key-path
    /// tweak when FROST-signing the TM input — and it is the key the BIP-322
    /// peg-in completion is signed under. Read from the beacon, never guessed.
    pub depositor_outputkey: UntweakedPublicKey,
    /// The peg-in `TaprootSpendInfo` derived during validation. Carried
    /// out so callers building the TM input don't recompute (and risk
    /// drifting from) the spend info this parse already proved matches
    /// the on-chain scriptPubKey.
    pub spend_info: TaprootSpendInfo,
}

#[derive(Debug)]
pub enum ParseError {
    /// Datum is not `Constr 0` or has the wrong field count / field
    /// types. Only field[1] (BoundedBytes = raw BTC tx) is inspected.
    BadDatumShape(String),
    /// Field[1] did not decode as a valid Bitcoin transaction.
    InvalidBtcTx(String),
    /// No `OP_RETURN "BFR"||xonly` output in the BTC tx. Either not a
    /// Bifrost peg-in, or the depositor built the tx incorrectly.
    NoBeacon,
    /// More than one beacon output — ambiguous; reject.
    AmbiguousBeacon,
    /// Beacon push and marker matched, but the 32-byte payload is not
    /// a valid x-only pubkey (point not on the curve / parity error).
    InvalidBeaconXonly(String),
    /// No tx output pays to the spec-derived peg-in Taproot address
    /// for the (Y_51, refund_timeout, Q_auth) tuple. Either the depositor
    /// used a stale `Y_51`, or built the refund leaf over a key other than
    /// the one their beacon names, or the attacker fabricated the
    /// PegInRequest over an unrelated BTC tx.
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
            Self::InvalidBeaconXonly(s) => write!(f, "invalid beacon xonly pubkey: {s}"),
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

/// Scan a BTC tx for the Bifrost beacon OP_RETURN output and return the
/// depositor's Taproot output key. Exactly one beacon must exist, and its
/// 32-byte payload must be a valid curve point.
///
/// ScriptPubKey shape (37 bytes):
/// ```text
/// 6a 23 42 46 52 <32-byte Q_auth>
/// ^^ ^^ ^^^^^^^^ ^^^^^^^^^^^^^^^^
/// |  |  "BFR"    the depositor's Taproot output key
/// |  push-35 (0x23)
/// OP_RETURN
/// ```
/// The one key it carries serves both roles: the deposit's refund leaf commits
/// it, and the BIP-322 completion signature verifies against it.
pub fn parse_beacon(tx: &Transaction) -> Result<UntweakedPublicKey, ParseError> {
    let mut found: Option<UntweakedPublicKey> = None;
    for out in &tx.output {
        let bytes = out.script_pubkey.as_bytes();
        if bytes.len() != BEACON_SCRIPT_LEN {
            continue;
        }
        if bytes[0] != 0x6a || bytes[1] != BEACON_PUSH_OPCODE || &bytes[2..5] != BEACON_MARKER {
            continue;
        }
        let depositor = UntweakedPublicKey::from_slice(&bytes[5..37])
            .map_err(|e| ParseError::InvalidBeaconXonly(e.to_string()))?;
        if found.is_some() {
            return Err(ParseError::AmbiguousBeacon);
        }
        found = Some(depositor);
    }
    found.ok_or(ParseError::NoBeacon)
}

/// Parse and validate a raw Cardano peg-in request.
///
/// `tree` carries the bridge-wide half of the peg-in Taproot — every value except the
/// depositor's. All of it comes from the on-chain treasury oracle ([`crate::epoch::traits::TreasuryUtxo`] has
/// `y_51`, `y_fed` and `federation_csv_blocks`), so no node configures any of it. The
/// internal key is `Y_51`, the FROST group key, and NOT `Y_fed`: commit `6af7c67`
/// ("simplify peg-in Taproot to Y_fed") switched it as a demo shortcut, and
/// spec-compliant deposits are keyed to `Y_51`.
///
/// The tree has TWO leaves (spec § Peg-in Taproot tree): the federation's emergency
/// sweep under `Y_fed`, and the depositor's refund under `Q_auth` — the Taproot output
/// key READ from the 35-byte beacon. Because that leaf commits the same key the beacon
/// carries, the peg-in address is computed once instead of searched for: the earlier
/// form, whose beacon named a completion key the leaf did not use, forced the refund key
/// to be recovered by reconstructing the address for every candidate key in the tx and
/// seeing which one appeared as an output — ambiguous whenever more than one matched.
pub fn parse_pegin_request(
    req: &CardanoPegInRequest,
    tree: &PeginTreeParams,
) -> Result<ParsedPegIn, ParseError> {
    // 1. Decode the Cardano datum: we only trust field[1] (raw tx).
    let plutus: PlutusData = pallas_codec::minicbor::decode(&req.datum_cbor)
        .map_err(|e| ParseError::BadDatumShape(format!("cbor: {e}")))?;
    let btc_tx_bytes = extract_raw_btc_tx(&plutus)?;

    // 2. Deserialize the referenced BTC tx.
    let btc_tx: Transaction =
        deserialize(&btc_tx_bytes).map_err(|e| ParseError::InvalidBtcTx(e.to_string()))?;
    let btc_txid = btc_tx.compute_txid();

    // 3. Read the depositor's Taproot output key Q_auth from the OP_RETURN beacon.
    let depositor_outputkey = parse_beacon(&btc_tx)?;

    // 4. Locate the deposit output. Q_auth is known and the rest of the tree comes from
    //    the oracle, so the peg-in address is computed once rather than searched for. Two
    //    outputs paying that same address remain ambiguous — this function resolves the
    //    peg-in from the tx alone, with no datum outpoint to disambiguate them — so that
    //    case is still refused.
    let secp = Secp256k1::new();
    let spend_info = pegin_spend_info(&secp, tree, depositor_outputkey);
    let expected_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    let mut hits = btc_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, txout)| txout.script_pubkey == expected_spk);
    let (vout, txout) = hits.next().ok_or(ParseError::NoPegInOutput)?;
    if hits.next().is_some() {
        return Err(ParseError::AmbiguousPegInOutput);
    }
    let value = txout.value;

    if value < DUST_THRESHOLD {
        return Err(ParseError::DustOutput);
    }

    Ok(ParsedPegIn {
        btc_tx: btc_tx.clone(),
        btc_txid,
        btc_vout: vout as u32,
        value,
        cardano_utxo: req.cardano_utxo.clone(),
        depositor_outputkey,
        spend_info,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::opcodes::all::OP_RETURN;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use bitcoin::{
        Amount, OutPoint, Sequence, TxIn, TxOut, Witness, absolute, script, transaction,
    };
    use pallas_primitives::conway::Constr;
    use pallas_primitives::{BigInt, BoundedBytes, MaybeIndefArray};

    // ------ Helpers ------------------------------------------------------

    const REFUND_TIMEOUT: u16 = 720;

    fn xonly_from_seed(seed: [u8; 32]) -> UntweakedPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&seed).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        kp.x_only_public_key().0
    }

    /// Return a deterministic depositor Taproot output key as 32 raw bytes.
    fn depositor_xonly() -> [u8; 32] {
        xonly_from_seed([0xABu8; 32]).serialize()
    }

    fn test_y_fed() -> UntweakedPublicKey {
        xonly_from_seed([0xFEu8; 32])
    }

    /// The bridge-wide tree the fixtures are built and parsed under. `test_y_fed()` is the
    /// INTERNAL key here for historical reasons (the fixtures were written when it was);
    /// what matters is that build and parse use the same params.
    fn test_tree() -> PeginTreeParams {
        PeginTreeParams {
            y_51: test_y_fed(),
            y_federation: xonly_from_seed([0xEDu8; 32]),
            federation_csv_blocks: 144,
            refund_timeout: REFUND_TIMEOUT,
        }
    }

    fn pegin_spk(depositor_xonly_bytes: [u8; 32]) -> ScriptBuf {
        let secp = Secp256k1::new();
        let depositor =
            UntweakedPublicKey::from_slice(&depositor_xonly_bytes).expect("valid xonly");
        let si = pegin_spend_info(&secp, &test_tree(), depositor);
        ScriptBuf::new_p2tr_tweaked(si.output_key())
    }

    /// Build the 35-byte one-key beacon: `"BFR" || Q_auth`.
    fn beacon_spk(depositor_key: [u8; 32]) -> ScriptBuf {
        let mut payload = Vec::with_capacity(35);
        payload.extend_from_slice(BEACON_MARKER);
        payload.extend_from_slice(&depositor_key);
        script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(payload.as_slice()).unwrap())
            .into_script()
    }

    /// Build the retired 67-byte dual-key beacon `"BFR" || D || Q_auth`, kept
    /// only to prove it is refused rather than dual-read.
    fn beacon_spk_dual(refund: [u8; 32], auth: [u8; 32]) -> ScriptBuf {
        let mut payload = Vec::with_capacity(67);
        payload.extend_from_slice(BEACON_MARKER);
        payload.extend_from_slice(&refund);
        payload.extend_from_slice(&auth);
        script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(payload.as_slice()).unwrap())
            .into_script()
    }

    /// Build a peg-in BTC tx with: 1 input (dummy P2WPKH), 1 P2TR peg-in
    /// output at `amount`, 1 OP_RETURN beacon, 1 change output.
    fn build_pegin_tx(depositor_xonly_bytes: [u8; 32], amount: Amount) -> Transaction {
        let change_script =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x33; 20]));
        build_tx_with_outputs(vec![
            TxOut {
                value: amount,
                script_pubkey: pegin_spk(depositor_xonly_bytes),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(depositor_xonly_bytes),
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
        parse_pegin_request(req, &test_tree())
    }

    // ------ Happy path --------------------------------------------------

    #[test]
    fn parse_happy_path() {
        let xonly = depositor_xonly();
        let tx = build_pegin_tx(xonly, Amount::from_sat(1_234_567));
        let expected_txid = tx.compute_txid();

        let req = make_request(build_datum_bytes(serialize(&tx)));
        let parsed = parse(&req).expect("should parse");

        assert_eq!(parsed.btc_txid, expected_txid);
        assert_eq!(parsed.btc_vout, 0);
        assert_eq!(parsed.value, Amount::from_sat(1_234_567));
        assert_eq!(parsed.cardano_utxo.tx_hash, [0xAA; 32]);
        assert_eq!(parsed.cardano_utxo.output_index, 7);
        assert_eq!(parsed.depositor_outputkey.serialize(), xonly);
    }

    /// Golden, end-to-end: a deposit tx built by the `depositor` binary parses here.
    /// The two sides of the peg-in are written independently — `depositor` derives
    /// `Q_auth` from a WIF and builds `Taproot(Y_51, refund_leaf(Q_auth))`, this
    /// parser reads `Q_auth` back out of the beacon and reconstructs the same
    /// address — so nothing but agreement on the format makes them meet.
    ///
    /// Reproduce (the WIF is a throwaway; its key is public in the tx anyway):
    /// ```text
    /// cargo run --bin depositor -- --config heimdall.testnet4.toml \
    ///   --frost-key b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854 \
    ///   --y-federation b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854 \
    ///   --federation-csv-blocks 144 --refund-timeout-blocks 720 \
    ///   --depositor-wif cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw \
    ///   --deposit-amount-sat 50000 --fee-sat 2000 \
    ///   --funding-txid 7afd38db928a8f30f789d5c2dc9f918a6b55f85dd251f42f2e31b535bdaa0583 \
    ///   --funding-vout 2 --funding-amount-sat 100000
    /// ```
    #[test]
    fn depositor_built_deposit_round_trips() {
        let raw_tx = hex::decode("020000000001018305aabd35b5312e2ff451d25df8556b8a919fdcc2d589f7308f8a92db38fd7a0200000000fdffffff0350c300000000000022512069cf12c4a55c407ba4ffae3bcad9832d2f6fb0f36e555265b9f72428539850830000000000000000256a234246522a64b1ee3375f3bb4b367b8cb8384a47f73cf231717f827c6c6fbbf5aecf0c3680bb000000000000160014fc7250a211deddc70ee5a2738de5f07817351cef0247304402205b9845147ffec180c0c2d6674b4ada8735f1738f351d30c0a32d0d294904faba02207a07d4f6a222808fd7d1c77a5c5e35a011fe87b1667bb1f4250f13a1e13f0ad20121034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa00000000")
            .unwrap();
        let y_51 = UntweakedPublicKey::from_slice(
            &hex::decode("b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854")
                .unwrap(),
        )
        .unwrap();

        // The live demo pins Y_federation to the FROST key's own value, so both are y_51 here.
        let tree = PeginTreeParams {
            y_51,
            y_federation: y_51,
            federation_csv_blocks: 144,
            refund_timeout: 720,
        };
        let req = make_request(build_datum_bytes(raw_tx));
        let parsed = parse_pegin_request(&req, &tree).expect("depositor output must parse");

        assert_eq!(parsed.btc_vout, 0);
        assert_eq!(parsed.value, Amount::from_sat(50_000));
        // Q_auth = BIP-86(WIF), the key the beacon carries and the refund leaf commits.
        assert_eq!(
            hex::encode(parsed.depositor_outputkey.serialize()),
            "2a64b1ee3375f3bb4b367b8cb8384a47f73cf231717f827c6c6fbbf5aecf0c36"
        );
        // The reconstruction landed on the address the depositor actually paid. Both sides
        // of that are this crate's, so it proves internal consistency and nothing more.
        // The CROSS-implementation check is not automated here: ft's
        // `documentation/pegin_deposit.py` and the frontend's bitcoinjs-lib were each run by
        // hand on these inputs (2026-08-13) and produced the same 69cf12c4… output key. If
        // the leaf depth or ordering ever diverges between the three, this test stays green
        // — re-run those two before trusting it.
        assert_eq!(
            hex::encode(ScriptBuf::new_p2tr_tweaked(parsed.spend_info.output_key()).as_bytes()),
            "512069cf12c4a55c407ba4ffae3bcad9832d2f6fb0f36e555265b9f7242853985083"
        );
    }

    /// Golden: the real third-party BIP-322 deposit (cardano `d8bed7d4…` / testnet4
    /// `badb6b79…:0`) carries a 35-byte beacon of exactly the accepted width, yet is
    /// still unsweepable — it predates the rule that the beacon's key is the key the
    /// refund leaf commits, so the two disagree and the deposit address does not
    /// reconstruct. The width check passes and the reconstruction is what refuses it.
    #[test]
    fn real_legacy_bip322_deposit_is_refused() {
        // A REAL preprod deposit, recorded when the beacon named only the completion
        // key. Its two depositor keys are genuinely decoupled —
        //   refund leaf = 681d0ee1e24d4bb8ac00cb5a62755eca29e71cb60116bc31c6a79d3863b640c2
        //                 (the change / self-send output key)
        //   beacon      = 346dd9ec860a874859b0ca49f8844b7c5dbd01d36301e4a5b60c03a07b68aeed
        //                 (the BIP-322 completion key)
        // — which is precisely what the one-key form forbids: a sweeper reconstructs
        // Taproot(Y_51, refund(beacon_key, 720)) and gets an address this tx never
        // pays. Recovering the leaf key by trying every P2TR output instead is the
        // search WI-037/WI-073 removed, so the deposit is refused rather than hunted
        // for. Deposits made before the rule are unsweepable by design.
        let raw_tx = hex::decode("02000000018305aabd35b5312e2ff451d25df8556b8a919fdcc2d589f7308f8a92db38fd7a0200000000ffffffff03521600000000000022512047e8a68afb967b171f231d3635e44d96f4a883c2a98110c578e8afbf2af4b5fd0000000000000000256a23424652346dd9ec860a874859b0ca49f8844b7c5dbd01d36301e4a5b60c03a07b68aeeddc27000000000000225120681d0ee1e24d4bb8ac00cb5a62755eca29e71cb60116bc31c6a79d3863b640c200000000")
            .unwrap();
        let y_51 = UntweakedPublicKey::from_slice(
            &hex::decode("b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854")
                .unwrap(),
        )
        .unwrap();

        // The beacon itself reads fine — it is the right width and carries a valid
        // point. Only the reconstruction refuses it.
        let btc_tx: Transaction = deserialize(&raw_tx).unwrap();
        assert_eq!(
            hex::encode(parse_beacon(&btc_tx).unwrap().serialize()),
            "346dd9ec860a874859b0ca49f8844b7c5dbd01d36301e4a5b60c03a07b68aeed"
        );

        let req = make_request(build_datum_bytes(raw_tx));
        assert!(matches!(
            parse_pegin_request(
                &req,
                &PeginTreeParams {
                    y_51,
                    ..test_tree()
                }
            )
            .unwrap_err(),
            ParseError::NoPegInOutput
        ));
    }

    /// The retired 67-byte dual-key beacon is refused outright, not dual-read:
    /// accepting both widths would keep alive the refund-key search the one-key
    /// form removes. `peg-in.ak` refuses it on chain for the same reason.
    #[test]
    fn dual_key_beacon_is_refused() {
        let xonly = depositor_xonly();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(xonly),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk_dual(xonly, xonly),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::NoBeacon));
    }

    /// The same deposit must NOT parse under the wrong internal key (the demo `Y_fed`),
    /// confirming `6af7c67`'s `Y_fed` reader genuinely can't see this deposit.
    #[test]
    fn valid_deposit_does_not_reconstruct_under_the_wrong_treasury_key() {
        // The peg-in address is Taproot(Y, refund_leaf(Q_auth)), so a deposit built
        // under one treasury key must not resolve under another.
        // `build_pegin_tx` builds under `test_y_fed()`; parse under a different key.
        let xonly = depositor_xonly();
        let tx = build_pegin_tx(xonly, Amount::from_sat(50_000));
        let req = make_request(build_datum_bytes(serialize(&tx)));
        let other_treasury_key = xonly_from_seed([0xAB; 32]);
        assert_ne!(other_treasury_key, test_y_fed());
        assert!(matches!(
            parse_pegin_request(
                &req,
                &PeginTreeParams {
                    y_51: other_treasury_key,
                    ..test_tree()
                }
            )
            .unwrap_err(),
            ParseError::NoPegInOutput
        ));
    }

    #[test]
    fn parse_happy_path_pegin_not_first_output() {
        // Beacon first, then peg-in — vout should be 1.
        let xonly = depositor_xonly();
        let change_script =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x33; 20]));
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(xonly),
            },
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(xonly),
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
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::BadDatumShape(_)
        ));
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
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::BadDatumShape(_)
        ));
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
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::BadDatumShape(_)
        ));
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
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::BadDatumShape(_)
        ));
    }

    // ------ BTC tx parsing failures -------------------------------------

    #[test]
    fn btc_tx_garbage() {
        // Valid datum, but field[1] is not a valid BTC tx.
        let req = make_request(build_datum_bytes(vec![0xFF, 0xFF, 0xFF]));
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::InvalidBtcTx(_)
        ));
    }

    // ------ Beacon failures ---------------------------------------------

    #[test]
    fn no_beacon_output() {
        let xonly = depositor_xonly();
        let tx = build_tx_with_outputs(vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: pegin_spk(xonly),
        }]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::NoBeacon));
    }

    #[test]
    fn beacon_wrong_prefix() {
        // OP_RETURN push-35 "FOO" + xonly — not "BFR".
        let xonly = depositor_xonly();
        let mut payload = Vec::with_capacity(35);
        payload.extend_from_slice(b"FOO");
        payload.extend_from_slice(&xonly);
        let wrong_beacon = script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(payload.as_slice()).unwrap())
            .into_script();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(xonly),
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
        // OP_RETURN push-3 "BFR" — no xonly payload; total 5 bytes.
        let xonly = depositor_xonly();
        let short_beacon = script::Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(<&bitcoin::script::PushBytes>::try_from(&b"BFR"[..]).unwrap())
            .into_script();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(xonly),
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
        let xonly = depositor_xonly();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(xonly),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(xonly),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(xonly), // second beacon
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::AmbiguousBeacon
        ));
    }

    // ------ Taproot-match failures --------------------------------------

    #[test]
    fn beacon_xonly_does_not_match_taproot() {
        // Beacon says xonly_A, but the P2TR output was derived from xonly_B.
        let xonly_a = depositor_xonly();
        let xonly_b = xonly_from_seed([0xCCu8; 32]).serialize();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(xonly_b), // wrong depositor
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(xonly_a),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::NoPegInOutput
        ));
    }

    #[test]
    fn no_pegin_output_only_beacon() {
        let xonly = depositor_xonly();
        let tx = build_tx_with_outputs(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: beacon_spk(xonly),
        }]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::NoPegInOutput
        ));
    }

    /// The federation leaf is part of the address, so a wrong `y_federation` makes a real
    /// deposit unrecognisable — the failure this test's neighbours never covered, because
    /// they all vary the internal key instead.
    #[test]
    fn no_pegin_output_wrong_federation_key() {
        let xonly = depositor_xonly();
        let tx = build_pegin_tx(xonly, Amount::from_sat(100_000));
        let req = make_request(build_datum_bytes(serialize(&tx)));
        let wrong = PeginTreeParams {
            y_federation: xonly_from_seed([0x77; 32]),
            ..test_tree()
        };
        assert_ne!(wrong.y_federation, test_tree().y_federation);
        assert!(matches!(
            parse_pegin_request(&req, &wrong).unwrap_err(),
            ParseError::NoPegInOutput
        ));
    }

    /// Same for the federation leaf's CSV delay: it is hashed into the leaf, so it moves the
    /// address just as surely as the key does.
    #[test]
    fn no_pegin_output_wrong_federation_csv() {
        let xonly = depositor_xonly();
        let tx = build_pegin_tx(xonly, Amount::from_sat(100_000));
        let req = make_request(build_datum_bytes(serialize(&tx)));
        let wrong = PeginTreeParams {
            federation_csv_blocks: test_tree().federation_csv_blocks + 1,
            ..test_tree()
        };
        assert!(matches!(
            parse_pegin_request(&req, &wrong).unwrap_err(),
            ParseError::NoPegInOutput
        ));
    }

    #[test]
    fn no_pegin_output_wrong_y_fed() {
        // Build the peg-in address from a *different* Y_fed than the
        // parser will use. parse() uses test_y_fed(); we use a stale
        // one here.
        let xonly = depositor_xonly();
        let stale_y_fed = xonly_from_seed([0x99u8; 32]);
        let secp = Secp256k1::new();
        let depositor = UntweakedPublicKey::from_slice(&xonly).unwrap();
        let stale_tree = PeginTreeParams {
            y_51: stale_y_fed,
            ..test_tree()
        };
        let stale_si = pegin_spend_info(&secp, &stale_tree, depositor);
        let stale_spk = ScriptBuf::new_p2tr_tweaked(stale_si.output_key());

        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: stale_spk,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(xonly),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::NoPegInOutput
        ));
    }

    #[test]
    fn ambiguous_pegin_outputs() {
        // Two outputs paying the correct peg-in Taproot.
        let xonly = depositor_xonly();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(xonly),
            },
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: pegin_spk(xonly),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(xonly),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::AmbiguousPegInOutput
        ));
    }

    #[test]
    fn dust_output() {
        let xonly = depositor_xonly();
        let tx = build_tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(329), // one below dust
                script_pubkey: pegin_spk(xonly),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: beacon_spk(xonly),
            },
        ]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(parse(&req).unwrap_err(), ParseError::DustOutput));
    }

    #[test]
    fn beacon_xonly_not_on_curve() {
        // Beacon payload is 32 bytes but is not a valid x-only point.
        let invalid_xonly = [0xFFu8; 32];
        let tx = build_tx_with_outputs(vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: beacon_spk(invalid_xonly),
        }]);
        let req = make_request(build_datum_bytes(serialize(&tx)));
        assert!(matches!(
            parse(&req).unwrap_err(),
            ParseError::InvalidBeaconXonly(_)
        ));
    }

    // ------ Raw beacon parser tests -------------------------------------

    #[test]
    fn beacon_parser_direct_happy() {
        let xonly = depositor_xonly();
        let tx = build_pegin_tx(xonly, Amount::from_sat(50_000));
        let depositor = parse_beacon(&tx).unwrap();
        assert_eq!(depositor.serialize(), xonly);
    }

    #[test]
    fn beacon_parser_direct_missing() {
        let tx = build_tx_with_outputs(vec![TxOut {
            value: Amount::from_sat(100),
            script_pubkey: ScriptBuf::new(),
        }]);
        assert!(matches!(
            parse_beacon(&tx).unwrap_err(),
            ParseError::NoBeacon
        ));
    }
}
