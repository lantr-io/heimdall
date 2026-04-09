//! Parse a `CardanoPegInRequest` into a validated `ParsedPegIn`.
//!
//! The datum is a raw `ByteString` containing a serialized Bitcoin
//! transaction. The parser deserializes it, then locates the unique
//! output that pays to the current treasury scriptPubKey — that
//! output's `(txid, vout, value)` becomes the TM input.

use bitcoin::consensus::encode::deserialize;
use bitcoin::{Amount, ScriptBuf, Transaction, Txid};

use crate::cardano::pegin_source::{CardanoOutRef, CardanoPegInRequest};

/// Dust threshold for P2TR outputs; must match `tm_builder::DUST_THRESHOLD`.
const DUST_THRESHOLD: Amount = Amount::from_sat(330);

/// A peg-in that has been parsed out of a Cardano datum and resolved
/// to a concrete Bitcoin `(outpoint, value)` paying to the treasury.
#[derive(Debug, Clone)]
pub struct ParsedPegIn {
    pub btc_tx: Transaction,
    pub btc_txid: Txid,
    pub btc_vout: u32,
    pub value: Amount,
    pub cardano_utxo: CardanoOutRef,
}

#[derive(Debug)]
pub enum ParseError {
    /// `btc_tx_bytes` did not decode as a valid Bitcoin transaction.
    InvalidBtcTx(String),
    /// No output in the parsed transaction pays to the treasury
    /// scriptPubKey — the depositor submitted an unrelated tx, or the
    /// treasury address has rotated since the request was posted.
    NoTreasuryOutput,
    /// More than one output pays to the treasury. The peg-in contract
    /// requires exactly one — otherwise we can't unambiguously pick a
    /// `vout` for the TM input.
    AmbiguousTreasuryOutput,
    /// The matching output was below dust (330 sat).
    DustOutput,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBtcTx(s) => write!(f, "invalid bitcoin tx: {s}"),
            Self::NoTreasuryOutput => write!(f, "no output pays to the treasury"),
            Self::AmbiguousTreasuryOutput => {
                write!(f, "multiple outputs pay to the treasury")
            }
            Self::DustOutput => write!(f, "treasury output below dust"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a raw Cardano peg-in request into a `ParsedPegIn`.
///
/// `treasury_script_pubkey` is the current Taproot output key's scriptPubKey —
/// the collector computes it from `group_keys` + the treasury oracle before
/// calling into the parser.
pub fn parse_pegin_request(
    req: &CardanoPegInRequest,
    treasury_script_pubkey: &ScriptBuf,
) -> Result<ParsedPegIn, ParseError> {
    let btc_tx: Transaction = deserialize(&req.btc_tx_bytes)
        .map_err(|e| ParseError::InvalidBtcTx(e.to_string()))?;
    let btc_txid = btc_tx.compute_txid();

    // Locate the unique output paying to the treasury.
    let mut matches = btc_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, out)| &out.script_pubkey == treasury_script_pubkey);

    let (vout, txout) = matches.next().ok_or(ParseError::NoTreasuryOutput)?;
    if matches.next().is_some() {
        return Err(ParseError::AmbiguousTreasuryOutput);
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
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, Script, Sequence, TxIn, TxOut, Witness,
    };

    fn treasury_script() -> ScriptBuf {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        ScriptBuf::new_p2tr(&secp, xonly, None)
    }

    fn other_script(tag: u8) -> ScriptBuf {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[tag; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        ScriptBuf::new_p2tr(&secp, xonly, None)
    }

    fn make_btc_tx(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x55; 32]),
                    vout: 0,
                },
                script_sig: Script::new().into(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::default(),
            }],
            output: outputs,
        }
    }

    fn make_req(btc_tx_bytes: Vec<u8>) -> CardanoPegInRequest {
        CardanoPegInRequest {
            cardano_utxo: CardanoOutRef {
                tx_hash: [0xAA; 32],
                output_index: 7,
            },
            btc_tx_bytes,
        }
    }

    #[test]
    fn parse_happy_path_picks_correct_vout() {
        let treasury = treasury_script();
        let decoy = other_script(0x22);

        // vout 0 = decoy, vout 1 = treasury, vout 2 = decoy
        let tx = make_btc_tx(vec![
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: decoy.clone(),
            },
            TxOut {
                value: Amount::from_sat(1_234_567),
                script_pubkey: treasury.clone(),
            },
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: decoy,
            },
        ]);

        let req = make_req(serialize(&tx));
        let parsed = parse_pegin_request(&req, &treasury).expect("should parse");

        assert_eq!(parsed.btc_txid, tx.compute_txid());
        assert_eq!(parsed.btc_vout, 1);
        assert_eq!(parsed.value, Amount::from_sat(1_234_567));
        assert_eq!(parsed.cardano_utxo.tx_hash, [0xAA; 32]);
        assert_eq!(parsed.cardano_utxo.output_index, 7);
    }

    #[test]
    fn parse_rejects_garbage_bytes() {
        let req = make_req(vec![0xFF, 0xFF, 0xFF, 0xFF]);
        let err = parse_pegin_request(&req, &treasury_script()).unwrap_err();
        assert!(matches!(err, ParseError::InvalidBtcTx(_)));
    }

    #[test]
    fn parse_rejects_no_treasury_output() {
        let tx = make_btc_tx(vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: other_script(0x33),
        }]);
        let req = make_req(serialize(&tx));
        let err = parse_pegin_request(&req, &treasury_script()).unwrap_err();
        assert!(matches!(err, ParseError::NoTreasuryOutput));
    }

    #[test]
    fn parse_rejects_ambiguous_treasury_outputs() {
        let treasury = treasury_script();
        let tx = make_btc_tx(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: treasury.clone(),
            },
            TxOut {
                value: Amount::from_sat(200_000),
                script_pubkey: treasury.clone(),
            },
        ]);
        let req = make_req(serialize(&tx));
        let err = parse_pegin_request(&req, &treasury).unwrap_err();
        assert!(matches!(err, ParseError::AmbiguousTreasuryOutput));
    }

    #[test]
    fn parse_rejects_dust() {
        let treasury = treasury_script();
        let tx = make_btc_tx(vec![TxOut {
            value: Amount::from_sat(329), // one below dust
            script_pubkey: treasury.clone(),
        }]);
        let req = make_req(serialize(&tx));
        let err = parse_pegin_request(&req, &treasury).unwrap_err();
        assert!(matches!(err, ParseError::DustOutput));
    }
}
