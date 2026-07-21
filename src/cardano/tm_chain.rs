//! Walk the Treasury Movement Confirmed chain.
//!
//! Every Confirmed TM record proves (at mint time, on-chain) that its BTC tx
//! spends the previous treasury outpoint: the Config UTxO's anchor (field 11,
//! `initial_btc_treasury_utxo`) for the first TM, or the predecessor Confirmed
//! record's output 0 for every subsequent TM. A Bitcoin outpoint spends exactly
//! once, so the Confirmed chain cannot fork - the current treasury is found by
//! walking records from the anchor: each record is indexed by the outpoint it
//! spent (`swept[0]`); the tip's `(btc_txid, 0)` with value
//! `fulfilled[0].amount` is the current treasury. Records not on the chain
//! (garbage posts that can never confirm, or abandoned pre-migration records)
//! are simply never visited.

use pallas_primitives::PlutusData;

/// A parsed on-chain `Confirmed` TM record.
#[derive(Debug, Clone)]
pub struct ConfirmedTm {
    /// `btcTxid`, internal byte order (as stored on-chain).
    pub btc_txid: [u8; 32],
    /// The outpoint this TM's BTC tx spent = `swept[0]` (txid internal ++ vout LE).
    pub spent_outpoint: [u8; 36],
    /// `fulfilled[0].amount` = the value of the new treasury output (output 0).
    pub treasury_value_sat: u64,
    /// The Cardano UTxO `(tx_hash, index)` holding this record - the mint
    /// reference input for the NEXT TM.
    pub cardano_utxo: (String, u32),
}

/// 36-byte outpoint encoding: txid internal order ++ vout LE.
#[must_use]
pub fn outpoint_bytes(op: &bitcoin::OutPoint) -> [u8; 36] {
    use bitcoin::hashes::Hash;
    let mut out = [0u8; 36];
    out[..32].copy_from_slice(op.txid.as_raw_hash().as_byte_array());
    out[32..].copy_from_slice(&op.vout.to_le_bytes());
    out
}

/// Walk from `anchor` to the chain tip. Returns `None` when no record spends
/// the anchor (genesis state: the first TM has not confirmed yet).
#[must_use]
pub fn walk_chain(anchor: [u8; 36], records: &[ConfirmedTm]) -> Option<&ConfirmedTm> {
    let mut tip: Option<&ConfirmedTm> = None;
    let mut current = anchor;
    // Bounded by records.len() hops - a cycle is impossible (each hop consumes
    // a distinct Bitcoin outpoint) but the bound keeps a malformed record set
    // from looping.
    for _ in 0..=records.len() {
        let Some(next) = records.iter().find(|r| r.spent_outpoint == current) else {
            return tip;
        };
        let mut op = [0u8; 36];
        op[..32].copy_from_slice(&next.btc_txid);
        op[32..].copy_from_slice(&0u32.to_le_bytes());
        current = op;
        tip = Some(next);
    }
    tip
}

/// Parse a `Confirmed` TM datum: Constr tag 122 with fields
/// `[BoundedBytes btcTxid, Array<BoundedBytes> swept, Array<Constr(scriptPubKey, amount)>,
/// BoundedBytes creator, BigInt created]` (creator/created ignored here).
/// Returns `(btc_txid, spent_outpoint = swept[0], treasury_value_sat = fulfilled[0].amount)`,
/// or `None` for anything else (Unconfirmed records, garbage datums).
#[must_use]
pub fn parse_confirmed_datum(data: &PlutusData) -> Option<([u8; 32], [u8; 36], u64)> {
    let PlutusData::Constr(c) = data else {
        return None;
    };
    // 5 fields since creator/created provenance was added (btcTxid, swept, fulfilled,
    // creator, created); accept >= 3 so pre-provenance fixtures/records still parse.
    if c.tag != 122 || c.fields.len() < 3 {
        return None;
    }
    let fields: Vec<&PlutusData> = c.fields.iter().collect();
    let PlutusData::BoundedBytes(txid_b) = fields[0] else {
        return None;
    };
    let btc_txid: [u8; 32] = Vec::<u8>::from(txid_b.clone()).try_into().ok()?;
    let PlutusData::Array(swept) = fields[1] else {
        return None;
    };
    let PlutusData::BoundedBytes(spent_b) = swept.iter().next()? else {
        return None;
    };
    let spent_outpoint: [u8; 36] = Vec::<u8>::from(spent_b.clone()).try_into().ok()?;
    let PlutusData::Array(fulfilled) = fields[2] else {
        return None;
    };
    let PlutusData::Constr(out0) = fulfilled.iter().next()? else {
        return None;
    };
    let out0_fields: Vec<&PlutusData> = out0.fields.iter().collect();
    let PlutusData::BigInt(amount) = out0_fields.get(1)? else {
        return None;
    };
    let sats: u64 = match amount {
        pallas_primitives::BigInt::Int(i) => u64::try_from(i128::from(*i)).ok()?,
        _ => return None,
    };
    Some((btc_txid, spent_outpoint, sats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::plutus;

    fn rec(spent: u8, txid: u8, val: u64) -> ConfirmedTm {
        let mut spent_outpoint = [spent; 36];
        spent_outpoint[32..].copy_from_slice(&0u32.to_le_bytes());
        ConfirmedTm {
            btc_txid: [txid; 32],
            spent_outpoint,
            treasury_value_sat: val,
            cardano_utxo: (format!("{txid:02x}"), 0),
        }
    }

    fn op(b: u8) -> [u8; 36] {
        let mut o = [b; 36];
        o[32..].copy_from_slice(&0u32.to_le_bytes());
        o
    }

    #[test]
    fn walk_empty_chain_returns_none() {
        assert!(walk_chain(op(0xaa), &[]).is_none());
    }

    #[test]
    fn walk_follows_anchor_to_tip() {
        // anchor aa -> tm1 (txid bb) -> tm2 (txid cc); a garbage record dd->ee is ignored.
        let records = vec![
            rec(0xaa, 0xbb, 100),
            rec(0xbb, 0xcc, 90),
            rec(0xdd, 0xee, 1),
        ];
        let tip = walk_chain(op(0xaa), &records).unwrap();
        assert_eq!(tip.btc_txid, [0xcc; 32]);
        assert_eq!(tip.treasury_value_sat, 90);
    }

    #[test]
    fn walk_ignores_records_chaining_from_unspent_outpoints() {
        // Only the record spending the anchor extends the chain; a "competitor"
        // spending a different outpoint is not the tip.
        let records = vec![rec(0x11, 0x22, 5), rec(0xaa, 0xbb, 100)];
        let tip = walk_chain(op(0xaa), &records).unwrap();
        assert_eq!(tip.btc_txid, [0xbb; 32]);
    }

    #[test]
    fn outpoint_bytes_is_txid_internal_plus_vout_le() {
        let txid: bitcoin::Txid =
            "1111111111111111111111111111111111111111111111111111111111111100"
                .parse()
                .unwrap();
        let b = outpoint_bytes(&bitcoin::OutPoint { txid, vout: 1 });
        // Display txid is byte-reversed: internal order starts with the LAST display byte pair.
        assert_eq!(b[0], 0x00);
        assert_eq!(&b[32..], &[1, 0, 0, 0]);
    }

    #[test]
    fn parse_confirmed_datum_extracts_txid_spent_and_amount() {
        // Confirmed(btcTxid, [spent0, spent1], [(spk, 7000), (spk, 1000)]) = Constr tag 122.
        let datum = plutus::constr(
            1,
            vec![
                plutus::bytes(&[0xcc; 32]),
                plutus::array(vec![plutus::bytes(&[0xaa; 36]), plutus::bytes(&[0xbb; 36])]),
                plutus::array(vec![
                    plutus::constr(0, vec![plutus::bytes(&[0x51; 34]), plutus::int(7000)]),
                    plutus::constr(0, vec![plutus::bytes(&[0x00; 22]), plutus::int(1000)]),
                ]),
            ],
        );
        let (txid, spent, sats) = parse_confirmed_datum(&datum).unwrap();
        assert_eq!(txid, [0xcc; 32]);
        assert_eq!(spent, [0xaa; 36]);
        assert_eq!(sats, 7000);
    }

    #[test]
    fn parse_confirmed_datum_accepts_provenance_fields() {
        // Confirmed(btcTxid, swept, fulfilled, creator, created) - the 5-field shape.
        let datum = plutus::constr(
            1,
            vec![
                plutus::bytes(&[0xcc; 32]),
                plutus::array(vec![plutus::bytes(&[0xaa; 36])]),
                plutus::array(vec![plutus::constr(
                    0,
                    vec![plutus::bytes(&[0x51; 34]), plutus::int(7000)],
                )]),
                plutus::bytes(&[0x7a; 28]),
                plutus::int(1_700_000_000_000),
            ],
        );
        let (txid, spent, sats) = parse_confirmed_datum(&datum).unwrap();
        assert_eq!(txid, [0xcc; 32]);
        assert_eq!(spent, [0xaa; 36]);
        assert_eq!(sats, 7000);
    }

    #[test]
    fn parse_confirmed_datum_rejects_unconfirmed_and_garbage() {
        let unconfirmed = plutus::constr(0, vec![plutus::bytes(&[0x02; 60])]);
        assert!(parse_confirmed_datum(&unconfirmed).is_none());
        let garbage = plutus::bytes(&[0x00; 4]);
        assert!(parse_confirmed_datum(&garbage).is_none());
    }
}
