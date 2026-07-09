//! Parse the treasury oracle datum.
//!
//! The treasury UTxO on Cardano carries an inline datum wrapping the
//! most recent Bitcoin treasury movement transaction. Constr(0) means
//! the BTC tx is unconfirmed on Bitcoin; Constr(1) means confirmed.
//!
//! An **Unconfirmed** (Constr 0) datum wraps the full signed BTC tx; the
//! legacy [`treasury_from_btc_tx_bytes`] / [`parse_treasury_datum`] helpers
//! deserialize it and take output 0.
//!
//! A **Confirmed** (Constr 1) datum instead carries the recomputed
//! `btc_txid`, the swept input outpoints, and every output — the shape
//! [`parse_confirmed_tm_datum`] decodes (WI-028). Because posting a TM does
//! NOT spend the previous TM UTxO, many Confirmed TMs coexist at the
//! validator address; [`select_tip`] chain-follows them (an output nobody
//! spent) to find the CURRENT treasury without any off-chain config.

use std::collections::HashSet;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use pallas_primitives::PlutusData;

use crate::epoch::traits::TreasuryUtxo;

/// Off-chain configuration for treasury parameters not stored in the
/// on-chain datum. These are protocol constants for a given epoch.
#[derive(Debug, Clone)]
pub struct TreasuryConfig {
    /// The internal key of the current treasury. At bootstrap this
    /// equals `y_fed`; in steady state it is the previous epoch's FROST
    /// group x-only key.
    pub y_51: bitcoin::key::UntweakedPublicKey,
    pub y_fed: bitcoin::key::UntweakedPublicKey,
    pub federation_csv_blocks: u32,
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee: Amount,
    /// The current treasury Bitcoin UTxO, tracked OFF-CHAIN by the SPO (spec
    /// §640/§1677: "known from the previous TM's change output, or from protocol
    /// bootstrap"). heimdall builds every TM, so in steady state it knows its own
    /// output 0; for the first TM it comes from bootstrap. The on-chain TM datum is
    /// read ONLY for `btc_confirmed` — the treasury pointer is not re-derived from
    /// it. Sourced from config `bitcoin.treasury_txid / treasury_vout / treasury_amount_sat`.
    pub treasury_outpoint: bitcoin::OutPoint,
    pub treasury_value: Amount,
}

#[derive(Debug)]
pub enum TreasuryDatumError {
    NotConstr,
    WrongTag(u64),
    /// The datum is an Unconfirmed (Constr 0) TM — not an error, but signals a
    /// scanner following the confirmed chain (`parse_confirmed_tm_datum`) to skip it.
    NotConfirmed,
    FieldCount {
        expected: usize,
        got: usize,
    },
    NotBytes(String),
    ExpectedList(String),
    ExpectedInt(String),
    BadTxidLen(usize),
    BadAmount(i128),
    BtcDeserialize(String),
    NoTreasuryOutput,
}

impl std::fmt::Display for TreasuryDatumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConstr => write!(f, "expected Constr"),
            Self::WrongTag(t) => write!(f, "unexpected Constr tag {t}"),
            Self::NotConfirmed => write!(f, "TM datum is Unconfirmed (Constr 0), not Confirmed"),
            Self::FieldCount { expected, got } => {
                write!(f, "expected {expected} field(s), got {got}")
            }
            Self::NotBytes(msg) => write!(f, "expected BoundedBytes, {msg}"),
            Self::ExpectedList(msg) => write!(f, "expected list, {msg}"),
            Self::ExpectedInt(msg) => write!(f, "expected int, {msg}"),
            Self::BadTxidLen(n) => write!(f, "btc_txid must be 32 bytes, got {n}"),
            Self::BadAmount(n) => write!(f, "output amount {n} is not a valid u64 sat value"),
            Self::BtcDeserialize(msg) => write!(f, "BTC tx deserialize: {msg}"),
            Self::NoTreasuryOutput => write!(f, "BTC tx has no outputs"),
        }
    }
}

impl std::error::Error for TreasuryDatumError {}

/// Failure selecting the current treasury from the set of on-chain Confirmed TMs.
#[derive(Debug)]
pub enum TipSelectError {
    /// No Confirmed TM UTxOs were found at the validator address.
    NoConfirmedTms,
    /// Every Confirmed TM's treasury output is spent by another TM — the set
    /// contains no chain tip (a cycle, or the tip's own datum is unreadable).
    NoUnspentTip,
    /// More than one unspent tip — divergent lineages. The caller must
    /// disambiguate (e.g. an explicit config outpoint).
    Ambiguous(Vec<Txid>),
    /// The single unspent tip's treasury scriptPubKey does not match the
    /// current treasury keys — we do not hold the keys to spend it.
    SpkMismatch { tip: Txid },
    /// Several unspent tips exist but none match the current treasury keys.
    NoMatchingTip,
}

impl std::fmt::Display for TipSelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoConfirmedTms => write!(f, "no Confirmed TM UTxOs at the treasury address"),
            Self::NoUnspentTip => write!(
                f,
                "no unspent Confirmed TM tip (all treasury outputs consumed)"
            ),
            Self::Ambiguous(txids) => write!(
                f,
                "ambiguous treasury tip: {} unspent Confirmed TMs match the current keys ({})",
                txids.len(),
                txids
                    .iter()
                    .map(|t| t.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::SpkMismatch { tip } => write!(
                f,
                "treasury tip {tip} scriptPubKey does not match the current treasury keys"
            ),
            Self::NoMatchingTip => write!(
                f,
                "no unspent Confirmed TM tip matches the current treasury keys"
            ),
        }
    }
}

impl std::error::Error for TipSelectError {}

/// Build a `TreasuryUtxo` directly from raw BTC transaction bytes.
///
/// This is the primary parse path used by the Blockfrost chain, which
/// fetches the datum via the JSON endpoint (avoiding CBOR chunking
/// issues) and hands us the raw bytes.
pub fn treasury_from_btc_tx_bytes(
    tx_bytes: &[u8],
    btc_confirmed: bool,
    config: &TreasuryConfig,
) -> Result<TreasuryUtxo, TreasuryDatumError> {
    let tx: Transaction =
        deserialize(tx_bytes).map_err(|e| TreasuryDatumError::BtcDeserialize(e.to_string()))?;

    let out = tx
        .output
        .first()
        .ok_or(TreasuryDatumError::NoTreasuryOutput)?;
    let txid = tx.compute_txid();

    Ok(TreasuryUtxo {
        outpoint: OutPoint { txid, vout: 0 },
        value: out.value,
        y_51: config.y_51,
        y_fed: config.y_fed,
        federation_csv_blocks: config.federation_csv_blocks,
        fee_rate_sat_per_vb: config.fee_rate_sat_per_vb,
        per_pegout_fee: config.per_pegout_fee,
        btc_confirmed,
    })
}

/// Extract the raw BTC transaction bytes and confirmation status.
///
/// Tag 121 = Constr(0) = unconfirmed, tag 122 = Constr(1) = confirmed.
fn extract_btc_tx_bytes(data: &PlutusData) -> Result<(Vec<u8>, bool), TreasuryDatumError> {
    let (tag, fields) = match data {
        PlutusData::Constr(constr) => (constr.tag, &constr.fields),
        _ => return Err(TreasuryDatumError::NotConstr),
    };

    let btc_confirmed = match tag {
        121 => false,
        122 => true,
        other => return Err(TreasuryDatumError::WrongTag(other)),
    };

    if fields.len() != 1 {
        return Err(TreasuryDatumError::FieldCount {
            expected: 1,
            got: fields.len(),
        });
    }

    match &fields[0] {
        PlutusData::BoundedBytes(b) => Ok((b.clone().into(), btc_confirmed)),
        other => Err(TreasuryDatumError::NotBytes(format!(
            "got {:?}",
            std::mem::discriminant(other)
        ))),
    }
}

/// Decode the on-chain treasury datum into a `TreasuryUtxo`.
///
/// The datum contains the raw BTC treasury movement transaction.
/// Output 0 is the treasury output — its value and the tx's txid give
/// us the outpoint. The remaining fields come from `config`.
pub fn parse_treasury_datum(
    data: &PlutusData,
    config: &TreasuryConfig,
) -> Result<TreasuryUtxo, TreasuryDatumError> {
    let (tx_bytes, btc_confirmed) = extract_btc_tx_bytes(data)?;
    let tx: Transaction =
        deserialize(&tx_bytes).map_err(|e| TreasuryDatumError::BtcDeserialize(e.to_string()))?;

    let out = tx
        .output
        .first()
        .ok_or(TreasuryDatumError::NoTreasuryOutput)?;
    let txid = tx.compute_txid();

    Ok(TreasuryUtxo {
        outpoint: OutPoint { txid, vout: 0 },
        value: out.value,
        y_51: config.y_51,
        y_fed: config.y_fed,
        federation_csv_blocks: config.federation_csv_blocks,
        fee_rate_sat_per_vb: config.fee_rate_sat_per_vb,
        per_pegout_fee: config.per_pegout_fee,
        btc_confirmed,
    })
}

// ---------------------------------------------------------------------------
// Confirmed (Constr 1) TM datum + chain-following tip selection (WI-028)
// ---------------------------------------------------------------------------

/// One output of a Treasury Movement, parsed from the Confirmed datum's
/// `fulfilled_peg_outs` list: the raw Bitcoin `scriptPubKey` and satoshi amount.
/// Output 0 is the new treasury; 1.. are the fulfilled peg-outs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmOutput {
    pub script_pub_key: Vec<u8>,
    pub amount: u64,
}

/// A parsed **Confirmed** (Constr 1) treasury-movement datum.
///
/// Mirror of binocular's Scalus `TmDatum.Confirmed` (the canonical producer)
/// and the upstream aiken `TreasuryMovementDatum::Confirmed`:
///
/// ```text
/// Confirmed { btc_txid, swept_peg_in_utxo_ids, fulfilled_peg_outs }
/// ```
///
/// - `fulfilled_peg_outs` is EVERY output of the raw BTC tx in order — output 0
///   is the new treasury (its SPK + value), 1.. are the peg-outs.
/// - `swept_peg_in_utxo_ids` is EVERY input outpoint (36 bytes = prev_txid(32,
///   internal byte order) ++ vout(4, little-endian)) — input 0 is the previous
///   treasury.
#[derive(Debug, Clone)]
pub struct ConfirmedTm {
    /// The TM's Bitcoin txid, in **internal** (double-SHA256) byte order — the
    /// same bytes `bitcoin::Txid::to_byte_array()` yields, and the same order
    /// the prev_txid inside `swept_inputs` uses. Display form is the reverse.
    pub btc_txid: [u8; 32],
    /// Every input outpoint (36 bytes each); input 0 = previous treasury.
    pub swept_inputs: Vec<Vec<u8>>,
    /// Every output; output 0 = the new treasury.
    pub outputs: Vec<TmOutput>,
}

impl ConfirmedTm {
    /// The treasury this TM produced: `(btc_txid, 0)`.
    pub fn treasury_outpoint(&self) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array(self.btc_txid),
            vout: 0,
        }
    }

    /// The 36-byte outpoint key of this TM's treasury output, in the SAME
    /// encoding as `swept_inputs` (btc_txid(32, internal) ++ vout 0 as 4 LE
    /// bytes) so membership tests against the swept set are byte-exact.
    fn treasury_outpoint_key(&self) -> Vec<u8> {
        let mut k = Vec::with_capacity(36);
        k.extend_from_slice(&self.btc_txid);
        k.extend_from_slice(&[0u8; 4]);
        k
    }

    /// The treasury output's value (output 0).
    pub fn treasury_value(&self) -> Option<Amount> {
        self.outputs.first().map(|o| Amount::from_sat(o.amount))
    }

    /// The treasury output's raw scriptPubKey (output 0).
    pub fn treasury_spk(&self) -> Option<&[u8]> {
        self.outputs.first().map(|o| o.script_pub_key.as_slice())
    }

    /// The Bitcoin outpoints this TM consumed (its `swept_peg_in_utxo_ids`, incl.
    /// the previous treasury), decoded from the 36-byte keys. Because a Confirmed
    /// TM is oracle-verified — its BTC tx is mined — these outpoints are
    /// **definitively spent on Bitcoin**, which is how heimdall knows what's spent
    /// WITHOUT querying Bitcoin directly (it reads Bitcoin state via the oracle).
    pub fn swept_outpoints(&self) -> Vec<OutPoint> {
        self.swept_inputs
            .iter()
            .filter_map(|k| outpoint_from_swept_key(k))
            .collect()
    }
}

/// Decode a 36-byte swept-input key (`prev_txid(32, internal) ++ vout(4, LE)`) —
/// the encoding used in `swept_peg_in_utxo_ids` — into an [`OutPoint`].
pub fn outpoint_from_swept_key(k: &[u8]) -> Option<OutPoint> {
    if k.len() != 36 {
        return None;
    }
    let txid = Txid::from_byte_array(k[..32].try_into().ok()?);
    let vout = u32::from_le_bytes(k[32..36].try_into().ok()?);
    Some(OutPoint { txid, vout })
}

/// Parse a **Confirmed** (Constr 1) treasury-movement datum.
///
/// Returns [`TreasuryDatumError::NotConfirmed`] for an Unconfirmed (Constr 0)
/// datum so a chain-following scanner can skip it. Expected shape (see
/// binocular `TreasuryMovementValidator`):
///
/// ```text
/// Constr(1, [ BoundedBytes(btc_txid),
///             [ BoundedBytes(outpoint_36) .. ],
///             [ Constr(0, [BoundedBytes(spk), BigInt(amount)]) .. ] ])
/// ```
pub fn parse_confirmed_tm_datum(data: &PlutusData) -> Result<ConfirmedTm, TreasuryDatumError> {
    let (tag, fields) = match data {
        PlutusData::Constr(c) => (c.tag, c.fields.iter().collect::<Vec<_>>()),
        _ => return Err(TreasuryDatumError::NotConstr),
    };
    match tag {
        121 => return Err(TreasuryDatumError::NotConfirmed),
        122 => {}
        other => return Err(TreasuryDatumError::WrongTag(other)),
    }
    if fields.len() != 3 {
        return Err(TreasuryDatumError::FieldCount {
            expected: 3,
            got: fields.len(),
        });
    }

    // field 0: btc_txid (32 bytes, internal order).
    let btc_txid: [u8; 32] = match fields[0] {
        PlutusData::BoundedBytes(b) => {
            let v: Vec<u8> = b.clone().into();
            let len = v.len();
            v.try_into()
                .map_err(|_| TreasuryDatumError::BadTxidLen(len))?
        }
        other => {
            return Err(TreasuryDatumError::NotBytes(format!(
                "btc_txid: got {:?}",
                std::mem::discriminant(other)
            )));
        }
    };

    // field 1: swept_peg_in_utxo_ids (list of 36-byte outpoints).
    let swept_inputs = match fields[1] {
        PlutusData::Array(arr) => arr
            .iter()
            .map(|e| match e {
                PlutusData::BoundedBytes(b) => Ok(b.clone().into()),
                other => Err(TreasuryDatumError::NotBytes(format!(
                    "swept input: got {:?}",
                    std::mem::discriminant(other)
                ))),
            })
            .collect::<Result<Vec<Vec<u8>>, _>>()?,
        other => {
            return Err(TreasuryDatumError::ExpectedList(format!(
                "swept_peg_in_utxo_ids: got {:?}",
                std::mem::discriminant(other)
            )));
        }
    };

    // field 2: fulfilled_peg_outs (list of PegOutEntry Constr(0, [spk, amount])).
    let outputs = match fields[2] {
        PlutusData::Array(arr) => arr
            .iter()
            .map(parse_tm_output)
            .collect::<Result<Vec<_>, _>>()?,
        other => {
            return Err(TreasuryDatumError::ExpectedList(format!(
                "fulfilled_peg_outs: got {:?}",
                std::mem::discriminant(other)
            )));
        }
    };

    Ok(ConfirmedTm {
        btc_txid,
        swept_inputs,
        outputs,
    })
}

/// A parsed Unconfirmed (Constr 0) TM datum — the signed BTC tx's identity, its
/// inputs (what it spends), and its outputs. Used to diagnose WHY the treasury is
/// blocked: which in-flight movement spends the current tip and what its BTC leg
/// references (a spent/missing input can never confirm, deadlocking the mover).
#[derive(Debug, Clone)]
pub struct UnconfirmedTm {
    pub btc_txid: bitcoin::Txid,
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<(Amount, bitcoin::ScriptBuf)>,
    /// The Cardano tx that created this Unconfirmed-TM UTxO — filled by the
    /// scanner (not the datum). Used to look up its block time for the staleness
    /// deadline (chain-now − block time = how long it has been unconfirmed).
    pub cardano_tx_hash: String,
    /// POSIX block time (secs) of `cardano_tx_hash`, filled by the scanner only
    /// when a staleness deadline is configured. `None` = not looked up.
    pub block_time: Option<i64>,
}

/// Parse an Unconfirmed (Constr 0) TM datum into its full BTC tx shape. Returns
/// `None` unless the datum is a deserializable Unconfirmed TM. The Cardano
/// metadata (`cardano_tx_hash` / `block_time`) is filled by the scanner.
pub fn parse_unconfirmed_tm(data: &PlutusData) -> Option<UnconfirmedTm> {
    let (tx_bytes, btc_confirmed) = extract_btc_tx_bytes(data).ok()?;
    if btc_confirmed {
        return None;
    }
    let tx: Transaction = deserialize(&tx_bytes).ok()?;
    Some(UnconfirmedTm {
        btc_txid: tx.compute_txid(),
        inputs: tx.input.iter().map(|i| i.previous_output).collect(),
        outputs: tx
            .output
            .iter()
            .map(|o| (o.value, o.script_pubkey.clone()))
            .collect(),
        cardano_tx_hash: String::new(),
        block_time: None,
    })
}

/// Parse a single `PegOutEntry` = `Constr(0, [BoundedBytes(spk), BigInt(amount)])`.
fn parse_tm_output(data: &PlutusData) -> Result<TmOutput, TreasuryDatumError> {
    let fields = match data {
        PlutusData::Constr(c) => c.fields.iter().collect::<Vec<_>>(),
        _ => return Err(TreasuryDatumError::NotConstr),
    };
    if fields.len() != 2 {
        return Err(TreasuryDatumError::FieldCount {
            expected: 2,
            got: fields.len(),
        });
    }
    let script_pub_key: Vec<u8> = match fields[0] {
        PlutusData::BoundedBytes(b) => b.clone().into(),
        other => {
            return Err(TreasuryDatumError::NotBytes(format!(
                "pegout spk: got {:?}",
                std::mem::discriminant(other)
            )));
        }
    };
    let amount = match fields[1] {
        PlutusData::BigInt(pallas_primitives::BigInt::Int(i)) => {
            let n = i128::from(*i);
            u64::try_from(n).map_err(|_| TreasuryDatumError::BadAmount(n))?
        }
        other => {
            return Err(TreasuryDatumError::ExpectedInt(format!(
                "pegout amount: got {:?}",
                std::mem::discriminant(other)
            )));
        }
    };
    Ok(TmOutput {
        script_pub_key,
        amount,
    })
}

/// Select the CURRENT treasury from a set of Confirmed TMs by **chain-following**.
///
/// Posting a TM does not spend the previous TM UTxO, so every Confirmed TM ever
/// posted coexists at the validator address. The tip is the one TM whose own
/// treasury output `(btc_txid, 0)` has NOT been consumed as an input by any
/// other TM — i.e. the end of the movement chain. Exactly one such tip is
/// expected in a healthy single-lineage bridge.
///
/// Re-confirmations of the same `btc_txid` (two Cardano UTxOs, same datum)
/// collapse to one tip. Genuinely divergent lineages surface as
/// [`TipSelectError::Ambiguous`] rather than silently picking one.
pub fn select_tip(confirmed: &[ConfirmedTm]) -> Result<&ConfirmedTm, TipSelectError> {
    if confirmed.is_empty() {
        return Err(TipSelectError::NoConfirmedTms);
    }
    let tips = unspent_tips(confirmed);
    match tips.len() {
        0 => Err(TipSelectError::NoUnspentTip),
        1 => Ok(tips[0]),
        _ => Err(TipSelectError::Ambiguous(
            tips.iter().map(|t| t.treasury_outpoint().txid).collect(),
        )),
    }
}

/// All unspent chain tips among `confirmed` (deduped by `btc_txid`): every TM
/// whose treasury output `(btc_txid, 0)` is not consumed as an input by another
/// TM. A healthy single-lineage bridge yields exactly one; divergent lineages
/// (e.g. retired preprod cycles under different keys) yield several — the caller
/// then disambiguates, typically by which tip's scriptPubKey matches the current
/// treasury keys ([`crate::bitcoin::taproot::treasury_spend_info`]).
pub fn unspent_tips(confirmed: &[ConfirmedTm]) -> Vec<&ConfirmedTm> {
    // Every outpoint consumed by any TM (36-byte keys).
    let mut spent: HashSet<&[u8]> = HashSet::new();
    for tm in confirmed {
        for inp in &tm.swept_inputs {
            spent.insert(inp.as_slice());
        }
    }

    // Candidates whose treasury output nobody spent, deduped on the FULL
    // treasury-output identity (btc_txid + output[0] SPK + value) rather than the
    // txid alone. Byte-identical re-confirmations (two Cardano UTxOs, same datum)
    // still collapse, but two datums that share a btc_txid yet DISAGREE on
    // output[0] — only possible via a fabricated TM (binocular
    // TreasuryMovementValidator's unenforced tx-match TODO) — stay distinct
    // candidates, so the scriptPubKey match in `select_spendable_tip` resolves
    // them deterministically (not by Blockfrost's UTxO order), and a
    // same-SPK-but-different-value conflict surfaces as Ambiguous rather than
    // silently feeding a bogus treasury value into `build_tm`.
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut tips: Vec<&ConfirmedTm> = Vec::new();
    for tm in confirmed {
        if spent.contains(tm.treasury_outpoint_key().as_slice()) {
            continue;
        }
        let mut ident = tm.btc_txid.to_vec();
        if let Some(out) = tm.outputs.first() {
            ident.extend_from_slice(&out.script_pub_key);
            ident.extend_from_slice(&out.amount.to_le_bytes());
        }
        if seen.insert(ident) {
            tips.push(tm);
        }
    }
    tips
}

/// Select the treasury tip we can actually spend: among the unspent tips, the
/// one whose treasury scriptPubKey equals `expected_spk` (the P2TR of the
/// current treasury keys). This BOTH selects the chain tip AND proves we hold
/// the keys to spend it, so a caller can build the next TM off the result
/// directly (WI-028 safety check).
///
/// - exactly one unspent tip: it MUST match `expected_spk`, else `SpkMismatch`
///   (we would otherwise sign a TM spending a UTxO we cannot unlock).
/// - several unspent tips (divergent lineages, e.g. retired preprod cycles): the
///   SPK match disambiguates — only the tip under our keys is ours to move.
pub fn select_spendable_tip<'a>(
    confirmed: &'a [ConfirmedTm],
    expected_spk: &[u8],
) -> Result<&'a ConfirmedTm, TipSelectError> {
    if confirmed.is_empty() {
        return Err(TipSelectError::NoConfirmedTms);
    }
    let tips = unspent_tips(confirmed);
    if tips.is_empty() {
        return Err(TipSelectError::NoUnspentTip);
    }
    let matching: Vec<&ConfirmedTm> = tips
        .iter()
        .copied()
        .filter(|t| t.treasury_spk() == Some(expected_spk))
        .collect();
    match (tips.len(), matching.len()) {
        (_, 1) => Ok(matching[0]),
        (1, 0) => Err(TipSelectError::SpkMismatch {
            tip: tips[0].treasury_outpoint().txid,
        }),
        (_, 0) => Err(TipSelectError::NoMatchingTip),
        (_, _) => Err(TipSelectError::Ambiguous(
            matching
                .iter()
                .map(|t| t.treasury_outpoint().txid)
                .collect(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_primitives::conway::Constr;
    use pallas_primitives::{BigInt, BoundedBytes, MaybeIndefArray};

    fn demo_config() -> TreasuryConfig {
        let secp = bitcoin::key::Secp256k1::new();
        let y_fed = bitcoin::key::UntweakedPublicKey::from_slice(
            &bitcoin::secp256k1::SecretKey::from_slice(&[0xFEu8; 32])
                .unwrap()
                .x_only_public_key(&secp)
                .0
                .serialize(),
        )
        .unwrap();
        TreasuryConfig {
            y_51: y_fed, // bootstrap: internal key = federation
            y_fed,
            federation_csv_blocks: 144,
            fee_rate_sat_per_vb: 1,
            per_pegout_fee: Amount::from_sat(1_000),
            treasury_outpoint: OutPoint::null(),
            treasury_value: Amount::from_sat(10_000_000),
        }
    }

    /// BTC tx hex extracted from the preprod treasury datum (tx 047c71ad...).
    /// This is the `bytes` field from Blockfrost's JSON datum endpoint.
    const PREPROD_BTC_TX_HEX: &str = "02000000000101f4780792094629c78ba9d82a41a6c5f6f66aa44fa9c9717818e3e2b51a401c130000000000fdffffff028096980000000000225120b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f28540e556d2901000000225120dcd898aeb18c66dcb701ede4641122e4a20d38eec1de6a1b49084d4569eed3730247304402200b053d4ee8b2402019b7168d6058360ba614b426c1b04b736ec01db844a18ffc02205f1fe66232bfeb9b6677cfdddfd49af33cf55a133ae0795b09dd85105f8e2c7d012103046eb15ca36697d619d908a255c1328e262aecb43043dd746cefce79b1bea99f79000000";

    #[test]
    fn parse_preprod_btc_tx() {
        let tx_bytes = hex::decode(PREPROD_BTC_TX_HEX).unwrap();
        let config = demo_config();
        let treasury = treasury_from_btc_tx_bytes(&tx_bytes, true, &config).unwrap();

        assert_eq!(treasury.value, Amount::from_sat(10_000_000));
        assert_eq!(treasury.outpoint.vout, 0);
        assert_eq!(treasury.federation_csv_blocks, 144);
        assert_eq!(treasury.fee_rate_sat_per_vb, 1);
    }

    #[test]
    fn roundtrip_through_cbor() {
        // Build a minimal BTC tx, wrap it in a datum, CBOR-encode, decode, parse.
        let btc_tx_hex = "02000000000101f4780792094629c78ba9d82a41a6c5f6f66aa44fa9c9717818e3e2b51a401c130000000000fdffffff028096980000000000225120b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f28540e556d2901000000225120dcd898aeb18c66dcb701ede4641122e4a20d38eec1de6a1b49084d4569eed3730247304402200b053d4ee8b2402019b7168d6058360ba614b426c1b04b736ec01db844a18ffc02205f1fe66232bfeb9b6677cfdddfd49af33cf55a133ae0795b09dd85105f8e2c7d012103046eb15ca36697d619d908a255c1328e262aecb43043dd746cefce79b1bea99f79000000";
        let tx_bytes = hex::decode(btc_tx_hex).unwrap();

        let datum = PlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![PlutusData::BoundedBytes(BoundedBytes::from(
                tx_bytes,
            ))]),
        });

        let cbor = pallas_codec::minicbor::to_vec(&datum).unwrap();
        let decoded: PlutusData = pallas_codec::minicbor::decode(&cbor).unwrap();
        let config = demo_config();
        let treasury = parse_treasury_datum(&decoded, &config).unwrap();
        assert_eq!(treasury.value, Amount::from_sat(10_000_000));
    }

    // --- Confirmed (Constr 1) datum + tip selection (WI-028) ---------------

    /// The 36-byte outpoint key (`txid(32, internal) ++ vout(4, LE)`) as it
    /// appears inside a Confirmed datum's `swept_peg_in_utxo_ids`.
    fn outpoint_key(txid: [u8; 32], vout: u32) -> Vec<u8> {
        let mut k = txid.to_vec();
        k.extend_from_slice(&vout.to_le_bytes());
        k
    }

    fn pegout_entry(spk: Vec<u8>, amount: u64) -> PlutusData {
        PlutusData::Constr(Constr {
            tag: 121, // PegOutEntry = Constr 0
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![
                PlutusData::BoundedBytes(BoundedBytes::from(spk)),
                PlutusData::BigInt(BigInt::Int((amount as i64).into())),
            ]),
        })
    }

    /// Build a Confirmed (Constr 1) TM datum from raw parts.
    fn confirmed_datum(
        btc_txid: [u8; 32],
        swept: &[Vec<u8>],
        outs: &[(Vec<u8>, u64)],
    ) -> PlutusData {
        PlutusData::Constr(Constr {
            tag: 122, // Confirmed = Constr 1
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![
                PlutusData::BoundedBytes(BoundedBytes::from(btc_txid.to_vec())),
                PlutusData::Array(MaybeIndefArray::Def(
                    swept
                        .iter()
                        .map(|o| PlutusData::BoundedBytes(BoundedBytes::from(o.clone())))
                        .collect(),
                )),
                PlutusData::Array(MaybeIndefArray::Def(
                    outs.iter()
                        .map(|(spk, amt)| pegout_entry(spk.clone(), *amt))
                        .collect(),
                )),
            ]),
        })
    }

    /// Round-trip a Confirmed datum through CBOR (the real wire path) and parse it.
    #[test]
    fn parse_confirmed_roundtrip() {
        let treasury_spk =
            hex::decode("5120b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854")
                .unwrap();
        let pegout_spk =
            hex::decode("5120dcd898aeb18c66dcb701ede4641122e4a20d38eec1de6a1b49084d4569eed373")
                .unwrap();
        let datum = confirmed_datum(
            [0xAB; 32],
            &[outpoint_key([0x63; 32], 0), outpoint_key([0x14; 32], 0)],
            &[(treasury_spk.clone(), 111_888), (pegout_spk.clone(), 550)],
        );

        let cbor = pallas_codec::minicbor::to_vec(&datum).unwrap();
        let decoded: PlutusData = pallas_codec::minicbor::decode(&cbor).unwrap();
        let tm = parse_confirmed_tm_datum(&decoded).unwrap();

        assert_eq!(tm.btc_txid, [0xAB; 32]);
        assert_eq!(tm.swept_inputs.len(), 2);
        assert_eq!(tm.outputs.len(), 2);
        assert_eq!(tm.treasury_value(), Some(Amount::from_sat(111_888)));
        assert_eq!(tm.treasury_spk(), Some(treasury_spk.as_slice()));
        assert_eq!(tm.outputs[1].amount, 550);
        // Outpoint txid is the internal bytes; vout 0.
        assert_eq!(tm.treasury_outpoint().vout, 0);
        assert_eq!(
            tm.treasury_outpoint().txid,
            Txid::from_byte_array([0xAB; 32])
        );
    }

    /// An Unconfirmed (Constr 0) datum is rejected with `NotConfirmed` so a
    /// chain-follow scan skips it rather than aborting.
    #[test]
    fn unconfirmed_datum_is_skippable() {
        let datum = PlutusData::Constr(Constr {
            tag: 121,
            any_constructor: None,
            fields: MaybeIndefArray::Def(vec![PlutusData::BoundedBytes(BoundedBytes::from(
                vec![0u8; 10],
            ))]),
        });
        assert!(matches!(
            parse_confirmed_tm_datum(&datum),
            Err(TreasuryDatumError::NotConfirmed)
        ));
    }

    fn tm(btc_txid: [u8; 32], prev_treasury: Option<[u8; 32]>, value: u64) -> ConfirmedTm {
        let swept = match prev_treasury {
            Some(p) => vec![outpoint_key(p, 0)],
            None => vec![outpoint_key([0x00; 32], 0)], // genesis / bootstrap input
        };
        ConfirmedTm {
            btc_txid,
            swept_inputs: swept,
            outputs: vec![TmOutput {
                script_pub_key: vec![0x51, 0x20],
                amount: value,
            }],
        }
    }

    /// A 3-long movement chain A→B→C: the tip is C, regardless of scan order.
    #[test]
    fn tip_follows_the_chain() {
        let a = tm([0xAA; 32], None, 100_000);
        let b = tm([0xBB; 32], Some([0xAA; 32]), 99_000);
        let c = tm([0xCC; 32], Some([0xBB; 32]), 98_000);

        let chain = [a.clone(), b.clone(), c.clone()];
        let tip = select_tip(&chain).unwrap();
        assert_eq!(tip.btc_txid, [0xCC; 32]);
        assert_eq!(tip.treasury_value(), Some(Amount::from_sat(98_000)));

        // Order independence — coexisting UTxOs arrive in arbitrary order.
        let shuffled = [c, a, b];
        let tip = select_tip(&shuffled).unwrap();
        assert_eq!(tip.btc_txid, [0xCC; 32]);
    }

    /// Re-confirmations of the same tip txid (two Cardano UTxOs, same datum)
    /// collapse to a single unambiguous tip.
    #[test]
    fn tip_dedups_reconfirmations() {
        let a = tm([0xAA; 32], None, 100_000);
        let b = tm([0xBB; 32], Some([0xAA; 32]), 99_000);
        let b_dup = tm([0xBB; 32], Some([0xAA; 32]), 99_000);
        let set = [a, b, b_dup];
        let tip = select_tip(&set).unwrap();
        assert_eq!(tip.btc_txid, [0xBB; 32]);
    }

    /// Two independent lineages (each with an unspent tip) → ambiguous.
    #[test]
    fn tip_ambiguous_on_divergent_lineages() {
        let a = tm([0xAA; 32], None, 100_000);
        let d = tm([0xDD; 32], None, 200_000);
        match select_tip(&[a, d]) {
            Err(TipSelectError::Ambiguous(txids)) => assert_eq!(txids.len(), 2),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    /// A cycle (A spends B's output, B spends A's) leaves no tip.
    #[test]
    fn tip_none_on_cycle() {
        let a = tm([0xAA; 32], Some([0xBB; 32]), 1);
        let b = tm([0xBB; 32], Some([0xAA; 32]), 1);
        assert!(matches!(
            select_tip(&[a, b]),
            Err(TipSelectError::NoUnspentTip)
        ));
    }

    #[test]
    fn tip_empty_set() {
        assert!(matches!(
            select_tip(&[]),
            Err(TipSelectError::NoConfirmedTms)
        ));
    }

    fn tm_spk(btc_txid: [u8; 32], prev: Option<[u8; 32]>, spk: Vec<u8>) -> ConfirmedTm {
        let mut t = tm(btc_txid, prev, 50_000);
        t.outputs[0].script_pub_key = spk;
        t
    }

    /// Two divergent lineages under different keys: `select_spendable_tip` picks
    /// the one whose treasury scriptPubKey matches the current keys.
    #[test]
    fn spendable_tip_disambiguates_by_spk() {
        let ours = vec![0x51, 0x20, 0xAA];
        let theirs = vec![0x51, 0x20, 0xBB];
        let mine = tm_spk([0x11; 32], None, ours.clone());
        let other = tm_spk([0x22; 32], None, theirs);
        let set = [mine, other];
        let tip = select_spendable_tip(&set, &ours).unwrap();
        assert_eq!(tip.btc_txid, [0x11; 32]);
    }

    /// A single tip whose SPK is not ours is refused rather than swept.
    #[test]
    fn spendable_tip_rejects_spk_mismatch() {
        let tip = tm_spk([0x11; 32], None, vec![0x51, 0x20, 0xAA]);
        let set = [tip];
        assert!(matches!(
            select_spendable_tip(&set, &[0x51, 0x20, 0xBB]),
            Err(TipSelectError::SpkMismatch { .. })
        ));
    }

    /// Two datums sharing a btc_txid but with DIFFERENT treasury SPKs (a
    /// fabricated TM) stay distinct after dedup, so the SPK match deterministically
    /// picks ours regardless of scan order — not Blockfrost-order dependent.
    #[test]
    fn dedup_keeps_conflicting_same_txid_distinct() {
        let ours = vec![0x51, 0x20, 0xAA];
        let theirs = vec![0x51, 0x20, 0xBB];
        let mine = tm_spk([0x11; 32], None, ours.clone());
        let fake = tm_spk([0x11; 32], None, theirs);

        let set1 = [mine.clone(), fake.clone()];
        assert_eq!(
            select_spendable_tip(&set1, &ours).unwrap().treasury_spk(),
            Some(ours.as_slice())
        );
        // Reversed order resolves to the same tip.
        let set2 = [fake, mine];
        assert_eq!(
            select_spendable_tip(&set2, &ours).unwrap().treasury_spk(),
            Some(ours.as_slice())
        );
    }

    /// Same btc_txid + same SPK but different VALUE → both match our keys →
    /// Ambiguous (refuse) rather than silently feeding a bogus treasury value.
    #[test]
    fn dedup_same_txid_same_spk_diff_value_is_ambiguous() {
        let ours = vec![0x51, 0x20, 0xAA];
        let mut a = tm_spk([0x11; 32], None, ours.clone());
        a.outputs[0].amount = 100_000;
        let mut b = tm_spk([0x11; 32], None, ours.clone());
        b.outputs[0].amount = 200_000;
        let set = [a, b];
        assert!(matches!(
            select_spendable_tip(&set, &ours),
            Err(TipSelectError::Ambiguous(_))
        ));
    }

    /// A 36-byte swept key decodes to the outpoint it was built from — the
    /// encoding must be byte-exact (txid internal order ++ vout LE), since it
    /// feeds the `consumed` set that gates dead-TM detection and peg-in skipping.
    #[test]
    fn swept_key_roundtrips_to_outpoint() {
        let txid_bytes = [0xAB; 32];
        for vout in [0u32, 1, 7, 0x0100, u32::MAX] {
            let key = outpoint_key(txid_bytes, vout);
            let op = outpoint_from_swept_key(&key).expect("36-byte key decodes");
            assert_eq!(op.txid, Txid::from_byte_array(txid_bytes));
            assert_eq!(op.vout, vout);
        }
    }

    /// Wrong-length keys are rejected (None) rather than silently mis-decoding.
    #[test]
    fn swept_key_rejects_bad_length() {
        assert!(outpoint_from_swept_key(&[0u8; 35]).is_none());
        assert!(outpoint_from_swept_key(&[0u8; 37]).is_none());
        assert!(outpoint_from_swept_key(&[]).is_none());
    }

    /// `swept_outpoints` decodes every input a Confirmed TM consumed — input 0 is
    /// the previous treasury, the rest are swept peg-in deposits.
    #[test]
    fn swept_outpoints_decodes_all_inputs() {
        let tm = ConfirmedTm {
            btc_txid: [0xCC; 32],
            swept_inputs: vec![
                outpoint_key([0xAA; 32], 0), // prev treasury
                outpoint_key([0xBB; 32], 3), // a swept deposit
            ],
            outputs: vec![TmOutput {
                script_pub_key: vec![0x51, 0x20],
                amount: 42,
            }],
        };
        let ops = tm.swept_outpoints();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0], OutPoint { txid: Txid::from_byte_array([0xAA; 32]), vout: 0 });
        assert_eq!(ops[1], OutPoint { txid: Txid::from_byte_array([0xBB; 32]), vout: 3 });
    }

    /// A malformed (non-36-byte) swept key is dropped, not panicked on.
    #[test]
    fn swept_outpoints_skips_malformed_key() {
        let tm = ConfirmedTm {
            btc_txid: [0xCC; 32],
            swept_inputs: vec![outpoint_key([0xAA; 32], 0), vec![0x00; 10]],
            outputs: vec![],
        };
        assert_eq!(tm.swept_outpoints().len(), 1);
    }
}
