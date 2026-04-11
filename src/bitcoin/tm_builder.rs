//! Deterministic Treasury Movement (TM) transaction builder.
//!
//! Every SPO independently constructs the same unsigned transaction from shared
//! Cardano state. Identical `txid` is required for FROST signing to succeed.

use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

/// Dust threshold for P2TR outputs (330 sat).
const DUST_THRESHOLD: Amount = Amount::from_sat(330);

/// Sequence value for all TM inputs (0xFFFFFFFD): signals RBF
/// (< 0xFFFFFFFE) and enables nLockTime (< 0xFFFFFFFF).
///
/// Note: this does NOT satisfy OP_CSV (bit 31 is set, so BIP 112
/// treats the relative locktime as disabled). For the federation
/// script-path leaf, the spender must replace this with the actual
/// relative locktime value at signing time.
const TM_SEQUENCE: Sequence = Sequence(0xFFFFFFFD);

// ---------------------------------------------------------------------------
// Input / output types
// ---------------------------------------------------------------------------

/// Current treasury UTXO.
pub struct TreasuryInput {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub spend_info: TaprootSpendInfo,
}

/// A peg-in UTXO to sweep into the treasury.
pub struct PegInInput {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub spend_info: TaprootSpendInfo,
}

/// A peg-out request to fulfil from the treasury.
pub struct PegOutRequest {
    pub script_pubkey: ScriptBuf,
    pub amount: Amount,
}

/// Protocol fee parameters.
pub struct FeeParams {
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee: Amount,
}

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// An unsigned TM transaction ready for FROST signing.
pub struct UnsignedTm {
    pub tx: Transaction,
    pub txid: Txid,
    pub prevouts: Vec<TxOut>,
    pub input_spend_info: Vec<TaprootSpendInfo>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum TmBuildError {
    InsufficientFunds { available: Amount, required: Amount },
    NoPegOutAmountAfterFee { index: usize, amount: Amount, fee: Amount },
    DustOutput { index: usize, value: Amount },
}

impl fmt::Display for TmBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientFunds { available, required } => {
                write!(f, "insufficient funds: have {available}, need {required}")
            }
            Self::NoPegOutAmountAfterFee { index, amount, fee } => {
                write!(f, "peg-out [{index}] amount {amount} <= per-pegout fee {fee}")
            }
            Self::DustOutput { index, value } => {
                write!(f, "output [{index}] value {value} below dust threshold")
            }
        }
    }
}

impl std::error::Error for TmBuildError {}

// ---------------------------------------------------------------------------
// Vsize estimation
// ---------------------------------------------------------------------------

/// Estimate the vsize of a key-path-spend Taproot transaction.
///
/// Non-witness per input: outpoint(36) + scriptSig_len(1) + sequence(4) = 41
/// Witness per input: items_count(1) + sig_len(1) + sig(64) = 66
/// Per P2TR output: value(8) + scriptPubKey_len(1) + scriptPubKey(34) = 43
/// Fixed overhead: version(4) + marker(1) + flag(1) + locktime(4) = 10
/// Plus varint for input/output counts (1 byte each for < 253 items).
pub fn estimate_vsize(num_inputs: usize, num_outputs: usize) -> u64 {
    let fixed = 10u64; // version(4) + marker(1) + flag(1) + locktime(4)
    let input_count_varint = varint_size(num_inputs as u64);
    let output_count_varint = varint_size(num_outputs as u64);

    let non_witness = fixed
        + input_count_varint
        + (num_inputs as u64) * 41
        + output_count_varint
        + (num_outputs as u64) * 43;

    let witness = (num_inputs as u64) * 66;

    // vsize = ceil((non_witness * 4 + witness) / 4)
    //       = (non_witness * 4 + witness + 3) / 4
    (non_witness * 4 + witness + 3) / 4
}

fn varint_size(n: u64) -> u64 {
    if n < 0xFD { 1 } else if n <= 0xFFFF { 3 } else if n <= 0xFFFF_FFFF { 5 } else { 9 }
}

// ---------------------------------------------------------------------------
// Outpoint sorting key
// ---------------------------------------------------------------------------

/// 36-byte sort key: txid bytes (big-endian / display order) || vout (LE).
fn outpoint_sort_key(op: &OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    let txid_bytes = op.txid.to_byte_array();
    key[..32].copy_from_slice(&txid_bytes);
    key[32..36].copy_from_slice(&op.vout.to_le_bytes());
    key
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build a deterministic unsigned Treasury Movement transaction.
///
/// Every honest SPO must produce byte-identical bytes for the same
/// inputs, so construction follows a canonical recipe:
///
/// - **Version:** 2 (needed for OP_CSV in leaf scripts)
/// - **Locktime:** 0
/// - **Inputs:** `[0]` = treasury, `[1..k]` = peg-ins sorted by `(txid || vout_le)`
/// - **Outputs:** `[0]` = treasury change, `[1..m]` = peg-out payments sorted
///   by `script_pubkey` bytes
/// - **Fee:** `vsize * fee_rate_sat_per_vb`
/// - **Change:** `sum(inputs) - sum(peg_out_outputs) - miner_fee`
pub fn build_tm(
    treasury: TreasuryInput,
    mut pegins: Vec<PegInInput>,
    mut pegouts: Vec<PegOutRequest>,
    change_script_pubkey: ScriptBuf,
    fee_params: &FeeParams,
) -> Result<UnsignedTm, TmBuildError> {
    // --- Validate peg-out amounts ---
    for (i, po) in pegouts.iter().enumerate() {
        if po.amount <= fee_params.per_pegout_fee {
            return Err(TmBuildError::NoPegOutAmountAfterFee {
                index: i,
                amount: po.amount,
                fee: fee_params.per_pegout_fee,
            });
        }
    }

    // --- Sort peg-in inputs lexicographically by (txid || vout_le) ---
    pegins.sort_by(|a, b| outpoint_sort_key(&a.outpoint).cmp(&outpoint_sort_key(&b.outpoint)));

    // --- Sort peg-out outputs by script_pubkey bytes ---
    pegouts.sort_by(|a, b| a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()));

    // --- Build inputs ---
    let num_inputs = 1 + pegins.len();
    let num_pegout_outputs = pegouts.len();
    let num_outputs = num_pegout_outputs + 1; // +1 for change

    let mut inputs = Vec::with_capacity(num_inputs);
    let mut prevouts = Vec::with_capacity(num_inputs);
    let mut input_spend_info = Vec::with_capacity(num_inputs);

    // [0] = treasury
    let treasury_script_pubkey = ScriptBuf::new_p2tr_tweaked(treasury.spend_info.output_key());
    inputs.push(TxIn {
        previous_output: treasury.outpoint,
        script_sig: ScriptBuf::default(),
        sequence: TM_SEQUENCE,
        witness: Witness::default(),
    });
    prevouts.push(TxOut {
        value: treasury.value,
        script_pubkey: treasury_script_pubkey,
    });
    input_spend_info.push(treasury.spend_info);

    // [1..k] = peg-ins (already sorted)
    for pi in pegins {
        let pi_script_pubkey = ScriptBuf::new_p2tr_tweaked(pi.spend_info.output_key());
        inputs.push(TxIn {
            previous_output: pi.outpoint,
            script_sig: ScriptBuf::default(),
            sequence: TM_SEQUENCE,
            witness: Witness::default(),
        });
        prevouts.push(TxOut {
            value: pi.value,
            script_pubkey: pi_script_pubkey,
        });
        input_spend_info.push(pi.spend_info);
    }

    // --- Compute total input value ---
    let total_input: Amount = prevouts.iter().map(|p| p.value).sum();

    // --- Compute peg-out totals ---
    let mut total_pegout = Amount::ZERO;
    let mut pegout_outputs = Vec::with_capacity(num_pegout_outputs);

    for (i, po) in pegouts.iter().enumerate() {
        let net_amount = po
            .amount
            .checked_sub(fee_params.per_pegout_fee)
            .expect("checked above");
        if net_amount < DUST_THRESHOLD {
            return Err(TmBuildError::DustOutput {
                index: i + 1, // +1 because output 0 is change
                value: net_amount,
            });
        }
        total_pegout = total_pegout.checked_add(net_amount).expect("no overflow");
        pegout_outputs.push(TxOut {
            value: net_amount,
            script_pubkey: po.script_pubkey.clone(),
        });
    }

    // --- Estimate fee ---
    let vsize = estimate_vsize(num_inputs, num_outputs);
    let miner_fee = Amount::from_sat(vsize * fee_params.fee_rate_sat_per_vb);

    let required = total_pegout.checked_add(miner_fee).expect("no overflow");
    if total_input < required {
        return Err(TmBuildError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    // --- Build outputs: [0] = change, [1..m] = peg-outs ---
    let mut outputs = Vec::with_capacity(num_outputs);

    let change_value = total_input.checked_sub(required).expect("checked above");
    // Change can be zero only if there's nothing left — but that would mean
    // the treasury is empty. Allow dust-or-above change, error on sub-dust non-zero.
    if change_value > Amount::ZERO && change_value < DUST_THRESHOLD {
        return Err(TmBuildError::DustOutput {
            index: 0,
            value: change_value,
        });
    }

    outputs.push(TxOut {
        value: change_value,
        script_pubkey: change_script_pubkey,
    });
    outputs.extend(pegout_outputs);

    // --- Assemble transaction ---
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    let txid = tx.compute_txid();

    Ok(UnsignedTm {
        tx,
        txid,
        prevouts,
        input_spend_info,
    })
}

// ---------------------------------------------------------------------------
// Sighash computation
// ---------------------------------------------------------------------------

/// Compute the BIP-341 key-path sighash for every input.
///
/// Returns one 32-byte sighash per input, suitable for FROST signing.
pub fn compute_sighashes(unsigned_tm: &UnsignedTm) -> Vec<[u8; 32]> {
    let prevouts = Prevouts::All(&unsigned_tm.prevouts);
    let mut cache = SighashCache::new(&unsigned_tm.tx);

    (0..unsigned_tm.tx.input.len())
        .map(|i| {
            let sighash = cache
                .taproot_key_spend_signature_hash(i, &prevouts, TapSighashType::Default)
                .expect("valid sighash");
            sighash.to_byte_array()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::taproot::treasury_spend_info;
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    fn xonly_from_seed(seed: [u8; 32]) -> bitcoin::key::UntweakedPublicKey {
        use bitcoin::hashes::{sha256, Hash as _};
        let secp = Secp256k1::new();
        // Hash the seed to get a value guaranteed to be in the valid range
        let hash = sha256::Hash::hash(&seed);
        let sk = bitcoin::secp256k1::SecretKey::from_slice(hash.as_ref()).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        kp.x_only_public_key().0
    }

    fn make_treasury_spend_info() -> TaprootSpendInfo {
        let secp = Secp256k1::new();
        let y_51 = xonly_from_seed([1u8; 32]);
        let y_67 = xonly_from_seed([2u8; 32]);
        let y_fed = xonly_from_seed([3u8; 32]);
        treasury_spend_info(&secp, y_51, y_67, y_fed, 144)
    }

    fn make_txid(b: u8) -> Txid {
        Txid::from_byte_array([b; 32])
    }

    fn make_treasury_input(txid_byte: u8, sats: u64) -> TreasuryInput {
        TreasuryInput {
            outpoint: OutPoint { txid: make_txid(txid_byte), vout: 0 },
            value: Amount::from_sat(sats),
            spend_info: make_treasury_spend_info(),
        }
    }

    fn make_pegin_input(txid_byte: u8, vout: u32, sats: u64) -> PegInInput {
        PegInInput {
            outpoint: OutPoint { txid: make_txid(txid_byte), vout },
            value: Amount::from_sat(sats),
            spend_info: make_treasury_spend_info(),
        }
    }

    fn make_pegout(script_byte: u8, sats: u64) -> PegOutRequest {
        // Use a valid P2TR-length scriptPubKey (34 bytes: OP_1 <32-byte key>)
        let secp = Secp256k1::new();
        let key = xonly_from_seed([script_byte; 32]);
        PegOutRequest {
            script_pubkey: ScriptBuf::new_p2tr(&secp, key, None),
            amount: Amount::from_sat(sats),
        }
    }

    fn default_fee_params() -> FeeParams {
        FeeParams {
            fee_rate_sat_per_vb: 10,
            per_pegout_fee: Amount::from_sat(1_000),
        }
    }

    fn change_address() -> ScriptBuf {
        let secp = Secp256k1::new();
        let key = xonly_from_seed([0xFFu8; 32]);
        ScriptBuf::new_p2tr(&secp, key, None)
    }

    // --- Determinism ---

    #[test]
    fn test_build_tm_deterministic() {
        let fee_params = default_fee_params();
        let change = change_address();

        let build = || {
            build_tm(
                make_treasury_input(0xAA, 10_000_000),
                vec![make_pegin_input(0xBB, 0, 5_000_000)],
                vec![make_pegout(0x10, 100_000)],
                change.clone(),
                &fee_params,
            )
            .unwrap()
        };

        let tm1 = build();
        let tm2 = build();
        assert_eq!(tm1.txid, tm2.txid);
    }

    // --- Input ordering ---

    #[test]
    fn test_input_ordering() {
        let fee_params = default_fee_params();
        let change = change_address();
        let treasury_txid_byte = 0xFF;

        // Peg-ins with txid bytes: 0xCC, 0xAA, 0xBB — should be sorted to AA, BB, CC
        let pegins = vec![
            make_pegin_input(0xCC, 0, 1_000_000),
            make_pegin_input(0xAA, 0, 1_000_000),
            make_pegin_input(0xBB, 0, 1_000_000),
        ];

        let tm = build_tm(
            make_treasury_input(treasury_txid_byte, 10_000_000),
            pegins,
            vec![make_pegout(0x10, 50_000)],
            change,
            &fee_params,
        )
        .unwrap();

        // Input [0] is treasury
        assert_eq!(tm.tx.input[0].previous_output.txid, make_txid(treasury_txid_byte));
        // Inputs [1..3] are sorted: AA < BB < CC
        assert_eq!(tm.tx.input[1].previous_output.txid, make_txid(0xAA));
        assert_eq!(tm.tx.input[2].previous_output.txid, make_txid(0xBB));
        assert_eq!(tm.tx.input[3].previous_output.txid, make_txid(0xCC));
    }

    // --- Output ordering ---

    #[test]
    fn test_output_ordering() {
        let fee_params = default_fee_params();
        let change = change_address();

        // Create pegouts with script_pubkeys that sort in a known order
        let po1 = make_pegout(0x30, 100_000);
        let po2 = make_pegout(0x10, 100_000);
        let po3 = make_pegout(0x20, 100_000);

        let expected_order = {
            let mut scripts = vec![
                po1.script_pubkey.clone(),
                po2.script_pubkey.clone(),
                po3.script_pubkey.clone(),
            ];
            scripts.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            scripts
        };

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![po1, po2, po3],
            change.clone(),
            &fee_params,
        )
        .unwrap();

        // Output 0 is change
        assert_eq!(tm.tx.output[0].script_pubkey, change);
        // Outputs 1..3 are peg-outs sorted by scriptPubKey
        for (i, expected) in expected_order.iter().enumerate() {
            assert_eq!(&tm.tx.output[i + 1].script_pubkey, expected, "output {} wrong order", i + 1);
        }
    }

    // --- Accounting ---

    #[test]
    fn test_fee_deduction() {
        let fee_params = default_fee_params();
        let change = change_address();

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![make_pegin_input(0xBB, 0, 5_000_000)],
            vec![make_pegout(0x10, 100_000)],
            change,
            &fee_params,
        )
        .unwrap();

        let total_in: u64 = tm.prevouts.iter().map(|p| p.value.to_sat()).sum();
        let total_out: u64 = tm.tx.output.iter().map(|o| o.value.to_sat()).sum();
        let vsize = estimate_vsize(tm.tx.input.len(), tm.tx.output.len());
        let expected_fee = vsize * fee_params.fee_rate_sat_per_vb;

        assert_eq!(total_in - total_out, expected_fee);
    }

    #[test]
    fn test_pegout_protocol_fee() {
        let fee_params = default_fee_params();
        let change = change_address();
        let requested = 100_000u64;

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, requested)],
            change,
            &fee_params,
        )
        .unwrap();

        // Output 0 is change; output 1 is the pegout
        assert_eq!(
            tm.tx.output[1].value.to_sat(),
            requested - fee_params.per_pegout_fee.to_sat()
        );
    }

    #[test]
    fn test_insufficient_funds_error() {
        let fee_params = default_fee_params();
        let change = change_address();

        let result = build_tm(
            make_treasury_input(0xAA, 1_000), // very little
            vec![],
            vec![make_pegout(0x10, 100_000)],
            change,
            &fee_params,
        );

        assert!(matches!(result, Err(TmBuildError::InsufficientFunds { .. })));
    }

    // --- Edge cases ---

    #[test]
    fn test_no_pegins() {
        let fee_params = default_fee_params();
        let change = change_address();

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, 100_000)],
            change,
            &fee_params,
        )
        .unwrap();

        assert_eq!(tm.tx.input.len(), 1); // just treasury
        assert_eq!(tm.tx.output.len(), 2); // pegout + change
    }

    #[test]
    fn test_no_pegouts() {
        let fee_params = FeeParams {
            fee_rate_sat_per_vb: 10,
            per_pegout_fee: Amount::ZERO,
        };
        let change = change_address();

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![make_pegin_input(0xBB, 0, 5_000_000)],
            vec![],
            change,
            &fee_params,
        )
        .unwrap();

        assert_eq!(tm.tx.input.len(), 2); // treasury + pegin
        assert_eq!(tm.tx.output.len(), 1); // change only
    }

    #[test]
    fn test_no_pegins_no_pegouts() {
        let fee_params = FeeParams {
            fee_rate_sat_per_vb: 10,
            per_pegout_fee: Amount::ZERO,
        };
        let change = change_address();

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![],
            change,
            &fee_params,
        )
        .unwrap();

        assert_eq!(tm.tx.input.len(), 1); // just treasury
        assert_eq!(tm.tx.output.len(), 1); // just change
    }

    // --- Sighash ---

    #[test]
    fn test_sighash_count_matches_inputs() {
        let fee_params = default_fee_params();
        let change = change_address();

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![make_pegin_input(0xBB, 0, 5_000_000)],
            vec![make_pegout(0x10, 100_000)],
            change,
            &fee_params,
        )
        .unwrap();

        let sighashes = compute_sighashes(&tm);
        assert_eq!(sighashes.len(), tm.tx.input.len());
    }

    #[test]
    fn test_sighash_differs_per_input() {
        let fee_params = default_fee_params();
        let change = change_address();

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![
                make_pegin_input(0xBB, 0, 2_000_000),
                make_pegin_input(0xCC, 0, 2_000_000),
            ],
            vec![make_pegout(0x10, 100_000)],
            change,
            &fee_params,
        )
        .unwrap();

        let sighashes = compute_sighashes(&tm);
        // All sighashes should be distinct
        for i in 0..sighashes.len() {
            for j in (i + 1)..sighashes.len() {
                assert_ne!(sighashes[i], sighashes[j], "sighash[{i}] == sighash[{j}]");
            }
        }
    }

    #[test]
    fn test_sighash_deterministic() {
        let fee_params = default_fee_params();
        let change = change_address();

        let build = || {
            build_tm(
                make_treasury_input(0xAA, 10_000_000),
                vec![make_pegin_input(0xBB, 0, 5_000_000)],
                vec![make_pegout(0x10, 100_000)],
                change.clone(),
                &fee_params,
            )
            .unwrap()
        };

        let sh1 = compute_sighashes(&build());
        let sh2 = compute_sighashes(&build());
        assert_eq!(sh1, sh2);
    }

    // --- FROST integration (unit-level) ---

    #[test]
    fn test_frost_sign_sighash() {
        use crate::frost::dkg::run_dkg_all_completions;
        use crate::frost::signing::run_signing;

        // Small DKG: 3-of-5
        let min_signers = 3u16;
        let max_signers = 5u16;
        println!("  DKG: {min_signers}-of-{max_signers}");
        let dkg_result = run_dkg_all_completions(min_signers, max_signers);

        // Extract the FROST group x-only public key
        let frost_group_key = dkg_result.public_key_package.verifying_key();
        let group_key_bytes = frost_group_key.serialize().expect("serialize verifying key");
        // frost-secp256k1-tr serializes as 33-byte compressed point (02/03 || x).
        // Extract the 32-byte x-coordinate for the x-only public key.
        let y_51 = bitcoin::key::UntweakedPublicKey::from_slice(&group_key_bytes[1..33])
            .expect("valid x-only pubkey");

        let secp = Secp256k1::new();
        let y_67 = xonly_from_seed([2u8; 32]);
        let y_fed = xonly_from_seed([3u8; 32]);

        let spend_info = treasury_spend_info(&secp, y_51, y_67, y_fed, 144);
        let treasury_script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

        // Build a simple TM: one treasury input, one pegout, change back
        let fee_params = default_fee_params();
        let tm = build_tm(
            TreasuryInput {
                outpoint: OutPoint { txid: make_txid(0xAA), vout: 0 },
                value: Amount::from_sat(10_000_000),
                spend_info,
            },
            vec![],
            vec![make_pegout(0x10, 100_000)],
            treasury_script_pubkey.clone(),
            &fee_params,
        )
        .unwrap();

        // Compute sighash for the treasury input (index 0)
        let sighashes = compute_sighashes(&tm);
        let sighash = &sighashes[0];

        // FROST-sign the sighash
        println!("  FROST signing sighash...");
        let signing_result = run_signing(
            &dkg_result.key_packages,
            &dkg_result.public_key_package,
            sighash,
            min_signers,
        );

        // Convert FROST signature (64 bytes: R || z) to bitcoin::taproot::Signature
        let frost_sig_bytes = signing_result.signature.serialize().expect("serialize signature");
        assert_eq!(frost_sig_bytes.len(), 64);

        let schnorr_sig =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&frost_sig_bytes)
                .expect("valid 64-byte schnorr sig");

        let tap_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::Default,
        };

        // Set the witness on a mutable copy
        let mut signed_tx = tm.tx.clone();
        signed_tx.input[0].witness = Witness::p2tr_key_spend(&tap_sig);

        // Verify: the signature should be valid under the *tweaked* output key.
        // The FROST group key is the internal key; the output key includes the
        // taproot tweak. For key-path spends, the signer must apply the tweak
        // to the secret key before signing. Since frost-secp256k1-tr doesn't
        // do Taproot tweaking internally, we verify here that the raw FROST
        // signature validates against the *untweaked* group key (which is what
        // frost::Signature::verify checks). The actual on-chain verification
        // would need the tweak applied during signing — that integration is
        // deferred to the full signing coordinator.
        //
        // For now, verify the FROST signature directly:
        dkg_result
            .public_key_package
            .verifying_key()
            .verify(sighash, &signing_result.signature)
            .expect("FROST signature should verify against group key");

        println!("  FROST signature verified against group public key");
        println!("  txid: {}", tm.txid);
        println!("  signed tx has {} inputs, {} outputs", signed_tx.input.len(), signed_tx.output.len());
    }
}
