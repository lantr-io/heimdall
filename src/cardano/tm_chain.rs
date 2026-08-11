//! Bitcoin outpoint encoding shared across the TM machinery.
//!
//! Rev 5.4 note: the Confirmed-chain WALK that used to live here is gone. The
//! current treasury is the bridge-state singleton's head (`BridgeState.
//! treasury_utxo_id` + `treasury_amount`), read through the Config's
//! `bridge_state_policy` — see `blockfrost_chain::fetch_config_singleton`.
//! Confirm burns the TM record, so there are no `Confirmed` records to follow.

/// 36-byte outpoint encoding: txid internal order ++ vout LE.
#[must_use]
pub fn outpoint_bytes(op: &bitcoin::OutPoint) -> [u8; 36] {
    use bitcoin::hashes::Hash;
    let mut out = [0u8; 36];
    out[..32].copy_from_slice(op.txid.as_raw_hash().as_byte_array());
    out[32..].copy_from_slice(&op.vout.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn outpoint_bytes_is_txid_le_then_vout_le() {
        let op = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xab; 32]),
            vout: 7,
        };
        let b = outpoint_bytes(&op);
        assert_eq!(&b[..32], &[0xab; 32]);
        assert_eq!(&b[32..], &7u32.to_le_bytes());
    }
}
