//! The BridgeState singleton: its datum and its on-chain lookup.
//!
//! One UTxO holds the bridge state that TM Confirm writes: both trie roots, the
//! current treasury outpoint on Bitcoin, and that outpoint's value. The NFT
//! `(bridge_state_policy, "BSS")` identifies it.
//!
//! The decode is STRICT on constructor tag and arity, per spec [LIB-1]. The
//! rev-5.1 reader took the head of the field list and checked neither, so a
//! one-field CPO trie datum and a five-field successor both "decoded" — and
//! against `BridgeState` a head read returns `spi_root` where `cpo_root` is
//! wanted. A wrong root makes an MPF membership proof fail harmlessly, but it
//! makes a NON-membership proof SUCCEED, which cancels a peg-out already paid
//! in BTC. Arity is therefore pinned here, and every reader takes fields by
//! name.

use crate::cardano::cpo_history::CpoHistorySource;
use crate::cardano::cpo_trie::CpoTrieError;
use crate::cardano::plutus;
use pallas_primitives::PlutusData;

/// Asset name of the bridge state NFT — the 3 ASCII bytes `"BSS"`.
///
/// Not the rev-5.1 `"CPO"`: the singleton holds two roots and the treasury head,
/// so it is not the completed-peg-outs trie under a new datum.
pub const BSS_ASSET_NAME: &[u8] = b"BSS";

/// Hex of [`BSS_ASSET_NAME`], for asset-unit strings and Kupo asset patterns.
pub const BSS_ASSET_NAME_HEX: &str = "425353";

/// Number of fields in the `BridgeState` `Constr`. Serialization fact: field
/// order and arity are consensus-visible, so both are pinned by the decode.
const BRIDGE_STATE_FIELDS: usize = 4;

/// The singleton datum, spec §BridgeState, the singleton datum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeState {
    /// Field 0 — swept peg-ins.
    pub spi_root: [u8; 32],
    /// Field 1 — completed peg-outs.
    pub cpo_root: [u8; 32],
    /// Field 2 — the current treasury UTxO on Bitcoin: `btc_txid ++ 00000000`.
    pub treasury_utxo_id: [u8; 36],
    /// Field 3 — that UTxO's satoshi amount.
    pub treasury_amount: u64,
}

/// The `ByteArray` field at index `i`, required to be exactly `N` bytes.
///
/// A short root or a short outpoint is a WRONG value, not a shorter one: the MPF
/// root is 32 bytes and the Bitcoin outpoint is `txid ‖ vout`, 36 bytes.
fn field_fixed<const N: usize>(
    fields: &[PlutusData],
    i: usize,
    name: &str,
) -> Result<[u8; N], String> {
    let b = plutus::field_bytes(fields, i)
        .map_err(|e| format!("BridgeState datum: field[{i}] ({name}): {e}"))?;
    <[u8; N]>::try_from(b.as_slice()).map_err(|_| {
        format!(
            "BridgeState datum: field[{i}] ({name}) is {} bytes, expected {N}",
            b.len()
        )
    })
}

/// Decode a `BridgeState` datum. Strict on constructor tag and arity, per [LIB-1].
pub fn parse_bridge_state(data: &PlutusData) -> Result<BridgeState, String> {
    let fields = plutus::constr_fields(data, 0).map_err(|e| format!("BridgeState datum: {e}"))?;
    if fields.len() != BRIDGE_STATE_FIELDS {
        return Err(format!(
            "BridgeState datum: {} fields, expected exactly {BRIDGE_STATE_FIELDS} — a trailing \
             or missing field means this is not a BridgeState, and reading it by position \
             would return the wrong root",
            fields.len()
        ));
    }
    let treasury_amount = plutus::field_int(fields, 3)
        .map_err(|e| format!("BridgeState datum: field[3] (treasury_amount): {e}"))?;
    let treasury_amount = u64::try_from(treasury_amount).map_err(|_| {
        format!("BridgeState datum: field[3] (treasury_amount) is {treasury_amount}, expected a non-negative satoshi amount")
    })?;
    Ok(BridgeState {
        spi_root: field_fixed::<32>(fields, 0, "spi_root")?,
        cpo_root: field_fixed::<32>(fields, 1, "cpo_root")?,
        treasury_utxo_id: field_fixed::<36>(fields, 2, "treasury_utxo_id")?,
        treasury_amount,
    })
}

/// The on-chain BridgeState singleton, located by the `(policy, "BSS")` NFT.
///
/// The singleton is the ONE unspent output carrying that NFT. Anything else is
/// an error, and the two cases stay distinct: zero means the configured policy is
/// wrong, or the singleton is not deployed, or the backend is not indexing that
/// policy; several mean the NFT is not a singleton, so no state is authoritative.
///
/// Callers that want the completed-peg-outs root take `state.cpo_root` BY NAME,
/// per [LIB-1].
pub async fn fetch_bridge_state(
    source: &dyn CpoHistorySource,
    policy_hex: &str,
) -> Result<BridgeState, CpoTrieError> {
    let policy = policy_hex.trim().to_ascii_lowercase();
    let unit = format!("{policy}.{BSS_ASSET_NAME_HEX}");
    let matches = source
        .unspent_with_asset(&policy, BSS_ASSET_NAME_HEX)
        .await
        .map_err(CpoTrieError::Source)?;
    let held: Vec<_> = matches
        .iter()
        .filter(|m| m.asset_quantity(&policy, BSS_ASSET_NAME_HEX) == 1)
        .collect();
    let m = match held.as_slice() {
        [only] => *only,
        [] => {
            return Err(CpoTrieError::Source(format!(
                "no unspent output holds the bridge state NFT {unit} — this node is reading \
                 the wrong bridge (Config field 3, bridge_state_policy), the singleton is not \
                 deployed, or the backend is not indexing that policy"
            )));
        }
        many => {
            return Err(CpoTrieError::Source(format!(
                "{} unspent outputs hold the bridge state NFT {unit} — it is not a singleton, \
                 so no state is authoritative",
                many.len()
            )));
        }
    };
    let datum = m.datum.resolved().ok_or_else(|| {
        CpoTrieError::Source(format!(
            "the bridge state singleton {}#{} has no resolvable datum ({})",
            m.tx_hash, m.output_index, m.datum_note
        ))
    })?;
    parse_bridge_state(datum).map_err(CpoTrieError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::cpo_history::{DatumState, HistoricalOutput};
    use crate::cardano::plutus::{bytes, constr, int, int_from_u64};
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const POLICY: &str = "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5";

    fn utxo_id(txid: u8) -> [u8; 36] {
        let mut id = [0u8; 36];
        id[..32].copy_from_slice(&[txid; 32]);
        id
    }

    /// The four well-formed fields, in datum order. Every malformed case below is
    /// this list with ONE thing changed, so a test can only fail for its own reason.
    fn good_fields() -> Vec<PlutusData> {
        vec![
            bytes(&[0x11; 32]),
            bytes(&[0x22; 32]),
            bytes(&utxo_id(0xa1)),
            int_from_u64(4_200_000),
        ]
    }

    /// A well-formed BridgeState datum: four fields, constructor 0.
    fn good_datum() -> PlutusData {
        constr(0, good_fields())
    }

    // --- the asset name ----------------------------------------------------

    // The hex form is what goes into asset-unit strings and Kupo asset patterns;
    // the byte form is what the Aiken constant says. Pin them to each other so the
    // singleton lookup cannot drift from `constants.ak` — and so it cannot drift
    // back to the retired `"CPO"` (hex `43504f`).
    #[test]
    fn the_bss_asset_name_hex_matches_the_bytes() {
        assert_eq!(BSS_ASSET_NAME, b"BSS");
        assert_eq!(hex::encode(BSS_ASSET_NAME), BSS_ASSET_NAME_HEX);
    }

    // --- parse_bridge_state ------------------------------------------------

    // Every field is read BY POSITION, and the two roots are DISTINCT values, so
    // a parser that returns spi_root where cpo_root is wanted cannot pass.
    #[test]
    fn parse_bridge_state_reads_four_fields_by_position() {
        let state = parse_bridge_state(&good_datum()).expect("well-formed BridgeState");
        assert_eq!(state.spi_root, [0x11; 32]);
        assert_eq!(state.cpo_root, [0x22; 32]);
        assert_eq!(state.treasury_utxo_id, utxo_id(0xa1));
        assert_eq!(state.treasury_amount, 4_200_000);
    }

    // Arity and constructor tag are consensus-visible facts, so the decode must
    // pin both. The rev-5.1 helper took the head of the field list and checked
    // neither, which is how a one-field CPO datum and a five-field successor
    // both "decoded".
    #[test]
    fn parse_bridge_state_rejects_trailing_and_missing_fields() {
        // Five fields: an inserted or appended field must break the decode, not
        // be tolerated (a tolerated append is how a future insert goes silent).
        let mut five = good_fields();
        five.push(bytes(b"extra"));
        assert!(
            parse_bridge_state(&constr(0, five)).is_err(),
            "5 fields must be rejected"
        );

        // Three fields: a truncated datum must not decode with a defaulted tail.
        let mut three = good_fields();
        three.pop();
        assert!(
            parse_bridge_state(&constr(0, three)).is_err(),
            "3 fields must be rejected"
        );

        // The old one-field CPO trie datum. Against BridgeState a head read
        // returns spi_root where cpo_root is wanted, so it MUST NOT decode.
        let old_cpo = constr(0, vec![bytes(&[0x5a; 32])]);
        assert!(
            parse_bridge_state(&old_cpo).is_err(),
            "the one-field CPO trie datum must be rejected"
        );

        // Wrong constructor tag, and not a Constr at all.
        assert!(
            parse_bridge_state(&constr(1, good_fields())).is_err(),
            "constructor 1 must be rejected"
        );
        assert!(parse_bridge_state(&bytes(b"nope")).is_err());
    }

    // A short root or a short outpoint is a wrong value, not a shorter one: the
    // MPF root is 32 bytes and the Bitcoin outpoint is txid ++ 4-byte index.
    #[test]
    fn parse_bridge_state_rejects_wrong_byte_lengths() {
        let case = |spi: usize, cpo: usize, outpoint: usize, amount: PlutusData| {
            constr(
                0,
                vec![
                    bytes(&vec![0x11u8; spi]),
                    bytes(&vec![0x22u8; cpo]),
                    bytes(&vec![0xa1u8; outpoint]),
                    amount,
                ],
            )
        };
        assert!(
            parse_bridge_state(&case(31, 32, 36, int_from_u64(1))).is_err(),
            "a 31-byte spi_root must be rejected"
        );
        assert!(
            parse_bridge_state(&case(32, 31, 36, int_from_u64(1))).is_err(),
            "a 31-byte cpo_root must be rejected"
        );
        assert!(
            parse_bridge_state(&case(32, 32, 35, int_from_u64(1))).is_err(),
            "a 35-byte treasury_utxo_id must be rejected"
        );
        assert!(
            parse_bridge_state(&case(32, 32, 36, int(-1))).is_err(),
            "a negative treasury_amount must be rejected"
        );
        // The control: the same shape with correct lengths does decode.
        assert!(parse_bridge_state(&case(32, 32, 36, int_from_u64(1))).is_ok());
    }

    // --- fetch_bridge_state ------------------------------------------------

    /// Records the asset name it was asked for, and serves only outputs whose
    /// assets match that unit — so a lookup under the old `"CPO"` name finds
    /// nothing here.
    #[derive(Default)]
    struct FakeSource {
        holders: Vec<HistoricalOutput>,
        asked: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CpoHistorySource for FakeSource {
        fn backend(&self) -> &'static str {
            "fake"
        }
        fn endpoint(&self) -> &str {
            "memory://"
        }
        fn datum_gap_advice(&self) -> &'static str {
            "fake advice"
        }
        async fn address_history(&self, address: &str) -> Result<Vec<HistoricalOutput>, String> {
            Err(format!("unexpected address query {address}"))
        }
        async fn unspent_with_asset(
            &self,
            policy_hex: &str,
            asset_name_hex: &str,
        ) -> Result<Vec<HistoricalOutput>, String> {
            self.asked
                .lock()
                .unwrap()
                .push(asset_name_hex.to_ascii_lowercase());
            let unit = format!(
                "{}{}",
                policy_hex.to_ascii_lowercase(),
                asset_name_hex.to_ascii_lowercase()
            );
            Ok(self
                .holders
                .iter()
                .filter(|h| h.assets.contains_key(&unit))
                .cloned()
                .collect())
        }
    }

    fn holder(tx: u8, unit: &str, datum: PlutusData) -> HistoricalOutput {
        let mut assets = BTreeMap::new();
        assets.insert(unit.to_string(), 1u64);
        HistoricalOutput {
            tx_hash: hex::encode([tx; 32]),
            output_index: 0,
            assets,
            datum: DatumState::Resolved(datum),
            datum_note: "inline".into(),
        }
    }

    // The singleton is found under asset name 425353 ("BSS"), and the caller
    // takes `cpo_root` BY NAME. Zero holders and several holders stay distinct
    // errors: one means "not deployed / not indexed", the other means "not a
    // singleton, so no root is authoritative".
    #[tokio::test]
    async fn fetch_bridge_state_selects_the_unique_bss_holder() {
        let bss_unit = format!("{POLICY}{BSS_ASSET_NAME_HEX}");
        let cpo_unit = format!("{POLICY}43504f");

        let source = FakeSource {
            holders: vec![
                // A decoy under the OLD CPO asset name, carrying the old
                // one-field datum. Querying 43504f would find it and fail.
                holder(0xc0, &cpo_unit, constr(0, vec![bytes(&[0x5a; 32])])),
                holder(0xbb, &bss_unit, good_datum()),
            ],
            ..Default::default()
        };
        let state = fetch_bridge_state(&source, POLICY)
            .await
            .expect("singleton");
        assert_eq!(state.cpo_root, [0x22; 32]);
        assert_eq!(state.spi_root, [0x11; 32]);
        assert_eq!(state.treasury_amount, 4_200_000);
        assert_eq!(
            source.asked.lock().unwrap().as_slice(),
            [BSS_ASSET_NAME_HEX.to_string()],
            "the singleton must be looked up by asset name 425353, not 43504f"
        );

        // Zero holders.
        let empty = FakeSource::default();
        let none = fetch_bridge_state(&empty, POLICY)
            .await
            .expect_err("no holder");
        assert!(
            format!("{none}").contains("no unspent output holds"),
            "{none}"
        );
        // The likeliest cause is a misconfigured policy id, not a sick indexer:
        // Name the Config field, so an operator knows which value to check.
        assert!(
            format!("{none}").contains("bridge_state_policy"),
            "the zero-holder error must name the config key that selects the policy: {none}"
        );

        // Two holders.
        let many = FakeSource {
            holders: vec![
                holder(0xbb, &bss_unit, good_datum()),
                holder(0xcc, &bss_unit, good_datum()),
            ],
            ..Default::default()
        };
        let dup = fetch_bridge_state(&many, POLICY)
            .await
            .expect_err("two holders");
        assert!(format!("{dup}").contains("not a singleton"), "{dup}");
        assert_ne!(
            format!("{none}"),
            format!("{dup}"),
            "zero holders and several holders must be distinct errors"
        );
    }
}
