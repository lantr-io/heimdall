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
                "no unspent output holds the bridge state NFT {unit} — cardano.cpo_policy_id \
                 names the wrong policy (it must be Config field 3, bridge_state_policy), the \
                 singleton is not deployed, or the backend is not indexing that policy"
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
        // `cardano.cpo_policy_id` must hold the BRIDGE STATE policy. Name the key.
        assert!(
            format!("{none}").contains("cardano.cpo_policy_id"),
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

/// How this node's persisted tries stand against the roots the bridge attests.
///
/// One reader for two callers that must never disagree: the startup catch-up
/// decides whether to rebuild from it, and preflight step 10 reports from it.
/// Two implementations of "is my state current" is how a node heals a fault the
/// check still reports, or reports one it has already healed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriesStatus {
    /// Both match what the singleton attests — including the case where the
    /// bridge has no history and this node correctly has no files.
    InSync,
    /// Files absent where the chain has history. Every new node starts here,
    /// and it is not a fault in the node — it has no starting point yet.
    NeverSeeded { missing: Vec<&'static str> },
    /// At least one file present and disagreeing. Different in kind: this node
    /// holds state the chain contradicts, and it can neither build nor co-sign
    /// until it is reconciled.
    ///
    /// `missing` rides along rather than being dropped: one trie diverged and
    /// the other absent is a real combination, and an operator diagnosing by
    /// hand needs to hear about both files, not the louder one.
    Diverged {
        detail: Vec<String>,
        missing: Vec<&'static str>,
    },
    /// A file exists and cannot be parsed — truncated by a crash, unreadable
    /// after a permission change, or written by a version this build does not
    /// understand.
    ///
    /// Its own case, not `Diverged`, for two reasons. The operator's fix is
    /// different: "this node's state disagrees with the chain" sends someone
    /// hunting a consensus fault when the answer is `chown`. And the CHAIN may
    /// not have moved at all, so a movement this node posted can still be in
    /// flight — which decides whether its pending record may be dropped.
    Unreadable { detail: Vec<String> },
}

/// Compare the tries in `state_dir` against the roots the bridge-state
/// singleton attests.
///
/// A trie that cannot be READ counts as diverged rather than absent: a corrupt
/// file is state this node cannot account for, and treating it as "never
/// seeded" would silently overwrite it.
#[must_use]
pub fn local_tries_status(
    state_dir: &std::path::Path,
    chain_cpo_root: [u8; 32],
    chain_spi_root: [u8; 32],
) -> TriesStatus {
    let cpo = crate::cardano::cpo_trie::CpoTrie::load(state_dir).map(|t| t.map(|t| t.root()));
    let spi = crate::cardano::spi_trie::SpiTrie::load(state_dir).map(|t| t.map(|t| t.root()));

    let mut missing: Vec<&'static str> = Vec::new();
    let mut detail: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    for (what, local, want) in [
        ("cpo", cpo.map_err(|e| e.to_string()), chain_cpo_root),
        ("spi", spi.map_err(|e| e.to_string()), chain_spi_root),
    ] {
        match local {
            Err(e) => unreadable.push(format!("{what}-trie.json cannot be read: {e}")),
            Ok(None) if want == crate::cardano::cpo_trie::EMPTY_ROOT => {}
            Ok(None) => missing.push(what),
            Ok(Some(root)) if root != want => detail.push(format!(
                "{what} root {} != the chain's {}",
                hex::encode(root),
                hex::encode(want)
            )),
            Ok(Some(_)) => {}
        }
    }
    if !unreadable.is_empty() {
        // Ahead of the others: an unparseable file is the fault to report, and
        // whatever the other trie says cannot be acted on until it is fixed.
        TriesStatus::Unreadable { detail: unreadable }
    } else if !detail.is_empty() {
        TriesStatus::Diverged { detail, missing }
    } else if !missing.is_empty() {
        TriesStatus::NeverSeeded { missing }
    } else {
        TriesStatus::InSync
    }
}

#[cfg(test)]
mod tries_status_tests {
    use super::*;
    use crate::cardano::cpo_trie::CpoTrie;
    use crate::cardano::spi_trie::SpiTrie;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("heimdall-tries-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        // Each test owns its directory; leftovers from a previous run would
        // make "never seeded" pass for the wrong reason.
        let _ = std::fs::remove_file(d.join("cpo-trie.json"));
        let _ = std::fs::remove_file(d.join("spi-trie.json"));
        d
    }

    /// A brand-new bridge has all-zero roots, and a node with no files is
    /// correct — which is exactly why the spo4 fault stayed invisible until
    /// the first peg-out moved the root off zero.
    #[test]
    fn no_files_against_a_bridge_with_no_history_is_in_sync() {
        let d = dir("fresh-bridge");
        assert_eq!(
            local_tries_status(&d, [0u8; 32], [0u8; 32]),
            TriesStatus::InSync
        );
    }

    /// Every new node on a live bridge. Not a fault in the node — it has no
    /// starting point — and the distinction is what the daemon keys its
    /// self-seeding on.
    #[test]
    fn no_files_against_a_bridge_with_history_is_never_seeded() {
        let d = dir("new-node");
        let status = local_tries_status(&d, [0xc8u8; 32], [0x26u8; 32]);
        assert_eq!(
            status,
            TriesStatus::NeverSeeded {
                missing: vec!["cpo", "spi"]
            }
        );
    }

    /// Present and disagreeing is a different kind of fault: this node holds
    /// state the chain contradicts.
    #[test]
    fn files_that_disagree_with_the_chain_are_diverged() {
        let d = dir("diverged");
        CpoTrie::empty().save(&d).unwrap();
        SpiTrie::empty().save(&d).unwrap();
        let TriesStatus::Diverged { detail, .. } =
            local_tries_status(&d, [0xc8u8; 32], [0x26u8; 32])
        else {
            panic!("empty tries against a bridge with history disagree");
        };
        assert_eq!(detail.len(), 2, "{detail:?}");
        assert!(detail[0].contains("cpo root"), "{detail:?}");
    }

    /// The combination `Diverged.missing` exists to carry, and the one the
    /// earlier version silently dropped: an operator diagnosing this by hand
    /// has to hear that the second file is GONE, not only that the first
    /// disagrees.
    #[test]
    fn one_trie_diverged_and_the_other_absent_reports_both() {
        let d = dir("mixed");
        CpoTrie::empty().save(&d).unwrap();
        let TriesStatus::Diverged { detail, missing } =
            local_tries_status(&d, [0xc8u8; 32], [0x26u8; 32])
        else {
            panic!("a stale cpo trie beside an absent spi trie is diverged");
        };
        assert_eq!(detail.len(), 1, "{detail:?}");
        assert!(detail[0].starts_with("cpo root"), "{detail:?}");
        assert_eq!(missing, vec!["spi"], "the absent file must not be dropped");
    }

    /// A file that exists and cannot be parsed is its own fault: the operator's
    /// fix is `chown`, not a consensus investigation, and the chain may not
    /// have moved at all — which decides whether a pending record may be
    /// dropped.
    #[test]
    fn an_unparseable_file_is_not_a_disagreement() {
        let d = dir("unreadable");
        std::fs::write(d.join("cpo-trie.json"), b"not json").unwrap();
        SpiTrie::empty().save(&d).unwrap();
        let status = local_tries_status(&d, [0xc8u8; 32], SpiTrie::empty().root());
        let TriesStatus::Unreadable { detail } = status else {
            panic!("got {status:?}, wanted Unreadable");
        };
        assert!(detail[0].contains("cannot be read"), "{detail:?}");
    }

    #[test]
    fn files_that_match_are_in_sync() {
        let d = dir("in-sync");
        CpoTrie::empty().save(&d).unwrap();
        SpiTrie::empty().save(&d).unwrap();
        let empty_cpo = CpoTrie::empty().root();
        let empty_spi = SpiTrie::empty().root();
        assert_eq!(
            local_tries_status(&d, empty_cpo, empty_spi),
            TriesStatus::InSync
        );
    }
}
