//! Where a deployed reference script is (WI-056).
//!
//! The `spos_registry` script is ~12 KB. A `register-spo` transaction spends the
//! registry, so it needs that script as a witness — embedded, it appears twice and
//! the transaction exceeds the 16 KB limit. `deploy-registry-ref` therefore parks
//! the script in a UTxO once and `register-spo` *references* it.
//!
//! That left the operator copying an outpoint between two commands. Both ends of
//! the copy know how to find the UTxO on their own: it is the one at the
//! operator's wallet address carrying this script hash. This module is that
//! lookup, in one place — the startup report (WI-053 step 5) and `register-spo`
//! must not be able to disagree about where the reference script is, since one
//! reports it healthy and the other builds the transaction against it.
//!
//! The lookup is deliberately scoped to the operator's own wallet, which is where
//! `deploy-registry-ref` key-locks it (so the ~55 ADA stays reclaimable). A
//! reference script is public and any UTxO carrying one will do, including another
//! SPO's — but Blockfrost has no by-script-hash query to find those. That is what
//! `--registry-ref` remains for.

use std::fmt;

use crate::cardano::bf_http::{self, BfUtxo};

/// A UTxO carrying a reference script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefScriptUtxo {
    pub tx_hash: String,
    pub index: u32,
}

impl RefScriptUtxo {
    /// The `(tx_hash, index)` pair the transaction builders take.
    #[must_use]
    pub fn outref(&self) -> (String, u32) {
        (self.tx_hash.clone(), self.index)
    }
}

impl fmt::Display for RefScriptUtxo {
    /// `<tx_hash>#<index>` — the Cardano UTxO convention. Note that the
    /// `--registry-ref` CLI argument is parsed as `<tx_hash>:<index>`; this is for
    /// display, not for feeding back into a command line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.tx_hash, self.index)
    }
}

/// Pick the UTxO carrying `script_hash` as its reference script.
///
/// Split from the query so it is testable without a node. Script hashes are
/// compared case-insensitively: they travel as hex through Blockfrost JSON, a
/// blueprint and a CLI argument, and a case difference is not a different script.
#[must_use]
pub fn find_ref_script(utxos: &[BfUtxo], script_hash: &str) -> Option<RefScriptUtxo> {
    utxos
        .iter()
        .find(|u| {
            u.reference_script_hash
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(script_hash))
        })
        .map(|u| RefScriptUtxo {
            tx_hash: u.tx_hash.clone(),
            index: u.output_index,
        })
}

/// Look for `script_hash`'s reference script among `address`'s UTxOs.
///
/// `Ok(None)` means the address holds no such UTxO — a state with a known fix,
/// distinct from `Err`, which means we could not find out.
pub async fn wallet_ref_script(
    base_url: &str,
    project_id: &str,
    address: &str,
    script_hash: &str,
) -> Result<Option<RefScriptUtxo>, String> {
    let utxos = bf_http::fetch_address_utxos(base_url, project_id, address)
        .await
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    Ok(find_ref_script(&utxos, script_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::bf_http::BfUtxo;

    fn utxo(tx_hash: &str, index: u32, ref_script: Option<&str>) -> BfUtxo {
        BfUtxo {
            tx_hash: tx_hash.to_string(),
            output_index: index,
            amount: vec![],
            inline_datum: None,
            reference_script_hash: ref_script.map(str::to_string),
        }
    }

    const REGISTRY: &str = "5a7575f9a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718";
    const OTHER: &str = "aabbccddeeff00112233445566778899aabbccddeeff001122334455";

    #[test]
    fn finds_the_utxo_carrying_the_script() {
        let utxos = vec![
            utxo("11".repeat(32).as_str(), 0, None),
            utxo("22".repeat(32).as_str(), 3, Some(REGISTRY)),
        ];
        let found = find_ref_script(&utxos, REGISTRY).expect("should find it");
        assert_eq!(found.tx_hash, "22".repeat(32));
        assert_eq!(found.index, 3);
        assert_eq!(found.outref(), ("22".repeat(32), 3));
    }

    /// A wallet holding *some* reference script is not a wallet holding *this*
    /// one. Getting this wrong would reference the wrong script and fail at
    /// script evaluation, well after the point that names the cause.
    #[test]
    fn a_different_reference_script_is_not_a_match() {
        let utxos = vec![utxo("33".repeat(32).as_str(), 0, Some(OTHER))];
        assert!(find_ref_script(&utxos, REGISTRY).is_none());
    }

    #[test]
    fn no_reference_script_anywhere_is_none_not_a_panic() {
        let utxos = vec![
            utxo("44".repeat(32).as_str(), 0, None),
            utxo("55".repeat(32).as_str(), 1, None),
        ];
        assert!(find_ref_script(&utxos, REGISTRY).is_none());
        assert!(find_ref_script(&[], REGISTRY).is_none());
    }

    /// The hash reaches this comparison from a blueprint on one side and
    /// Blockfrost JSON on the other; neither promises a case.
    #[test]
    fn the_hash_comparison_ignores_case() {
        let utxos = vec![utxo(
            "66".repeat(32).as_str(),
            2,
            Some(&REGISTRY.to_uppercase()),
        )];
        assert!(find_ref_script(&utxos, REGISTRY).is_some());
    }

    /// Display is the UTxO convention, NOT the `--registry-ref` argument syntax.
    #[test]
    fn display_uses_the_utxo_convention() {
        let r = RefScriptUtxo {
            tx_hash: "77".repeat(32),
            index: 1,
        };
        assert_eq!(r.to_string(), format!("{}#1", "77".repeat(32)));
    }
}
