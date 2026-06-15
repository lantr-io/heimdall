//! Scan address UTxOs for on-chain linked-list *element* UTxOs.
//!
//! Both bifrost linked lists (`spos_registry.ak`, `spo_bans.ak`) store one
//! element per UTxO, authenticated by an NFT of the list policy whose asset
//! name is the element's key. An element UTxO carries exactly `[ADA, one
//! list-policy NFT]` plus an inline datum. This module is the shared
//! value-shape filter: a UTxO with no list-policy asset is ignored (anyone
//! can send unrelated value to a script address), while a UTxO carrying
//! list-policy assets in any other shape is an error — the on-chain list
//! could never have produced it, so the snapshot is not trustworthy.
//!
//! Datum *content* decoding stays with the callers ([`crate::cardano::register_spo::find_registry_utxos`],
//! [`crate::cardano::ban_list::find_ban_utxos`]) — only the value/datum
//! plumbing is shared.

use pallas_codec::minicbor;
use pallas_primitives::PlutusData;

use crate::cardano::bf_http::BfUtxo;

/// One located element UTxO: the list-policy NFT's asset name plus the
/// decoded inline datum (content not yet interpreted).
#[derive(Debug, Clone)]
pub struct NftUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub lovelace: u64,
    pub asset_name: Vec<u8>,
    pub datum: PlutusData,
}

/// Filter `utxos` (fetched from a list script address) down to well-formed
/// element UTxOs of `policy_id_hex`. Errors are human-readable descriptions
/// of the offending UTxO; callers wrap them in their own error type.
pub fn find_policy_nft_utxos(
    utxos: &[BfUtxo],
    policy_id_hex: &str,
) -> Result<Vec<NftUtxo>, String> {
    // A policy id is a 28-byte script hash = 56 lowercase hex chars. Matching
    // units by `strip_prefix(policy_id_hex)` only equals policy-equality at
    // that exact length; a short/empty prefix would split foreign units
    // mid-policy and misread the remainder as an asset name. Callers pass
    // ParameterizedScript::hash_hex() (always 56), but guard the pub API.
    if policy_id_hex.len() != 56 || !policy_id_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "policy id must be 56 hex chars (28-byte script hash), got {:?}",
            policy_id_hex
        ));
    }
    let mut out = Vec::new();
    for u in utxos {
        let at = |what: &str| format!("{}#{}: {what}", u.tx_hash, u.output_index);
        let mut lovelace = 0u64;
        let mut nft: Option<(Vec<u8>, String)> = None; // (asset_name, quantity)
        let mut foreign: Option<String> = None;
        for a in &u.amount {
            if a.unit == "lovelace" {
                lovelace = a
                    .quantity
                    .parse()
                    .map_err(|e| at(&format!("lovelace: {e}")))?;
            } else if let Some(name_hex) = a.unit.strip_prefix(policy_id_hex) {
                let name =
                    hex::decode(name_hex).map_err(|e| at(&format!("asset name hex: {e}")))?;
                if nft.replace((name, a.quantity.clone())).is_some() {
                    return Err(at("multiple list-policy assets on one UTxO"));
                }
            } else {
                foreign = Some(a.unit.clone());
            }
        }
        let Some((asset_name, quantity)) = nft else {
            continue; // not a list element (stray value at the address)
        };
        if quantity != "1" {
            return Err(at(&format!("element NFT quantity {quantity}, expected 1")));
        }
        if let Some(unit) = foreign {
            return Err(at(&format!(
                "foreign asset {unit} alongside the element NFT"
            )));
        }
        let datum_hex = u
            .inline_datum
            .as_deref()
            .ok_or_else(|| at("no inline datum"))?;
        let datum_cbor = hex::decode(datum_hex).map_err(|e| at(&format!("datum hex: {e}")))?;
        let datum: PlutusData =
            minicbor::decode(&datum_cbor).map_err(|e| at(&format!("datum CBOR: {e}")))?;
        out.push(NftUtxo {
            tx_hash: u.tx_hash.clone(),
            output_index: u.output_index,
            lovelace,
            asset_name,
            datum,
        });
    }
    Ok(out)
}
