//! The bridge's PUBLISHED view, resolved from the one Config NFT.
//!
//! Every value that decides a peg-in deposit address is on chain, reachable from
//! the Config NFT alone:
//!
//! ```text
//! Config #9/#10 -> treasury_info -> current_spos_frost_key  = Y_51 (tree INTERNAL key)
//! Config #11                                                 = Y_federation (sweep leaf)
//! Config #11 params[7]                                       = federation_csv_blocks
//! Config [CFG-9] params.pegin_refund_timeout_blocks          = refund_timeout
//! ```
//!
//! Only the depositor's own key is not here, and it cannot be: it is theirs.
//!
//! This exists because the alternative — an operator copying those four values
//! onto a command line — is a live footgun rather than a theoretical one. `Y_51`
//! rotates every ceremony, and a deposit built under the previous one is a
//! well-formed P2TR that the bridge cannot sweep and the depositor cannot touch
//! until the refund timeout. That is not hypothetical: a 15468 sat deposit
//! stranded exactly that way on 2026-08-28. Reading the chain is not "guessing" —
//! it is the only source that is right by construction.

use bitcoin::key::UntweakedPublicKey;

use crate::bitcoin::taproot::PeginTreeParams;
use crate::cardano::config_params::ConfigView;
use crate::config::HeimdallConfig;

/// Read the bridge Config UTxO, when this node is pointed at one.
///
/// `Ok(None)` means no Config is configured at all — not that the read failed.
/// A genuine read error propagates, because "the bridge publishes nothing" and
/// "we could not ask" have different right answers.
pub async fn config_view(cfg: &HeimdallConfig) -> Result<Option<ConfigView>, String> {
    let (Some(pid), Some(addr), Some(policy)) = (
        cfg.cardano.blockfrost_project_id.as_deref(),
        cfg.cardano.config_address.as_deref(),
        cfg.cardano.config_nft_policy_id.as_deref(),
    ) else {
        return Ok(None);
    };
    let base_url = crate::cardano::bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let nft_unit = format!(
        "{policy}{}",
        cfg.cardano.config_nft_asset_name.as_deref().unwrap_or("")
    );
    crate::cardano::config_params::fetch_config(&base_url, pid, addr, &nft_unit)
        .await
        .map(Some)
}

/// `Y_51` as the bridge publishes it: `treasury_info.current_spos_frost_key`.
///
/// This is the key the spec tells depositors to derive from, and the one both
/// sweep paths reconstruct the address under. It changes at every handoff, so it
/// is read, never remembered.
pub async fn published_y51(cfg: &HeimdallConfig) -> Result<UntweakedPublicKey, String> {
    let config = config_view(cfg).await?;
    let source = crate::cardano::roster::RegistryRosterSource::resolve(
        &cfg.cardano,
        config.as_ref().map(|v| &v.params),
    )
    .map_err(|e| format!("cannot locate the treasury_info state: {e}"))?
    .ok_or("this bridge's Config publishes no treasury_info to read Y_51 from")?;

    let pid =
        cfg.cardano.blockfrost_project_id.as_deref().ok_or(
            "cardano.blockfrost_project_id is required to read the bridge's published keys",
        )?;
    let base_url = crate::cardano::bf_http::base_url(pid, cfg.cardano.blockfrost_url.as_deref());
    let utxos =
        crate::cardano::bf_http::fetch_address_utxos(&base_url, pid, &source.treasury_info_address)
            .await
            .map_err(|e| format!("could not read treasury_info: {e}"))?;
    let state = crate::cardano::treasury_spend::find_treasury_state(
        &utxos,
        &source.treasury_info_policy_hex,
        &source.treasury_info_asset_name_hex,
    )
    .map_err(|e| format!("could not locate the treasury_info state: {e}"))?;

    UntweakedPublicKey::from_slice(&state.datum.current_spos_frost_key).map_err(|e| {
        format!(
            "treasury_info current_spos_frost_key ({}) is not an x-only key: {e}",
            hex::encode(&state.datum.current_spos_frost_key)
        )
    })
}

/// The peg-in deposit tree, every input taken from the chain.
///
/// The federation half goes through [`crate::cardano::federation::resolve`] with
/// no local share — a depositor holds none, and passing `None` is how you say so.
/// `validate()` runs inside [`crate::cardano::federation::FederationIdentity::pegin_tree`],
/// so a Config whose refund window opens before the federation's is refused here
/// rather than producing an address that lets a depositor take a deposit back
/// while the bridge is still recovering it.
pub async fn pegin_tree_from_chain(cfg: &HeimdallConfig) -> Result<PeginTreeParams, String> {
    let config = config_view(cfg).await?;
    let federation =
        crate::cardano::federation::resolve(&cfg.bitcoin, None, config.as_ref().map(|v| &v.params))
            .map_err(|e| format!("{e}\n{}", e.fix()))?;
    let y_51 = published_y51(cfg).await?;
    federation.pegin_tree(y_51)
}
