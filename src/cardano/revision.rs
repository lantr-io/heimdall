//! Which one-shot a federation script was compiled from, once that is no longer
//! Config #12.
//!
//! Every federation script is parameterized by a one-shot outpoint that its
//! `Bootstrap` spends. At genesis that is ONE outpoint for all of them,
//! published at #12 (WI-090). A revision cannot reuse it — #12 was spent at
//! genesis — so a revised registry or ban list is compiled from a fresh
//! outpoint, and the Config publishes only the result: the policy id at #9 or
//! #8. Deriving from #12 after a revision yields the OLD policy, and a command
//! that does so builds against a registry the bridge no longer uses.
//!
//! The outpoint is recoverable from the chain. The revised script's root token
//! was minted by its `Bootstrap`, which spent the one-shot, so the one-shot is
//! one of that transaction's inputs. Each input is tried, and one is accepted
//! only if it derives the policy id the Config publishes. The derivation is a
//! hash over the outpoint, so a provider that lies can make this fail but can
//! never make it return the wrong outpoint. And it uses this binary's blueprint,
//! so a match also says this heimdall speaks the contracts release the bridge
//! runs — the check the #12 derivation used to make on its own.

use crate::cardano::bf_http;
use crate::cardano::roster::parse_outref;

/// The one-shot `published` was compiled from, or `None` when no candidate
/// derives it.
///
/// `genesis_one_shot` (Config #12) is tried first and costs no chain read, so a
/// bridge that has never been revised behaves exactly as before. Only when it
/// does not derive `published` is the root token's minting transaction read.
///
/// `derive` maps a `<tx_hash>:<index>` candidate to the policy id it produces.
pub async fn one_shot_for(
    base_url: &str,
    project_id: &str,
    genesis_one_shot: &str,
    published: &[u8; 28],
    root_asset_name: &[u8],
    derive: impl Fn(&str) -> Result<[u8; 28], String>,
) -> Result<Option<String>, String> {
    if derive(genesis_one_shot)? == *published {
        return Ok(Some(genesis_one_shot.to_string()));
    }
    let unit = format!("{}{}", hex::encode(published), hex::encode(root_asset_name));
    let Some(bootstrap_tx) =
        bf_http::fetch_asset_initial_mint_tx(base_url, project_id, &unit).await?
    else {
        return Ok(None);
    };
    let spent = bf_http::fetch_tx_spent_inputs(base_url, project_id, &bootstrap_tx).await?;
    let candidates: Vec<String> = spent.iter().map(|(h, i)| format!("{h}:{i}")).collect();
    pick(&candidates, published, derive)
}

/// The candidate that derives `published`. Split from the reads so the one rule
/// that matters — accept only what hashes back — is testable without a node.
fn pick(
    candidates: &[String],
    published: &[u8; 28],
    derive: impl Fn(&str) -> Result<[u8; 28], String>,
) -> Result<Option<String>, String> {
    for c in candidates {
        // An input that is not an outpoint this code can parse cannot be the
        // one-shot, and must not stop the search for the one that is.
        if parse_outref(c).is_err() {
            continue;
        }
        if derive(c)? == *published {
            return Ok(Some(c.clone()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outref(seed: u8, ix: u32) -> String {
        format!("{}:{ix}", hex::encode([seed; 32]))
    }

    /// A stand-in derivation: the policy is a function of the outpoint, as the
    /// real one is.
    fn fake_derive(o: &str) -> Result<[u8; 28], String> {
        let (tx, ix) = parse_outref(o)?;
        let mut p = [0u8; 28];
        p[0] = tx[0];
        p[1] = u8::try_from(ix).unwrap_or(0xff);
        Ok(p)
    }

    #[test]
    fn only_the_candidate_that_derives_the_published_policy_is_accepted() {
        let published = fake_derive(&outref(7, 2)).unwrap();
        let candidates = [outref(1, 0), outref(7, 1), outref(7, 2), outref(9, 0)];
        assert_eq!(
            pick(&candidates, &published, fake_derive).unwrap(),
            Some(outref(7, 2))
        );
    }

    /// A provider that returns the wrong transaction yields no answer, never a
    /// wrong one.
    #[test]
    fn no_candidate_deriving_the_policy_is_no_answer() {
        let published = fake_derive(&outref(7, 2)).unwrap();
        let candidates = [outref(1, 0), outref(2, 0)];
        assert_eq!(pick(&candidates, &published, fake_derive).unwrap(), None);
    }

    #[test]
    fn an_unparseable_candidate_is_skipped_not_fatal() {
        let published = fake_derive(&outref(3, 0)).unwrap();
        let candidates = ["not-an-outref".to_string(), outref(3, 0)];
        assert_eq!(
            pick(&candidates, &published, fake_derive).unwrap(),
            Some(outref(3, 0))
        );
    }
}
