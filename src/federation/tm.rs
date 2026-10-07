//! Posting a federation movement to Cardano.
//!
//! `federation-spend` signs a Taproot script-path spend of the treasury and
//! prints the bytes. Printing is the whole story for a *sweep* — WI-086 keeps
//! Bitcoin broadcast out of heimdall on purpose — but it is not the whole story
//! for a Treasury Movement. Spec §Treasury Movement: in federation mode "the
//! federation signs via the $Y_{federation}$ script path with timelock and the
//! resulting signed transaction is posted to Cardano the same way", and the
//! watchtower relays it from that posted record.
//!
//! Skip the post and the bridge-state singleton never learns the movement
//! happened. The next builder then works from a head that Bitcoin has already
//! spent, so every movement it builds is dead on arrival under [CTM-18]. That is
//! not a cosmetic gap: it is how a recovery turns into a second outage.
//!
//! The posting itself is `CardanoChain::submit_signed_tm`, the same call the
//! daemon's post phase makes. Reusing it is the point — a second posting path
//! would be a second record shape for watchtowers to agree about.

use bitcoin::Transaction;

use crate::epoch::traits::CardanoChain;

/// Post a federation-signed movement as an `UnconfirmedTm` record.
///
/// Refuses when input 0 is not the singleton's current head. Such a record can
/// never confirm ([CTM-18]) — `show-treasury` already flags the two preprod
/// records in that state as `DEAD` — so posting another adds a record nobody can
/// act on and buries the one that matters.
///
/// `fulfilled_por_outpoints` is the rev-5.1 data-availability hint: the Cardano
/// outpoints of the peg-out requests this movement fulfils. Empty for a treasury
/// move that pays none.
pub async fn post_federation_tm(
    chain: &dyn CardanoChain,
    signed: &Transaction,
    fulfilled_por_outpoints: &[[u8; 36]],
) -> Result<(), String> {
    let head = chain
        .query_treasury()
        .await
        .map_err(|e| format!("reading the treasury head: {e}"))?;

    let spent = signed
        .input
        .first()
        .ok_or_else(|| "the signed movement has no inputs".to_string())?
        .previous_output;

    if spent != head.outpoint {
        return Err(format!(
            "refusing to post: this movement spends {spent} at input 0, but the singleton's \
             head is {}. A record whose input 0 is not the head can never confirm ([CTM-18]), \
             so posting it would stall the bridge rather than move it",
            head.outpoint
        ));
    }

    // Where the money goes. The singleton follows whatever output 0 is, so a
    // posted movement paying the wrong address moves bridge custody there. The
    // likeliest wrong address is the OLD tree – `federation-spend` without `--to`
    // self-sends to the tree the head is already under – which after a rotation
    // only the dead roster can spend.
    let expected = head.authorized_treasury_spk();
    let paid = &signed
        .output
        .first()
        .ok_or_else(|| "the signed movement has no outputs".to_string())?
        .script_pubkey;
    if *paid != expected {
        return Err(format!(
            "refusing to post: output 0 pays {}, but the treasury the datum authorizes (key \
             {}) is {}. Every movement must pay the new treasury at output 0 ([BTC-2]); pass \
             that address as --to",
            hex::encode(paid.as_bytes()),
            hex::encode(head.authorized_key.serialize()),
            hex::encode(expected.as_bytes()),
        ));
    }

    let commitments = signed
        .output
        .iter()
        .filter(|o| crate::bitcoin::tm_builder::is_btmr1_commitment(o.script_pubkey.as_bytes()))
        .count();
    if commitments != 1 {
        return Err(format!(
            "refusing to post: the movement carries {commitments} BTMR1 commitment outputs, and \
             every spend of the treasury needs exactly one ([BTC-1], [CTM-26])"
        ));
    }

    let raw = bitcoin::consensus::encode::serialize(signed);
    chain
        .submit_signed_tm(&raw, fulfilled_por_outpoints)
        .await
        .map_err(|e| format!("posting the movement to Cardano: {e}"))
}

#[cfg(test)]
mod tests {
    use bitcoin::key::{Keypair, Secp256k1, UntweakedPublicKey};
    use bitcoin::{OutPoint, ScriptBuf};

    use super::*;
    use crate::bitcoin::taproot::treasury_spend_info;
    use crate::bitcoin::tm_builder::btmr1_commitment_script;
    use crate::epoch::fixture::demo_static_fixture;
    use crate::epoch::mocks::MockCardanoChain;

    fn xonly(seed: u8) -> UntweakedPublicKey {
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
    }

    /// The bridge between a `[UY-5]` rotation and the federation movement that
    /// follows it: the head still sits under the old key's tree while the datum
    /// already names `new_key`. Preprod spent 2026-10-06 15:13 to 2026-10-07 08:27
    /// in exactly this state.
    struct Rotated {
        chain: MockCardanoChain,
        head: OutPoint,
        old_tree: ScriptBuf,
        new_tree: ScriptBuf,
    }

    fn rotated(port: u16) -> Rotated {
        let fixture = demo_static_fixture(2, 3, port);
        let secp = Secp256k1::new();
        let (y_fed, csv) = (fixture.y_fed, fixture.federation_csv_blocks);
        let tree = |internal| {
            ScriptBuf::new_p2tr_tweaked(
                treasury_spend_info(&secp, internal, y_fed, csv).output_key(),
            )
        };
        let new_key = xonly(0x5a);
        let (old_tree, new_tree, head) =
            (tree(fixture.y_51), tree(new_key), fixture.treasury_outpoint);
        let chain = MockCardanoChain::new(fixture)
            .with_treasury_info(MockCardanoChain::treasury_info_state(new_key, [7; 32]));
        Rotated {
            chain,
            head,
            old_tree,
            new_tree,
        }
    }

    /// A movement spending `spends` and paying `pays` at output 0, with or without
    /// its BTMR1 commitment. The witness is irrelevant: posting carries bytes, it
    /// does not verify signatures.
    fn movement(spends: OutPoint, pays: ScriptBuf, commitments: usize) -> Transaction {
        let mut output = vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(500_000),
            script_pubkey: pays,
        }];
        for _ in 0..commitments {
            output.push(bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: btmr1_commitment_script(&[1; 32], &[2; 32]),
            });
        }
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: spends,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::from_height(144),
                witness: bitcoin::Witness::new(),
            }],
            output,
        }
    }

    #[tokio::test]
    async fn a_movement_to_the_new_treasury_is_posted_verbatim() {
        let r = rotated(29100);
        let recorded = r.chain.submitted_txs();
        let signed = movement(r.head, r.new_tree, 1);

        post_federation_tm(&r.chain, &signed, &[])
            .await
            .expect("posts");

        let posted = recorded.lock().unwrap();
        assert_eq!(posted.len(), 1, "exactly one record");
        assert_eq!(
            posted[0],
            bitcoin::consensus::encode::serialize(&signed),
            "the record carries the signed bytes verbatim"
        );
    }

    #[tokio::test]
    async fn a_movement_that_does_not_spend_the_head_is_refused() {
        let r = rotated(29110);
        let recorded = r.chain.submitted_txs();
        let stale = OutPoint {
            txid: "cefb913dd5d6ac7715363b05692797cdc4e4146072c05102d6d0bf0a74f9270a"
                .parse()
                .unwrap(),
            vout: 0,
        };

        let err = post_federation_tm(&r.chain, &movement(stale, r.new_tree, 1), &[])
            .await
            .expect_err("must refuse");

        assert!(
            err.contains("CTM-18"),
            "says why it can never confirm: {err}"
        );
        assert!(recorded.lock().unwrap().is_empty(), "nothing was posted");
    }

    /// The mistake that is easiest to make: `federation-spend` without `--to`
    /// self-sends to the tree the head is ALREADY under. After a rotation that is
    /// the old key's tree, so posting it would hand the singleton an output that
    /// only the dead roster could ever spend, and the treasury would be exactly
    /// as stuck as before, minus a fee.
    #[tokio::test]
    async fn a_movement_paying_anywhere_but_the_authorized_treasury_is_refused() {
        let r = rotated(29120);
        let recorded = r.chain.submitted_txs();

        let err = post_federation_tm(&r.chain, &movement(r.head, r.old_tree, 1), &[])
            .await
            .expect_err("must refuse");

        assert!(err.contains("BTC-2"), "names the rule it breaks: {err}");
        assert!(recorded.lock().unwrap().is_empty(), "nothing was posted");
    }

    #[tokio::test]
    async fn a_movement_without_exactly_one_commitment_output_is_refused() {
        for commitments in [0, 2] {
            let r = rotated(29130 + commitments as u16);
            let recorded = r.chain.submitted_txs();

            let err = post_federation_tm(
                &r.chain,
                &movement(r.head, r.new_tree.clone(), commitments),
                &[],
            )
            .await
            .expect_err("must refuse");

            assert!(err.contains("BTC-1"), "{commitments} commitments: {err}");
            assert!(recorded.lock().unwrap().is_empty(), "nothing was posted");
        }
    }
}
