//! The FROST → BIP-340 boundary: turning a derived group key into the 32-byte
//! x-only key Bitcoin and Cardano actually use, with the parity handled on
//! purpose instead of sliced off.
//!
//! A secp256k1 point serializes as `parity_byte ‖ x`. Everything downstream of
//! DKG — the Taproot internal key, the `treasury_info` datum's
//! `current_spos_frost_key`, Aiken's `verify_schnorr_signature` — is x-only, so
//! the parity byte has to go somewhere. Dropping it *silently* is what makes a
//! derived key quietly stop matching the address it is supposed to control: the
//! reader can no longer tell whether the 32 bytes denote the point the DKG
//! produced or its negation, and nothing checks that the two agree.
//!
//! [`group_xonly`] makes the choice explicit. BIP-340 addresses a point by its
//! x coordinate alone and *defines* the key to be the even-Y point with that x
//! — so the normalization this performs is `into_even_y`, and the parity it
//! observed is kept in [`GroupXOnly::had_odd_y`] rather than discarded. Because
//! negating a point leaves x untouched, the normalized key serializes to the
//! same 32 bytes; the function asserts exactly that, so a future ciphersuite
//! that broke the invariant would fail loudly here rather than produce an
//! address the group cannot spend.
//!
//! **Why an odd-Y group key still signs correctly.** `frost-secp256k1-tr`
//! applies the same `into_even_y` normalization internally at every signing
//! boundary — `pre_sign` on the `KeyPackage`, `pre_aggregate` on the
//! `PublicKeyPackage`, `pre_verify` on the `VerifyingKey` — and the BIP-340
//! challenge hashes only x coordinates. So an aggregated signature verifies
//! under this x-only key for either parity. That is a property of the
//! ciphersuite, not an accident, and `signs_under_the_xonly_key_for_both_parities`
//! below pins it for both branches.

use bitcoin::key::UntweakedPublicKey;
use frost_secp256k1_tr as frost;

/// A DKG-derived FROST group key, normalized for BIP-340 use.
///
/// `xonly` is what gets stored on-chain and tweaked into a Taproot output key;
/// `had_odd_y` records the parity of the point the ceremony actually produced,
/// so the pre-normalization point can be reconstructed ([`Self::compressed`])
/// by anything that needs the full curve point back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupXOnly {
    /// The 32-byte x-only key — the even-Y point with this x coordinate.
    pub xonly: UntweakedPublicKey,
    /// Whether the DKG-derived point had an odd Y (i.e. `xonly` denotes its
    /// negation). Diagnostic and reconstruction only: it never changes what is
    /// stored, signed with, or compared.
    pub had_odd_y: bool,
}

impl GroupXOnly {
    /// SEC1 parity prefix of the point the DKG derived (`0x02` even, `0x03` odd).
    #[must_use]
    pub fn parity_byte(&self) -> u8 {
        if self.had_odd_y { 0x03 } else { 0x02 }
    }
}

/// Normalize a FROST verifying key to its BIP-340 x-only form, keeping the
/// observed parity.
///
/// Fails if the key does not serialize as a 33-byte compressed point, if the
/// parity prefix is not `0x02`/`0x03`, or if even-Y normalization moves the x
/// coordinate (it cannot, and the check is what makes the discard safe).
pub fn group_xonly(vk: &frost::VerifyingKey) -> Result<GroupXOnly, String> {
    use frost::keys::EvenY;

    let bytes = vk
        .serialize()
        .map_err(|e| format!("verifying_key serialize: {e}"))?;
    let bytes: [u8; 33] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "expected 33-byte compressed verifying key, got {}",
            bytes.len()
        )
    })?;
    let had_odd_y = match bytes[0] {
        0x02 => false,
        0x03 => true,
        other => return Err(format!("unexpected SEC1 parity prefix 0x{other:02x}")),
    };

    // Normalize deliberately rather than assuming the slice is already the
    // BIP-340 key, and check the normalization is x-preserving.
    let even = (*vk).into_even_y(Some(!had_odd_y));
    let even_bytes = even
        .serialize()
        .map_err(|e| format!("even-Y verifying_key serialize: {e}"))?;
    if even_bytes.len() != 33 || even_bytes[0] != 0x02 {
        return Err("even-Y normalization did not yield an even-Y point".to_string());
    }
    if even_bytes[1..] != bytes[1..] {
        return Err("even-Y normalization moved the x coordinate".to_string());
    }

    let xonly = UntweakedPublicKey::from_slice(&bytes[1..])
        .map_err(|e| format!("x-only key from group key: {e}"))?;
    Ok(GroupXOnly { xonly, had_odd_y })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::participant;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use frost::Identifier;
    use std::collections::BTreeMap;

    /// A fresh 2-of-2 group. The parity property under test is a property of
    /// the resulting key, not of how it was produced, so the dealer is used —
    /// an interactive ceremony would cost 40× here for nothing.
    fn dealt_2_of_2(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> (
        BTreeMap<Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ) {
        let (shares, pkp) =
            frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, rng)
                .unwrap();
        let kps = shares
            .into_iter()
            .map(|(id, s)| (id, frost::keys::KeyPackage::try_from(s).unwrap()))
            .collect();
        (kps, pkp)
    }

    /// Untweaked 2-of-2 FROST signature over `msg` — the shape the Update-Y
    /// authorization uses (BIP-340 under the group key itself, no Taproot tweak).
    fn frost_sign(
        key_packages: &BTreeMap<Identifier, frost::keys::KeyPackage>,
        pkp: &frost::keys::PublicKeyPackage,
        msg: &[u8],
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> [u8; 64] {
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (id, kp) in key_packages {
            let (n, c) = participant::sign_round1(kp, rng);
            nonces.insert(*id, n);
            commitments.insert(*id, c);
        }
        let package = frost::SigningPackage::new(commitments, msg);
        let mut shares = BTreeMap::new();
        for (id, kp) in key_packages {
            shares.insert(
                *id,
                participant::sign_round2(&package, &nonces[id], kp).unwrap(),
            );
        }
        participant::sign_aggregate(&package, &shares, pkp)
            .unwrap()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn x_only_key_is_the_even_y_point_and_parity_round_trips() {
        let mut rng = rand::thread_rng();
        let (_, pkp) = dealt_2_of_2(&mut rng);
        let vk = pkp.verifying_key();
        let compressed = vk.serialize().unwrap();
        let g = group_xonly(vk).unwrap();

        // Parity is reported, not guessed, and the x coordinate is untouched —
        // together these reconstruct exactly what the ceremony derived.
        assert_eq!(g.parity_byte(), compressed[0]);
        assert_eq!(&g.xonly.serialize()[..], &compressed[1..]);
        // secp256k1 agrees this is a valid x-only key.
        assert_eq!(
            UntweakedPublicKey::from_slice(&g.xonly.serialize()).unwrap(),
            g.xonly
        );
    }

    /// The property the whole normalization rests on: whatever parity the DKG
    /// happened to produce, an untweaked FROST signature verifies under the
    /// 32-byte key we store on-chain. Runs ceremonies until BOTH parities have
    /// been observed, so neither branch can rot untested.
    #[test]
    fn signs_under_the_xonly_key_for_both_parities() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let msg = [0x5au8; 32];
        let mut seen_even = false;
        let mut seen_odd = false;

        // P(odd) = 1/2 per ceremony; 40 draws makes a miss ~1e-12.
        for _ in 0..40 {
            let (key_packages, pkp) = dealt_2_of_2(&mut rng);
            let g = group_xonly(pkp.verifying_key()).unwrap();
            let sig_bytes = frost_sign(&key_packages, &pkp, &msg, &mut rng);
            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
            secp.verify_schnorr(&sig, &Message::from_digest(msg), &g.xonly)
                .unwrap_or_else(|e| {
                    panic!(
                        "FROST signature must verify under the stored x-only key \
                         (had_odd_y={}): {e}",
                        g.had_odd_y
                    )
                });
            seen_even |= !g.had_odd_y;
            seen_odd |= g.had_odd_y;
            if seen_even && seen_odd {
                return;
            }
        }
        panic!("never observed both group-key parities (even={seen_even}, odd={seen_odd})");
    }
}
