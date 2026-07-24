//! `treasury.ak` (`treasury_info`) state datum + the SPO-registration transition.
//!
//! This is the **roster/key oracle** datum — distinct from `treasury_datum.rs`,
//! which is the *treasury-movement* oracle (`Constr(0/1,[btc_tx])`). The
//! `treasury_info` UTxO carries:
//!
//! ```text
//! Constr(0, [ bifrost_identity_root, current_spos_frost_key,
//!             y_federation,          federation_csv_blocks ])
//! //          ^ByteArray x3          ^Int
//! ```
//!
//! matching the Aiken `bifrost/types/treasury.ak` `TreasuryDatum` (N10b: the two
//! vestigial pointer fields were retired and the federation fields added).
//!
//! `register_spo` (R1c) spends this UTxO to insert `bifrost_id_pk → pool_id`
//! into the `bifrost_identity_root` Merkle-Patricia-Forestry trie. This module
//! provides the heimdall-side machinery shared with K1 (bootstrap) and the
//! registry mint (R1): encode/decode the datum, encode the spend redeemer and
//! the on-chain proof, and compute the post-registration datum + the
//! `bifrost_identity_absence_proof` from the off-chain MPF trie ([`crate::cardano::mpf`]).
//!
//! NOTE: building/submitting the full register_spo Cardano tx (spending a live
//! `treasury_info` UTxO + the registry linked-list) is blocked on K1 — the
//! `treasury_info` validator is not deployed yet. The logic here is pure and
//! testable now.

use pallas_codec::minicbor;
use pallas_primitives::PlutusData;

use crate::cardano::mpf;
use crate::cardano::plutus::{self, array, bytes, constr, int};

/// The `treasury_info` state datum (`TreasuryDatum`). `bifrost_identity_root` is
/// the 32-byte MPF root; `current_spos_frost_key` / `y_federation` are x-only
/// keys; `federation_csv_blocks` is the CSV timeout (an on-chain `Int`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreasuryInfoDatum {
    pub bifrost_identity_root: mpf::Hash,
    pub current_spos_frost_key: Vec<u8>,
    pub y_federation: Vec<u8>,
    pub federation_csv_blocks: i64,
}

#[derive(Debug)]
pub enum TreasuryInfoError {
    NotConstr,
    WrongConstructor(u64),
    FieldCount {
        expected: usize,
        got: usize,
    },
    NotBytes(usize),
    BadRootLen(usize),
    /// The off-chain trie's root does not match `current.bifrost_identity_root`,
    /// so any proof generated from it would be rejected on-chain.
    RootMismatch,
    Mpf(mpf::MpfError),
}

impl std::fmt::Display for TreasuryInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConstr => write!(f, "expected Constr"),
            Self::WrongConstructor(c) => write!(f, "unexpected constructor {c}"),
            Self::FieldCount { expected, got } => {
                write!(f, "expected {expected} field(s), got {got}")
            }
            Self::NotBytes(i) => write!(f, "field[{i}]: expected ByteArray"),
            Self::BadRootLen(n) => write!(f, "bifrost_identity_root must be 32 bytes, got {n}"),
            Self::RootMismatch => write!(f, "off-chain trie root != datum bifrost_identity_root"),
            Self::Mpf(e) => write!(f, "mpf: {e:?}"),
        }
    }
}

impl std::error::Error for TreasuryInfoError {}

impl From<plutus::PlutusError> for TreasuryInfoError {
    fn from(e: plutus::PlutusError) -> Self {
        match e {
            plutus::PlutusError::NotConstr => Self::NotConstr,
            plutus::PlutusError::WrongConstructor { got, .. } => Self::WrongConstructor(got),
            // Field-count is checked first, so MissingField is unreachable here.
            // NotInt is reachable now (federation_csv_blocks is field #3, an Int);
            // it and the byte-field errors collapse to NotBytes(i) — the index
            // still points at the offending field, which is what callers log.
            plutus::PlutusError::MissingField(i)
            | plutus::PlutusError::NotBytes(i)
            | plutus::PlutusError::NotInt(i)
            | plutus::PlutusError::NotBool(i)
            | plutus::PlutusError::NotList(i) => Self::NotBytes(i),
        }
    }
}

// Plutus encode/decode (constructor tags, canonical encoding) live in
// `crate::cardano::plutus`.

// ---------------------------------------------------------------------------
// TreasuryDatum
// ---------------------------------------------------------------------------

impl TreasuryInfoDatum {
    /// Encode as `Constr(0, [root, frost_key, y_federation, federation_csv_blocks])`.
    #[must_use]
    pub fn to_plutus_data(&self) -> PlutusData {
        constr(
            0,
            vec![
                bytes(&self.bifrost_identity_root),
                bytes(&self.current_spos_frost_key),
                bytes(&self.y_federation),
                int(self.federation_csv_blocks),
            ],
        )
    }

    /// CBOR bytes of the inline datum (for the continuing `treasury_info` output).
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        minicbor::to_vec(self.to_plutus_data()).expect("PlutusData CBOR encode")
    }

    pub fn from_plutus_data(data: &PlutusData) -> Result<Self, TreasuryInfoError> {
        let fields = plutus::constr_fields(data, 0)?;
        if fields.len() != 4 {
            return Err(TreasuryInfoError::FieldCount {
                expected: 4,
                got: fields.len(),
            });
        }
        let root_bytes = plutus::field_bytes(fields, 0)?;
        let bifrost_identity_root: mpf::Hash = root_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TreasuryInfoError::BadRootLen(root_bytes.len()))?;
        Ok(TreasuryInfoDatum {
            bifrost_identity_root,
            current_spos_frost_key: plutus::field_bytes(fields, 1)?,
            y_federation: plutus::field_bytes(fields, 2)?,
            federation_csv_blocks: plutus::field_int(fields, 3)?,
        })
    }
}

/// Encode the `TreasurySpendRedeemer::RegistryUpdate { new_bifrost_identity_root }`
/// (constructor 0) — the Register/Deregister path. `treasury.ak` preserves every
/// other datum field itself (record-update spread off the spent datum), so only
/// the new MPF root travels in the redeemer.
#[must_use]
pub fn registry_update_redeemer(new: &TreasuryInfoDatum) -> PlutusData {
    constr(0, vec![bytes(&new.bifrost_identity_root)])
}

/// Encode the `TreasurySpendRedeemer::UpdateY { new_spos_frost_key, epoch, signature }`
/// (constructor 1) — the DKG key-rotation path.
#[must_use]
pub fn update_y_redeemer(new_spos_frost_key: &[u8], epoch: i64, signature: &[u8]) -> PlutusData {
    constr(
        1,
        vec![bytes(new_spos_frost_key), int(epoch), bytes(signature)],
    )
}

/// The domain-separated message the OUTGOING roster signs (BIP340) to authorize
/// an Update-Y rotation. MUST match `treasury.ak`'s `update_y_sig_msg`
/// byte-for-byte:
///
/// ```text
/// sha2_256("bifrost-update-y" ++ spent_txid(32B) ++ spent_vout(4B LE)
///          ++ epoch(8B BE) ++ new_spos_frost_key(32B))
/// ```
///
/// `spent_txid` is the 32-byte Cardano tx id of the treasury state UTxO being
/// spent; `spent_vout` its output index.
#[must_use]
pub fn update_y_sig_msg(
    spent_txid: &[u8; 32],
    spent_vout: u32,
    epoch: u64,
    new_spos_frost_key: &[u8],
) -> [u8; 32] {
    use bitcoin::hashes::{Hash as _, sha256};
    let mut pre = Vec::with_capacity(16 + 32 + 4 + 8 + new_spos_frost_key.len());
    pre.extend_from_slice(b"bifrost-update-y");
    pre.extend_from_slice(spent_txid);
    pre.extend_from_slice(&spent_vout.to_le_bytes());
    pre.extend_from_slice(&epoch.to_be_bytes());
    pre.extend_from_slice(new_spos_frost_key);
    sha256::Hash::hash(&pre).to_byte_array()
}

// ---------------------------------------------------------------------------
// MPF proof → Plutus data (the on-chain `Proof = List<ProofStep>`)
// ---------------------------------------------------------------------------

/// Encode an MPF proof as the on-chain `Proof` (a `List<ProofStep>`), for the
/// `SposRegistry.Register` redeemer's `bifrost_identity_absence_proof`.
#[must_use]
pub fn proof_to_plutus_data(proof: &mpf::Proof) -> PlutusData {
    array(proof.iter().map(step_to_plutus_data).collect())
}

fn step_to_plutus_data(step: &mpf::ProofStep) -> PlutusData {
    match step {
        // Branch { skip, neighbors }
        mpf::ProofStep::Branch { skip, neighbors } => {
            constr(0, vec![int(*skip as i64), bytes(neighbors)])
        }
        // Fork { skip, neighbor }
        mpf::ProofStep::Fork { skip, neighbor } => constr(
            1,
            vec![int(*skip as i64), neighbor_to_plutus_data(neighbor)],
        ),
        // Leaf { skip, key, value }
        mpf::ProofStep::Leaf { skip, key, value } => {
            constr(2, vec![int(*skip as i64), bytes(key), bytes(value)])
        }
    }
}

fn neighbor_to_plutus_data(n: &mpf::Neighbor) -> PlutusData {
    // Neighbor { nibble, prefix, root }
    constr(
        0,
        vec![int(i64::from(n.nibble)), bytes(&n.prefix), bytes(&n.root)],
    )
}

// ---------------------------------------------------------------------------
// Registration transition
// ---------------------------------------------------------------------------

/// Compute the post-registration `treasury_info` datum and the
/// `bifrost_identity_absence_proof` for inserting `bifrost_id_pk → pool_id`.
///
/// `identity_trie` is the off-chain reconstruction of the current
/// `bifrost_identity_root` (built from the on-chain `spos_registry` linked
/// list, R1b). Only `bifrost_identity_root` changes; address / utxo_id /
/// frost_key are preserved (registration does not move the treasury or rekey).
///
/// On-chain, the registry's `Register` validator recomputes
/// `mpf.insert(old_root, bifrost_id_pk, pool_id, proof)` and requires the
/// treasury output datum to carry the result — so a mismatched off-chain trie
/// (caught here as `RootMismatch`) would otherwise produce a tx the validator
/// rejects.
pub fn apply_registration(
    current: &TreasuryInfoDatum,
    identity_trie: &mpf::Trie,
    bifrost_id_pk: &[u8],
    pool_id: &[u8],
) -> Result<(TreasuryInfoDatum, mpf::Proof), TreasuryInfoError> {
    if identity_trie.root_hash() != current.bifrost_identity_root {
        return Err(TreasuryInfoError::RootMismatch);
    }
    let absence_proof = identity_trie
        .prove_non_membership(bifrost_id_pk)
        .map_err(TreasuryInfoError::Mpf)?;
    let new_root =
        mpf::including(bifrost_id_pk, pool_id, &absence_proof).map_err(TreasuryInfoError::Mpf)?;
    // Only the identity root changes; the frost key and federation fields are
    // preserved (mirrors treasury.ak's RegistryUpdate / spos-registry.ak).
    let new_datum = TreasuryInfoDatum {
        bifrost_identity_root: new_root,
        ..current.clone()
    };
    Ok((new_datum, absence_proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_primitives::MaybeIndefArray;

    fn pairs(n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        (0..n)
            .map(|i| {
                (
                    format!("spo-{i}").into_bytes(),
                    format!("pool-{i}").into_bytes(),
                )
            })
            .collect()
    }

    fn sample_datum(root: mpf::Hash) -> TreasuryInfoDatum {
        TreasuryInfoDatum {
            bifrost_identity_root: root,
            current_spos_frost_key: vec![0xABu8; 32],
            y_federation: vec![0xCDu8; 32],
            federation_csv_blocks: 144,
        }
    }

    #[test]
    fn datum_cbor_roundtrip() {
        let d = sample_datum([7u8; 32]);
        let cbor = d.to_cbor();
        let decoded: PlutusData = minicbor::decode(&cbor).unwrap();
        let d2 = TreasuryInfoDatum::from_plutus_data(&decoded).unwrap();
        assert_eq!(d, d2);
    }

    // The datum must use the canonical plutus-core encoding (indefinite-length
    // constr fields) — the Rust uplc evaluator compares encodings, so a
    // definite-encoded datum fails `output_has_correct_datum` under simulation
    // even though a Haskell node would accept it.
    #[test]
    fn datum_cbor_is_canonical() {
        let cbor = sample_datum([7u8; 32]).to_cbor();
        let hex = hex::encode(&cbor);
        assert!(
            hex.starts_with("d8799f"),
            "non-empty Constr 0 → d879 9f…: {hex}"
        );
        assert!(hex.ends_with("ff"), "indefinite array terminator: {hex}");
    }

    #[test]
    fn datum_rejects_bad_shape() {
        // wrong constructor
        let wrong = constr(
            1,
            vec![bytes(&[0u8; 32]), bytes(b""), bytes(b""), bytes(b"")],
        );
        assert!(matches!(
            TreasuryInfoDatum::from_plutus_data(&wrong),
            Err(TreasuryInfoError::WrongConstructor(1))
        ));
        // root not 32 bytes
        let short = constr(
            0,
            vec![bytes(&[0u8; 8]), bytes(b""), bytes(b""), bytes(b"")],
        );
        assert!(matches!(
            TreasuryInfoDatum::from_plutus_data(&short),
            Err(TreasuryInfoError::BadRootLen(8))
        ));
    }

    // The R1c core: the new datum's root is exactly the MPF insert of the new
    // SPO, and the returned absence proof verifies against both the old and new
    // roots (the on-chain registry validator does exactly this check).
    #[test]
    fn apply_registration_updates_root_and_yields_valid_proof() {
        let trie = mpf::Trie::from_pairs(pairs(30)).unwrap();
        let current = sample_datum(trie.root_hash());

        let pk = b"new-bifrost-id-pk";
        let pool = b"new-pool-id";
        let (new_datum, proof) = apply_registration(&current, &trie, pk, pool).unwrap();

        // absence proof rebuilds the OLD root; inserting (pk -> pool) gives the NEW root.
        assert_eq!(
            mpf::excluding(pk, &proof).unwrap(),
            current.bifrost_identity_root
        );
        assert_eq!(
            mpf::including(pk, pool, &proof).unwrap(),
            new_datum.bifrost_identity_root
        );
        // only the root changed.
        assert_ne!(
            new_datum.bifrost_identity_root,
            current.bifrost_identity_root
        );
        assert_eq!(
            new_datum.current_spos_frost_key,
            current.current_spos_frost_key
        );
        assert_eq!(new_datum.y_federation, current.y_federation);
        assert_eq!(
            new_datum.federation_csv_blocks,
            current.federation_csv_blocks
        );
    }

    #[test]
    fn apply_registration_rejects_stale_trie_and_present_key() {
        let trie = mpf::Trie::from_pairs(pairs(10)).unwrap();
        // datum root disagrees with the trie → RootMismatch.
        let stale = sample_datum([9u8; 32]);
        assert!(matches!(
            apply_registration(&stale, &trie, b"x", b"y"),
            Err(TreasuryInfoError::RootMismatch)
        ));
        // key already registered → KeyPresent surfaced as Mpf error.
        let current = sample_datum(trie.root_hash());
        assert!(matches!(
            apply_registration(&current, &trie, b"spo-0", b"pool-0"),
            Err(TreasuryInfoError::Mpf(mpf::MpfError::KeyPresent))
        ));
    }

    // The encoded proof is a CBOR-roundtrippable List<ProofStep> of the right length.
    #[test]
    fn proof_encodes_to_plutus_list() {
        let trie = mpf::Trie::from_pairs(pairs(30)).unwrap();
        let proof = trie.prove_non_membership(b"absent-key").unwrap();
        let pd = proof_to_plutus_data(&proof);

        match &pd {
            // Canonical: a non-empty list encodes indefinite-length.
            PlutusData::Array(MaybeIndefArray::Indef(steps)) => {
                assert_eq!(steps.len(), proof.len());
            }
            other => panic!("expected indefinite Array, got {other:?}"),
        }
        // CBOR-encodes and decodes without error.
        let cbor = minicbor::to_vec(&pd).unwrap();
        let _back: PlutusData = minicbor::decode(&cbor).unwrap();

        // The spend redeemer also encodes.
        let current = sample_datum(trie.root_hash());
        let (new_datum, _) = apply_registration(&current, &trie, b"absent-key", b"pool").unwrap();
        let redeemer = registry_update_redeemer(&new_datum);
        let _cbor = minicbor::to_vec(redeemer).unwrap();
    }

    // RegistryUpdate is Constr(0, [new_root]) — a single field now that
    // treasury.ak preserves every other datum field itself.
    #[test]
    fn registry_update_redeemer_is_single_field_constr0() {
        let d = sample_datum([3u8; 32]);
        let PlutusData::Constr(c) = registry_update_redeemer(&d) else {
            panic!("expected Constr");
        };
        assert_eq!(c.tag, 121); // Constr 0
        let fields: Vec<_> = c.fields.to_vec();
        assert_eq!(fields.len(), 1);
        assert!(matches!(&fields[0], PlutusData::BoundedBytes(b) if **b == [3u8; 32]));
    }

    // UpdateY is Constr(1, [new_key, epoch, signature]).
    #[test]
    fn update_y_redeemer_is_constr1_three_fields() {
        let PlutusData::Constr(c) = update_y_redeemer(&[0xAB; 32], 7, &[0xCD; 64]) else {
            panic!("expected Constr");
        };
        assert_eq!(c.tag, 122); // Constr 1
        let fields: Vec<_> = c.fields.to_vec();
        assert_eq!(fields.len(), 3);
        assert!(matches!(&fields[0], PlutusData::BoundedBytes(b) if **b == [0xAB; 32]));
        assert!(matches!(&fields[1], PlutusData::BigInt(_)));
        assert!(matches!(&fields[2], PlutusData::BoundedBytes(b) if **b == [0xCD; 64]));
    }

    // The signed message MUST match treasury.ak byte-for-byte. This vector is the
    // one the Aiken `spend_update_y_happy` test verifies a real BIP340 signature
    // against (txid = 0x22*32, vout = 0, epoch = 7, new_key = 0xAB*32), so this
    // single assertion locks the two implementations together.
    #[test]
    fn update_y_sig_msg_matches_onchain_vector() {
        let msg = update_y_sig_msg(&[0x22u8; 32], 0, 7, &[0xABu8; 32]);
        assert_eq!(
            hex::encode(msg),
            "e347507502df93a1056a7c889b943d24ff614d78bdb54e3f6275c6b2ea268492"
        );
    }
}
