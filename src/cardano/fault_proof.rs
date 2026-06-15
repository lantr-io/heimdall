//! FaultProof datum + redeemer encoders (`fault_verifier.ak`, WI-018 part 3).
//!
//! `fault_verifier.ak` mints a singleton FaultProof token named
//! `blake2b_256(accused_pool_id || evidence_hash)` ([`super::ban_list::fault_token_name`])
//! and parks it in a verifier UTxO carrying an inline [`FaultProofDatum`]. The
//! ApplyBan tx (part 4 / WI-017) recomputes that name, spends the verifier UTxO,
//! and burns the token to insert/update the ban node.
//!
//! These are the byte-exact encoders the mint/ApplyBan tx builders sit on top of.
//! The on-chain shapes (from `lib/bifrost/types/fault-verifier.ak`):
//!
//! ```text
//! FaultKind            = InvalidPayload  -- Constr(0, [])
//!                      | Equivocation    -- Constr(1, [])
//! FaultProofDatum      = Constr(0, [ kind, accused_pool_id, namespace_hash, evidence_hash ])
//! FaultProofMintRedeemer
//!   = PublishProof Constr(0, [ input_ref, accused_pool_id, fault ])
//!   | BurnProof    Constr(1, [])
//! ```
//!
//! NOTE: `input_ref` is a `cardano/transaction.OutputReference`, encoded here as
//! the modern flat `Constr(0, [ bytes(tx_id), int(output_index) ])`. The exact
//! shape is blueprint-pinned — verify against the compiled `fault_verifier`
//! redeemer schema before submitting (same care the registry redeemer indices
//! get in `register_spo.rs`).

use pallas_primitives::PlutusData;

use crate::cardano::plutus::{self, bytes, constr, int_from_u64};

/// `FaultKind` — the on-chain fault category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// A cryptographically-invalid DKG payload (proved by a ZK fault circuit).
    InvalidPayload,
    /// Two distinct signed payloads for the same namespace.
    Equivocation,
}

impl FaultKind {
    /// `Constr(0,[])` / `Constr(1,[])`.
    #[must_use]
    pub fn to_plutus_data(self) -> PlutusData {
        let tag = match self {
            FaultKind::InvalidPayload => 0,
            FaultKind::Equivocation => 1,
        };
        constr(tag, vec![])
    }

    fn from_ctor(ctor: u64) -> Option<Self> {
        match ctor {
            0 => Some(FaultKind::InvalidPayload),
            1 => Some(FaultKind::Equivocation),
            _ => None,
        }
    }
}

/// The inline datum a FaultProof verifier UTxO carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultProofDatum {
    pub kind: FaultKind,
    /// 28-byte `blake2b_224(cold_vkey)` of the accused SPO.
    pub accused_pool_id: Vec<u8>,
    /// `blake2b_256` of the protocol namespace the fault occurred in.
    pub namespace_hash: Vec<u8>,
    /// The fault evidence commitment: the ZK circuit public input
    /// (`InvalidPayload`) or a hash of the two conflicting messages
    /// (`Equivocation`). 32 bytes. Bound into the token name.
    pub evidence_hash: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FaultProofError {
    NotConstr,
    WrongConstructor(u64),
    FieldCount { expected: usize, got: usize },
    BadKind(u64),
    BadField(plutus::PlutusError),
}

impl std::fmt::Display for FaultProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConstr => write!(f, "expected Constr"),
            Self::WrongConstructor(c) => write!(f, "unexpected constructor {c}"),
            Self::FieldCount { expected, got } => {
                write!(f, "expected {expected} fields, got {got}")
            }
            Self::BadKind(c) => write!(f, "unknown FaultKind constructor {c}"),
            Self::BadField(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FaultProofError {}

impl From<plutus::PlutusError> for FaultProofError {
    fn from(e: plutus::PlutusError) -> Self {
        Self::BadField(e)
    }
}

impl FaultProofDatum {
    /// `Constr(0, [kind, accused_pool_id, namespace_hash, evidence_hash])`.
    #[must_use]
    pub fn to_plutus_data(&self) -> PlutusData {
        constr(
            0,
            vec![
                self.kind.to_plutus_data(),
                bytes(&self.accused_pool_id),
                bytes(&self.namespace_hash),
                bytes(&self.evidence_hash),
            ],
        )
    }

    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        pallas_codec::minicbor::to_vec(self.to_plutus_data()).expect("PlutusData CBOR encode")
    }

    pub fn from_plutus_data(pd: &PlutusData) -> Result<Self, FaultProofError> {
        let fields = plutus::constr_fields(pd, 0).map_err(|e| match e {
            plutus::PlutusError::NotConstr => FaultProofError::NotConstr,
            plutus::PlutusError::WrongConstructor { got, .. } => {
                FaultProofError::WrongConstructor(got)
            }
            other => FaultProofError::BadField(other),
        })?;
        if fields.len() != 4 {
            return Err(FaultProofError::FieldCount {
                expected: 4,
                got: fields.len(),
            });
        }
        let (kind_ctor, kind_fields) = plutus::as_constr(&fields[0])?;
        if !kind_fields.is_empty() {
            return Err(FaultProofError::BadKind(kind_ctor));
        }
        let kind = FaultKind::from_ctor(kind_ctor).ok_or(FaultProofError::BadKind(kind_ctor))?;
        Ok(FaultProofDatum {
            kind,
            accused_pool_id: plutus::field_bytes(fields, 1)?,
            namespace_hash: plutus::field_bytes(fields, 2)?,
            evidence_hash: plutus::field_bytes(fields, 3)?,
        })
    }
}

/// `cardano/transaction.OutputReference` → `Constr(0, [bytes(tx_id), int(output_index)])`.
#[must_use]
pub fn output_reference(tx_id: &[u8], output_index: u32) -> PlutusData {
    constr(0, vec![bytes(tx_id), int_from_u64(u64::from(output_index))])
}

/// `PublishProof { input_ref, accused_pool_id, fault }` = `Constr(0, [...])`.
#[must_use]
pub fn publish_proof_redeemer(
    input_ref_tx_id: &[u8],
    input_ref_index: u32,
    accused_pool_id: &[u8],
    fault: &FaultProofDatum,
) -> PlutusData {
    constr(
        0,
        vec![
            output_reference(input_ref_tx_id, input_ref_index),
            bytes(accused_pool_id),
            fault.to_plutus_data(),
        ],
    )
}

/// `BurnProof` = `Constr(1, [])`.
#[must_use]
pub fn burn_proof_redeemer() -> PlutusData {
    constr(1, vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_codec::minicbor;

    fn datum() -> FaultProofDatum {
        FaultProofDatum {
            kind: FaultKind::InvalidPayload,
            accused_pool_id: vec![0x11; 28],
            namespace_hash: vec![0x22; 32],
            evidence_hash: vec![0x33; 32],
        }
    }

    #[test]
    fn datum_cbor_roundtrips() {
        for kind in [FaultKind::InvalidPayload, FaultKind::Equivocation] {
            let d = FaultProofDatum { kind, ..datum() };
            let cbor = d.to_cbor();
            let pd: PlutusData = minicbor::decode(&cbor).unwrap();
            assert_eq!(FaultProofDatum::from_plutus_data(&pd).unwrap(), d);
        }
    }

    #[test]
    fn kind_constructors() {
        // InvalidPayload=Constr(0,[]), Equivocation=Constr(1,[]).
        let invalid = FaultKind::InvalidPayload.to_plutus_data();
        let (c0, f0) = plutus::as_constr(&invalid).unwrap();
        assert_eq!((c0, f0.len()), (0, 0));
        let equiv = FaultKind::Equivocation.to_plutus_data();
        let (c1, f1) = plutus::as_constr(&equiv).unwrap();
        assert_eq!((c1, f1.len()), (1, 0));
    }

    #[test]
    fn publish_redeemer_shape() {
        let d = datum();
        let r = publish_proof_redeemer(&[0xAB; 32], 3, &d.accused_pool_id, &d);
        let fields = plutus::constr_fields(&r, 0).unwrap();
        assert_eq!(fields.len(), 3);
        // field 0 = OutputReference Constr(0, [tx_id(32B), index]).
        let (oref_c, oref_f) = plutus::as_constr(&fields[0]).unwrap();
        assert_eq!(oref_c, 0);
        assert_eq!(plutus::field_bytes(oref_f, 0).unwrap(), vec![0xAB; 32]);
        assert_eq!(plutus::field_int(oref_f, 1).unwrap(), 3);
        // field 1 = accused_pool_id, field 2 = the fault datum.
        assert_eq!(plutus::field_bytes(fields, 1).unwrap(), d.accused_pool_id);
        assert_eq!(FaultProofDatum::from_plutus_data(&fields[2]).unwrap(), d);
    }

    #[test]
    fn burn_redeemer_is_constr1_empty() {
        let burn = burn_proof_redeemer();
        let (c, f) = plutus::as_constr(&burn).unwrap();
        assert_eq!((c, f.len()), (1, 0));
    }

    #[test]
    fn datum_rejects_unknown_kind() {
        // Constr(0, [Constr(2,[]), ...]) — FaultKind only has 0/1.
        let bad = constr(
            0,
            vec![constr(2, vec![]), bytes(&[0x11; 28]), bytes(&[0x22; 32]), bytes(&[0x33; 32])],
        );
        assert!(matches!(
            FaultProofDatum::from_plutus_data(&bad),
            Err(FaultProofError::BadKind(2))
        ));
    }
}
