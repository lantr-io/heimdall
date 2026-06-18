//! FaultProof datum + redeemer encoders and mint tx builder (`fault_verifier.ak`,
//! WI-018 parts 3 + 3b).
//!
//! `fault_verifier.ak` mints a singleton FaultProof token named
//! `blake2b_256(accused_pool_id || evidence_hash)` ([`super::ban_list::fault_token_name`])
//! and parks it in a UTxO carrying an inline [`FaultProofDatum`]. The ApplyBan tx
//! (part 4 / WI-017) takes that UTxO as a regular input, recomputes the name, and
//! burns the token (the `BurnProof` mint leg) to insert/update the ban node.
//!
//! [`build_fault_proof_mint_tx`] builds the `PublishProof` mint tx. The on-chain
//! shapes (from `lib/bifrost/types/fault-verifier.ak`, confirmed against the
//! compiled blueprint redeemer/datum schema):
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
//! `input_ref` is a `cardano/transaction.OutputReference`, the modern flat
//! `Constr(0, [ bytes(tx_id), int(output_index) ])` — verified against the
//! blueprint's `cardano/transaction/OutputReference` definition. The validator
//! only requires `input_ref` to be a *spent input of this tx* (`find_input`), so
//! it is an anti-replay nonce, not an index — the fee input fills the role.
//!
//! PARKING ADDRESS: the FaultProof UTxO is parked at the operator's own (pubkey)
//! address, NOT the fault_verifier script address. `fault_verifier.ak` handles
//! only `mint`; every other script purpose falls through to `else -> False`, so a
//! UTxO at its address can never be spent — and ApplyBan must *spend* the proof
//! UTxO to burn the token. `PublishProof` does not constrain the output address
//! (only that exactly one output carries the token with `InlineDatum(fault)`), so
//! a wallet-locked, spendable output satisfies it.
//!
//! NOTE: `fault-verifier.ak:42` still TODOs the ZK evidence verification, so the
//! validator is currently PERMISSIVE — a well-formed `PublishProof` mints without
//! proving the evidence. The mint ex-units budget below reflects the light path;
//! the real verify (an upstream gap) will dominate the budget once it lands.

use pallas_codec::minicbor;
use pallas_primitives::PlutusData;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::ban_list::fault_token_name;
use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::plutus::{self, bytes, constr, int_from_u64};
use crate::cardano::publish::WalletUtxo;
use crate::cardano::tx_common::{sign_built_tx as common_sign_built_tx, whisky_network};
use crate::cardano::wallet::pub_key_hash_hex;

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

/// `EquivocationProof { input_ref, registration_ref_input_index, bifrost_id_pk,
/// fault, payload_a, signature_a, payload_b, signature_b }` = `Constr(2, [...])`.
/// The `fault_verifier` EquivocationProof branch (technical_documentation §9.2)
/// verifies the two BIP-340 signatures, that `fault.evidence_hash` commits to the
/// two payloads, and that `bifrost_id_pk` is the key registered for
/// `accused_pool_id` in the `spos_registry` node at
/// `registration_ref_input_index` in `reference_inputs`. Field order MUST match
/// `bifrost/types/fault_verifier`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn equivocation_proof_redeemer(
    input_ref_tx_id: &[u8],
    input_ref_index: u32,
    registration_ref_input_index: u32,
    bifrost_id_pk: &[u8],
    fault: &FaultProofDatum,
    payload_a: &[u8],
    signature_a: &[u8],
    payload_b: &[u8],
    signature_b: &[u8],
) -> PlutusData {
    constr(
        2,
        vec![
            output_reference(input_ref_tx_id, input_ref_index),
            int_from_u64(u64::from(registration_ref_input_index)),
            bytes(bifrost_id_pk),
            fault.to_plutus_data(),
            bytes(payload_a),
            bytes(signature_a),
            bytes(payload_b),
            bytes(signature_b),
        ],
    )
}

// ---------------------------------------------------------------------------
// FaultProof mint tx builder (fault_verifier.PublishProof) — WI-018 part 3b
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FaultProofMintError {
    /// `fault.accused_pool_id` is not 28 bytes — `is_pool_id` would reject it.
    BadAccusedPoolId(usize),
    /// `fault.evidence_hash` is not 32 bytes — `is_evidence_hash` would reject it.
    BadEvidenceHash(usize),
    /// `fault.kind == Equivocation` but no `equivocation` witness was supplied.
    MissingEquivocationWitness,
    /// An `equivocation` witness was supplied for a non-`Equivocation` fault.
    UnexpectedEquivocationWitness,
    /// No suitable wallet UTxO for fees / collateral.
    Wallet(String),
    /// whisky tx build / CBOR (de)code failed.
    Build(String),
}

impl std::fmt::Display for FaultProofMintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadAccusedPoolId(n) => {
                write!(f, "accused_pool_id must be 28 bytes, got {n}")
            }
            Self::BadEvidenceHash(n) => write!(f, "evidence_hash must be 32 bytes, got {n}"),
            Self::MissingEquivocationWitness => {
                write!(f, "Equivocation fault requires an equivocation witness")
            }
            Self::UnexpectedEquivocationWitness => {
                write!(
                    f,
                    "equivocation witness supplied for a non-Equivocation fault"
                )
            }
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "tx build: {e}"),
        }
    }
}

impl std::error::Error for FaultProofMintError {}

/// The on-chain `EquivocationProof` witness: the accused's x-only bifrost key
/// and the two conflicting BIP-340-signed canonical payloads. Supplied when
/// minting an `Equivocation` FaultProof so `fault_verifier` can verify the
/// double-signature. Mirror of `circuits::fault_evidence::EquivocationEvidence`.
pub struct EquivocationWitness<'a> {
    pub bifrost_id_pk: &'a [u8],
    pub payload_a: &'a [u8],
    pub signature_a: &'a [u8],
    pub payload_b: &'a [u8],
    pub signature_b: &'a [u8],
    /// `(tx_hash, output_index)` of the accused's `spos_registry` node UTxO —
    /// added as a read-only reference input so the validator can read the
    /// registered `bifrost_id_pk` and bind it to `accused_pool_id`.
    pub registration_ref: (&'a str, u32),
}

/// Everything [`build_fault_proof_mint_tx`] needs. UTxOs are caller-fetched so
/// the builder stays pure/testable; `wallet_utxos` pays the fee (and supplies
/// the anti-replay nonce input) plus collateral.
pub struct FaultProofMintRequest<'a> {
    /// The `fault_verifier` minting policy (cbor + hash), parameterized by the
    /// `spos_registry` policy id via
    /// [`crate::cardano::blueprint::fault_verifier_script`].
    pub fault_verifier_script: &'a ParameterizedScript,
    /// The fully-formed datum to park on-chain. Its `accused_pool_id` (28B) and
    /// `evidence_hash` (32B) determine the minted token name; `namespace_hash`
    /// is descriptive metadata neither validator reads.
    pub fault: &'a FaultProofDatum,
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    /// Wallet payment key — pays fees/collateral and signs the body.
    pub key: &'a PrivateKey,
    /// Live `[V1, V2, V3]` cost models; `None` → whisky's built-in Preprod.
    pub cost_models: Option<Vec<Vec<i64>>>,
    /// The equivocation witness — must be `Some` iff `fault.kind ==
    /// Equivocation`. Selects the `EquivocationProof` redeemer over `PublishProof`.
    pub equivocation: Option<EquivocationWitness<'a>>,
}

/// A built (signed, unsubmitted) FaultProof mint tx plus what the operator
/// needs to record to later build ApplyBan.
#[derive(Debug, Clone)]
pub struct FaultProofMintTx {
    pub signed_tx_hex: String,
    /// `fault_verifier` policy id (hex) the token is minted under.
    pub policy_id_hex: String,
    /// `blake2b_256(accused_pool_id || evidence_hash)` — the minted token name.
    pub token_name: [u8; 32],
    /// Where the FaultProof UTxO is parked (the wallet address — it must be
    /// spendable so ApplyBan can consume + burn it; see module docs).
    pub proof_address: String,
    /// min-ADA locked with the token at `proof_address`.
    pub lovelace: u64,
    /// `(tx_hash, index)` of the spent input the redeemer commits to as the
    /// anti-replay nonce (`input_ref`).
    pub input_ref: (String, u32),
}

/// Min-UTxO for the parked FaultProof output (same conservative datum-scaled
/// formula as the registry/treasury element outputs).
fn proof_lovelace(datum_cbor_len: usize) -> u64 {
    std::cmp::max(2_000_000u64, (datum_cbor_len as u64 + 600) * 4310)
}

/// Decode `tx_hash` hex into the 32-byte transaction id.
fn tx_id_bytes(tx_hash: &str) -> Result<[u8; 32], FaultProofMintError> {
    hex::decode(tx_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| FaultProofMintError::Build(format!("bad tx hash: {tx_hash}")))
}

/// Pick the fee input (richest clean wallet UTxO — it doubles as the
/// `input_ref` nonce) and a DISTINCT pure-ADA collateral. Both skip
/// token-bearing / ref-script UTxOs (`pure_ada`). Collateral must differ from
/// the fee input: a UTxO cannot be both a spent input and a collateral input.
fn select_fee_and_collateral(
    wallet_utxos: &[WalletUtxo],
    min_fee_lovelace: u64,
) -> Result<(&WalletUtxo, &WalletUtxo), FaultProofMintError> {
    let fee_utxo = wallet_utxos
        .iter()
        .filter(|u| u.pure_ada)
        .max_by_key(|u| u.lovelace)
        .ok_or_else(|| FaultProofMintError::Wallet("no clean wallet UTxOs for fees".into()))?;
    if fee_utxo.lovelace < min_fee_lovelace {
        return Err(FaultProofMintError::Wallet(format!(
            "largest wallet UTxO ({} lovelace) cannot cover the parked output plus fees \
             (needs >= {min_fee_lovelace}) — fund the wallet or consolidate UTxOs",
            fee_utxo.lovelace
        )));
    }
    let coll_utxo = wallet_utxos
        .iter()
        .find(|u| {
            u.lovelace >= 5_000_000
                && u.pure_ada
                && !(u.tx_hash == fee_utxo.tx_hash && u.output_index == fee_utxo.output_index)
        })
        .ok_or_else(|| {
            FaultProofMintError::Wallet(
                "no pure-ADA wallet UTxO with >= 5 ADA for collateral, distinct from the fee input"
                    .into(),
            )
        })?;
    Ok((fee_utxo, coll_utxo))
}

/// Sign the whisky-built tx body with the wallet key and splice the vkey
/// witness in (same flow as register_spo / treasury_bootstrap).
fn sign_built_tx(unsigned_hex: &str, key: &PrivateKey) -> Result<String, FaultProofMintError> {
    common_sign_built_tx(unsigned_hex, key).map_err(FaultProofMintError::Build)
}

/// Build + sign the `fault_verifier.PublishProof` mint tx: mint exactly one
/// FaultProof token `blake2b_256(accused_pool_id || evidence_hash)` and park it
/// at the wallet address with the inline [`FaultProofDatum`]. The fee input
/// doubles as the `input_ref` nonce the validator requires to be spent.
pub fn build_fault_proof_mint_tx(
    req: &FaultProofMintRequest,
) -> Result<FaultProofMintTx, FaultProofMintError> {
    // Fail fast on what fault_verifier.PublishProof would reject. (`fault.
    // accused_pool_id == accused_pool_id` is guaranteed: the redeemer reuses the
    // datum's bytes for both, so it always holds.)
    if req.fault.accused_pool_id.len() != 28 {
        return Err(FaultProofMintError::BadAccusedPoolId(
            req.fault.accused_pool_id.len(),
        ));
    }
    if req.fault.evidence_hash.len() != 32 {
        return Err(FaultProofMintError::BadEvidenceHash(
            req.fault.evidence_hash.len(),
        ));
    }

    let policy_id_hex = req.fault_verifier_script.hash_hex();
    let token_name = fault_token_name(&req.fault.accused_pool_id, &req.fault.evidence_hash);

    // Parked at the operator's own address: it must be SPENDABLE so the later
    // ApplyBan tx can take it as `fault_input` and burn it (the fault_verifier
    // address would lock it — see module docs).
    let proof_address = req.wallet_address.to_string();
    let datum_cbor = req.fault.to_cbor();
    let lovelace = proof_lovelace(datum_cbor.len());

    let (fee_utxo, coll_utxo) = select_fee_and_collateral(req.wallet_utxos, lovelace + 1_000_000)?;
    // `input_ref` is matched by value (`find_input`), not by position, so no
    // input-index pinning is needed — just commit to the fee input's outpoint.
    let nonce_tx_id = tx_id_bytes(&fee_utxo.tx_hash)?;
    // InvalidPayload → PublishProof (the permissive mock); Equivocation →
    // EquivocationProof (the real §9.2 double-signature check), which needs the
    // two signed payloads.
    let (redeemer, reference_inputs) = match (req.fault.kind, &req.equivocation) {
        (FaultKind::InvalidPayload, None) => (
            publish_proof_redeemer(
                &nonce_tx_id,
                fee_utxo.output_index,
                &req.fault.accused_pool_id,
                req.fault,
            ),
            Vec::new(),
        ),
        (FaultKind::Equivocation, Some(w)) => {
            // The accused's registration node is the sole reference input, so its
            // index is 0 (no other ref inputs; the fault_verifier script is
            // provided inline, not as a ref script).
            let registration_ref_input_index = 0;
            let redeemer = equivocation_proof_redeemer(
                &nonce_tx_id,
                fee_utxo.output_index,
                registration_ref_input_index,
                w.bifrost_id_pk,
                req.fault,
                w.payload_a,
                w.signature_a,
                w.payload_b,
                w.signature_b,
            );
            let refs = vec![RefTxIn {
                tx_hash: w.registration_ref.0.to_string(),
                tx_index: w.registration_ref.1,
                script_size: None,
            }];
            (redeemer, refs)
        }
        (FaultKind::Equivocation, None) => {
            return Err(FaultProofMintError::MissingEquivocationWitness);
        }
        (FaultKind::InvalidPayload, Some(_)) => {
            return Err(FaultProofMintError::UnexpectedEquivocationWitness);
        }
    };
    let redeemer_hex = hex::encode(minicbor::to_vec(&redeemer).expect("redeemer CBOR encode"));

    let token_unit = format!("{policy_id_hex}{}", hex::encode(token_name));
    let proof_out = Output {
        address: proof_address.clone(),
        amount: vec![
            Asset::new_from_str("lovelace", &lovelace.to_string()),
            Asset::new_from_str(&token_unit, "1"),
        ],
        datum: Some(Datum::Inline(hex::encode(datum_cbor))),
        reference_script: None,
    };

    let body = TxBuilderBody {
        inputs: vec![TxIn::PubKeyTxIn(PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: fee_utxo.tx_hash.clone(),
                tx_index: fee_utxo.output_index,
                amount: Some(vec![Asset::new_from_str(
                    "lovelace",
                    &fee_utxo.lovelace.to_string(),
                )]),
                address: Some(req.wallet_address.to_string()),
            },
        })],
        outputs: vec![proof_out],
        collaterals: vec![PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: coll_utxo.tx_hash.clone(),
                tx_index: coll_utxo.output_index,
                amount: Some(vec![Asset::new_from_str(
                    "lovelace",
                    &coll_utxo.lovelace.to_string(),
                )]),
                address: Some(req.wallet_address.to_string()),
            },
        }],
        required_signatures: vec![pub_key_hash_hex(req.key)],
        change_address: req.wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(&req.cost_models)),
        reference_inputs,
        withdrawals: vec![],
        mints: vec![MintItem::ScriptMint(ScriptMint {
            mint: MintParameter {
                policy_id: policy_id_hex.clone(),
                asset_name: hex::encode(token_name),
                amount: 1,
            },
            redeemer: Some(Redeemer {
                data: redeemer_hex,
                // PublishProof is currently the light path (find_input, an
                // output filter, length checks, one blake2b_256); the ZK verify
                // it TODOs will dominate this once implemented upstream.
                ex_units: Budget {
                    mem: 2_000_000,
                    steps: 900_000_000,
                },
            }),
            script_source: Some(ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
                script_cbor: req.fault_verifier_script.cbor_hex(),
                language_version: LanguageVersion::V3,
            })),
        })],
        certificates: vec![],
        votes: vec![],
        fee: None,
        change_datum: None,
        metadata: vec![],
        validity_range: ValidityRange {
            invalid_before: None,
            invalid_hereafter: None,
        },
        total_collateral: None,
        collateral_return_address: None,
    };

    let mut pallas = WhiskyPallas::new(None);
    pallas.tx_builder_body = body;
    let unsigned_hex = pallas
        .serialize_tx_body()
        .map_err(|e| FaultProofMintError::Build(format!("whisky tx build: {e:?}")))?;
    let signed_tx_hex = sign_built_tx(&unsigned_hex, req.key)?;

    Ok(FaultProofMintTx {
        signed_tx_hex,
        policy_id_hex,
        token_name,
        proof_address,
        lovelace,
        input_ref: (fee_utxo.tx_hash.clone(), fee_utxo.output_index),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::blueprint;
    use crate::cardano::wallet::{derive_payment_key, wallet_address};
    use pallas_codec::minicbor;
    use pallas_primitives::conway::{DatumOption, PseudoTransactionOutput, Tx, Value};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
            vec![
                constr(2, vec![]),
                bytes(&[0x11; 28]),
                bytes(&[0x22; 32]),
                bytes(&[0x33; 32]),
            ],
        );
        assert!(matches!(
            FaultProofDatum::from_plutus_data(&bad),
            Err(FaultProofError::BadKind(2))
        ));
    }

    // ---- FaultProof mint tx builder ----------------------------------------

    fn fault_verifier_script() -> ParameterizedScript {
        // Parameterized by a dummy spos_registry hash. The registry binding is
        // verified on-chain (aiken), not by this tx builder, so any 28-byte
        // value gives a representative policy id.
        let code = include_str!("../../tests/fixtures/fault_verifier_code.txt");
        blueprint::apply_params(code.trim(), &[bytes(&[0x11u8; 28])]).unwrap()
    }

    /// Two pure-ADA UTxOs: the richer (`aa…:0`) funds fees + the nonce, the
    /// other (`bb…:1`) is the distinct collateral.
    fn wallet_utxos() -> Vec<WalletUtxo> {
        vec![
            WalletUtxo {
                tx_hash: "aa".repeat(32),
                output_index: 0,
                lovelace: 50_000_000,
                pure_ada: true,
            },
            WalletUtxo {
                tx_hash: "bb".repeat(32),
                output_index: 1,
                lovelace: 6_000_000,
                pure_ada: true,
            },
        ]
    }

    fn build_with(
        fault: &FaultProofDatum,
        utxos: &[WalletUtxo],
    ) -> Result<FaultProofMintTx, FaultProofMintError> {
        let script = fault_verifier_script();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        build_fault_proof_mint_tx(&FaultProofMintRequest {
            fault_verifier_script: &script,
            fault,
            wallet_address: &addr,
            wallet_utxos: utxos,
            key: &key,
            cost_models: None,
            equivocation: None,
        })
    }

    /// Synthetic equivocation witness (the builder does not verify signatures,
    /// so opaque bytes suffice here — the real signing is tested in
    /// `circuits::fault_evidence`).
    #[allow(clippy::type_complexity)]
    fn equiv_witness() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            vec![0x02; 32], // bifrost_id_pk
            b"bifrost-dkg-r1-payload-a".to_vec(),
            vec![0xAA; 64], // signature_a
            b"bifrost-dkg-r1-payload-b".to_vec(),
            vec![0xBB; 64], // signature_b
        )
    }

    fn build_equivocation(
        fault: &FaultProofDatum,
        w: &EquivocationWitness,
    ) -> Result<FaultProofMintTx, FaultProofMintError> {
        let script = fault_verifier_script();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        build_fault_proof_mint_tx(&FaultProofMintRequest {
            fault_verifier_script: &script,
            fault,
            wallet_address: &addr,
            wallet_utxos: &wallet_utxos(),
            key: &key,
            cost_models: None,
            equivocation: Some(EquivocationWitness {
                bifrost_id_pk: w.bifrost_id_pk,
                payload_a: w.payload_a,
                signature_a: w.signature_a,
                payload_b: w.payload_b,
                signature_b: w.signature_b,
                registration_ref: w.registration_ref,
            }),
        })
    }

    /// Whether a post-alonzo output carries `policy.name` (any quantity).
    fn output_has_token(
        out: &pallas_primitives::conway::PostAlonzoTransactionOutput,
        policy: &[u8; 28],
        name: &[u8; 32],
    ) -> bool {
        match &out.value {
            // whisky encodes pure-ADA change as Multiasset(coin, <empty map>);
            // either coin shape carries no tokens.
            Value::Coin(_) => false,
            Value::Multiasset(_, ma) => ma.iter().any(|(p, assets)| {
                p.as_slice() == policy && assets.iter().any(|(n, _q)| n.as_slice() == name)
            }),
        }
    }

    fn output_coin(out: &pallas_primitives::conway::PostAlonzoTransactionOutput) -> u64 {
        match &out.value {
            Value::Coin(c) | Value::Multiasset(c, _) => *c,
        }
    }

    /// The single token-bearing output: its lovelace + decoded inline datum.
    fn decode_proof_output(tx: &Tx, policy: &[u8; 28], name: &[u8; 32]) -> (u64, FaultProofDatum) {
        let token_outs: Vec<_> = tx
            .transaction_body
            .outputs
            .iter()
            .filter_map(|o| match o {
                PseudoTransactionOutput::PostAlonzo(o) if output_has_token(o, policy, name) => {
                    Some(o)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            token_outs.len(),
            1,
            "exactly one output must carry the token"
        );
        let out = token_outs[0];
        let Some(DatumOption::Data(wrapped)) = &out.datum_option else {
            panic!("expected inline datum on the proof output");
        };
        let d = FaultProofDatum::from_plutus_data(&wrapped.0).unwrap();
        (output_coin(out), d)
    }

    fn mint_redeemer(tx: &Tx) -> PlutusData {
        use pallas_primitives::conway::{RedeemerTag, Redeemers};
        let redeemers = tx.transaction_witness_set.redeemer.as_ref().unwrap();
        match redeemers {
            Redeemers::List(rs) => rs
                .iter()
                .find(|r| matches!(r.tag, RedeemerTag::Mint))
                .expect("mint redeemer present")
                .data
                .clone(),
            Redeemers::Map(kv) => kv
                .iter()
                .find(|(k, _)| matches!(k.tag, RedeemerTag::Mint))
                .expect("mint redeemer present")
                .1
                .data
                .clone(),
        }
    }

    #[test]
    fn build_fault_proof_mint_end_to_end() {
        let script = fault_verifier_script();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        let fault = datum();
        let built = build_with(&fault, &wallet_utxos()).expect("build fault proof mint");

        // Policy id, token name, parking address, nonce input.
        assert_eq!(built.policy_id_hex, script.hash_hex());
        assert_eq!(
            built.token_name,
            fault_token_name(&fault.accused_pool_id, &fault.evidence_hash)
        );
        assert_eq!(built.proof_address, addr);
        // The richest UTxO (aa…:0) is the fee + nonce input.
        assert_eq!(built.input_ref, ("aa".repeat(32), 0));

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();

        // Mint: exactly (fault policy, token_name, +1).
        let mint = tx.transaction_body.mint.as_ref().expect("mint present");
        let policies: Vec<_> = mint.iter().collect();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].0.as_slice(), script.hash);
        let assets: Vec<_> = policies[0].1.iter().collect();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].0.as_slice(), built.token_name);
        assert_eq!(i64::from(assets[0].1), 1);

        // The nonce input is among the spent inputs (find_input must succeed).
        assert!(
            tx.transaction_body
                .inputs
                .iter()
                .any(|i| i.transaction_id.as_slice() == [0xaa; 32] && i.index == 0)
        );
        // Collateral is the DISTINCT second UTxO (bb…:1), never the fee input.
        let coll = tx
            .transaction_body
            .collateral
            .as_ref()
            .expect("collateral present");
        assert!(
            coll.iter()
                .any(|i| i.transaction_id.as_slice() == [0xbb; 32] && i.index == 1)
        );
        assert!(
            coll.iter()
                .all(|i| !(i.transaction_id.as_slice() == [0xaa; 32] && i.index == 0))
        );

        // Exactly one output carries the token (proof output), with the inline
        // fault datum and the parked min-ADA; whisky's change output (pure ADA)
        // must not carry it.
        let (lovelace, datum_back) = decode_proof_output(&tx, &script.hash, &built.token_name);
        assert_eq!(lovelace, built.lovelace);
        assert_eq!(datum_back, fault);

        // Redeemer = PublishProof Constr(0, [OutputReference(aa…,0), pool, fault]).
        let redeemer = mint_redeemer(&tx);
        let fields = plutus::constr_fields(&redeemer, 0).unwrap();
        assert_eq!(fields.len(), 3);
        let (oref_c, oref_f) = plutus::as_constr(&fields[0]).unwrap();
        assert_eq!(oref_c, 0);
        assert_eq!(plutus::field_bytes(oref_f, 0).unwrap(), vec![0xaa; 32]);
        assert_eq!(plutus::field_int(oref_f, 1).unwrap(), 0);
        assert_eq!(
            plutus::field_bytes(fields, 1).unwrap(),
            fault.accused_pool_id
        );
        assert_eq!(
            FaultProofDatum::from_plutus_data(&fields[2]).unwrap(),
            fault
        );

        // Signed by the wallet key.
        let pk: [u8; 32] = key.public_key().into();
        assert!(
            tx.transaction_witness_set
                .vkeywitness
                .as_ref()
                .unwrap()
                .iter()
                .any(|w| w.vkey.as_slice() == pk)
        );
    }

    #[test]
    fn equivocation_kind_builds_with_witness() {
        let fault = FaultProofDatum {
            kind: FaultKind::Equivocation,
            ..datum()
        };
        let (pk, pa, sa, pb, sb) = equiv_witness();
        let reg_tx = "cc".repeat(32);
        let w = EquivocationWitness {
            bifrost_id_pk: &pk,
            payload_a: &pa,
            signature_a: &sa,
            payload_b: &pb,
            signature_b: &sb,
            registration_ref: (&reg_tx, 0),
        };
        let built = build_equivocation(&fault, &w).expect("equivocation mint builds");
        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        let (_, datum_back) =
            decode_proof_output(&tx, &fault_verifier_script().hash, &built.token_name);
        assert_eq!(datum_back, fault);
    }

    #[test]
    fn equivocation_redeemer_is_constr2_with_eight_fields() {
        let (pk, pa, sa, pb, sb) = equiv_witness();
        // input_ref_index = 5, registration_ref_input_index = 7.
        let r = equivocation_proof_redeemer(&[0xCD; 32], 5, 7, &pk, &datum(), &pa, &sa, &pb, &sb);
        let fields = plutus::constr_fields(&r, 2).unwrap();
        assert_eq!(fields.len(), 8);
        // field 0 = OutputReference Constr(0, [tx_id(32B), index]).
        let (oref_c, oref_f) = plutus::as_constr(&fields[0]).unwrap();
        assert_eq!(oref_c, 0);
        assert_eq!(plutus::field_int(oref_f, 1).unwrap(), 5);
        assert_eq!(plutus::field_int(fields, 1).unwrap(), 7); // registration_ref_input_index
        assert_eq!(plutus::field_bytes(fields, 2).unwrap(), pk); // bifrost_id_pk
        assert_eq!(
            FaultProofDatum::from_plutus_data(&fields[3]).unwrap(),
            datum()
        );
        assert_eq!(plutus::field_bytes(fields, 4).unwrap(), pa);
        assert_eq!(plutus::field_bytes(fields, 5).unwrap(), sa);
        assert_eq!(plutus::field_bytes(fields, 6).unwrap(), pb);
        assert_eq!(plutus::field_bytes(fields, 7).unwrap(), sb);
    }

    #[test]
    fn equivocation_without_witness_is_rejected() {
        let fault = FaultProofDatum {
            kind: FaultKind::Equivocation,
            ..datum()
        };
        assert!(matches!(
            build_with(&fault, &wallet_utxos()),
            Err(FaultProofMintError::MissingEquivocationWitness)
        ));
    }

    #[test]
    fn invalid_payload_with_witness_is_rejected() {
        let (pk, pa, sa, pb, sb) = equiv_witness();
        let reg_tx = "cc".repeat(32);
        let w = EquivocationWitness {
            bifrost_id_pk: &pk,
            payload_a: &pa,
            signature_a: &sa,
            payload_b: &pb,
            signature_b: &sb,
            registration_ref: (&reg_tx, 0),
        };
        // datum() is InvalidPayload — a witness must not be supplied.
        assert!(matches!(
            build_equivocation(&datum(), &w),
            Err(FaultProofMintError::UnexpectedEquivocationWitness)
        ));
    }

    #[test]
    fn rejects_bad_pool_id_and_evidence() {
        let bad_pool = FaultProofDatum {
            accused_pool_id: vec![0x11; 27],
            ..datum()
        };
        assert!(matches!(
            build_with(&bad_pool, &wallet_utxos()),
            Err(FaultProofMintError::BadAccusedPoolId(27))
        ));
        let bad_ev = FaultProofDatum {
            evidence_hash: vec![0x33; 31],
            ..datum()
        };
        assert!(matches!(
            build_with(&bad_ev, &wallet_utxos()),
            Err(FaultProofMintError::BadEvidenceHash(31))
        ));
    }

    #[test]
    fn requires_distinct_collateral() {
        // A single rich UTxO covers fees but leaves no DISTINCT collateral
        // (a UTxO can't be both a spent input and a collateral input).
        let utxos = vec![WalletUtxo {
            tx_hash: "aa".repeat(32),
            output_index: 0,
            lovelace: 50_000_000,
            pure_ada: true,
        }];
        assert!(matches!(
            build_with(&datum(), &utxos),
            Err(FaultProofMintError::Wallet(_))
        ));
    }

    #[test]
    fn rejects_insufficient_wallet() {
        // Below min-ADA + fee headroom, and no collateral either.
        let utxos = vec![WalletUtxo {
            tx_hash: "aa".repeat(32),
            output_index: 0,
            lovelace: 1_000_000,
            pure_ada: true,
        }];
        assert!(matches!(
            build_with(&datum(), &utxos),
            Err(FaultProofMintError::Wallet(_))
        ));
    }
}
