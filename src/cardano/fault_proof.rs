//! FaultProof redeemer encoders and mint transaction builder.
//!
//! Bifrost uses three specialized minting policies for punishable faults:
//! Round 1 invalid payloads, Round 2 invalid payloads, and direct
//! equivocation. Each policy is parameterized by the SPO registry policy id and
//! exposes the same redeemer shape:
//!
//! ```text
//! FaultProofMintRedeemer evidence
//!   = PublishProof { evidence }  -- Constr(0, [evidence])
//!   | BurnProof                  -- Constr(1, [])
//! ```
//!
//! The evidence record is specialized per policy. The minted token name is
//! always `blake2b_256(accused_pool_id || evidence_hash)`, where
//! `evidence_hash` is either the Halo2 public input carried in the signed DKG
//! payload or the Bifrost equivocation hash
//! `blake2b_256("bifrost-fault-equiv-v1" || len(lo) || lo || len(hi) || hi)`.

use pallas_codec::minicbor;
use pallas_codec::utils::NonEmptySet;
use pallas_primitives::PlutusData;
use pallas_primitives::conway::Tx;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::ban_list::fault_token_name;
use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::plutus::{self, array, bytes, constr, int};
use crate::cardano::publish::WalletUtxo;
use crate::cardano::tx_common::{sign_built_tx as common_sign_built_tx, whisky_network};
use crate::cardano::wallet::pub_key_hash_hex;

const POOL_ID_LEN: usize = 28;
const EVIDENCE_HASH_LEN: usize = 32;
const ROUND2_HEADER_LEN: usize = 14 + 8 + 8 + 8 + POOL_ID_LEN;
const ROUND2_ENTRY_LEN: usize = POOL_ID_LEN + 8 + 33 + 32 + 32 + EVIDENCE_HASH_LEN;
const ROUND2_ENTRY_EVIDENCE_OFFSET: usize = POOL_ID_LEN + 8 + 33 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultProofKind {
    Round1InvalidPayload,
    Round2InvalidPayload,
    Equivocation,
}

impl FaultProofKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Round1InvalidPayload => "round1-invalid-payload",
            Self::Round2InvalidPayload => "round2-invalid-payload",
            Self::Equivocation => "equivocation",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Round1InvalidPayloadEvidence<'a> {
    pub accused_pool_id: &'a [u8],
    pub canonical_round1_bytes: &'a [u8],
    pub payload_signature: &'a [u8],
    pub halo2_proof: &'a [u8],
    pub halo2_public_inputs: &'a [Vec<u8>],
}

#[derive(Debug, Clone)]
pub struct Round2InvalidPayloadEvidence<'a> {
    pub accused_pool_id: &'a [u8],
    pub canonical_round1_bytes: &'a [u8],
    pub round1_signature: &'a [u8],
    pub canonical_round2_bytes: &'a [u8],
    pub round2_signature: &'a [u8],
    pub round2_entry_index: u32,
    pub pad: &'a [u8],
    pub opened_share: &'a [u8],
    pub halo2_proof: &'a [u8],
    pub halo2_public_inputs: &'a [Vec<u8>],
}

#[derive(Debug, Clone)]
pub struct EquivocationEvidence<'a> {
    pub accused_pool_id: &'a [u8],
    pub payload_a: &'a [u8],
    pub signature_a: &'a [u8],
    pub payload_b: &'a [u8],
    pub signature_b: &'a [u8],
    pub evidence_hash: &'a [u8],
}

#[derive(Debug, Clone)]
pub enum FaultProofEvidence<'a> {
    Round1InvalidPayload(Round1InvalidPayloadEvidence<'a>),
    Round2InvalidPayload(Round2InvalidPayloadEvidence<'a>),
    Equivocation(EquivocationEvidence<'a>),
}

impl<'a> FaultProofEvidence<'a> {
    #[must_use]
    pub fn kind(&self) -> FaultProofKind {
        match self {
            Self::Round1InvalidPayload(_) => FaultProofKind::Round1InvalidPayload,
            Self::Round2InvalidPayload(_) => FaultProofKind::Round2InvalidPayload,
            Self::Equivocation(_) => FaultProofKind::Equivocation,
        }
    }

    #[must_use]
    pub fn accused_pool_id(&self) -> &'a [u8] {
        match self {
            Self::Round1InvalidPayload(e) => e.accused_pool_id,
            Self::Round2InvalidPayload(e) => e.accused_pool_id,
            Self::Equivocation(e) => e.accused_pool_id,
        }
    }

    pub fn evidence_hash(&self) -> Result<[u8; EVIDENCE_HASH_LEN], FaultProofMintError> {
        match self {
            Self::Round1InvalidPayload(e) => round1_evidence_hash(e.canonical_round1_bytes),
            Self::Round2InvalidPayload(e) => {
                round2_evidence_hash(e.canonical_round2_bytes, e.round2_entry_index)
            }
            Self::Equivocation(e) => fixed_hash(e.evidence_hash),
        }
    }

    fn to_plutus_data(
        &self,
        registration_ref_input_index: i64,
    ) -> Result<PlutusData, FaultProofMintError> {
        Ok(match self {
            Self::Round1InvalidPayload(e) => round1_invalid_payload_evidence(
                registration_ref_input_index,
                e.accused_pool_id,
                e.canonical_round1_bytes,
                e.payload_signature,
                e.halo2_proof,
                e.halo2_public_inputs,
            ),
            Self::Round2InvalidPayload(e) => round2_invalid_payload_evidence(
                registration_ref_input_index,
                e.accused_pool_id,
                e.canonical_round1_bytes,
                e.round1_signature,
                e.canonical_round2_bytes,
                e.round2_signature,
                e.round2_entry_index,
                e.pad,
                e.opened_share,
                e.halo2_proof,
                e.halo2_public_inputs,
            ),
            Self::Equivocation(e) => equivocation_evidence(
                registration_ref_input_index,
                e.accused_pool_id,
                e.payload_a,
                e.signature_a,
                e.payload_b,
                e.signature_b,
                e.evidence_hash,
            ),
        })
    }
}

#[derive(Debug)]
pub enum FaultProofMintError {
    BadAccusedPoolId(usize),
    BadEvidenceHash(usize),
    BadRound2Payload(String),
    Wallet(String),
    Build(String),
}

impl std::fmt::Display for FaultProofMintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadAccusedPoolId(n) => write!(f, "accused_pool_id must be 28 bytes, got {n}"),
            Self::BadEvidenceHash(n) => write!(f, "evidence_hash must be 32 bytes, got {n}"),
            Self::BadRound2Payload(e) => write!(f, "bad round2 payload: {e}"),
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "tx build: {e}"),
        }
    }
}

impl std::error::Error for FaultProofMintError {}

fn fixed_hash(bytes: &[u8]) -> Result<[u8; EVIDENCE_HASH_LEN], FaultProofMintError> {
    bytes
        .try_into()
        .map_err(|_| FaultProofMintError::BadEvidenceHash(bytes.len()))
}

fn round1_evidence_hash(
    canonical_round1_bytes: &[u8],
) -> Result<[u8; EVIDENCE_HASH_LEN], FaultProofMintError> {
    if canonical_round1_bytes.len() < EVIDENCE_HASH_LEN {
        return Err(FaultProofMintError::BadEvidenceHash(0));
    }
    fixed_hash(&canonical_round1_bytes[canonical_round1_bytes.len() - EVIDENCE_HASH_LEN..])
}

fn round2_evidence_hash(
    canonical_round2_bytes: &[u8],
    entry_index: u32,
) -> Result<[u8; EVIDENCE_HASH_LEN], FaultProofMintError> {
    if canonical_round2_bytes.len() < ROUND2_HEADER_LEN + ROUND2_ENTRY_LEN {
        return Err(FaultProofMintError::BadRound2Payload(format!(
            "got {} bytes, shorter than one entry",
            canonical_round2_bytes.len()
        )));
    }
    let entry_start = ROUND2_HEADER_LEN + (entry_index as usize) * ROUND2_ENTRY_LEN;
    let hash_start = entry_start + ROUND2_ENTRY_EVIDENCE_OFFSET;
    let hash_end = hash_start + EVIDENCE_HASH_LEN;
    let Some(bytes) = canonical_round2_bytes.get(hash_start..hash_end) else {
        return Err(FaultProofMintError::BadRound2Payload(format!(
            "entry index {entry_index} out of range"
        )));
    };
    fixed_hash(bytes)
}

/// `cardano/transaction.OutputReference` -> `Constr(0, [bytes(tx_id), int(output_index)])`.
#[must_use]
pub fn output_reference(tx_id: &[u8], output_index: u32) -> PlutusData {
    constr(
        0,
        vec![bytes(tx_id), plutus::int_from_u64(u64::from(output_index))],
    )
}

/// `PublishProof { evidence }`.
#[must_use]
pub fn publish_proof_redeemer(evidence: PlutusData) -> PlutusData {
    constr(0, vec![evidence])
}

/// `BurnProof`.
#[must_use]
pub fn burn_proof_redeemer() -> PlutusData {
    constr(1, vec![])
}

fn public_inputs_data(inputs: &[Vec<u8>]) -> PlutusData {
    array(inputs.iter().map(|input| bytes(input)).collect())
}

/// `Round1InvalidPayloadEvidence`.
#[must_use]
pub fn round1_invalid_payload_evidence(
    registration_ref_input_index: i64,
    accused_pool_id: &[u8],
    canonical_round1_bytes: &[u8],
    payload_signature: &[u8],
    halo2_proof: &[u8],
    halo2_public_inputs: &[Vec<u8>],
) -> PlutusData {
    constr(
        0,
        vec![
            int(registration_ref_input_index),
            bytes(accused_pool_id),
            bytes(canonical_round1_bytes),
            bytes(payload_signature),
            bytes(halo2_proof),
            public_inputs_data(halo2_public_inputs),
        ],
    )
}

/// `Round2InvalidPayloadEvidence`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn round2_invalid_payload_evidence(
    registration_ref_input_index: i64,
    accused_pool_id: &[u8],
    canonical_round1_bytes: &[u8],
    round1_signature: &[u8],
    canonical_round2_bytes: &[u8],
    round2_signature: &[u8],
    round2_entry_index: u32,
    pad: &[u8],
    opened_share: &[u8],
    halo2_proof: &[u8],
    halo2_public_inputs: &[Vec<u8>],
) -> PlutusData {
    constr(
        0,
        vec![
            int(registration_ref_input_index),
            bytes(accused_pool_id),
            bytes(canonical_round1_bytes),
            bytes(round1_signature),
            bytes(canonical_round2_bytes),
            bytes(round2_signature),
            int(i64::from(round2_entry_index)),
            bytes(pad),
            bytes(opened_share),
            bytes(halo2_proof),
            public_inputs_data(halo2_public_inputs),
        ],
    )
}

/// `EquivocationEvidence`.
#[must_use]
pub fn equivocation_evidence(
    registration_ref_input_index: i64,
    accused_pool_id: &[u8],
    payload_a: &[u8],
    signature_a: &[u8],
    payload_b: &[u8],
    signature_b: &[u8],
    evidence_hash: &[u8],
) -> PlutusData {
    constr(
        0,
        vec![
            int(registration_ref_input_index),
            bytes(accused_pool_id),
            bytes(payload_a),
            bytes(signature_a),
            bytes(payload_b),
            bytes(signature_b),
            bytes(evidence_hash),
        ],
    )
}

pub struct FaultProofMintRequest<'a> {
    /// The specialized fault verifier minting policy for `evidence.kind()`.
    pub fault_verifier_script: &'a ParameterizedScript,
    /// Optional deployed reference-script UTxO for the verifier policy. When
    /// absent, the script is included in the transaction witness set.
    pub fault_verifier_ref_script: Option<FaultProofRefScript<'a>>,
    /// The evidence record consumed by that specialized policy.
    pub evidence: FaultProofEvidence<'a>,
    /// `(tx_hash, output_index)` of the accused's `spos_registry` node UTxO.
    pub registration_ref: (&'a str, u32),
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    pub key: &'a PrivateKey,
    pub cost_models: Option<Vec<Vec<i64>>>,
}

#[derive(Debug, Clone, Copy)]
pub struct FaultProofRefScript<'a> {
    pub tx_hash: &'a str,
    pub output_index: u32,
    pub script_size: usize,
}

#[derive(Debug, Clone)]
pub struct FaultProofMintTx {
    pub signed_tx_hex: String,
    pub policy_id_hex: String,
    pub token_name: [u8; 32],
    pub proof_address: String,
    pub lovelace: u64,
    pub kind: FaultProofKind,
}

fn tx_id_bytes(tx_hash: &str) -> Result<[u8; 32], FaultProofMintError> {
    hex::decode(tx_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| FaultProofMintError::Build(format!("bad tx hash: {tx_hash}")))
}

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
            "largest wallet UTxO ({} lovelace) cannot cover the proof output plus fees",
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

fn sign_built_tx(unsigned_hex: &str, key: &PrivateKey) -> Result<String, FaultProofMintError> {
    common_sign_built_tx(unsigned_hex, key).map_err(FaultProofMintError::Build)
}

/// Declared execution budget for the FaultProof mint, per fault kind.
///
/// Conway caps a whole transaction at `maxTxExUnits` = 14,000,000 memory /
/// 10,000,000,000 steps. A single flat 16,000,000-memory budget therefore
/// exceeded the ceiling and every fault-proof mint was rejected outright with
/// `ExUnitsTooBigUTxO` — before phase 2 ran at all, so no script ever got the
/// chance to succeed or fail on its own terms. Script-level evaluation tests
/// cannot catch this: the cap is a transaction-level rule.
///
/// Budgeting per kind rather than giving everything the maximum keeps the fee
/// honest — declared ExUnits are what the fee is charged on, so an oversized
/// declaration is real overpayment on a live network.
fn fault_mint_ex_units(kind: FaultProofKind) -> Budget {
    match kind {
        // ZK-free: the policy re-hashes the two retained payloads and checks
        // they differ under one namespace. Cheap, with headroom to spare.
        FaultProofKind::Equivocation => Budget {
            mem: 8_000_000,
            steps: 5_000_000_000,
        },
        // Halo2/KZG proof verification on-chain — give these as much as Conway
        // permits, less a margin for the rest of the transaction.
        FaultProofKind::Round1InvalidPayload | FaultProofKind::Round2InvalidPayload => Budget {
            mem: 13_500_000,
            steps: 9_000_000_000,
        },
    }
}

pub fn build_fault_proof_mint_tx(
    req: &FaultProofMintRequest,
) -> Result<FaultProofMintTx, FaultProofMintError> {
    let accused_pool_id = req.evidence.accused_pool_id();
    if accused_pool_id.len() != POOL_ID_LEN {
        return Err(FaultProofMintError::BadAccusedPoolId(accused_pool_id.len()));
    }
    let evidence_hash = req.evidence.evidence_hash()?;
    let policy_id_hex = req.fault_verifier_script.hash_hex();
    let token_name = fault_token_name(accused_pool_id, &evidence_hash);
    let proof_address = req.wallet_address.to_string();
    let lovelace = 2_000_000u64;

    let (fee_utxo, coll_utxo) = select_fee_and_collateral(req.wallet_utxos, lovelace + 1_000_000)?;
    let _fee_tx_id = tx_id_bytes(&fee_utxo.tx_hash)?;
    let registration_ref = (tx_id_bytes(req.registration_ref.0)?, req.registration_ref.1);
    let mut reference_inputs = vec![registration_ref];
    if let Some(ref_script) = req.fault_verifier_ref_script {
        reference_inputs.push((tx_id_bytes(ref_script.tx_hash)?, ref_script.output_index));
    }
    reference_inputs.sort();
    reference_inputs.dedup();
    let registration_ref_input_index = reference_inputs
        .iter()
        .position(|reference_input| *reference_input == registration_ref)
        .expect("registration reference input is present")
        as i64;
    let evidence_data = req.evidence.to_plutus_data(registration_ref_input_index)?;
    let redeemer = publish_proof_redeemer(evidence_data);
    let redeemer_hex = hex::encode(minicbor::to_vec(&redeemer).expect("redeemer CBOR encode"));
    let script_source = req.fault_verifier_ref_script.map_or_else(
        || {
            ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
                script_cbor: req.fault_verifier_script.cbor_hex(),
                language_version: LanguageVersion::V3,
            })
        },
        |ref_script| {
            ScriptSource::InlineScriptSource(InlineScriptSource {
                ref_tx_in: RefTxIn {
                    tx_hash: ref_script.tx_hash.to_string(),
                    tx_index: ref_script.output_index,
                    script_size: Some(ref_script.script_size),
                },
                script_hash: policy_id_hex.clone(),
                language_version: LanguageVersion::V3,
                script_size: ref_script.script_size,
            })
        },
    );

    let token_unit = format!("{policy_id_hex}{}", hex::encode(token_name));
    let proof_out = Output {
        address: proof_address.clone(),
        amount: vec![
            Asset::new_from_str("lovelace", &lovelace.to_string()),
            Asset::new_from_str(&token_unit, "1"),
        ],
        datum: None,
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
        reference_inputs: vec![RefTxIn {
            tx_hash: req.registration_ref.0.to_string(),
            tx_index: req.registration_ref.1,
            script_size: None,
        }],
        withdrawals: vec![],
        mints: vec![MintItem::ScriptMint(ScriptMint {
            mint: MintParameter {
                policy_id: policy_id_hex.clone(),
                asset_name: hex::encode(token_name),
                amount: 1,
            },
            redeemer: Some(Redeemer {
                data: redeemer_hex,
                ex_units: fault_mint_ex_units(req.evidence.kind()),
            }),
            script_source: Some(script_source),
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

    let unsigned_hex = {
        let tx_bytes = hex::decode(&unsigned_hex)
            .map_err(|e| FaultProofMintError::Build(format!("unsigned hex decode: {e}")))?;
        let mut tx: Tx = minicbor::decode(&tx_bytes)
            .map_err(|e| FaultProofMintError::Build(format!("tx decode: {e}")))?;
        if let Some(refs) = tx.transaction_body.reference_inputs.take() {
            let mut v = refs.to_vec();
            v.sort_by_key(|input| (input.transaction_id, input.index));
            v.dedup();
            tx.transaction_body.reference_inputs = NonEmptySet::from_vec(v);
        }
        let refs: Vec<_> = tx
            .transaction_body
            .reference_inputs
            .as_ref()
            .map(|inputs| inputs.iter().collect())
            .unwrap_or_default();
        let got = refs
            .get(registration_ref_input_index as usize)
            .ok_or_else(|| {
                FaultProofMintError::Build("registration ref input index out of range".into())
            })?;
        if got.transaction_id.as_slice() != registration_ref.0
            || got.index != u64::from(registration_ref.1)
        {
            return Err(FaultProofMintError::Build(
                "registry node not at redeemer ref index -- ref ordering changed".into(),
            ));
        }
        hex::encode(
            minicbor::to_vec(&tx)
                .map_err(|e| FaultProofMintError::Build(format!("re-encode: {e}")))?,
        )
    };

    let signed_tx_hex = sign_built_tx(&unsigned_hex, req.key)?;

    Ok(FaultProofMintTx {
        signed_tx_hex,
        policy_id_hex,
        token_name,
        proof_address,
        lovelace,
        kind: req.evidence.kind(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::always_ok::ALWAYS_OK_PLUTUS_CBOR_HEX;
    use crate::cardano::blueprint::script_hash_v3;
    use crate::cardano::plutus;
    use crate::cardano::wallet::{derive_payment_key, wallet_address};
    use pallas_codec::minicbor;
    use pallas_primitives::conway::{PseudoTransactionOutput, Tx, Value};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn script() -> ParameterizedScript {
        let cbor = hex::decode(ALWAYS_OK_PLUTUS_CBOR_HEX).unwrap();
        ParameterizedScript {
            hash: script_hash_v3(&cbor),
            cbor,
        }
    }

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

    fn output_has_token(
        out: &pallas_primitives::conway::PostAlonzoTransactionOutput,
        policy: &[u8; 28],
        name: &[u8; 32],
    ) -> bool {
        match &out.value {
            Value::Coin(_) => false,
            Value::Multiasset(_, ma) => ma.iter().any(|(p, assets)| {
                p.as_slice() == policy && assets.iter().any(|(n, _q)| n.as_slice() == name)
            }),
        }
    }

    fn proof_output_count(tx: &Tx, policy: &[u8; 28], name: &[u8; 32]) -> usize {
        tx.transaction_body
            .outputs
            .iter()
            .filter(|o| match o {
                PseudoTransactionOutput::PostAlonzo(out) => output_has_token(out, policy, name),
                _ => false,
            })
            .count()
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
    fn round1_redeemer_shape() {
        let inputs = vec![vec![0x33; 32], vec![0x11; 28]];
        let evidence = round1_invalid_payload_evidence(
            0,
            &[0x11; 28],
            &[0xAA; 160],
            &[0xBB; 64],
            &[0xCC; 96],
            &inputs,
        );
        let fields = plutus::constr_fields(&evidence, 0).unwrap();
        assert_eq!(fields.len(), 6);
        assert_eq!(plutus::field_int(fields, 0).unwrap(), 0);
        assert_eq!(plutus::field_bytes(fields, 1).unwrap(), vec![0x11; 28]);
        assert_eq!(
            plutus::field_bytes(fields, 5).unwrap_err().to_string(),
            "field [5] is not a ByteArray"
        );
    }

    #[test]
    fn round2_evidence_hash_reads_selected_entry() {
        let hash_a = [0xA1; 32];
        let hash_b = [0xB2; 32];
        let entry = |hash: [u8; 32]| {
            let mut out = Vec::new();
            out.extend_from_slice(&[0x01; 28]);
            out.extend_from_slice(&2u64.to_be_bytes());
            out.extend_from_slice(&[0x02; 33]);
            out.extend_from_slice(&[0x03; 32]);
            out.extend_from_slice(&[0x04; 32]);
            out.extend_from_slice(&hash);
            out
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(b"bifrost-dkg-r2");
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&51u64.to_be_bytes());
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&[0x11; 28]);
        payload.extend_from_slice(&entry(hash_a));
        payload.extend_from_slice(&entry(hash_b));
        assert_eq!(round2_evidence_hash(&payload, 1).unwrap(), hash_b);
    }

    #[test]
    fn build_round1_fault_proof_mint_tx() {
        let script = script();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        let pool = [0x11; 28];
        let evidence_hash = [0x33; 32];
        let mut canonical = vec![0xAA; 128];
        canonical.extend_from_slice(&evidence_hash);
        let public_inputs = vec![evidence_hash.to_vec(), pool.to_vec()];
        let evidence = FaultProofEvidence::Round1InvalidPayload(Round1InvalidPayloadEvidence {
            accused_pool_id: &pool,
            canonical_round1_bytes: &canonical,
            payload_signature: &[0xBB; 64],
            halo2_proof: &[0xCC; 96],
            halo2_public_inputs: &public_inputs,
        });

        let built = build_fault_proof_mint_tx(&FaultProofMintRequest {
            fault_verifier_script: &script,
            fault_verifier_ref_script: None,
            evidence,
            registration_ref: (&"cc".repeat(32), 0),
            wallet_address: &addr,
            wallet_utxos: &wallet_utxos(),
            key: &key,
            cost_models: None,
        })
        .expect("mint tx builds");

        assert_eq!(built.token_name, fault_token_name(&pool, &evidence_hash));
        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        assert_eq!(proof_output_count(&tx, &script.hash, &built.token_name), 1);

        let redeemer = mint_redeemer(&tx);
        let publish_fields = plutus::constr_fields(&redeemer, 0).unwrap();
        assert_eq!(publish_fields.len(), 1);
        let evidence_fields = plutus::constr_fields(&publish_fields[0], 0).unwrap();
        assert_eq!(plutus::field_int(evidence_fields, 0).unwrap(), 0);
    }

    #[test]
    fn build_fault_proof_mint_tx_can_use_reference_script() {
        let script = script();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        let pool = [0x11; 28];
        let evidence_hash = [0x33; 32];
        let mut canonical = vec![0xAA; 128];
        canonical.extend_from_slice(&evidence_hash);
        let public_inputs = vec![evidence_hash.to_vec(), pool.to_vec()];
        let evidence = FaultProofEvidence::Round1InvalidPayload(Round1InvalidPayloadEvidence {
            accused_pool_id: &pool,
            canonical_round1_bytes: &canonical,
            payload_signature: &[0xBB; 64],
            halo2_proof: &[0xCC; 96],
            halo2_public_inputs: &public_inputs,
        });
        let ref_tx = "00".repeat(32);

        let built = build_fault_proof_mint_tx(&FaultProofMintRequest {
            fault_verifier_script: &script,
            fault_verifier_ref_script: Some(FaultProofRefScript {
                tx_hash: &ref_tx,
                output_index: 2,
                script_size: script.cbor.len(),
            }),
            evidence,
            registration_ref: (&"cc".repeat(32), 0),
            wallet_address: &addr,
            wallet_utxos: &wallet_utxos(),
            key: &key,
            cost_models: None,
        })
        .expect("mint tx builds with a reference script");

        let tx: Tx = minicbor::decode(&hex::decode(&built.signed_tx_hex).unwrap()).unwrap();
        assert_eq!(
            tx.transaction_body
                .reference_inputs
                .as_ref()
                .map(|inputs| inputs.len()),
            Some(2)
        );
        assert!(tx.transaction_witness_set.plutus_v3_script.is_none());

        let redeemer = mint_redeemer(&tx);
        let publish_fields = plutus::constr_fields(&redeemer, 0).unwrap();
        let evidence_fields = plutus::constr_fields(&publish_fields[0], 0).unwrap();
        assert_eq!(
            plutus::field_int(evidence_fields, 0).unwrap(),
            1,
            "registration reference must be read from the sorted ref-input index"
        );
    }

    #[test]
    fn burn_redeemer_is_constr1_empty() {
        let burn = burn_proof_redeemer();
        let (c, f) = plutus::as_constr(&burn).unwrap();
        assert_eq!((c, f.len()), (1, 0));
    }
}
