//! WI-019 — turn captured DKG misbehavior into a real `FaultProof`.
//!
//! This module is the heimdall-side glue between three pieces that already
//! existed but were never wired together:
//!
//! 1. **WI-014 evidence capture** — the epoch driver / HTTP transport
//!    (`http::peer_network`) retains the raw signed payload of every fetched
//!    peer message and drops cryptographically-invalid ones. The structured
//!    pieces of a bad payload (an accused's Round 1 commitments + the
//!    malformed PoK, or a sender's commitments + a decrypted bad share, or
//!    two conflicting signed payloads) are the inputs here.
//! 2. **The Axiom/Halo2 fault PROVER** (`circuits::dkg_fault`) — round1
//!    PoK-fault and round2 share-fault circuits whose public inputs are
//!    `[evidence_hash, pool_id]`, where
//!    `evidence_hash = Poseidon(pool_id, message_fields)`. The circuit
//!    *attests* that the committed payload is genuinely faulty
//!    (`μ·G − c·φ₀ ≠ R`, resp. `f_i(l)·G ≠ Σ_j l^j φ_{i,j}`).
//! 3. **The WI-016 mint tx** (`cardano::fault_proof::build_fault_proof_mint_tx`)
//!    — mints the `FaultProof` token named `blake2b_256(pool_id ‖ evidence_hash)`.
//!
//! ## Spec compliance — the authentication envelope (tech-doc §9.2)
//!
//! A fault proof is only sound if the accused *actually authored* the bad
//! payload. The protocol uses the **sign-the-hash** scheme: every DKG payload
//! carries a BIP-340 signature by the accused's `bifrost_id_pk` over
//! `message_hash = SHA256(canonical_bytes)`. A direct-fault submission therefore
//! carries (§9.2): the signed canonical payload bytes + the accused signature
//! (64B) + the Halo2 proof + its public inputs; the verifier policy checks
//! `verifySchnorrSecp256k1Signature(bifrost_id_pk, SHA256(canonical_bytes),
//! signature)` AND the proof.
//!
//! So every invalid-payload evidence type here carries the accused's
//! `bifrost_id_pk`, the `(epoch, threshold, attempt, pool_id)` namespace, and
//! the accused's payload signature. `canonical_bytes()` rebuilds the exact
//! signed bytes from the structured fields, `message_hash()` is their SHA256,
//! and `verify_payload_signature()` confirms the accused signed them — refusing
//! to forge a FaultProof against a payload they never published. Equivocation
//! carries the two signed canonical payloads and `verify()`s both signatures +
//! same-namespace + distinct-content, exactly as the equivocation policy does.
//!
//! ## The bridge — `evidence_hash`
//!
//! - `InvalidPayload`: `evidence_hash = digest.to_repr()` — the 32-byte little-
//!   endian serialization of public input 0. Public input 1 is the 28-byte
//!   accused `pool_id` interpreted as a little-endian BLS scalar. The signed
//!   DKG payload carries this `evidence_hash`, so the generated verifier must
//!   pass exactly `[evidence_hash, pool_id]`, and the on-chain token name is
//!   `blake2b_256(pool_id || evidence_hash)`.
//! - `Equivocation`: no ZK.
//!   `evidence_hash = blake2b_256("bifrost-fault-equiv-v1" ‖ len(lo) ‖ lo ‖ len(hi) ‖ hi)`
//!   over the two conflicting signed payload byte strings, where `lo <= hi`.
//!   Sorting makes it order-independent, and length prefixes keep the preimage
//!   unambiguous.
//!
//! ## Cost
//!
//! Deriving `evidence_hash` is a cheap host-side Poseidon hash (no SRS, no
//! proof) — that is the path the mint tx needs. GENERATING the ZK proof
//! (`prove_*`) keygens + proves a k=18 (round2) / k=22 (round1) circuit and
//! costs seconds-to-minutes + an SRS; it is only needed once the upstream
//! verify checks proofs on-chain. `insecure_test_srs` is for tests/local
//! proving ONLY — production must load a real ceremony SRS.

use bitcoin::secp256k1::Secp256k1;
use halo2_base::{
    gates::circuit::builder::RangeCircuitBuilder,
    halo2_proofs::{
        halo2curves::{
            bls12_381::{Bls12, Fr as BlsFr, G1Affine},
            ff::{Field, PrimeField},
            secp256k1::{Fq, Secp256k1Affine},
        },
        plonk::{Circuit, ProvingKey, create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
    },
};
use k256::{
    AffinePoint as K256AffinePoint, EncodedPoint as K256EncodedPoint,
    elliptic_curve::sec1::FromEncodedPoint,
};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

use crate::cardano::hash::blake2b_256;
use crate::circuits::cardano_transcript::{CardanoBlake2bRead, CardanoBlake2bWrite};
use crate::circuits::dkg_fault::{
    AxiomDkgCircuitParams, DKG_POOL_ID_BYTES, DkgRound1PokDigestFaultWitness,
    DkgRound2ShareFaultWitness, axiom_point_from_compressed,
    build_round1_digest_fault_keygen_circuit, build_round1_digest_fault_prover_circuit,
    build_round2_digest_fault_keygen_circuit, build_round2_digest_fault_prover_circuit,
    is_identity, round1_digest_fault_public_inputs, round1_digest_residual, round1_hdk_challenge,
    round1_message_digest, round2_digest_fault_public_inputs, round2_residual,
};
use crate::http::{auth, canonical};

/// FROST identifiers are `u16` indices, so the round2 share circuit only ever
/// needs 16 index bits. Fixed across the protocol.
pub const DKG_INDEX_BITS: usize = 16;

/// 28-byte `blake2b_224(cold_vkey)` pool id.
const POOL_ID_LEN: usize = DKG_POOL_ID_BYTES;
const EQUIVOCATION_DOMAIN: &[u8] = b"bifrost-fault-equiv-v1";

/// Anything that can go wrong turning captured bytes into a fault proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultEvidenceError {
    /// An accused's commitment vector was empty (φ₀ is required).
    NoCommitments,
    /// A commitment / nonce point was not a valid compressed secp256k1 point.
    BadPoint,
    /// A scalar (μ or share) was not a canonical secp256k1 field element.
    NonCanonicalScalar,
    /// `commitments.len()` did not match the const generic threshold `T`.
    ThresholdMismatch { expected: usize, got: usize },
    /// `round2_evidence_hash_dyn` has no arm for this threshold (commitment
    /// count); add one to the dispatch macro.
    UnsupportedThreshold(usize),
    /// The accused's BIP-340 payload signature did not verify against their
    /// `bifrost_id_pk` over `SHA256(canonical_bytes)` — they did not author
    /// this payload, so it must not be turned into a FaultProof.
    SignatureInvalid,
    /// Equivocation: the two payloads are not in the same `(phase, epoch,
    /// threshold, attempt, pool_id)` namespace.
    NamespaceMismatch,
    /// Equivocation: the two payloads are byte-identical, so there is no
    /// conflict.
    NotEquivocation,
    /// The evidence does NOT actually encode a fault (the payload verifies),
    /// so there is nothing to prove — refusing to build an unsatisfiable
    /// circuit.
    NotAFault,
    /// The generated proof failed its own verification (should be impossible;
    /// a bug or a corrupt SRS).
    ProofSelfVerifyFailed,
}

impl std::fmt::Display for FaultEvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCommitments => write!(f, "evidence carries no commitments"),
            Self::BadPoint => write!(f, "invalid compressed secp256k1 point in evidence"),
            Self::NonCanonicalScalar => write!(f, "non-canonical secp256k1 scalar in evidence"),
            Self::ThresholdMismatch { expected, got } => {
                write!(
                    f,
                    "threshold mismatch: circuit T={expected}, evidence has {got} commitments"
                )
            }
            Self::UnsupportedThreshold(n) => {
                write!(
                    f,
                    "unsupported threshold {n} (no round2_evidence_hash_dyn arm)"
                )
            }
            Self::SignatureInvalid => {
                write!(
                    f,
                    "accused payload signature does not verify (not authored by the accused)"
                )
            }
            Self::NamespaceMismatch => {
                write!(f, "equivocation payloads are not in the same namespace")
            }
            Self::NotEquivocation => write!(f, "equivocation payloads are byte-identical"),
            Self::NotAFault => write!(f, "evidence does not encode a fault (payload verifies)"),
            Self::ProofSelfVerifyFailed => {
                write!(f, "generated fault proof failed self-verification")
            }
        }
    }
}

impl std::error::Error for FaultEvidenceError {}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Verify a BIP-340 payload signature against `bifrost_id_pk` over
/// `SHA256(canonical_bytes)`, mapping any failure to `SignatureInvalid`.
fn verify_sig(
    bifrost_id_pk: &[u8; 32],
    canonical_bytes: &[u8],
    signature: &[u8; 64],
) -> Result<(), FaultEvidenceError> {
    let secp = Secp256k1::new();
    auth::verify_payload(&secp, bifrost_id_pk, canonical_bytes, signature)
        .map_err(|_| FaultEvidenceError::SignatureInvalid)
}

// ---------------------------------------------------------------------------
// Evidence inputs (circuit-consumable shape + authentication envelope)
// ---------------------------------------------------------------------------

/// A captured invalid Round 1 proof-of-knowledge.
///
/// `commitments` and `sigma_i` are the spec wire fields
/// (`http::frost_bridge::round1_fields`): φ_{i,0..t−1} as compressed points and
/// σ_i = x-only R(32) ‖ μ(32). The PoK is invalid iff `μ·G − c·φ₀ ≠ R`, where
/// `c = H_DKG(identifier ‖ φ₀ ‖ R)` (recomputed by the circuit).
///
/// The remaining fields are the **authentication envelope**: the accused signed
/// `SHA256(canonical_bytes)` — where `canonical_bytes` is rebuilt from the
/// namespace + `commitments` + `sigma_i` + `evidence_hash` — with
/// `bifrost_id_pk`. So the same evidence hash the circuit opens is the one the
/// accused authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round1PokFaultEvidence {
    pub epoch: u64,
    pub threshold: u64,
    pub attempt: u64,
    pub accused_pool_id: [u8; POOL_ID_LEN],
    pub bifrost_id_pk: [u8; 32],
    pub identifier: u16,
    pub commitments: Vec<[u8; 33]>,
    pub sigma_i: [u8; 64],
    /// Accused's BIP-340 signature over `SHA256(canonical_bytes)`.
    pub payload_signature: [u8; 64],
}

/// A captured invalid Round 2 secret share.
///
/// `sender_commitments` are the sender's Round 1 commitments φ_{i,0..t−1};
/// `share` is the decrypted scalar `f_i(l)` the sender addressed to recipient
/// index `l = recipient_index` (big-endian, as `signing_share().serialize()`).
/// The share is invalid iff `f_i(l)·G ≠ Σ_j l^j φ_{i,j}`.
///
/// `round2_canonical_bytes` are the full Round 2 payload (the encrypted-share
/// vector) the sender BIP-340-signed; `message_hash = SHA256(round2_canonical_bytes)`.
/// The selected share entry carries this circuit's `evidence_hash`; the
/// on-chain policy checks that the opened ciphertext/pad matches the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round2ShareFaultEvidence {
    pub epoch: u64,
    pub threshold: u64,
    pub attempt: u64,
    /// The accused SENDER's pool id.
    pub accused_pool_id: [u8; POOL_ID_LEN],
    /// The accused SENDER's x-only bifrost identity key.
    pub bifrost_id_pk: [u8; 32],
    pub recipient_index: u16,
    /// Index of this recipient's entry in the signed canonical Round 2 payload.
    pub round2_entry_index: u32,
    pub sender_commitments: Vec<[u8; 33]>,
    /// The exact Round 1 canonical bytes that introduced `sender_commitments`.
    pub canonical_round1_bytes: Vec<u8>,
    /// Accused's BIP-340 signature over `SHA256(canonical_round1_bytes)`.
    pub round1_signature: [u8; 64],
    pub share: [u8; 32],
    /// One-time pad opening the selected Round 2 ciphertext.
    pub pad: [u8; 32],
    /// The exact Round 2 canonical bytes the sender signed.
    pub round2_canonical_bytes: Vec<u8>,
    /// Accused's BIP-340 signature over `SHA256(round2_canonical_bytes)`.
    pub round2_signature: [u8; 64],
}

/// Two conflicting, same-namespace, BIP-340-signed payloads from one accused.
///
/// `payload_a` / `payload_b` are the **canonical bytes** (the signed message
/// preimage), each with its signature. `verify()` reproduces the equivocation
/// policy's checks (tech-doc §9.2): both belong to the same namespace, both
/// signatures verify under `bifrost_id_pk`, and the two payloads differ. There
/// is no ZK — the double-signature is itself the misbehavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationEvidence {
    pub epoch: u64,
    pub threshold: u64,
    pub attempt: u64,
    pub phase: NamespacePhase,
    pub accused_pool_id: [u8; POOL_ID_LEN],
    pub bifrost_id_pk: [u8; 32],
    pub payload_a: Vec<u8>,
    pub signature_a: [u8; 64],
    pub payload_b: Vec<u8>,
    pub signature_b: [u8; 64],
}

fn checked_scalar(be: &[u8; 32]) -> Result<Fq, FaultEvidenceError> {
    let mut repr = *be;
    repr.reverse(); // halo2curves Fq::from_repr is little-endian
    Option::<Fq>::from(Fq::from_repr(repr)).ok_or(FaultEvidenceError::NonCanonicalScalar)
}

fn checked_point(compressed: &[u8; 33]) -> Result<Secp256k1Affine, FaultEvidenceError> {
    // Validate via k256 first so the (panicking) axiom converter can't blow up
    // on adversarial bytes.
    let encoded =
        K256EncodedPoint::from_bytes(compressed).map_err(|_| FaultEvidenceError::BadPoint)?;
    let on_curve = K256AffinePoint::from_encoded_point(&encoded);
    if bool::from(on_curve.is_none()) {
        return Err(FaultEvidenceError::BadPoint);
    }
    Ok(axiom_point_from_compressed(compressed))
}

/// `digest.to_repr()` as a fixed 32-byte array — the `InvalidPayload`
/// `evidence_hash`.
fn digest_bytes(digest: BlsFr) -> [u8; 32] {
    let repr = digest.to_repr();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

/// Circuit params for the round1 PoK-fault digest circuit (k=22).
#[must_use]
pub fn round1_params() -> AxiomDkgCircuitParams {
    AxiomDkgCircuitParams::round1_digest_fault()
}

/// Circuit params for the round2 share-fault digest circuit (k=18).
#[must_use]
pub fn round2_params() -> AxiomDkgCircuitParams {
    AxiomDkgCircuitParams::round2_digest_fault()
}

pub fn round1_evidence_hash_from_fields(
    accused_pool_id: &[u8; POOL_ID_LEN],
    identifier: u16,
    commitments: &[[u8; 33]],
    sigma_i: &[u8; 64],
) -> Result<[u8; 32], FaultEvidenceError> {
    let phi0 = checked_point(
        commitments
            .first()
            .ok_or(FaultEvidenceError::NoCommitments)?,
    )?;
    let mu_bytes: [u8; 32] = sigma_i[32..64].try_into().expect("64-byte sigma");
    let mu = checked_scalar(&mu_bytes)?;
    let mut r_compressed = [0u8; 33];
    r_compressed[0] = 0x02;
    r_compressed[1..].copy_from_slice(&sigma_i[0..32]);
    let transcript_r = checked_point(&r_compressed)?;
    let witness = DkgRound1PokDigestFaultWitness {
        accused_pool_id: *accused_pool_id,
        identifier: u64::from(identifier),
        mu,
        challenge: Fq::ZERO,
        phi0,
        transcript_r,
    };
    Ok(digest_bytes(round1_message_digest(
        round1_params(),
        &witness,
    )))
}

pub fn round2_evidence_hash_from_fields_dyn(
    accused_pool_id: &[u8; POOL_ID_LEN],
    recipient_index: u16,
    sender_commitments: &[[u8; 33]],
    share: &[u8; 32],
) -> Result<[u8; 32], FaultEvidenceError> {
    let evidence = Round2ShareFaultEvidence {
        epoch: 0,
        threshold: 0,
        attempt: 0,
        accused_pool_id: *accused_pool_id,
        bifrost_id_pk: [0u8; 32],
        recipient_index,
        round2_entry_index: 0,
        sender_commitments: sender_commitments.to_vec(),
        share: *share,
        canonical_round1_bytes: Vec::new(),
        round1_signature: [0u8; 64],
        pad: [0u8; 32],
        round2_canonical_bytes: Vec::new(),
        round2_signature: [0u8; 64],
    };
    round2_evidence_hash_dyn(&evidence)
}

impl Round1PokFaultEvidence {
    /// The exact bytes the accused signed:
    /// `TAG_R1 ‖ namespace ‖ φ… ‖ σ_i ‖ evidence_hash`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FaultEvidenceError> {
        let evidence_hash = self.evidence_hash()?;
        Ok(canonical::round1(
            self.epoch,
            self.threshold,
            self.attempt,
            &self.accused_pool_id,
            &self.commitments,
            &self.sigma_i,
            &evidence_hash,
        ))
    }

    /// `message_hash = SHA256(canonical_bytes)` — the §9.2 submission field the
    /// fault verifier checks the accused signature against.
    #[must_use]
    pub fn message_hash(&self) -> [u8; 32] {
        sha256(
            &self
                .canonical_bytes()
                .expect("validated round1 evidence has canonical bytes"),
        )
    }

    /// Confirm the accused actually authored this payload (BIP-340 over
    /// `message_hash`). A fault proof must not be built without this.
    pub fn verify_payload_signature(&self) -> Result<(), FaultEvidenceError> {
        verify_sig(
            &self.bifrost_id_pk,
            &self.canonical_bytes()?,
            &self.payload_signature,
        )
    }

    /// The descriptive `namespace_hash` for this Round 1 namespace.
    #[must_use]
    pub fn namespace_hash(&self) -> [u8; 32] {
        namespace_hash(
            NamespacePhase::Round1,
            self.epoch,
            self.threshold,
            self.attempt,
        )
    }

    /// Build the circuit witness, recomputing the HDKG challenge from
    /// `(identifier, φ₀, R)`.
    pub fn witness(&self) -> Result<DkgRound1PokDigestFaultWitness, FaultEvidenceError> {
        let phi0 = checked_point(
            self.commitments
                .first()
                .ok_or(FaultEvidenceError::NoCommitments)?,
        )?;
        let mu_bytes: [u8; 32] = self.sigma_i[32..64].try_into().expect("64-byte sigma");
        let mu = checked_scalar(&mu_bytes)?;
        // σ_i carries R x-only; the -tr ciphersuite forces even Y, so 0x02 is
        // the correct SEC1 prefix.
        let mut r_compressed = [0u8; 33];
        r_compressed[0] = 0x02;
        r_compressed[1..].copy_from_slice(&self.sigma_i[0..32]);
        let transcript_r = checked_point(&r_compressed)?;
        let probe = DkgRound1PokDigestFaultWitness {
            accused_pool_id: self.accused_pool_id,
            identifier: u64::from(self.identifier),
            mu,
            challenge: Fq::ZERO,
            phi0,
            transcript_r,
        };
        let challenge = round1_hdk_challenge(&probe);
        Ok(DkgRound1PokDigestFaultWitness { challenge, ..probe })
    }

    /// `true` iff the PoK is genuinely invalid (`μ·G − c·φ₀ ≠ R`).
    pub fn is_fault(&self) -> Result<bool, FaultEvidenceError> {
        let w = self.witness()?;
        Ok(round1_digest_residual(&w) != w.transcript_r)
    }

    /// The circuit public inputs: `[evidence_hash, pool_id]`.
    pub fn public_inputs(&self) -> Result<Vec<BlsFr>, FaultEvidenceError> {
        let w = self.witness()?;
        Ok(round1_digest_fault_public_inputs(round1_params(), &w))
    }

    /// The 32-byte `evidence_hash` = the first circuit public input,
    /// `Poseidon(pool_id, msg)`. Cheap: no proof, no SRS.
    pub fn evidence_hash(&self) -> Result<[u8; 32], FaultEvidenceError> {
        Ok(digest_bytes(self.public_inputs()?[0]))
    }
}

impl Round2ShareFaultEvidence {
    /// `message_hash = SHA256(round2_canonical_bytes)`.
    #[must_use]
    pub fn message_hash(&self) -> [u8; 32] {
        sha256(&self.round2_canonical_bytes)
    }

    /// Confirm the accused sender actually authored the Round 2 payload.
    pub fn verify_payload_signature(&self) -> Result<(), FaultEvidenceError> {
        verify_sig(
            &self.bifrost_id_pk,
            &self.canonical_round1_bytes,
            &self.round1_signature,
        )?;
        verify_sig(
            &self.bifrost_id_pk,
            &self.round2_canonical_bytes,
            &self.round2_signature,
        )
    }

    /// The descriptive `namespace_hash` for this Round 2 namespace.
    #[must_use]
    pub fn namespace_hash(&self) -> [u8; 32] {
        namespace_hash(
            NamespacePhase::Round2,
            self.epoch,
            self.threshold,
            self.attempt,
        )
    }

    /// Build the circuit witness.
    pub fn witness(&self) -> Result<DkgRound2ShareFaultWitness, FaultEvidenceError> {
        if self.sender_commitments.is_empty() {
            return Err(FaultEvidenceError::NoCommitments);
        }
        let share = checked_scalar(&self.share)?;
        let commitments = self
            .sender_commitments
            .iter()
            .map(checked_point)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DkgRound2ShareFaultWitness {
            accused_pool_id: self.accused_pool_id,
            share,
            participant_index: u64::from(self.recipient_index),
            commitments,
        })
    }

    /// `true` iff the share is inconsistent with the commitments
    /// (`f_i(l)·G ≠ Σ_j l^j φ_{i,j}`).
    pub fn is_fault(&self) -> Result<bool, FaultEvidenceError> {
        let w = self.witness()?;
        Ok(!is_identity(&round2_residual(&w)))
    }

    /// The circuit public inputs for the configured threshold `T`:
    /// `[evidence_hash, pool_id]`. `T` must equal `sender_commitments.len()`.
    pub fn public_inputs<const T: usize>(&self) -> Result<Vec<BlsFr>, FaultEvidenceError> {
        if self.sender_commitments.len() != T {
            return Err(FaultEvidenceError::ThresholdMismatch {
                expected: T,
                got: self.sender_commitments.len(),
            });
        }
        let w = self.witness()?;
        Ok(round2_digest_fault_public_inputs::<T, DKG_INDEX_BITS>(
            round2_params(),
            &w,
        ))
    }

    /// The 32-byte `evidence_hash` for the configured threshold `T` = the first
    /// circuit public input. `T` must equal `sender_commitments.len()`.
    pub fn evidence_hash<const T: usize>(&self) -> Result<[u8; 32], FaultEvidenceError> {
        Ok(digest_bytes(self.public_inputs::<T>()?[0]))
    }
}

/// Derive the round2 `evidence_hash` without knowing the threshold `T` at
/// compile time, dispatching on `sender_commitments.len()`. Used by the CLI,
/// which only learns the threshold at runtime. Supports DKG min_signers
/// 2..=16; add an arm for larger thresholds.
pub fn round2_evidence_hash_dyn(
    ev: &Round2ShareFaultEvidence,
) -> Result<[u8; 32], FaultEvidenceError> {
    macro_rules! dispatch {
        ($($t:literal),* $(,)?) => {
            match ev.sender_commitments.len() {
                $( $t => ev.evidence_hash::<$t>(), )*
                other => Err(FaultEvidenceError::UnsupportedThreshold(other)),
            }
        };
    }
    dispatch!(2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
}

impl EquivocationEvidence {
    /// `true` iff the two payloads actually differ (a single payload is not
    /// equivocation).
    #[must_use]
    pub fn is_equivocation(&self) -> bool {
        self.payload_a != self.payload_b
    }

    /// The descriptive `namespace_hash` for this namespace.
    #[must_use]
    pub fn namespace_hash(&self) -> [u8; 32] {
        namespace_hash(self.phase, self.epoch, self.threshold, self.attempt)
    }

    /// The canonical namespace header both payloads must carry:
    /// `TAG ‖ epoch ‖ threshold ‖ attempt ‖ pool_id`.
    fn expected_header(&self) -> Vec<u8> {
        let mut h = Vec::with_capacity(self.phase.tag().len() + 24 + POOL_ID_LEN);
        h.extend_from_slice(self.phase.tag());
        h.extend_from_slice(&self.epoch.to_be_bytes());
        h.extend_from_slice(&self.threshold.to_be_bytes());
        h.extend_from_slice(&self.attempt.to_be_bytes());
        h.extend_from_slice(&self.accused_pool_id);
        h
    }

    /// Reproduce the equivocation policy's checks (tech-doc §9.2): both payloads
    /// belong to this `(phase, epoch, threshold, attempt, pool_id)` namespace,
    /// both signatures verify under `bifrost_id_pk`, and the payloads differ.
    pub fn verify(&self) -> Result<(), FaultEvidenceError> {
        if !self.is_equivocation() {
            return Err(FaultEvidenceError::NotEquivocation);
        }
        let header = self.expected_header();
        if !self.payload_a.starts_with(&header) || !self.payload_b.starts_with(&header) {
            return Err(FaultEvidenceError::NamespaceMismatch);
        }
        verify_sig(&self.bifrost_id_pk, &self.payload_a, &self.signature_a)?;
        verify_sig(&self.bifrost_id_pk, &self.payload_b, &self.signature_b)?;
        Ok(())
    }

    /// `evidence_hash = blake2b_256(domain ‖ len(lo) ‖ lo ‖ len(hi) ‖ hi)` —
    /// order-independent and byte-compatible with `fault_verifier_equivocation`.
    #[must_use]
    pub fn evidence_hash(&self) -> [u8; 32] {
        let (lo, hi) = if self.payload_a <= self.payload_b {
            (&self.payload_a, &self.payload_b)
        } else {
            (&self.payload_b, &self.payload_a)
        };
        let mut buf = Vec::with_capacity(EQUIVOCATION_DOMAIN.len() + 16 + lo.len() + hi.len());
        buf.extend_from_slice(EQUIVOCATION_DOMAIN);
        buf.extend_from_slice(&(lo.len() as u64).to_be_bytes());
        buf.extend_from_slice(lo);
        buf.extend_from_slice(&(hi.len() as u64).to_be_bytes());
        buf.extend_from_slice(hi);
        blake2b_256(&buf)
    }
}

/// Which DKG round a namespace belongs to (the spec's domain tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespacePhase {
    Round1,
    Round2,
}

impl NamespacePhase {
    /// The spec phase tag, identical to `http::canonical`'s `TAG_R{1,2}`.
    #[must_use]
    pub fn tag(self) -> &'static [u8] {
        match self {
            NamespacePhase::Round1 => b"bifrost-dkg-r1",
            NamespacePhase::Round2 => b"bifrost-dkg-r2",
        }
    }
}

/// The descriptive `namespace_hash` datum field:
/// `blake2b_256(phase ‖ epoch ‖ threshold ‖ attempt)` (each integer 8-byte
/// big-endian), per tech-doc §9.1 (txid omitted for DKG namespaces). Not
/// validated on-chain today.
#[must_use]
pub fn namespace_hash(phase: NamespacePhase, epoch: u64, threshold: u64, attempt: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(phase.tag().len() + 24);
    buf.extend_from_slice(phase.tag());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&threshold.to_be_bytes());
    buf.extend_from_slice(&attempt.to_be_bytes());
    blake2b_256(&buf)
}

// ---------------------------------------------------------------------------
// Real ZK proof generation
// ---------------------------------------------------------------------------

/// A generated DKG fault proof. Carries everything a §9.2 direct-fault
/// submission needs: the accused `pool_id`, the `evidence_hash` (public input
/// 0), the `message_hash` the accused signed, that signature, and the accused
/// key — plus the proof and raw public instances.
#[derive(Debug, Clone)]
pub struct DkgFaultProof {
    pub accused_pool_id: [u8; POOL_ID_LEN],
    pub evidence_hash: [u8; 32],
    pub message_hash: [u8; 32],
    pub payload_signature: [u8; 64],
    pub bifrost_id_pk: [u8; 32],
    pub public_instances: Vec<BlsFr>,
    pub proof: Vec<u8>,
}

/// Generate a fixed-seed KZG SRS sized for `params`.
///
/// INSECURE — the toxic waste of a deterministic setup is recoverable. Use
/// ONLY for tests / local proving. Production must load a real ceremony SRS
/// (e.g. perpetual powers of tau) of degree ≥ `params.degree`.
#[must_use]
pub fn insecure_test_srs(params: AxiomDkgCircuitParams) -> ParamsKZG<Bls12> {
    ParamsKZG::<Bls12>::setup(params.degree, StdRng::seed_from_u64(2))
}

fn keygen(
    srs: &ParamsKZG<Bls12>,
    keygen_builder: RangeCircuitBuilder<BlsFr>,
) -> (ProvingKey<G1Affine>, Vec<Vec<usize>>) {
    let vk = keygen_vk(srs, &keygen_builder).expect("vkey generation");
    let pk = keygen_pk(srs, vk, &keygen_builder).expect("pkey generation");
    let break_points = keygen_builder.break_points();
    (pk, break_points)
}

fn gen_proof<C: Circuit<BlsFr>>(
    srs: &ParamsKZG<Bls12>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    public_instances: &[BlsFr],
) -> Vec<u8> {
    let rng = StdRng::seed_from_u64(1);
    let instances: &[&[BlsFr]] = &[public_instances];
    let mut transcript = CardanoBlake2bWrite::<_, G1Affine>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bls12>,
        ProverSHPLONK<'_, Bls12>,
        Challenge255<_>,
        _,
        CardanoBlake2bWrite<Vec<u8>, G1Affine>,
        _,
    >(srs, pk, &[circuit], &[instances], rng, &mut transcript)
    .expect("proof generation");
    transcript.finalize()
}

fn verify(
    srs: &ParamsKZG<Bls12>,
    pk: &ProvingKey<G1Affine>,
    proof: &[u8],
    public_instances: &[BlsFr],
) -> Result<(), FaultEvidenceError> {
    let verifier_params = srs.verifier_params();
    let strategy = SingleStrategy::new(srs);
    let instances: &[&[BlsFr]] = &[public_instances];
    let mut transcript = CardanoBlake2bRead::<_, G1Affine>::init(proof);
    verify_proof::<
        KZGCommitmentScheme<Bls12>,
        VerifierSHPLONK<'_, Bls12>,
        Challenge255<G1Affine>,
        CardanoBlake2bRead<&[u8], G1Affine>,
        SingleStrategy<'_, Bls12>,
    >(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[instances],
        &mut transcript,
    )
    .map_err(|_| FaultEvidenceError::ProofSelfVerifyFailed)
}

/// Generate a proof that a Round 1 PoK is invalid. First confirms the accused
/// signed the payload (`SignatureInvalid` otherwise) — heimdall never proves a
/// fault against a payload the accused did not author. Self-verifies before
/// returning. EXPENSIVE (k=22 keygen + prove).
pub fn prove_round1_pok_fault(
    srs: &ParamsKZG<Bls12>,
    evidence: &Round1PokFaultEvidence,
) -> Result<DkgFaultProof, FaultEvidenceError> {
    evidence.verify_payload_signature()?;
    let params = round1_params();
    let witness = evidence.witness()?;
    if round1_digest_residual(&witness) == witness.transcript_r {
        return Err(FaultEvidenceError::NotAFault);
    }
    let (keygen_builder, stats) = build_round1_digest_fault_keygen_circuit(params, &witness);
    let (pk, break_points) = keygen(srs, keygen_builder);
    let (prover_builder, public_instances) = build_round1_digest_fault_prover_circuit(
        stats.config_params,
        break_points,
        params,
        &witness,
    );
    let proof = gen_proof(srs, &pk, prover_builder, &public_instances);
    verify(srs, &pk, &proof, &public_instances)?;
    Ok(DkgFaultProof {
        accused_pool_id: evidence.accused_pool_id,
        evidence_hash: digest_bytes(public_instances[0]),
        message_hash: evidence.message_hash(),
        payload_signature: evidence.payload_signature,
        bifrost_id_pk: evidence.bifrost_id_pk,
        public_instances,
        proof,
    })
}

/// Generate a proof that a Round 2 share is inconsistent with the sender's
/// commitments. First confirms the accused sender signed the Round 2 payload.
/// `T` must equal `sender_commitments.len()`. Self-verifies before returning.
/// EXPENSIVE (k=18 keygen + prove).
pub fn prove_round2_share_fault<const T: usize>(
    srs: &ParamsKZG<Bls12>,
    evidence: &Round2ShareFaultEvidence,
) -> Result<DkgFaultProof, FaultEvidenceError> {
    if evidence.sender_commitments.len() != T {
        return Err(FaultEvidenceError::ThresholdMismatch {
            expected: T,
            got: evidence.sender_commitments.len(),
        });
    }
    evidence.verify_payload_signature()?;
    let params = round2_params();
    let witness = evidence.witness()?;
    if is_identity(&round2_residual(&witness)) {
        return Err(FaultEvidenceError::NotAFault);
    }
    let (keygen_builder, stats) =
        build_round2_digest_fault_keygen_circuit::<T, DKG_INDEX_BITS>(params, &witness);
    let (pk, break_points) = keygen(srs, keygen_builder);
    let (prover_builder, public_instances) = build_round2_digest_fault_prover_circuit::<
        T,
        DKG_INDEX_BITS,
    >(
        stats.config_params, break_points, params, &witness
    );
    let proof = gen_proof(srs, &pk, prover_builder, &public_instances);
    verify(srs, &pk, &proof, &public_instances)?;
    Ok(DkgFaultProof {
        accused_pool_id: evidence.accused_pool_id,
        evidence_hash: digest_bytes(public_instances[0]),
        message_hash: evidence.message_hash(),
        payload_signature: evidence.round2_signature,
        bifrost_id_pk: evidence.bifrost_id_pk,
        public_instances,
        proof,
    })
}

/// Generate a Round 2 share-fault proof when the DKG threshold is only known at
/// runtime. Supports DKG min_signers 2..=16, matching
/// [`round2_evidence_hash_dyn`].
pub fn prove_round2_share_fault_dyn(
    srs: &ParamsKZG<Bls12>,
    evidence: &Round2ShareFaultEvidence,
) -> Result<DkgFaultProof, FaultEvidenceError> {
    macro_rules! dispatch {
        ($($t:literal),* $(,)?) => {
            match evidence.sender_commitments.len() {
                $( $t => prove_round2_share_fault::<$t>(srs, evidence), )*
                other => Err(FaultEvidenceError::UnsupportedThreshold(other)),
            }
        };
    }
    dispatch!(2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::ban_list::fault_token_name;
    use crate::cardano::blueprint::{self, ParameterizedScript};
    use crate::cardano::fault_proof::{
        EquivocationEvidence as OnchainEquivocationEvidence, FaultProofEvidence,
        FaultProofMintRequest, Round1InvalidPayloadEvidence, Round2InvalidPayloadEvidence,
        build_fault_proof_mint_tx,
    };
    use crate::cardano::hash::blake2b_256;
    use crate::cardano::publish::WalletUtxo;
    use crate::cardano::wallet::{derive_payment_key, wallet_address};
    use crate::circuits::dkg_fault::{
        axiom_scalar_from_be_bytes, be_bytes_from_fq, pool_id_public_input, round1_message_digest,
        round2_message_digest,
    };
    use crate::frost::participant;
    use crate::http::frost_bridge;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use frost_secp256k1_tr::Identifier;
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeMap;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// Threshold of the synthetic fixtures: `dkg_part1(_, 3, 2)` ⇒ 2 commitments.
    const FIXTURE_T: usize = 2;
    const EPOCH: u64 = 7;
    const THRESHOLD: u64 = 51;
    const ATTEMPT: u64 = 0;
    const POOL: [u8; POOL_ID_LEN] = [0x11; POOL_ID_LEN];

    fn corrupt_scalar_be(bytes: &[u8; 32]) -> [u8; 32] {
        // +1 in the scalar field — guaranteed to change the value and stay
        // canonical, flipping a valid payload into an invalid one.
        be_bytes_from_fq(axiom_scalar_from_be_bytes(bytes) + Fq::ONE)
    }

    /// A fresh accused keypair: returns (keypair, x-only bifrost_id_pk).
    fn accused_key() -> (Secp256k1<bitcoin::secp256k1::All>, Keypair, [u8; 32]) {
        let secp = Secp256k1::new();
        let (sk, _pk) = secp.generate_keypair(&mut OsRng);
        let kp = Keypair::from_secret_key(&secp, &sk);
        let xonly = kp.x_only_public_key().0.serialize();
        (secp, kp, xonly)
    }

    /// A Round 1 PoK evidence, signed by the accused. `corrupt` flips μ so the
    /// PoK is invalid (`μ·G − c·φ₀ = R + G ≠ R`); the accused signs the payload
    /// as published (a malicious SPO authenticating a bad PoK).
    fn round1_evidence(corrupt: bool) -> Round1PokFaultEvidence {
        let mut rng = ChaCha20Rng::seed_from_u64(0xF0);
        let identifier = 1u16;
        let (_secret, pkg) =
            participant::dkg_part1(Identifier::try_from(identifier).unwrap(), 3, 2, &mut rng)
                .unwrap();
        let (commitments, mut sigma_i) = frost_bridge::round1_fields(&pkg).unwrap();
        if corrupt {
            let mu: [u8; 32] = sigma_i[32..64].try_into().unwrap();
            sigma_i[32..64].copy_from_slice(&corrupt_scalar_be(&mu));
        }
        let evidence_hash =
            round1_evidence_hash_from_fields(&POOL, identifier, &commitments, &sigma_i).unwrap();
        let canonical = canonical::round1(
            EPOCH,
            THRESHOLD,
            ATTEMPT,
            &POOL,
            &commitments,
            &sigma_i,
            &evidence_hash,
        );
        let (secp, kp, bifrost_id_pk) = accused_key();
        let payload_signature = auth::sign_payload(&secp, &kp, &canonical);
        Round1PokFaultEvidence {
            epoch: EPOCH,
            threshold: THRESHOLD,
            attempt: ATTEMPT,
            accused_pool_id: POOL,
            bifrost_id_pk,
            identifier,
            commitments,
            sigma_i,
            payload_signature,
        }
    }

    fn round1_fault_evidence() -> Round1PokFaultEvidence {
        round1_evidence(true)
    }

    /// A genuinely-invalid Round 2 share, signed by the accused sender. The
    /// Round 2 canonical payload carries one share entry whose ciphertext field
    /// holds the corrupted share bytes (the encrypted↔decrypted binding is the
    /// documented upstream gap).
    fn round2_fault_evidence() -> Round2ShareFaultEvidence {
        let mut rng = ChaCha20Rng::seed_from_u64(0xF1);
        let ids: Vec<Identifier> = (1..=3u16)
            .map(|i| Identifier::try_from(i).unwrap())
            .collect();
        let mut secrets = BTreeMap::new();
        let mut packages = BTreeMap::new();
        for &id in &ids {
            let (s, p) = participant::dkg_part1(id, 3, 2, &mut rng).unwrap();
            secrets.insert(id, s);
            packages.insert(id, p);
        }
        let sender = ids[0];
        let recipient = ids[1];
        let others: BTreeMap<_, _> = packages
            .iter()
            .filter(|&(&id, _)| id != sender)
            .map(|(&id, p)| (id, p.clone()))
            .collect();
        let (_s2, round2) =
            participant::dkg_part2(secrets.remove(&sender).unwrap(), &others).unwrap();
        let share = frost_bridge::round2_share_bytes(&round2[&recipient]).unwrap();
        let (sender_commitments, sender_sigma) =
            frost_bridge::round1_fields(&packages[&sender]).unwrap();
        let bad_share = corrupt_scalar_be(&share);
        let evidence_hash =
            round2_evidence_hash_from_fields_dyn(&POOL, 2, &sender_commitments, &bad_share)
                .unwrap();
        let (secp, kp, bifrost_id_pk) = accused_key();
        let round1_evidence_hash =
            round1_evidence_hash_from_fields(&POOL, 1, &sender_commitments, &sender_sigma).unwrap();
        let canonical_round1_bytes = canonical::round1(
            EPOCH,
            THRESHOLD,
            ATTEMPT,
            &POOL,
            &sender_commitments,
            &sender_sigma,
            &round1_evidence_hash,
        );
        let round1_signature = auth::sign_payload(&secp, &kp, &canonical_round1_bytes);
        let entry = canonical::ShareEntry {
            recipient_pool_id: [0x22; POOL_ID_LEN],
            recipient_identifier: 2,
            ephemeral_pk: sender_commitments[0],
            ciphertext: bad_share,
            pad_commit: blake2b_256(&[0u8; 32]),
            evidence_hash,
        };
        let round2_canonical_bytes = canonical::round2(EPOCH, THRESHOLD, ATTEMPT, &POOL, &[entry]);
        let round2_signature = auth::sign_payload(&secp, &kp, &round2_canonical_bytes);
        Round2ShareFaultEvidence {
            epoch: EPOCH,
            threshold: THRESHOLD,
            attempt: ATTEMPT,
            accused_pool_id: POOL,
            bifrost_id_pk,
            recipient_index: 2,
            round2_entry_index: 0,
            sender_commitments,
            canonical_round1_bytes,
            round1_signature,
            share: bad_share,
            pad: [0u8; 32],
            round2_canonical_bytes,
            round2_signature,
        }
    }

    /// Two distinct Round 1 payloads for the same namespace, both signed by one
    /// accused key — a genuine equivocation.
    fn equivocation_evidence() -> EquivocationEvidence {
        let (secp, kp, bifrost_id_pk) = accused_key();
        let mk = |seed: u64| {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let (_s, pkg) =
                participant::dkg_part1(Identifier::try_from(1u16).unwrap(), 3, 2, &mut rng)
                    .unwrap();
            let (commitments, sigma_i) = frost_bridge::round1_fields(&pkg).unwrap();
            let evidence_hash =
                round1_evidence_hash_from_fields(&POOL, 1, &commitments, &sigma_i).unwrap();
            let bytes = canonical::round1(
                EPOCH,
                THRESHOLD,
                ATTEMPT,
                &POOL,
                &commitments,
                &sigma_i,
                &evidence_hash,
            );
            let sig = auth::sign_payload(&secp, &kp, &bytes);
            (bytes, sig)
        };
        let (payload_a, signature_a) = mk(0xA1);
        let (payload_b, signature_b) = mk(0xB2);
        EquivocationEvidence {
            epoch: EPOCH,
            threshold: THRESHOLD,
            attempt: ATTEMPT,
            phase: NamespacePhase::Round1,
            accused_pool_id: POOL,
            bifrost_id_pk,
            payload_a,
            signature_a,
            payload_b,
            signature_b,
        }
    }

    fn fault_verifier_script() -> ParameterizedScript {
        // Parameterized by a dummy spos_registry hash (the registry binding is
        // verified on-chain, not by this builder).
        let code = include_str!("../../tests/fixtures/fault_verifier_code.txt");
        blueprint::apply_params(code.trim(), &[crate::cardano::plutus::bytes(&[0x11u8; 28])])
            .unwrap()
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

    fn public_inputs(evidence_hash: [u8; 32], pool_id: [u8; POOL_ID_LEN]) -> Vec<Vec<u8>> {
        vec![evidence_hash.to_vec(), pool_id.to_vec()]
    }

    /// The pipeline's core claim: a derived `evidence_hash` threads into the
    /// minted FaultProof token name exactly as `blake2b_256(pool_id || hash)`.
    fn assert_mints_with(evidence_hash: [u8; 32], evidence: FaultProofEvidence<'_>) {
        let accused_pool_id = evidence.accused_pool_id().to_vec();
        let script = fault_verifier_script();
        let key = derive_payment_key(TEST_MNEMONIC).unwrap();
        let addr = wallet_address(&key);
        let utxos = wallet_utxos();
        let reg_tx = "cc".repeat(32);
        let built = build_fault_proof_mint_tx(&FaultProofMintRequest {
            fault_verifier_script: &script,
            fault_verifier_ref_script: None,
            evidence,
            registration_ref: (&reg_tx, 0),
            wallet_address: &addr,
            wallet_utxos: &utxos,
            key: &key,
            cost_models: None,
        })
        .expect("mint tx builds from derived evidence_hash");
        assert_eq!(
            built.token_name,
            fault_token_name(&accused_pool_id, &evidence_hash),
            "token name must bind the derived evidence_hash"
        );
        assert!(!built.signed_tx_hex.is_empty());
    }

    /// Equivocation mints via the `EquivocationProof` redeemer, carrying the
    /// two signed payloads from the evidence.
    fn assert_equivocation_mints(ev: &EquivocationEvidence) {
        let evidence_hash = ev.evidence_hash();
        assert_mints_with(
            evidence_hash,
            FaultProofEvidence::Equivocation(OnchainEquivocationEvidence {
                accused_pool_id: &ev.accused_pool_id,
                payload_a: &ev.payload_a,
                signature_a: &ev.signature_a,
                payload_b: &ev.payload_b,
                signature_b: &ev.signature_b,
                evidence_hash: &evidence_hash,
            }),
        );
    }

    #[test]
    fn round1_evidence_is_a_fault_and_hash_matches_digest() {
        let ev = round1_fault_evidence();
        assert!(ev.is_fault().unwrap(), "corrupted PoK must be a fault");
        let w = ev.witness().unwrap();
        let expect = digest_bytes(round1_message_digest(round1_params(), &w));
        assert_eq!(ev.evidence_hash().unwrap(), expect);
        let public_inputs = ev.public_inputs().unwrap();
        assert_eq!(public_inputs.len(), 2);
        assert_eq!(digest_bytes(public_inputs[0]), expect);
        assert_eq!(public_inputs[1], pool_id_public_input(&POOL));
    }

    #[test]
    fn round1_honest_pok_is_not_a_fault() {
        let ev = round1_evidence(false);
        assert!(!ev.is_fault().unwrap(), "honest PoK is not a fault");
    }

    // ---- authentication envelope (spec §9.2) -------------------------------

    #[test]
    fn round1_message_hash_is_sha256_of_canonical() {
        let ev = round1_fault_evidence();
        assert_eq!(ev.message_hash(), sha256(&ev.canonical_bytes().unwrap()));
    }

    #[test]
    fn round1_accused_signature_verifies() {
        let ev = round1_fault_evidence();
        ev.verify_payload_signature()
            .expect("accused signed the published payload");
    }

    #[test]
    fn round1_tampered_signature_is_rejected() {
        let mut ev = round1_fault_evidence();
        ev.payload_signature[0] ^= 0x01;
        assert_eq!(
            ev.verify_payload_signature(),
            Err(FaultEvidenceError::SignatureInvalid)
        );
    }

    #[test]
    fn round1_wrong_key_is_rejected() {
        let mut ev = round1_fault_evidence();
        ev.bifrost_id_pk = accused_key().2; // a different identity
        assert_eq!(
            ev.verify_payload_signature(),
            Err(FaultEvidenceError::SignatureInvalid)
        );
    }

    #[test]
    fn round2_accused_signature_verifies() {
        let ev = round2_fault_evidence();
        ev.verify_payload_signature().expect("sender signed round2");
        assert_eq!(ev.message_hash(), sha256(&ev.round2_canonical_bytes));
    }

    #[test]
    fn prove_refuses_payload_the_accused_did_not_sign() {
        // Tiny SRS — never reached: the signature gate fails before keygen.
        let tiny = insecure_test_srs(AxiomDkgCircuitParams {
            degree: 4,
            ..round1_params()
        });
        let mut ev = round1_fault_evidence();
        ev.payload_signature = [0u8; 64];
        assert_eq!(
            prove_round1_pok_fault(&tiny, &ev).unwrap_err(),
            FaultEvidenceError::SignatureInvalid
        );
    }

    #[test]
    fn round2_evidence_is_a_fault_and_hash_matches_digest() {
        let ev = round2_fault_evidence();
        assert!(ev.is_fault().unwrap(), "corrupted share must be a fault");
        let w = ev.witness().unwrap();
        let expect = digest_bytes(round2_message_digest::<FIXTURE_T, DKG_INDEX_BITS>(
            round2_params(),
            &w,
        ));
        assert_eq!(ev.evidence_hash::<FIXTURE_T>().unwrap(), expect);
        let public_inputs = ev.public_inputs::<FIXTURE_T>().unwrap();
        assert_eq!(public_inputs.len(), 2);
        assert_eq!(digest_bytes(public_inputs[0]), expect);
        assert_eq!(public_inputs[1], pool_id_public_input(&POOL));
    }

    #[test]
    fn round2_threshold_mismatch_is_rejected() {
        let ev = round2_fault_evidence(); // 2 commitments
        assert_eq!(
            ev.evidence_hash::<3>(),
            Err(FaultEvidenceError::ThresholdMismatch {
                expected: 3,
                got: 2
            })
        );
    }

    // ---- equivocation ------------------------------------------------------

    #[test]
    fn equivocation_verify_accepts_two_signed_conflicting_payloads() {
        let ev = equivocation_evidence();
        assert!(ev.is_equivocation());
        ev.verify().expect("two valid conflicting signed payloads");
    }

    #[test]
    fn equivocation_rejects_bad_signature() {
        let mut ev = equivocation_evidence();
        ev.signature_b[0] ^= 0x01;
        assert_eq!(ev.verify(), Err(FaultEvidenceError::SignatureInvalid));
    }

    #[test]
    fn equivocation_rejects_cross_namespace_payloads() {
        let mut ev = equivocation_evidence();
        // Re-sign payload_b under a DIFFERENT attempt ⇒ different namespace
        // header ⇒ not the same namespace.
        let (secp, kp, pk) = accused_key();
        let mut rng = ChaCha20Rng::seed_from_u64(0xC9);
        let (_s, pkg) =
            participant::dkg_part1(Identifier::try_from(1u16).unwrap(), 3, 2, &mut rng).unwrap();
        let (commitments, sigma_i) = frost_bridge::round1_fields(&pkg).unwrap();
        let evidence_hash =
            round1_evidence_hash_from_fields(&POOL, 1, &commitments, &sigma_i).unwrap();
        let other_ns = canonical::round1(
            EPOCH,
            THRESHOLD,
            ATTEMPT + 1,
            &POOL,
            &commitments,
            &sigma_i,
            &evidence_hash,
        );
        ev.bifrost_id_pk = pk;
        ev.signature_a = auth::sign_payload(&secp, &kp, &ev.payload_a); // keep a valid
        ev.signature_b = auth::sign_payload(&secp, &kp, &other_ns);
        ev.payload_b = other_ns;
        assert_eq!(ev.verify(), Err(FaultEvidenceError::NamespaceMismatch));
    }

    #[test]
    fn equivocation_hash_is_order_independent() {
        let ev = equivocation_evidence();
        let swapped = EquivocationEvidence {
            payload_a: ev.payload_b.clone(),
            signature_a: ev.signature_b,
            payload_b: ev.payload_a.clone(),
            signature_b: ev.signature_a,
            ..ev.clone()
        };
        assert_eq!(ev.evidence_hash(), swapped.evidence_hash());
    }

    #[test]
    fn equivocation_hash_matches_bifrost_policy_vector() {
        let payload_a = hex::decode(
            "626966726f73742d646b672d723100000000000000010000000000000033000000000000000001010101010101010101010101010101010101010101010101010101021111111111111111111111111111111111111111111111111111111111111111121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121313131313131313131313131313131313131313131313131313131313131313",
        )
        .unwrap();
        let payload_b = hex::decode(
            "626966726f73742d646b672d723100000000000000010000000000000033000000000000000001010101010101010101010101010101010101010101010101010101022222222222222222222222222222222222222222222222222222222222222222232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232424242424242424242424242424242424242424242424242424242424242424",
        )
        .unwrap();
        let expected =
            hex::decode("d80be6e612c4afe7842f224d0aedfcaa9d827c9c8e890467e6fbe8955fe8462c")
                .unwrap();
        let ev = EquivocationEvidence {
            phase: NamespacePhase::Round1,
            epoch: 1,
            threshold: 51,
            attempt: 0,
            accused_pool_id: [0x01; POOL_ID_LEN],
            bifrost_id_pk: [0u8; 32],
            payload_a,
            signature_a: [0u8; 64],
            payload_b,
            signature_b: [0u8; 64],
        };
        assert_eq!(ev.evidence_hash().as_slice(), expected.as_slice());
    }

    #[test]
    fn bad_point_in_evidence_errors_not_panics() {
        let mut ev = round1_fault_evidence();
        ev.commitments = vec![[0xFFu8; 33]]; // not a valid SEC1 point
        assert_eq!(ev.witness().unwrap_err(), FaultEvidenceError::BadPoint);
    }

    // ---- full pipeline: synthetic evidence -> evidence_hash -> mint tx -----

    #[test]
    fn round1_invalid_payload_evidence_hash_mints_fault_proof() {
        let ev = round1_fault_evidence();
        let evidence_hash = ev.evidence_hash().unwrap();
        let canonical = ev.canonical_bytes().unwrap();
        let public_inputs = public_inputs(evidence_hash, ev.accused_pool_id);
        assert_mints_with(
            evidence_hash,
            FaultProofEvidence::Round1InvalidPayload(Round1InvalidPayloadEvidence {
                accused_pool_id: &ev.accused_pool_id,
                canonical_round1_bytes: &canonical,
                payload_signature: &ev.payload_signature,
                halo2_proof: &[0xCC; 96],
                halo2_public_inputs: &public_inputs,
            }),
        );
    }

    #[test]
    fn round2_invalid_payload_evidence_hash_mints_fault_proof() {
        let ev = round2_fault_evidence();
        let evidence_hash = ev.evidence_hash::<FIXTURE_T>().unwrap();
        let public_inputs = public_inputs(evidence_hash, ev.accused_pool_id);
        assert_mints_with(
            evidence_hash,
            FaultProofEvidence::Round2InvalidPayload(Round2InvalidPayloadEvidence {
                accused_pool_id: &ev.accused_pool_id,
                canonical_round1_bytes: &ev.canonical_round1_bytes,
                round1_signature: &ev.round1_signature,
                canonical_round2_bytes: &ev.round2_canonical_bytes,
                round2_signature: &ev.round2_signature,
                round2_entry_index: ev.round2_entry_index,
                pad: &ev.pad,
                opened_share: &ev.share,
                halo2_proof: &[0xCC; 96],
                halo2_public_inputs: &public_inputs,
            }),
        );
    }

    #[test]
    fn equivocation_evidence_hash_mints_fault_proof() {
        assert_equivocation_mints(&equivocation_evidence());
    }

    // ---- the full ZK path (slow: k=18/k=22 keygen + prove) -----------------

    #[test]
    #[ignore = "generates real Halo2/KZG proofs (k=18 + k=22) — minutes; run with --ignored"]
    fn full_pipeline_round1_proof_then_mint() {
        let ev = round1_fault_evidence();
        let srs = insecure_test_srs(round1_params());
        let proof = prove_round1_pok_fault(&srs, &ev).expect("round1 fault proof");
        assert!(!proof.proof.is_empty());
        assert_eq!(proof.accused_pool_id, ev.accused_pool_id);
        assert_eq!(proof.evidence_hash, ev.evidence_hash().unwrap());
        assert_eq!(proof.message_hash, ev.message_hash());
        assert_eq!(proof.bifrost_id_pk, ev.bifrost_id_pk);
        let canonical = ev.canonical_bytes().unwrap();
        let public_inputs = public_inputs(proof.evidence_hash, proof.accused_pool_id);
        assert_mints_with(
            proof.evidence_hash,
            FaultProofEvidence::Round1InvalidPayload(Round1InvalidPayloadEvidence {
                accused_pool_id: &proof.accused_pool_id,
                canonical_round1_bytes: &canonical,
                payload_signature: &proof.payload_signature,
                halo2_proof: &proof.proof,
                halo2_public_inputs: &public_inputs,
            }),
        );
    }

    #[test]
    #[ignore = "generates a real Halo2/KZG proof (k=18) — slow; run with --ignored"]
    fn full_pipeline_round2_proof_then_mint() {
        let ev = round2_fault_evidence();
        let srs = insecure_test_srs(round2_params());
        let proof = prove_round2_share_fault::<FIXTURE_T>(&srs, &ev).expect("round2 fault proof");
        assert!(!proof.proof.is_empty());
        assert_eq!(proof.accused_pool_id, ev.accused_pool_id);
        assert_eq!(
            proof.evidence_hash,
            ev.evidence_hash::<FIXTURE_T>().unwrap()
        );
        assert_eq!(proof.message_hash, ev.message_hash());
        let public_inputs = public_inputs(proof.evidence_hash, proof.accused_pool_id);
        assert_mints_with(
            proof.evidence_hash,
            FaultProofEvidence::Round2InvalidPayload(Round2InvalidPayloadEvidence {
                accused_pool_id: &proof.accused_pool_id,
                canonical_round1_bytes: &ev.canonical_round1_bytes,
                round1_signature: &ev.round1_signature,
                canonical_round2_bytes: &ev.round2_canonical_bytes,
                round2_signature: &proof.payload_signature,
                round2_entry_index: ev.round2_entry_index,
                pad: &ev.pad,
                opened_share: &ev.share,
                halo2_proof: &proof.proof,
                halo2_public_inputs: &public_inputs,
            }),
        );
    }
}
