//! DKG fault-proof circuits using Axiom's Halo2 stack.
//!
//! The circuits prove only the secp256k1 computations that are too expensive
//! for Plutus. The original builders expose the computed residual point as
//! public instances. The digest builders bind the private DKG message to a
//! Poseidon public input and prove the fault predicate inside the circuit.

use halo2_base::{
    AssignedValue, Context,
    gates::{
        GateInstructions, RangeChip, RangeInstructions,
        circuit::{BaseCircuitParams, CircuitBuilderStage, builder::RangeCircuitBuilder},
    },
    halo2_proofs::halo2curves::{
        CurveAffine,
        bls12_381::Fr as BlsFr,
        ff::{Field, PrimeField},
        group::{Curve, prime::PrimeCurveAffine},
        secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine},
    },
    poseidon::hasher::{PoseidonHasher, spec::OptimizedPoseidonSpec},
    utils::CurveAffineExt,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::{EcPoint, EccChip, ec_double, ec_select, ec_sub_strict, multi_scalar_multiply},
    fields::FieldChip,
    secp256k1::{FpChip, FqChip},
};
use k256::{
    AffinePoint as K256AffinePoint, ProjectivePoint as K256ProjectivePoint, Scalar as K256Scalar,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use pse_poseidon::Poseidon;
use sha2::{Digest, Sha256};

const POSEIDON_T: usize = 3;
const POSEIDON_RATE: usize = 2;
const POSEIDON_FULL_ROUNDS: usize = 8;
const POSEIDON_PARTIAL_ROUNDS: usize = 57;
const POSEIDON_SECURE_MDS: usize = 0;

const DKG_FAULT_MESSAGE_DOMAIN: u64 = 0x4845_494d_4441_4c4c;
const DKG_FAULT_MESSAGE_VERSION: u64 = 1;
const DKG_ROUND1_MESSAGE_TAG: u64 = 1;
const DKG_ROUND2_MESSAGE_TAG: u64 = 2;
const HDKG_CONTEXT: &[u8] = b"FROST-secp256k1-SHA256-TR-v1";
const HDKG_LABEL: &[u8] = b"dkg";
const HDKG_DST_LEN: u8 = (HDKG_CONTEXT.len() + HDKG_LABEL.len()) as u8;
const HDKG_OKM_BYTES: usize = 48;
const SECP_SCALAR_BITS: usize = 256;
const SECP_SCALAR_CHUNK_BYTES: usize = 24;
const BYTE_BITS: usize = 8;
const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_WORD_BITS: usize = 32;

type AssignedBit = AssignedValue<BlsFr>;
type AssignedByte = Vec<AssignedBit>;
type AssignedWord = Vec<AssignedBit>;

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone, Copy, Debug)]
pub struct AxiomDkgCircuitParams {
    pub degree: u32,
    pub lookup_bits: usize,
    pub advice_columns: usize,
    pub lookup_advice_columns: usize,
    pub fixed_columns: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
    pub window_bits: usize,
    pub unusable_rows: usize,
}

impl Default for AxiomDkgCircuitParams {
    fn default() -> Self {
        Self {
            degree: 21,
            lookup_bits: 17,
            advice_columns: 4,
            lookup_advice_columns: 1,
            fixed_columns: 1,
            limb_bits: 88,
            num_limbs: 3,
            window_bits: 4,
            unusable_rows: 9,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CircuitStats {
    pub total_advice_cells: usize,
    pub enabled_gate_constraints: usize,
    pub total_lookup_cells: usize,
    pub total_fixed_cells: usize,
    pub config_params: BaseCircuitParams,
}

#[derive(Clone, Copy, Debug)]
pub struct DkgRound1PokFaultWitness {
    pub mu: Fq,
    pub challenge: Fq,
    pub phi0: Secp256k1Affine,
}

#[derive(Clone, Copy, Debug)]
pub struct DkgRound1PokDigestFaultWitness {
    pub identifier: u64,
    pub mu: Fq,
    pub challenge: Fq,
    pub phi0: Secp256k1Affine,
    pub transcript_r: Secp256k1Affine,
}

#[derive(Clone, Debug)]
pub struct DkgRound2ShareFaultWitness {
    pub share: Fq,
    pub participant_index: u64,
    pub commitments: Vec<Secp256k1Affine>,
}

pub fn build_round1_keygen_circuit(
    params: AxiomDkgCircuitParams,
    witness: &DkgRound1PokFaultWitness,
) -> (RangeCircuitBuilder<BlsFr>, CircuitStats) {
    let mut builder = keygen_builder(params);
    let range = builder.range_chip();
    let public_inputs = synthesize_round1(builder.main(0), &range, params, witness);
    builder.assigned_instances[0].extend(public_inputs);
    let stats = circuit_stats(&mut builder, params);
    (builder, stats)
}

pub fn build_round1_prover_circuit(
    config_params: BaseCircuitParams,
    break_points: Vec<Vec<usize>>,
    params: AxiomDkgCircuitParams,
    witness: &DkgRound1PokFaultWitness,
) -> (RangeCircuitBuilder<BlsFr>, Vec<BlsFr>) {
    let mut builder = RangeCircuitBuilder::prover(config_params, break_points);
    builder.set_lookup_bits(params.lookup_bits);
    let range = builder.range_chip();
    let public_inputs = synthesize_round1(builder.main(0), &range, params, witness);
    builder.assigned_instances[0].extend(public_inputs);
    let instances = public_instance_values(&builder.assigned_instances[0]);
    (builder, instances)
}

pub fn build_round1_digest_fault_keygen_circuit(
    params: AxiomDkgCircuitParams,
    witness: &DkgRound1PokDigestFaultWitness,
) -> (RangeCircuitBuilder<BlsFr>, CircuitStats) {
    let mut builder = keygen_builder(params);
    let range = builder.range_chip();
    let public_inputs = synthesize_round1_digest_fault(builder.main(0), &range, params, witness);
    builder.assigned_instances[0].extend(public_inputs);
    let stats = circuit_stats(&mut builder, params);
    (builder, stats)
}

pub fn build_round1_digest_fault_prover_circuit(
    config_params: BaseCircuitParams,
    break_points: Vec<Vec<usize>>,
    params: AxiomDkgCircuitParams,
    witness: &DkgRound1PokDigestFaultWitness,
) -> (RangeCircuitBuilder<BlsFr>, Vec<BlsFr>) {
    let mut builder = RangeCircuitBuilder::prover(config_params, break_points);
    builder.set_lookup_bits(params.lookup_bits);
    let range = builder.range_chip();
    let public_inputs = synthesize_round1_digest_fault(builder.main(0), &range, params, witness);
    builder.assigned_instances[0].extend(public_inputs);
    let instances = public_instance_values(&builder.assigned_instances[0]);
    (builder, instances)
}

pub fn build_round2_keygen_circuit<const T: usize, const INDEX_BITS: usize>(
    params: AxiomDkgCircuitParams,
    witness: &DkgRound2ShareFaultWitness,
) -> (RangeCircuitBuilder<BlsFr>, CircuitStats) {
    assert_eq!(witness.commitments.len(), T);
    let mut builder = keygen_builder(params);
    let range = builder.range_chip();
    let public_inputs =
        synthesize_round2::<T, INDEX_BITS>(builder.main(0), &range, params, witness);
    builder.assigned_instances[0].extend(public_inputs);
    let stats = circuit_stats(&mut builder, params);
    (builder, stats)
}

pub fn build_round2_prover_circuit<const T: usize, const INDEX_BITS: usize>(
    config_params: BaseCircuitParams,
    break_points: Vec<Vec<usize>>,
    params: AxiomDkgCircuitParams,
    witness: &DkgRound2ShareFaultWitness,
) -> (RangeCircuitBuilder<BlsFr>, Vec<BlsFr>) {
    assert_eq!(witness.commitments.len(), T);
    let mut builder = RangeCircuitBuilder::prover(config_params, break_points);
    builder.set_lookup_bits(params.lookup_bits);
    let range = builder.range_chip();
    let public_inputs =
        synthesize_round2::<T, INDEX_BITS>(builder.main(0), &range, params, witness);
    builder.assigned_instances[0].extend(public_inputs);
    let instances = public_instance_values(&builder.assigned_instances[0]);
    (builder, instances)
}

pub fn build_round2_digest_fault_keygen_circuit<const T: usize, const INDEX_BITS: usize>(
    params: AxiomDkgCircuitParams,
    witness: &DkgRound2ShareFaultWitness,
) -> (RangeCircuitBuilder<BlsFr>, CircuitStats) {
    assert_eq!(witness.commitments.len(), T);
    let mut builder = keygen_builder(params);
    let range = builder.range_chip();
    let public_inputs =
        synthesize_round2_digest_fault::<T, INDEX_BITS>(builder.main(0), &range, params, witness);
    builder.assigned_instances[0].extend(public_inputs);
    let stats = circuit_stats(&mut builder, params);
    (builder, stats)
}

pub fn build_round2_digest_fault_prover_circuit<const T: usize, const INDEX_BITS: usize>(
    config_params: BaseCircuitParams,
    break_points: Vec<Vec<usize>>,
    params: AxiomDkgCircuitParams,
    witness: &DkgRound2ShareFaultWitness,
) -> (RangeCircuitBuilder<BlsFr>, Vec<BlsFr>) {
    assert_eq!(witness.commitments.len(), T);
    let mut builder = RangeCircuitBuilder::prover(config_params, break_points);
    builder.set_lookup_bits(params.lookup_bits);
    let range = builder.range_chip();
    let public_inputs =
        synthesize_round2_digest_fault::<T, INDEX_BITS>(builder.main(0), &range, params, witness);
    builder.assigned_instances[0].extend(public_inputs);
    let instances = public_instance_values(&builder.assigned_instances[0]);
    (builder, instances)
}

pub fn round1_residual(witness: &DkgRound1PokFaultWitness) -> Secp256k1Affine {
    let lhs = Secp256k1::generator() * witness.mu;
    let rhs = witness.phi0 * witness.challenge;
    (lhs - rhs).to_affine()
}

pub fn round1_digest_residual(witness: &DkgRound1PokDigestFaultWitness) -> Secp256k1Affine {
    let lhs = Secp256k1::generator() * witness.mu;
    let rhs = witness.phi0 * witness.challenge;
    (lhs - rhs).to_affine()
}

pub fn round1_hdk_challenge(witness: &DkgRound1PokDigestFaultWitness) -> Fq {
    let (d0, d1) = round1_hdk_scalar_chunks(witness);
    d0 * fq_two_192() + d1
}

pub fn round2_residual(witness: &DkgRound2ShareFaultWitness) -> Secp256k1Affine {
    assert!(!witness.commitments.is_empty());
    let index = Fq::from(witness.participant_index);
    let mut horner = witness
        .commitments
        .last()
        .expect("checked non-empty")
        .to_curve();
    for commitment in witness.commitments[..witness.commitments.len() - 1]
        .iter()
        .rev()
    {
        horner = commitment.to_curve() + horner * index;
    }
    (horner - Secp256k1::generator() * witness.share).to_affine()
}

pub fn is_identity(point: &Secp256k1Affine) -> bool {
    bool::from(point.is_identity())
}

pub fn round1_message_digest(
    params: AxiomDkgCircuitParams,
    witness: &DkgRound1PokDigestFaultWitness,
) -> BlsFr {
    poseidon_digest(&round1_message_elements(params, witness))
}

pub fn round1_message_elements(
    params: AxiomDkgCircuitParams,
    witness: &DkgRound1PokDigestFaultWitness,
) -> Vec<BlsFr> {
    let mut elements = Vec::with_capacity(6 + params.num_limbs * 5);
    elements.extend_from_slice(&round1_message_header(params));
    elements.push(BlsFr::from(witness.identifier));
    elements.extend_from_slice(&fq_public_limbs(witness.mu, params));
    elements.extend_from_slice(&point_public_limbs(witness.phi0, params));
    elements.extend_from_slice(&point_public_limbs(witness.transcript_r, params));
    elements
}

pub fn round2_message_digest<const T: usize, const INDEX_BITS: usize>(
    params: AxiomDkgCircuitParams,
    witness: &DkgRound2ShareFaultWitness,
) -> BlsFr {
    poseidon_digest(&round2_message_elements::<T, INDEX_BITS>(params, witness))
}

pub fn round2_message_elements<const T: usize, const INDEX_BITS: usize>(
    params: AxiomDkgCircuitParams,
    witness: &DkgRound2ShareFaultWitness,
) -> Vec<BlsFr> {
    assert!(T > 0);
    assert!(INDEX_BITS > 0);
    assert_eq!(witness.commitments.len(), T);
    assert!(witness.participant_index < (1u64 << INDEX_BITS));

    let mut elements = Vec::with_capacity(7 + params.num_limbs * (1 + 2 * T));
    elements.extend_from_slice(&round2_message_header::<T, INDEX_BITS>(params));
    elements.extend_from_slice(&fq_public_limbs(witness.share, params));
    elements.push(BlsFr::from(witness.participant_index));
    for commitment in &witness.commitments {
        elements.extend_from_slice(&point_public_limbs(*commitment, params));
    }
    elements
}

pub fn axiom_scalar_from_be_bytes(bytes: &[u8; 32]) -> Fq {
    let mut repr = *bytes;
    repr.reverse();
    Option::<Fq>::from(Fq::from_repr(repr)).expect("canonical secp256k1 scalar")
}

pub fn axiom_point_from_compressed(bytes: &[u8; 33]) -> Secp256k1Affine {
    let encoded = k256::EncodedPoint::from_bytes(bytes).expect("valid SEC1 point");
    let affine = Option::<K256AffinePoint>::from(K256AffinePoint::from_encoded_point(&encoded))
        .expect("point on secp256k1");
    axiom_point_from_k256(affine)
}

pub fn axiom_point_from_projective(point: K256ProjectivePoint) -> Secp256k1Affine {
    if point == K256ProjectivePoint::IDENTITY {
        Secp256k1Affine::identity()
    } else {
        axiom_point_from_k256(point.to_affine())
    }
}

pub fn k256_projective_from_axiom(point: Secp256k1Affine) -> K256ProjectivePoint {
    if bool::from(point.is_identity()) {
        return K256ProjectivePoint::IDENTITY;
    }

    let (x, y) = point.into_coordinates();
    let mut encoded = [0u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(&be_bytes_from_fp(x));
    encoded[33..65].copy_from_slice(&be_bytes_from_fp(y));
    let encoded = k256::EncodedPoint::from_bytes(encoded).expect("valid SEC1 point");
    let affine = Option::<K256AffinePoint>::from(K256AffinePoint::from_encoded_point(&encoded))
        .expect("point on secp256k1");
    K256ProjectivePoint::from(affine)
}

pub fn k256_scalar_from_axiom(scalar: Fq) -> K256Scalar {
    K256Scalar::from_repr(be_bytes_from_fq(scalar).into()).expect("canonical secp256k1 scalar")
}

pub fn be_bytes_from_fq(value: Fq) -> [u8; 32] {
    let mut repr = value.to_repr();
    repr.reverse();
    repr
}

pub fn be_bytes_from_fp(value: Fp) -> [u8; 32] {
    let mut repr = value.to_repr();
    repr.reverse();
    repr
}

fn keygen_builder(params: AxiomDkgCircuitParams) -> RangeCircuitBuilder<BlsFr> {
    let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_params(base_circuit_params(params));
    builder.set_lookup_bits(params.lookup_bits);
    builder
}

fn base_circuit_params(params: AxiomDkgCircuitParams) -> BaseCircuitParams {
    BaseCircuitParams {
        k: params.degree as usize,
        num_advice_per_phase: vec![params.advice_columns],
        num_fixed: params.fixed_columns,
        num_lookup_advice_per_phase: vec![params.lookup_advice_columns, 0, 0],
        lookup_bits: Some(params.lookup_bits),
        num_instance_columns: 1,
    }
}

fn synthesize_round1(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    witness: &DkgRound1PokFaultWitness,
) -> Vec<AssignedValue<BlsFr>> {
    let fp_chip = FpChip::<BlsFr>::new(range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<BlsFr>::new(range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<BlsFr, FpChip<BlsFr>>::new(&fp_chip);

    let mu = fq_chip.load_private(ctx, witness.mu);
    let challenge = fq_chip.load_private(ctx, witness.challenge);
    let phi0 = ecc_chip.assign_point::<Secp256k1Affine>(ctx, witness.phi0);
    assert_non_identity(ecc_chip.field_chip(), ctx, &phi0);
    let generator =
        ecc_chip.assign_constant_point::<Secp256k1Affine>(ctx, Secp256k1::generator().to_affine());

    let mu_g = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        generator,
        mu.limbs().to_vec(),
        fq_chip.limb_bits,
        params.window_bits,
    );
    let c_phi0 = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        phi0.clone(),
        challenge.limbs().to_vec(),
        fq_chip.limb_bits,
        params.window_bits,
    );
    let residual = secp_sub_complete(ecc_chip.field_chip(), ctx, mu_g, c_phi0);

    let mut public_inputs = Vec::with_capacity(params.num_limbs * 6);
    public_inputs.extend_from_slice(mu.limbs());
    public_inputs.extend_from_slice(challenge.limbs());
    public_inputs.extend_from_slice(phi0.x.limbs());
    public_inputs.extend_from_slice(phi0.y.limbs());
    public_inputs.extend_from_slice(residual.x.limbs());
    public_inputs.extend_from_slice(residual.y.limbs());
    public_inputs
}

fn synthesize_round1_digest_fault(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    witness: &DkgRound1PokDigestFaultWitness,
) -> Vec<AssignedValue<BlsFr>> {
    let fp_chip = FpChip::<BlsFr>::new(range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<BlsFr>::new(range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<BlsFr, FpChip<BlsFr>>::new(&fp_chip);

    let identifier = ctx.load_witness(BlsFr::from(witness.identifier));
    let mu = fq_chip.load_private(ctx, witness.mu);
    let challenge = fq_chip.load_private(ctx, witness.challenge);
    let phi0 = ecc_chip.assign_point::<Secp256k1Affine>(ctx, witness.phi0);
    let transcript_r = ecc_chip.assign_point::<Secp256k1Affine>(ctx, witness.transcript_r);
    assert_non_identity(ecc_chip.field_chip(), ctx, &phi0);
    assert_non_identity(ecc_chip.field_chip(), ctx, &transcript_r);
    constrain_round1_hdk_challenge(
        ctx,
        range,
        params,
        &fq_chip,
        &challenge,
        identifier,
        &phi0,
        &transcript_r,
        witness,
    );
    let generator =
        ecc_chip.assign_constant_point::<Secp256k1Affine>(ctx, Secp256k1::generator().to_affine());

    let mu_g = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        generator,
        mu.limbs().to_vec(),
        fq_chip.limb_bits,
        params.window_bits,
    );
    let c_phi0 = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        phi0.clone(),
        challenge.limbs().to_vec(),
        fq_chip.limb_bits,
        params.window_bits,
    );
    let residual = secp_sub_complete(ecc_chip.field_chip(), ctx, mu_g, c_phi0);
    assert_points_not_equal(ecc_chip.field_chip(), ctx, &residual, &transcript_r);

    let mut digest_inputs = Vec::with_capacity(6 + params.num_limbs * 5);
    digest_inputs.extend(
        round1_message_header(params)
            .into_iter()
            .map(|value| ctx.load_constant(value)),
    );
    digest_inputs.push(identifier);
    digest_inputs.extend_from_slice(mu.limbs());
    digest_inputs.extend_from_slice(phi0.x.limbs());
    digest_inputs.extend_from_slice(phi0.y.limbs());
    digest_inputs.extend_from_slice(transcript_r.x.limbs());
    digest_inputs.extend_from_slice(transcript_r.y.limbs());

    let digest = poseidon_digest_assigned(ctx, range, &digest_inputs);
    // The pinned Aiken verifier generator currently mishandles singleton
    // instance vectors. Keep a circuit-constrained zero until that is fixed.
    vec![digest, ctx.load_zero()]
}

fn synthesize_round2<const T: usize, const INDEX_BITS: usize>(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    witness: &DkgRound2ShareFaultWitness,
) -> Vec<AssignedValue<BlsFr>> {
    assert!(T > 0);
    assert!(INDEX_BITS > 0);
    assert_eq!(witness.commitments.len(), T);
    assert!(witness.participant_index < (1u64 << INDEX_BITS));

    let fp_chip = FpChip::<BlsFr>::new(range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<BlsFr>::new(range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<BlsFr, FpChip<BlsFr>>::new(&fp_chip);

    let share = fq_chip.load_private(ctx, witness.share);
    let index = ctx.load_witness(BlsFr::from(witness.participant_index));
    let _index_bits = range.gate.num_to_bits(ctx, index, INDEX_BITS);

    let commitments = witness
        .commitments
        .iter()
        .map(|commitment| {
            let commitment = ecc_chip.assign_point::<Secp256k1Affine>(ctx, *commitment);
            assert_non_identity(ecc_chip.field_chip(), ctx, &commitment);
            commitment
        })
        .collect::<Vec<_>>();

    let mut horner = commitments.last().expect("T > 0").clone();
    let one = ctx.load_constant(BlsFr::ONE);
    for commitment in commitments[..T - 1].iter().rev() {
        horner = small_linear_combination::<INDEX_BITS, _>(
            ecc_chip.field_chip(),
            ctx,
            commitment.clone(),
            one,
            horner,
            index,
            params.window_bits,
        );
    }

    let generator =
        ecc_chip.assign_constant_point::<Secp256k1Affine>(ctx, Secp256k1::generator().to_affine());
    let share_g = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        generator,
        share.limbs().to_vec(),
        fq_chip.limb_bits,
        params.window_bits,
    );
    let residual = secp_sub_complete(ecc_chip.field_chip(), ctx, horner, share_g);

    let mut public_inputs = Vec::with_capacity(params.num_limbs * (3 + 2 * T) + 1);
    public_inputs.extend_from_slice(share.limbs());
    public_inputs.push(index);
    for commitment in &commitments {
        public_inputs.extend_from_slice(commitment.x.limbs());
        public_inputs.extend_from_slice(commitment.y.limbs());
    }
    public_inputs.extend_from_slice(residual.x.limbs());
    public_inputs.extend_from_slice(residual.y.limbs());
    public_inputs
}

fn synthesize_round2_digest_fault<const T: usize, const INDEX_BITS: usize>(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    witness: &DkgRound2ShareFaultWitness,
) -> Vec<AssignedValue<BlsFr>> {
    assert!(T > 0);
    assert!(INDEX_BITS > 0);
    assert_eq!(witness.commitments.len(), T);
    assert!(witness.participant_index < (1u64 << INDEX_BITS));

    let fp_chip = FpChip::<BlsFr>::new(range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<BlsFr>::new(range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<BlsFr, FpChip<BlsFr>>::new(&fp_chip);

    let share = fq_chip.load_private(ctx, witness.share);
    let index = ctx.load_witness(BlsFr::from(witness.participant_index));
    let _index_bits = range.gate.num_to_bits(ctx, index, INDEX_BITS);

    let commitments = witness
        .commitments
        .iter()
        .map(|commitment| {
            let commitment = ecc_chip.assign_point::<Secp256k1Affine>(ctx, *commitment);
            assert_non_identity(ecc_chip.field_chip(), ctx, &commitment);
            commitment
        })
        .collect::<Vec<_>>();

    let mut horner = commitments.last().expect("T > 0").clone();
    let one = ctx.load_constant(BlsFr::ONE);
    for commitment in commitments[..T - 1].iter().rev() {
        horner = small_linear_combination::<INDEX_BITS, _>(
            ecc_chip.field_chip(),
            ctx,
            commitment.clone(),
            one,
            horner,
            index,
            params.window_bits,
        );
    }

    let generator =
        ecc_chip.assign_constant_point::<Secp256k1Affine>(ctx, Secp256k1::generator().to_affine());
    let share_g = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        generator,
        share.limbs().to_vec(),
        fq_chip.limb_bits,
        params.window_bits,
    );
    let residual = secp_sub_complete(ecc_chip.field_chip(), ctx, horner, share_g);
    assert_non_identity(ecc_chip.field_chip(), ctx, &residual);

    let mut digest_inputs = Vec::with_capacity(7 + params.num_limbs * (1 + 2 * T));
    digest_inputs.extend(
        round2_message_header::<T, INDEX_BITS>(params)
            .into_iter()
            .map(|value| ctx.load_constant(value)),
    );
    digest_inputs.extend_from_slice(share.limbs());
    digest_inputs.push(index);
    for commitment in &commitments {
        digest_inputs.extend_from_slice(commitment.x.limbs());
        digest_inputs.extend_from_slice(commitment.y.limbs());
    }

    let digest = poseidon_digest_assigned(ctx, range, &digest_inputs);
    // The pinned Aiken verifier generator currently mishandles singleton
    // instance vectors. Keep a circuit-constrained zero until that is fixed.
    vec![digest, ctx.load_zero()]
}

fn small_linear_combination<const INDEX_BITS: usize, FC>(
    chip: &FC,
    ctx: &mut Context<BlsFr>,
    first: EcPoint<BlsFr, FC::FieldPoint>,
    first_scalar: AssignedValue<BlsFr>,
    second: EcPoint<BlsFr, FC::FieldPoint>,
    second_scalar: AssignedValue<BlsFr>,
    window_bits: usize,
) -> EcPoint<BlsFr, FC::FieldPoint>
where
    FC: FieldChip<BlsFr, FieldType = Fp> + halo2_ecc::fields::Selectable<BlsFr, FC::FieldPoint>,
{
    multi_scalar_multiply::<BlsFr, FC, Secp256k1Affine>(
        chip,
        ctx,
        &[first, second],
        vec![vec![first_scalar], vec![second_scalar]],
        INDEX_BITS,
        window_bits,
    )
}

// Axiom's `ec_sub_strict` assumes non-identity inputs and rejects inverse pairs.
// This wrapper keeps the residual computation complete by feeding safe dummy
// points to incomplete gadgets, then selecting the mathematically correct branch.
fn secp_sub_complete<FC>(
    chip: &FC,
    ctx: &mut Context<BlsFr>,
    p: EcPoint<BlsFr, FC::FieldPoint>,
    q: EcPoint<BlsFr, FC::FieldPoint>,
) -> EcPoint<BlsFr, FC::FieldPoint>
where
    FC: FieldChip<BlsFr, FieldType = Fp> + halo2_ecc::fields::Selectable<BlsFr, FC::FieldPoint>,
{
    let p_is_identity = chip.is_zero(ctx, &p.y);
    let q_is_identity = chip.is_zero(ctx, &q.y);
    let either_is_identity = chip.gate().or(ctx, p_is_identity, q_is_identity);
    let both_non_identity = chip.gate().not(ctx, either_is_identity);

    let x_is_equal = chip.is_equal(ctx, p.x(), q.x());
    let y_is_equal = chip.is_equal(ctx, p.y(), q.y());
    let y_is_different = chip.gate().not(ctx, y_is_equal);
    let inverse_case = chip.gate().and(ctx, x_is_equal, y_is_different);
    let inverse_case = chip.gate().and(ctx, inverse_case, both_non_identity);

    let incomplete_case = chip.gate().or(ctx, either_is_identity, inverse_case);
    let use_general_case = chip.gate().not(ctx, incomplete_case);

    let generator = secp_generator(chip, ctx);
    let generator_double = ec_double(chip, ctx, generator.clone());

    let safe_p = ec_select(chip, ctx, p.clone(), generator.clone(), use_general_case);
    let safe_q = ec_select(
        chip,
        ctx,
        q.clone(),
        generator_double.clone(),
        use_general_case,
    );
    let general = ec_sub_strict(chip, ctx, safe_p, safe_q);

    let p_for_double = ec_select(chip, ctx, p.clone(), generator.clone(), inverse_case);
    let doubled_p = ec_double(chip, ctx, p_for_double);

    let zero = chip.load_constant(ctx, Fp::ZERO);
    let q_neg_y = chip.negate(ctx, q.y.clone());
    let zero_minus_q = EcPoint::new(q.x.clone(), q_neg_y);
    let zero_minus_q = ec_select(
        chip,
        ctx,
        zero_minus_q,
        EcPoint::new(zero.clone(), zero.clone()),
        q_is_identity,
    );
    let identity_branch = ec_select(chip, ctx, zero_minus_q, p.clone(), p_is_identity);
    let exceptional = ec_select(chip, ctx, doubled_p, identity_branch, inverse_case);

    ec_select(chip, ctx, general, exceptional, use_general_case)
}

fn secp_generator<FC>(chip: &FC, ctx: &mut Context<BlsFr>) -> EcPoint<BlsFr, FC::FieldPoint>
where
    FC: FieldChip<BlsFr, FieldType = Fp>,
{
    let (x, y) = Secp256k1::generator().to_affine().into_coordinates();
    EcPoint::new(chip.load_constant(ctx, x), chip.load_constant(ctx, y))
}

fn assert_non_identity<FC>(
    chip: &FC,
    ctx: &mut Context<BlsFr>,
    point: &EcPoint<BlsFr, FC::FieldPoint>,
) where
    FC: FieldChip<BlsFr, FieldType = Fp>,
{
    let y_is_zero = chip.is_zero(ctx, point.y.clone());
    chip.gate().assert_is_const(ctx, &y_is_zero, &BlsFr::ZERO);
}

fn assert_points_not_equal<FC>(
    chip: &FC,
    ctx: &mut Context<BlsFr>,
    first: &EcPoint<BlsFr, FC::FieldPoint>,
    second: &EcPoint<BlsFr, FC::FieldPoint>,
) where
    FC: FieldChip<BlsFr, FieldType = Fp>,
{
    let x_is_equal = chip.is_equal(ctx, first.x(), second.x());
    let y_is_equal = chip.is_equal(ctx, first.y(), second.y());
    let points_are_equal = chip.gate().and(ctx, x_is_equal, y_is_equal);
    chip.gate()
        .assert_is_const(ctx, &points_are_equal, &BlsFr::ZERO);
}

fn constrain_round1_hdk_challenge(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    fq_chip: &FqChip<BlsFr>,
    challenge: &ProperCrtUint<BlsFr>,
    identifier: AssignedValue<BlsFr>,
    phi0: &EcPoint<BlsFr, ProperCrtUint<BlsFr>>,
    transcript_r: &EcPoint<BlsFr, ProperCrtUint<BlsFr>>,
    witness: &DkgRound1PokDigestFaultWitness,
) {
    let preimage = round1_hdk_preimage_assigned(ctx, range, params, identifier, phi0, transcript_r);
    let okm = expand_message_xmd_sha256_48_assigned(ctx, range, &preimage);
    let (d0_witness, d1_witness) = round1_hdk_scalar_chunks(witness);

    let d0 = fq_chip.load_private(ctx, d0_witness);
    constrain_fq_to_be_bytes(ctx, range, params, &d0, &okm[..SECP_SCALAR_CHUNK_BYTES]);

    let d1 = fq_chip.load_private(ctx, d1_witness);
    constrain_fq_to_be_bytes(
        ctx,
        range,
        params,
        &d1,
        &okm[SECP_SCALAR_CHUNK_BYTES..HDKG_OKM_BYTES],
    );

    let two_192 = fq_chip.load_constant(ctx, fq_two_192());
    let d0_shifted = fq_chip.mul(ctx, d0, two_192);
    let derived_no_carry = fq_chip.add_no_carry(ctx, d0_shifted, d1);
    let derived = fq_chip.carry_mod(ctx, derived_no_carry);
    fq_chip.assert_equal(ctx, challenge.clone(), derived);
}

fn round1_hdk_preimage_assigned(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    identifier: AssignedValue<BlsFr>,
    phi0: &EcPoint<BlsFr, ProperCrtUint<BlsFr>>,
    transcript_r: &EcPoint<BlsFr, ProperCrtUint<BlsFr>>,
) -> Vec<AssignedByte> {
    let mut preimage = Vec::with_capacity(98);
    preimage.extend(identifier_be_bytes_assigned(ctx, range, identifier));
    preimage.extend(compressed_point_bytes_assigned(ctx, range, params, phi0));
    preimage.extend(compressed_point_bytes_assigned(
        ctx,
        range,
        params,
        transcript_r,
    ));
    preimage
}

fn identifier_be_bytes_assigned(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    identifier: AssignedValue<BlsFr>,
) -> Vec<AssignedByte> {
    let bits_le = range.gate().num_to_bits(ctx, identifier, 64);
    let mut bytes = Vec::with_capacity(32);
    for _ in 0..24 {
        bytes.push(const_byte_bits(ctx, 0));
    }
    for byte in (0..8).rev() {
        bytes.push(bits_le[byte * BYTE_BITS..(byte + 1) * BYTE_BITS].to_vec());
    }
    bytes
}

fn compressed_point_bytes_assigned(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    point: &EcPoint<BlsFr, ProperCrtUint<BlsFr>>,
) -> Vec<AssignedByte> {
    let mut bytes = Vec::with_capacity(33);
    let y_bits = field_bits_le(ctx, range, params, &point.y);
    let y_is_odd = y_bits[0];
    bytes.push(sec1_prefix_bits(ctx, y_is_odd));
    bytes.extend(field_be_bytes_assigned(ctx, range, params, &point.x));
    bytes
}

fn sec1_prefix_bits(ctx: &mut Context<BlsFr>, y_is_odd: AssignedValue<BlsFr>) -> AssignedByte {
    let mut bits = Vec::with_capacity(BYTE_BITS);
    bits.push(y_is_odd);
    bits.push(ctx.load_constant(BlsFr::ONE));
    for _ in 2..BYTE_BITS {
        bits.push(ctx.load_zero());
    }
    bits
}

fn field_be_bytes_assigned(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    value: &ProperCrtUint<BlsFr>,
) -> Vec<AssignedByte> {
    let bits_le = field_bits_le(ctx, range, params, value);
    (0..32)
        .rev()
        .map(|byte| bits_le[byte * BYTE_BITS..(byte + 1) * BYTE_BITS].to_vec())
        .collect()
}

fn field_bits_le(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    value: &ProperCrtUint<BlsFr>,
) -> Vec<AssignedBit> {
    let mut bits = Vec::with_capacity(params.limb_bits * params.num_limbs);
    for limb in value.limbs() {
        bits.extend(range.gate().num_to_bits(ctx, *limb, params.limb_bits));
    }
    bits.truncate(SECP_SCALAR_BITS);
    bits
}

fn constrain_fq_to_be_bytes(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    params: AxiomDkgCircuitParams,
    value: &ProperCrtUint<BlsFr>,
    bytes: &[AssignedByte],
) {
    assert_eq!(bytes.len(), SECP_SCALAR_CHUNK_BYTES);

    let mut bits_le = Vec::with_capacity(SECP_SCALAR_CHUNK_BYTES * BYTE_BITS);
    for byte in bytes.iter().rev() {
        bits_le.extend_from_slice(byte);
    }

    for (limb_index, limb) in value.limbs().iter().enumerate() {
        let mut limb_bits = Vec::with_capacity(params.limb_bits);
        let start = limb_index * params.limb_bits;
        for bit_index in start..start + params.limb_bits {
            limb_bits.push(
                bits_le
                    .get(bit_index)
                    .copied()
                    .unwrap_or_else(|| ctx.load_zero()),
            );
        }
        let expected_limb = range.gate().bits_to_num(ctx, &limb_bits);
        ctx.constrain_equal(limb, &expected_limb);
    }
}

fn expand_message_xmd_sha256_48_assigned(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    msg: &[AssignedByte],
) -> Vec<AssignedByte> {
    let dst = HDKG_CONTEXT
        .iter()
        .chain(HDKG_LABEL.iter())
        .map(|byte| const_byte_bits(ctx, *byte))
        .collect::<Vec<_>>();
    let dst_len = const_byte_bits(ctx, HDKG_DST_LEN);

    let mut b0_input = Vec::with_capacity(SHA256_BLOCK_BYTES + msg.len() + 35);
    for _ in 0..SHA256_BLOCK_BYTES {
        b0_input.push(const_byte_bits(ctx, 0));
    }
    b0_input.extend_from_slice(msg);
    b0_input.push(const_byte_bits(ctx, 0));
    b0_input.push(const_byte_bits(ctx, HDKG_OKM_BYTES as u8));
    b0_input.push(const_byte_bits(ctx, 0));
    b0_input.extend_from_slice(&dst);
    b0_input.push(dst_len.clone());
    let b0 = sha256_digest_assigned(ctx, range, &b0_input);

    let mut b1_input = Vec::with_capacity(65);
    b1_input.extend_from_slice(&b0);
    b1_input.push(const_byte_bits(ctx, 1));
    b1_input.extend_from_slice(&dst);
    b1_input.push(dst_len.clone());
    let b1 = sha256_digest_assigned(ctx, range, &b1_input);

    let b0_xor_b1 = b0
        .iter()
        .zip(b1.iter())
        .map(|(left, right)| xor_bytes(ctx, range, left, right))
        .collect::<Vec<_>>();
    let mut b2_input = Vec::with_capacity(65);
    b2_input.extend_from_slice(&b0_xor_b1);
    b2_input.push(const_byte_bits(ctx, 2));
    b2_input.extend_from_slice(&dst);
    b2_input.push(dst_len);
    let b2 = sha256_digest_assigned(ctx, range, &b2_input);

    let mut okm = Vec::with_capacity(HDKG_OKM_BYTES);
    okm.extend_from_slice(&b1);
    okm.extend_from_slice(&b2[..16]);
    okm
}

fn sha256_digest_assigned(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    input: &[AssignedByte],
) -> Vec<AssignedByte> {
    let mut padded = input.to_vec();
    padded.push(const_byte_bits(ctx, 0x80));
    while padded.len() % SHA256_BLOCK_BYTES != 56 {
        padded.push(const_byte_bits(ctx, 0));
    }
    let bit_len = (input.len() as u64) * BYTE_BITS as u64;
    for byte in bit_len.to_be_bytes() {
        padded.push(const_byte_bits(ctx, byte));
    }

    let mut state = SHA256_IV
        .iter()
        .map(|word| const_word_bits(ctx, *word))
        .collect::<Vec<_>>();
    for block in padded.chunks(SHA256_BLOCK_BYTES) {
        state = sha256_compress_assigned(ctx, range, &state, block);
    }

    state
        .iter()
        .flat_map(|word| word_to_be_bytes(word))
        .collect()
}

fn sha256_compress_assigned(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    state: &[AssignedWord],
    block: &[AssignedByte],
) -> Vec<AssignedWord> {
    assert_eq!(state.len(), 8);
    assert_eq!(block.len(), SHA256_BLOCK_BYTES);

    let mut schedule = block
        .chunks(4)
        .map(word_from_be_bytes)
        .collect::<Vec<AssignedWord>>();
    for index in 16..64 {
        let s0 = sha256_small_sigma0(ctx, range, &schedule[index - 15]);
        let s1 = sha256_small_sigma1(ctx, range, &schedule[index - 2]);
        schedule.push(add_words_mod_2_32(
            ctx,
            range,
            &[
                schedule[index - 16].clone(),
                s0,
                schedule[index - 7].clone(),
                s1,
            ],
        ));
    }

    let mut a = state[0].clone();
    let mut b = state[1].clone();
    let mut c = state[2].clone();
    let mut d = state[3].clone();
    let mut e = state[4].clone();
    let mut f = state[5].clone();
    let mut g = state[6].clone();
    let mut h = state[7].clone();

    for round in 0..64 {
        let big_sigma1 = sha256_big_sigma1(ctx, range, &e);
        let choice = sha256_ch(ctx, range, &e, &f, &g);
        let round_constant = const_word_bits(ctx, SHA256_K[round]);
        let t1 = add_words_mod_2_32(
            ctx,
            range,
            &[
                h.clone(),
                big_sigma1,
                choice,
                round_constant,
                schedule[round].clone(),
            ],
        );
        let big_sigma0 = sha256_big_sigma0(ctx, range, &a);
        let majority = sha256_maj(ctx, range, &a, &b, &c);
        let t2 = add_words_mod_2_32(ctx, range, &[big_sigma0, majority]);

        h = g;
        g = f;
        f = e;
        e = add_words_mod_2_32(ctx, range, &[d, t1.clone()]);
        d = c;
        c = b;
        b = a;
        a = add_words_mod_2_32(ctx, range, &[t1, t2]);
    }

    [a, b, c, d, e, f, g, h]
        .into_iter()
        .enumerate()
        .map(|(index, word)| add_words_mod_2_32(ctx, range, &[state[index].clone(), word]))
        .collect()
}

fn add_words_mod_2_32(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    words: &[AssignedWord],
) -> AssignedWord {
    assert!(!words.is_empty());
    let mut acc = words[0].clone();
    for word in &words[1..] {
        acc = add_two_words_mod_2_32(ctx, range, &acc, word);
    }
    acc
}

fn add_two_words_mod_2_32(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    left: &AssignedWord,
    right: &AssignedWord,
) -> AssignedWord {
    assert_eq!(left.len(), SHA256_WORD_BITS);
    assert_eq!(right.len(), SHA256_WORD_BITS);

    let mut carry = ctx.load_zero();
    let mut out = Vec::with_capacity(SHA256_WORD_BITS);
    for (left_bit, right_bit) in left.iter().zip(right.iter()) {
        let left_xor_right = range.gate().xor(ctx, *left_bit, *right_bit);
        let sum = range.gate().xor(ctx, left_xor_right, carry);
        let left_and_right = range.gate().and(ctx, *left_bit, *right_bit);
        let carry_and_xor = range.gate().and(ctx, carry, left_xor_right);
        carry = range.gate().xor(ctx, left_and_right, carry_and_xor);
        out.push(sum);
    }
    out
}

fn sha256_ch(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    x: &AssignedWord,
    y: &AssignedWord,
    z: &AssignedWord,
) -> AssignedWord {
    x.iter()
        .zip(y.iter())
        .zip(z.iter())
        .map(|((x_bit, y_bit), z_bit)| {
            let y_xor_z = range.gate().xor(ctx, *y_bit, *z_bit);
            let x_and = range.gate().and(ctx, *x_bit, y_xor_z);
            range.gate().xor(ctx, *z_bit, x_and)
        })
        .collect()
}

fn sha256_maj(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    x: &AssignedWord,
    y: &AssignedWord,
    z: &AssignedWord,
) -> AssignedWord {
    x.iter()
        .zip(y.iter())
        .zip(z.iter())
        .map(|((x_bit, y_bit), z_bit)| {
            let xy = range.gate().and(ctx, *x_bit, *y_bit);
            let xz = range.gate().and(ctx, *x_bit, *z_bit);
            let yz = range.gate().and(ctx, *y_bit, *z_bit);
            let xy_xor_xz = range.gate().xor(ctx, xy, xz);
            range.gate().xor(ctx, xy_xor_xz, yz)
        })
        .collect()
}

fn sha256_big_sigma0(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    word: &AssignedWord,
) -> AssignedWord {
    xor3_words(ctx, range, &rotr(word, 2), &rotr(word, 13), &rotr(word, 22))
}

fn sha256_big_sigma1(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    word: &AssignedWord,
) -> AssignedWord {
    xor3_words(ctx, range, &rotr(word, 6), &rotr(word, 11), &rotr(word, 25))
}

fn sha256_small_sigma0(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    word: &AssignedWord,
) -> AssignedWord {
    let shifted = shr(ctx, word, 3);
    xor3_words(ctx, range, &rotr(word, 7), &rotr(word, 18), &shifted)
}

fn sha256_small_sigma1(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    word: &AssignedWord,
) -> AssignedWord {
    let shifted = shr(ctx, word, 10);
    xor3_words(ctx, range, &rotr(word, 17), &rotr(word, 19), &shifted)
}

fn xor3_words(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    first: &AssignedWord,
    second: &AssignedWord,
    third: &AssignedWord,
) -> AssignedWord {
    first
        .iter()
        .zip(second.iter())
        .zip(third.iter())
        .map(|((first_bit, second_bit), third_bit)| {
            let tmp = range.gate().xor(ctx, *first_bit, *second_bit);
            range.gate().xor(ctx, tmp, *third_bit)
        })
        .collect()
}

fn rotr(word: &AssignedWord, shift: usize) -> AssignedWord {
    (0..SHA256_WORD_BITS)
        .map(|index| word[(index + shift) % SHA256_WORD_BITS])
        .collect()
}

fn shr(ctx: &mut Context<BlsFr>, word: &AssignedWord, shift: usize) -> AssignedWord {
    let zero = ctx.load_zero();
    (0..SHA256_WORD_BITS)
        .map(|index| {
            if index + shift < SHA256_WORD_BITS {
                word[index + shift]
            } else {
                zero
            }
        })
        .collect()
}

fn xor_bytes(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    left: &AssignedByte,
    right: &AssignedByte,
) -> AssignedByte {
    left.iter()
        .zip(right.iter())
        .map(|(left_bit, right_bit)| range.gate().xor(ctx, *left_bit, *right_bit))
        .collect()
}

fn word_from_be_bytes(bytes: &[AssignedByte]) -> AssignedWord {
    assert_eq!(bytes.len(), 4);
    bytes
        .iter()
        .rev()
        .flat_map(|byte| byte.iter().copied())
        .collect()
}

fn word_to_be_bytes(word: &AssignedWord) -> Vec<AssignedByte> {
    assert_eq!(word.len(), SHA256_WORD_BITS);
    (0..4)
        .rev()
        .map(|byte| word[byte * BYTE_BITS..(byte + 1) * BYTE_BITS].to_vec())
        .collect()
}

fn const_word_bits(ctx: &mut Context<BlsFr>, value: u32) -> AssignedWord {
    (0..SHA256_WORD_BITS)
        .map(|bit| const_bit(ctx, ((value >> bit) & 1) == 1))
        .collect()
}

fn const_byte_bits(ctx: &mut Context<BlsFr>, value: u8) -> AssignedByte {
    (0..BYTE_BITS)
        .map(|bit| const_bit(ctx, ((value >> bit) & 1) == 1))
        .collect()
}

fn const_bit(ctx: &mut Context<BlsFr>, value: bool) -> AssignedBit {
    ctx.load_constant(BlsFr::from(value as u64))
}

fn round1_hdk_scalar_chunks(witness: &DkgRound1PokDigestFaultWitness) -> (Fq, Fq) {
    let okm = expand_message_xmd_sha256_48(&round1_hdk_preimage_bytes(witness));
    (
        fq_from_24_be_bytes(&okm[..SECP_SCALAR_CHUNK_BYTES]),
        fq_from_24_be_bytes(&okm[SECP_SCALAR_CHUNK_BYTES..HDKG_OKM_BYTES]),
    )
}

fn expand_message_xmd_sha256_48(msg: &[u8]) -> [u8; HDKG_OKM_BYTES] {
    let mut dst = Vec::with_capacity(HDKG_DST_LEN as usize);
    dst.extend_from_slice(HDKG_CONTEXT);
    dst.extend_from_slice(HDKG_LABEL);

    let mut b0_hasher = Sha256::new();
    b0_hasher.update([0u8; SHA256_BLOCK_BYTES]);
    b0_hasher.update(msg);
    b0_hasher.update((HDKG_OKM_BYTES as u16).to_be_bytes());
    b0_hasher.update([0u8]);
    b0_hasher.update(&dst);
    b0_hasher.update([HDKG_DST_LEN]);
    let b0 = b0_hasher.finalize();

    let mut b1_hasher = Sha256::new();
    b1_hasher.update(&b0);
    b1_hasher.update([1u8]);
    b1_hasher.update(&dst);
    b1_hasher.update([HDKG_DST_LEN]);
    let b1 = b1_hasher.finalize();

    let mut b0_xor_b1 = [0u8; 32];
    for (out, (left, right)) in b0_xor_b1.iter_mut().zip(b0.iter().zip(b1.iter())) {
        *out = left ^ right;
    }

    let mut b2_hasher = Sha256::new();
    b2_hasher.update(b0_xor_b1);
    b2_hasher.update([2u8]);
    b2_hasher.update(&dst);
    b2_hasher.update([HDKG_DST_LEN]);
    let b2 = b2_hasher.finalize();

    let mut okm = [0u8; HDKG_OKM_BYTES];
    okm[..32].copy_from_slice(&b1);
    okm[32..].copy_from_slice(&b2[..16]);
    okm
}

fn round1_hdk_preimage_bytes(witness: &DkgRound1PokDigestFaultWitness) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(98);
    preimage.extend_from_slice(&identifier_be_bytes(witness.identifier));
    preimage.extend_from_slice(&compressed_point_bytes(witness.phi0));
    preimage.extend_from_slice(&compressed_point_bytes(witness.transcript_r));
    preimage
}

fn identifier_be_bytes(identifier: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&identifier.to_be_bytes());
    bytes
}

fn compressed_point_bytes(point: Secp256k1Affine) -> [u8; 33] {
    assert!(!bool::from(point.is_identity()));
    let (x, y) = point.into_coordinates();
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02 | (be_bytes_from_fp(y)[31] & 1);
    bytes[1..].copy_from_slice(&be_bytes_from_fp(x));
    bytes
}

fn fq_from_24_be_bytes(bytes: &[u8]) -> Fq {
    assert_eq!(bytes.len(), SECP_SCALAR_CHUNK_BYTES);
    let mut be = [0u8; 32];
    be[8..].copy_from_slice(bytes);
    axiom_scalar_from_be_bytes(&be)
}

fn fq_two_192() -> Fq {
    let mut repr = [0u8; 32];
    repr[24] = 1;
    Option::<Fq>::from(Fq::from_repr(repr)).expect("2^192 fits in secp256k1 scalar field")
}

fn public_instance_values(public_input_cells: &[AssignedValue<BlsFr>]) -> Vec<BlsFr> {
    public_input_cells
        .iter()
        .map(|public_input| *public_input.value())
        .collect()
}

fn round1_message_header(params: AxiomDkgCircuitParams) -> [BlsFr; 5] {
    [
        BlsFr::from(DKG_FAULT_MESSAGE_DOMAIN),
        BlsFr::from(DKG_FAULT_MESSAGE_VERSION),
        BlsFr::from(DKG_ROUND1_MESSAGE_TAG),
        BlsFr::from(params.limb_bits as u64),
        BlsFr::from(params.num_limbs as u64),
    ]
}

fn round2_message_header<const T: usize, const INDEX_BITS: usize>(
    params: AxiomDkgCircuitParams,
) -> [BlsFr; 7] {
    [
        BlsFr::from(DKG_FAULT_MESSAGE_DOMAIN),
        BlsFr::from(DKG_FAULT_MESSAGE_VERSION),
        BlsFr::from(DKG_ROUND2_MESSAGE_TAG),
        BlsFr::from(params.limb_bits as u64),
        BlsFr::from(params.num_limbs as u64),
        BlsFr::from(T as u64),
        BlsFr::from(INDEX_BITS as u64),
    ]
}

fn poseidon_digest(elements: &[BlsFr]) -> BlsFr {
    let mut hasher = Poseidon::<BlsFr, POSEIDON_T, POSEIDON_RATE>::new(
        POSEIDON_FULL_ROUNDS,
        POSEIDON_PARTIAL_ROUNDS,
    );
    hasher.update(elements);
    hasher.squeeze()
}

fn poseidon_digest_assigned(
    ctx: &mut Context<BlsFr>,
    range: &RangeChip<BlsFr>,
    elements: &[AssignedValue<BlsFr>],
) -> AssignedValue<BlsFr> {
    let spec = OptimizedPoseidonSpec::<BlsFr, POSEIDON_T, POSEIDON_RATE>::new::<
        POSEIDON_FULL_ROUNDS,
        POSEIDON_PARTIAL_ROUNDS,
        POSEIDON_SECURE_MDS,
    >();
    let mut hasher = PoseidonHasher::<BlsFr, POSEIDON_T, POSEIDON_RATE>::new(spec);
    hasher.initialize_consts(ctx, &range.gate);
    hasher.hash_fix_len_array(ctx, &range.gate, elements)
}

fn point_public_limbs(point: Secp256k1Affine, params: AxiomDkgCircuitParams) -> Vec<BlsFr> {
    if bool::from(point.is_identity()) {
        return vec![BlsFr::ZERO; params.num_limbs * 2];
    }

    let (x, y) = point.into_coordinates();
    [x, y]
        .into_iter()
        .flat_map(|coordinate| fp_public_limbs(coordinate, params))
        .collect()
}

fn fp_public_limbs(value: Fp, params: AxiomDkgCircuitParams) -> Vec<BlsFr> {
    field_public_limbs(&value.to_repr(), params)
}

fn fq_public_limbs(value: Fq, params: AxiomDkgCircuitParams) -> Vec<BlsFr> {
    field_public_limbs(&value.to_repr(), params)
}

fn field_public_limbs(source: &[u8], params: AxiomDkgCircuitParams) -> Vec<BlsFr> {
    (0..params.num_limbs)
        .map(|limb| bls_fr_from_bits(source, limb * params.limb_bits, params.limb_bits))
        .collect()
}

fn bls_fr_from_bits(source: &[u8], bit_offset: usize, bit_len: usize) -> BlsFr {
    let mut repr = [0u8; 32];
    for bit in 0..bit_len {
        let source_bit = bit_offset + bit;
        if source_bit / 8 >= source.len() {
            break;
        }
        let is_set = ((source[source_bit / 8] >> (source_bit % 8)) & 1) == 1;
        if is_set {
            repr[bit / 8] |= 1 << (bit % 8);
        }
    }
    Option::<BlsFr>::from(BlsFr::from_repr(repr)).expect("limb fits in BLS scalar field")
}

fn circuit_stats(
    builder: &mut RangeCircuitBuilder<BlsFr>,
    params: AxiomDkgCircuitParams,
) -> CircuitStats {
    let raw_stats = builder.statistics();
    let total_advice_cells = raw_stats.gate.total_advice_per_phase.iter().sum();
    let total_lookup_cells = raw_stats.total_lookup_advice_per_phase.iter().sum();
    let total_fixed_cells = raw_stats.gate.total_fixed;
    let enabled_gate_constraints = builder
        .core()
        .phase_manager
        .iter()
        .flat_map(|phase| phase.threads.iter())
        .map(|ctx| ctx.selector.iter().filter(|enabled| **enabled).count())
        .sum();
    let config_params = builder.config_params.clone();
    assert_circuit_shape_capacity(
        &config_params,
        params.unusable_rows,
        &raw_stats.gate.total_advice_per_phase,
        &raw_stats.total_lookup_advice_per_phase,
        total_fixed_cells,
    );

    CircuitStats {
        total_advice_cells,
        enabled_gate_constraints,
        total_lookup_cells,
        total_fixed_cells,
        config_params,
    }
}

fn assert_circuit_shape_capacity(
    config_params: &BaseCircuitParams,
    unusable_rows: usize,
    advice_cells_per_phase: &[usize],
    lookup_cells_per_phase: &[usize],
    fixed_cells: usize,
) {
    assert_ne!(config_params.k, 0, "circuit degree must be pinned");
    let usable_rows = (1usize << config_params.k) - unusable_rows;

    for (phase, cells) in advice_cells_per_phase.iter().enumerate() {
        let columns = config_params
            .num_advice_per_phase
            .get(phase)
            .copied()
            .unwrap_or(0);
        assert!(
            *cells <= columns * usable_rows,
            "fixed circuit shape does not fit advice cells in phase {phase}: cells={cells}, columns={columns}, usable_rows={usable_rows}"
        );
    }

    for (phase, cells) in lookup_cells_per_phase.iter().enumerate() {
        let columns = config_params
            .num_lookup_advice_per_phase
            .get(phase)
            .copied()
            .unwrap_or(0);
        assert!(
            *cells <= columns * usable_rows,
            "fixed circuit shape does not fit lookup cells in phase {phase}: cells={cells}, columns={columns}, usable_rows={usable_rows}"
        );
    }

    let fixed_capacity = config_params.num_fixed * (1usize << config_params.k);
    assert!(
        fixed_cells <= fixed_capacity,
        "fixed circuit shape does not fit fixed cells: cells={fixed_cells}, columns={}, rows={}",
        config_params.num_fixed,
        1usize << config_params.k
    );
}

fn axiom_point_from_k256(point: K256AffinePoint) -> Secp256k1Affine {
    let encoded = point.to_encoded_point(false);
    let x = fp_from_be_slice(encoded.x().expect("affine x"));
    let y = fp_from_be_slice(encoded.y().expect("affine y"));
    Option::<Secp256k1Affine>::from(Secp256k1Affine::from_xy(x, y)).expect("point on secp256k1")
}

fn fp_from_be_slice(bytes: &[u8]) -> Fp {
    let bytes: [u8; 32] = bytes.try_into().expect("secp256k1 coordinate length");
    let mut repr = bytes;
    repr.reverse();
    Option::<Fp>::from(Fp::from_repr(repr)).expect("canonical secp256k1 coordinate")
}
