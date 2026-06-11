//! DKG fault-proof circuits using Axiom's Halo2 stack.
//!
//! The circuits prove only the secp256k1 computations that are too expensive
//! for Plutus. They expose the computed residual point as public instances; the
//! host or Plutus verifier performs the final equality or non-equality check.

use halo2_base::{
    AssignedValue, Context,
    gates::{
        GateInstructions, RangeChip,
        circuit::{BaseCircuitParams, CircuitBuilderStage, builder::RangeCircuitBuilder},
    },
    halo2_proofs::halo2curves::{
        CurveAffine,
        bls12_381::Fr as BlsFr,
        ff::{Field, PrimeField},
        group::{Curve, prime::PrimeCurveAffine},
        secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine},
    },
    utils::CurveAffineExt,
};
use halo2_ecc::{
    ecc::{EcPoint, EccChip, ec_double, ec_select, ec_sub_strict, multi_scalar_multiply},
    fields::FieldChip,
    secp256k1::{FpChip, FqChip},
};
use k256::{
    AffinePoint as K256AffinePoint, ProjectivePoint as K256ProjectivePoint, Scalar as K256Scalar,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};

#[derive(Clone, Copy, Debug)]
pub struct AxiomDkgCircuitParams {
    pub degree: u32,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
    pub window_bits: usize,
    pub unusable_rows: usize,
}

impl Default for AxiomDkgCircuitParams {
    fn default() -> Self {
        Self {
            degree: 18,
            lookup_bits: 17,
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

pub fn round1_residual(witness: &DkgRound1PokFaultWitness) -> Secp256k1Affine {
    let lhs = Secp256k1::generator() * witness.mu;
    let rhs = witness.phi0 * witness.challenge;
    (lhs - rhs).to_affine()
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
        .use_k(params.degree as usize)
        .use_instance_columns(1);
    builder.set_lookup_bits(params.lookup_bits);
    builder
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

fn public_instance_values(public_input_cells: &[AssignedValue<BlsFr>]) -> Vec<BlsFr> {
    public_input_cells
        .iter()
        .map(|public_input| *public_input.value())
        .collect()
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

    CircuitStats {
        total_advice_cells,
        enabled_gate_constraints,
        total_lookup_cells,
        total_fixed_cells,
        config_params: builder.calculate_params(Some(params.unusable_rows)),
    }
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
