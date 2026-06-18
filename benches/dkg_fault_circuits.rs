use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use frost::{Ciphersuite, Identifier};
use frost_secp256k1_tr as frost;
use halo2_base::{
    gates::circuit::builder::RangeCircuitBuilder,
    halo2_proofs::{
        halo2curves::{
            bls12_381::{Bls12, Fr as BlsFr, G1Affine},
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
use heimdall::circuits::cardano_transcript::{CardanoBlake2bRead, CardanoBlake2bWrite};
use k256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        PrimeField,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use rand::{SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha20Rng;

use heimdall::circuits::dkg_fault::{
    AxiomDkgCircuitParams, CircuitStats, DkgRound1PokDigestFaultWitness, DkgRound1PokFaultWitness,
    DkgRound2ShareFaultWitness, axiom_point_from_compressed, axiom_point_from_projective,
    axiom_scalar_from_be_bytes, build_round1_digest_fault_keygen_circuit,
    build_round1_digest_fault_prover_circuit, build_round1_keygen_circuit,
    build_round1_prover_circuit, build_round2_digest_fault_keygen_circuit,
    build_round2_digest_fault_prover_circuit, build_round2_keygen_circuit,
    build_round2_prover_circuit, is_identity, round1_digest_residual, round1_hdk_challenge,
    round1_message_digest, round1_residual, round2_message_digest, round2_residual,
};
use heimdall::frost::participant;

const ROUND2_T: usize = 2;
const ROUND2_INDEX_BITS: usize = 16;

fn main() {
    println!(
        "backend: Axiom halo2-axiom, BLS12-381 KZG, SHPLONK, Cardano-friendly Blake2b transcript"
    );

    run_round1_benchmark(AxiomDkgCircuitParams::default());
    run_round1_digest_fault_benchmark(AxiomDkgCircuitParams::round1_digest_fault());
    run_round2_benchmark(AxiomDkgCircuitParams::default());
    run_round2_digest_fault_benchmark(AxiomDkgCircuitParams::round2_digest_fault());
}

fn run_round1_benchmark(params: AxiomDkgCircuitParams) {
    let cases = round1_fixtures();
    let (keygen_builder, stats) = build_round1_keygen_circuit(params, &cases[0].witness);
    let setup = setup(params);
    let (pk, break_points, keygen_times) = keygen(&setup, keygen_builder);

    println!();
    println!("== round1-pok ==");
    print_circuit_config(params);
    print_stats(&stats, params);
    print_keygen_times(&keygen_times);

    for case in cases {
        let (prover_builder, public_instances) = build_round1_prover_circuit(
            stats.config_params.clone(),
            break_points.clone(),
            params,
            &case.witness,
        );
        let computed = round1_residual(&case.witness);
        assert_eq!(
            computed == case.transcript_r,
            case.expect_residual_matches_transcript
        );
        run_proof_case(
            &setup,
            &pk,
            prover_builder,
            &public_instances,
            &case.name,
            case.host_check_label(),
        );
    }
}

fn run_round1_digest_fault_benchmark(params: AxiomDkgCircuitParams) {
    let case = round1_fixtures()
        .into_iter()
        .find(|case| !case.expect_residual_matches_transcript)
        .expect("round 1 corrupted fixture");
    assert_eq!(
        case.digest_witness.challenge,
        round1_hdk_challenge(&case.digest_witness)
    );
    let expected_digest = round1_message_digest(params, &case.digest_witness);
    let (keygen_builder, stats) =
        build_round1_digest_fault_keygen_circuit(params, &case.digest_witness);
    let setup = setup(params);
    let (pk, break_points, keygen_times) = keygen(&setup, keygen_builder);

    println!();
    println!("== round1-pok-digest-fault ==");
    print_circuit_config(params);
    print_stats(&stats, params);
    print_keygen_times(&keygen_times);

    let (prover_builder, public_instances) = build_round1_digest_fault_prover_circuit(
        stats.config_params.clone(),
        break_points,
        params,
        &case.digest_witness,
    );
    assert_eq!(public_instances, vec![expected_digest]);
    let computed = round1_digest_residual(&case.digest_witness);
    assert_ne!(computed, case.digest_witness.transcript_r);
    run_proof_case(
        &setup,
        &pk,
        prover_builder,
        &public_instances,
        &case.name,
        "public input = Poseidon(message), circuit derives HDKG and asserts D != R",
    );
}

fn run_round2_benchmark(params: AxiomDkgCircuitParams) {
    let cases = round2_fixtures();
    let (keygen_builder, stats) =
        build_round2_keygen_circuit::<ROUND2_T, ROUND2_INDEX_BITS>(params, &cases[0].witness);
    let setup = setup(params);
    let (pk, break_points, keygen_times) = keygen(&setup, keygen_builder);

    println!();
    println!("== round2-share ==");
    print_circuit_config(params);
    print_stats(&stats, params);
    print_keygen_times(&keygen_times);

    for case in cases {
        let (prover_builder, public_instances) =
            build_round2_prover_circuit::<ROUND2_T, ROUND2_INDEX_BITS>(
                stats.config_params.clone(),
                break_points.clone(),
                params,
                &case.witness,
            );
        let computed = round2_residual(&case.witness);
        assert_eq!(is_identity(&computed), case.expect_identity_residual);
        run_proof_case(
            &setup,
            &pk,
            prover_builder,
            &public_instances,
            &case.name,
            case.host_check_label(),
        );
    }
}

fn run_round2_digest_fault_benchmark(params: AxiomDkgCircuitParams) {
    let case = round2_fixtures()
        .into_iter()
        .find(|case| !case.expect_identity_residual)
        .expect("round 2 corrupted fixture");
    let expected_digest =
        round2_message_digest::<ROUND2_T, ROUND2_INDEX_BITS>(params, &case.witness);
    let (keygen_builder, stats) = build_round2_digest_fault_keygen_circuit::<
        ROUND2_T,
        ROUND2_INDEX_BITS,
    >(params, &case.witness);
    let setup = setup(params);
    let (pk, break_points, keygen_times) = keygen(&setup, keygen_builder);

    println!();
    println!("== round2-share-digest-fault ==");
    print_circuit_config(params);
    print_stats(&stats, params);
    print_keygen_times(&keygen_times);

    let (prover_builder, public_instances) =
        build_round2_digest_fault_prover_circuit::<ROUND2_T, ROUND2_INDEX_BITS>(
            stats.config_params.clone(),
            break_points,
            params,
            &case.witness,
        );
    assert_eq!(public_instances, vec![expected_digest]);
    let computed = round2_residual(&case.witness);
    assert!(!is_identity(&computed));
    run_proof_case(
        &setup,
        &pk,
        prover_builder,
        &public_instances,
        &case.name,
        "public input = Poseidon(message), circuit asserts D != identity",
    );
}

fn setup(params: AxiomDkgCircuitParams) -> ParamsKZG<Bls12> {
    ParamsKZG::<Bls12>::setup(params.degree, StdRng::seed_from_u64(2))
}

fn keygen(
    setup: &ParamsKZG<Bls12>,
    keygen_builder: RangeCircuitBuilder<BlsFr>,
) -> (ProvingKey<G1Affine>, Vec<Vec<usize>>, KeygenTimes) {
    let vk_start = Instant::now();
    let vk = keygen_vk(setup, &keygen_builder).expect("vkey generation should succeed");
    let vk_time = vk_start.elapsed();

    let pk_start = Instant::now();
    let pk = keygen_pk(setup, vk, &keygen_builder).expect("pkey generation should succeed");
    let pk_time = pk_start.elapsed();

    let break_points = keygen_builder.break_points();
    (pk, break_points, KeygenTimes { vk_time, pk_time })
}

fn run_proof_case<C>(
    setup: &ParamsKZG<Bls12>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    public_instances: &[BlsFr],
    name: &str,
    host_check: &str,
) where
    C: Circuit<BlsFr>,
{
    let proof_start = Instant::now();
    let proof = gen_proof(setup, pk, circuit, public_instances);
    let proof_time = proof_start.elapsed();

    let verify_start = Instant::now();
    verify(setup, pk, &proof, public_instances);
    let verify_time = verify_start.elapsed();

    println!("case: {name}");
    println!("  public_instance_count: {}", public_instances.len());
    println!("  proof_size_bytes: {}", proof.len());
    println!("  proof_time: {}", fmt_duration(proof_time));
    println!("  verify_time: {}", fmt_duration(verify_time));
    println!("  host_check: {host_check}");
}

fn gen_proof<C>(
    params: &ParamsKZG<Bls12>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    public_instances: &[BlsFr],
) -> Vec<u8>
where
    C: Circuit<BlsFr>,
{
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
    >(params, pk, &[circuit], &[instances], rng, &mut transcript)
    .expect("proof generation should succeed");
    transcript.finalize()
}

fn verify(
    params: &ParamsKZG<Bls12>,
    pk: &ProvingKey<G1Affine>,
    proof: &[u8],
    public_instances: &[BlsFr],
) {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
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
    .expect("proof verification should succeed");
}

fn print_circuit_config(params: AxiomDkgCircuitParams) {
    println!(
        "circuit_config: k={}, lookup_bits={}, advice_columns={}, lookup_advice_columns={}, fixed_columns={}, limb_bits={}, num_limbs={}, window_bits={}, unusable_rows={}",
        params.degree,
        params.lookup_bits,
        params.advice_columns,
        params.lookup_advice_columns,
        params.fixed_columns,
        params.limb_bits,
        params.num_limbs,
        params.window_bits,
        params.unusable_rows
    );
}

fn print_stats(stats: &CircuitStats, params: AxiomDkgCircuitParams) {
    println!(
        "shape: k={}, usable_rows={}, advice={:?}, lookup_advice={:?}, fixed={}, lookup_bits={:?}",
        stats.config_params.k,
        (1usize << stats.config_params.k) - params.unusable_rows,
        stats.config_params.num_advice_per_phase,
        stats.config_params.num_lookup_advice_per_phase,
        stats.config_params.num_fixed,
        stats.config_params.lookup_bits
    );
    println!("total_advice_cells: {}", stats.total_advice_cells);
    println!(
        "enabled_gate_constraints: {}",
        stats.enabled_gate_constraints
    );
    println!("total_lookup_cells: {}", stats.total_lookup_cells);
    println!("total_fixed_cells: {}", stats.total_fixed_cells);
}

fn print_keygen_times(times: &KeygenTimes) {
    println!("vk_time: {}", fmt_duration(times.vk_time));
    println!("pk_time: {}", fmt_duration(times.pk_time));
}

fn fmt_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}

#[derive(Clone, Copy)]
struct KeygenTimes {
    vk_time: Duration,
    pk_time: Duration,
}

struct Round1Case {
    name: String,
    witness: DkgRound1PokFaultWitness,
    digest_witness: DkgRound1PokDigestFaultWitness,
    transcript_r: Secp256k1Affine,
    expect_residual_matches_transcript: bool,
}

impl Round1Case {
    fn host_check_label(&self) -> &'static str {
        if self.expect_residual_matches_transcript {
            "D == R"
        } else {
            "D != R"
        }
    }
}

struct Round2Case {
    name: String,
    witness: DkgRound2ShareFaultWitness,
    expect_identity_residual: bool,
}

impl Round2Case {
    fn host_check_label(&self) -> &'static str {
        if self.expect_identity_residual {
            "D == identity"
        } else {
            "D != identity"
        }
    }
}

fn round1_fixtures() -> Vec<Round1Case> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x524f_554e_4431);
    let participant_identifier = 1u16;
    let identifier = Identifier::try_from(participant_identifier).unwrap();
    let (_secret, package) = participant::dkg_part1(identifier, 3, 2, &mut rng).unwrap();

    let commitments = package.commitment().serialize().unwrap();
    let phi0_bytes: [u8; 33] = commitments[0].as_slice().try_into().unwrap();
    let phi0 = axiom_point_from_compressed(&phi0_bytes);

    let proof_bytes = package.proof_of_knowledge().serialize().unwrap();
    let mut mu_bytes = [0u8; 32];
    mu_bytes.copy_from_slice(&proof_bytes[32..64]);
    let mu = axiom_scalar_from_be_bytes(&mu_bytes);

    let mut r_bytes = [0u8; 33];
    r_bytes[0] = 0x02;
    r_bytes[1..].copy_from_slice(&proof_bytes[..32]);
    let honest_r_projective = projective_from_compressed(&r_bytes);
    let corrupted_r_projective = honest_r_projective + ProjectivePoint::GENERATOR;

    [
        ("round1-honest-pok", honest_r_projective, true),
        ("round1-corrupted-pok", corrupted_r_projective, false),
    ]
    .into_iter()
    .map(|(name, transcript_r_projective, expect_match)| {
        let transcript_r_bytes = compressed_from_projective(transcript_r_projective);
        let challenge = round1_challenge(identifier, &phi0_bytes, &transcript_r_bytes);
        let witness = DkgRound1PokFaultWitness {
            mu,
            challenge,
            phi0,
        };
        let transcript_r = axiom_point_from_projective(transcript_r_projective);
        let digest_witness = DkgRound1PokDigestFaultWitness {
            identifier: u64::from(participant_identifier),
            mu,
            challenge,
            phi0,
            transcript_r,
        };
        Round1Case {
            name: name.to_string(),
            witness,
            digest_witness,
            transcript_r,
            expect_residual_matches_transcript: expect_match,
        }
    })
    .collect()
}

fn round1_challenge(identifier: Identifier, phi0_bytes: &[u8; 33], r_bytes: &[u8; 33]) -> Fq {
    let mut challenge_preimage = Vec::new();
    challenge_preimage.extend_from_slice(&identifier.serialize());
    challenge_preimage.extend_from_slice(phi0_bytes);
    challenge_preimage.extend_from_slice(r_bytes);
    let challenge = frost::Secp256K1Sha256TR::HDKG(&challenge_preimage).unwrap();
    let challenge_bytes: [u8; 32] = challenge.to_bytes().into();
    axiom_scalar_from_be_bytes(&challenge_bytes)
}

fn round2_fixtures() -> Vec<Round2Case> {
    let mut rng = ChaCha20Rng::seed_from_u64(0x524f_554e_4432);
    let ids: Vec<Identifier> = (1..=3u16)
        .map(|id| Identifier::try_from(id).unwrap())
        .collect();

    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for &id in &ids {
        let (secret, package) = participant::dkg_part1(id, 3, 2, &mut rng).unwrap();
        round1_secrets.insert(id, secret);
        round1_packages.insert(id, package);
    }

    let mut round2_packages_per_sender = BTreeMap::new();
    for &id in &ids {
        let others: BTreeMap<_, _> = round1_packages
            .iter()
            .filter(|&(&peer, _)| peer != id)
            .map(|(&peer, package)| (peer, package.clone()))
            .collect();
        let secret = round1_secrets.remove(&id).unwrap();
        let (_secret2, packages2) = participant::dkg_part2(secret, &others).unwrap();
        round2_packages_per_sender.insert(id, packages2);
    }

    let sender = ids[0];
    let recipient = ids[1];
    let participant_index = 2u64;
    let commitments = round1_packages[&sender]
        .commitment()
        .serialize()
        .unwrap()
        .into_iter()
        .map(|bytes| {
            let bytes: [u8; 33] = bytes.as_slice().try_into().unwrap();
            axiom_point_from_compressed(&bytes)
        })
        .collect::<Vec<_>>();

    let share_bytes = round2_packages_per_sender[&sender][&recipient]
        .signing_share()
        .serialize();
    let share_bytes: [u8; 32] = share_bytes.as_slice().try_into().unwrap();
    let honest_share = axiom_scalar_from_be_bytes(&share_bytes);
    let corrupted_share = {
        let scalar = Scalar::from_repr(share_bytes.into()).unwrap() + Scalar::ONE;
        let bytes: [u8; 32] = scalar.to_bytes().into();
        axiom_scalar_from_be_bytes(&bytes)
    };

    [
        ("round2-honest-share", honest_share, true),
        ("round2-corrupted-share", corrupted_share, false),
    ]
    .into_iter()
    .map(|(name, share, expect_identity)| Round2Case {
        name: name.to_string(),
        witness: DkgRound2ShareFaultWitness {
            share,
            participant_index,
            commitments: commitments.clone(),
        },
        expect_identity_residual: expect_identity,
    })
    .collect()
}

fn projective_from_compressed(bytes: &[u8; 33]) -> ProjectivePoint {
    let encoded = EncodedPoint::from_bytes(bytes).unwrap();
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)).unwrap();
    ProjectivePoint::from(affine)
}

fn compressed_from_projective(point: ProjectivePoint) -> [u8; 33] {
    let encoded = point.to_affine().to_encoded_point(true);
    encoded.as_bytes().try_into().unwrap()
}
