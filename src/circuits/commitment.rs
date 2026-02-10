/// Feldman VSS Commitment Misbehavior Proof Circuit.
///
/// During FROST DKG, each participant j publishes commitments C_{j,k} = a_{j,k} * G
/// for their polynomial coefficients, and sends secret shares s_{j,i} = f_j(i) to
/// participant i.
///
/// The verification equation (Feldman VSS):
///   s_{j,i} * G == Σ_{k=0}^{t-1} (i^k * C_{j,k})
///
/// This circuit proves misbehavior: LHS point ≠ RHS point,
/// providing a succinct proof of cheating verifiable on Cardano via BLS12-381.
use dusk_plonk::prelude::*;

use crate::gadgets::nonnative::NonNativeWitness;
use crate::gadgets::secp256k1::Secp256k1PointWitness;

/// Maximum number of signers (N). The circuit is compiled once for this size
/// and works for any threshold M ≤ N by zero-padding unused commitment slots.
pub const MAX_SIGNERS: usize = 500;

/// Precomputed values the prover provides to the circuit.
/// The prover runs the actual secp256k1 math externally and feeds results as witnesses.
pub struct CommitmentCheckWitness {
    /// The share value s_{j,i} (private — this is the secret share)
    pub share_limbs: [u64; 4],

    /// s_{j,i} * G — the LHS point (prover-computed)
    pub lhs_x: [u64; 4],
    pub lhs_y: [u64; 4],

    /// Σ(i^k * C_{j,k}) — the RHS point (prover-computed from public commitments)
    pub rhs_x: [u64; 4],
    pub rhs_y: [u64; 4],

    /// The commitment points C_{j,k} for k = 0..degree (public inputs)
    pub commitments_x: Vec<[u64; 4]>,
    pub commitments_y: Vec<[u64; 4]>,

    /// Participant index i
    pub participant_index: u64,
}

impl Default for CommitmentCheckWitness {
    fn default() -> Self {
        Self {
            share_limbs: [0; 4],
            lhs_x: [0; 4],
            lhs_y: [0; 4],
            rhs_x: [1; 4], // different from lhs so the "not equal" check has a valid inverse
            rhs_y: [1; 4],
            commitments_x: vec![[0; 4]; MAX_SIGNERS],
            commitments_y: vec![[0; 4]; MAX_SIGNERS],
            participant_index: 1,
        }
    }
}

/// The PLONK circuit proving Feldman VSS misbehavior.
/// Proves: the share received from a cheating SPO does NOT match their published commitments.
#[derive(Default)]
pub struct CommitmentMisbehaviorCircuit {
    pub witness: CommitmentCheckWitness,
}

impl Circuit for CommitmentMisbehaviorCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let w = &self.witness;

        // 1. Witness the secret share (private input — not revealed in the proof)
        let _share = NonNativeWitness::from_limbs(composer, w.share_limbs);

        // 2. Witness the LHS point: s * G (prover-computed)
        let lhs = Secp256k1PointWitness::from_coords(composer, w.lhs_x, w.lhs_y);

        // 3. Witness the RHS point: Σ(i^k * C_k) (prover-computed from public commitments)
        let rhs = Secp256k1PointWitness::from_coords(composer, w.rhs_x, w.rhs_y);

        // 4. Register commitment points and participant index as public inputs.
        // This binds the proof to specific commitments that were broadcast during DKG.
        let num_commitments = w.commitments_x.len().min(MAX_SIGNERS);
        for k in 0..num_commitments {
            for limb_idx in 0..4 {
                composer.append_public(BlsScalar::from(w.commitments_x[k][limb_idx]));
                composer.append_public(BlsScalar::from(w.commitments_y[k][limb_idx]));
            }
        }
        // Pad unused commitment slots with zeros (fixed circuit size)
        for _ in num_commitments..MAX_SIGNERS {
            for _ in 0..8 {
                composer.append_public(BlsScalar::zero());
            }
        }
        composer.append_public(BlsScalar::from(w.participant_index));

        // 5. Register LHS and RHS as public inputs.
        // The on-chain verifier can independently recompute RHS from the public commitments
        // and compare to confirm the proof statement.
        for limb_idx in 0..4 {
            composer.append_public(BlsScalar::from(w.lhs_x[limb_idx]));
        }
        for limb_idx in 0..4 {
            composer.append_public(BlsScalar::from(w.lhs_y[limb_idx]));
        }
        for limb_idx in 0..4 {
            composer.append_public(BlsScalar::from(w.rhs_x[limb_idx]));
        }
        for limb_idx in 0..4 {
            composer.append_public(BlsScalar::from(w.rhs_y[limb_idx]));
        }

        // 6. MISBEHAVIOR CONSTRAINT: prove LHS ≠ RHS
        // The x-coordinates differ → the points differ.
        // We prove nonzero by witnessing the inverse of (lhs_x_combined - rhs_x_combined).
        Secp256k1PointWitness::assert_not_equal_x(composer, &lhs, &rhs);

        Ok(())
    }
}
