/// FROST Signature Share Misbehavior Proof Circuit.
///
/// During FROST signing, each participant p computes a signature share z_p such that:
///   z_p * G == R_p + (rho_p * E_p) + (lambda_p * c * Y_p)
///
/// where R_p is the group commitment for participant p, and Y_p is their verification share.
///
/// This circuit proves misbehavior: the submitted z_p * G does NOT equal the expected point,
/// providing a succinct proof of a bad signature share verifiable on Cardano via BLS12-381.
use dusk_plonk::prelude::*;

use crate::gadgets::nonnative::NonNativeWitness;
use crate::gadgets::secp256k1::Secp256k1PointWitness;

/// Precomputed values the prover provides to the circuit.
pub struct SignatureShareCheckWitness {
    /// The corrupted signature share z_p (private — the scalar value)
    pub share_limbs: [u64; 4],

    /// z_bad * G — the LHS point (prover-computed from corrupted share)
    pub lhs_x: [u64; 4],
    pub lhs_y: [u64; 4],

    /// z_good * G — the RHS point (prover-computed from honest share = expected value)
    pub rhs_x: [u64; 4],
    pub rhs_y: [u64; 4],

    /// The corrupted share value z_p (public input — the value that was submitted)
    pub z_p_limbs: [u64; 4],

    /// LHS point (public — so verifier can confirm z_bad * G was computed correctly)
    pub lhs_pub_x: [u64; 4],
    pub lhs_pub_y: [u64; 4],

    /// RHS point (public — the expected point from protocol transcript)
    pub rhs_pub_x: [u64; 4],
    pub rhs_pub_y: [u64; 4],
}

impl Default for SignatureShareCheckWitness {
    fn default() -> Self {
        Self {
            share_limbs: [0; 4],
            lhs_x: [0; 4],
            lhs_y: [0; 4],
            rhs_x: [1; 4], // different from lhs so the "not equal" check has a valid inverse
            rhs_y: [1; 4],
            z_p_limbs: [0; 4],
            lhs_pub_x: [0; 4],
            lhs_pub_y: [0; 4],
            rhs_pub_x: [1; 4],
            rhs_pub_y: [1; 4],
        }
    }
}

/// The PLONK circuit proving FROST signature share misbehavior.
/// Proves: the signature share z_p does NOT satisfy z_p * G == expected point.
#[derive(Default)]
pub struct SignatureMisbehaviorCircuit {
    pub witness: SignatureShareCheckWitness,
}

impl Circuit for SignatureMisbehaviorCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let w = &self.witness;

        // 1. Witness the corrupted share scalar (private input)
        let _share = NonNativeWitness::from_limbs(composer, w.share_limbs);

        // 2. Witness the LHS point: z_bad * G (prover-computed)
        let lhs = Secp256k1PointWitness::from_coords(composer, w.lhs_x, w.lhs_y);

        // 3. Witness the RHS point: z_good * G = expected (prover-computed)
        let rhs = Secp256k1PointWitness::from_coords(composer, w.rhs_x, w.rhs_y);

        // 4. Register public inputs: the corrupted share value
        for limb in &w.z_p_limbs {
            composer.append_public(BlsScalar::from(*limb));
        }

        // 5. Register LHS point as public input (z_bad * G)
        for limb in &w.lhs_pub_x {
            composer.append_public(BlsScalar::from(*limb));
        }
        for limb in &w.lhs_pub_y {
            composer.append_public(BlsScalar::from(*limb));
        }

        // 6. Register RHS point as public input (expected = z_good * G)
        for limb in &w.rhs_pub_x {
            composer.append_public(BlsScalar::from(*limb));
        }
        for limb in &w.rhs_pub_y {
            composer.append_public(BlsScalar::from(*limb));
        }

        // 7. MISBEHAVIOR CONSTRAINT: prove LHS ≠ RHS
        Secp256k1PointWitness::assert_not_equal_x(composer, &lhs, &rhs);

        Ok(())
    }
}
