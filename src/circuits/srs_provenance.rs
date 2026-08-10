//! Provenance checks for the KZG structured reference string behind the DKG
//! fault proofs.
//!
//! # Why this module exists
//!
//! The round 1 and round 2 fault verifiers are *generated* from an SRS: the
//! Aiken sources embed `s_g2` (the setup's `[tau]_2` element) along with KZG
//! commitments to the fixed and permutation columns. Whoever knows `tau` can
//! forge a proof those verifiers accept, mint a `FaultProof`, and ban an
//! honest SPO. The SRS is therefore consensus-critical, not a tuning knob.
//!
//! The verifiers deployed today were generated from a *deterministic test*
//! setup — `StdRng::seed_from_u64(2)`, the same tau as
//! [`crate::circuits::fault_evidence::insecure_test_srs`] and as
//! `benches/dkg_fault_onchain.rs`. That tau is recoverable by anyone who reads
//! the source, so those verifiers are forgeable and must not back real value.
//! See `docs/fault-proof-srs.md`.
//!
//! This module makes that state *checkable* rather than folklore:
//! [`check_fault_srs`] refuses to start a mainnet node whose configured SRS
//! carries the known-insecure tau, and warns loudly everywhere else.
//!
//! The equivocation fault path is unaffected — it verifies two BIP-340
//! signatures on chain and uses no ZK proof, hence no SRS.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use tracing::warn;

/// Compressed BLS12-381 G1 element, as written by `ParamsKZG::write_custom`.
const G1_COMPRESSED_LEN: u64 = 48;
/// Compressed BLS12-381 G2 element.
const G2_COMPRESSED_LEN: usize = 96;
/// `k` is written as a little-endian `u32` before the point data.
const K_PREFIX_LEN: u64 = 4;

/// `tau * G2` for `tau` drawn from `StdRng::seed_from_u64(2)` — the tau behind
/// [`crate::circuits::fault_evidence::insecure_test_srs`], behind the
/// `benches/dkg_fault_onchain.rs` generator, and behind the fault verifiers
/// currently committed in the contracts repo.
///
/// Compressed, in the standard (`GroupEncoding::to_bytes`) byte order.
pub const INSECURE_SEED2_S_G2: &str = "dca072743cf5b6edcf68374bbee367f2cf1a38ccdbc4ac437cfa7daa9de4b3b8ed56ad385a94e03282d04e2a305216185475bf5382fa438889eeb078badd48b01e6f4a12a64bfeb7b52b90845e905e52c6fec4dc6f950b2bed817a028023fe8a";

/// The same point as it appears in the generated Aiken verifiers, which emit
/// `reverse_hex_bytes(g2_hex(s_g2))` — i.e. [`INSECURE_SEED2_S_G2`] with the
/// byte order reversed.
///
/// This is the literal `s_g2` constant in the contracts repo at
/// `onchain/lib/bifrost/fault_verifier/round1/proof_verifier.ak` and
/// `.../round2/proof_verifier.ak`. Keeping it here lets
/// [`tests::onchain_constant_is_the_seed2_tau`] assert the correspondence
/// without a checkout of that repo.
pub const INSECURE_SEED2_S_G2_ONCHAIN: &str = "8afe2380027a81ed2b0b956fdcc4fec6525e905e84902bb5b7fe4ba6124a6f1eb048ddba78b0ee898843fa8253bf7554181652302a4ed08232e0945a38ad56edb8b3e49daa7dfa7c43acc4dbcc381acff267e3be4b3768cfedb6f53c7472a0dc";

/// What [`read_srs_header`] could learn about an SRS file without parsing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsHeader {
    /// The degree the file was generated at: it holds `2^k` G1 points.
    pub k: u32,
    /// The setup's `[tau]_2`, hex, standard byte order.
    pub s_g2: String,
}

impl SrsHeader {
    /// Whether this SRS carries the known-insecure deterministic tau.
    #[must_use]
    pub fn is_insecure_seed2(&self) -> bool {
        self.s_g2 == INSECURE_SEED2_S_G2
    }
}

/// Read an SRS file's degree and `s_g2` without loading the point data.
///
/// `ParamsKZG::write_custom` lays the file out as `k` (u32 LE), then `2^k`
/// compressed G1 points for `g`, then `2^k` more for `g_lagrange`, then `g2`
/// and `s_g2` as compressed G2. So `k` is the first 4 bytes and `s_g2` is the
/// last 96 — both reachable with two small reads instead of the ~400 MiB a
/// `k = 22` file would cost to parse.
///
/// The length check that makes this safe is also the check that rejects a
/// placeholder file: a truncated or non-SRS file cannot have the exact length
/// the layout implies.
pub fn read_srs_header(path: &Path) -> Result<SrsHeader, String> {
    let mut file = File::open(path).map_err(|e| format!("open SRS {}: {e}", path.display()))?;
    let len = file
        .metadata()
        .map_err(|e| format!("stat SRS {}: {e}", path.display()))?
        .len();

    let mut k_bytes = [0u8; 4];
    file.read_exact(&mut k_bytes).map_err(|e| {
        format!(
            "read SRS {}: file is {len} bytes, too short to be a KZG SRS ({e})",
            path.display()
        )
    })?;
    let k = u32::from_le_bytes(k_bytes);
    // `2^k` points twice, and k is read from the file, so bound it before
    // shifting: BLS12-381's two-adicity caps any real SRS far below this.
    if k > 32 {
        return Err(format!(
            "SRS {} declares k={k}, which is not a plausible degree — the file \
             is probably not a KZG SRS in ParamsKZG format",
            path.display()
        ));
    }
    let n = 1u64 << k;
    let expected = K_PREFIX_LEN + 2 * n * G1_COMPRESSED_LEN + 2 * G2_COMPRESSED_LEN as u64;
    if len != expected {
        return Err(format!(
            "SRS {} declares k={k}, which implies a {expected}-byte file, but it \
             is {len} bytes — not a KZG SRS in ParamsKZG `Processed` format",
            path.display()
        ));
    }

    let mut s_g2 = [0u8; G2_COMPRESSED_LEN];
    file.seek(SeekFrom::End(-(G2_COMPRESSED_LEN as i64)))
        .map_err(|e| format!("seek SRS {}: {e}", path.display()))?;
    file.read_exact(&mut s_g2)
        .map_err(|e| format!("read SRS {} s_g2: {e}", path.display()))?;

    Ok(SrsHeader {
        k,
        s_g2: hex::encode(s_g2),
    })
}

/// Startup gate for the round 1 / round 2 fault-proof path.
///
/// On mainnet an SRS that is missing, malformed, too small, or carries the
/// known-insecure tau is a hard startup failure: a node that would mint
/// forgeable fault proofs must not run at all. Everywhere else the same
/// conditions warn and continue, so preprod and devnet keep working — they
/// exercise the equivocation path, which needs no SRS, and the round 1 /
/// round 2 path still fails closed at proving time if it is ever reached.
///
/// `required_k` is the largest degree either circuit needs; round 1 is the
/// binding one at `k = 22`.
pub fn check_fault_srs(path: &Path, required_k: u32, mainnet: bool) -> Result<(), String> {
    let refuse_or_warn = |problem: String| -> Result<(), String> {
        if mainnet {
            Err(format!(
                "{problem}\nRefusing to run on mainnet: the round 1 / round 2 fault \
                 verifiers are generated from this SRS, so an untrustworthy setup lets \
                 anyone forge a fault proof and ban an honest SPO. Point \
                 cardano.fault_proof_srs_path at an SRS from a real ceremony, or unset \
                 cardano.ban_bootstrap to leave fault enforcement off."
            ))
        } else {
            warn!("{problem}");
            warn!(
                "continuing because this is not mainnet — the equivocation fault path \
                 needs no SRS, and round 1 / round 2 proving will fail closed if reached"
            );
            Ok(())
        }
    };

    let header = match read_srs_header(path) {
        Ok(header) => header,
        Err(e) => return refuse_or_warn(e),
    };

    if header.k < required_k {
        return refuse_or_warn(format!(
            "SRS {} has k={} but the round 1 fault circuit needs k={required_k}",
            path.display(),
            header.k
        ));
    }

    if header.is_insecure_seed2() {
        return refuse_or_warn(format!(
            "SRS {} carries the known-insecure deterministic tau \
             (StdRng::seed_from_u64(2)); its toxic waste is recoverable by anyone who \
             reads the source, so proofs against it are forgeable",
            path.display()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::dkg_fault::AxiomDkgCircuitParams;
    use crate::circuits::fault_evidence::{insecure_test_srs, round1_params};
    use halo2_base::halo2_proofs::{
        SerdeFormat,
        halo2curves::{bls12_381::Bls12, group::GroupEncoding},
        poly::kzg::commitment::ParamsKZG,
    };
    use std::io::Write;

    /// Small enough to write in a test; tau does not depend on the degree.
    const TEST_K: u32 = 4;

    /// Per-test directory, matching the repo's temp-file idiom.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("heimdall-srs-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn write_srs(params: &ParamsKZG<Bls12>, path: &Path) {
        let mut buf = Vec::new();
        params
            .write_custom(&mut buf, SerdeFormat::Processed)
            .expect("serialize SRS");
        let mut f = File::create(path).expect("create SRS file");
        f.write_all(&buf).expect("write SRS file");
    }

    fn seed2_srs() -> ParamsKZG<Bls12> {
        insecure_test_srs(AxiomDkgCircuitParams {
            degree: TEST_K,
            ..round1_params()
        })
    }

    /// The constant this module gates on really is seed-2's tau — recomputed,
    /// not copied. `ParamsKZG::setup` draws tau as its first and only use of
    /// the rng, so a small k reproduces the same `s_g2` as `k = 22`.
    #[test]
    fn insecure_constant_matches_a_freshly_derived_seed2_srs() {
        let params = seed2_srs();
        assert_eq!(
            hex::encode(params.s_g2().to_bytes().as_ref()),
            INSECURE_SEED2_S_G2
        );
    }

    /// The `s_g2` compiled into the deployed Aiken verifiers is the same point
    /// in the generator's reversed byte order. If this ever fails, the
    /// contracts were regenerated against a different setup — which is the
    /// outcome we want, but the constants here must be updated with it.
    #[test]
    fn onchain_constant_is_the_seed2_tau() {
        let mut bytes = hex::decode(INSECURE_SEED2_S_G2).expect("hex");
        bytes.reverse();
        assert_eq!(hex::encode(bytes), INSECURE_SEED2_S_G2_ONCHAIN);
    }

    #[test]
    fn header_round_trips_and_flags_the_insecure_tau() {
        let path = scratch("header").join("kzg_params_4");
        write_srs(&seed2_srs(), &path);

        let header = read_srs_header(&path).expect("read header");
        assert_eq!(header.k, TEST_K);
        assert_eq!(header.s_g2, INSECURE_SEED2_S_G2);
        assert!(header.is_insecure_seed2());
    }

    /// The 48-byte `.dummy-srs.bin` placeholder — and anything else that is not
    /// an SRS — is rejected on its length, before any point is parsed.
    #[test]
    fn placeholder_file_is_rejected() {
        let path = scratch("placeholder").join("dummy-srs.bin");
        std::fs::write(&path, b"dummy srs (never read on the equivocation path)")
            .expect("write placeholder");

        let err = read_srs_header(&path).expect_err("placeholder must not parse");
        assert!(err.contains("not a KZG SRS"), "unexpected error: {err}");
    }

    #[test]
    fn mainnet_refuses_the_insecure_tau_and_other_networks_warn() {
        let path = scratch("gate").join("kzg_params_4");
        write_srs(&seed2_srs(), &path);

        let err = check_fault_srs(&path, TEST_K, true).expect_err("mainnet must refuse");
        assert!(err.contains("known-insecure"), "unexpected error: {err}");
        assert!(err.contains("Refusing to run on mainnet"));

        check_fault_srs(&path, TEST_K, false).expect("preprod continues");
    }

    #[test]
    fn mainnet_refuses_an_srs_that_is_too_small() {
        let path = scratch("too-small").join("kzg_params_4");
        write_srs(&seed2_srs(), &path);

        let err = check_fault_srs(&path, TEST_K + 1, true).expect_err("mainnet must refuse");
        assert!(err.contains("needs k="), "unexpected error: {err}");
    }

    #[test]
    fn mainnet_refuses_a_missing_srs() {
        let path = scratch("missing").join("absent");

        let err = check_fault_srs(&path, TEST_K, true).expect_err("mainnet must refuse");
        assert!(err.contains("open SRS"), "unexpected error: {err}");
        check_fault_srs(&path, TEST_K, false).expect("preprod continues");
    }
}
