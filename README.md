# Heimdall

SPO program for the Bifrost Bridge, a Bitcoin-Cardano bridge that uses Cardano
SPOs as distributed custodians for BTC transfers.

Heimdall coordinates FROST threshold Schnorr signing over secp256k1. The
optimistic protocol keeps DKG and signing communication off-chain, while direct
DKG faults are proven with Axiom Halo2 circuits and verified on Cardano through
generated Aiken/Plutus validators.

## DKG Fault-Proof Path

The DKG fault-proof implementation is in:

```text
src/circuits/dkg_fault.rs
benches/dkg_fault_circuits.rs
benches/dkg_fault_onchain.rs
scripts/generate_dkg_fault_aiken_project.sh
```

The circuits use Axiom's Halo2 stack with BLS12-381 KZG, SHPLONK, and a
Cardano-friendly Blake2b transcript.

The implemented DKG fault cases are:

- Round 1 invalid proof-of-knowledge fault.
- Round 2 invalid share fault.

The on-chain benchmark generates an Aiken minting policy that verifies the
Halo2 proof with two public inputs:

```text
[evidence_hash, pool_id]
```

It mints exactly one fault token whose name is:

```text
blake2b_256(pool_id || evidence_hash)
```

## Build

Requires Rust 2024 edition. A Nix flake is provided for reproducible builds.

```sh
nix develop
RUSTC_BOOTSTRAP=1 RUSTFLAGS='-D warnings' cargo check --all-targets
```

Without Nix, use a local Rust toolchain that can build the pinned dependencies.

## DKG Fault Benchmarks

Run the off-chain circuit proof benchmarks:

```sh
RUSTC_BOOTSTRAP=1 RUSTFLAGS='-D warnings' \
  cargo bench --bench dkg_fault_circuits
```

Run the on-chain Aiken/Plutus benchmark for Round 1:

```sh
RUSTC_BOOTSTRAP=1 RUSTFLAGS='-D warnings' \
  DKG_FAULT_ONCHAIN_ROUND=round1 \
  cargo bench --bench dkg_fault_onchain
```

Run the on-chain Aiken/Plutus benchmark for Round 2:

```sh
RUSTC_BOOTSTRAP=1 RUSTFLAGS='-D warnings' \
  DKG_FAULT_ONCHAIN_ROUND=round2 \
  cargo bench --bench dkg_fault_onchain
```

Generate the Aiken projects without running the Aiken benchmark:

```sh
scripts/generate_dkg_fault_aiken_project.sh
```

This writes:

```text
target/dkg_fault_onchain/round1/
target/dkg_fault_onchain/round2/
```

Build a generated Plutus blueprint with:

```sh
cd target/dkg_fault_onchain/round1
aiken build
```

or:

```sh
cd target/dkg_fault_onchain/round2
aiken build
```

## Dependencies

Important proving and protocol dependencies:

| Crate | Purpose |
| --- | --- |
| `frost-secp256k1-tr` | FROST over secp256k1/Taproot |
| `halo2-base`, `halo2-ecc` | Axiom Halo2 circuit construction |
| `pse-poseidon` | Poseidon public-input digest inside the circuit |
| `plutus-halo2-verifier-gen` | Aiken verifier generation for Axiom SHPLONK proofs |
| `pallas-*`, `whisky-*`, `uplc` | Cardano transaction/data/script tooling |

## References

- [Bifrost Bridge](https://github.com/FluidTokens/ft-bifrost-bridge)
- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
- [FROST Explainer](https://lantr.io/blog/frost-schnorr-threshold-signatures-bitcoin/)

## License

All rights reserved.
