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
- Equivocation over two signed DKG payloads in the same namespace.

For Round 1 and Round 2, the on-chain benchmark generates an Aiken minting
policy that verifies the Halo2 proof with two public inputs:

```text
[evidence_hash, pool_id]
```

Heimdall signs canonical DKG payload bytes that carry the same
`evidence_hash`, so Bifrost can verify the accused SPO's BIP-340 signature over
the payload and compare the signed evidence hash with the Halo2 public input.

It mints exactly one fault token whose name is:

```text
blake2b_256(pool_id || evidence_hash)
```

The same benchmark also builds and evaluates signed Bifrost transactions using
the corresponding Round 1, Round 2, or equivocation verifier policy from the
Bifrost `plutus.json` artifact pinned by URL in the benchmark: the fault-token
mint transaction and the first-ban `spo_bans.ApplyBan` transaction that consumes
and burns the fault token. The equivocation benchmark does not use a Halo2
proof; the Bifrost policy verifies both signatures, same-namespace payload
binding, distinct payloads, and the equivocation evidence hash. The transactions
use reference scripts and check both phase-2 ExUnits and transaction size.

When the on-chain ban list is configured for the epoch loop, Heimdall also
enables automatic DKG fault banning. The following `[cardano]` fields must be
set with the same deployed Bifrost scripts and parameters:

```toml
registry_blueprint = "path/to/bifrost/onchain/plutus.json"
registry_bootstrap = "<tx_hash>:<index>"
ban_bootstrap = "<tx_hash>:<index>"
fault_proof_policies = [
  "<round1_fault_policy_id>",
  "<round2_fault_policy_id>",
  "<equivocation_fault_policy_id>",
]
base_ban_duration_ms = 86400000
max_faults_before_permanent = 3
max_validity_window_ms = 600000
spo_bans_ref = "<tx_hash>:<index>"
fault_verifier_round1_ref = "<tx_hash>:<index>"
fault_verifier_round2_ref = "<tx_hash>:<index>"
fault_verifier_equivocation_ref = "<tx_hash>:<index>"
fault_proof_srs_path = "path/to/bls12_381_kzg_srs.params"
```

The fault verifier and `spo_bans` reference-script UTxOs are required for the
automatic mint/apply-ban transaction sequence. The SRS file must be a trusted
BLS12-381 KZG SRS serialized by Axiom Halo2 with
`ParamsKZG::write_custom(..., SerdeFormat::Processed)`.

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

Run the on-chain Bifrost equivocation benchmark:

```sh
RUSTC_BOOTSTRAP=1 RUSTFLAGS='-D warnings' \
  DKG_FAULT_ONCHAIN_ROUND=equivocation \
  cargo bench --bench dkg_fault_onchain
```

Omit `DKG_FAULT_ONCHAIN_ROUND` or set it to `all` to run all three fault
policy benchmarks. The full-transaction benchmark downloads the pinned Bifrost
`plutus.json` artifact from GitHub.

Override the full-transaction limits with:

```sh
DKG_FAULT_MAX_TX_EX_MEM=16500000
DKG_FAULT_MAX_TX_EX_CPU=10000000000
DKG_FAULT_MAX_TX_SIZE_BYTES=16384
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
