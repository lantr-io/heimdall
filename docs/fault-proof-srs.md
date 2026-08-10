# The fault-proof trusted setup

> **Status: the DKG fault verifiers deployed today are generated from an insecure
> test setup and must not back real value.** Heimdall refuses to start on mainnet
> with fault enforcement configured against it. Preprod and devnet are unaffected.

Most operators never need this file. Read it if you are deploying the DKG fault
verifiers, regenerating them, or wondering why a mainnet node refused to start
with a message about `cardano.fault_proof_srs_path`.

## What the SRS is, and why it is consensus-critical

Two of the three DKG fault proofs are Halo2 zero-knowledge proofs:

| Fault | Proved how | Needs the SRS? |
|---|---|---|
| DKG Round 1 — invalid proof of knowledge | Halo2 ZK, `k = 22` | yes |
| DKG Round 2 — share inconsistent with commitment | Halo2 ZK, `k = 18` | yes |
| Equivocation — two signed payloads for one namespace | two BIP-340 checks on chain | **no** |

A Halo2/KZG proof system is parameterised by a *structured reference string* —
powers of a secret scalar `tau` in the pairing groups. The on-chain verifier is
**generated** from it: `onchain/lib/bifrost/fault_verifier/round{1,2}/proof_verifier.ak`
embed `s_g2` (that is `[tau]_2`) along with KZG commitments to the circuit's fixed
and permutation columns.

Nobody may know `tau`. Whoever does can forge a proof of a fault that never
happened — one the on-chain verifier accepts — mint a `FaultProof` token, and get
an honest SPO banned. `tau` is the ceremony's *toxic waste*: a real setup is run
by many participants so that the secret is unrecoverable unless *every one* of
them colluded, and it is destroyed as the ceremony proceeds.

This is why an SRS is not a tuning knob. A wrong one does not make proofs slow;
it makes bans forgeable.

## Where things stand

The verifiers currently in the contracts repo were generated from
`StdRng::seed_from_u64(2)` — a deterministic test setup whose `tau` anyone can
recompute from two lines of public source. Concretely:

- `plutus-halo2-verifier-gen` (heimdall dev-dependency) has one SRS path,
  `get_or_create_kzg_params`: a cached `kzg_params/kzg_params_{k}` file if one
  exists, otherwise `ParamsKZG::unsafe_setup`, documented *"unsafe … only for
  testing purposes"*.
- `benches/dkg_fault_onchain.rs` — the generator in this repo — used the same
  seed unconditionally until `DKG_FAULT_SRS` was added.
- `ParamsKZG::setup` draws `tau` as its first and only use of the RNG, so the
  seed alone determines it, independent of `k`.
- The resulting `[tau]_2`, byte-reversed as the generator emits it, reproduces
  the `s_g2` constant committed in both `.ak` verifiers exactly. Asserted by
  `circuits::srs_provenance::tests::onchain_constant_is_the_seed2_tau`.

`fixed_0..3` and `permutation_common_0..4` in those files are derived from the
same SRS and are equally compromised. `n`, `omega`, `omega_inv` and
`barycentric_weight` depend only on the circuit's domain size and are unaffected.

Two things are **not** problems, and should not be "fixed" in a hurry:

- `insecure_test_srs` in `src/circuits/fault_evidence.rs` is correctly named,
  documented, and reachable only from `#[cfg(test)]` code.
- `.dummy-srs.bin` is a 48-byte placeholder — literally the ASCII string
  `dummy srs (never read on the equivocation path)`. Configs point at it only
  because setting `cardano.ban_bootstrap` makes every fault key mandatory, and
  those configs exercise the equivocation path, which uses no SRS at all. It
  cannot yield a forged proof: it fails to parse.

## What heimdall enforces

`circuits::srs_provenance::check_fault_srs` runs at startup, from
`DkgFaultBanFlow::from_config`, whenever `cardano.ban_bootstrap` is set. It reads
two small pieces of the SRS file rather than parsing it — `k` from the first four
bytes, `s_g2` from the last 96 — so the check costs nothing even for a ~400 MiB
`k = 22` file.

It fails the startup on **mainnet** — determined, as elsewhere in the codebase,
by `cardano.blockfrost_project_id` starting with `mainnet` — when the SRS is
missing, is not a `ParamsKZG` file in `Processed` format, has `k < 22`, or
carries the known-insecure `tau`. On every other network the same conditions log
a warning and continue: those deployments exercise equivocation, which needs no
SRS, and the Round 1 / Round 2 path still fails closed at proving time.

So a mainnet node cannot silently run with forgeable fault proofs, and a preprod
node keeps working exactly as before.

## Regenerating the verifiers against a different SRS

The generator lives in this repo because the circuits do. It is the
`dkg_fault_onchain` bench:

```bash
# Insecure deterministic setup — benchmarking and testnets only.
cargo bench --bench dkg_fault_onchain

# Against a real ceremony's parameters.
DKG_FAULT_SRS=/path/to/kzg_params_22 cargo bench --bench dkg_fault_onchain

# Emit the Aiken project without running the on-chain benchmark.
DKG_FAULT_ONCHAIN_GENERATE_ONLY=1 DKG_FAULT_SRS=/path/to/kzg_params_22 \
  cargo bench --bench dkg_fault_onchain
```

The SRS file must be `ParamsKZG::write_custom(.., SerdeFormat::Processed)` over
BLS12-381 with `k >= 22`. The bench prints the `s_g2` it generated against, and
says so loudly when that is the insecure one. Generated sources land under
`target/dkg_fault_onchain/`; they replace
`onchain/lib/bifrost/fault_verifier/round{1,2}/proof_verifier.ak` in the
contracts repo.

**Swapping the SRS is a redeploy, not a file swap.** New constants change the
compiled validators, so the script hashes change, so the policy IDs change. That
means: publish new reference scripts, update `cardano.fault_verifier_round1_ref`
and `cardano.fault_verifier_round2_ref` in every config, update any on-chain
Config that names those policies, and re-run the `FaultProof` end-to-end check on
chain. Budget for it.

Note also that this repo reads an SRS as `SerdeFormat::Processed` while
`plutus-halo2-verifier-gen`'s own `read_params` uses `SerdeFormat::RawBytesUnchecked`.
Both consume the same file; reconcile the two explicitly when converting a
ceremony transcript rather than assuming either one.

## Getting a real SRS

Not yet done — tracked as its own work item. The constraints that make it
procurement rather than engineering:

- The curve **must** be BLS12-381. Most published `.ptau` files — snarkjs, the
  original perpetual powers of tau — are BN254 and are simply unusable here.
- The degree must reach `2^22` for Round 1. That is 4,194,304 G1 points.
- Ethereum's KZG ceremony (EIP-4844) is the obvious candidate and **does not
  fit**: right curve and an excellent honesty assumption at ~141k participants,
  but built for blob commitments and topping out near `2^15`.
- Running our own ceremony among the SPO roster would be actively wrong — it
  hands `tau` to exactly the set the fault proofs exist to hold accountable. One
  honest participant is enough, so a large public ceremony beats anything
  in-house.
