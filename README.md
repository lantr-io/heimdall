# Heimdall

SPO (Stake Pool Operator) program for the [Bifrost Bridge](https://github.com/FluidTokens/ft-bifrost-bridge) — a Bitcoin-Cardano bridge that uses Cardano SPOs as distributed custodians to secure BTC transfers between chains.

## What is this?

Heimdall coordinates Cardano SPOs to jointly custody Bitcoin using **FROST threshold Schnorr signatures** (RFC 9591). The resulting Taproot signature on Bitcoin is indistinguishable from a single-signer spend — no multisig scripts, no on-chain footprint.

The protocol is **optimistic**: all FROST communication (DKG and signing) happens off-chain via a pull-only model. Only the final aggregated signature is posted on-chain. If any participant misbehaves, an honest party submits a **PLONK proof** of misbehavior on Cardano, and the cheater is slashed.

## Security Model

- **Weighted-majority honesty assumption** — security is proportional to Cardano's total staked ADA
- **No single point of failure** — FROST M-of-N threshold, no party knows the full secret key
- **Identifiable abort** — cheating SPOs are detected and provably slashed
- **On-chain verification** — BLS12-381 PLONK proofs verified via Plutus V3 builtins

## Architecture

```
src/
├── lib.rs                    # Crate root
├── main.rs                   # Demo: 400-of-500 DKG + cheating detection + PLONK proof
├── frost/
│   ├── mod.rs
│   └── dkg.rs                # Parallelized FROST DKG (frost-secp256k1-tr wrapper)
├── gadgets/
│   ├── mod.rs
│   ├── nonnative.rs          # Non-native field arithmetic (secp256k1 over BLS12-381)
│   └── secp256k1.rs          # secp256k1 point operations in PLONK circuit
└── circuits/
    ├── mod.rs
    └── commitment.rs         # Feldman VSS misbehavior proof circuit
```

## How It Works

### FROST DKG

Each epoch, SPOs run Distributed Key Generation to produce:
- A **group public key** `Y` — the Taproot address for Bitcoin treasury
- **Individual signing shares** — each SPO holds a secret share, no one holds the full key

### Misbehavior Proof

If SPO `j` sends a bad secret share to SPO `i` during DKG:

1. SPO `i` detects the Feldman VSS check failure: `s_{j,i} * G ≠ Σ(i^k * C_{j,k})`
2. SPO `i` generates a PLONK proof showing LHS ≠ RHS without revealing the secret share
3. The proof is a BLS12-381 PLONK proof — verifiable on Cardano via Plutus V3 builtins
4. On-chain contract verifies the proof, cheating SPO is slashed

### Proof Characteristics

| Property       | Value                              |
| -------------- | ---------------------------------- |
| Proving system | PLONK over BLS12-381               |
| Circuit size   | 2^14 (16,384 constraints)          |
| Proof size     | 1,008 bytes                        |
| Public inputs  | 49 field elements                  |
| Max signers    | 500 (circuit supports any M ≤ 500) |

## Building

Requires Rust (2024 edition). A Nix flake is provided for reproducible builds.

```sh
# With Nix
nix develop
cargo build

# Without Nix
cargo build
```

## Running the Demo

The demo runs a 400-of-500 FROST DKG, injects a cheating SPO, detects the misbehavior, and generates a PLONK proof:

```sh
cargo run --release
```

Output:
```
=== Heimdall: FROST DKG + PLONK Misbehavior Proof ===
=== 400-of-500 threshold ===

--- Step 1: Running honest 400-of-500 DKG (single SPO completion) ---
--- Step 2: Running DKG with SPO #300 cheating (bad share to SPO #1) ---
--- Step 3: Generating PLONK misbehavior proof ---
  PROOF VERIFIED! SPO #300's misbehavior is proven.
  Verifiable on Cardano via Plutus V3 BLS12-381 builtins
```

## Dependencies

| Crate                | Version     | Purpose                               |
| -------------------- | ----------- | ------------------------------------- |
| `frost-secp256k1-tr` | 3.0.0-rc.0  | FROST with Taproot (Zcash Foundation) |
| `dusk-plonk`         | 0.22.0-rc.0 | PLONK proving system over BLS12-381   |
| `dusk-bls12_381`     | 0.14        | BLS12-381 curve                       |
| `rayon`              | 1.10        | Parallel DKG execution                |

## References

- [Optimistic FROST Protocol](Optimistic%20FROST.md) — full protocol specification
- [Stake Threshold Analysis](analysis/stake-threshold-analysis.md) — M-of-N parameter selection
- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) — FROST: Flexible Round-Optimized Schnorr Threshold Signatures
- [FROST Explainer](https://lantr.io/blog/frost-schnorr-threshold-signatures-bitcoin/) — intuitive overview
- [Bifrost Bridge](https://github.com/FluidTokens/ft-bifrost-bridge) — on-chain smart contracts

## License

All rights reserved.
