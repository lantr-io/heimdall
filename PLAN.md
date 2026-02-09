# Plan: PLONK Circuit for FROST Verification (BLS12-381)

## Goal

Build a Rust project implementing PLONK circuits that verify FROST DKG polynomial commitments, polynomial evaluations, and partial signatures. Proofs are verifiable on Cardano via native BLS12-381 builtins.

## Architecture

- **Proving system**: PLONK with KZG commitments over **BLS12-381** (`dusk-plonk`)
- **FROST protocol**: `frost-secp256k1-tr` from Zcash Foundation (DKG, signing, types)
- **On-chain verification**: BLS12-381 pairing checks via Cardano Plutus V3 builtins
- **In-circuit operations**: secp256k1 FROST verification via non-native field arithmetic

## Libraries

### `frost-secp256k1-tr` (v3.0.0-rc.0) — Zcash Foundation
- Reference FROST implementation with **Taproot** support on secp256k1
- Provides: DKG (keygen), signing rounds, share types, verification shares
- Used for: generating FROST keys/shares/signatures that the PLONK circuit then proves

### `dusk-plonk` (v0.22.0-rc.0) — Dusk Network
- Pure-Rust PLONK over **BLS12-381** with KZG polynomial commitments
- `Circuit` trait, `Composer` for arithmetic/EC gates, range checks
- Verification = BLS12-381 pairing equation → maps to Cardano Plutus V3 builtins

## Circuits

### 1. Commitment Verification Circuit
Verifies Feldman VSS commitments from DKG Round 1:
- **Public inputs**: commitment points `C_{j,0}, ..., C_{j,t-1}` (secp256k1), participant index `i`
- **Private witness**: share value `s_{j,i}`
- **Constraint**: `s_{j,i} * G == Σ_{k=0}^{t-1}(i^k * C_{j,k})`

### 2. Evaluation Verification Circuit
Verifies aggregated share derivation from DKG:
- **Public inputs**: individual commitments from all participants, verification share `Y_p`
- **Private witness**: individual shares `s_{j,p}`, combined share `s_p`
- **Constraints**: `s_p == Σ_j(s_{j,p})` and `s_p * G == Y_p`

### 3. Partial Signature Verification Circuit
Verifies a FROST signature share:
- **Public inputs**: verification share `Y_p`, nonce commitments `D_p, E_p`, binding factor `ρ_p`, challenge `c`, Lagrange coefficient `λ_p`
- **Private witness**: signature share `z_p`, secret nonces `d_p, e_p`, secret share `s_p`
- **Constraint**: `z_p * G == D_p + ρ_p * E_p + c * λ_p * Y_p`

## Non-Native Field Arithmetic

secp256k1 base field `p ≈ 2^256` doesn't fit in BLS12-381 scalar field `r ≈ 2^255`:
- Decompose into **4 limbs × 64 bits**
- Range checks on each limb (via dusk-plonk range gates)
- Schoolbook multiplication with carry propagation
- Modular reduction via quotient witnesses

## Project Structure

```
bifrost-spot/
├── Cargo.toml
├── flake.nix
├── CLAUDE.md
├── .envrc
└── src/
    ├── lib.rs              -- crate root, re-exports
    ├── frost/
    │   ├── mod.rs          -- re-export frost-secp256k1-tr types
    │   ├── dkg.rs          -- DKG wrapper using frost-secp256k1-tr
    │   └── signing.rs      -- signing wrapper using frost-secp256k1-tr
    ├── gadgets/
    │   ├── mod.rs
    │   ├── nonnative.rs    -- non-native field arithmetic (4×64-bit limbs)
    │   └── secp256k1.rs    -- secp256k1 point add/scalar_mul using nonnative
    ├── circuits/
    │   ├── mod.rs
    │   ├── commitment.rs   -- Feldman VSS commitment verification
    │   ├── evaluation.rs   -- polynomial evaluation & share aggregation
    │   └── signature.rs    -- FROST partial signature verification
    └── main.rs             -- CLI entry point, proof generation & verification
```

## Dependencies

```toml
[dependencies]
dusk-plonk = "0.22.0-rc.0"       # PLONK over BLS12-381
dusk-bls12_381 = "0.14"          # BLS12-381 curve
dusk-jubjub = "0.15"             # JubJub embedded curve
frost-secp256k1-tr = "3.0.0-rc.0" # FROST with Taproot on secp256k1
rand = "0.8"
hex = "0.4"
```

## Demo Scenario: Cheating SPO Detection

### Setup
- **3-of-5 threshold**: 5 SPOs run FROST DKG, threshold t=3
- All SPOs register with secp256k1 Bifrost identity keys

### Happy Path
1. Run DKG with all 5 honest SPOs
2. Each SPO publishes commitments and distributes encrypted shares
3. All shares verify against commitments → DKG succeeds
4. Group public key `Y` and verification shares `Y_p` produced

### Cheating Detection
1. SPO #3 sends a **bad share** to SPO #1 (doesn't match their published commitments)
2. SPO #1 detects: `s_{3,1} * G ≠ Σ(1^k * C_{3,k})` — Feldman VSS check fails
3. SPO #1 generates a **PLONK proof** proving:
   - "I received share `s_{3,1}` from SPO #3"
   - "SPO #3's published commitments are `C_{3,0}, ..., C_{3,t-1}`"
   - "The Feldman VSS equation does NOT hold"
4. This proof is a BLS12-381 PLONK proof → **verifiable on Cardano**
5. On-chain contract verifies the proof → SPO #3 is slashed

### What the PLONK Proof Demonstrates
- The prover (SPO #1) knows the share value (private witness)
- The commitments are public (from DKG Round 1 broadcast)
- The circuit checks `s * G` vs `Σ(i^k * C_k)` and proves they differ
- Succinct proof (~few hundred bytes) instead of revealing the share itself

## Implementation Steps

1. `cargo init` the project, set up Cargo.toml with dependencies
2. Implement `frost/` wrappers — thin layer over `frost-secp256k1-tr` for DKG and signing
3. Implement `gadgets::nonnative` — non-native field element type with add, mul, reduce
4. Implement `gadgets::secp256k1` — secp256k1 point operations using nonnative gadgets
5. Implement `circuits::commitment` — Feldman VSS commitment verification circuit (+ mismatch proof variant)
6. Implement `circuits::evaluation` — share aggregation verification circuit
7. Implement `circuits::signature` — FROST partial signature verification circuit
8. Wire up `main.rs` — 3-of-5 DKG demo with one cheating SPO, generate PLONK misbehavior proof
9. Add tests: honest DKG succeeds, cheating SPO detected with valid proof
