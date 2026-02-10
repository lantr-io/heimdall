# Heimdall

## Project Goal

Build **Heimdall**, the SPO (Stake Pool Operator) program for the Bifrost Bridge — a Bitcoin-Cardano bridge that uses Cardano SPOs as distributed custodians to secure BTC transfers between chains.

This program is responsible for:

1. **Bitcoin peg-in processing** — detecting BTC deposits to the treasury, confirming them, and facilitating minting of fBTC on Cardano
2. **Bitcoin peg-out processing** — handling fBTC burn requests and coordinating BTC withdrawals from treasury
3. **SPO registration** — binding Cardano pool identity to Bifrost identity keys and managing membership
4. **FROST signature aggregation** — coordinating distributed key generation (DKG) and threshold signing among SPOs

## Bifrost Bridge Architecture

Reference: [FluidTokens/ft-bifrost-bridge](https://github.com/FluidTokens/ft-bifrost-bridge)

### Security Model

- Security assumption: **weighted-majority of Cardano SPOs must behave honestly**
- No single point of failure — uses FROST threshold signatures instead of multisig
- Optimistic bridge design — operations span 1+ Cardano epochs (5+ days)
- Prioritizes security and availability over speed

### On-Chain Components

- **Cardano smart contracts**: `peg_in.ak`, `peg_out.ak` managing peg operations
- **Bitcoin treasury**: under FROST multisig SPO control (Taproot address)
- **Binocular Oracle**: tracks Bitcoin block headers and state on Cardano
- **Membership tokens**: one-per-SPO via minting policy, tracked in Patricia Merkle Tree

### Participants

- **Depositors/Withdrawers**: users moving BTC <-> fBTC
- **SPOs**: distributed custodians running this program (Heimdall)
- **Watchtowers**: permissionless monitors posting Bitcoin block headers and proofs

## Peg-In Flow (Bitcoin -> Cardano)

1. User mints unique NFT on Cardano, locks in `peg_in.ak` smart contract
2. User sends BTC to current treasury address with NFT reference in metadata
3. Watchtower detects deposit after 100+ Bitcoin confirmations (~12 hours)
4. Watchtower constructs Merkle inclusion proof using Binocular Oracle
5. Bridged fBTC minted on Cardano, NFT burned

## Peg-Out Flow (Cardano -> Bitcoin)

1. User mints unique NFT on Cardano
2. User sends fBTC + NFT to `peg_out.ak` contract
3. SPOs coordinate FROST-signed Bitcoin transaction from treasury
4. Watchtower creates Bitcoin transaction inclusion proof
5. Request completed, NFT and fBTC burned

## FROST Protocol (Flexible Round-Optimized Schnorr Threshold Signatures)

Reference: RFC 9591, [FROST explainer](https://lantr.io/blog/frost-schnorr-threshold-signatures-bitcoin/)

FROST enables t-of-n SPOs to jointly produce a Schnorr signature without any single party knowing the full secret key. The resulting signature is indistinguishable from a single-signer Taproot spend on Bitcoin.

### Threshold Calculation

Threshold `t` = minimum number of SPOs where even the weakest `t` participants exceed the protocol-defined security threshold (weighted by stake).

### Distributed Key Generation (DKG)

Executes off-chain each epoch. Produces group public key `Y` and individual signing shares.

1. Candidate set determined by Patricia Merkle Tree root at epoch boundary
2. Lexicographic ordering by `bifrost_id_pk` assigns participant indices
3. **Round 0**: Initialization, candidate enumeration
4. **Round 1**: Each SPO generates random polynomial, publishes commitments + proof-of-knowledge
5. **Round 2**: Secret shares encrypted via ECDH (using recipients' `bifrost_id_pk`) and distributed
6. Each SPO derives combined share `sp = sum_j(fj(p))`, group key `Y`, and new treasury address
7. Current roster FROST-signs treasury handoff transaction to new address

### Two-Round Signing Protocol

**Round 1 (Commitment):** Each signing SPO generates nonce pair `(dp, ep)`, publishes curve points `(Dp, Ep)`.

**Round 2 (Response):** Each SPO computes:
- Binding factors: `rho_p = H(Y || all_commitments || m || p)`
- Group commitment: `R = sum(Dp + rho_p * Ep)`
- Challenge: `c = H(R || Y || m)`
- Lagrange coefficient: `lambda_p` for their index in the signing set
- Signature share: `zp = dp + rho_p * ep + lambda_p * sp * c`

Coordinator aggregates: `z = sum(zp)`, producing final signature `(R, z)`.

### Misbehavior Detection

- Identifiable abort: invalid shares detectable via verification shares `Yp = sp * G`
- Misbehaving SPOs slashed via Membership Exit mechanism (FROST group signature from current roster)
- DKG restarts with reduced candidate set after slashing

## SPO Registration & Identity

### Key Types

| Key | Curve | Purpose |
|-----|-------|---------|
| Pool ID | blake2b_224 of cold vkey | Cardano pool identity |
| Cold keys | Ed25519 | Registration and revocation only (minimized exposure) |
| Bifrost identity | Secp256k1 | All protocol operations (DKG, signing) |
| Bifrost URL | — | Endpoint for DKG data publication |

### Registration

- One-time on-chain registration binding pool ID to Bifrost identity
- Membership token minted (one per SPO, enforced by minting policy)
- Patricia Merkle Tree updated with `bifrost_id_pk` and `bifrost_url`
- Security deposit required for economic accountability

### Exit

- **Voluntary**: cold key signed revocation
- **Forced**: roster-initiated slashing via FROST group signature
- Both update the Patricia Merkle Tree

## Watchtower & Binocular Oracle

- Watchtowers monitor Bitcoin for new blocks, submit 80-byte headers to oracle
- Oracle validates Bitcoin consensus rules (PoW, difficulty, timestamps, chain continuity)
- Maintains fork tree with chainwork-based canonical chain selection
- 200-minute challenge window before finalization
- Only one honest watchtower needed for system correctness
- Anyone can run a watchtower (permissionless)

## Cryptographic Details

- Single curve: **secp256k1** for all Bifrost operations (eliminates conversion complexity)
- Bitcoin integration via **Taproot/BIP-340** Schnorr signatures
- ECDH for encrypted share distribution during DKG
- Replay resistance via epoch binding
- Air-gapped signing supported for registration/revocation

## Development Guidelines

- This is a Rust project
- Security-critical code — prioritize correctness over performance
- All FROST operations must support identifiable abort
- DKG and signing are off-chain; only results posted on-chain
- Treasury handoff transactions must be atomic with epoch transitions
- Never include "Co-Authored-By" or "Co-authored-by" lines in commit messages
