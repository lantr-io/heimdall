# Heimdall Design Document

## 1. System Overview

Heimdall is the SPO (Stake Pool Operator) sidecar program for the Bifrost Bridge. It runs alongside a Cardano node and enables the SPO to participate in:

- **FROST Distributed Key Generation (DKG)** — producing group keys for the Bitcoin treasury
- **FROST Threshold Signing** — co-signing Bitcoin Treasury Movement transactions
- **Epoch Lifecycle Management** — detecting epoch boundaries, roster formation, treasury handoff
- **Misbehavior Detection & Proving** — generating PLONK proofs of DKG/signing misbehavior
- **Cardano Chain Interaction** — reading smart contract state, submitting transactions

The program is a long-running daemon with an HTTP server (the SPO's `bifrost_url` endpoint) and a Cardano chain follower.

## 2. Architecture

```
                                    +---------------------------+
                                    |      Bitcoin Network      |
                                    +---------------------------+
                                                 ^
                                                 | (Watchtowers relay signed TM txs)
                                                 |
+-------------------+    N2C     +------------------------------------------+
|   cardano-node    |<---------->|              HEIMDALL                     |
|   (SPO's node)    |            |                                          |
+-------------------+            |  +------------+  +---------------------+ |
                                 |  | Chain       |  | Epoch State Machine | |
                                 |  | Follower    |->| (DKG, Sign, Submit) | |
                                 |  +------------+  +---------------------+ |
                                 |                          |               |
                                 |  +------------+  +---------------------+ |
                                 |  | HTTP Server |  | FROST Engine        | |
                                 |  | (bifrost_   |  | (DKG rounds,        | |
                                 |  |  url)       |<>| signing rounds)     | |
                                 |  +------------+  +---------------------+ |
                                 |                          |               |
                                 |  +------------+  +---------------------+ |
                                 |  | Bitcoin Tx  |  | PLONK Prover        | |
                                 |  | Builder     |  | (misbehavior        | |
                                 |  |             |  |  circuits)           | |
                                 |  +------------+  +---------------------+ |
                                 |                                          |
                                 |  +-------------------------------------+ |
                                 |  | Persistent State (local DB)         | |
                                 |  +-------------------------------------+ |
                                 +------------------------------------------+
                                         ^              ^
                                         |              |
                              HTTP pull from    HTTP pull from
                              other SPOs        other SPOs
```

### 2.1 Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| **Chain Follower** | Follows Cardano tip via N2C ChainSync. Detects epoch boundaries, reads registry linked-list, reads PegInRequest/PegOut UTxOs, reads Treasury UTxO state. |
| **Epoch State Machine** | Orchestrates the epoch lifecycle: DKG initiation, signing window, TM construction, leader election, Cardano submission. |
| **FROST Engine** | Executes DKG rounds 1-3 and signing rounds 1-2. Manages key packages, nonces, and shares. Detects misbehavior. |
| **HTTP Server** | Serves DKG and signing payloads at well-known URL paths. Other SPOs pull from here. |
| **HTTP Client** | Polls other SPOs' `bifrost_url` endpoints to fetch their DKG/signing payloads. |
| **Bitcoin Tx Builder** | Deterministically constructs Treasury Movement transactions from shared Cardano state. Computes Taproot tweaks, sighashes. |
| **Cardano Tx Builder** | Builds Cardano transactions for: publishing group keys to `treasury.ak`, posting signed TMs to `treasury_movement.ak`. |
| **PLONK Prover** | Generates misbehavior proofs for DKG share and signing share violations. |
| **Persistent State** | Stores DKG key packages, signing nonces, epoch state, and operational data across restarts. |

### 2.2 Data Flow

**Inbound (from Cardano chain):**
```
cardano-node --[N2C ChainSync]--> Chain Follower --[events]--> Epoch State Machine
cardano-node --[N2C StateQuery]--> Chain Follower --[UTxO sets]--> Bitcoin Tx Builder
```

**Inbound (from other SPOs):**
```
Other SPO bifrost_url --[HTTP GET]--> HTTP Client --[payloads]--> FROST Engine
```

**Outbound (to other SPOs):**
```
FROST Engine --[payloads]--> HTTP Server (bifrost_url) <--[HTTP GET]-- Other SPOs
```

**Outbound (to Cardano):**
```
Cardano Tx Builder --[N2C TxSubmission]--> cardano-node
```

## 3. Module Structure

```
heimdall/
+-- Cargo.toml
+-- src/
    +-- main.rs                    -- CLI entry point, daemon startup
    +-- lib.rs                     -- crate root, re-exports
    +-- config.rs                  -- configuration (keys, URLs, node socket path)
    |
    +-- chain/                     -- Cardano chain interaction
    |   +-- mod.rs
    |   +-- follower.rs            -- ChainSync follower, epoch boundary detection
    |   +-- state_query.rs         -- N2C state queries (stake dist, UTxOs, params)
    |   +-- tx_submit.rs           -- N2C transaction submission
    |   +-- tx_builder.rs          -- Cardano transaction construction
    |   +-- codec.rs               -- CBOR datum encoding/decoding for Bifrost contracts
    |   +-- registry.rs            -- On-chain linked-list traversal (SPO registry)
    |
    +-- frost/                     -- FROST protocol (existing + extensions)
    |   +-- mod.rs
    |   +-- dkg.rs                 -- DKG wrapper (existing, to be extended)
    |   +-- signing.rs             -- Signing wrapper (existing, to be extended)
    |   +-- types.rs               -- Canonical byte layouts, payload serialization
    |   +-- auth.rs                -- BIP-340 sign-the-hash authentication
    |
    +-- bitcoin/                   -- Bitcoin transaction handling
    |   +-- mod.rs
    |   +-- taproot.rs             -- Treasury + peg-in Taproot address derivation
    |   +-- tm_builder.rs          -- Deterministic TM transaction construction + sighash
    |
    +-- http/                      -- HTTP server and client
    |   +-- mod.rs
    |   +-- server.rs              -- Axum server (bifrost_url endpoint)
    |   +-- client.rs              -- reqwest-based peer polling
    |   +-- routes.rs              -- Route definitions for DKG/signing payloads
    |   +-- payloads.rs            -- JSON payload types (serde)
    |
    +-- epoch/                     -- Epoch lifecycle orchestration
    |   +-- mod.rs
    |   +-- state_machine.rs       -- Epoch phases, transitions, timeouts
    |   +-- roster.rs              -- Candidate enumeration, threshold calculation
    |   +-- leader.rs              -- Deterministic leader election + timeout cascade
    |
    +-- crypto/                    -- Cryptographic utilities
    |   +-- mod.rs
    |   +-- ecdh.rs                -- ECDH for DKG share encryption
    |   +-- keys.rs                -- Key management (bifrost_id, cold key loading)
    |   +-- convert.rs             -- k256 <-> bitcoin::secp256k1 type conversions
    |
    +-- circuits/                  -- PLONK misbehavior proofs (existing)
    |   +-- mod.rs
    |   +-- commitment.rs          -- DKG commitment misbehavior circuit
    |   +-- signature.rs           -- Signing share misbehavior circuit
    |
    +-- gadgets/                   -- ZK circuit building blocks (existing)
    |   +-- mod.rs
    |   +-- nonnative.rs           -- Non-native field arithmetic
    |   +-- secp256k1.rs           -- secp256k1 point operations in-circuit
    |
    +-- storage/                   -- Persistent state
    |   +-- mod.rs
    |   +-- db.rs                  -- Local key-value store (sled or rocksdb)
    |   +-- models.rs              -- Stored types (key packages, epoch state)
```

## 4. Epoch Lifecycle State Machine

The core of Heimdall is an epoch-driven state machine. Each Cardano epoch (~5 days) progresses through these phases:

```
                                +---> [Error/Timeout] ---> [Federation Fallback]
                                |
[Idle] --> [EpochStart] --> [DKG] --> [BuildTM] --> [Sign] --> [Submit] --> [AwaitConfirm] --> [Idle]
              |                                                                |
              +-- read registry snapshot                                       +-- next epoch
              +-- read stake distribution
              +-- enumerate candidates
```

### 4.1 Phase Details

| Phase | Trigger | Actions | Duration |
|-------|---------|---------|----------|
| **EpochStart** | Epoch boundary slot detected | Snapshot registry, query stake distribution, compute threshold, order candidates | Minutes |
| **DKG** | Candidate set ready | Run DKG rounds 1-3 via bifrost_url pull model. Produce $Y_{67}$, $Y_{51}$ | ~5 minutes (happy path) |
| **PublishKeys** | DKG complete | Current roster leader posts new group keys to `treasury.ak` | Minutes |
| **BuildTM** | Keys published | Read all confirmed PegInRequest + pending PegOut UTxOs, construct single deterministic TM transaction | Minutes |
| **Sign** | TM constructed | Run FROST signing cascade: try 67% first, fall back to 51%, then federation | Minutes to hours |
| **Submit** | Signing complete | Leader posts signed TM to `treasury_movement.ak` (timeout cascade for leader election) | Minutes |
| **AwaitConfirm** | TM posted on Cardano | Wait for watchtowers to relay to Bitcoin and for Bitcoin confirmation | ~17 hours |

### 4.2 Single TM Per Epoch

Each epoch produces exactly **one** Treasury Movement transaction. This TM:
- Sweeps all confirmed peg-in UTxOs accumulated during the epoch
- Fulfills all pending peg-out requests
- Moves the treasury balance to the new roster's Taproot address

Peg-in and peg-out requests that arrive after the pegs snapshot (stability window) roll over to the next epoch.

This simplifies the design: no chaining of treasury UTxOs within an epoch, no tracking which requests belong to which batch, and no dependency on intermediate Bitcoin confirmations.

### 4.3 Signing Cascade

```
[Attempt 67% quorum]
     |
     +-- Success: sign via Y_67 script leaf on treasury, Y_51 key path on peg-ins
     |
     +-- Timeout (~24h) --> [Attempt 51% quorum]
                                  |
                                  +-- Success: sign via Y_51 key path on all inputs
                                  |
                                  +-- Timeout (~24h) --> [Federation fallback]
                                                              |
                                                              +-- Y_federation script path
```

## 5. HTTP Server (bifrost_url)

### 5.1 Endpoints

All endpoints serve JSON payloads authenticated with BIP-340 Schnorr signatures.

| Method | Path | Content |
|--------|------|---------|
| GET | `/dkg/{epoch}/{threshold}/round1/{pool_id}.json` | DKG Round 1: commitments + proof-of-knowledge |
| GET | `/dkg/{epoch}/{threshold}/round2/{pool_id}.json` | DKG Round 2: encrypted shares per recipient |
| GET | `/sign/{epoch}/tm.json` | Current TM transaction proposal (raw_tx + txid) |
| GET | `/sign/{epoch}/{txid}/round1/{pool_id}.json` | Signing nonce commitments per input |
| GET | `/sign/{epoch}/{txid}/round2/{pool_id}.json` | Partial signatures per input |
| GET | `/health` | Liveness check + current epoch/phase |

### 5.2 Authentication

Every payload includes a 64-byte BIP-340 Schnorr signature over `SHA256(canonical_bytes)`:

```
Receiver:
  1. Parse JSON, extract structured fields
  2. Reconstruct canonical_bytes from fields (per message type spec)
  3. Compute message_hash = SHA256(canonical_bytes)
  4. Verify: verifySchnorrSecp256k1Signature(bifrost_id_pk, message_hash, signature)
```

The same `message_hash + signature` pair serves dual purpose:
- Off-chain: SPO-to-SPO authentication
- On-chain: evidence for misbehavior proofs (Cardano validators verify the same signature)

## 6. Bitcoin Transaction Construction

### 6.1 Taproot Address Derivation

**Treasury address** (per epoch):
```
Internal key: Y_51 (x-only)
Script tree:
  Leaf 1: <Y_67> OP_CHECKSIG
  Leaf 2: <timeout_federation> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG
Merkle root: tagged_hash("TapBranch", leaf1_hash || leaf2_hash)
Q_treasury = Y_51 + tagged_hash("TapTweak", Y_51 || merkle_root) * G
Address: bc1p<bech32m(Q_treasury)>
```

**Peg-in address** (per depositor):
```
Internal key: Y_51 (x-only)
Script tree:
  Leaf 1: <timeout_federation> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG
  Leaf 2: OP_DUP OP_HASH160 <depositor_pubkey_hash> OP_EQUALVERIFY OP_CHECKSIGVERIFY <4320> OP_CSV
Merkle root: tagged_hash("TapBranch", leaf1_hash || leaf2_hash)
Q_pegin = Y_51 + tagged_hash("TapTweak", Y_51 || merkle_root) * G
```

**Implementation** (`src/bitcoin/taproot.rs`):

| Function | Description |
|----------|-------------|
| `treasury_spend_info(secp, y_51, y_67, y_federation, federation_timeout)` | Builds treasury `TaprootSpendInfo` |
| `pegin_spend_info(secp, y_51, y_federation, federation_timeout, depositor_pubkey_hash, depositor_refund_timeout)` | Builds peg-in `TaprootSpendInfo` |

Both return `TaprootSpendInfo` — the caller uses `.output_key()` for the on-chain address and `.merkle_root()` for the sighash tweak.

Script builders (internal):
- `build_checksig_script(pubkey)` — `<pubkey> OP_CHECKSIG`
- `build_csv_checksig_script(timeout, pubkey)` — `<timeout> OP_CSV OP_DROP <pubkey> OP_CHECKSIG`
- `build_depositor_refund_script(pubkey_hash, timeout)` — `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIGVERIFY <timeout> OP_CSV`

### 6.2 Treasury Movement Transaction

Deterministic construction from shared Cardano state:

```
Version: 2
Locktime: 0

Inputs:
  [0]    Treasury UTxO (txid+vout from previous TM change output)
  [1..k] Peg-in UTxOs, sorted lexicographically by (txid || vout_le)
  All sequences: 0xFFFFFFFD

Outputs:
  [0..m-1] Peg-out payments, sorted by scriptPubKey bytes
  [m]      Treasury change -> new roster's Taproot address

Fee: tx_vsize * fee_rate_sat_per_vb (protocol parameter)
```

**Implementation** (`src/bitcoin/tm_builder.rs`):

The `build_tm()` function is a pure, deterministic builder. Same inputs always produce the same `txid`.

Input types:

| Type | Fields |
|------|--------|
| `TreasuryInput` | `outpoint: OutPoint`, `value: Amount`, `spend_info: TaprootSpendInfo` |
| `PegInInput` | `outpoint: OutPoint`, `value: Amount`, `spend_info: TaprootSpendInfo` |
| `PegOutRequest` | `script_pubkey: ScriptBuf`, `amount: Amount` |
| `FeeParams` | `fee_rate_sat_per_vb: u64`, `per_pegout_fee: Amount` |

Output type:

| Type | Fields |
|------|--------|
| `UnsignedTm` | `tx: Transaction`, `txid: Txid`, `prevouts: Vec<TxOut>`, `input_spend_info: Vec<TaprootSpendInfo>` |

Construction rules:

1. **Validate** — each peg-out amount must exceed `per_pegout_fee`
2. **Sort inputs** — peg-ins sorted by 36-byte key: `txid_bytes || vout_le_bytes`
3. **Sort outputs** — peg-out outputs sorted by raw `script_pubkey` bytes
4. **Deduct per-pegout fee** — each peg-out output value = `request.amount - per_pegout_fee`
5. **Estimate vsize** — from input/output counts assuming key-path Taproot witnesses
6. **Compute miner fee** — `vsize * fee_rate_sat_per_vb`
7. **Compute change** — `sum(inputs) - sum(pegout_outputs) - miner_fee`
8. **Dust check** — all outputs must be ≥ 330 sat (P2TR dust threshold)

Error cases: `InsufficientFunds`, `NoPegOutAmountAfterFee`, `DustOutput`.

Edge cases supported: no peg-ins (pure peg-out), no peg-outs (pure sweep/consolidation), no peg-ins and no peg-outs (epoch handoff only).

### 6.3 Per-Input FROST Signing

Each TM input requires a separate FROST signing round because:
- Different BIP-341 sighash per input (commits to input index)
- Different Taproot tweak per input (treasury vs. each peg-in has different script tree)

For $k+1$ inputs, SPOs run $k+1$ parallel signing rounds. All nonce commitments and partial signatures are arrays indexed by input position.

**Implementation** (`src/bitcoin/tm_builder.rs`):

`compute_sighashes(unsigned_tm)` returns one 32-byte sighash per input using `SighashCache::taproot_key_spend_signature_hash` with `Prevouts::All` and `TapSighashType::Default`.

Each sighash is passed directly to FROST `run_signing()` as the signing message. The resulting 64-byte FROST `Signature` (R || z) maps directly to a BIP-340 Schnorr signature for the Taproot key-path spend witness.

### 6.4 Vsize Estimation

For fee calculation, the transaction vsize is estimated before assembly:

```
Fixed overhead:   version(4) + marker(1) + flag(1) + locktime(4) = 10 bytes
Per input (non-witness): outpoint(36) + scriptSig_len(1) + sequence(4) = 41 bytes
Per input (witness):     items_count(1) + sig_len(1) + sig(64) = 66 bytes
Per P2TR output:         value(8) + scriptPubKey_len(1) + scriptPubKey(34) = 43 bytes
Plus varint sizes for input/output counts.

vsize = ceil((non_witness_bytes * 4 + witness_bytes) / 4)
```

This assumes all inputs use key-path spends (single 64-byte Schnorr signature). Script-path spends (used in cascade fallbacks) would have larger witnesses — vsize estimation for those cases will be added when the signing cascade is implemented.

## 7. Cardano Chain Interaction

### 7.1 Chain Follower

Connects to the local `cardano-node` via Unix domain socket using Pallas N2C mini-protocols:

- **ChainSync**: follows the tip, detects epoch boundaries by computing `epoch = slot / epoch_length`
- **StateQuery**: acquires ledger state for stake distribution, UTxO queries, protocol parameters

### 7.2 Smart Contract State Reading

| Contract | What to Read | How |
|----------|-------------|-----|
| `spos_registry.ak` | All registered SPO nodes (linked list) | Query all UTxOs at script address, decode datums, reconstruct ordered list from NFT pointers |
| `treasury.ak` | Current $Y_{67}$, $Y_{51}$, completed peg-ins trie root | Query reference UTxO by known NFT policy |
| `peg_in.ak` | Confirmed PegInRequest UTxOs | Query UTxOs at script address, filter by NFT policy, decode datums for raw Bitcoin tx bytes |
| `peg_out.ak` | Pending PegOut UTxOs | Query UTxOs at script address, decode datums for destination address + amount |
| `treasury_movement.ak` | Posted signed TMs | Query UTxOs, decode datums for signed tx bytes + epoch + leader info |

### 7.3 Transaction Submission

Heimdall submits Cardano transactions for:
1. **Key publication** (`treasury.ak`): after DKG, leader posts new $Y_{67}$, $Y_{51}$
2. **TM posting** (`treasury_movement.ak`): after signing, leader posts the signed Bitcoin transaction
3. **Misbehavior proofs**: any SPO can submit a PLONK proof to slash a cheater

## 8. Key Management

### 8.1 Key Types

| Key | Curve | Storage | Usage |
|-----|-------|---------|-------|
| `cold_skey` / `cold_vkey` | Ed25519 | Air-gapped, loaded only for registration/revocation | Signs registration message binding `bifrost_id_pk` to `pool_id` |
| `bifrost_id_sk` / `bifrost_id_pk` | secp256k1 | Encrypted file on SPO machine | Signs all protocol messages (DKG, signing payloads). Used for ECDH. |
| DKG signing share $s_i$ | secp256k1 scalar | Encrypted in local DB, per-epoch | FROST partial signature computation |
| DKG nonces $(d, e)$ | secp256k1 scalars | Memory only, single-use | FROST signing round 1 |

### 8.2 Key Lifecycle

```
[First run]
  1. Generate bifrost_id keypair (secp256k1)
  2. Load cold key (one-time, for registration)
  3. Sign registration message: "bifrost-spo" || bifrost_id_pk || bifrost_url
  4. Submit registration tx to Cardano
  5. Securely delete cold key from memory

[Each epoch]
  6. Run DKG -> receive signing share s_i
  7. Store encrypted s_i in local DB
  8. Use s_i for signing rounds during the epoch
  9. On epoch transition, s_i for old epoch can be archived/deleted
```

## 9. Persistent Storage

Heimdall needs local persistent state for crash recovery:

| Data | Lifetime | Purpose |
|------|----------|---------|
| `bifrost_id_sk` | Permanent | Identity key (encrypted at rest) |
| DKG `KeyPackage` | Per-epoch | Signing share + group verification data |
| DKG `PublicKeyPackage` | Per-epoch | Group public key + all verification shares |
| Epoch state | Per-epoch | Current phase, collected payloads, progress |
| Nonce commitments | Per-signing-round | Must not be reused (single-use nonces) |
| Peer payload cache | Transient | Cached DKG/signing payloads from other SPOs |

**Storage backend**: `sled` (embedded key-value store, pure Rust, crash-safe) for simplicity. Evaluate `rocksdb` if performance demands it.

## 10. Error Handling & Recovery

### 10.1 Crash Recovery

On restart, Heimdall:
1. Reads persistent state to determine current epoch and phase
2. Resumes chain following from the last known tip
3. Checks if DKG/signing is in progress and whether it can rejoin
4. If nonces were generated but not yet used, they are safe to reuse (stored persistently)
5. If nonces were already used in a signing round, they must NOT be reused (replay attack)

### 10.2 Network Failures

- **Peer unreachable**: Skip peer, continue with remaining participants if threshold is still reachable
- **Node disconnected**: Reconnect with exponential backoff
- **Timeout on peer payload**: Log warning, proceed without that peer's contribution

### 10.3 Misbehavior Response

When a peer's payload fails verification:
1. Log the misbehavior with full context
2. Generate PLONK proof (commitment or signature misbehavior)
3. Construct and submit ban transaction on Cardano
4. Restart DKG/signing with reduced candidate set

## 11. Configuration

```toml
[node]
socket_path = "/run/cardano-node/node.socket"     # N2C Unix socket
network_magic = 764824073                           # Mainnet

[identity]
bifrost_id_key_file = "/etc/heimdall/bifrost_id.sk" # Encrypted secp256k1 key
pool_id = "pool1..."                                 # Bech32 pool ID

[server]
listen_addr = "0.0.0.0:8470"                       # bifrost_url bind address
external_url = "https://my-spo.example.com:8470"    # Public URL registered on-chain

[protocol]
fee_rate_sat_per_vb = 10                            # Bitcoin fee rate
federation_pubkey = "02..."                          # Y_federation compressed pubkey
federation_timeout = 144                             # CSV timelock (blocks)
depositor_refund_timeout = 4320                      # ~30 days in blocks

[storage]
db_path = "/var/lib/heimdall/db"                    # sled database directory

[contracts]                                          # Script addresses / policy IDs
registry_address = "addr1..."
treasury_policy_id = "..."
peg_in_address = "addr1..."
peg_out_address = "addr1..."
treasury_movement_address = "addr1..."
bridged_asset_policy_id = "..."
```

## 12. Dependency Stack

### 12.1 Core Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `frost-secp256k1-tr` | 3.0.0-rc.0 | FROST DKG + signing with Taproot support |
| `bitcoin` | 0.32 | Bitcoin transaction construction, Taproot, BIP-340/341 |
| `pallas` | 1.0.0-alpha.6 | Cardano N2C protocols, CBOR, primitives |
| `k256` | 0.13 | secp256k1 arithmetic (pinned by frost-secp256k1-tr) |
| `tokio` | 1 | Async runtime |
| `axum` | 0.8 | HTTP server |
| `reqwest` | 0.13 | HTTP client |
| `serde` / `serde_json` | 1 | JSON serialization |

### 12.2 Cryptography

| Crate | Version | Purpose |
|-------|---------|---------|
| `hkdf` | 0.12 | Key derivation for DKG share encryption (pinned by sha2 0.10) |
| `sha2` | 0.10 | SHA-256 for canonical byte hashing (pinned by frost-secp256k1-tr) |
| `ed25519-dalek` | 2 | Ed25519 for cold key registration signing |
| `blake2` | 0.10 | Blake2b-256 for Cardano key hashing |

### 12.3 ZK Proofs (existing)

| Crate | Version | Purpose |
|-------|---------|---------|
| `dusk-plonk` | 0.22.0 | PLONK proving system over BLS12-381 |
| `dusk-bls12_381` | 0.14 | BLS12-381 curve |
| `ff` | 0.13 | Finite field traits |

### 12.4 Infrastructure

| Crate | Version | Purpose |
|-------|---------|---------|
| `tower` | 0.5 | Middleware framework |
| `tower-http` | 0.6 | Tracing, timeout middleware |
| `sled` | 0.34 | Embedded key-value store |
| `tracing` | 0.1 | Structured logging |
| `tracing-subscriber` | 0.3 | Log output formatting |
| `clap` | 4 | CLI argument parsing |
| `hex` | 0.4 | Hex encoding/decoding |
| `minicbor` | 2.2 | CBOR encoding for Cardano datums |
| `rayon` | 1.10 | Data parallelism for DKG |

## 13. Concurrency Model

Heimdall runs on Tokio with these long-lived tasks:

```
tokio::spawn(chain_follower_task)     -- follows Cardano tip, emits epoch events
tokio::spawn(http_server_task)        -- serves bifrost_url endpoints
tokio::spawn(epoch_orchestrator_task) -- drives the epoch state machine

                                        +-- spawns per-round tasks:
                                            - peer_polling_task (fetch payloads)
                                            - frost_compute_task (DKG/signing, may use rayon)
                                            - tx_submission_task (post to Cardano)
```

**Rayon** is used within FROST compute tasks for parallelizing DKG operations across participants (existing pattern). Tokio handles all async I/O (network, chain sync, HTTP).

## 14. Security Considerations

- **Nonce reuse prevention**: Signing nonces are generated fresh per round and destroyed after use. Persistent storage of nonce state enables crash recovery but must ensure nonces are never reused.
- **Key encryption at rest**: `bifrost_id_sk` and DKG signing shares encrypted with a passphrase or HSM.
- **Cold key isolation**: Cold key is loaded exactly once for registration, then purged from memory.
- **Canonical byte determinism**: All protocol messages use fixed canonical byte layouts (not JSON) for signing and verification. JSON is transport only.
- **Replay resistance**: All messages bound to epoch number and threshold value.
- **Input validation**: All payloads from peers verified against `bifrost_id_pk` before processing.
- **Rate limiting**: HTTP server rate-limits requests to prevent DoS.
- **No TLS required**: All payloads are authenticated via BIP-340 signatures. TLS adds no security benefit since forgery is impossible without `bifrost_id_sk`.

## 15. Testing Strategy

| Level | What | How |
|-------|------|-----|
| **Unit** | FROST DKG/signing, Bitcoin tx construction, Taproot address derivation, canonical byte encoding | Pure functions, no I/O |
| **Integration** | Multi-SPO DKG and signing with simulated network | Multiple Heimdall instances on localhost, mock chain state |
| **Property** | Deterministic TM construction produces identical txids across SPOs | QuickCheck/proptest with randomized UTxO sets |
| **End-to-end** | Full epoch lifecycle on Cardano testnet | Deploy to preview/preprod, use testnet Bitcoin (signet) |
| **Adversarial** | Misbehavior detection and PLONK proof generation | Inject corrupted DKG shares / signing shares, verify proofs |
