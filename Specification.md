# Specification v0.1 — Bitcoin TM Transaction Builder

## 1. Goal

Implement a pure, deterministic function that takes treasury state + peg-in/peg-out requests and produces an unsigned Bitcoin Taproot transaction + per-input sighash data. Every SPO must produce the same `txid` — if any field differs, FROST signing will fail.

## 2. Module Layout

```
src/bitcoin/
├── mod.rs         -- pub mod taproot, tm_builder;
├── taproot.rs     -- Taproot address/tree derivation (treasury + peg-in)
└── tm_builder.rs  -- Deterministic TM transaction construction + sighash
```

## 3. Taproot Address Derivation (`taproot.rs`)

### Treasury Taproot tree

```rust
pub fn treasury_spend_info(
    secp: &Secp256k1<All>,
    y_51: UntweakedPublicKey,
    y_67: UntweakedPublicKey,
    y_federation: UntweakedPublicKey,
    federation_timeout: u16,
) -> TaprootSpendInfo
```

Script tree:
- Leaf 1 (depth 1): `<Y_67> OP_CHECKSIG`
- Leaf 2 (depth 1): `<federation_timeout> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG`
- Internal key: `Y_51`

### Peg-in Taproot tree

```rust
pub fn pegin_spend_info(
    secp: &Secp256k1<All>,
    y_51: UntweakedPublicKey,
    y_federation: UntweakedPublicKey,
    federation_timeout: u16,
    depositor_pubkey_hash: [u8; 20],
    depositor_refund_timeout: u16,
) -> TaprootSpendInfo
```

Script tree:
- Leaf 1 (depth 1): `<federation_timeout> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG`
- Leaf 2 (depth 1): `OP_DUP OP_HASH160 <depositor_pubkey_hash> OP_EQUALVERIFY OP_CHECKSIGVERIFY <depositor_refund_timeout> OP_CSV`
- Internal key: `Y_51`

### Script builders (internal)

| Function | Script |
|----------|--------|
| `build_checksig_script(pubkey)` | `<pubkey> OP_CHECKSIG` |
| `build_csv_checksig_script(timeout, pubkey)` | `<timeout> OP_CSV OP_DROP <pubkey> OP_CHECKSIG` |
| `build_depositor_refund_script(pubkey_hash, timeout)` | `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIGVERIFY <timeout> OP_CSV` |

## 4. TM Transaction Builder (`tm_builder.rs`)

### Types

```rust
pub struct TreasuryInput {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub spend_info: TaprootSpendInfo,
}

pub struct PegInInput {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub spend_info: TaprootSpendInfo,
}

pub struct PegOutRequest {
    pub script_pubkey: ScriptBuf,
    pub amount: Amount,
}

pub struct FeeParams {
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee: Amount,
}

pub struct UnsignedTm {
    pub tx: Transaction,
    pub txid: Txid,
    pub prevouts: Vec<TxOut>,
    pub input_spend_info: Vec<TaprootSpendInfo>,
}
```

### Builder function

```rust
pub fn build_tm(
    treasury: TreasuryInput,
    pegins: Vec<PegInInput>,
    pegouts: Vec<PegOutRequest>,
    change_script_pubkey: ScriptBuf,
    fee_params: &FeeParams,
) -> Result<UnsignedTm, TmBuildError>
```

**Construction rules (Bifrost spec §6.2):**

1. **Version:** 2 (for OP_CSV compatibility)
2. **Locktime:** 0
3. **Inputs:** `[0]` = treasury UTXO, `[1..k]` = peg-in UTXOs sorted by 36-byte key `(txid_bytes || vout_le_bytes)`. All sequences: `0xFFFFFFFD`.
4. **Outputs:** `[0..m-1]` = peg-out payments sorted by raw `script_pubkey` bytes. Each amount = `request.amount - per_pegout_fee`. `[m]` = treasury change.
5. **Fee:** `estimate_vsize(num_inputs, num_outputs) * fee_rate_sat_per_vb`
6. **Change:** `sum(input_values) - sum(peg_out_outputs) - miner_fee`

**Error cases:**

| Error | Condition |
|-------|-----------|
| `InsufficientFunds` | total inputs < total outputs + miner fee |
| `NoPegOutAmountAfterFee` | a peg-out amount ≤ `per_pegout_fee` |
| `DustOutput` | any output below 330 sat (P2TR dust threshold) |

**Determinism:** The function is pure — same inputs always produce the same `txid`. No randomness, no timestamps, no external state.

### Vsize estimation

```rust
pub fn estimate_vsize(num_inputs: usize, num_outputs: usize) -> u64
```

Assumes key-path Taproot spends (single 64-byte Schnorr signature per input):

| Component | Size |
|-----------|------|
| Fixed overhead | version(4) + marker(1) + flag(1) + locktime(4) = 10 bytes |
| Per input (non-witness) | outpoint(36) + scriptSig_len(1) + sequence(4) = 41 bytes |
| Per input (witness) | items_count(1) + sig_len(1) + sig(64) = 66 bytes |
| Per P2TR output | value(8) + scriptPubKey_len(1) + scriptPubKey(34) = 43 bytes |

`vsize = ceil((non_witness_bytes * 4 + witness_bytes) / 4)`

### Sighash computation

```rust
pub fn compute_sighashes(unsigned_tm: &UnsignedTm) -> Vec<[u8; 32]>
```

Returns one 32-byte sighash per input using `SighashCache::taproot_key_spend_signature_hash` with `Prevouts::All` and `TapSighashType::Default`.

## 5. FROST Integration

Each sighash is passed to FROST `run_signing()` as the signing message. The resulting 64-byte `frost::Signature` (R || z) maps directly to a BIP-340 Schnorr signature:

```
FROST group key (33-byte compressed) → extract 32-byte x-coordinate → UntweakedPublicKey
FROST signature (64-byte R || z) → bitcoin::secp256k1::schnorr::Signature → Witness::p2tr_key_spend
```

> **Note:** The FROST group key serves as the Taproot internal key. For key-path spends, the Taproot tweak must be applied to the signing share before FROST signing. This tweak integration is deferred to the signing coordinator implementation.

## 6. Dependencies

Added to `Cargo.toml`:

```toml
bitcoin = { version = "0.32", features = ["rand-std"] }
```

No other new dependencies. The `bitcoin` crate bundles `bitcoin_hashes` and `secp256k1`.

## 7. Test Plan

### Taproot tests (5)

| Test | Verifies |
|------|----------|
| `test_treasury_spend_info_deterministic` | Same keys → same `output_key` |
| `test_pegin_spend_info_deterministic` | Same keys + depositor → same `output_key` |
| `test_treasury_vs_pegin_different` | Treasury and peg-in trees produce different output keys |
| `test_treasury_script_leaves` | Two script leaves match expected opcodes |
| `test_pegin_script_leaves` | Two script leaves match expected opcodes |

### TM builder tests (13)

**Determinism:**

| Test | Verifies |
|------|----------|
| `test_build_tm_deterministic` | Build twice → same `txid` |
| `test_input_ordering` | Treasury at [0], peg-ins lexicographically sorted |
| `test_output_ordering` | Peg-outs sorted by `scriptPubKey`, change last |

**Accounting:**

| Test | Verifies |
|------|----------|
| `test_fee_deduction` | `total_inputs = total_outputs + miner_fee` |
| `test_pegout_protocol_fee` | Each peg-out output = `requested - per_pegout_fee` |
| `test_insufficient_funds_error` | Returns `InsufficientFunds` error |

**Edge cases:**

| Test | Verifies |
|------|----------|
| `test_no_pegins` | Treasury-only input, peg-outs + change |
| `test_no_pegouts` | Peg-in sweep + change (pure consolidation) |
| `test_no_pegins_no_pegouts` | Treasury → new treasury (epoch handoff only) |

**Sighash:**

| Test | Verifies |
|------|----------|
| `test_sighash_count_matches_inputs` | One sighash per input |
| `test_sighash_differs_per_input` | Each input produces a different sighash |
| `test_sighash_deterministic` | Same tx → same sighashes |

**FROST integration:**

| Test | Verifies |
|------|----------|
| `test_frost_sign_sighash` | 3-of-5 DKG → compute sighash → FROST sign → verify signature against group key |

---

# Specification v0.2 — Epoch State Machine

## 1. Approach Rationale

The epoch orchestrator must track which phase an SPO is in across a ~5-day Cardano epoch, enforce per-phase deadlines, handle the 67%→51%→federation signing cascade, and abstract external dependencies for testability.

> **Note:** Persistent state storage (sled) and crash recovery are deferred to Specification v0.3.

Five approaches were evaluated:

| Criterion | Enum + Match | Typestate | Actor Model | Async Streams | Statig Crate |
|---|---|---|---|---|---|
| **Testability** | Excellent | Excellent | Good | Fair | Good |
| **Timeout handling** | Excellent | Fair | Good | Good | Good |
| **Complexity** | Low | High | Medium-High | Medium | Medium |
| **Concurrency** | Excellent | Fair | Excellent | Good | Fair |
| **Auditability** | Excellent | Fair | Fair | Fair | Fair |
| **New deps** | None | None | kameo | tokio-stream | statig |

**Winner: Enum-based state machine with match loop.**

Key reasons:

1. **Testability is maximum.** Each phase = standalone `async fn` taking trait objects. Unit test any transition with mocks. No actor runtime or stream scaffolding needed.

2. **Timeouts are idiomatic.** Each match arm wraps I/O in `tokio::select!` with a deadline. No framework, no timer actors, no stream combinators.

3. **Auditability.** Every state transition visible in one `match`. Critical for security-sensitive crypto protocol code. Macros (statig) and message flows (actors) are harder to audit.

4. **Serializable by design.** The phase enum is `#[derive(Serialize, Deserialize)]`, making future persistence (v0.3) a trivial addition.

5. **No new dependencies.** Uses `serde` + `tokio` already in the tree.

## 2. Phase Enum

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EpochPhase {
    Idle,
    EpochStart { epoch: u64 },
    Dkg {
        epoch: u64,
        round: DkgRound,
        roster: Roster,
        collected: DkgCollected,
    },
    PublishKeys {
        epoch: u64,
        roster: Roster,
        group_keys: GroupKeys,
    },
    BuildTm {
        epoch: u64,
        roster: Roster,
        group_keys: GroupKeys,
    },
    Sign {
        epoch: u64,
        roster: Roster,
        cascade: CascadeLevel,
        tm: TreasuryMovement,
        round: SigningRound,
        collected: SignCollected,
    },
    Submit {
        epoch: u64,
        signed_tm: Vec<u8>,
        leader_attempt: u8,
    },
    AwaitConfirm {
        epoch: u64,
        cardano_tx_id: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DkgRound { Round1, Round2, Part3 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CascadeLevel { Quorum67, Quorum51, Federation }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningRound { Round1, Round2 }
```

Supporting data types (`Roster`, `GroupKeys`, `TreasuryMovement`, `DkgCollected`, `SignCollected`) are all `Serialize + Deserialize`.

## 3. Trait Abstractions

### CardanoChain — Cardano node interaction (N2C)

```rust
#[async_trait]
pub trait CardanoChain: Send + Sync {
    async fn await_epoch_boundary(&self) -> Result<EpochBoundaryEvent>;
    async fn query_spo_registry(&self) -> Result<Vec<SpoInfo>>;
    async fn query_stake_distribution(&self, epoch: u64) -> Result<BTreeMap<PoolId, u64>>;
    async fn query_pegin_requests(&self) -> Result<Vec<PegInRequest>>;
    async fn query_pegout_requests(&self) -> Result<Vec<PegOutRequest>>;
    async fn query_treasury(&self) -> Result<TreasuryUtxo>;
    async fn submit_tx(&self, tx_bytes: &[u8]) -> Result<TxHash>;
}
```

### PeerNetwork — Peer SPO HTTP communication (pull-only)

```rust
#[async_trait]
pub trait PeerNetwork: Send + Sync {
    async fn publish_dkg_round1(&self, payload: &Dkg1Payload) -> Result<()>;
    async fn publish_dkg_round2(&self, payload: &Dkg2Payload) -> Result<()>;
    async fn publish_sign_round1(&self, payload: &Sign1Payload) -> Result<()>;
    async fn publish_sign_round2(&self, payload: &Sign2Payload) -> Result<()>;
    async fn fetch_dkg_round1(&self, peer: &SpoInfo) -> Result<Option<Dkg1Payload>>;
    async fn fetch_dkg_round2(&self, peer: &SpoInfo) -> Result<Option<Dkg2Payload>>;
    async fn fetch_sign_round1(&self, peer: &SpoInfo) -> Result<Option<Sign1Payload>>;
    async fn fetch_sign_round2(&self, peer: &SpoInfo) -> Result<Option<Sign2Payload>>;
}
```

### Clock — Abstraction for fake time in tests

```rust
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn deadline(&self, duration: Duration) -> Instant;
}
```

## 4. Main Loop Architecture

```
src/epoch/
├── mod.rs          -- pub mod state, machine, dkg, signing, traits;
├── state.rs        -- EpochPhase enum + per-phase data structs
├── traits.rs       -- CardanoChain, PeerNetwork, Clock traits
├── machine.rs      -- run_epoch_loop() + per-phase dispatch (v0.3 adds EpochStore)
├── dkg.rs          -- DKG phase logic (round1 -> round2 -> part3)
└── signing.rs      -- Signing phase logic (cascade, per-input parallel rounds)
```

Existing modules unchanged: `src/frost/participant.rs`, `src/http/*`, `src/demo/*`.

```rust
pub async fn run_epoch_loop(
    chain: Arc<dyn CardanoChain>,
    peers: Arc<dyn PeerNetwork>,
    clock: Arc<dyn Clock>,
    config: &EpochConfig,
) {
    let mut phase = EpochPhase::Idle;

    loop {
        phase = match phase {
            EpochPhase::Idle =>
                idle_phase(&chain).await,
            EpochPhase::EpochStart { epoch } =>
                epoch_start_phase(&chain, epoch).await,
            EpochPhase::Dkg { epoch, round, roster, collected } =>
                dkg_phase(&peers, &clock, config, epoch, round, roster, collected).await,
            EpochPhase::PublishKeys { epoch, roster, group_keys } =>
                publish_keys_phase(&chain, epoch, roster, group_keys).await,
            EpochPhase::BuildTm { epoch, roster, group_keys } =>
                build_tm_phase(&chain, epoch, roster, group_keys).await,
            EpochPhase::Sign { epoch, roster, cascade, tm, round, collected } =>
                sign_phase(&peers, &clock, config, epoch, roster, cascade, tm, round, collected).await,
            EpochPhase::Submit { epoch, signed_tm, leader_attempt } =>
                submit_phase(&chain, &clock, config, epoch, signed_tm, leader_attempt).await,
            EpochPhase::AwaitConfirm { epoch, cardano_tx_id } =>
                await_confirm_phase(&chain, epoch, cardano_tx_id).await,
        };
    }
}
```

Each `*_phase` function is a standalone `async fn` — independently testable with mock traits.

## 5. DKG Phase Pattern

```rust
async fn dkg_phase(..., round: DkgRound, ...) -> EpochPhase {
    match round {
        DkgRound::Round1 => {
            // Generate our package, publish via peers.publish_dkg_round1()
            // Poll peers with deadline via tokio::select!
            tokio::select! {
                result = poll_dkg_round1(&peers, &roster) => {
                    // transition to Round2 with collected packages
                }
                _ = tokio::time::sleep_until(deadline) => {
                    // timeout: identify non-responsive peers, log, restart with smaller set
                }
            }
        }
        DkgRound::Round2 => {
            // Publish round2, poll peers, transition to Part3
        }
        DkgRound::Part3 => {
            // Pure computation: derive key package
            // transition to PublishKeys
        }
    }
}
```

Uses existing `frost::participant::dkg_part1/2/3`.

## 6. Signing Cascade

The signing cascade handles progressive fallback when quorum thresholds are not met within deadlines:

```rust
async fn sign_phase(..., cascade: CascadeLevel, ...) -> EpochPhase {
    let (signers, timeout) = match cascade {
        Quorum67 => (roster.signers_67(), config.quorum67_timeout),
        Quorum51 => (roster.signers_51(), config.quorum51_timeout),
        Federation => (roster.federation(), config.federation_timeout),
    };

    tokio::select! {
        result = run_frost_signing(&peers, &signers, &tm) => {
            match result {
                Ok(signed) => EpochPhase::Submit { ... },
                Err(e) => { /* log, retry or escalate */ }
            }
        }
        _ = tokio::time::sleep_until(clock.deadline(timeout)) => {
            match cascade {
                Quorum67 => EpochPhase::Sign { cascade: Quorum51, round: Round1, .. },
                Quorum51 => EpochPhase::Sign { cascade: Federation, round: Round1, .. },
                Federation => panic!("federation timeout -- critical failure"),
            }
        }
    }
}
```

## 7. Parallel Per-Input Signing

Each TM input needs a separate FROST signing round (different sighash + tweak). These run concurrently via `JoinSet`:

```rust
async fn run_frost_signing(peers, signers, tm) -> Result<Vec<u8>> {
    let mut join_set = JoinSet::new();
    for (idx, input) in tm.inputs().iter().enumerate() {
        let sighash = input.sighash();
        join_set.spawn(sign_single_input(peers, signers, idx, sighash));
    }
    let mut sigs = Vec::new();
    while let Some(result) = join_set.join_next().await {
        sigs.push(result??);
    }
    Ok(assemble_signed_tx(tm, &sigs))
}
```

## 8. Generic Polling Helper

Used by both DKG and signing phases to collect payloads from peers:

```rust
async fn poll_peers<T>(
    peers: &[SpoInfo],
    threshold: usize,
    deadline: Instant,
    poll_interval: Duration,
    fetch_one: impl Fn(&SpoInfo) -> Fut<Result<Option<T>>>,
) -> Result<BTreeMap<SpoId, T>, PollError> {
    let mut results = BTreeMap::new();
    loop {
        for peer in peers {
            if results.contains_key(&peer.id) { continue; }
            if let Ok(Some(data)) = fetch_one(peer).await {
                results.insert(peer.id.clone(), data);
            }
        }
        if results.len() >= threshold { return Ok(results); }
        if Instant::now() >= deadline {
            return Err(PollError::Timeout { got: results.len(), need: threshold });
        }
        tokio::time::sleep(poll_interval).await;
    }
}
```

## 9. Nonce Safety

FROST nonces MUST NOT be reused. In v0.2, nonces are held in memory only — generated fresh each run. A crash mid-signing means the signing round restarts from scratch on the next run (safe, since unused nonces are simply discarded).

> **v0.3** will add sled-backed persistence: nonce save/load/mark-used protocol, phase persistence for crash recovery, and resume-from-any-phase on restart.

## 10. Config

```rust
pub struct EpochConfig {
    pub dkg_round_timeout: Duration,      // 5 min per round
    pub poll_interval: Duration,           // 500ms
    pub quorum67_timeout: Duration,        // ~24h
    pub quorum51_timeout: Duration,        // ~24h
    pub federation_timeout: Duration,      // ~24h (CSV timelock)
    pub leader_timeout: Duration,          // 60s per cascade level
    pub identity: SpoIdentity,
}
```

## 11. Implementation Steps

### Step 1: Trait definitions + state enum + config

**Files**: `src/epoch/mod.rs`, `src/epoch/state.rs`, `src/epoch/traits.rs`

- Define all traits (`CardanoChain`, `PeerNetwork`, `Clock`)
- Define `EpochPhase` enum + all supporting types (`Roster`, `GroupKeys`, etc.)
- Define `EpochConfig`
- Add `async-trait` to Cargo.toml
- **Test**: enum serializes/deserializes via serde_json roundtrip

### Step 2: In-memory mock implementations

**Files**: `src/epoch/mocks.rs`

- `MockCardanoChain` — configurable responses, tracks calls
- `MockPeerNetwork` — in-memory payload store, publish/fetch work locally
- `FakeClock` — controllable time
- **Test**: mock smoke tests

### Step 3: Main loop + idle/epoch_start phases

**Files**: `src/epoch/machine.rs`

- `run_epoch_loop()` with match dispatch
- `idle_phase()` — call `chain.await_epoch_boundary()`
- `epoch_start_phase()` — query registry + stake → compute thresholds → build roster
- **Test**: mock chain returns epoch boundary → transitions to EpochStart → Dkg

### Step 4: DKG phase

**Files**: `src/epoch/dkg.rs`

- `dkg_phase()` with Round1 → Round2 → Part3
- Uses existing `frost::participant::dkg_part1/2/3`
- `poll_peers()` generic helper
- Timeout handling per round
- **Test**: happy path 3-of-3 via mocks, timeout transitions, partial collection

### Step 5: Signing phase + cascade

**Files**: `src/epoch/signing.rs`

- `sign_phase()` with cascade levels (67% → 51% → federation)
- `run_frost_signing()` with JoinSet for parallel per-input rounds
- Uses existing `frost::participant::sign_round1/2/aggregate`
- **Test**: happy path signing, cascade timeout fallback

### Step 6: Submit + AwaitConfirm phases

**Files**: `src/epoch/machine.rs` (extend)

- Leader election: `hash("bifrost-leader" || prev_tm_txid) % roster_size`
- Leader timeout cascade: `attempt++` after `config.leader_timeout`
- `await_confirm_phase()` — poll chain for confirmation
- **Test**: leader submits successfully, leader timeout → next SPO

### Step 7: Adapt existing HTTP to PeerNetwork trait

**Files**: `src/http/peer_network.rs`

- `HttpPeerNetwork` struct implementing `PeerNetwork` trait
- Wraps existing `PeerClient` (fetch) + `SharedState` (publish)
- **Test**: existing http_client tests still pass

### Step 8: Wire into main.rs

- New `run` subcommand for production mode
- Adapt `demo-local` to use state machine with `MockCardanoChain`

## 12. Verification Plan

After each step, `cargo test`. After step 8:

1. **`cargo test`** — all unit + integration tests pass
2. **`cargo run -- demo-local`** — still works (uses mocks)
3. **Mock-based integration test**: full epoch cycle (idle → DKG → sign → submit → confirm → idle)
