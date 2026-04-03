# Heimdall Decisions Log

All architectural and technology decisions for the Heimdall SPO program, with dates and reasoning.

---

## DEC-001: FROST Library Selection

**Date:** 2025-02-09 (initial), 2026-04-03 (confirmed)
**Decision:** Use `frost-secp256k1-tr` v3.0.0-rc.0 from ZcashFoundation/frost
**Status:** Confirmed

### Context

Heimdall needs a FROST implementation that produces Bitcoin-compatible Taproot (BIP-340) Schnorr signatures. The threshold signature must be indistinguishable from a single-signer Taproot spend.

### Options Considered

| Library | Taproot | Weighted | Audit | RFC 9591 | Maintenance |
|---------|---------|----------|-------|----------|-------------|
| **frost-secp256k1-tr** (Zcash Foundation) | Yes | No (manual multi-share) | NCC Group (partial) | Yes | Active, 250+ stars |
| frost-secp256k1 (Zcash Foundation) | No | No | Same | Yes | Same repo |
| WSTS (Trust-Machines/Stacks) | Not explicit | **Yes (native)** | Unknown | No | Active, 35 stars |
| ICE-FROST (Topos) | No | No | None | No | **Archived Oct 2024** |
| secp256kfun/schnorr_fun (LLFourn) | Partial | No | None | No | Experimental |

### Rationale

- **BIP-340 Taproot compatibility is non-negotiable** for Bitcoin treasury signing. Only `frost-secp256k1-tr` provides this with `aggregate_with_tweak()`.
- **RFC 9591 compliance** ensures formal specification backing and interoperability.
- **Identifiable abort** (always-on in v3.0.0-rc.0) supports the misbehavior detection model.
- **DKG share refresh** (v2.1+) supports epoch-boundary key rotation.
- **NCC Group audit** provides baseline confidence for security-critical infrastructure.
- **Weighted thresholds** are handled by computing an appropriate `min_signers` value based on stake distribution (bottom-k-by-stake approach), not by assigning multiple shares per SPO. This avoids WSTS's lack of BIP-340 support.

### Risks

- v3.0.0-rc.0 is a release candidate, not stable. Monitor for breaking changes before 3.0 final.
- BIP-445 (Blockstream's FROST BIP) may eventually become the canonical Bitcoin standard — but it's C-only and not merged yet. Re-evaluate if a Rust binding appears.

---

## DEC-002: Bitcoin Transaction Library

**Date:** 2026-04-03
**Decision:** Use `bitcoin` crate v0.32 (rust-bitcoin)
**Status:** Accepted

### Context

Heimdall must construct Bitcoin Treasury Movement transactions with Taproot inputs/outputs, compute BIP-341 sighashes, and embed FROST-produced signatures.

### Options Considered

| Library | Taproot | Maturity | Ecosystem |
|---------|---------|----------|-----------|
| **rust-bitcoin** (`bitcoin` 0.32) | Full (TaprootBuilder, SighashCache, x-only keys) | Production-grade, canonical | Standard |
| bitcoincore-rpc | RPC only, no tx construction | Mature | Requires bitcoind |
| secp256kfun | Low-level only | Research | Niche |

### Rationale

- `bitcoin` is the canonical Rust Bitcoin library with comprehensive BIP-340/341 support.
- Provides `TaprootBuilder` for script tree construction and `SighashCache` for per-input sighash computation.
- `bitcoin_hashes` is bundled within (no separate dependency needed).
- Extensive documentation including the Rust Bitcoin Cookbook for Taproot transactions.

### Integration Note

FROST produces signatures as `k256` types. A thin conversion layer serializes FROST `(R, z)` into `bitcoin::taproot::Signature`. Both libraries operate on the same secp256k1 curve — conversion is just byte serialization/deserialization.

---

## DEC-003: Cardano Node Communication

**Date:** 2026-04-03
**Decision:** Use Pallas for direct N2C communication with cardano-node
**Status:** Accepted

### Context

Heimdall must: follow the Cardano chain tip, query ledger state (stake distribution, UTxOs), and submit transactions. SPOs already run `cardano-node`.

### Options Considered

| Approach | Trust Model | Infrastructure | Rust Support | Capabilities |
|----------|-------------|---------------|--------------|--------------|
| **Pallas N2C** | Trustless (direct node) | Node only | Native crate | ChainSync, StateQuery, TxSubmission |
| Ogmios | Trustless (local bridge) | Node + Ogmios process | WebSocket client | Same + tx evaluation |
| Blockfrost | **Trusted third party** | None | Auto-generated SDK | REST queries, no ChainSync |
| cardano-multiplatform-lib | N/A (no networking) | — | Native crate | Tx building only |

### Rationale

- **Trust minimization**: A bridge program should not depend on third-party hosted APIs. N2C talks directly to the SPO's own node.
- **Zero additional infrastructure**: SPOs already run `cardano-node`. Pallas connects via the existing Unix socket.
- **Full protocol support**: ChainSync for epoch boundary detection, StateQuery for stake distribution and UTxO queries, TxSubmission for posting transactions.
- **Pallas is battle-tested**: Used by Oura, Scrolls, and Mithril in production.

### Alternatives Kept as Fallback

- **Ogmios**: Useful for `evaluateTransaction` (execution unit estimation) which N2C StateQuery doesn't provide. May add as optional dependency for development/debugging.
- **Blockfrost**: Useful for cross-verification during development. Not in the critical path.

---

## DEC-004: Cardano Transaction Building

**Date:** 2026-04-03
**Decision:** Use `pallas-txbuilder` as primary, evaluate Whisky if needed
**Status:** Accepted

### Context

Heimdall builds Cardano transactions for key publication, TM posting, and misbehavior proof submission.

### Options Considered

| Library | Maturity | Plutus Support | Backend |
|---------|----------|----------------|---------|
| **pallas-txbuilder** | Alpha (v1.0.0-alpha.6) | V2/V3 | Pure Pallas |
| Whisky SDK | Active | V1/V2/V3, script refs | Pallas or CSL |
| CML (cardano-multiplatform-lib) | Mature (v6) | Full | Own CDDL codegen |

### Rationale

- **pallas-txbuilder** keeps the dependency tree minimal — we already depend on Pallas for N2C protocols.
- Conway-era transaction building with `StagingTransaction` API covers our needs.
- If `pallas-txbuilder`'s alpha status proves limiting (missing features, bugs), Whisky provides a more ergonomic alternative with the same Pallas backend.
- CML is the most battle-tested option but adds a large dependency with different serialization approach.

### Action Items

- Start with pallas-txbuilder. If it lacks critical features (e.g., script reference handling, Plutus datum attachment), migrate to Whisky.

---

## DEC-005: secp256k1 Library Strategy

**Date:** 2026-04-03
**Decision:** Use both `k256` and `bitcoin::secp256k1` with clear boundary
**Status:** Accepted

### Context

Two secp256k1 implementations exist in Rust with different design goals.

### Analysis

| Aspect | `k256` (RustCrypto) | `secp256k1` (rust-bitcoin) |
|--------|---------------------|---------------------------|
| Implementation | Pure Rust | FFI to C (libsecp256k1) |
| Performance | ~2x slower | Fastest |
| Ecosystem | RustCrypto traits (`elliptic-curve`) | Bitcoin-specific API |
| Used by | frost-secp256k1-tr | bitcoin crate |
| C dependency | None | Yes |

### Decision

- **`k256`** for all FROST protocol operations (DKG, threshold signing, ECDH). This is dictated by `frost-secp256k1-tr`'s internal API.
- **`secp256k1`** (via `bitcoin` crate re-export) for Bitcoin transaction construction and final signature embedding.
- Thin conversion functions at the boundary: serialize FROST's `k256` types to bytes, deserialize into `bitcoin::secp256k1` types.

### Rationale

Both libraries operate on the same curve. The conversion boundary is narrow (64-byte signatures, 32-byte scalars, 33-byte compressed points). Performance is not a concern at this boundary — it happens once per signing round, not in a hot loop.

---

## DEC-006: HTTP Framework

**Date:** 2026-04-03
**Decision:** Use Axum 0.8 for the HTTP server, reqwest 0.12 for the HTTP client
**Status:** Accepted

### Context

Each SPO runs an HTTP server at their `bifrost_url` serving DKG/signing payloads (pull model). Each SPO also polls other SPOs' endpoints.

### Options Considered (Server)

| Framework | Tokio Integration | Performance | Ecosystem | Learning Curve |
|-----------|------------------|-------------|-----------|---------------|
| **Axum** 0.8 | Native (same team) | Excellent | Tower middleware | Low |
| Actix-Web | Own runtime | ~15% faster raw | Own middleware | Medium |
| Warp | Tokio-based | Good | Filter combinators | Higher |

### Rationale

- **Native Tokio integration**: Heimdall uses Tokio for everything (chain sync, signing coordination). Axum is built by the Tokio team.
- **Tower middleware**: Rate limiting, tracing, timeouts, CORS all available via `tower-http`.
- **Performance**: The `bifrost_url` endpoint serves a small set of SPO peers, not high-traffic web requests. Actix's raw performance advantage is irrelevant.
- **reqwest** is the dominant Rust HTTP client (300M+ downloads), Tokio-native, with JSON support.

---

## DEC-007: Async Runtime

**Date:** 2026-04-03
**Decision:** Use Tokio as the async runtime
**Status:** Accepted

### Rationale

Not really a choice — Tokio is required by Axum, reqwest, and Pallas. It's the de facto Rust async runtime. Key features used:
- Multi-threaded work-stealing for concurrent DKG/signing
- Async TCP for Ouroboros protocol communication
- Timers for epoch scheduling and round timeouts
- `tokio::sync` channels between chain follower and epoch orchestrator
- `tokio::select!` for managing multiple concurrent protocol phases

---

## DEC-008: Persistent Storage

**Date:** 2026-04-03
**Decision:** Use `sled` as embedded key-value store
**Status:** Accepted

### Context

Heimdall needs crash-safe local storage for DKG key packages, epoch state, and operational data.

### Options Considered

| Store | Type | Rust Support | Crash Safety | Dependencies |
|-------|------|-------------|--------------|--------------|
| **sled** | Embedded KV | Pure Rust | Yes (write-ahead log) | None (pure Rust) |
| RocksDB | Embedded KV | FFI wrapper | Yes | C++ (librocksdb) |
| SQLite | Embedded SQL | rusqlite (FFI) | Yes | C (libsqlite) |
| File-based | JSON/CBOR files | Manual | No (unless fsync) | None |

### Rationale

- **Pure Rust**: No C/C++ build dependencies. Simpler cross-compilation for SPO environments.
- **Crash-safe**: sled uses a write-ahead log, ensuring data isn't corrupted on unexpected shutdown.
- **Simple API**: Key-value is sufficient — Heimdall's storage patterns are all "store by key, retrieve by key" (epoch number, pool_id, etc.).
- **Performance**: More than adequate for the low-frequency storage patterns (writes per DKG round, not per millisecond).

### Risk

sled's author has noted it's "beta" quality. If reliability concerns emerge in testing, migrate to RocksDB (well-proven, used by many blockchain projects, but adds C++ dependency).

---

## DEC-009: DKG Share Encryption

**Date:** 2026-04-03
**Decision:** Use k256 ECDH + HKDF-SHA256 + XOR
**Status:** Accepted

### Context

During DKG Round 2, each SPO encrypts secret shares for each recipient using the recipient's `bifrost_id_pk` (secp256k1 public key).

### Scheme

```
1. Generate ephemeral secp256k1 keypair (e_i, E_i)
2. Shared secret: ss = ECDH(e_i, bifrost_id_pk_recipient)
3. Symmetric key: k = HKDF-SHA256(ss, info="bifrost-dkg-share")
4. Ciphertext: share XOR k (32 bytes)
5. Publish: (recipient_pool_id, E_i, ciphertext)
```

### Libraries

- `k256::ecdh` for Diffie-Hellman (integrates with FROST's k256 types)
- `hkdf` (RustCrypto) for key derivation
- `sha2` for HKDF's underlying HMAC

### Rationale

- XOR encryption is sufficient because each key `k` is derived from a fresh ephemeral keypair and used exactly once. This is effectively a one-time pad.
- HKDF ensures the shared secret is properly expanded into a uniform key.
- The scheme matches the Bifrost technical documentation specification exactly.

---

## DEC-010: Weighted Threshold Approach

**Date:** 2026-04-03
**Decision:** Compute threshold `t` as minimum signers where bottom-t-by-stake exceeds security threshold
**Status:** Accepted

### Context

FROST uses a standard t-of-n model. Bifrost needs weighted thresholds based on stake.

### Approach

```
t = min { k : combined_stake(bottom k SPOs by stake) > security_threshold }
```

Where `security_threshold` is 51% (or 67%) of total delegated stake among Bifrost SPOs.

### Rationale

This ensures that **any** subset of `t` signers collectively controls sufficient stake, regardless of which specific SPOs participate. The approach is simpler than WSTS's native weighted shares and works with the standard `frost-secp256k1-tr` API.

### Trade-off

This produces a higher `t` than would be optimal with native weighted shares (because it must account for the worst case: the t smallest SPOs signing). For example, with 400 SPOs and a heavy-tailed stake distribution, `t` might be 350 instead of a theoretical minimum of ~200. This is acceptable because:
- DKG and signing are off-chain and fast (~minutes)
- Higher `t` means stronger security guarantees
- The existing codebase already demonstrates 350-of-400 DKG/signing performance

---

## DEC-011: Misbehavior Proof System

**Date:** 2025-02-09 (initial), 2026-04-03 (confirmed)
**Decision:** PLONK over BLS12-381 with non-native secp256k1 arithmetic
**Status:** Confirmed

### Context

Misbehavior proofs must be verifiable on Cardano. Plutus V3 provides native BLS12-381 pairing builtins.

### Design

- **Proving system**: PLONK with KZG commitments over BLS12-381 (`dusk-plonk`)
- **In-circuit**: secp256k1 operations via 4x64-bit limb non-native field arithmetic
- **Proof types**: DKG commitment misbehavior, signing share misbehavior
- **Proof size**: ~1,008 bytes (constant, regardless of participant count)
- **On-chain verification**: BLS12-381 pairing check via Plutus V3 builtins

### Rationale

The sign-the-hash scheme (BIP-340 Schnorr over `SHA256(canonical_bytes)`) enables this: the accused SPO's signed `message_hash` binds them to specific protocol data, and the ZK circuit proves that data is cryptographically invalid — without revealing the full payload on-chain.

---

## DEC-012: Communication Model

**Date:** 2026-04-03
**Decision:** Pull-only HTTP model (no push, no coordinator, no P2P)
**Status:** Accepted

### Context

SPOs need to exchange DKG and signing data. The Bifrost technical documentation specifies a pull model.

### Design

- Each SPO publishes its own data at well-known URL paths on its HTTP server.
- Each SPO polls other SPOs' endpoints to fetch their data.
- No coordinator, no push notifications, no message ordering dependency.

### Rationale

- **No NAT/firewall issues**: Only outbound HTTP requests needed to participate.
- **No coordination**: SPOs operate independently, publishing at their own pace.
- **Censorship resistance**: Data availability is the publisher's responsibility — failure to publish is detectable.
- **Simplicity**: No message routing, relay infrastructure, or P2P networking.
- **Consistency with spec**: Matches the Bifrost technical documentation exactly.

---

## DEC-013: Cardano Datum Encoding

**Date:** 2026-04-03
**Decision:** Use `minicbor` for CBOR encoding/decoding of Cardano datums
**Status:** Accepted

### Context

Bifrost smart contracts (written in Aiken) use CBOR-encoded datums. Heimdall must encode datums when building transactions and decode datums when reading UTxO state.

### Options Considered

| Library | Approach | Pallas Compat |
|---------|----------|--------------|
| **minicbor** | Derive macros, lightweight | Used by Pallas internally |
| cbor-diag | Diagnostic only | N/A |
| serde_cbor | Serde-based | Different encoding choices |
| ciborium | Full CBOR, heavy | Overkill |

### Rationale

- `minicbor` is already used internally by Pallas, so it's already in the dependency tree.
- Lightweight with derive macros for struct-level encoding/decoding.
- Direct compatibility with Pallas's CBOR representation.

---

## DEC-014: Logging Framework

**Date:** 2026-04-03
**Decision:** Use `tracing` + `tracing-subscriber`
**Status:** Accepted

### Rationale

- `tracing` is the Tokio ecosystem standard for structured logging and diagnostics.
- Integrates with `tower-http` for request tracing.
- Supports span-based context (e.g., `epoch=42, phase=DKG, round=1`) for debugging multi-phase protocol execution.
- `tracing-subscriber` provides JSON and human-readable output formats.

---

## DEC-015: CLI Framework

**Date:** 2026-04-03
**Decision:** Use `clap` v4 for command-line argument parsing
**Status:** Accepted

### Rationale

- Industry standard for Rust CLIs.
- Derive macro API for declarative argument definition.
- Subcommands for different modes: `heimdall run`, `heimdall register`, `heimdall revoke`, `heimdall status`.

---

## DEC-016: Leader Election for Cardano Submission

**Date:** 2026-04-03
**Decision:** Deterministic leader election with timeout cascade
**Status:** Accepted

### Design

```
leader_index = hash("bifrost-leader" || prev_tm_txid) mod roster_size
```

With timeout cascade: if leader doesn't submit within T slots (~1 min), next SPO in roster order becomes eligible. Since there is one TM per epoch, `tm_sequence` is unnecessary.

### Rationale

- **Fairness**: Previous TM's Bitcoin txid as entropy is unpredictable before that TM is mined.
- **Verifiable**: On-chain validator can recompute leader_index from Treasury Info UTxO.
- **Liveness**: Timeout cascade ensures submission happens even if the primary leader is offline.
- **Incentive**: Leader receives a reward from subsequent fBTC minting transactions.

---

## DEC-017: Merkle Patricia Trie for Completed Peg-ins

**Date:** 2026-04-03
**Decision:** Implement Rust port of Aiken Merkle Patricia Forestry
**Status:** Accepted

### Context

The `treasury.ak` contract maintains a Merkle Patricia Trie of completed peg-ins to prevent double minting. The on-chain verifier uses the Aiken `merkle-patricia-forestry` library. Off-chain code must produce proofs compatible with this verifier.

### Options Considered

| Approach | Compatibility | Effort |
|----------|--------------|--------|
| **Port Aiken MPF to Rust** | Exact proof format match | Medium |
| Use Parity trie-db | Different proof format | Low, but incompatible |
| Use Node.js MPF via FFI | Compatible | Fragile, operational complexity |

### Rationale

- **Proof compatibility is mandatory**: The on-chain Aiken verifier expects a specific proof format (sparse merkle tree with specific hash construction).
- The Aiken MPF specification is well-documented in the repository.
- A Rust port ensures native integration without FFI overhead or Node.js runtime dependency.
- The trie is not large (one entry per completed peg-in), so performance is not a concern.

---

## DEC-018: TLS for bifrost_url

**Date:** 2026-04-03
**Decision:** TLS is not required. Plain HTTP is sufficient.
**Status:** Accepted

### Rationale

- All protocol payloads are authenticated via BIP-340 Schnorr signatures over `SHA256(canonical_bytes)`. An attacker who compromises DNS or intercepts traffic **cannot forge valid payloads** without `bifrost_id_sk`. Tampering is detected by signature verification.
- TLS would theoretically prevent traffic analysis (which SPO talks to which), but this metadata is already public — the registry linked-list contains every SPO's `bifrost_url`, and every SPO polls every other SPO. There's nothing to hide.
- TLS doesn't help against active blocking/delay attacks — an attacker who can block TCP can block TLS too.
- Requiring TLS adds operational burden on SPOs (certificate management, renewal) with no security benefit given the existing authentication model.
- SPOs who want TLS for their own reasons (e.g., reverse proxy already terminates TLS) can use it, but the protocol doesn't require it.

---

## DEC-019: Dependency Version Constraints

**Date:** 2026-04-03
**Decision:** Document version pins and upgrade path
**Status:** Accepted

### Hard Constraints (pinned by upstream)

`frost-secp256k1-tr` 3.0.0-rc.0 pins the following transitive dependencies. We cannot upgrade these independently:

| Crate | Pinned Version | Latest Available | Blocked By |
|-------|---------------|-----------------|------------|
| `rand_core` | 0.6 | 0.10.0 | frost-core, k256, dusk-plonk, ff, elliptic-curve |
| `rand` | 0.8 | 0.10.0 | Must match rand_core 0.6 |
| `sha2` | 0.10 | 0.11.0 | frost-secp256k1-tr, dusk-plonk |
| `k256` | 0.13 | 0.14.0-rc.8 | frost-secp256k1-tr |
| `hkdf` | 0.12 | 0.13.0 | Must match sha2 0.10 (hmac dependency) |

These will all upgrade together when frost-secp256k1-tr releases 3.0 stable (or a version that bumps to the RustCrypto 2026 edition).

### Upgraded to Latest Stable

| Crate | From | To | Notes |
|-------|------|----|-------|
| `dusk-plonk` | 0.22.0-rc.0 | **0.22.0** | Stable released 2026-03-31. Build verified. |

### Versions Confirmed as Latest

| Crate | Version | Status |
|-------|---------|--------|
| `frost-secp256k1-tr` | 3.0.0-rc.0 | Newest release (stable is 2.2.0 but lacks features we use) |
| `bitcoin` | 0.32 | Latest stable line (0.32.8). 0.33 is beta. |
| `pallas` | 1.0.0-alpha.6 | Latest published. No stable release exists yet — alpha is the norm for this crate. |
| `axum` | 0.8 | Latest stable (0.8.8) |
| `reqwest` | 0.13 | Latest stable (0.13.2) |
| `dusk-bls12_381` | 0.14 | Latest stable (0.14.2) |
| `ff` | 0.13 | Latest stable (0.13.1) |
| `ed25519-dalek` | 2 | Latest stable (2.2.0) |
| `blake2` | 0.10 | Latest stable. 0.11 is RC only. |
| `sled` | 0.34 | Latest stable (0.34.7). 1.0 is alpha. |
| `minicbor` | 2.2 | Latest stable (2.2.1). Major jump from old 0.24 API. |
| `hex` | 0.4 | Latest stable (0.4.3) |
| `rayon` | 1.10 | Near-latest (1.11.0 available, minor) |
| `tokio` | 1 | Latest stable (1.50.0) |
| `clap` | 4 | Latest stable (4.5.54+) |
| `tracing` | 0.1 | Latest stable (0.1.44) |

---

## DEC-020: Single Treasury Movement Per Epoch

**Date:** 2026-04-03
**Decision:** Produce exactly one TM transaction at the end of each epoch
**Status:** Accepted

### Context

The Bifrost technical documentation describes the possibility of multiple TM batches per epoch (4-5 batches, each cycling through build -> sign -> broadcast -> Bitcoin confirmation). This requires chaining treasury UTxOs within an epoch and tracking which peg-in/peg-out requests belong to which batch.

### Decision

One TM per epoch. It sweeps all confirmed peg-ins, fulfills all pending peg-outs, and moves the treasury to the new roster's Taproot address.

### Rationale

- **Simpler state machine**: No chaining of treasury UTxOs within an epoch, no tracking batch membership, no dependency on intermediate Bitcoin confirmations.
- **Simpler leader election**: No `tm_sequence` parameter — one leader per epoch for the single TM.
- **Simpler deterministic construction**: All SPOs read the same snapshot of peg-in/peg-out UTxOs at the pegs deadline, construct one transaction.
- **Sufficient for initial implementation**: Bifrost is designed for large, infrequent transfers — one batch per epoch (~5 days) is adequate.
- **Can be extended later**: If throughput demands it, multi-TM batching can be added as an optimization without changing the core protocol.

### Trade-off

Depositors and withdrawers wait up to one full epoch (~5 days) plus Bitcoin confirmation time (~17 hours) for their operations to complete. This is acceptable per Bifrost's design goal of prioritizing security over speed.
