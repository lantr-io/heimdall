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

---

## DEC-021: Remove 67% Quorum Tier from Signing Cascade

**Date:** 2026-04-22
**Decision:** Signing cascade is two-mode (51% → federation); drop `Y_67` leaf, `CascadeLevel::Quorum67`, and `quorum67_timeout`.
**Status:** Accepted

### Context

The Bifrost technical documentation previously described a three-mode signing cascade: 67% → 51% → federation. The current documentation describes it as two-mode: 51% → federation. The main design text throughout `technical_documentation.md` consistently uses the two-mode form (§1.3 glossary, §2 architecture, §3 participants, §7 flows).

Heimdall's implementation carried the three-mode form across ~12 files: a `Y_67` leaf in the treasury Taproot tree, a `y_67` field on `TreasuryUtxo`/`TreasuryConfig`, a `CascadeLevel::Quorum67` enum variant, a `quorum67_timeout` config field, and a `y_67_seed_hex` in the demo TOML.

### Decision

- Treasury Taproot tree: internal key `Y_51` + single federation-CSV leaf. No `Y_67` leaf.
- `CascadeLevel` enum variants: `Quorum51`, `Federation` only.
- `TreasuryUtxo` / `TreasuryConfig` / `StaticFixture`: drop `y_67` field.
- `EpochConfig` / `ProtocolConfig`: drop `quorum67_timeout`.
- `BitcoinConfig`: drop `y_67_seed_hex`.

### Rationale

- **Alignment with spec.** Heimdall implements the Bifrost spec. When the spec changed, the code had to follow.
- **Pure code refactor.** The on-chain Plutus datum does not encode treasury keys (they come from `TreasuryConfig`), so no datum migration is required.
- **Cascade is still placeholder.** `sign_phase` does not yet implement any cascade failover — removing the unused `Quorum67` variant is a simplification, not a regression.

### Trade-off / Known Impact

Removing the `Y_67` leaf changes the merkle root → the Taproot tweak → the treasury output key → the on-chain treasury address. Any BTC held at the current preprod treasury address is stranded under the new derivation. Operationally either (a) treat preprod state as reset and re-fund, or (b) do a one-off sweep from the old address to the new one under the existing `Y_51 = Y_fed` key-path before deploying.

Existing `heimdall.toml` files with `y_67_seed_hex` / `quorum67_timeout_secs` become silent no-ops (serde ignores unknown fields with `#[serde(default)]`). Operators should prune the stale fields.

### Reference

- Design doc: `docs/superpowers/specs/2026-04-22-remove-67-percent-design.md`
- Driver: `../ft-bifrost-bridge/documentation/technical_documentation.md` (cascade now `51% → federation`).

## DEC-022: Treasury Resolution via the Confirmed TM Chain

Date: 2026-07-20
Status: Accepted

### Context

The Bitcoin treasury outpoint was configured locally (`[bitcoin] treasury_txid/vout/amount_sat`)
and the "current" treasury on Cardano was resolved by picking the most recent datum-bearing UTxO
at the TM address. With the TM Control NFT removed and TM minting made permissionless (gated
on-chain by chain linkage), a latest-UTxO scan becomes attacker-influenceable: anyone can post
Unconfirmed records, and a fake tip would deadlock the `btc_confirmed` polling loop.

### Decision

- `query_treasury` reads the bridge Config UTxO's field 11 (`initial_btc_treasury_utxo`, located
  by the config NFT) and walks the Confirmed TM chain (`cardano::tm_chain`): each Confirmed
  record is indexed by the outpoint it spent (`swept[0]`); the tip's `(btc_txid, 0)` valued at
  `fulfilled[0].amount` is the current treasury. Genesis anchor value comes from bitcoind
  `gettxout`.
- `btc_confirmed` combines two signals: the WI-028 in-flight scan (no Unconfirmed record spends
  the tip, no opaque unconfirmed) AND "our last-submitted TM txid has reached the chain tip"
  (tracked in-process, restart-safe against a lost Cardano post). The in-flight signal keeps
  cross-process safety (mover vs daemon) at the cost of a bounded liveness DoS: with
  permissionless minting anyone can post a correctly-linked but unsigned Unconfirmed record
  spending the tip (min-ADA cost per post; the mover's staleness deadline bounds the stall).
- `publish.rs` mints the TM NFT with the `TmMintRedeemer`: `Genesis(0)` (Constr 0 [0],
  referencing the Config UTxO) before the first TM confirms, `Chain(0)` (Constr 1 [0],
  referencing the tip Confirmed record) afterwards. Both variants carry the 0-based
  reference-input index of their anchor; the tx has exactly one reference input, so the sorted
  index is always 0.
- Local treasury config and `tm_control_ref` are removed; `[cardano]` gains `config_address`,
  `config_nft_policy_id`, `config_nft_asset_name`.

### Consequences

- Single source of truth on-chain; heimdall restart loses only the in-flight-TM marker, which is
  harmless (a rebuilt TM double-spending our own mempool tx is rejected by Bitcoin; the next
  poll sees the advanced tip).
- CLI commands with explicit `--treasury-outpoint` flags keep them for manual use; the
  sweep/mover path requires them for the FIRST movement (its tip selection is sync and does not
  read the Cardano config anchor).

### Reference

- Design doc: `../ft-bifrost-bridge/docs/superpowers/specs/2026-07-20-tm-confirmed-chain-design.md`
- Driver: `../ft-bifrost-bridge/documentation/technical_documentation.md` ("Post signed TM",
  "The TM chain").

---

## DEC-023: SPI Proof Endpoint Wire Format

**Date:** 2026-08-07
**Decision:** Serve swept peg-ins proofs as JSON with hex-encoded byte fields at `GET /spi/proof/{peg_in_utxo_id}`
**Status:** Accepted

### Context

Spec 2026-08-06-bridge-state-singleton-design rule [SPI-4] requires an unauthenticated
GET route that serves a swept peg-ins membership (or non-membership) proof for a given
`peg_in_utxo_id`. The spec does not fix the wire format, so this entry does.

### Decision

- Route: `GET /spi/proof/{peg_in_utxo_id}`. The path segment is the 36-byte
  `peg_in_utxo_id` (txid internal order ++ vout LE, the `tm_chain::outpoint_bytes`
  encoding), hex-encoded. Anything that is not exactly 36 bytes of hex is a 400.
- Response, membership (the outpoint is in the trie):

  ```json
  {
    "member": true,
    "peg_in_utxo_id": "<hex, 36 bytes>",
    "root": "<hex, 32 bytes>",
    "value": "<hex, 36 bytes>",
    "proof": [ ...steps ]
  }
  ```

  `value` is the sweeping TM's input-0 outpoint ([SPI-3]).
- Response, non-membership: same shape with `"member": false` and no `value`.
- `proof` is a JSON array of MPF proof steps, one object per step, all byte fields
  hex-encoded (implemented by `spi_trie::proof_to_json`):
  - `{"type":"branch","skip":n,"neighbors":"<hex, 128 bytes>"}`
  - `{"type":"fork","skip":n,"neighbor":{"nibble":n,"prefix":"<hex>","root":"<hex>"}}`
  - `{"type":"leaf","skip":n,"key":"<hex>","value":"<hex>"}`
- The proof verifies against `root` via `mpf::verify_inclusion` (membership) or
  `mpf::verify_exclusion` (non-membership).

### Rationale

- Hex strings keep the payload greppable and language-neutral; every field is a plain
  byte string with a fixed meaning, so no client needs a CBOR decoder.
- The step objects mirror `mpf::ProofStep` one-to-one, so the mapping is mechanical in
  both directions and cannot lose information.
- Returning `root` in the body lets a client verify the proof offline and compare the
  root against the on-chain singleton on its own schedule.
- Non-membership answers 200 with `member: false` (not 404): the trie answers the
  question either way, and the exclusion proof is the useful payload.

## DEC-024: SPI Trie Production Wiring

**Date:** 2026-08-07
**Decision:** Serve /spi/proof from the persisted trie loaded per request; advance the trie on TM confirmation; enforce the [SPI-2] gate before signing
**Status:** Accepted

### Context

The first SPI trie cut (DEC-023) shipped the module and the proof route, but the
route read an `AppState.spi` field nothing ever populated: a deployed node would
have answered every query with a valid-looking exclusion proof against the empty
trie, presenting "was never swept" as authoritative for deposits that WERE swept.
`SpiTrie::verify_proposed` likewise had no caller, so [SPI-2] was not enforced.

### Decision

- `GET /spi/proof/{peg_in_utxo_id}` loads `spi-trie.json` from
  `protocol.state_dir` at the point of use, the same idiom `verify_cpo_root`
  and `advance_cpo_trie` use for `cpo-trie.json`. No in-memory trie snapshot.
  - `state_dir` unset: 503. The node keeps no trie, so it must not answer.
  - File absent: the genesis state (empty trie, nothing swept yet). The route
    answers honestly with exclusion proofs against the zero root.
  - File corrupt: 500 (`SpiTrie::load` refuses a root that fails its self-check).
- `advance_spi_trie` (epoch machine, next to `advance_cpo_trie`) folds every
  CONFIRMED TM's inputs except input 0 into the persisted trie [SPI-1] [SPI-3].
  It refuses to persist when the post-insert root disagrees with `tm.spi_root`.
- `TreasuryMovement` carries `spi_root`: the builder's trie advanced by the tx
  inputs, computed in `build_tm_phase`. The TM does not yet COMMIT this root on
  Bitcoin; the spec's `BTMR1` commitment output (replacing `CPOR1`) is a
  separate task, and when it lands the proposed root should be read back out of
  the tx like `committed_cpo_root` does today.
- `verify_spi_root` (sign_phase Round1, next to `verify_cpo_root`) reloads the
  trie and runs `SpiTrie::verify_proposed(&tm.spi_root, inputs)` before any
  signing material leaves the node [SPI-2]. Same honesty note as the CPO gate:
  the TM is self-built today, so what this catches is the on-disk trie moving
  between build and sign; the shape becomes a real co-signer gate unchanged
  once a leader-proposed TM wire format exists.

### Rationale

- Loading at the point of use cannot drift: whatever the last confirmed TM
  persisted is what the route serves and what the gate verifies.
- 503 without `state_dir` beats a technically-valid exclusion proof that is
  operationally a lie.
- Refusing to persist or sign on a root mismatch is the safe direction: a stale
  trie fails loudly at the next gate, a wrong one signs confidently wrong roots.

## DEC-025: SPI Trie Storage Discipline and Duplicate-Key Semantics

**Date:** 2026-08-07
**Decision:** Share one atomic-write helper between the trie state files; treat a repeated peg-in outpoint as a no-op only when the value is identical
**Status:** Accepted

### Context

`spi-trie.json` needs the same on-disk handling `cpo-trie.json` already had, and
`insert_for_confirmed_tm` can be reached twice for the same confirmed TM (a
restart replays the tail of the TM chain).

### Decision

- The 0700-directory / 0600-file / temp+rename write moved out of `cpo_trie.rs`
  into `src/cardano/state_file.rs`, and both tries call it. `epoch::persist`
  deliberately keeps its own copy: it force-chmods a pre-existing temp file and
  tolerates a failed `sync_all`, which the shared helper does not.
  - Rejected: a second copy of the helper inside `spi_trie.rs`. Two copies of a
    security-relevant write path drift, and only one of them gets the fix.
- Re-inserting a `peg_in_utxo_id` with the SAME value is a no-op. The same key
  with a DIFFERENT value is `SpiTrieError::Conflict`.
  - Rejected: last-write-wins. A Bitcoin outpoint is spent once, so two
    sweeping TMs for one deposit means one input is wrong; either choice yields
    a root no TM ever committed, and the [SPI-2] gate would then refuse every
    later TM with no way to tell which source lied.
- Persisted entries are hex strings and the file records its own root. `load`
  recomputes the root from the entries and refuses the file on a mismatch, so a
  hand-edited or truncated file cannot silently change what this node signs.

## DEC-026: BTMR1 Two-Root Commitment via a Builder-Side SpiTrieView

**Date:** 2026-08-07
**Decision:** `build_tm` computes and embeds both roots itself; the spi trie reaches it through a new `SpiTrieView` trait; test-pinned CPO names keep their spelling
**Status:** Accepted
**Spec:** ft-bifrost-bridge `docs/superpowers/specs/2026-08-06-bridge-state-singleton-design.md`,
§Root commitment output, §Checks/Confirm TM ([CTM-26]), §Off-chain: heimdall ([OH-3]),
§Off-chain rules ([SPI-1] to [SPI-3])

### Context

Rev 5.4 replaces the 39-byte "CPOR1" commitment with the 71-byte "BTMR1"
output: `OP_RETURN OP_PUSHBYTES_69 "BTMR1" ++ spi_root ++ cpo_root`. Before
this change the spi_root was computed in `build_tm_phase` AFTER `build_tm`
returned, which cannot work once the root lives inside the transaction bytes.

### Decision

- `build_tm` gains an eighth parameter, `spi: &dyn SpiTrieView`, mirroring
  `CpoTrieView`: the trait lives in `tm_builder.rs` and `SpiTrie` implements it
  in `spi_trie.rs`, so the `bitcoin` modules still never depend on `cardano`.
  - Rejected: patching the commitment output after `build_tm`. The txid,
    sighashes and `UnsignedTm` invariants are all fixed at build time.
- `verify_spi_root` ([SPI-2]) now also compares the root the transaction ITSELF
  commits (script bytes [7, 39)) against the locally recomputed one. A TM with
  NO commitment output is not its problem: `verify_cpo_root` runs first and
  refuses zero-or-many commitments, so the spi gate only cross-checks a present
  one. This keeps the gate callable on synthetic no-output TMs in tests.
- Names pinned by the task's tests keep their old spelling even where "cpo" is
  now half the story: `is_cpo_commitment`, `committed_cpo_root`,
  `CPO_COMMITMENT_EXTRA_VBYTES` (now 37 per [OH-3]). New names are BTMR1-scoped:
  `BTMR1_COMMITMENT_PREFIX`, `BTMR1_COMMITMENT_SCRIPT_LEN`,
  `btmr1_commitment_script`, `committed_roots` / `committed_spi_root`.
- `cpo_trie::confirmed_committed_root` reads the cpo half at [39, 71) and gains
  the sibling `confirmed_committed_spi_root` at [7, 39) (shared scanner
  `confirmed_committed_roots`). The mover and the two dev CLI paths load the
  spi trie via a new `spi_trie_from_cfg`, mirroring `cpo_trie_from_cfg`.
- The commitment byte offsets live in exactly one function, `tm_builder::
  btmr1_roots(spk) -> Option<(spi_root, cpo_root)>`, with `is_btmr1_commitment`
  as its length-and-prefix half. Both readers go through it — the Bitcoin one
  over `TxOut::script_pubkey` and the Cardano one over the Confirmed datum's
  output bytes — so 7 / 39 / 71 can never drift apart between the two.

---

## DEC-027: The BridgeState Singleton Decoder Replaces the One-Field CPO Reader

**Date:** 2026-08-07
**Decision:** A strict four-field `BridgeState` decoder in `cardano::bridge_state`; the
singleton is fetched by the `"BSS"` NFT; every caller takes `cpo_root` by name
**Status:** Accepted
**Spec:** ft-bifrost-bridge `docs/superpowers/specs/2026-08-06-bridge-state-singleton-design.md`,
§BridgeState, the singleton datum ([LIB-1] to [LIB-3]), §Off-chain: heimdall ([OH-4])

### Context

Rev 5.4 replaces the one-field completed-peg-outs trie datum with a four-field
`BridgeState` under a new NFT asset name, `"BSS"` (hex `425353`), not `"CPO"`
(hex `43504f`). Field 0 of the new datum is `spi_root`, not `cpo_root`.

### Decision

- `parse_bridge_state` pins the constructor tag AND the arity. The old
  `parse_cpo_trie_datum` took the head of the field list and checked neither, so
  against a `BridgeState` datum it would have returned `spi_root` where the
  caller wanted `cpo_root`. That failure is silent and asymmetric: a wrong root
  makes an MPF membership proof fail harmlessly, but it makes a non-membership
  proof succeed, which cancels a peg-out already paid in BTC.
  - Rejected: keeping the old reader with an index argument. That is one
    character away from the bug it fixes, which is why [LIB-1] requires access
    by name.
- Byte lengths are part of the decode: 32 for each root, 36 for
  `treasury_utxo_id` (`btc_txid ‖ vout`). A short value is a wrong value.
- `treasury_amount` is rejected when negative rather than cast. A satoshi amount
  has no negative reading, and `u64::try_from` on a decoded `i64` is the only
  place the sign can be caught before it becomes a huge unsigned value.
- `fetch_onchain_cpo_root` became `fetch_bridge_state`, returning the typed
  state. Its zero-holder and several-holder errors stay distinct, as before:
  zero means not deployed or not indexed, several mean the NFT is not a
  singleton. All three callers (`reconstruct`, `BlockfrostChain::query_cpo_root`,
  the `build-tm` preflight in `main.rs`) now read `state.cpo_root` by name.
- `CPO_ASSET_NAME` / `CPO_ASSET_NAME_HEX` and `parse_cpo_trie_datum` were
  removed with their tests, rather than left as dead exports. Nothing in
  heimdall reads a one-field singleton datum any more, and a leftover `"CPO"`
  asset-name constant is exactly the thing a future lookup would reach for.
  The Aiken `utils.get_mpf_from_output` helper still exists on-chain for the CPI
  trie ([LIB-2]); heimdall has no CPI trie reader today.
  - Their bytes-to-hex pin test came WITH them, as
    `the_bss_asset_name_hex_matches_the_bytes`. `BSS_ASSET_NAME` (the Aiken byte
    form) and `BSS_ASSET_NAME_HEX` (the asset-unit form) are two spellings of one
    fact, and only a test that ties them together stops the hex from drifting
    back to `43504f` on its own.
- The `cpo_policy_id` config key keeps its name. Renaming it to
  `bridge_state_policy` is a config-compatibility change, not part of [OH-4].
  Because the name now lies, the DOCS carry the truth: `config.rs` and
  `heimdall.toml` both say the value is Config field 3 `bridge_state_policy`,
  looked up with asset name `"BSS"` (hex `425353`), and that `"CPO"` (`43504f`)
  is gone. An operator reads only those two places.
- The zero-holder error of `fetch_bridge_state` names `cardano.cpo_policy_id`
  first. A wrong policy id and a sick indexer produce the SAME empty result, and
  the wrong policy id is far likelier right after this rename, so the message
  must not point only at the backend.
- The prose sweep from "CPO singleton" to "bridge state singleton" covers the
  modules this change touches (`cpo_trie`, `cpo_history`, `blockfrost_chain`,
  `config`, `main`, `heimdall.toml`). `epoch::machine`, `epoch::traits` and
  `epoch::mocks` still say "CPO singleton" in doc comments and in operator
  messages.
  - Rejected: sweeping them here. Their operator strings are the ones a live SPO
    reads on a mismatch, and changing message text is a behaviour change that
    belongs with the `cpo_policy_id` -> `bridge_state_policy` config rename, not
    with [OH-4]. They name the right UTxO by the old word; they are not wrong
    about what is read.

---

## DEC-028: FederationReset Removed; the Federation Authorizes Update-Y

**Date:** 2026-08-07
**Decision:** Delete the FederationReset builder, CLI and evidence readers; a
federation-signed Update-Y ([UY-5]) replaces them; `treasury_info` is
parameterized by `registry_policy_id` alone ([PRE-1]); the bootstrap accepts an
operator-supplied `bifrost_identity_root` ([PRE-2])
**Status:** Accepted
**Spec:** ft-bifrost-bridge `docs/superpowers/specs/2026-08-06-bridge-state-singleton-design.md`,
§Update-Y, federation branch ([UY-5], [UY-6]-[UY-8] withdrawn), §Contracts to
fix before first deployment ([PRE-1], [PRE-2]), §Federation co-authority

### Context

Rev 5.4 removes `treasury.ak`'s `FederationReset` branch. Its job (dead-roster
recovery) is covered by [UY-5]: the federation is a standing co-authority that
can sign an ordinary Update-Y under `y_federation`, naming ANY successor key
([UY-6] withdrawn). With the branch gone, `treasury.ak` no longer reads the
Confirmed TM record, so its `tm_nft_policy_id` compile parameter must go before
first deployment ([PRE-1]), and the bootstrap must not hard-code the empty MPF
root ([PRE-2]).

### Decision

- `build_update_y_tx` gained an `UpdateYAuthorizer` (`Roster` | `Federation`)
  on the request. It never changes the built bytes: both authorizations share
  ONE redeemer (`UpdateY`, Constr 1), ONE signed message
  (`update_y_sig_msg`, tag `"bifrost-update-y"`) and ONE datum transition. The
  on-chain branch differs only in which datum key verifies the signature, so
  the choice lives in the signature.
  - The builder BIP340-verifies `signature` under the datum key the authorizer
    names (`current_spos_frost_key` or `y_federation`) before building,
    mirroring `register_spo::verify_registration`. A wrong-key signature is
    rejected client-side (`UpdateYError::SignatureInvalid`) instead of failing
    phase-2 validation on chain and forfeiting collateral. Review round 1
    flagged the earlier design (a carried-but-unread field) as dead code with
    an unenforced doc promise; this check is the fix.
  - Rejected: a separate redeemer constructor or a `"bifrost-update-y-reset"`
    tag. The spec says every other Update-Y rule is unchanged; a second wire
    shape would force the validator and every off-chain builder to carry two
    paths for one transition.
- **Resolved `TreasuryInfoDatum` shape: all 5 fields stay, including
  `last_reset_tm_txid`.** The bridge-track `treasury.ak` change owns the datum
  shape; the current blueprint (upstream `plutus.json` and the
  `treasury_info_code.txt` fixture) still encodes
  `[bifrost_identity_root, current_spos_frost_key, y_federation,
  federation_csv_blocks, last_reset_tm_txid]`, so heimdall keeps the field –
  documented as vestigial, empty at bootstrap, preserved verbatim – to stay in
  lockstep. If the bridge track drops the field, the fixture bump carries the
  matching heimdall change.
- `treasury_info_script` takes only `registry_policy_id`. The `tm_nft_policy`
  config helper and `tm_nft_policy_from_script_cbor` were deleted with it:
  their own docs defined them as "treasury_info's 2nd param", so keeping them
  would leave a helper that derives a hash nothing accepts.
- `federation_reset.rs`, the `federation-reset` CLI, `federation_reset_redeemer`,
  `federation_reset_sig_msg`, `confirmed_tm_spent_via_federation_leaf` and
  `confirmed_tm_reset_evidence_from_hex` were deleted rather than deprecated –
  they read a Confirmed TM record that no longer exists in rev 5.4, and their
  sig-msg vector tests pinned an on-chain branch that is being removed.
- The bootstrap builder forwards `bifrost_identity_root` verbatim (the
  empty-root refusal and its test were removed); `bootstrap-treasury-info`
  gained `--identity-root` (optional, default empty MPF root). The on-chain
  mint branch still pins `mpf.root(mpf.empty)` until the bridge-track [PRE-2]
  change lands; until then a non-empty root builds but cannot validate, so
  `--identity-root` prints a warning when the root is not the empty MPF root.
- The ignored `registry_then_treasury_chain_matches_aiken` hash was re-pinned
  to the single-param application against the CURRENT upstream blueprint,
  whose compiledCode still declares the (now-unapplied) `tm_nft_policy_id`
  parameter. Re-pin both hashes when the bridge-track treasury.ak change
  regenerates `plutus.json`.

## 2026-08-10 - rev-5.4 Config + treasury sourcing (bridge-state singleton)

**DEC-030: the treasury is the singleton's head, end of chain walks.**
`query_treasury`, the CLI sweep and `tm-status` read the current treasury
outpoint AND its satoshi amount from the BridgeState datum, located through the
Config's `bridge_state_policy` ([PAR-1]). The Confirmed-chain walk (`tm_chain::
walk_chain`) is deleted: Confirm burns the TM record, so no Confirmed records
exist to follow. The taproot-tree selection that used to read the Confirmed
datum's outputs now reconstructs the candidate trees and checks them against
bitcoind `gettxout` on the head - the daemon therefore requires a Bitcoin RPC
for treasury resolution (it already did for genesis pricing).

**DEC-031: config_params reads the eight-field rev-5.4 layout.**
`bridge_state_policy` (#3) and `tm_script_hash` (#4) by position, the tunables
nested at #7 (always present; fewer than 8 fields is refused, more are
tolerated - appends stay the legal evolution). `min_stake`, the treasury
anchor and `leader_reward` left the datum; the register-spo R2 gate reads the
local `cardano.min_stake_lovelace` again (the field never had an on-chain
reader), and the posted TM datum is the 4-field `UnconfirmedTm`
`[signed_btc_tx, creator, created, fulfilled_por_outpoints]`.

**DEC-032: the mint redeemer names the singleton reference input.**
`publish.rs` posts with `TmMintRedeemer(bss_ref_index)` = Constr 0 [i], the
Config UTxO and the singleton both as reference inputs, and the index computed
against the SORTED (tx_hash, index) order the ledger presents to the script
(`MintRefs::sorted`). The Genesis/Chain split is retired ([PTM-5] withdrawn).

**DEC-033: "already swept" comes from the SPI trie.**
The sweep's auto-skip used `TmScan.consumed` (outpoints swept per Confirmed
records). Those records no longer exist; the swept set is the SPI trie the
node already maintains for the BTMR1 commitment, plus the live in-flight
spends. `TmScan` keeps its legacy Confirmed parsing (empty on a fresh
deployment) - removing it is a wider cleanup than this migration needs.

## 2026-08-11 - Cardano-only Bitcoin data on the SPO runtime

**DEC-034: treasury tree selection is Cardano-sourced; supersedes DEC-030's
"requires a Bitcoin RPC" clause.** The head's scriptPubKey comes from the TM
that CREATED the head: output 0 of the signed bytes in the (spent)
UnconfirmedTm record at the TM address, found by the txid RECOMPUTED from the
record's own bytes (the [SPI-7] discipline - a hostile record can only occupy
its own hash's slot). Backend selection matches `query_cpo_root` (Kupo, else
Blockfrost), and the result is cached per head (it only moves at Confirm).
The BOOTSTRAP anchor was created by the funding tx, not a TM, so no record
exists: the tree is then constructed from the configured keys WITHOUT
verification, logged loudly. Self-limiting per the spec's bootstrap trust
model - under wrong keys the FROST signatures simply do not verify.

**DEC-035: BTC broadcast is a dev flag, default off.** `bitcoin.submit` and
the sweep's `--broadcast` default to false and are documented DEV-ONLY:
production SPOs run no Bitcoin node, and the binocular watchtower relays
`signed_btc_tx` from the posted UnconfirmedTm record (that is what the record
is for). `bitcoin.rpc_url` serves only that opt-in path and the federation
ops tools (`treasury-self-send`, `federation-spend`), which are not SPO
runtime. The `gettxout` helpers are deleted; `broadcast_btc_tx` remains.

**DEC-036: the always-ok posting scaffold is gone; `tm_script_cbor` is
required.** binocular deleted TmtxScript (its salted always-ok stand-in) and
the create-tmtx/spend-tmtx commands, so a post minted under anything but the
real TreasuryMovementValidator lands at an address nothing scans. `publish.rs`
therefore refuses to build without `cardano.tm_script_cbor`, the
`oracle_constructor` knob is deleted (the UnconfirmedTm record is the only
datum shape - always Constr 0), and the `"TMTx"` asset-name defaults become
`""` (the real validator counts the empty-name token). `always_ok.rs` survives
as a TEST FIXTURE ONLY for the tx-composition tests.


**DEC-037: rev-5.4 reconstruction walks the singleton's spend history; the SPI
trie gets the same pre-signing guard as the CPO trie.** `cpo_trie::reconstruct`
replayed Constr-1 `Confirmed` records, which rev 5.4 never mints ([CTM-24]/
[CTM-25] burn the NFT and forbid a TM-address output), so on any live rev-5.4
chain it replayed an empty set and always failed the singleton cross-check.
It now harvests the spent `UnconfirmedTm` records (keyed by the txid RECOMPUTED
from `signed_btc_tx`, [OB-9]/[SPI-7]) and walks the treasury chain BACKWARD
from the singleton's head via input-0 ancestry ([OB-2]) - the same walk
binocular's SPI proof server uses, so a mined-but-unconfirmed TM is never
replayed. `cpo_policy_id` became REQUIRED: the singleton supplies both the
walk's start and the final check. The same harvest powers the new
`reconstruct-spi-trie` command (`cpo_trie::reconstruct_spi`), and `BuildTm`'s
pre-signing cross-check now covers BOTH tries (`query_bridge_roots`, one
singleton fetch): [SPI-2]'s peer recomputation cannot catch a roster-wide
stale spi-trie.json - every co-signer recomputes from the SAME restored state -
and a confirmed truncated spi_root strands every swept-but-unminted depositor.

**DEC-038: heimdall serves no SPI proofs.** The unauthenticated
`GET /spi/proof/{peg_in_utxo_id}` route (DEC-023) is removed: [SPI-4] (revised)
names binocular as the proof server and forbids heimdall the role, and the
route served proofs from the locally persisted trie without reconciling its
root against the singleton's attested spi_root - a lagging node would answer
`member=false` with an exclusion proof against a stale root, which reads as
"was never swept". This node's trie is quorum-internal state for the [SPI-2]
gate; depositors and tools ask a watchtower.

**DEC-039: BuildTm requires `protocol.state_dir`; the walk stops at a
non-TM.** Two defects with one shape - state the node cannot reconstruct is
state it must not attest.

`advance_spi_trie` returned `Ok(())` when `state_dir` was unset, while
`build_tm_phase` reloaded `SpiTrie::load_or_empty(None)`, so every TM
committed a `spi_root` covering only its own sweeps. Neither guard could see
it: [SPI-2]'s `verify_spi_root` recomputes from the same empty trie and agrees,
and `cross_check_bridge_roots` is skipped when `cardano.cpo_policy_id` is unset
- and BOTH keys are commented out in the shipped heimdall.toml, so this was the
DEFAULT configuration. Once such a TM confirms, the singleton's spi_root omits
every earlier sweep permanently, binocular's [SPI-6] replay fails, and no
depositor can obtain a [CPI-9] proof again. `load_cpo_trie` had the same hole on
the CPO side. BuildTm now refuses without a state_dir rather than degrading:
a node that cannot track the tries must not be the one proposing roots.

`walk_confirmed_chain` also lacked binocular's rule of stopping, WITHOUT
harvesting, at the first ancestor carrying no BTMR1 commitment output. The TM
address is permissionlessly payable and the harvest cannot require the TM NFT
(Confirm has burned it), so anyone could park a Constr-0 datum wrapping the
public genesis funding transaction and send the walk past the chain's origin
into unrelated Bitcoin history. The two implementations of [SPI-6] must agree;
they now do.

Test note: `fast_config` gives every node a temp state_dir, unique per CALL.
Keying it on the identifier alone made `full_cycle_2_of_2` and
`full_cycle_3_of_3` share node 1's trie under the parallel runner.
