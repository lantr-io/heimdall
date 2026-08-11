# Remove the 67% Quorum Tier from Heimdall

**Status:** Design — ready for planning
**Date:** 2026-04-22
**Driver:** `ft-bifrost-bridge/documentation/technical_documentation.md` — bifrost signing cascade is now `51% → federation` (two modes), not `67% → 51% → federation`.

---

## Goal

Bring heimdall into alignment with the current bifrost spec by removing the 67% SPO quorum tier. After this change:

- The treasury Taproot tree has a **single leaf** (federation-CSV fallback), finalized under `Y_51`.
- The signing cascade enum tracks only `Quorum51` and `Federation`.
- No `Y_67` key flows through the system — the oracle, config, fixtures, CLI, and datum parser all lose the field.

This is a **pure code refactor**. The on-chain Plutus datum does not encode treasury keys (they come from `TreasuryConfig`), so no datum migration is required.

## Out of scope

- The `CascadeLevel` enum itself and its cascade plumbing stay. The real 51%→federation failover is still a placeholder per the TODO at `src/epoch/signing.rs:27`; implementing it is separate work.
- Peg-in Taproot is already simplified (commit `6af7c67`); this change targets the treasury Taproot only.
- `Design.md` narrative stays as point-in-time design context. Only `Specification.md` (current spec authority) and `DecisionsLog.md` (decision record) are updated.

## Architecture

### Before

```text
Treasury Taproot:
  Internal key: Y_51            (51% FROST group key)
  Script tree:
    Leaf 1 (depth 1): <Y_67> OP_CHECKSIG
    Leaf 2 (depth 1): <federation_timeout> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG

Signing cascade: Quorum67 → Quorum51 → Federation
Config keys: y_51, y_67, y_fed (all three carried on TreasuryUtxo + TreasuryConfig)
```

### After

```text
Treasury Taproot:
  Internal key: Y_51
  Script tree:
    Leaf 1 (depth 0): <federation_timeout> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG

Signing cascade: Quorum51 → Federation
Config keys: y_51, y_fed
```

## Changes by File

### `src/bitcoin/taproot.rs`

- `treasury_spend_info` signature drops the `y_67` parameter. New body: a single leaf at depth 0 — `<federation_timeout> OP_CSV OP_DROP <Y_federation> OP_CHECKSIG` — finalized under `y_51`.
- Delete `build_checksig_script` (its only caller was the removed `<Y_67> OP_CHECKSIG` leaf).
- Update the three inline tests (`test_treasury_spend_info_deterministic`, `test_treasury_vs_pegin_different`, `test_treasury_script_leaves`) to match the new signature and single-leaf tree.

### `src/epoch/traits.rs`, `src/cardano/treasury_datum.rs`

- Remove `y_67` field from `TreasuryUtxo` and `TreasuryConfig`.
- Update the two `TreasuryUtxo` constructions in `treasury_datum.rs` (`treasury_from_btc_tx_bytes`, `parse_treasury_datum`) and the test `demo_config`.
- No datum decoding changes — `y_67` was never in the CBOR.

### `src/cardano/blockfrost_chain.rs`, `src/epoch/mocks.rs`

- Drop the `y_67` field from both `TreasuryUtxo` constructions (pre-DKG bootstrap + post-DKG branch).

### `src/epoch/fixture.rs`

- Remove the `y_67` field, the hardcoded `[0x67u8; 32]` seed construction, and the `y_67_seed_hex` config read.

### `src/epoch/state.rs`, `src/epoch/signing.rs`, `src/epoch/machine.rs`

- Remove the `CascadeLevel::Quorum67` variant.
- The `BuildTm → Sign` transition in `machine.rs` defaults to `CascadeLevel::Quorum51`.
- Remove `EpochConfig::quorum67_timeout`.
- Update the `sign_phase` docstring at `signing.rs:27` — cascade TODO now reads "Quorum51 → Federation".
- `machine.rs` call sites (`treasury_input_spend`, `change_spend`, the pegin fallback at `:350`) drop the `y_67` arg.

### `src/config.rs`, `heimdall.toml`

- Remove `quorum67_timeout_secs` from `ProtocolConfig`.
- Remove `y_67_seed_hex` from `BitcoinConfig`.
- Remove the corresponding lines from `heimdall.toml`.
- Config compat: `config.rs` does not use `#[serde(deny_unknown_fields)]`, so stale `y_67_seed_hex` / `quorum67_timeout_secs` in existing TOML files will be silently ignored rather than failing. Operators should prune them, but nothing breaks if they don't.

### `src/main.rs`

- Remove `y_67_seed_hex` read, `y_67` construction, third arg to `treasury_spend_info`.
- Update the demo treasury-address printout from `"Y_fed=Y_67=Y_51=FROST"` to `"Y_fed=Y_51=FROST"`.

### `src/bitcoin/tm_builder.rs`

- Two test call sites drop their `y_67 = xonly_from_seed([2u8; 32])` placeholders and the `treasury_spend_info` arg count.

### `Specification.md`

- Rewrite the cascade section (§6 and the `CascadeLevel` enum at line 306) as two-mode.
- Update the §24–33 treasury Taproot example to show the single-leaf tree.

### `DecisionsLog.md`

- Append a dated entry: "2026-04-22 — removed 67% quorum tier to match bifrost spec (signing cascade is 51% → federation)."

## Testing

All existing tests should still pass after mechanical updates.

- **`taproot.rs` inline tests:** updated signatures, single-leaf assertion replacing the two-leaf checks. `test_treasury_vs_pegin_different` still yields distinct addresses because the treasury leaf uses `Y_federation` as the leaf key while the peg-in leaf uses `depositor_xonly` — different scripts.
- **`treasury_datum.rs` tests** (`parse_preprod_btc_tx`, `roundtrip_through_cbor`): `demo_config()` drops the `y_67` construction. `PREPROD_BTC_TX_HEX` is unchanged (the datum doesn't encode keys).
- **`tm_builder.rs` tests:** drop `y_67` placeholders from `treasury_spend_info` calls. Sighashes and vsize assertions are unaffected — key-path spend witness structure is independent of merkle tree shape.
- **`config.rs` tests** (`test_epoch_config_from_protocol`, `test_demo_default_matches_toml_defaults`): drop `quorum67_timeout` assertions; keep `quorum51_timeout` and `federation_timeout`.
- **`fixture.rs` and `mocks.rs`:** mechanical edits to keep them compiling.

**Manual verification:** `cargo build`, `cargo test`, and the demo binary (`cargo run -- print-treasury-address` with the simplified TOML) should all succeed.

**No new tests.** The scope is pure deletion; existing coverage already exercises every touched code path.

## Known Impact

### Treasury address changes

Removing the `Y_67` leaf changes the merkle root → the Taproot tweak → the treasury output key → the on-chain treasury address. Any BTC held at the current preprod treasury address is stranded under the new derivation.

Deployment options (not part of this refactor):

- Treat preprod state as reset and re-fund the new treasury address.
- Do a one-off sweep from the old address to the new one under the existing `Y_51 = Y_fed` key-path (holds because bootstrap sets internal key = federation), then deploy the refactored code.

### Config compatibility

Existing `heimdall.toml` files with `y_67_seed_hex` and `quorum67_timeout_secs` become silent no-ops (serde ignores unknown fields). Operators should prune them but nothing breaks.

## Non-Goals / Deferred

- Implementing the actual 51%→federation failover logic in `sign_phase`.
- Collapsing the `CascadeLevel` enum (would be premature until the cascade is real).
- Updating `Design.md` narrative.
- Automated migration tooling for old TOML files.
