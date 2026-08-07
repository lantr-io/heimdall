# Simplified Peg-In Taproot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current 2-leaf peg-in Taproot derivation (internal key `Y_51` + federation-CSV leaf + depositor-refund-by-pkh leaf) and its 20-byte-PKH OP_RETURN beacon with the demo-simplified form: internal key `Y_federation`, a single tapleaf `<refund_timeout> OP_CSV OP_DROP <depositor_xonly_pubkey> OP_CHECKSIG`, and a 32-byte x-only beacon.

**Architecture:** The on-chain peg-in Taproot spec lives in `../ft-bifrost-bridge/documentation/demo_simplifications.md`. Heimdall reconstructs this address per-depositor from (a) the constant federation key `Y_fed` carried on the treasury oracle, (b) the depositor's x-only pubkey recovered from an OP_RETURN beacon on the deposit tx, and (c) the protocol-parameterized refund timeout (720 blocks per demo). The parser then locates the unique BTC output paying to that reconstructed address. Changes are confined to `taproot.rs` (script derivation), `pegin_datum.rs` (datum + beacon parser), the call site in `machine.rs`, and the config default.

**Tech Stack:** Rust, `bitcoin` crate 0.32 (Taproot, BIP-341), `pallas-primitives` (Plutus datum decode).

**Out of scope:** Treasury Taproot simplification (same doc also simplifies the treasury, but the user's request is limited to peg-in). The `tm_builder` TODO at `src/epoch/machine.rs:347` — peg-in inputs in the TM tx still reuse `treasury_spend_info` rather than the new `pegin_spend_info`; that becomes a follow-up plan once treasury simplification is in.

---

## File Structure

- **`src/bitcoin/taproot.rs`** — `pegin_spend_info()` becomes a one-leaf tree finalized under `Y_fed`. The unused `build_depositor_refund_script` helper is removed; a new `build_xonly_refund_script` replaces it. Existing `treasury_spend_info` is untouched.
- **`src/cardano/pegin_datum.rs`** — `ParsedPegIn.depositor_pkh: [u8;20]` becomes `depositor_xonly_pubkey_pubkey: [u8;32]`. `parse_beacon` expects a 37-byte scriptPubKey with push-35. `parse_pegin_request` drops the `y_51` and `federation_timeout` parameters; call signature is `(req, y_fed, refund_timeout)`. Module docstring updated.
- **`src/epoch/machine.rs`** — `collect_pegins_phase` call site drops `treasury.y_51` and `fed_timeout`.
- **`heimdall.toml`** — `pegin_refund_timeout_blocks` value set to `720` (code defaults stay at `4320` so production spec remains the default; demo just overrides in TOML).

---

## Task 1: Simplify `pegin_spend_info` to single-leaf Taproot under Y_fed

**Files:**
- Modify: `src/bitcoin/taproot.rs`
- Test: `src/bitcoin/taproot.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Replace the depositor refund script builder**

In `src/bitcoin/taproot.rs`, remove `build_depositor_refund_script` and replace it with a 32-byte-xonly variant. The new script is:
`<refund_timeout> OP_CSV OP_DROP <depositor_xonly_pubkey> OP_CHECKSIG`.

This is structurally identical to the existing `build_csv_checksig_script`, so consolidate: callers pass an `UntweakedPublicKey` for both federation and depositor refund. Delete `build_depositor_refund_script` entirely.

```rust
// In src/bitcoin/taproot.rs — keep build_csv_checksig_script as-is.
// Delete build_depositor_refund_script(pubkey_hash: [u8; 20], timeout: u16).
```

- [ ] **Step 2: Rewrite the `pegin_spend_info` signature + body**

```rust
/// Build the peg-in `TaprootSpendInfo` for a specific depositor — demo
/// simplification (internal key = Y_federation, single tapleaf).
///
/// ```text
/// Internal key: Y_federation (key-path — federation sweeps into treasury)
/// Script tree:
///   Leaf 1 (depth 0): <refund_timeout> OP_CSV OP_DROP <depositor_xonly_pubkey> OP_CHECKSIG
/// ```
pub fn pegin_spend_info(
    secp: &Secp256k1<All>,
    y_federation: UntweakedPublicKey,
    depositor_xonly_pubkey: UntweakedPublicKey,
    refund_timeout: u16,
) -> TaprootSpendInfo {
    let leaf = build_csv_checksig_script(refund_timeout, depositor_xonly_pubkey);
    bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(0, leaf)
        .expect("valid leaf")
        .finalize(secp, y_federation)
        .expect("finalizable tree")
}
```

Note: a single-leaf tree is added at depth 0 (per `TaprootBuilder::add_leaf` rules — the root is a single leaf, not depth 1). If `add_leaf(0, ...)` is rejected by the API, use `add_leaf(1, ...)` with the same leaf added twice (dummy) — but verify first with the bitcoin crate docs; 0 is correct for single-leaf trees in bitcoin 0.32.

- [ ] **Step 3: Update the inline tests in `taproot.rs` to match the new signature**

Replace `test_pegin_spend_info_deterministic`, `test_treasury_vs_pegin_different`, and `test_pegin_script_leaves`:

```rust
#[test]
fn test_pegin_spend_info_deterministic() {
    let secp = Secp256k1::new();
    let y_fed = xonly_from_seed([3u8; 32]);
    let depositor = xonly_from_seed([0xAB; 32]);

    let si1 = pegin_spend_info(&secp, y_fed, depositor, 720);
    let si2 = pegin_spend_info(&secp, y_fed, depositor, 720);

    assert_eq!(si1.output_key(), si2.output_key());
    assert_eq!(si1.merkle_root(), si2.merkle_root());
}

#[test]
fn test_treasury_vs_pegin_different() {
    let secp = Secp256k1::new();
    let (y_51, y_67, y_fed) = test_keys();
    let depositor = xonly_from_seed([0xAB; 32]);

    let treasury = treasury_spend_info(&secp, y_51, y_67, y_fed, 144);
    let pegin = pegin_spend_info(&secp, y_fed, depositor, 720);

    assert_ne!(treasury.output_key(), pegin.output_key());
}

#[test]
fn test_pegin_script_leaves() {
    let secp = Secp256k1::new();
    let y_fed = xonly_from_seed([3u8; 32]);
    let depositor = xonly_from_seed([0xAB; 32]);
    let si = pegin_spend_info(&secp, y_fed, depositor, 720);

    let expected_leaf = build_csv_checksig_script(720, depositor);
    let script_map = si.script_map();
    assert!(
        script_map.keys().any(|(s, _)| *s == expected_leaf),
        "csv+checksig leaf not found in script map"
    );
    assert_eq!(script_map.len(), 1, "expected exactly 1 script leaf");
}
```

- [ ] **Step 4: Run the taproot tests and verify they pass**

Run: `cargo test --lib bitcoin::taproot::tests -- --nocapture`
Expected: all 4 `test_*` functions pass.

Note: the rest of the crate will not compile yet — `pegin_datum.rs` and `machine.rs` still call the old 6-arg signature. That's fixed in Tasks 2–4; for this step, limit the test invocation to the single module so the cargo harness succeeds against only `taproot.rs`. If cargo refuses to compile the whole crate, defer this step to after Task 4 and instead verify this task by reading the `taproot.rs` diff.

- [ ] **Step 5: Commit**

```bash
git add src/bitcoin/taproot.rs
git commit -m "refactor: simplify pegin_spend_info to single-leaf tree under Y_fed"
```

---

## Task 2: Rewrite OP_RETURN beacon parsing for 32-byte x-only pubkey

**Files:**
- Modify: `src/cardano/pegin_datum.rs` (constants + `parse_beacon` + helpers in `#[cfg(test)]`)

- [ ] **Step 1: Update the beacon constants**

In `src/cardano/pegin_datum.rs` lines 35–40, replace:

```rust
/// 3-byte beacon marker `"BFR"` that prefixes the OP_RETURN payload on
/// every Bifrost peg-in tx.
const BEACON_MARKER: &[u8; 3] = b"BFR";

/// Full scriptPubKey length of the beacon OP_RETURN:
/// OP_RETURN (1) + push-35 (1) + "BFR" (3) + xonly (32) = 37 bytes.
const BEACON_SCRIPT_LEN: usize = 37;

/// Push-opcode value matching a 35-byte payload ("BFR" || xonly).
const BEACON_PUSH_OPCODE: u8 = 0x23; // OP_PUSHBYTES_35
```

- [ ] **Step 2: Rewrite `parse_beacon` to return `[u8; 32]`**

Replace lines 144–163:

```rust
/// Scan a BTC tx for the Bifrost beacon OP_RETURN output and return
/// the 32-byte depositor x-only pubkey. Exactly one beacon must exist.
///
/// ScriptPubKey shape (37 bytes):
/// ```text
/// 6a 23 42 46 52 <32-byte-xonly>
/// ^^ ^^ ^^^^^^^^
/// |  |  "BFR"
/// |  push-35 (0x23)
/// OP_RETURN
/// ```
pub fn parse_beacon(tx: &Transaction) -> Result<[u8; 32], ParseError> {
    let mut found: Option<[u8; 32]> = None;
    for out in &tx.output {
        let bytes = out.script_pubkey.as_bytes();
        if bytes.len() != BEACON_SCRIPT_LEN {
            continue;
        }
        if bytes[0] != 0x6a || bytes[1] != BEACON_PUSH_OPCODE || &bytes[2..5] != BEACON_MARKER {
            continue;
        }
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&bytes[5..37]);
        if found.is_some() {
            return Err(ParseError::AmbiguousBeacon);
        }
        found = Some(xonly);
    }
    found.ok_or(ParseError::NoBeacon)
}
```

- [ ] **Step 3: Update the test helpers `beacon_spk` and `depositor_keys`**

In the `#[cfg(test)] mod tests` block, replace `depositor_keys` (lines 257–266) and `beacon_spk` (lines 286–294):

```rust
fn depositor_keys() -> ([u8; 32], [u8; 32]) {
    // (x-only pubkey bytes, same bytes — the second tuple slot
    // keeps the existing test shape for minimal test churn.)
    let seed = [0xABu8; 32];
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&seed).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let xonly_bytes = kp.x_only_public_key().0.serialize();
    (xonly_bytes, xonly_bytes)
}

fn beacon_spk(xonly: [u8; 32]) -> ScriptBuf {
    let mut payload = Vec::with_capacity(35);
    payload.extend_from_slice(BEACON_MARKER);
    payload.extend_from_slice(&xonly);
    script::Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(<&bitcoin::script::PushBytes>::try_from(payload.as_slice()).unwrap())
        .into_script()
}
```

Remove the now-unused `use bitcoin::hashes::{hash160, Hash as _};` line — the xonly form doesn't hash.

- [ ] **Step 4: Update the direct beacon tests that use the old shape**

Update `beacon_wrong_length` (lines 538–558) to build a short beacon matching the new expected 37-byte length:

```rust
#[test]
fn beacon_wrong_length() {
    // OP_RETURN push-3 "BFR" — no xonly payload; total 5 bytes.
    let short_beacon = script::Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(<&bitcoin::script::PushBytes>::try_from(&b"BFR"[..]).unwrap())
        .into_script();
    let (_, xonly) = depositor_keys();
    let tx = build_tx_with_outputs(vec![
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: pegin_spk(xonly),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: short_beacon,
        },
    ]);
    let req = make_request(build_datum_bytes(serialize(&tx)));
    assert!(matches!(parse(&req).unwrap_err(), ParseError::NoBeacon));
}
```

Update `beacon_wrong_prefix` (lines 513–536) so the wrong-prefix script is still 37 bytes (otherwise the length filter would pass it through first):

```rust
#[test]
fn beacon_wrong_prefix() {
    // OP_RETURN push-35 "FOO" + xonly — not "BFR".
    let (_, xonly) = depositor_keys();
    let mut payload = Vec::with_capacity(35);
    payload.extend_from_slice(b"FOO");
    payload.extend_from_slice(&xonly);
    let wrong_beacon = script::Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(<&bitcoin::script::PushBytes>::try_from(payload.as_slice()).unwrap())
        .into_script();
    let tx = build_tx_with_outputs(vec![
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: pegin_spk(xonly),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: wrong_beacon,
        },
    ]);
    let req = make_request(build_datum_bytes(serialize(&tx)));
    assert!(matches!(parse(&req).unwrap_err(), ParseError::NoBeacon));
}
```

- [ ] **Step 5: Run `parse_beacon` direct tests**

Run: `cargo test --lib cardano::pegin_datum::tests::beacon -- --nocapture`
Expected: `beacon_parser_direct_happy` and `beacon_parser_direct_missing` pass.

As with Task 1, the full crate won't compile yet. If cargo rejects a filtered test run, defer verification to Task 4.

- [ ] **Step 6: Commit**

```bash
git add src/cardano/pegin_datum.rs
git commit -m "refactor: OP_RETURN beacon carries 32-byte xonly pubkey instead of 20-byte pkh"
```

---

## Task 3: Update `ParsedPegIn` + `parse_pegin_request` for simplified script

**Files:**
- Modify: `src/cardano/pegin_datum.rs`

- [ ] **Step 1: Rename `depositor_pkh` field and update module docstring**

In `src/cardano/pegin_datum.rs`:

Module header lines 12–19 — replace the three-bullet description of the Taproot reconstruction. New text:

```rust
//! 2. The BTC tx has exactly one `OP_RETURN "BFR" || depositor_xonly_pubkey`
//!    beacon output (spec § Peg-in deposit, demo simplification). This
//!    is how watchtowers and SPOs recover the depositor's x-only pubkey.
//! 3. Using `Y_fed` from the on-chain treasury oracle and the
//!    `refund_timeout` protocol parameter (720 blocks per demo), we
//!    reconstruct the expected peg-in Taproot address Q via
//!    `pegin_spend_info`.
```

Lines 45–56 — rename the field in `ParsedPegIn`:

```rust
/// 32-byte x-only pubkey of the depositor, recovered from the
/// OP_RETURN beacon. Needed later to reconstruct the peg-in
/// script tree for FROST-signing the TM input.
pub depositor_xonly_pubkey: [u8; 32],
```

Line 71–74 — update the `NoPegInOutput` doc:

```rust
    /// No tx output pays to the spec-derived peg-in Taproot address
    /// for the (Y_fed, refund_timeout, depositor_xonly_pubkey) tuple. Either
    /// the depositor used a stale Y_fed, or the attacker fabricated
    /// the PegInRequest over an unrelated BTC tx.
    NoPegInOutput,
```

- [ ] **Step 2: Rewrite `parse_pegin_request` with the new signature**

Replace lines 165–226 with:

```rust
/// Parse and validate a raw Cardano peg-in request.
///
/// `y_fed` comes from the current on-chain treasury oracle;
/// `refund_timeout` is a protocol parameter (720 blocks per demo,
/// overridable per-network).
pub fn parse_pegin_request(
    req: &CardanoPegInRequest,
    y_fed: UntweakedPublicKey,
    refund_timeout: u16,
) -> Result<ParsedPegIn, ParseError> {
    // 1. Decode the Cardano datum: we only trust field[1] (raw tx).
    let plutus: PlutusData = pallas_codec::minicbor::decode(&req.datum_cbor)
        .map_err(|e| ParseError::BadDatumShape(format!("cbor: {e}")))?;
    let btc_tx_bytes = extract_raw_btc_tx(&plutus)?;

    // 2. Deserialize the referenced BTC tx.
    let btc_tx: Transaction = deserialize(&btc_tx_bytes)
        .map_err(|e| ParseError::InvalidBtcTx(e.to_string()))?;
    let btc_txid = btc_tx.compute_txid();

    // 3. Recover the depositor x-only pubkey from the OP_RETURN beacon.
    let depositor_xonly_pubkey_bytes = parse_beacon(&btc_tx)?;
    let depositor_xonly_pubkey = UntweakedPublicKey::from_slice(&depositor_xonly_pubkey_bytes)
        .map_err(|e| ParseError::BadDatumShape(format!("beacon xonly: {e}")))?;

    // 4. Reconstruct the spec-defined peg-in Taproot address and find
    //    the unique output paying to it.
    let secp = Secp256k1::new();
    let spend_info = pegin_spend_info(&secp, y_fed, depositor_xonly_pubkey, refund_timeout);
    let expected_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    let mut matches = btc_tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, out)| out.script_pubkey == expected_spk);

    let (vout, txout) = matches.next().ok_or(ParseError::NoPegInOutput)?;
    if matches.next().is_some() {
        return Err(ParseError::AmbiguousPegInOutput);
    }

    if txout.value < DUST_THRESHOLD {
        return Err(ParseError::DustOutput);
    }

    Ok(ParsedPegIn {
        btc_tx: btc_tx.clone(),
        btc_txid,
        btc_vout: vout as u32,
        value: txout.value,
        cardano_utxo: req.cardano_utxo.clone(),
        depositor_xonly_pubkey: depositor_xonly_pubkey_bytes,
    })
}
```

Note: an invalid 32-byte slice (not a valid x-only pubkey point) is reported as `BadDatumShape` — the beacon payload is attacker-controlled, so we shouldn't panic. This is a new failure mode; no separate error variant is needed because `BadDatumShape` already carries a string description.

- [ ] **Step 3: Update test helpers and fixtures for the new signature**

Replace `FED_TIMEOUT`, `REFUND_TIMEOUT`, `test_keys`, `pegin_spk`, `build_pegin_tx`, and `parse` at the top of the `#[cfg(test)] mod tests` block (around lines 247–378):

```rust
const REFUND_TIMEOUT: u16 = 720;

fn xonly_from_seed(seed: [u8; 32]) -> UntweakedPublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&seed).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    kp.x_only_public_key().0
}

fn test_y_fed() -> UntweakedPublicKey {
    xonly_from_seed([0xFEu8; 32])
}

// depositor_keys() as updated in Task 2 — returns (xonly, xonly).

fn pegin_spk(depositor_xonly_pubkey_bytes: [u8; 32]) -> ScriptBuf {
    let secp = Secp256k1::new();
    let depositor =
        UntweakedPublicKey::from_slice(&depositor_xonly_pubkey_bytes).expect("valid xonly");
    let si = pegin_spend_info(&secp, test_y_fed(), depositor, REFUND_TIMEOUT);
    ScriptBuf::new_p2tr_tweaked(si.output_key())
}

/// Build a peg-in BTC tx with: 1 input (dummy P2WPKH), 1 P2TR peg-in
/// output at `amount`, 1 OP_RETURN beacon, 1 change output.
fn build_pegin_tx(depositor_xonly_pubkey: [u8; 32], amount: Amount) -> Transaction {
    let change_script =
        ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x33; 20]));
    build_tx_with_outputs(vec![
        TxOut {
            value: amount,
            script_pubkey: pegin_spk(depositor_xonly_pubkey),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: beacon_spk(depositor_xonly_pubkey),
        },
        TxOut {
            value: Amount::from_sat(500_000),
            script_pubkey: change_script,
        },
    ])
}

fn parse(req: &CardanoPegInRequest) -> Result<ParsedPegIn, ParseError> {
    parse_pegin_request(req, test_y_fed(), REFUND_TIMEOUT)
}
```

- [ ] **Step 4: Fix the remaining tests that still reference the old API**

Update `parse_happy_path` (around line 382) — change `parsed.depositor_pkh` → `parsed.depositor_xonly_pubkey`.

Update `parse_happy_path_pegin_not_first_output` — rename the local `pkh` → `xonly`.

Update `beacon_pkh_does_not_match_taproot` (around line 583) — rename the test to `beacon_xonly_does_not_match_taproot`, use two different x-only pubkeys instead of two PKHs:

```rust
#[test]
fn beacon_xonly_does_not_match_taproot() {
    // Beacon says xonly_A, but the P2TR output was derived from xonly_B.
    let (_, xonly_a) = depositor_keys();
    let xonly_b = xonly_from_seed([0xCCu8; 32]).serialize();
    let tx = build_tx_with_outputs(vec![
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: pegin_spk(xonly_b), // wrong depositor
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: beacon_spk(xonly_a),
        },
    ]);
    let req = make_request(build_datum_bytes(serialize(&tx)));
    assert!(matches!(parse(&req).unwrap_err(), ParseError::NoPegInOutput));
}
```

Replace `no_pegin_output_wrong_y51` with `no_pegin_output_wrong_y_fed` (around line 613):

```rust
#[test]
fn no_pegin_output_wrong_y_fed() {
    // Build the peg-in address from a *different* Y_fed than the
    // parser will use. parse() uses test_y_fed(); we use a stale one here.
    let (_, xonly) = depositor_keys();
    let stale_y_fed = xonly_from_seed([0x99u8; 32]);
    let secp = Secp256k1::new();
    let depositor = UntweakedPublicKey::from_slice(&xonly).unwrap();
    let stale_si = pegin_spend_info(&secp, stale_y_fed, depositor, REFUND_TIMEOUT);
    let stale_spk = ScriptBuf::new_p2tr_tweaked(stale_si.output_key());

    let tx = build_tx_with_outputs(vec![
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: stale_spk,
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: beacon_spk(xonly),
        },
    ]);
    let req = make_request(build_datum_bytes(serialize(&tx)));
    assert!(matches!(parse(&req).unwrap_err(), ParseError::NoPegInOutput));
}
```

All remaining tests (`parse_happy_path_pegin_not_first_output`, `datum_*`, `btc_tx_garbage`, `no_beacon_output`, `beacon_ambiguous`, `no_pegin_output_only_beacon`, `ambiguous_pegin_outputs`, `dust_output`) only need `pkh` → `xonly` variable renaming; their logic does not depend on the old field shape. Walk through each and fix cascading compiler errors in one pass.

- [ ] **Step 5: Add one new test for invalid-xonly beacon payload**

```rust
#[test]
fn beacon_xonly_not_on_curve() {
    // Beacon payload decodes but is not a valid x-only point.
    let invalid_xonly = [0xFFu8; 32]; // definitely not a valid x-coord
    let tx = build_tx_with_outputs(vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: beacon_spk(invalid_xonly),
    }]);
    let req = make_request(build_datum_bytes(serialize(&tx)));
    assert!(matches!(parse(&req).unwrap_err(), ParseError::BadDatumShape(_)));
}
```

- [ ] **Step 6: Run the full `pegin_datum` test module**

Run: `cargo test --lib cardano::pegin_datum`
Expected: all tests pass; no warnings about unused `hash160` import.

- [ ] **Step 7: Commit**

```bash
git add src/cardano/pegin_datum.rs
git commit -m "feat: parse peg-in requests against simplified single-leaf Taproot"
```

---

## Task 4: Update the call site in `machine.rs`

**Files:**
- Modify: `src/epoch/machine.rs`

- [ ] **Step 1: Simplify `collect_pegins_phase`**

In `src/epoch/machine.rs` lines 207–268, drop the `fed_timeout` local and pass the trimmed argument list to `parse_pegin_request`:

```rust
/// Poll the Cardano peg-in source over `config.pegin_collection_window`,
/// parsing each observed request against the spec-derived peg-in
/// Taproot for the current Y_fed + refund_timeout + depositor_xonly_pubkey.
/// Parse failures are logged and dropped. The deduped, parsed set is
/// frozen into the next `BuildTm` phase.
async fn collect_pegins_phase(
    chain: &Arc<dyn CardanoChain>,
    pegin_source: &Arc<dyn CardanoPegInSource>,
    clock: &Arc<dyn Clock>,
    config: &EpochConfig,
    epoch: u64,
    roster: Roster,
    group_keys: GroupKeys,
) -> EpochResult<EpochPhase> {
    let me = *group_keys.key_package.identifier();

    // Pull current Y_fed from the on-chain treasury oracle. The
    // peg-in Taproot Q is derived per-depositor inside
    // `parse_pegin_request` using the OP_RETURN beacon xonly pubkey.
    let treasury = chain.query_treasury().await?;
    let refund_timeout = config.pegin_refund_timeout_blocks;

    let deadline = clock.deadline(config.pegin_collection_window);
    let mut accepted: BTreeMap<CardanoOutRef, ParsedPegIn> = BTreeMap::new();

    crate::epoch_log!(
        me, epoch,
        "CollectPegins: polling source for {:?} (poll interval {:?})",
        config.pegin_collection_window, config.pegin_poll_interval
    );

    loop {
        let batch = pegin_source
            .query_pegin_requests(&config.pegin_policy_id)
            .await?;
        for req in batch {
            if accepted.contains_key(&req.cardano_utxo) {
                continue;
            }
            match parse_pegin_request(&req, treasury.y_fed, refund_timeout) {
                Ok(parsed) => {
                    accepted.insert(req.cardano_utxo.clone(), parsed);
                }
                Err(e) => {
                    crate::epoch_log!(
                        me, epoch,
                        "  dropped peg-in {:?}: {}",
                        req.cardano_utxo, e
                    );
                }
            }
        }
        if clock.now() >= deadline {
            break;
        }
        tokio::time::sleep(config.pegin_poll_interval).await;
    }

    let frozen_pegins: Vec<ParsedPegIn> = accepted.into_values().collect();
    crate::epoch_log!(
        me, epoch,
        "  -> froze {} peg-in(s) for BuildTm",
        frozen_pegins.len()
    );

    Ok(EpochPhase::BuildTm {
        epoch,
        roster,
        group_keys,
        frozen_pegins,
    })
}
```

No changes needed to `build_tm_phase` — it still uses `treasury_spend_info` as a placeholder for peg-in inputs (see the existing `TODO` comment at line 347). That substitution is out of scope for this plan.

- [ ] **Step 2: Build the whole crate**

Run: `cargo build --all-targets`
Expected: clean build. If the test binary in `tests/integration_demo.rs` references the old field names, fix them (see Task 5).

- [ ] **Step 3: Run the full unit test suite**

Run: `cargo test --lib`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/epoch/machine.rs
git commit -m "refactor: collect_pegins_phase drops y_51/fed_timeout per simplified peg-in script"
```

---

## Task 5: Set `pegin_refund_timeout_blocks = 720` in `heimdall.toml`

**Files:**
- Modify: `heimdall.toml`
- Modify (if needed): `tests/integration_demo.rs`

Code-level defaults in `src/config.rs` and `src/epoch/state.rs` keep `4320` (production spec). The demo simplification is applied via the TOML file only; any deployment reading `heimdall.toml` picks up `720`.

- [ ] **Step 1: Update `heimdall.toml` value + comment**

In `heimdall.toml` lines 19–21, replace:

```toml
# Depositor refund timelock in BTC blocks (peg-in Taproot refund leaf).
# Production spec is 4320 (~30 days); demo simplification uses 720 (~5 days).
pegin_refund_timeout_blocks = 720
```

- [ ] **Step 2: Fix integration test if it references the old field name**

Run: `rg -n 'depositor_pkh|pegin_spend_info\s*\(' tests`
Expected: no hits. If any surface, rename `depositor_pkh` → `depositor_xonly_pubkey` and update call-sites to the new 4-arg `pegin_spend_info(secp, y_fed, depositor_xonly_pubkey, refund_timeout)`.

- [ ] **Step 3: Run the full test suite**

Run: `cargo test`
Expected: all unit tests and integration tests pass.

- [ ] **Step 4: Commit**

```bash
git add heimdall.toml tests
git commit -m "chore: pin demo peg-in refund timeout to 720 blocks in heimdall.toml"
```

---

## Final verification

- [ ] **Step 1: Confirm the full crate builds warning-free**

Run: `cargo build --all-targets 2>&1 | grep -i warning`
Expected: no output (or only unrelated warnings present before this change).

- [ ] **Step 2: Confirm `cargo clippy` is green for the touched modules**

Run: `cargo clippy -- -D warnings` (or the project's configured clippy command)
Expected: no new warnings from `src/bitcoin/taproot.rs`, `src/cardano/pegin_datum.rs`, or `src/epoch/machine.rs`.

- [ ] **Step 3: Manual sanity-check the derived address against the demo spec**

Write a one-off scratch assertion (in a test or `main` example) that uses the exact constants from `demo_simplifications.md`:

- `Y_fed_hex = "02b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854"` — this is a 33-byte compressed secp256k1 point; drop the leading byte (02/03) to get the 32-byte x-only form.
- Any depositor xonly (e.g. the demo fixture's).
- `refund_timeout = 720`.

Print `pegin_spend_info(...).output_key()` and the resulting `bech32m` testnet address. This is a sanity check that the derivation output is a well-formed Taproot address; the exact value cannot be cross-checked against the doc (the doc doesn't publish a per-depositor peg-in address), so just eyeball it.

- [ ] **Step 4: Report done**

Message the user: "Peg-in parser and Taproot derivation updated to the demo-simplified form. See commits on the current branch."

---

## Follow-up (not in this plan)

- Simplify the treasury Taproot per `demo_simplifications.md` (just `Y_fed`, no script tree). That requires updating `treasury_spend_info` + the `TreasuryUtxo` oracle shape (`y_51`, `y_67` become vestigial), the mock/blockfrost chain adapters, and the fixture. Significant cross-cutting surface — separate plan.
- Replace `treasury_spend_info(...)` with `pegin_spend_info(...)` at `src/epoch/machine.rs:347` so the TM builder actually spends peg-in inputs via the correct Taproot. Blocked on real fBTC minting integration; add when that work lands.
