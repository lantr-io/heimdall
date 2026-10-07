# Federation Cycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the federation complete the spec's signing cascade without an operator: when the roster cannot sign and the treasury head has aged past `federation_csv_blocks`, the federation builds, signs and posts a full batch-carrying Treasury Movement, and rotates a dead roster's key under `[UY-5]`.

**Architecture:** The Bitcoin-layer primitives already exist and are tested (`build_tm`, `federation_leaf_spend`, `sign_tm_federation_leaf`, `federation::spend::frost_sign`, `update_y::UpdateYAuthorizer::Federation`). What is missing is wiring: the federation path is driven only by a CLI that passes empty peg-in/peg-out lists, spends only input 0, never posts to Cardano, and is never reached by the daemon. Each task below closes one of those, smallest-blast-radius first, so preprod can be unfrozen before the daemon work lands.

**Tech Stack:** Rust; `frost-secp256k1-tr`; `bitcoin` crate (Taproot/BIP-341 script path); Blockfrost + Pallas Cardano sources; whisky-pallas tx builder.

**Spec:** `../ft-bifrost-bridge/documentation/technical_documentation.md` (rev 5.6). Load-bearing clauses cited inline per task.

## Global Constraints

- `federation_csv_blocks = 144` on this deployment (Config `params[7]`, and `/var/lib/heimdall-fed1/heimdall.toml:26`). Never hardcode it; read it from the chain. It is a `u16` end to end since WI-069.
- The federation on this deployment is **2-of-3** FROST, group key `8b4e2c88686bb5aa201171cb9c6e174dba6dfd48862c42b1bf0972e2c789e957`, shares in `/var/lib/heimdall-fed{1,2,3}/federation-key.json`.
- `[BTC-1]` (spec `:1576`): every transaction that spends the treasury outpoint MUST carry a conforming BTMR1 commitment output.
- `[BTC-2]` (spec `:1578`): every transaction that spends the treasury outpoint MUST pay the new treasury at output 0.
- `[CTM-26]`: exactly one BTMR1 output in every TM.
- The federation variant differs from the key-path variant in **only** two things (spec `:1740`, `:2254`): `nSequence` (CSV-enabling) and witness structure (script path). The batch itself is identical, computed by exact reconstruction (Model A′) so every member reaches one sighash.
- `[UY-5]` (spec `:2935`, rev 5.5): the Update-Y federation branch authorizes by a BIP340 signature under the Config's `y_federation` alone. **No deadness proof, no timeout, no sweep evidence.** It may name ANY key ([UY-6] withdrawn).
- Federation co-authority is a standing power, not an emergency fallback (spec `:3320`).
- Every FROST operation must support identifiable abort.
- Commit messages: 1, max 2 paragraphs; no co-author or tool-attribution trailers.

## Live state, re-verified 2026-10-06 14:50 UTC

Eleven days after the plan was written. One fact changed and it removes an option.

| | 2026-09-26 | 2026-10-06 |
|---|---|---|
| Bridge epoch | 1559 | **1569** (10 virtual epochs, zero movement) |
| Treasury head | `cefb913d…:0`, 576107 sat | **unchanged**, still "free to move" |
| Datum key | `46f4e530…`, 6 of 6 | **unchanged** |
| adanorthpool (share holder) | up 122 ms | **DOWN / unreachable** |
| xstakepool (share holder) | up 55 ms, dkg 1558 | up 31 ms, dkg 1558 – share still held |
| Reachable holders of the 6-of-6 key | 6 of 6 | **5 of 6** |
| Next ceremony threshold | 2 of 5 | 2 of 5 |
| Host disk | 949 MB free (98%) | 1.9 GB free (95%) |
| Dead in-flight TMs | 2, reported DEAD | 2, now auto-ignored past the 129600 s deadline |

**The consequence: the re-registration fallback is gone.** On 2026-09-26 both
departed nodes were up, so re-registering them would have reached 6 of 6 with no
code. adanorthpool is now unreachable, so the sixth share cannot be collected at
all. The federation path in this plan is now the only route that does not require
adanorthpool's operator to bring their node back.

**Gap 4 is confirmed in production.** fed1 logs `machine.rs:1755` verbatim at every
epoch boundary, most recently 2026-10-06 00:01:03:

```
[epoch=1569] no ceremony seat, and none needed: the treasury is held by SPO roster
key 46f4e530…, not by Config y_federation 8b4e2c88…, so this FEDERATION seat has
nothing to sign. Idling until the next epoch boundary
```

spo4 logs `AwaitRotation: treasury_info still names the outgoing key; re-reading in
300s` every 5 minutes, and has done so for 11 days.

**Unchanged and still useful:** the federation is 2-of-3 with all three shares on
the host; all four services (`heimdall-fed{1,2,3}`, `heimdall-spo4`) are active;
`blueprint_digest e8987f35bc2e577f` is identical across the live roster and
xstakepool, so there is one blueprint in play to check against. The head is ~1600
blocks old against a 144-block CSV, so Step 2's depth check will pass.

`git log`: one new commit since the plan, `5c223ac chore: dual-license heimdall
under Apache-2.0 or GPL-3.0-or-later`. Nothing touching the federation path. Local
`main` is level with `origin/main`.

## Corrections to earlier analysis this plan supersedes

Recorded because three prior conclusions were wrong and the plan is smaller as a result.

1. **"No federation-variant TM builder exists" – wrong.** `bitcoin/tm_builder.rs:1147` `federation_leaf_spend` builds it: revealed leaf, control block, `nSequence = csv_blocks`, script-path sighash. `:1227` signs it with a single seed; `federation/spend.rs:85` `frost_sign` signs the same 32 bytes with a t-of-n federation. Tests at `tm_builder.rs:2832` and `:2890` prove the two paths produce byte-identical transactions.
2. **"Update-Y first breaks `query_treasury` on every node" – wrong.** `blockfrost_chain.rs:2653-2665` deliberately offers the superseded key as an internal-key candidate, with the comment "the handoff window, where Cardano has rotated but the BTC has not moved yet". Ordinary rotation always passes through that window. The hazard does not exist.
3. **Phase A/D are not new work items.** `epoch/rotation.rs:63-67` already names this exact gap as **WI-078**, with the same reasoning: "a node that signs whatever `sig_msg` it is handed hands the treasury to whoever asked." Use WI-078, not phase letters.

Also superseded: WI-047 already lets the rotation proceed on a threshold subset of the outgoing roster (`rotation.rs:537`), so a departed member no longer stalls a handoff *in general*. Our deadlock is the degenerate case where the threshold is `6 of 6` and so there is no subset slack at all.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/bitcoin/tm_builder.rs` | Federation script-path spend across **all** inputs, not only input 0 | Modify (`federation_leaf_spend`, new `FederationLeafSpend::sighashes`) |
| `src/federation/tm.rs` | **New.** One function that turns a chain-sourced batch into a federation-variant `UnsignedTm`, shared by the CLI and the daemon so both reach one sighash | Create |
| `src/main.rs` | `federation-spend --batch` / `--post`; daemon Update-Y authorizer selection | Modify (`run_federation_spend` ~`:5070-5237`) |
| `src/epoch/machine.rs` | Replace the permanent federation stand-down with the CSV-age trigger | Modify (`:1745-1770`) |
| `src/cardano/blockfrost_chain.rs` | Choose the Update-Y authorizer by which key this node can sign under | Modify (`:3037`) |
| `src/epoch/rotation.rs` | WI-078: derive the incoming group key from published round-1 commitments | Modify |

---

## Task 0: Unfreeze preprod with the tools that already exist

No code. Run before Task 1 so the bridge is live while the rest lands, and so the
federation cycle is exercised once by hand before it is automated.

**Why this order.** The Bitcoin head `cefb913d…:0` is locked under the Taproot tree
whose internal key is the epoch-1558 key `46f4e530…`. The live 5-node roster holds
shares of `43fe7922…`, not of `46f4e530…`, so it can never take that head's key
path. Only the CSV leaf can move it. And `[BTC-2]` requires output 0 to pay the
**new** treasury, so the datum must already name the new key when the spend is
built. Hence: Update-Y first, federation CSV spend second.

- [ ] **Step 1: Record the starting state**

```bash
ssh root@dev.lantr.io 'cd /var/lib/heimdall-fed1 && \
  /var/lib/heimdall-fed/heimdall show-treasury --config heimdall.toml'
```

Expected, as of 2026-09-26: head `cefb913dd5d6ac7715363b05692797cdc4e4146072c05102d6d0bf0a74f9270a:0` – 576107 sat, "free to move"; `treasury Y_51: 46f4e530…`; 2 in-flight movements both marked DEAD by `[CTM-18]`.

- [ ] **Step 2: Confirm the head is CSV-eligible**

The leaf needs the head `>= 144` blocks deep. `federation-spend` checks this itself
(`check_federation_csv_depth`, `main.rs:5124`) before any signing, so do not
pre-compute it – but read the number it prints. If it refuses, stop: nothing below
can work until the head ages.

- [x] **Step 3: BLOCKING CHECK – is the `[UY-5]` branch actually deployed? → YES, verified 2026-10-06 14:53 UTC**

**Result: `[UY-5]` is deployed. This branch of the plan is live.**

Three independent confirmations:

1. **The validator source has the branch.** `ft-bifrost-bridge/onchain/validators/bitcoin/treasury.ak:220-262` reads `y_federation` from the Config datum and accepts either signer:

   ```
   or {
     crypto.verify_schnorr_signature(in_datum.current_spos_frost_key, msg, signature),
     crypto.verify_schnorr_signature(y_federation, msg, signature),
   }
   ```

   Commented `spec [UY-5] … standing co-authority … [UY-6] WITHDRAWN: the federation MAY name any key`, with a dedicated test `spend_update_y_federation_signed()` at `:913`.

2. **The deployed validator is that source.** `update-y --federation` compiles `treasury_info` locally and prints `treasury policy: 833d11e51e1586923b6fca37bf19b7f1c7e2cc94aa467d7b8fbba0ac`, which equals Config **#10** byte for byte. Note `show-roster`'s `blueprint ✓` does NOT prove this – it only compares peers against each other (`roster_report.rs:493`). The compile-and-match is the real proof.

3. **`y_federation` is at Config #11**, the rev 5.5 `[CFG-6]` shape, and heimdall read it: `y_federation: 8b4e2c88…`.

**Live dry run output** (build-and-print; no `--signature`, no `--submit`):

```
treasury policy:   833d11e51e1586923b6fca37bf19b7f1c7e2cc94aa467d7b8fbba0ac
state UTxO:        34eb66b0f62a10837c6d9ce7ea4c9ad5a1a24b959a256de6501748826f31422c:1
current key:       46f4e53024708b0a5d477db5d4c333cd6d6bb5f83037de0c50458c1af2502349
y_federation:      8b4e2c88686bb5aa201171cb9c6e174dba6dfd48862c42b1bf0972e2c789e957
new key:           c54a5b9b0ce9aecde174c67bda94fe6216a6eb00549d9e9a8f6e74139684acf9
epoch:             1569
sign message:      58b0664c352a2992607225a07ebbee529c0b15d09da5d7d674d2b5bbc6d60101
ERROR: this command signs with the federation key as a SINGLE key, and this node
holds a SHARE of a t-of-n federation key … run `heimdall federation-sign
--message <the sign message printed above>` … and pass the result back as --signature
```

That error is the expected one and confirms Step 4's three-command ceremony is the
right procedure, not a workaround.

**Values for Step 4, read from the chain on 2026-10-06:**

| | |
|---|---|
| Epoch-1569 group key (`--new-key`) | `c54a5b9b0ce9aecde174c67bda94fe6216a6eb00549d9e9a8f6e74139684acf9` |
| Epoch-1569 threshold | **2 of 5** (`dkg-epoch-1569.json`) |
| `--epoch` | `1569` |
| Message to sign | `58b0664c352a2992607225a07ebbee529c0b15d09da5d7d674d2b5bbc6d60101` |
| `treasury_info` state UTxO | `34eb66b0…:1` |
| New treasury BTC address (`--to` for Step 5) | `tb1p0tlksk4mymptwje2myfkz8fukeaqz9vcutehhr4lajpfs08ze5cq84tzeq` |

heimdall already computes that address itself; from the 2026-10-06 00:10:48 log:
"the treasury address it produces is tb1p0tlksk4… and this epoch's key handoff pays
the treasury there".

**The mnemonic constraint.** `update-y` needs a wallet key and `$HEIMDALL_MNEMONIC`
must never appear in argv (visible in `ps`) or leave the host. Run every command
through the unit's own environment file:

```bash
systemd-run --pipe --quiet --wait --collect \
  --property=EnvironmentFile=/var/lib/heimdall-fed/secrets.env \
  --property=User=heimdall \
  --property=WorkingDirectory=/var/lib/heimdall-fed1 \
  /var/lib/heimdall-fed/heimdall update-y … 
```

**Also recorded: the 1569 handoff failed exactly as the plan predicted.** From
spo4's log, 2026-10-06 00:40:49:

```
Update-Y: round 1 is spent (commitments already published): peer poll timed out:
got 4, need 6 – this node's round is spent, so it will not run the ceremony again.
```

<details><summary>Original instructions for this step (superseded by the result above)</summary>

Do not skip. Spec `:3345` records that "the heimdall builders are NOT yet updated
for rev 5.5", and `update-y --help` still describes the signature as checked
"against the **spent datum's** `y_federation`" – the rev 5.4 shape – while
`update_y.rs` reads it from Config per rev 5.5. Preprod's only rotation so far was
the bootstrap one, where `y_fed` was itself the *current* key, so it used `[UY-3]`
(`UpdateYAuthority::Federation` in `rotation.rs` means "the federation key happened
to be the current key", **not** `[UY-5]`). The `[UY-5]` branch may never have run on
this chain.

Confirm the deployed `treasury_info` validator hash matches a blueprint whose
`UpdateY` redeemer carries the federation branch:

```bash
ssh root@dev.lantr.io 'cd /var/lib/heimdall-fed1 && \
  /var/lib/heimdall-fed/heimdall show-config-params --config heimdall.toml'
```

Cross-check the hash against `src/cardano/blueprint.rs`'s embedded blueprint.

**If `[UY-5]` is not deployed, stop and escalate.** As of 2026-10-06 there is no
longer a code-free fallback: adanorthpool is unreachable, so the sixth share of the
6-of-6 key cannot be collected and re-registration can no longer reach threshold.
The options then are, in order of preference:

1. Get adanorthpool's operator to bring the node back up **and** re-register,
   together with xstakepool, before a boundary. Restores 6 of 6 with no code. This
   depends entirely on a third party, which is why it is no longer the plan.
2. Deploy a `treasury_info` with the `[UY-5]` branch, then resume Task 0 Step 4.
   This is a contract deployment on a live bridge: scope it separately.
3. Federation self-send to the **old** address. Keeps `[BTC-1]`/`[BTC-2]` and resets
   the CSV clock, but pays nobody and does not break the deadlock. Only worth doing
   if the head needs to be kept alive for some other reason.

Say which one before acting. None of them is a default.

</details>

**This fallback is moot: `[UY-5]` is deployed. Proceed to Step 4.**

- [x] **Step 4: Rotate the datum key under `[UY-5]` → DONE 2026-10-06 15:13 UTC**

**The `[UY-5]` federation branch worked on a live bridge, first time it has ever run here.**

```
Cardano tx: 28d2297cf03d668f6fe1bb38947db62e696851fe260f850cd11c96af96d4c120
treasury_info datum: 46f4e530…  ->  c54a5b9b0ce9aecde174c67bda94fe6216a6eb00549d9e9a8f6e74139684acf9
authorized by:       y_federation 8b4e2c88… (2-of-3 FROST), NOT the outgoing roster
federation signature: 45a4c3bb212e24ef8cc4d1b7e4166fb3138219a174a79972dcb11d14a5f1ede5
                      4606748e7116ec7bb655c0fc5c618e9b0a2240a243c10b6dc248ad18e6f518a6
```

All three members independently aggregated that identical signature and each logged
"signature aggregated and verified under y_federation". The redeemer went on chain as
`d87a9f 190621 5840<sig> 00` – constructor 1, epoch 1569, signature, Config
ref-input index 0 – with Config `3a02336e…#0` as the reference input, which is the
`[TSY-12]` read of `y_federation`.

**Operational note for next time: the federation ports are held by the daemons.**
`federation-sign` binds each member's own URL (`127.0.0.1:18511/12/13`), and
`heimdall-fed{1,2,3}.service` already listen there. The first attempt failed with
`bind 127.0.0.1:18511: Address in use`. The sequence that works:

```bash
systemctl stop heimdall-fed1 heimdall-fed2 heimdall-fed3
# run federation-sign on all THREE concurrently (the config warns the rounds poll
# every peer, so a 2-of-3 key still needs all three reachable)
systemctl start heimdall-fed1 heimdall-fed2 heimdall-fed3
```

The member URLs are baked into `roster_digest 97aa6dd3fddb3eba`, so they cannot be
moved to free ports without changing the key.

### What Step 4 did and did NOT achieve

**Achieved:** the datum key is no longer frozen. Before, no key could ever be named
again without 6 of 6 of a key with an unreachable holder. Now the datum names a
2-of-5 key the live roster holds, so ordinary rotation resumes at the next boundary
(1569 -> 1570 needs 2 of 5 of `c54a5b9b…`, which is available).

**Not achieved: the BTC did not move, and the peg-outs are still unpaid.** The head
`cefb913d…:0` is locked under `46f4e530…`'s Taproot tree, and rotating the Cardano
datum does not change a Bitcoin scriptPubKey.

What the nodes do now is better than `AwaitRotation` but still blocked. They
correctly detect the situation and build the right transaction (spo4, 15:12:56):

```
the treasury head is locked under 46f4e530…, which is not this epoch's ceremony key
– signing with the persisted epoch-1558 ceremony (6-of-6) and paying the change to
the datum's authorized key c54a5b9b…, which is what hands custody over

treasury movement built: txid 800607e9… ; sweeps 24 deposits, pays 3 peg-outs,
5 outputs. Signing starts
```

Then it stalls at **3 of 6** (4 at best). The arithmetic is unchanged: the 1558 key
is 6-of-6, adanorthpool is down, and xstakepool publishes nothing.

### WI-078, demonstrated in production

xstakepool is **up (58 ms)** and **holds the epoch-1558 share** (`dkg 1558/16`), and
it is polled. It contributes nothing, because it has no seat in the incoming roster –
precisely the gap `rotation.rs:63-67` describes. Were WI-078 implemented, this
signing round would reach 5 of 6. It would still fall one short of adanorthpool, so
WI-078 alone would not have saved this particular case – but it is no longer a
hypothetical, and it is why the 6-of-6 trap closed at all.

**Therefore the federation CSV leaf is now the only way to move the BTC**, and that
needs the posting path. Task 3 is next, as the critical path already said.

<details><summary>Original instructions for Step 4 (kept for the procedure)</summary>

A 2-of-3 threshold federation cannot sign inline: `rotation.rs:432-441` refuses and
names the out-of-band sequence. Three commands, in order.

First, print the message to sign (no `--submit`, no `--signature`). Take
`--new-key` from the current `show-roster` "next ceremony" key, not from this
document – a further DKG may have moved it.

```bash
ssh root@dev.lantr.io 'cd /var/lib/heimdall-fed1 && \
  /var/lib/heimdall-fed/heimdall update-y --config heimdall.toml \
    --federation \
    --new-key 43fe792234b6120d867bc2f48fed3a090d36ce0dd68e43e102bafcdff1c3f83a \
    --epoch 1559'
```

Second, two of the three members sign that 32-byte message together. Both pass the
**same** `--signers` list; it is comma-delimited, not repeated.

```bash
ssh root@dev.lantr.io 'cd /var/lib/heimdall-fed1 && \
  /var/lib/heimdall-fed/heimdall federation-sign --config heimdall.toml \
    --message <32-byte message from the previous command> \
    --signers 1,2'
```

Third, submit with the aggregated 64-byte signature.

```bash
ssh root@dev.lantr.io 'cd /var/lib/heimdall-fed1 && \
  /var/lib/heimdall-fed/heimdall update-y --config heimdall.toml \
    --federation \
    --new-key 43fe792234b6120d867bc2f48fed3a090d36ce0dd68e43e102bafcdff1c3f83a \
    --epoch 1559 \
    --signature <64-byte hex> \
    --submit'
```

Verify with `show-roster` that `current key` is now the one the live roster holds.

</details>

- [ ] **Step 5: Move the treasury with the federation CSV leaf**

`--y51` is the **old** internal key, because it names the tree the *input* is locked
under. `--to` is the **new** treasury address, which is what `[BTC-2]` demands at
output 0.

`show-treasury` prints the target as `expected treasury spk` in hex, but `--to`
wants an address. Convert it, do not hand-assemble it:

```bash
# 51 20 <32-byte x-only output key>  =>  P2TR address
python3 - <<'EOF'
import subprocess
spk = "5120…"          # from show-treasury, AFTER step 4 has landed
assert spk.startswith("5120") and len(spk) == 68
EOF
```

or simpler: re-run `show-treasury` after step 4 – it prints the treasury address
alongside the spk. Use that string verbatim.

Run on the same two federation members with identical arguments (each builds the
transaction itself and they must reach one sighash).

```bash
ssh root@dev.lantr.io 'cd /var/lib/heimdall-fed1 && \
  /var/lib/heimdall-fed/heimdall federation-spend --config heimdall.toml \
    --y51 46f4e53024708b0a5d477db5d4c333cd6d6bb5f83037de0c50458c1af2502349 \
    --to <new treasury address> \
    --signers 1,2'
```

- [ ] **Step 6: BLOCKED – posting the signed bytes to Cardano**

`federation-spend` deliberately does not post (WI-086); it prints `raw tx`. The only
existing posting surface is `sweep-pegins --existing-tm-hex … --broadcast`, and
`sweep-pegins` **requires `--cardano-socket`**. Checked on 2026-09-26: there is no
Cardano node socket on dev.lantr.io (`/tmp/*.socket`, `/run/cardano*`,
`/var/lib/cardano*` are all absent) – the fed nodes run on Blockfrost.

So this step cannot run as things stand, which makes **Task 3 a prerequisite of
finishing Task 0, not a follow-on.** Do not broadcast the Bitcoin transaction until
posting works: an unposted movement leaves the singleton at `cefb913d…:0`, which is
then spent, so every subsequent roster TM is dead on arrival (`[CTM-18]` – exactly
the two DEAD records `show-treasury` already reports).

Two ways forward, pick one and say which: stand up a Cardano node socket on the
host, or do Task 3 first and post with `federation-spend --post`. Task 3 is the
smaller and more durable of the two.

- [ ] **Step 7: Confirm recovery**

```bash
ssh root@dev.lantr.io 'cd /var/lib/heimdall-spo4 && ./heimdall show-roster --config heimdall.toml'
```

Expected: `current key` is the live roster's key; `threshold 2 of 5`; the handoff
line no longer says it cannot complete. The 6 peg-outs are still unpaid – Task 1 is
what pays them.

---

## Task 1: A federation TM that carries the batch

**Files:**
- Create: `src/federation/tm.rs`
- Modify: `src/federation/mod.rs` (add `pub mod tm;`)
- Modify: `src/main.rs:5070-5237` (`run_federation_spend`: add `--batch`)
- Test: `src/federation/tm.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `crate::bitcoin::tm_builder::{build_tm, TreasuryInput, PegInInput, PegOutRequest, TmParams, Freshness, UnsignedTm}`; `crate::epoch::traits::BatchSnapshot`.
- Produces: `pub fn federation_unsigned_tm(treasury: TreasuryInput, pegins: Vec<PegInInput>, pegouts: Vec<PegOutRequest>, new_treasury_spk: ScriptBuf, snapshot: &BatchSnapshot, cpo: &CpoTrie, spi: &SpiTrie) -> Result<UnsignedTm, TmBuildError>` – used by Task 4's daemon trigger.

**Why.** `run_federation_spend` calls `build_tm(treasury, vec![], vec![], …)`
(`main.rs:5162`). Empty lists mean no peg-out is paid and no trie advances, so the
federation can only ever self-send. Spec `:2171` requires the federation to sign
"a Treasury Movement transaction for the **same peg-in/peg-out batch** and treasury
move", and `:2163` that "both quorum levels construct **full** Treasury Movement
transactions".

Peg-outs only in this task. Peg-in **inputs** need Task 2; peg-out **outputs** do
not, because only inputs carry `nSequence` and witnesses.

- [ ] **Step 1: Write the failing test – a federation TM pays the peg-outs**

```rust
#[test]
fn a_federation_tm_pays_the_pegouts_in_the_batch() {
    let (treasury, spk) = treasury_and_spk(576_107);
    let pegouts = vec![make_pegout(0xAA, 100_000), make_pegout(0xBB, 50_000)];
    let unsigned = federation_unsigned_tm(
        treasury, vec![], pegouts, spk.clone(),
        &snapshot(), &empty_cpo(), &empty_spi(),
    )
    .expect("builds");

    // output 0 is the new treasury ([BTC-2]), then one output per peg-out,
    // then exactly one BTMR1 commitment ([CTM-26]).
    assert_eq!(unsigned.tx.output[0].script_pubkey, spk);
    let paid: Vec<u64> = unsigned.tx.output[1..3].iter().map(|o| o.value.to_sat()).collect();
    assert_eq!(paid, vec![100_000, 50_000]);
    assert_eq!(
        unsigned.tx.output.iter()
            .filter(|o| crate::bitcoin::tm_builder::is_btmr1_commitment(o.script_pubkey.as_bytes()))
            .count(),
        1
    );
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p heimdall federation::tm::tests::a_federation_tm_pays_the_pegouts -- --nocapture`
Expected: FAIL, `cannot find function 'federation_unsigned_tm'`.

- [ ] **Step 3: Write the minimal implementation**

```rust
/// One construction of the federation-variant TM body, shared by the CLI and the
/// daemon. The federation variant differs from the key path ONLY in nSequence and
/// witness structure (spec §Treasury Movement, rev 5.6), both of which
/// `federation_leaf_spend` applies afterwards – so the body is built by exactly
/// the same `build_tm` every SPO uses. Sharing it is what makes the two quorum
/// levels reach one sighash.
pub fn federation_unsigned_tm(
    treasury: TreasuryInput,
    pegins: Vec<PegInInput>,
    pegouts: Vec<PegOutRequest>,
    new_treasury_spk: ScriptBuf,
    snapshot: &BatchSnapshot,
    cpo: &CpoTrie,
    spi: &SpiTrie,
) -> Result<UnsignedTm, TmBuildError> {
    build_tm(
        treasury,
        pegins,
        pegouts,
        new_treasury_spk,
        &snapshot.tm_params,
        &Freshness::at(snapshot.now_ms),
        cpo,
        spi,
    )
}
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p heimdall federation::tm`
Expected: PASS.

- [ ] **Step 5: Write the failing test – `--batch` reaches the same bytes on two members**

Exact reconstruction is the whole safety argument: two members that build
different transactions must not mix signing material. Pin it.

```rust
#[test]
fn two_members_building_the_same_batch_reach_one_sighash() {
    let build = || {
        let (treasury, spk) = treasury_and_spk(576_107);
        federation_unsigned_tm(
            treasury, vec![], vec![make_pegout(0xAA, 100_000)], spk,
            &snapshot(), &empty_cpo(), &empty_spi(),
        )
        .unwrap()
    };
    let a = federation_leaf_spend(&build(), y_fed(), 144).unwrap();
    let b = federation_leaf_spend(&build(), y_fed(), 144).unwrap();
    assert_eq!(a.sighash, b.sighash);
    assert_eq!(a.tx.compute_txid(), b.tx.compute_txid());
}
```

- [ ] **Step 6: Run it, watch it fail, then pass**

Run: `cargo test -p heimdall federation::tm`
If it fails on nondeterminism, the cause is a wall-clock or fee read inside the
build. Fix by taking both from `BatchSnapshot` – never from `SystemTime::now()`.

- [ ] **Step 7: Wire `--batch` into the CLI**

Add `#[arg(long)] batch: bool` to the `FederationSpend` subcommand
(`main.rs:300`). When set, source peg-outs from the same
`fetch_pegout_requests` + batch-window path `sweep-pegins` uses, so a federation
member and an SPO freeze the same set; pass them to `federation_unsigned_tm`.
When unset, behaviour is exactly today's (treasury-only), so Task 0 stays valid.

Print the frozen set before signing – member count, each peg-out's id and value –
because co-signers verify by comparing this output out of band.

- [ ] **Step 8: Commit**

```bash
git add src/federation/tm.rs src/federation/mod.rs src/main.rs
git commit -m "feat: the federation TM carries the batch, not only the treasury move

federation-spend built its movement with empty peg-in and peg-out lists, so the one
transaction the federation could make was a self-send: no peg-out was paid and no
trie advanced, while the spec requires both quorum levels to construct full Treasury
Movements over the same frozen batch. The batch construction now lives in one place
that the CLI and the daemon share, because two members that build different bodies
reach different sighashes and would wait for each other forever."
```

---

## Task 2: Federation-spend every input, not only input 0

**Files:**
- Modify: `src/bitcoin/tm_builder.rs:1119-1220` (`FederationLeafSpend`, `federation_leaf_spend`, `finish`)
- Test: `src/bitcoin/tm_builder.rs` tests module

**Interfaces:**
- Consumes: `crate::bitcoin::taproot::{build_csv_checksig_script, pegin_spend_info}`.
- Produces: `FederationLeafSpend { tx, leaves: Vec<ScriptBuf>, control_blocks: Vec<ControlBlock>, sighashes: Vec<[u8;32]> }` and `fn finish(self, signatures: Vec<[u8;64]>) -> Result<Transaction, TmBuildError>`. Task 1's peg-in path and Task 4 depend on these names.

**Why.** `federation_leaf_spend` documents "Only input 0 is federation-spent"
(`:1140`) and sets `nSequence` and the witness on input 0 alone. A batch with
peg-in inputs would go out with inputs `1..n` unwitnessed. Spec `:2171` requires
"CSV timelock on **all relevant inputs**", and `:2255` prices a federation-path
peg-in input at 214 B – "41 + 173 B witness: item count 1 + signature 65 +
revealed leaf ≈41 + control block 66, **the deposit tree having two leaves**". The
peg-in tree's control block differs from the treasury's, so it cannot be reused.

- [ ] **Step 1: Write the failing test – a peg-in input is federation-spent too**

```rust
#[test]
fn every_input_of_a_federation_tm_is_script_path_spent() {
    let tm = build_tm_with_one_pegin();   // treasury input + 1 peg-in input
    let spend = federation_leaf_spend(&tm, y_fed_xonly(), 144).unwrap();

    assert_eq!(spend.sighashes.len(), 2, "one sighash per input");
    // Both inputs must carry the CSV sequence, or OP_CSV fails on the one that does not.
    for input in &spend.tx.input {
        assert_eq!(input.sequence, Sequence::from_height(144));
    }
    // The peg-in tree has TWO leaves, so its control block differs from the treasury's.
    assert_ne!(
        spend.control_blocks[0].serialize(),
        spend.control_blocks[1].serialize()
    );
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p heimdall bitcoin::tm_builder::tests::every_input_of_a_federation_tm`
Expected: FAIL – `sighashes` does not exist; the current struct has a single `sighash`.

- [ ] **Step 3: Write the failing test – the witness lands on every input**

```rust
#[test]
fn finish_witnesses_every_input_it_asked_a_signature_for() {
    let tm = build_tm_with_one_pegin();
    let spend = federation_leaf_spend(&tm, y_fed_xonly(), 144).unwrap();
    let sigs = spend.sighashes.iter().map(|h| sign_with_fed_seed(*h)).collect();
    let signed = spend.finish(sigs).unwrap();
    for (i, input) in signed.input.iter().enumerate() {
        assert_eq!(input.witness.len(), 3, "input {i}: sig, leaf, control block");
    }
}
```

- [ ] **Step 4: Run it and watch it fail**

Expected: FAIL – `finish` takes one `[u8;64]`, not a `Vec`.

- [ ] **Step 5: Implement, then run both to green**

Set `nSequence = Sequence::from_height(csv_blocks)` on every input **before**
hashing any of them, because `nSequence` commits into every input's sighash.
Derive each input's leaf and control block from that input's own
`input_spend_info[i]`: the treasury's tree has one leaf, a peg-in's has two, and
asking the wrong tree for a control block yields `None`, which must be the typed
`FederationLeafSpend` error, not a panic.

Reject a signature-count mismatch in `finish` with a typed error rather than
witnessing a prefix of the inputs.

Run: `cargo test -p heimdall bitcoin::tm_builder`
Expected: PASS, including the pre-existing `:2832` and `:2890` tests. If `:2890`
(the byte-for-byte agreement between the seed and FROST paths) breaks, the two
paths have diverged and that is a stop-and-fix, not a test to update.

- [ ] **Step 6: Commit**

```bash
git add src/bitcoin/tm_builder.rs
git commit -m "fix: a federation movement spends every input, not only the treasury

federation_leaf_spend set nSequence and the script-path witness on input 0 alone, so
the moment the federation carried a batch with peg-in inputs it would publish a
transaction whose remaining inputs were unwitnessed. Each input now reveals the leaf
of its own tree with its own control block - the deposit tree has two leaves where
the treasury's has one, so the blocks are not interchangeable - and every input takes
the CSV sequence before any sighash is computed, since nSequence commits into all of
them."
```

---

## Task 3: Post a federation-signed TM to Cardano

**Files:**
- Modify: `src/main.rs` (`FederationSpend` subcommand + `run_federation_spend`)
- Test: `src/main.rs` tests, or `tests/federation_post.rs`

**Interfaces:**
- Consumes: the Post-TM builder the daemon uses to record an `UnconfirmedTm` (find its call site from `epoch/machine.rs`'s post phase; do not re-implement it).
- Produces: `federation-spend --post` posting the signed bytes as an `UnconfirmedTm` record.

**Why.** `run_federation_spend` ends at `println!("raw tx : …")` with a deliberate
WI-086 note that heimdall does not send it. For a *sweep* that is right. For a
**Treasury Movement** it is not: spec `:160` says the federation-mode transaction
"is posted to Cardano the same way", and the watchtower relays it from the posted
record. Skip the post and the bridge-state singleton never advances, which strands
the peg-outs as unfulfilled even after Bitcoin pays them.

Keep Bitcoin broadcast out (WI-086 stands): the watchtower relays.

- [ ] **Step 1: Write the failing test – `--post` records an UnconfirmedTm**

```rust
#[tokio::test]
async fn a_federation_movement_is_posted_as_an_unconfirmed_tm() {
    let chain = MockChain::with_head(head_outpoint(), 576_107);
    let signed = federation_signed_tm_fixture();
    post_federation_tm(&chain, &signed).await.expect("posts");

    let posted = chain.unconfirmed_tms();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0].raw_bytes, bitcoin::consensus::encode::serialize(&signed));
    assert_eq!(posted[0].inputs[0], head_outpoint(), "input 0 must be the current head");
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p heimdall a_federation_movement_is_posted`
Expected: FAIL – `post_federation_tm` not found.

- [ ] **Step 3: Implement `--post`**

Reuse the daemon's Post-TM path so the record shape is identical. Refuse to post
when input 0 is not the current singleton head: `show-treasury` already marks such
records `DEAD ([CTM-18])`, and posting another is pure noise.

- [ ] **Step 4: Run it and watch it pass, then check the full suite**

Run: `cargo test -p heimdall`
Expected: PASS, no new warnings.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat: federation-spend can post its movement to Cardano

A federation movement that is never posted leaves the bridge-state singleton behind
the chain: the peg-outs Bitcoin has paid still read as unfulfilled, and the next
builder works from a head that has already moved. --post records the signed bytes as
an UnconfirmedTm through the same path the daemon uses, and refuses when input 0 is
not the current head, since such a record can never confirm. Bitcoin broadcast stays
out of heimdall - the watchtower relays from the record."
```

---

## Task 4: The daemon triggers the federation on head age

**Files:**
- Modify: `src/epoch/machine.rs:1745-1770`
- Test: `src/epoch/machine.rs` tests module

**Interfaces:**
- Consumes: `federation::tm::federation_unsigned_tm` (Task 1), `federation_leaf_spend` (Task 2), `post_federation_tm` (Task 3); the chain trait's head-depth read used by `check_federation_csv_depth`.
- Produces: a new `EpochPhase` variant for the federation movement.

**Why.** The stand-down at `:1745` returns `Ok(EpochPhase::Idle)` with the comment
"This state lasts the life of the bridge". That encodes the pre-5.5 model in which
the federation retired after the first handoff. Rev 5.5 `[UY-5]` and spec `:3320`
make it a **standing co-authority**, and spec `:1727` bounds its latency: it "can
act on any treasury or peg-in UTxO that has sat unmoved for
`federation_csv_blocks`".

So the trigger is **head age**, not "detect that roster signing failed". Spec
`:1725` explains why that is safe: "a functioning roster can never be raced by the
federation – every TM re-creates the treasury as a fresh output, resetting the
federation's clock." A head that has aged past 144 blocks *is* the proof the roster
is not moving.

- [ ] **Step 1: Write the failing test – a fresh head keeps the federation idle**

```rust
#[tokio::test]
async fn a_head_younger_than_the_csv_delay_leaves_the_federation_idle() {
    let cfg = federation_node_with_share();
    let chain = MockChain::with_head_depth(143);   // one block short
    let phase = epoch_start_phase(&cfg, &chain, 1559).await.unwrap();
    assert_eq!(phase, EpochPhase::Idle, "144 not reached: the roster still owns the move");
}
```

- [ ] **Step 2: Write the failing test – an aged head triggers the movement**

```rust
#[tokio::test]
async fn an_aged_head_triggers_the_federation_movement() {
    let cfg = federation_node_with_share();
    let chain = MockChain::with_head_depth(144);
    let phase = epoch_start_phase(&cfg, &chain, 1559).await.unwrap();
    assert!(
        matches!(phase, EpochPhase::FederationMovement { .. }),
        "the head has sat unmoved for the CSV delay, so the federation may act"
    );
}
```

- [ ] **Step 3: Write the failing test – an in-flight movement is not raced**

```rust
#[tokio::test]
async fn an_in_flight_movement_holds_the_federation_back() {
    let cfg = federation_node_with_share();
    let mut chain = MockChain::with_head_depth(200);
    chain.add_unconfirmed_tm_spending(chain.head());   // a live record, not a DEAD one
    let phase = epoch_start_phase(&cfg, &chain, 1559).await.unwrap();
    assert_eq!(phase, EpochPhase::Idle, "someone is already moving this head");
}
```

- [ ] **Step 4: Run all three and watch them fail**

Run: `cargo test -p heimdall epoch::machine::tests::federation`
Expected: FAIL – no `EpochPhase::FederationMovement`.

- [ ] **Step 5: Implement**

Replace the `return Ok(EpochPhase::Idle)` at `:1767` with the age test. Keep the
`health.activity` reporting, but stop claiming permanence: a watchdog must be able
to tell "idle, the roster is moving" from "idle, waiting out the CSV delay", so put
the remaining block count in the field. Delete the "lasts the life of the bridge"
comment – it is now false.

Require a federation share before entering the phase: a node without one still has
nothing to contribute.

- [ ] **Step 6: Run to green, and the full suite**

Run: `cargo test -p heimdall`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/epoch/machine.rs
git commit -m "feat: the federation acts on a treasury head that has aged past the CSV delay

The federation node stood down for the life of the bridge once the treasury left
y_federation, which was the pre-5.5 model where it retired after the first handoff;
rev 5.5 makes it a standing co-authority whose latency is bounded by
federation_csv_blocks. The trigger is head age rather than a detected signing
failure, because every movement re-creates the treasury and resets the clock, so an
aged head is itself the evidence that no roster is moving - and a live Unconfirmed
record still holds the federation back so it cannot race a slow but working quorum."
```

---

## Task 5: The daemon may authorize Update-Y as the federation

**Scope, stated plainly:** this task is **authorizer selection only**. It does not
make automatic `[UY-5]` rotation work, because the federation still has no way to
learn *which* key to name – the live roster's key is not on-chain until the
Update-Y lands, and the only safe source is Task 6's
`derive_group_key_from_round1` over the incoming roster's published packages.
Automatic federation rotation = Task 5 (authorizer) + Task 6 (key derivation) +
a trigger. Sequence Task 6 before Task 5 if you want the automatic path in one
go; otherwise Task 5 alone just unblocks the field.


**Files:**
- Modify: `src/cardano/blockfrost_chain.rs:3037`
- Test: `src/cardano/blockfrost_chain.rs` tests, or `src/cardano/update_y.rs` tests

**Why.** `plan_update_y` hardcodes `authorizer: UpdateYAuthorizer::Roster`, so the
daemon can never use `[UY-5]` even though `update_y.rs:101-126` implements the
branch and `main.rs:7697` proves the builder works. A permanently dead roster
therefore needs an operator at a CLI, which is exactly the situation `[UY-5]` was
revised to remove.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn a_federation_node_plans_its_rotation_under_the_federation_branch() {
    let chain = chain_whose_treasury_key_no_roster_can_sign();
    let plan = chain.plan_update_y(1559, new_y51()).await.unwrap();
    assert_eq!(plan.authorizer, UpdateYAuthorizer::Federation);
}
```

- [ ] **Step 2: Run it and watch it fail**

Expected: FAIL – `Roster != Federation`.

- [ ] **Step 3: Implement**

Select by which key this node can actually produce a signature under: a roster
share of the datum's current key gives `Roster`; otherwise a federation share gives
`Federation`. Never prefer `Federation` when `Roster` is available – the roster
branch is the main line and `[UY-5]` is the co-authority, and spec `:2970` is
explicit that this power lets the federation take the treasury, so it must not be
reached while the roster can still sign.

- [ ] **Step 4: Run to green**

Run: `cargo test -p heimdall update_y`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cardano/blockfrost_chain.rs
git commit -m "feat: the daemon can authorize a rotation under the federation branch

plan_update_y named the roster authorizer unconditionally, so the [UY-5] branch the
builder already supports was reachable only from the CLI and a permanently dead
roster needed an operator to recover it. The authorizer now follows the key this node
can actually sign under, and the roster branch keeps precedence wherever it is
available, since the federation branch can name any key and is a co-authority rather
than a first choice."
```

---

## Task 6: WI-078 – a seatless share holder can still serve the handoff

**Files:**
- Modify: `src/epoch/rotation.rs`
- Modify: `src/epoch/machine.rs` (the `NotInEligibleSet` path)
- Test: `src/epoch/rotation.rs` tests module

**Why.** `rotation.rs:63-67` states the gap: "a node sitting the epoch out cannot
help even though it holds a share, because it has no way to learn or validate the
incoming group key it would be signing over. Letting it contribute needs an
attested-key path, not just a phase change: a node that signs whatever `sig_msg`
it is handed hands the treasury to whoever asked. That is WI-078."

The live evidence that this is the fix: `show-roster` reports both departed nodes
**up** (122 ms and 55 ms) and still holding `dkg 1558/16`. The shares are alive and
reachable. Only registry membership is gone.

The attested-key path: a FROST group key is the sum of the participants' round-1
constant-term commitments. That data is already published and already fetched by
`part3`, so a non-participant can recompute the incoming key and compare it with
what the coordinator claims – deriving instead of trusting.

- [ ] **Step 1: Write the failing test – the derivation agrees with the DKG**

This is the test that keeps the sum honest. If it passes, the rest is safe.

```rust
#[test]
fn the_derived_group_key_equals_what_the_dkg_produced() {
    let (round1_packages, pubkey_package) = run_demo_dkg_round1_and_finish(5, 2);
    let derived = derive_group_key_from_round1(&round1_packages).unwrap();
    assert_eq!(derived, group_xonly(pubkey_package.verifying_key()).unwrap().xonly);
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p heimdall rotation::tests::the_derived_group_key_equals`
Expected: FAIL – `derive_group_key_from_round1` not found.

- [ ] **Step 3: Implement the derivation**

Sum the constant term (`coefficients()[0]`) of every incoming participant's round-1
commitment and convert to x-only. Require a package from **every** member of the
incoming roster: a missing one silently changes the sum, which would produce a key
that is wrong rather than absent.

- [ ] **Step 4: Run to green**

Run: `cargo test -p heimdall rotation`
Expected: PASS.

- [ ] **Step 5: Write the failing test – a coordinator-supplied key is refused**

```rust
#[test]
fn a_new_key_the_commitments_do_not_produce_is_refused() {
    let (round1_packages, _) = run_demo_dkg_round1_and_finish(5, 2);
    let attacker_key = xonly_from_seed([0xEE; 32]);
    let err = validate_incoming_key(&round1_packages, attacker_key).unwrap_err();
    assert!(
        format!("{err}").contains("commitments"),
        "must say the claimed key is not the one the roster's commitments produce"
    );
}
```

- [ ] **Step 6: Write the failing test – the incident, reduced**

```rust
#[tokio::test]
async fn two_deregistered_share_holders_still_complete_a_six_of_six_handoff() {
    // The 2026-09-26 preprod deadlock in miniature: a 6-of-6 key, two of whose
    // holders left the registry but are still running and still hold their shares.
    let outgoing = roster_of(6, /* min_signers */ 6);
    let incoming = roster_of(4, /* min_signers */ 2);
    let net = network_where(&outgoing, |pool| pool.serves_handoff_even_without_a_seat());

    let result = run_handoff(&outgoing, &incoming, &net).await;
    assert!(result.is_ok(), "6 of 6 shares are reachable, so the rotation completes");
}
```

- [ ] **Step 7: Run both, watch them fail, then implement**

In `machine.rs`, the `NotInEligibleSet` path must, before returning the error,
check for a persisted share whose group key equals the datum's current key. If one
exists, derive and validate the incoming key, then serve the handoff ceremony
without claiming a seat in the new roster. The duty must end once the datum names
the new key – a departed node that keeps waking every epoch forever is a bug of its
own, so assert that too.

Run: `cargo test -p heimdall`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/epoch/rotation.rs src/epoch/machine.rs
git commit -m "feat: a share holder without a seat can still serve the handoff (WI-078)

A node that left the registry after a ceremony still holds a share the outgoing key
needs, but it could not contribute because it had no way to learn the incoming group
key it would be signing over - and a node that signs whatever sig_msg it is handed
hands the treasury to whoever asked. It now derives that key itself by summing the
incoming roster's published round-1 commitments and refuses any claimed key the sum
does not produce, which is what makes serving the ceremony safe rather than merely
possible; the duty ends once the datum names the new key."
```

---

## Task 7: REJECTED – do not gate `deregister-spo`

**Rejected 2026-10-07 by the user, on the protocol's own terms:** the bridge is
permissionless. An SPO may leave at any time, and the client must not stand in the way.

The objection is stronger than the task was. Three reasons it is right:

1. **It would not work.** Deregistration is a Cardano transaction. Any wallet or script
   can build it, so a check inside `deregister-spo` stops nobody who means to leave; it
   only inconveniences the operator who is being polite about it.
2. **It asserts a duty the protocol cannot confer.** `deregister-spo --help` says leaving
   before the boundary "is a fault, not an exit". That is a fair warning about
   consequences, but enforcing it in the client reads as a claim on the operator's
   machine that a permissionless protocol has no standing to make.
3. **It pushes operators toward the worse exit.** An operator told "refused" is likelier
   to `systemctl stop` and walk away. A clean deregistration at least tells the registry
   what happened; a silent disappearance does not.

### Where the real defect is

Departure was never the bug. The bug is that the epoch-1558 key was **6-of-6** – `t == n`,
zero fault tolerance. A key like that is one departure, one crash or one lost disk away
from needing the federation, and in a permissionless system those are certainties, not
edge cases. Two SPOs leaving merely collected on it.

The threshold rule produced `t == n` legitimately: `t` is the smallest number of SPOs whose
weakest members still exceed the 20% security threshold, and with one pool near 95% of
stake that is everybody. So the rule is working as specified, and the resulting key is
simply fragile.

Which means the answer is the one the spec already gives (security property 5, "Every
failure of the roster has a bounded, Bitcoin-enforced way out"): make the **federation
cycle automatic**, so roster churn self-heals without an operator at a terminal. That is
Tasks 4, 5 and 6 – already in this plan, and now the whole of the recurrence story.

## Task 7b: report a `t == n` key – DONE 2026-10-07

Nothing in heimdall noticed that a ceremony had produced a zero-slack key: verified
2026-10-07, no code compared `min_signers` with `max_signers`. So the operators of the
6-of-6 bridge got no signal that their treasury was one departure from the federation
path, from 2026-09-25 until it was.

Reports, never refuses – the roster is permissionless (see Task 7). What an operator may
not do is leave without anyone having been able to see the risk beforehand.

**`src/epoch/log.rs`** – `no_slack_note(min_signers, max_signers) -> Option<String>`:

```
NO fault tolerance: the threshold is every one of the 6 share holders, so a single
departure, crash or lost share leaves the treasury movable only by the federation CSV path
```

`None` whenever `min_signers < max_signers`, and `None` for an empty roster – a report is
the wrong place to raise a roster that does not exist.

**Two call sites.**

* `src/cardano/roster_report.rs` – a fourth line under `show-roster`'s current key, right
  after `made in bridge epoch 1558, threshold 6 of 6`.
* `src/epoch/dkg.rs` – a `warn` straight after the `key generation complete` event, which
  is the moment the operators could still register another pool before the boundary.
  `warn` rather than `event`: a risk to act on, not a step completed.

**Tests** (6 new, 977 passing): the helper over `6/6`, `2/5`, `6/7`, `1/1` and `0/0`; and
`show-roster` rendering the note for a 6-of-6 key and staying silent for a 4-of-6 one. The
6-of-6 test is the 2026-09-25 key, so it fails if the incident's own case ever stops being
reported.

**Verification gap, stated plainly:** the `dkg.rs` call site is verified by reading, not by
test. Capturing tracing output through the full ceremony needs scaffolding that does not
exist in that module, and the two lines pass the same two values the adjacent event line
already prints. The helper itself is tested directly. A live check falls out of the next
deploy, though only on a bridge whose ceremony is actually `t == n` – preprod's is now 2 of
5, so it will exercise the `show-roster` half and not the DKG half.

## A note on the illustrative tests

The test bodies in Tasks 3, 4 and 6 name helpers that **do not exist yet**:
`MockChain::with_head_depth`, `post_federation_tm`, `run_handoff`, `network_where`,
`serves_handoff_even_without_a_seat`, `run_demo_dkg_round1_and_finish`. Treat them
as the assertion *shape*, not copy-paste code. Before writing each one, read
`src/epoch/mocks.rs` and build the test on the mock that is already there – it
already models the chain, the peer network and the clock, and inventing a parallel
mock is how two test suites start disagreeing about what the chain does. If a mock
genuinely lacks a capability (head depth is the likely one), extending `mocks.rs` is
part of that task.

## Fee sizing to verify (Task 1 or 2)

`estimate_vsize` (`tm_builder.rs:590`) charges 66 B of witness per input – the
key-path figure. The federation treasury input is **182 B** and a federation peg-in
input **214 B** (spec `:2255`). A federation TM is therefore materially larger than
the estimate, so the fee may fall under the relay minimum and the transaction would
simply not propagate. Check what `estimate_vsize` produces for a federation-variant
body and correct the per-input figure if it is wrong. A wrong fee here is invisible
until broadcast, which in the recovery case is the worst place to find it.

## Self-review

**Spec coverage.** Signing cascade `:151`/`:2163` → Tasks 1, 2. Federation variant
definition `:1740`/`:2254` → Task 2. Posting `:160` → Task 3. CSV bound `:1721-1729`
→ Task 4. `[UY-5]` `:2935` and co-authority `:3320` → Tasks 0, 5. `[BTC-1]`/`[BTC-2]`
→ Global Constraints, asserted in Task 1 Step 1. `:3345` "the heimdall builders are
NOT yet updated for rev 5.5" → Task 5 closes the daemon half; the Config-read half
is already done (`update_y.rs` reads `y_federation` from Config).

**Not covered, deliberately.** Peg-in *collection* by the federation (sweeping
deposits stranded at retired addresses, the standing "9 sit at a retired address"
issue) – Task 2 makes it possible, but choosing which stranded deposits are
sweepable is its own question and needs its own plan. The `federation_csv_blocks`
"racing" margin is left at exactly 144 plus the in-flight check; if preprod shows
the federation and a slow roster colliding, add a configurable margin then rather
than guessing one now.

**Critical path, revised 2026-10-06 16:10 UTC after Tasks 0.3, 0.4 and 3 landed.**

The key realisation: **Task 1 is no longer what pays this incident's peg-outs.** Once
the federation moves the BTC head under the NEW tree (`c54a5b9b…`), the live 2-of-5
roster owns the key path again and pays the 3 open peg-outs itself with an ordinary
TM. A treasury-only federation spend is enough to hand custody over. Task 1 becomes
what it should always have been: the capability for a federation facing a roster with
no live successor at all.

| Step | State |
|---|---|
| Task 0.1-0.2 state + CSV depth | done |
| Task 0.3 `[UY-5]` deployed? | **done – YES** |
| Task 0.4 Update-Y under `[UY-5]` | **done – tx `28d2297c…`** |
| Task 3 posting (`--post`) | **done – commit `29733d4`**, hardened after review: refuses a wrong output 0 ([BTC-2]), a missing or doubled BTMR1 ([BTC-1]), and `submit_oracle = false` |
| Deploy the binary carrying `--post` | **done – `heimdall catalyst-m5-2-gb145027`**, a pre-review build: the copy on the host (`heimdall.new`) lacks the output-0 and BTMR1 checks. The next deploy, batched with the fed daemon upgrade, carries them |
| Task 0.5 federation CSV spend `--to <new> --post` | **done 2026-10-07 08:27 UTC** |
| Observe the roster pay the peg-outs at 2 of 5 | the acceptance test, in progress |
| ~~Task 7 deregister gate~~ | REJECTED 2026-10-07: permissionless |
| Task 7b report a `t == n` key | **done 2026-10-07** |
| Task 1, Task 2 | then |
| Task 6 -> 5 -> 4 | the automatic cycle |

### Task 0.5/0.6 result: the federation CSV cycle ran end to end

```
BTC movement    ecca14d898b3fd14bfd0c959b0b838875fccda6cd7346e805812bf8539de1f79
Cardano record  d1628ec31ecebc81196ec949d82c89b2c5bd720c79b5dd847323952ec8b1a291  (confirmed 08:25:03)
spends          cefb913d…:0  (576107 sat, unmoved 11 days, 1559 confirmations)
output 0        575914 sat -> 51209a1be4e6…  = tb1pngd7fes… , the epoch-1570 treasury
output 1        BTMR1: spi 3e450e64… ‖ cpo f2f6f47d…
witness         3 items: BIP340 sig, leaf `<144> OP_CSV OP_DROP <y_fed> OP_CHECKSIG`,
                control block pinning internal key 46f4e530…
nSequence       144
fee             193 sat at 1 sat/vB
```

Every precondition was verified before posting, by running the spend once WITHOUT
`--post` (the natural dry run – the pre-existing behaviour, which prints and stops):

* `CSV: 1559 confirmation(s) >= 144 required – the timelock is satisfied`
* `treasury script: matches the head on Bitcoin (tb1ptehggpe…)` – so `--y51 46f4e530…` named the right tree
* fed1's local tries agree with the singleton: cpo `f2f6f47d…`, spi `3e450e64…`, the same roots spo4 reports
* output 0 equals `show-treasury`'s `expected treasury spk` exactly, satisfying `[BTC-2]`
* exactly one BTMR1 output, satisfying `[BTC-1]` and `[CTM-26]`

Then the chain of custody, each step logged:

```
08:24:26  [federation] signature aggregated and verified under y_federation   (2-of-3)
08:24:32  [submit] submitting Cardano oracle-update tx (4979 bytes CBOR)
08:25:03  [submit] Cardano oracle-update confirmed: d1628ec3…
08:27:19  [relay] Broadcast OK: BTC txid=ecca14d8…        (binocular-bridge-v2)
08:27:26  [confirm] not ready: TxNotConfirmed             (awaiting a testnet4 block)
```

`show-treasury` now reports the record as `SPENDS THE CURRENT HEAD (blocks the mover)`
and the head as `NOT free to move`, which is the singleton correctly following a
movement for the first time in eleven days.

**Observed non-batch overhead: 4651 B against the 5064 B budgeted** (WI-107). The
budget held, with room.

### Note: the binary was not swapped

`heimdall.new` was invoked directly for the CLI work; `heimdall-fed{1,2,3}` still run
`0.1-M5.8 (f5e30ad)` from `/var/lib/heimdall-fed/heimdall`. Nothing about this recovery
needed the daemons upgraded – only the CLI had to carry `--post`. The daemons were
stopped twice for ~90 s each time, because `federation-sign` and `federation-spend`
bind the member URLs the daemons hold (18511-13).

### Proof that 0.4 worked, independent of 0.5

Overnight the roster rotated the datum **by itself**: epoch 1569's key `c54a5b9b…` gave
way to epoch 1570's `da8d1045…` at 00:10:48 UTC, needing only 2 of 5. Before the
`[UY-5]` rotation the datum had been frozen on `46f4e530…` for eleven days. That is the
deadlock broken, confirmed by the chain rather than by argument.

### Deploying the binary (no toolchain on the host)

dev.lantr.io has `nix` only – no cargo, no source checkout – and the running binaries
were copied in (`/var/lib/heimdall-fed/heimdall`, Sep 22; `/var/lib/heimdall-spo4/heimdall`,
Sep 25). The build recipe is `deploy/build-musl.sh`, a static x86_64 musl ELF built
inside `rust:alpine`, invoked locally by `deploy/build-linux.sh` (needs Docker) or in
CI by `release.yml`.

`release.yml` is **not** the path here: it creates a real tag and GitHub release.
`ci.yml` builds and tests but uploads no artifact. So: start Docker, then

```bash
deploy/build-linux.sh            # -> deploy/out/heimdall (static musl)
scp deploy/out/heimdall root@dev.lantr.io:/var/lib/heimdall-fed/heimdall.new
```

`heimdall-fed{1,2,3}.service` all `ExecStart` from the one
`/var/lib/heimdall-fed/heimdall`, so swapping it affects all three: stop, move into
place, start. spo4 keeps its own copy and does not need this binary to benefit – it
only needs the BTC head to move.

### Dry-run the post before posting for real

`--post` is verified against `MockCardanoChain`, never against a real chain. The
`blueprint ✓` lesson applies: a mock agreeing with itself proves less than it looks.
`submit_signed_tm` has a built-in dry run – it skips the publish when
`cardano.submit_oracle=false` or no wallet key is configured, and logs
`[submit] … skipping Cardano oracle publish (dry run)`. Take it once with
`submit_oracle=false`, confirm that line appears **after** `query_treasury` and
`query_config_singleton` have succeeded, and only then post for real.

Verified while writing Task 3: `TreasuryConfig.treasury_value` is `ZERO` in the posting
adapter and is never read by `blockfrost_chain` – the only non-test reader of that field
is a fixture path in `machine.rs`. The real amount comes from the chain.

### Read the destination address fresh

The recorded `tb1p0tlksk4…` was derived for the epoch-1569 key. The datum rotates again
at ~00:01 UTC to the 1570 key, after which the 1569 address is the wrong target.
Re-read `show-treasury`'s treasury address immediately before the spend, and run the
spend clear of the boundary. `--y51` stays `46f4e530…` either way: it names the tree the
INPUT is under, not the output.

<details><summary>Superseded ordering (2026-09-26)</summary>

Task 0 is executable through Step 5
only. Step 6 (posting) has no working surface on dev.lantr.io, so **Task 3 comes
before Task 0 completes**. Recommended order:

1. Task 0 Steps 1-3 (the `[UY-5]` deployment check decides everything below).
2. Task 3 – posting. Nothing else is safe to broadcast without it.
3. Task 0 Steps 4-7 – the manual cycle, end to end, once.
4. Task 1, Task 7 – pay the peg-outs; stop the recurrence.
5. Task 2 – peg-in inputs.
6. Task 6, then Task 5, then Task 4 – the automatic cycle.

**If `[UY-5]` is not deployed** (Task 0 Step 3 fails), the whole Task 0 branch is
replaced by: re-register adanorthpool and xstakepool before the next boundary. Both
are up and hold their shares; `show-roster` prints this as the verdict. Tasks 1-7
still stand as the durable fix.

*Resolved: `[UY-5]` IS deployed, and adanorthpool went down, so this fallback was
never available anyway.*

</details>

**Not verified, and load-bearing.** Whether `sweep-pegins --existing-tm-hex` works
against a real (non-demo) treasury at all – `run_sweep_pegins` recovers `Y_51` via
`run_demo_dkg` for its own signing path (`main.rs:9510`). Task 3 makes the question
moot, which is another reason to do it early rather than investigate this.
