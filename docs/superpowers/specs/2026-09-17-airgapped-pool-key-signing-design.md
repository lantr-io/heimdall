# Air-gapped registration in three commands and one round trip

**Status:** Implemented on `feat/airgapped-pool-key-signing` (2026-09-17). Design kept as the record of why.
**Date:** 2026-09-17
**Driver:** The air-gapped flow in `docs/operator-guide.md` §6 asks the operator to run `sign-registration` beside the pool cold key, copy four hex flags by hand, and re-type a URL byte-identically on the other machine. It also requires the **bifrost secret key** on the air-gapped machine, which contradicts the same guide's line 830 ("it stays on this machine"). Registration is the first thing an SPO does and the step most likely to be done once, under time pressure, by someone who has never done it.

---

## Goal

An operator registers or deregisters with three commands and one trip to the machine that holds `cold.skey`:

```bash
# ONLINE
heimdall register-spo --config /etc/heimdall/heimdall.toml --out /media/usb/request.json
# OFFLINE – cold key only, no config, no network, no state dir
heimdall sign-with-pool-key /media/usb/request.json --cold-skey cold.skey --out /media/usb/signed.json
# ONLINE
heimdall register-spo --config /etc/heimdall/heimdall.toml --signed /media/usb/signed.json --submit
```

Leaving is the same three lines with `deregister-spo`. Nothing is copied by hand, no value is re-typed on the second machine, and the bifrost secret key never leaves the node.

## Out of scope

- The on-chain authorization scheme. `spos-registry.ak:229-230` and `:323-324` are unchanged, so no redeploy, no re-bootstrap, and no SPO re-registers. See §Rejected alternatives.
- `update-y`'s `--signature` air-gapped flag. It signs with a different key (the outgoing FROST key or `y_federation`) and belongs to a federation operator, not an SPO. It keeps its hex flag.
- The registry reference-script step (`deploy-registry-ref`). Unchanged; it stays a precondition and is reported in the request.

---

## What the code does today

Read from `src/main.rs` and `src/cardano/` on `main` (`bcfdb3d`).

### The crypto for a one-round-trip flow already exists

`run_register_spo` resolves the two identities independently (`src/main.rs:6305-6374`) and assembles each signature independently (`src/main.rs:6381-6407`):

| | local secret key | air-gapped |
|---|---|---|
| cold | `--cold-skey` / `cardano.cold_skey_path` | `--cold-vkey` + `--cold-sig` |
| bifrost | `--bifrost-skey` / `[bifrost].skey_path` | `--bifrost-id-pk` + `--bifrost-sig` |

The combinations are free. `--cold-vkey --cold-sig` together with `[bifrost].skey_path` already works: the cold half arrives pre-signed, the bifrost half is signed locally. Nothing in this design needs a new signature scheme – it needs the values to arrive in a file instead of four shell flags.

### Why the offline machine currently needs the bifrost secret key

`registration_message` (`src/cardano/register_spo.rs:164-176`) is

```
"bifrost-spo" || pool_id || bifrost_id_pk || bifrost_url
```

and `pool_id = blake2b_224(cold_vkey)`. Both halves sign the same message, so **whoever signs second must know what the other signed**. `run_sign_registration` (`src/main.rs:1407`) resolves this by signing both halves offline, which forces the bifrost key onto the cold machine.

The other resolution is cheaper and is what this design uses: the cold half signs first and returns `cold_vkey` with its signature. The online node derives `pool_id` from that `cold_vkey` and signs the bifrost half afterwards. One trip, and the bifrost key stays put.

### The offline machine needs no config

`load_config(None)` returns `HeimdallConfig::default()` (`src/main.rs:1084`) – no file lookup, no validation, no network. A command that reads only `--cold-skey` and a request file runs on a machine that has never seen `heimdall.toml`.

### Where the pool id is known

The min-stake gate (`src/main.rs:6443-6499`) is keyed on `pool_id`, so it can only run where the cold **verification** key is known. `cardano.cold_vkey_path` (`src/config.rs:448`) is read in exactly two places, `src/main.rs:6319` and `:6706`. It is public material and safe on the node. Setting it is what lets the operator find out about a min-stake FAIL *before* the trip to the safe rather than after.

---

## Design

### The two files

`request.json`, register:

```json
{
  "v": 1,
  "heimdall": "<binary version>",
  "action": "register",
  "network": "preprod",
  "registry_policy": "<hex>",
  "bifrost_url": "http://spo.example:8080",
  "bifrost_id_pk": "<64 hex>",
  "pool_id": "<56 hex, only when the cold vkey is known here>",
  "message": "<hex, only when pool_id is known>"
}
```

`request.json`, deregister: `"action": "deregister"`, no `bifrost_url`, no `bifrost_id_pk`. `pool_id` and `message` follow the same rule.

`network` is `cardano.network`; `registry_policy` is the parameterized `spos_registry` hash the command already prints. Both are display-only: they let the offline machine name which bridge it is about to join or leave.

`message` is the exact preimage the cold key signs. It is present only when the online box can compute it. It exists so an operator who does not want to trust an unfamiliar binary beside their cold key can reproduce or verify the signature with any Ed25519 tool, and feed the result back through the retained `--cold-sig` flag.

`signed.json`:

```json
{
  "v": 1,
  "heimdall": "<binary version>",
  "action": "register",
  "request": { "...": "the request file, verbatim" },
  "pool_id": "<56 hex>",
  "cold_vkey": "<64 hex>",
  "cold_sig": "<128 hex>"
}
```

The response embeds the request verbatim. That is what lets the online side report `you signed http://host:8080, config now says http://host:8080/` instead of `cold signature invalid`. URL drift is the failure this flow gets wrong most often, and today it is diagnosed only as a bad signature.

**The two `signed.json` files are not equally safe to leave lying around, and the implementation must not treat them alike.** A register response can only authorize the values the operator chose, so leaking it costs nothing. A deregister response is a **bearer instrument**: the revocation message commits to the pool id and nothing else, so it never expires, and `deregister-spo` needs nothing but that signature. Anyone who picks the stick up can post the exit from their own wallet – and the freed registry deposit lands in *their* change output (`docs/operator-guide.md:1202`). `run_sign_revocation` says this today and the replacement must keep saying it. Until the message itself is fixed (§Queued), the mitigation is to keep the file's life as short as the procedure allows:

- `sign-with-pool-key` writes a deregister response `0600` and repeats the standing-authorization warning on the confirmation screen and again after writing.
- `deregister-spo --signed <path>` **deletes the file after a successful submit**, and says so. `--keep` opts out. The file only needs to exist between the safe and the submit; leaving it on the stick afterwards is the whole exposure.
- The guide's leaving section states the risk in one sentence rather than leaving it to the operator to infer.

This is bounded, not fixed, and it is still better than today: `run_sign_revocation` prints the standing signature to a terminal, where it lands in scrollback and in whatever logs that session.

Both files are plain JSON, pretty-printed, one object, no encoding layer. `--out <path>` writes the file; omitting `--out` prints the same JSON to stdout, so an operator with a shell on both machines can paste instead of carrying a stick. It is for pasting, not for `>` redirection: the read-only check lines share that stdout. `--signed -` reads stdin.

### `register-spo` gains two modes

The command has three modes, chosen by what it is given. The first two are new; the third is today's behaviour untouched:

1. **Request mode** – no cold key on this machine and no `--signed`. Today this is an error (`src/main.rs:6333-6338`, `:6388-6392`). It becomes: run every read-only check the command already runs, print them, then write `request.json` and stop. Nothing is built and nothing is submitted. `--submit` in this mode is an error, not a silent no-op.
2. **Signed mode** – `--signed <file>`. Decode, check the embedded request against live config, sign the bifrost half locally, then continue on today's path unchanged.
3. **Local mode** – `cardano.cold_skey_path` or `--cold-skey`. Unchanged.

`--signed` wins over a cold key that happens to be on this machine, so a node with `cardano.cold_skey_path` set can still be driven from a signed file. If the local key's verification key differs from `signed.cold_vkey`, that is an error naming both: the two say different things about which pool is registering.

Request mode runs the checks *before* writing the request, so the trip to the safe happens only when the rest is green. Concretely it reports, in this order: pool id (when known), `bifrost_id_pk`, `bifrost_url`, registry and treasury policy, registry reference script (discovered or missing), the min-stake gate, and the validity window. A missing reference script stops it exactly as it stops the build today – there is no point signing for a registration that cannot be posted.

This gap exists for registration only. A registering pool is by definition not in the registry yet, so nothing on chain can tell the node its own pool id and `cardano.cold_vkey_path` is the only source. Deregistration is the opposite case: see below.

When `pool_id` is unknown the min-stake gate cannot run. Request mode prints

```
min-stake gate:    SKIPPED – pool id is not known on this machine.
                   Set cardano.cold_vkey_path (the PUBLIC half, safe here) to
                   check the gate before you make the trip. It runs on --signed.
```

and the gate still runs in signed mode, where `cold_vkey` has arrived. So the gate is never skipped before a submit, only before a trip.

### `deregister-spo` gains the same two modes

Identical shape. Its request carries no bifrost material because `revocation_message` is `"bifrost-revoke" || pool_id` (`src/cardano/deregister_spo.rs:143-148`) and nothing else. It is emitted anyway, so there is one procedure to learn and one to document, and so the offline machine can say *which* bridge is being left.

Here `pool_id` is **always** known, with no `cold_vkey_path` needed: a leaving pool is already in the registry, and `RegisteredSpo` (`src/cardano/roster.rs:192-198`) carries `pool_id` beside `bifrost_id_pk`, so the node finds its own entry by the bifrost key it runs on – the lookup `preflight.rs:868` already does for `[6/11]`. So a deregister request always carries `pool_id` and `message`, and today's ban-record report always runs before the trip, which is when the operator needs to read it. If the bifrost key matches no registry entry, the command stops there: there is nothing to leave, and no trip should be made.

### `sign-with-pool-key`

```
heimdall sign-with-pool-key <request.json|-> --cold-skey cold.skey [--out signed.json] [--yes] [--config …]
```

Named for the key, not the action: the request file says what is being signed, and the one thing this command fixes in the operator's mind is that it wants the **pool cold key** and never the bifrost key.

- Cold key from `--cold-skey`, falling back to `cardano.cold_skey_path` only when `--config` is given. Accepts a `cold.skey` TextEnvelope, a path to one, or raw 32-byte hex, via the existing `parse_key32`.
- Reads no chain, opens no socket, touches no state directory.
- Rejects a request whose `v` is not 1 or whose `action` is neither `register` nor `deregister`, before it reads the cold key at all.
- Derives `pool_id` from the cold key, rebuilds the message from the request, and **refuses** if the request carries a `pool_id` that this key does not produce. That is the "you brought the wrong bridge's request" and "you are at the wrong pool's safe" check, and it fires beside the key.
- Prints what it is about to authorize, then asks:

```
JOIN the bifrost bridge on preprod
  pool id:        pool1abc…  (a8f2…c41d)
  bifrost url:    http://spo.example:8080
  bifrost pk:     9f3c…
  registry:       7d21…

Sign with the pool cold key? [y/N]
```

  For deregister the first line is `LEAVE the bifrost bridge on preprod`, the middle two lines are absent, and the standing-authorization warning sits between the detail and the prompt: this file never expires, and whoever holds it can post the exit and take the deposit.
- `--yes` skips the prompt. When stdin is not a terminal and `--yes` was not given, it exits with an error rather than assuming consent.
- Verifies its own signature before writing, exactly as `run_sign_registration` does now – the same check the validator performs, so a construction drift between here and `spos-registry.ak` cannot reach a chain.

### What signed mode checks before it builds

In order, each with its own message:

| check | failure message names |
|---|---|
| `v` is 1 | the file's `heimdall` version and this binary's |
| `action` matches the command | `signed.json is a deregister; you ran register-spo` |
| `request.bifrost_url` equals the live resolved URL | both values, on separate lines |
| `request.bifrost_id_pk` equals this node's bifrost key | both values |
| `blake2b_224(cold_vkey)` equals `signed.pool_id` | a corrupt or hand-edited file |
| `now.pool_id`, if known, equals `blake2b_224(cold_vkey)` | a file for another pool, checked by a node acting for this one |
| `cardano.cold_vkey_path`, if set, equals `cold_vkey` | the node was told a different pool |
| `verify_registration` / `verify_revocation` | unchanged, last |

One case the check cannot make: a **registration** on a node with no `cardano.cold_vkey_path`. The node has no opinion about which pool it is, so a `signed.json` for any pool verifies — it is internally consistent, and nothing else knows better. What catches it is what catches it today: the command prints the pool id the file carries, before `--submit`, and the guide tells the operator to compare it with their own. Setting `cold_vkey_path` closes the case outright, which is the second reason to recommend it.

### Removed and kept

**Removed:** the `SignRegistration` and `SignRevocation` clap variants (`src/main.rs:195`, `:692`) and their `run_*` functions (`src/main.rs:1407`, `:1457`). Both are superseded, and `sign-registration` is the command whose contract this design contradicts.

**Kept, still functional, dropped from the guide:** `--cold-vkey`, `--cold-sig`, `--bifrost-id-pk`, `--bifrost-sig`. They are the escape hatch for an operator who produced the signature with their own Ed25519 tool from the `message` field, and they are what signed mode decodes into internally.

**Kept, still documented, now optional:** `cardano.cold_vkey_path`. It stops being the way the air-gapped flow works and becomes the way the operator gets the min-stake gate and the pool id checked before the trip. The guide should recommend it for exactly that.

`sign_registration` in `src/cardano/register_spo.rs:191-220` loses its only caller. Keep it – it is covered by round-trip tests against `verify_registration` and is the readable statement of what the two signatures are.

---

## Queued: the exit signature is replayable, and the fix is on chain

Decided 2026-09-17: the CLI redesign ships first, and this rides the next `spos-registry.ak` revision. It is written down here because the file format is designed to absorb it at `v: 2` with no reshaping, and because the reasoning should not have to be rediscovered.

**Revised 2026-09-22.** The three bindings this section first proposed – `bifrost_id_pk`, `deadline`, `submitter` – are replaced by one: a **nonce outpoint**, a UTxO under the operator's own payment key that the transaction must spend. The spec side is [REG-10] and [DRG-6] in `technical_documentation.md` (§SPO Registration, sections 4 and 7.1, rev 5.6), with the migration that makes the rollout automatic as [MIG-1] to [MIG-6] (section 8) and Config #13 ([CFG-10]); the contract side is the queued `spos-registry.ak` revision, tracked as WI-20260922-3KT03. The rest of this section is the reasoning as it now stands.

`revocation_message` is `"bifrost-revoke" || pool_id` and the validator (`spos-registry.ak:323-324`) checks only that the vkey hashes to the node key. The signature names no time, no spender and no registration instance, so it is valid forever, usable by anyone who obtains it, and it still works against a *later* registration of the same pool. It is also public from its first use, because it rides in the redeemer of the exit that lands. The registration message has the milder form of the same flaw: an old one can put a pool that has left back into the registry against its will, with its old key and URL, where it is faulted and banned in absentia – and the ban list is keyed by `pool_id`, so the ban outlives the replayed registration.

The fix: both messages end with `nonce_outpoint`, the 36-byte `txid ‖ index LE` of an input the transaction spends, named by a new redeemer field `nonce_input_index`. The validator rebuilds the message from `self.inputs[nonce_input_index].output_reference` – a few lines per branch, no new proof, no datum change. The operator chooses the UTxO among their own; the fee UTxO will do.

| property | how the nonce gives it |
|---|---|
| used at most once | an outpoint is spent once; after the transaction lands the signature fits no other |
| retried freely | a failed attempt spends nothing, so the same signature is rebuilt against whatever the treasury outpoint is now |
| usable by one wallet | the transaction must spend the operator's UTxO, so it must carry the operator's payment witness; a leaked file is useless from any other wallet, and the freed deposit cannot land in a stranger's change |
| same-key re-registration | every registration signs a fresh outpoint, so the message needs nothing else to tell instances apart |

This subsumes the earlier table. `submitter` and `deadline` fall out of the witness requirement, and `bifrost_id_pk` in the exit message becomes a display choice rather than a security one.

**Not the Treasury state outpoint**, although Update-Y binds to exactly that (`update_y_sig_msg`). The roster signs Update-Y online, seconds before submitting, and re-signs on a lost race. The cold key signs on the other side of an air gap and the signature has to survive the trip. The Treasury state is spent by every registration, exit and rotation of every pool, so a cold signature bound to it dies at other operators' choice – and anyone can make that happen for the price of fees, since nothing on-chain checks that a registering pool exists and the min-stake gate is CLI-only. **Not the anchor outpoint** either, the obvious candidate before that: `linked_list.remove` spends the *predecessor* node as the anchor (`spos-registry.ak:298-325`), so a node's UTxO is rewritten whenever a neighbour is inserted or removed. Both fail for one reason: an outpoint the operator does not control is a nonce someone else consumes.

What it does to this flow, when it lands: nothing structural. Still three commands, still one trip.

- `request.json` becomes `v: 2` and gains `nonce_outpoint` (`"<txid hex>#<index>"`), chosen by the online node when the request is written. The register request keeps `bifrost_url` and `bifrost_id_pk`; the deregister request gains nothing else. `message` is computed as today, with the outpoint appended.
- The online node **reserves** the UTxO from request to submit: the outpoint is recorded in the state directory and wallet coin selection skips recorded outpoints. Cleanest is for the request command to create a dedicated ~2 ADA UTxO to its own address and pin that – one ordinary transaction before the trip – so a running daemon posting movements or bans cannot spend the nonce out from under an exit.
- Signed mode's drift check (§What signed mode checks before it builds) extends to `nonce_outpoint`, and a file whose UTxO is already spent is refused by naming the spend, not as an invalid signature. A failed submit leaves the UTxO unspent, so retry needs no new file.
- The confirmation screen gains one line: *usable once, by the wallet that holds `<outpoint>`*.
- The bearer-instrument handling in §The two files (`0600`, delete after submit, `--keep`) stays, and stops being load-bearing: a deregister response is then usable only from the wallet that wrote the request.
- No validity-range work. The deadline variant needed a slot↔ms conversion because validity ranges reach the validator as POSIX milliseconds while heimdall builds in slots; the nonce needs nothing from the validity interval.

**Rollout.** The Config NFT is not redeployed: one governance `Update` rewrites field #9 (`spos_registry_policy_id`), moves #8 with it (`spo-bans.ak` takes `registration_script_hash` as a compile parameter, so it is rebuilt with the registry) and sets the appended field #13 `previous_spos_registry_policy_id` to the value #9 held (spec [CFG-10]). `treasury.ak` reads #9 at run time, so the treasury, the bridge state and every peg script stay. What is rebuilt: `spos-registry.ak` (new hash, new bootstrap outref, new root, new reference-script UTxO) and `spo-bans.ak`. heimdall follows the fields per read (`src/cardano/config_params.rs`), so no TOML changes.

The registrations are not redone. The spec's `Migrate` branch ([MIG-1] to [MIG-6], §SPO Registration section 8) carries each one across by a membership proof against the identity trie the treasury still commits to, with no cold or Bifrost signature, so anyone may submit it. On the heimdall side (WI-20260922-3KT03, steps b8 and b9): `run-spo` classifies its own membership at startup and at every roster read – present under #9: nothing to do; absent there, #13 set and present under that policy: migrate itself, retry on the anchor race, report `migrating` then `migrated` on `/health`; in neither list: today's "run register-spo". Nothing is persisted for this; the chain is the source of truth, which is what lets a node that upgrades late find itself already migrated. `migrate-registration --all` is the federation's pass minutes after the Update, so the next boundary snapshot of the new list equals the old roster whatever the operators' calendars. An operator installs the new package and restarts; the cold key is next needed only to leave, with the `v: 2` request. Old nodes stay in the old list, inert, their min-ADA stranded; once #9 has moved the old `Deregister` cannot pass the treasury's [TSY-13], and a pool never migrated leaves by being migrated first, by anyone, then exiting under the new registry.

## Rejected alternatives

### Let `cardano-cli` produce the cold signature

`cardano-cli` has no arbitrary-message signer. It signs one thing: a transaction body hash, through `transaction sign` or `transaction witness` + `assemble`. CIP-8 message signing is implemented by community tools, not the CLI, and wraps the payload in COSE, so the bytes differ and the result verifies nowhere – the trap `docs/operator-guide.md:920` already warns about.

Making `cardano-cli` usable would mean changing the contract to authorize by required signer. Because `pool_id == blake2b_224(cold_vkey)`, `spos-registry.ak:229-230` could become `list.has(self.extra_signatories, new_node_key)`, the pattern `authorizer.ak:46` already uses. Rejected on three grounds, in order of weight:

1. **It widens what the cold key authorizes.** A vkey witness is a signature over a 32-byte transaction body hash whose contents the operator cannot see without inspecting the body. A hostile "registration" body could carry a pool retirement certificate, or a re-registration pointing at another reward account – both authorized by exactly that witness. The present scheme cannot be abused that way: the message is domain-separated (`"bifrost-spo"`, `src/cardano/register_spo.rs:76`) and 71+ bytes, so it is never 32 bytes and a registration signature and a transaction witness can never be confused for each other in either direction.
2. **It binds the signature to one transaction.** Today's cold signature commits to `(pool_id, bifrost_id_pk, bifrost_url)` and survives a spent wallet UTxO, a fee change, an expired validity window or a moved reference script: build and submit retry freely from one trip. A witness dies with its body, so every failed submit costs another trip to the safe.
3. **It is a breaking on-chain change.** A new registry validator is a new policy id, so every membership token on the preprod pilot is under the old policy and every SPO re-registers after a re-bootstrap.

If a contract revision happens for other reasons, accepting `list.has(extra_signatories, pool_id)` *in addition to* the signature is the cheap form, and this design does not foreclose it.

### A single-line token instead of a file

A bech32m-style token (`bifreq1…`, ~110 chars request, ~160 response) carries its own checksum and can be typed. Rejected: it needs an encoding layer to build and to debug, and a file on removable media is what SPOs already move between these two machines for pool certificates. The stdout fallback covers the paste case at no cost.

### A request-free deregistration

`sign-with-pool-key --revoke --cold-skey cold.skey` would work, since the revocation message needs nothing from the online machine. Rejected: two shapes of one procedure in the guide, and the offline machine could then name only the pool id, not the bridge being left.

---

## Testing

The two file types, their encode/decode and every check in the table above live in a new library module, `src/cardano/airgap.rs`, next to the `verify_registration` they feed. `main.rs` only reads the file, calls in, and prints. That is what makes these tests writeable with no wallet, no Blockfrost and no 9000-line binary crate.

Unit, in `src/cardano/airgap.rs`:

- Round trip per action: build request → sign → decode → `verify_registration` / `verify_revocation` passes, and the resulting `RegistrationSignatures` matches what local mode produces from the same keys.
- `sign-with-pool-key` against `HeimdallConfig::default()` with no config file and no `cardano.*` set.
- `pool_id` in the request that the cold key does not produce → refused offline, message names both.
- `bifrost_url` changed between request and signed → the named drift error, not `cold signature invalid`.
- `action` mismatch (`deregister` response into `register-spo`) → named error.
- `v: 2` → named error carrying both versions.
- Flipped byte in `cold_sig` → `verify_registration` rejects.
- Request mode with an unknown `pool_id` → gate reported SKIPPED, not PASS and not an error.
- A deregister response written with `--out` has mode `0600`; a register response does not have to.
- A response for one pool, checked by a node acting for another, is refused naming both. This is the exit case: the node finds its own pool id in the registry, and the file verifies against its own cold_vkey, so nothing else compares the two.
- `deregister-spo --signed <path> --submit` removes the file on success, keeps it on failure, and keeps it under `--keep`. Covered by the offline smoke test rather than a unit test: it needs a submitted transaction, and extracting the branch to fake one would test the extraction.

The existing `build_register_spo_tx` / `build_deregister_spo_tx` tests are untouched: signed mode reaches them with identical inputs.

## Documentation

`docs/operator-guide.md`:

- 154-175, quick-start step 6: the three-command flow as the air-gapped default.
- 835-922, §6: replace the four-flag block; drop the claim that the bifrost key must be offline; keep and sharpen the CIP-8 warning, now pointing at the `message` field for operators who want their own signer.
- 843-856, the config table: `cold_vkey_path` described as the optional pre-trip check, not as the air-gapped requirement.
- 852 and 916: the "byte-identical URL" paragraphs shrink to one sentence – the file carries the URL, and drift is now a named error rather than an invalid signature.
- 1169-1177, leaving: the same three commands, plus one sentence on why the exit file is dangerous to leave lying around and the note that `--signed` removes it after a successful submit unless `--keep` is given.
- 1236, troubleshooting: the `[6/11]` row keeps naming `register-spo`. The command that row refers to – the one `doctor` step 6 prints for an unregistered node – becomes the request-mode invocation, so an operator who follows the printed line lands in the new flow rather than the old one.

`README.md` and `--help` text: `sign-registration` and `sign-revocation` disappear; `sign-with-pool-key` says in its first line that it wants the pool cold key and never the bifrost key.
