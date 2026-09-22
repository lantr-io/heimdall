# Operator-facing logging: one grammar, explicit identifiers, visible progress

**Status:** Implemented on `feat/operator-logging` (2026-09-21), in the order of §10. Design kept as the record of why, with an *Implementation status* note on each rule that shipped differently.
**Date:** 2026-09-21
**Driver:** The log is the only account an SPO gets of what their node did. Three days of the live `heimdall-spo4` journal (2026-09-18 to 2026-09-21, INFO level) show six line kinds making up nearly all of it, and every one of them has at least one of these defects: the node and its peers are named by a positional index or a key prefix, times are given in slots, Rust syntax and protocol jargon leak into INFO lines, a failed round names nobody, the failure path prints `epoch=0`, and startup has no version line but prints four facts twice.

---

## Goal

An SPO who does not know the protocol reads `journalctl -u heimdall` and can answer, from the log alone:

1. Which build is running, on which network, as which pool, with which peers.
2. What the node is doing now, and when the next thing happens, in UTC.
3. When something failed, which peer was missing, by pool id and URL, and what to do next.

## Out of scope

- The subscriber, formats and filter in `src/logging.rs`. Journal priorities, the `heimdall::event` target, JSON output and `RUST_LOG` handling stay as they are.
- The `println!` command reports in `src/main.rs` (`show-treasury`, `status`, `doctor`, the preflight report). They are command output, not logs, and the preflight report is already in the target shape.
- The demo tutorial narration in `src/frost/dkg.rs` and `src/frost/signing.rs`.
- Structured tracing fields. See §Rejected alternatives.

---

## Definitions

Fixed spellings. Use these terms and no synonyms, in the log and in this document. The backticked strings in the last column are the ones `[LG-15]` forbids at INFO and above; `—` means the term is already in use and nothing is forbidden.

| Term | Meaning | Replaces in log text |
|---|---|---|
| bridge epoch | the epoch the ceremony, batches and persisted state are keyed by; on a test run this is the virtual epoch | `ceremony epoch` |
| Cardano epoch | the ledger's epoch number | `chain epoch` |
| group key | the FROST group verifying key of an epoch's ceremony | `Y_51`, `group_key`, `verifying key` |
| key handoff | the transaction that rotates the treasury record to a new group key | `Update-Y`, `rotation`, `succession` |
| treasury record | the on-chain datum that names the key the treasury is held under | `treasury_info` |
| treasury movement | a Bitcoin transaction that spends the treasury | `TM`, `movement`, `Post-TM` |
| bridge state record | the on-chain UTxO that carries both trie roots | `singleton`, `bridge-state singleton`, `cpo source` |
| completed peg-outs ledger | the local trie of fulfilled peg-outs | `cpo trie`, `completed-peg-outs trie` |
| swept peg-ins ledger | the local trie of swept peg-in deposits | `spi trie`, `swept peg-ins trie` |
| SPO roster | the set of registered, eligible pools of a bridge epoch | `the 51% mode` |
| signer set | the members whose round-1 commitments closed a signing round | `S1`, `threshold subset` |
| key generation round N | DKG round N | `DKG round1`, `Dkg(Round1)`, `part3` |
| signing round N | FROST signing round N | `Sign(Round1)`, `Sign round1` |
| batch B_i | the i-th treasury movement opportunity of a bridge epoch | — |
| security threshold | the constant `SECURITY_THRESHOLD_PERCENT` (20) in `src/cardano/dkg_roster.rs` | — |
| pool label | the short form of a bech32 pool id, see `[LG-2]` | `spo=N`, `#N` |
| this node | the pool this process runs for | `me`, `SPO d0367aa8` |

---

## What the code does today

Read from `src/` on `main` (`8d37abc`).

### The machinery is right; the sentences are not

`src/logging.rs` already delivers severity to journald, keeps one stream, and routes operator events under `heimdall::event` to `tools/heimdall-discord`. `src/epoch/log.rs` provides six macros (`epoch_log!`, `epoch_event!`, `epoch_event_warn!`, `epoch_debug!`, `epoch_warn!`, `epoch_error!`) that prefix every line with `[spo=N epoch=E]`, plus `describe_selected`, `describe_registry`, `pool_label`, `id_list`, `one_line` and `Unreachable`. The Discord relay (`tools/heimdall-discord/src/record.rs`) matches on the tracing target and the level only. It does not parse the bracket prefix, so the prefix wording is free to change.

### What the live journal shows

Real lines from `heimdall-spo4`, one per line kind, with the defect each proves:

| Line (abridged) | Defect |
|---|---|
| `[spo=4 epoch=1551] waiting for batch B_4 at slot 134049600 (9134 slot(s) from slot 134040466)` every 5 min, 288 times a day | slots, not time; too frequent for its content |
| `round1 for input 0 closed at the deadline with 4/6, below the 6 required — the round is unavailable.` after 30 min of silence | names no peer; `signing.rs:1013` omits the absentee list that `signing.rs:1038` prints |
| `[spo=4 epoch=0] Sign(Round1) failed (…); backing off 2s then re-entering CollectPegins` | epoch lost: `machine.rs:602` and `:614` pass `EpochPhase::Idle` to `current_epoch`; Rust type syntax |
| `=== Heimdall SPO d0367aa8 (6-of-7) ===` | this node named by a key prefix the operator has never seen |
| `[chain-view] epoch=314 attempt=0 epoch_start_ms=1789689600000 registered=7 active_bans=[] eligible=[209c6caf,…]` twice at startup | key=value dump, key prefixes, printed twice |
| `[blockfrost] treasury head 3333d8…:0 = 520045 sat (singleton, in_flight=true, btc_confirmed=false)` twice per batch | Rust booleans, jargon, repeated |
| `completed-peg-outs trie: 3 entr(y|ies), root 1cc1…` | regex plural |
| `[federation] Y_fed 8b4e…, csv 144 — published in the Config datum` and both `TEST RUN` warnings | printed by the preflight report and again by `run_spo` |
| no line carries the build version | `build.rs` computes `HEIMDALL_VERSION`; only `/health` and the air-gap file show it |

### Facts the code already has at the point of logging

- The batch wait loop (`machine.rs:2896-2920`) holds `snapshot.now_ms` and `snapshot.slot`, so the target slot's wall-clock time is arithmetic.
- The signing and DKG polls (`signing.rs:958`, `dkg.rs:1086`) already log each peer's arrival at DEBUG.
- `SpoInfo` (`state.rs:32`) carries `pool_id` and `bifrost_url` for every roster member. `DkgContext.participants` carries `active_stake` and `DkgContext.total_stake` the total.
- `stake_weighted_threshold` (`dkg_roster.rs:414`) is the smallest `k` whose `k` lowest stakes sum to strictly more than the security threshold of the total, clamped to `FROST_MIN_PARTICIPANTS`.
- A node's identifier index is re-derived at every roster read (`main.rs` comment above `run_spo`'s loop), so a label keyed by identifier is valid only for one roster read.
- `EpochPhase::name()` (`state.rs:641`) is the single source of `Dkg(Round1)`, `Sign(Round1)`, `BuildTm` and the other phase names.

---

## Design

### 1. Line grammar `[LG]`

Applies to every line the daemon writes through the `epoch_*!` macros, and to every `info!`, `warn!` and `error!` in `src/main.rs`'s `run_spo` path, `src/cardano/`, `src/http/` and `src/health.rs`.

- `[LG-1]` The `epoch_*!` macros MUST render the prefix as `[<pool label> epoch=<bridge epoch>]`.

**Implementation status for `[LG-1]`:** the prefix is `[epoch=<bridge epoch>]`; the pool label appears only once a process has logged under more than one identity. A daemon runs one pool, so the label never varied within a stream: `journalctl -u <unit>` has already scoped the reader to that node, the startup block states the full pool id, and the roster table marks `(this node)`. Eighteen constant characters on every line bought nothing on the main reading path. The epoch always stays, because it moves and everything is keyed by it. `log::prefix` restores the label automatically if two identities ever interleave.
- `[LG-2]` The pool label MUST be the bech32 pool id's first 10 characters, then `…` (U+2026), then its last 4 characters.
- `[LG-3]` When the roster entry for an identifier has an empty `pool_id`, the pool label MUST be `spo#N` where `N` is the identifier index.
- `[LG-4]` `src/epoch/log.rs` MUST keep a process-wide label table from identifier to pool label, used for the prefix of `[LG-1]` only.
- `[LG-4a]` A line that renders a peer MUST resolve the peer's pool label and URL from the roster or `peer_infos` of the session it reports on, never from the label table.
- `[LG-5]` The epoch machine MUST replace the whole label table at every roster read, before it logs any line of the new bridge epoch.
- `[LG-6]` A line that names a peer MUST give the peer's pool label and its bifrost URL, as `<pool label> (<url>)`.
- `[LG-7]` A line that reports a count of peers MUST also list them, unless the list is the whole roster already printed by `[RS-1]` in the same bridge epoch.
- `[LG-8]` A line MUST give every amount with its unit: `sat` for Bitcoin, `ADA` with two decimals at most for Cardano.
- `[LG-9]` A line MUST NOT print lovelace.
- `[LG-10]` A line that names a moment MUST print it as `HH:MM:SS UTC`.
- `[LG-11]` A line that names a future moment MUST append the countdown as `(in <d>d<h>h<m>m)`, omitting zero leading units and rounding down to the minute.
- `[LG-11a]` When the moment is not after now, the countdown MUST be `(now)`.
- `[LG-12]` A line MAY append the slot number in parentheses after the time on batch lines only.
- `[LG-13]` A line at INFO or above MUST NOT contain, outside the prefix, a Rust type, enum variant, `{:?}` rendering, or a `key=value` run; a config flag named with its value in `[ST-1]` line 10 is exempt.
- `[LG-14]` A line MUST NOT contain a regex-style plural such as `(s)` or `(y|ies)`; the writer MUST use the `plural` helper.
- `[LG-15]` A line at INFO or above MUST use the terms of §Definitions and MUST NOT use the strings in the "Replaces" column.
- `[LG-16]` A line at INFO MUST report a state change or a milestone.
- `[LG-17]` A line at WARN MUST report a degraded state and MUST end with what the operator can do, or say that nothing is needed.
- `[LG-18]` A line at ERROR MUST report that the node gave up on an action and MUST end with what the operator can do.
- `[LG-19]` A line that reports a transaction MUST give the full txid.
- `[LG-20]` A line that reports an address MUST give the full address.
- `[LG-21]` `EpochPhase::name()` MUST return the human names in the table below.
- `[LG-22]` A line at INFO or above that lists peers MUST name at most `PEER_LIST_CAP` of them, then `… and <n> more`.
- `[LG-24]` A line that names a retry MUST count from 1; the 0-based index stays on the wire and in the signing namespace.
- `[LG-25]` The formatter MUST NOT print the tracing target at INFO or WARN, MUST print it at ERROR and below INFO, and MUST always print `EVENT_TARGET`.
- `[LG-26]` A line that names the posting order MUST give the whole order, numbered from 1, each entry per `[LG-6]`, capped per `[LG-22]`, with this node marked.

**Why `[LG-24]`:** `(attempt 0)` reads as a defect, not a first try.

**Why `[LG-25]`:** `heimdall::epoch::machine:` in front of an English sentence is the Rust internals this design removes everywhere else, and `EnvFilter` matches on metadata before formatting — `RUST_LOG` never needed the target printed. `EVENT_TARGET` is exempt because it is a wire format, not decoration: the relay classifies a line by parsing it out of the text, journald carries no structured field to hold it, and events are INFO while the relay's floor is WARN — dropping it would silently stop every success event reaching the channel.

**Why `[LG-26]`:** the posting order is re-elected per movement from the txid being spent, so there is no standing leader to look up and the log is the only place it can be seen. The order was computed on every movement and never shown; the lines that did mention it rendered a peer as `Identifier("0000…0006")`, 64 hex characters of a FROST scalar, which `[LG-13]` already banned.

- `[LG-23]` A string that is COMPARED rather than read MUST be rendered uncapped, whatever `[LG-22]` says about the line built from it.

**Why `[LG-22]`:** A bridge is not capped at seven pools. Each entry runs about 50 characters, so 100 pools is a 5,000-character journal line, and the relay cuts every message at 2,000 — one roster becomes three Discord messages of names. Ten is enough to recognise a round's stragglers or a roster's newcomers; past that the operator wants `heimdall show-roster`. `[IN-26]` is the same rule stated for one line, and predates this one.

**Why `[LG-23]`:** The `registry:` event fires on its rendered string changing. Capped, one pool leaving and another joining past the cap renders identically — same counts, same first ten names — and the event never fires. `/health` serves the same string and is pulled on demand, so it can carry the whole set.

*Example, illustrative, for `[LG-22]` with `PEER_LIST_CAP` = 10 and 100 eligible pools.*

```
registry: 100 registered, all eligible: pool1s7wet…z2sj (http://heimdal.adanorthpool.com:18500), … 9 more named … … and 90 more
```

| Variant | `name()` |
|---|---|
| `Idle` | `idle` |
| `EpochStart` | `epoch start` |
| `Dkg(Round1)` | `key generation round 1` |
| `Dkg(Round2)` | `key generation round 2` |
| `Dkg(Part3)` | `key generation round 3` |
| `PublishKeys` | `publishing the group key` |
| `AwaitRotation` | `waiting for the key handoff` |
| `CollectPegins` | `collecting peg-ins` |
| `BuildTm` | `building the treasury movement` |
| `Sign(Round1)` | `signing round 1` |
| `Sign(Round2)` | `signing round 2` |
| `Submit` | `posting the treasury movement` |
| `RecordMovement` | `recording the treasury movement` |

**Why `[LG-4a]`:** A signing round can run under the previous epoch's persisted ceremony while the current roster has one more pool (the live node did exactly this on 2026-09-21: "signing with the persisted epoch-1553 ceremony (6-of-6)" under a 7-pool 1554 roster). Indices follow the lexicographic order of bifrost keys, so one added pool shifts every index above it. A table refreshed at the 1554 read and looked up with 1553 identifiers would put the wrong pool id next to the wrong URL on the missing-signer line, which is the line this design exists for. The prefix is safe because `me` is always the current-roster identifier.

**Why:** A positional index means nothing to the operator and moves every epoch. The pool id is what they registered and what every Cardano tool shows. Full identifiers make a line copy-pasteable into an explorer. Units and UTC remove a lookup step. Rust syntax tells the reader "this was not written for you". A WARN that ends with an action is the difference between a line that gets read and one that gets skipped.

*Example, illustrative, for `[LG-2]`.* Pool id `pool1zk3nsdlq0d6xr4x7g9k5vnxw2m8r0wj3h6l9tqv7cyfa2sq7wd` renders as `pool1zk3ns…q7wd`.

*Example, illustrative, for `[LG-11]`.*

| Seconds ahead | Countdown |
|---|---|
| 0 | `(now)` |
| 59 | `(in 0m)` |
| 60 | `(in 1m)` |
| 9000 | `(in 2h30m)` |
| 90000 | `(in 1d1h0m)` |

### 1a. Greppability `[GR]`

Soft requirements. SHOULD, not MUST: a sentence that reads well wins over an anchor that forces awkward English.

- `[GR-1]` A line SHOULD begin, after the prefix, with a fixed phrase that names its subject, and SHOULD put its variable values after that phrase.
- `[GR-2]` The same outcome SHOULD use the same verb on every line: `opened`, `closed`, `skipped`, `built`, `posted`, `confirmed`, `complete`, `aborted`, `failed`, `waiting for`.
- `[GR-3]` A line SHOULD keep every identifier unbroken and unabbreviated, except the pool label of `[LG-2]`.
- `[GR-4]` A line SHOULD NOT wrap; one event is one line unless `[RS-9]` applies.
- `[GR-5]` `docs/operator-guide.md` SHOULD carry the anchor table below, kept in step with the lines.

*Anchor table, illustrative.* What an operator greps for and what it returns.

| `grep` for | Returns |
|---|---|
| `batch B_` | every batch line: waiting, opened, skipped |
| `signing round` | the whole story of every signing round: opened, arrivals, closed, failed |
| `key generation` | the same for every DKG |
| `treasury movement` | built, posted, confirmed, not signed, post failed |
| `key handoff` | every rotation of the treasury record |
| `roster for bridge epoch` | one table per epoch |
| `threshold` | one derivation per epoch |
| `peg-in request` | every skipped or dropped request, once per epoch |
| `this node:` | the pool and URL this process runs for |
| `heimdall::event:` | the operator events, unchanged |
| `Missing:` | every round that closed short, with who was absent |

**Why:** `journalctl -u heimdall | grep` is how an operator reads a multi-day log, and the relay's filters are greps too. A fixed leading phrase with the values after it makes one pattern return one subject's whole history. It is soft because the sentence is the deliverable; when the two conflict, the anchor moves, not the meaning.

### 2. Helpers `[HL]`

New functions in `src/epoch/log.rs`.

- `[HL-1]` `pool_short(pool_id: &[u8]) -> String` MUST implement `[LG-2]` and `[LG-3]`.
- `[HL-2]` `label(id: Identifier) -> String` MUST return the table entry from `[LG-4]`, or `spo#N` when the table has no entry; the macros MUST call it for the prefix and nothing else MUST call it.
- `[HL-3]` `set_labels(roster: &BTreeMap<Identifier, SpoInfo>)` MUST replace the table of `[LG-4]`.
- `[HL-4]` `utc_hms(unix_ms: i64) -> String` MUST implement `[LG-10]`.
- `[HL-5]` `countdown(target_ms: i64, now_ms: i64) -> String` MUST implement `[LG-11]`.
- `[HL-6]` `slot_time_ms(snapshot, slot) -> i64` MUST return `snapshot.now_ms + (slot − snapshot.slot) × 1000`.
- `[HL-7]` `plural(n, one, many) -> String` MUST return `"<n> <one>"` for `n == 1` and `"<n> <many>"` otherwise.
- `[HL-8]` `ada(lovelace: u64) -> String` MUST render with a thousands separator and at most two decimals, trailing zeros dropped.
- `[HL-9]` `describe_selected` MUST render each member as `[LG-6]` requires, from the roster it is given.
- `[HL-10]` `Unreachable::record` MUST take the peer's `SpoInfo` and store the rendered `<pool label> (<url>)` at record time, so `Unreachable::note` needs no roster.
- `[HL-11]` `describe_absent(peer_infos, answered) -> String` MUST render every member of `peer_infos` not in `answered` as `[LG-6]` requires.

**Why:** `[HL-6]` is exact, not approximate: `BatchSnapshot.now_ms` is the tip block's own time and `BatchSnapshot.slot` the tip slot, an aligned pair, so no wall-clock lag enters. `[HL-6]` assumes one second per slot. That holds on mainnet, preprod and the yaci devnet, and it is the same assumption the batch grid in `config_params.rs` already makes. A network with a different slot length would need the length threaded through `snapshot`; none is in scope.

*Example, illustrative, for `[HL-8]`.* `1_234_567_000_000` lovelace renders as `1,234,567 ADA`; `5_000_000` renders as `5 ADA`; `2_500_000` renders as `2.5 ADA`.

### 3. Startup block `[ST]`

Emitted once by `run_spo` in `src/main.rs`, after the preflight report and after the first roster read.

- `[ST-1]` `run_spo` MUST log the startup block in this order, one line each, at INFO unless the item says otherwise:
  1. `heimdall <HEIMDALL_VERSION> starting on cardano <name> / bitcoin <name>`
  2. withdrawn — folded into line 1
  3. `bridge deployment: Config NFT <policy id>.<asset name> at <txid>#<index> (<config address>)`, or `bridge deployment: none (fixture mode)` when no Config locator is set
  4. `this node: <full pool id> at <bifrost url>`
  5. `roster: <n> registered, <m> eligible, threshold <t> of <m>`
  6. `peg-in requests at <full address> (policy <id>); peg-out requests at <full address>`
  7. `wallet <full address> (key from <source>)`, or at WARN `no Cardano wallet: <reason>. This node signs but cannot post`
  8. `peers listen on <bind>:<port>; health on http://<bind>` or `; health surface disabled`
  9. `TEST RUN: <flag>[, <flag>] — every node of this roster must match, and these are refused on mainnet` at WARN, only when a test-run flag is set
- `[ST-2]` The version in line 1 MUST be `env!("HEIMDALL_VERSION")`.
- `[ST-2a]` Line 3 MUST print the Config NFT as the unit string (policy id followed by asset name) and the address it is held at.
- `[ST-2b]` The bridge-to-Cardano epoch mapping MUST be logged at INFO where the ceremony anchor is resolved, once per bridge epoch, as `bridge epoch <E> = Cardano epoch <C>, which began at <HH:MM:SS UTC>`.

**Implementation status for `[ST-2b]`:** the first draft put this mapping on line 2 of the startup block. Only the chain layer knows it — `run_spo` has no Cardano epoch in hand at the banner — and plumbing one through for a display string would be worse than logging it where it is derived. `query_dkg_context` runs twice at startup and again at every ceremony entry, so the line is suppressed unless the mapping has changed; that also fixes the duplicate the journal showed. Line 9 of the block still names `demo_virtual_epoch_slots` when it is set, so a test run is visible from the block alone.
- `[ST-3]` Line 4 MUST print the full pool id, not the pool label.
- `[ST-3a]` When this node has no pool id, line 4 MUST read `this node: spo#N (no pool id) at <bifrost url>`.

**Implementation status for `[ST-1]` ordering:** line 1 is emitted BEFORE the preflight gate, not with the rest of the block. The gate prints eleven lines of its own, so the block that followed it put the version below them — and a node that FAILS preflight never reaches the block at all, leaving the one question every report opens with unanswered. The remaining lines stay after the gate, because they name values the config resolution behind it produces.

**Implementation status for `[ST-1]` line 1:** the first draft split the version and the network across lines 1 and 2. `network preprod` alone reads as a fragment, and the pair is one answer — which build, running against what. Line 1 also names the BITCOIN network now: a node pointed at the wrong one is the same class of fault as the wrong Cardano network, and the block never said which it was.

**Implementation status for `[ST-1]`:** the treasury balance the first draft listed is not in the block. `run_spo` does not read the treasury — preflight check 8 and the per-batch `treasury holds <n> sat` line both do — and adding a chain read to the banner would buy one number already reported twice.
- `[ST-4]` `run_spo` MUST NOT log the roster table; `[RS-1]` logs it at the first epoch start, which follows the startup block within seconds.
- `[ST-5]` `run_spo` MUST NOT log the lines listed under "Removed" below.

Removed from `run_spo` and its callees at INFO and WARN, because the preflight report or the block above already says it:

| Line today | Site |
|---|---|
| `[federation] Y_fed …, csv … — …` | `main.rs:2526` |
| `[stake] TEST RUN: …` | `main.rs:2701` |
| `[epoch] TEST RUN: …` | `main.rs:2727` |
| `note: eligible roster = registry − active bans; … (WI-012)` | `main.rs:2754` |
| `=== Heimdall SPO <hex> (t-of-n) ===` | `main.rs:3160` |
| `Waiting for the other N SPOs to come online...` | `main.rs:3165` |
| `[config] TM validator … sourced from the chain and verified against Config #5` | `main.rs:2503` (to DEBUG) |
| `[chain-view] epoch=… registered=… eligible=[…]` | `dkg_roster.rs:959` (to DEBUG) |
| `[virtual-epoch] ceremony epoch … anchored at … ms — …` | `blockfrost_chain.rs:1159` (to DEBUG) |

**Why:** A support request starts with "which version, which network, which bridge, which pool". Today none of the four is on one screen. The Config NFT is what identifies a Bifrost deployment: two bridges on the same network differ only by it, and a node pointed at the wrong one looks healthy while it signs for nothing. Duplicates train the reader to skip.

*Example, illustrative, the whole block.*

```
heimdall 0.1-M5.7 (b00574a 2026-09-17) starting
network preprod; bridge epoch 1554 = Cardano epoch 314 (test run: 86400-slot virtual epoch)
bridge deployment: Config NFT 7b0c2e9d4a1f6e8b3c5d9a2f1e4b7c8d0a3f6e9b2c5d8a1f4e7b0c3d.436f6e666967 at 3a02336e5bee7ffc0547484068ff4711db9836c5a075ef1956b933dede95ac3c#0 (addr_test1wq7k3m2n4p5r6s8t9v0w1x2y3z4a5b6c7d8e9f0g1h2i3j4k5l6m7n8p9q)
this node: pool1zk3nsdlq0d6xr4x7g9k5vnxw2m8r0wj3h6l9tqv7cyfa2sq7wd at http://dev.lantr.io:18514
roster: 7 registered, 7 eligible, threshold 6 of 7
treasury tb1pgqlp8qm42lvq37l63w8dzdlae58085w9p8l5zg06n2r44t8q8k0sr2tmw3 holds 550309 sat
peg-in requests at addr_test1wrxw3hx8h4lye7g8pn03u8rdgmaeazjryvngepcrtnpaf6gh6jprx; peg-out requests at addr_test1wr74gvdtv9exe4psnpy2602py8kz7yuvzdw7gng4xgkr3aq8wju9e
wallet addr_test1qzwg0u9fpl8dac9rkramkcgzerjsfdlqgkw0q8hy5vwk8tzk5pgcmdpe5jeh92guy4mke4zdmagv228nucldzxv95clq68fray (key from $HEIMDALL_MNEMONIC)
peers listen on 0.0.0.0:18514; health on http://127.0.0.1:18581
TEST RUN: demo_live_stake, demo_virtual_epoch_slots=86400 (every node of the roster must match)
```

### 4. Roster and stake table `[RS]`

- `[RS-1]` The epoch machine MUST log the roster table at INFO at every epoch start, after the roster read.
- `[RS-2]` The table header MUST read `roster for bridge epoch <E>: <n> registered, <m> eligible, total stake <ADA> ADA`.
- `[RS-3]` The table MUST list every eligible pool, one per line, in ascending order of stake.
- `[RS-4]` Each row MUST carry, in this order: pool label, stake in ADA, share of total as a percentage with one decimal, the running total of shares so far as `so far <p>%` with one decimal, bifrost URL.
- `[RS-4a]` The running-total column MUST be labelled `so far`, not `cum` or `cumulative`.
- `[RS-5]` The row for this node MUST end with ` (this node)`.
- `[RS-6]` The table MUST end with a threshold line: `threshold <t> of <m>: the <t> smallest stakes hold <p>% of total; the <t−1> smallest hold <q>%, not above the <S>% security threshold`.
- `[RS-7]` When `t` was clamped up to `FROST_MIN_PARTICIPANTS`, the threshold line MUST instead read `threshold <t> of <m>: raised to the FROST minimum of <t>; the <k> smallest stakes already hold <p>% of total, above the <S>% security threshold`.
- `[RS-8]` When the roster has excluded pools, the table MUST end with one line per excluded pool: `not eligible: <pool label> — <reason>`.
- `[RS-9]` The epoch machine MUST emit the table as one `epoch_log!` call per line, so every line carries the prefix.

**Why `[RS-9]`:** The formatter repeats the target and priority on every line of a multi-line event, but the `[… epoch=E]` prefix is message text and appears once. One call per row is the only way every row carries it.

**Why:** The operator asked how "6 of 7" is derived. The ascending order and the cumulative column make the derivation visible without knowing the algorithm: the threshold is the first row whose cumulative share passes the security threshold. Printing it every epoch matters because stake moves every epoch and the threshold with it.

*Example, illustrative.*

```
[pool1zk3ns…q7wd epoch=1554] roster for bridge epoch 1554: 7 registered, 7 eligible, total stake 1,234,567 ADA
[pool1zk3ns…q7wd epoch=1554]   pool1m4hs2…x8pl     30,000 ADA   2.4%  so far   2.4%  http://139.59.140.78:18501
[pool1zk3ns…q7wd epoch=1554]   pool1dq7wf…3kkc     40,000 ADA   3.2%  so far   5.7%  http://heimdal.adanorthpool.com:18500
[pool1zk3ns…q7wd epoch=1554]   pool1zk3ns…q7wd     45,000 ADA   3.6%  so far   9.3%  http://dev.lantr.io:18514  (this node)
[pool1zk3ns…q7wd epoch=1554]   pool1u9e2r…7pqa     60,000 ADA   4.9%  so far  14.2%  http://139.59.140.78:18500
[pool1zk3ns…q7wd epoch=1554]   pool1xstk3…2qdn     70,000 ADA   5.7%  so far  19.8%  https://bifrost.xstakepool.com
[pool1zk3ns…q7wd epoch=1554]   pool1e1sy4…0zzr    100,000 ADA   8.1%  so far  27.9%  https://preprod-bifrost.easy1staking.com
[pool1zk3ns…q7wd epoch=1554]   pool1n8f2l…4rtm    889,567 ADA  72.1%  so far 100.0%  http://139.59.140.78:18502
[pool1zk3ns…q7wd epoch=1554] threshold 6 of 7: the 6 smallest stakes hold 27.9% of total; the 5 smallest hold 19.8%, not above the 20% security threshold
```

### 5. Progress `[PR]`

#### 5.1 Waiting for a batch

- `[PR-1]` When the wait loop starts waiting for a batch, or the batch it waits for changes, the epoch machine MUST log at INFO: `waiting for batch B_<i> at <HH:MM:SS UTC> (in <countdown>), slot <slot>`.

**Implementation status for `[PR-1]`:** the pending peg-in and peg-out counts the first draft required were dropped. `await_batch_opportunity` is called before anything reads the peg-in source, so every heartbeat would have cost a second chain query to carry two numbers that the batch-open lines report a moment later anyway. A count is not worth a request per tick.
- `[PR-2]` While the target batch is unchanged, the epoch machine MUST log `still waiting for batch B_<i> at <HH:MM:SS UTC> (in <countdown>)` at INFO when 3600 s or more have passed since the last waiting line for that batch.
- `[PR-3]` The wait loop MUST keep its 5-minute re-read and its `/health` update unchanged.
- `[PR-4]` When a batch opens, the epoch machine MUST log at INFO: `batch B_<i> opened at <HH:MM:SS UTC>; requests created before <HH:MM:SS UTC> qualify`.
- `[PR-5]` When a batch passes unused, the epoch machine MUST log at INFO one line that names the batch and the reason in the terms of §Definitions, and names the next batch with its time.
- `[PR-6]` `config_params.rs:1098` (`slot … is outside this epoch's batch grid`) MUST move to DEBUG.

**Implementation status, `[PR-5]`:** The line names the batch and the reason. It does NOT name the next batch with its time. The site has no `BatchSnapshot` in hand, and reading one costs a chain query per pass, so the next batch is left to the wait loop's own line under `[PR-2]`, which runs moments later and carries the time.

*Example, illustrative, for `[PR-2]` with a wait that started at 06:30:24.*

| Loop tick at | Logs |
|---|---|
| 06:30:24 | `waiting for batch B_3 at 09:00:00 UTC (in 2h29m, slot 134298000); 0 peg-ins, 1 peg-out pending` |
| 07:25:24 | nothing (3300 s) |
| 07:30:24 | `still waiting for batch B_3 at 09:00:00 UTC (in 1h29m)` (3600 s, boundary inclusive) |
| 08:30:24 | `still waiting for batch B_3 at 09:00:00 UTC (in 29m)` |
| 09:00:18 | `batch B_3 opened at 09:00:00 UTC; requests created before 07:00:00 UTC qualify` |

#### 5.2 Inside a round

Applies to signing rounds 1 and 2, key generation rounds 1 to 3, and the key handoff rounds.

- `[PR-7]` When a round opens, the round's poll MUST log at INFO: `<round name>: waiting for <k> peers until <HH:MM:SS UTC>`.
- `[PR-8]` When a peer's package arrives, the poll MUST log at INFO: `<round name>: <have> of <need> in (+<pool label>)`, where `have` counts this node.
- `[PR-9]` The poll MUST log at most one line per peer per round for arrivals.
- `[PR-10]` When a round closes at the deadline below the threshold, the poll MUST log at WARN a line that names every absent peer per `[HL-11]`, then the peers that answered with an error per `[HL-10]`, and ends with the next batch and its time.
- `[PR-10a]` When no peer answered with an error, the line of `[PR-10]` MUST say `Up but erroring: none`.
- `[PR-11]` When a round closes at the deadline at or above the threshold, the poll MUST log at WARN a line that names every absent peer per `[HL-11]` and says the round proceeds.
- `[PR-12]` The `==> phase = <name>` line (`machine.rs:298`) MUST move to DEBUG.

**Implementation status, `[PR-8]`:** The line reads `signing round 1 for input 0: 2 of 7 in — <pool label> (<url>) just answered`, not `(+<pool label>)`. The `(+label)` form carries no URL, which `[LG-6]` requires of any line that names a peer, and the URL is the half an operator acts on when a peer is late. The `signing round` opening is what makes one `grep` return a round's whole history, per `[GR-5]`.

**Implementation status, `[PR-7]`:** The line reads `waiting up to <window> for <k> peers`, not `until <HH:MM:SS UTC>`. A round deadline is a monotonic `Instant`, which carries no wall-clock epoch to convert from, and no wall clock reaches the signing module. The window is also seconds to minutes, so the relative form is the number the operator wanted. `log::remaining` renders it.

**Implementation status, `[PR-10]`:** The line names the absent peers and the erroring peers. It does NOT end with the next batch and its time, for the reason given under `[PR-5]`.

**Why:** Thirty minutes of silence followed by "4/6" is the single most reported gap. The absentee list exists for the at-threshold branch and is missing from the below-threshold branch, which is the one an operator needs to act on. Arrivals are already logged at DEBUG; at INFO they replace the silence with a countdown of who is in.

*Example, illustrative, for `[PR-7]` to `[PR-10]`.*

```
09:00:21Z INFO [pool1zk3ns…q7wd epoch=1554] signing round 1 for input 0: waiting up to 29m39s for 6 peers
09:00:40Z INFO [pool1zk3ns…q7wd epoch=1554] signing round 1 for input 0: 2 of 7 in — pool1m4hs2…x8pl (http://139.59.140.78:18501) just answered
09:00:41Z INFO [pool1zk3ns…q7wd epoch=1554] signing round 1 for input 0: 3 of 7 in — pool1dq7wf…3kkc (https://bifrost.example.com) just answered
09:03:12Z INFO [pool1zk3ns…q7wd epoch=1554] signing round 1 for input 0: 4 of 7 in — pool1u9e2r…7pqa (http://dev.lantr.io:18514) just answered
09:30:04Z WARN [pool1zk3ns…q7wd epoch=1554] signing round 1 for input 0 closed at the deadline with 4 of 7, below the 6 required — the round is unavailable. Missing: pool1xstk3…2qdn (https://bifrost.xstakepool.com), pool1e1sy4…0zzr (https://preprod-bifrost.easy1staking.com), pool1n8f2l…4rtm (http://139.59.140.78:18502). Up but erroring: none.
```

#### 5.3 Failure path

- `[PR-13]` The failure lines at `machine.rs:602` and `machine.rs:614` MUST carry the bridge epoch of the phase that failed.
- `[PR-14]` The failure lines MUST read `<phase name> failed: <cause>; next try at batch B_<i>, <HH:MM:SS UTC> (in <countdown>)` when a next batch exists, and `<phase name> failed: <cause>; no batch left this epoch, waiting for bridge epoch <E+1>` otherwise.
- `[PR-15]` The `TM NOT SIGNED` event at `machine.rs:530` MUST read `treasury movement <txid> not signed: <cause>; <n> in a row. If this keeps climbing, the treasury moves only through the federation's emergency path: heimdall federation-spend`.

**Implementation status:** `[PR-13]` is a bug fix and ships in PR 1 alone, before any wording change. The cause is `current_epoch(&EpochPhase::Idle)` where the phase that failed is `stepped`.

**Implementation status, `[PR-14]`:** The line reads `<phase name> failed: <cause>. Retrying in <n>s, from <phase name>`. A failure does not wait for the next batch: it backs off and re-enters from the resume phase, so `next try at batch B_<i>` would name a moment that is not when the next try happens. The rule was written before that control flow was read.

### 6. Tier-1 line inventory `[IN]`

The lines the live journal shows. Each row is a requirement: the writer MUST replace the "before" with a line of the "after" shape at the "level" given. `[IN-1]` to `[IN-24]` are the row numbers.

| ID | Site | Before (abridged) | After (shape) | Level |
|---|---|---|---|---|
| IN-1 | `machine.rs:2905` | `waiting for batch B_4 at slot … (… slot(s) from slot …)` | `[PR-1]`, `[PR-2]` | INFO |
| IN-2 | `machine.rs:2833` | `═══ batch B_3 @ slot … (membership cutoff: created at or before slot …) ═══` | `[PR-4]` | INFO |
| IN-3 | `machine.rs:3049` | `batch B_3 passes UNUSED: a treasury movement is still in flight against the current tip …` | `batch B_3 skipped: treasury movement <txid> is still waiting for Bitcoin confirmation; next batch B_4 at <time> (in …)` | INFO |
| IN-4 | `machine.rs:2882` | `batch B_… @ slot … passes unused: its round-1 window closed at slot …` | `batch B_3 skipped: its signing window closed at <time>, before this node was ready; next batch …` | INFO |
| IN-5 | `machine.rs:3909` | `chain query: treasury=… sat, 0 eligible pegins, 1 open pegouts, fee_rate=1sat/vb (params: Config UTxO …); byte budget: …` | `treasury <address> holds <sat> sat; <n> peg-ins eligible, <m> peg-outs open; fee 1 sat/vB` at INFO; Config UTxO and byte budget at DEBUG | INFO + DEBUG |
| IN-6 | `machine.rs:298` | `==> phase = Sign(Round1)` | `[PR-12]` | DEBUG |
| IN-7 | `machine.rs:602`, `:614` | `Sign(Round1) failed (…); backing off 2s then re-entering CollectPegins` | `[PR-13]`, `[PR-14]` | WARN |
| IN-8 | `machine.rs:530` | `TM NOT SIGNED: the 51% mode did not sign this movement (…) — 2 consecutive now …` | `[PR-15]` | WARN event |
| IN-9 | `machine.rs:4273` | `TM built: txid … — 1 input(s) (0 deposit(s) swept), 3 output(s), 1 peg-out(s) paid; signing starts` | `treasury movement built: txid <txid>; sweeps <n> deposits (<sat> sat), pays <m> peg-outs (<sat> sat); signing needs <t> of <n>` | INFO event |
| IN-10 | `machine.rs:4750` | `TM posted: txid … — Post-TM submitted (… bytes; …)` | `treasury movement posted: txid <txid> (<bytes> bytes); pays <m> peg-outs, sweeps <n> deposits; waiting for Bitcoin confirmation` | INFO event |
| IN-11 | `machine.rs:4735` | `TM post FAILED: txid … — this node could not complete the Post-TM (…) …` | `treasury movement post failed: txid <txid>; <cause>. <what to do>` | WARN event |
| IN-12 | `machine.rs:1042` | `TM confirmed: txid … — treasury head is now … (… peg-out(s) completed, … deposit(s) …)` | `treasury movement confirmed: txid <txid>; treasury is now <txid>:<vout> with <sat> sat; <m> peg-outs completed, <n> deposits swept` | INFO event |
| IN-13 | `signing.rs:187`, `:250`, `:281`, `:308`, `:335`, `:418`, `:568`, `:581` | `Sign round1 (attempt 0): …`, `waiting for round1 commitments on input 0 from 5 peer(s)...`, `<- have all round1 commitments` | `[PR-7]`, `[PR-8]`, `signing round 1 complete: <need> of <need> in` | INFO |
| IN-14 | `signing.rs:958`, `dkg.rs:1072`, `dkg.rs:1167` | arrival at DEBUG | `[PR-8]` | INFO |
| IN-15 | `signing.rs:1013`, `:1038` | `round1 for input 0 closed at the deadline with 4/6, below the 6 required — the round is unavailable.` | `[PR-10]`, `[PR-11]` | WARN |
| IN-16 | `dkg.rs:116`, `:206`, `:276`, `:289`, `:389`, `:495`, `:508`, `:546` | `DKG round1 (attempt 0) started: n=7 t=6, participants: …` | `key generation round 1 opened (attempt 0): 7 members, threshold 6; waiting until <time>`, then `[PR-8]` shape | INFO |
| IN-17 | `dkg.rs:618` | `DKG complete (attempt 0): Y_51=… — 7 share-holder(s), threshold 6.` | `key generation complete (attempt 0): group key <hex>; 7 share holders, threshold 6` | INFO event |
| IN-18 | `dkg.rs:761` | `DKG ABORTED (attempt 0): 5 of 7 eligible qualified — …. Excluded: ….` | `key generation ABORTED (attempt 0): 5 of 7 eligible qualified — <why>. Excluded: <summary>. …` | WARN event |
| IN-19 | `machine.rs:2501`, `:2529`, `:2536` | `PublishKeys: group_key = … (derived point parity 0x03; stored x-only per BIP-340)`, `-> new treasury: output_key=… scriptPubKey=…`, `New treasury address …` | one INFO event `group key for bridge epoch <E>: <hex>; treasury address <address>`; parity and scriptPubKey at DEBUG | INFO event + DEBUG |
| IN-20 | `machine.rs:2577`, `:2730`, `:2013`, `rotation.rs:157`, `:175`, `:528`, `:584` | `Update-Y: rotating treasury_info … from … to …`, `Update-Y posted: cardano tx …` | `key handoff: rotating the treasury record from <hex> to <hex>`, `key handoff posted: Cardano tx <txid>; treasury key <hex> -> <hex>` | INFO event |
| IN-21 | `blockfrost_chain.rs:2765` | `[blockfrost] treasury head …:0 = … sat (singleton, in_flight=true, btc_confirmed=false)` | unchanged text at DEBUG; the INFO facts come from IN-5 | DEBUG |
| IN-22 | `machine.rs:3251`, `:3239` | `dropped peg-in <utxo>: no output pays to the peg-in Taproot` every batch | once per request per bridge epoch: `peg-in request <utxo> skipped: <reason>; it will not be swept until <what fixes it>` | WARN |
| IN-23 | `machine.rs:3639`, `:1198`, `:1250`, `:3745` | `completed-peg-outs trie: 3 entr(y|ies), root …`, `local tries match the bridge state singleton at head …` | `completed peg-outs ledger: 3 entries, root <hex>`; `local ledgers match the bridge state record at <txid>:<vout>` | INFO |
| IN-24 | `main.rs:2503`, `dkg_roster.rs:959`, `blockfrost_chain.rs:1159` | see §3 Removed | `[ST-5]` | DEBUG |

- `[IN-25]` The writer MUST keep a set of already-reported peg-in request UTxOs in the machine for `IN-22`, cleared at every epoch start.
- `[IN-26]` The event line of `IN-18` MUST keep the excluded list within a stated byte budget, as an exception to `[LG-6]`.

**Why `[IN-26]`:** The relay carries one event on one line of at most 1992 bytes. Seven excluded pools with URL and reason do not fit, and the roster table of the same epoch has already printed every URL.

**Implementation status for `[IN-26]`:** the existing `one_line_within(&summary, 600)` cap already satisfies this, so the split into an event plus one WARN line per excluded pool was not built. The `key generation exclusions` WARN line beside it already carries the full untruncated summary for anyone reading the node's own log.

### 7. Tier-2 sweep `[SW]`

Every remaining `epoch_*!`, `info!`, `warn!` and `error!` site in the daemon path not listed in §6.

- `[SW-1]` The writer MUST check every site against `[LG-6]` to `[LG-20]` and rewrite any line that breaks one of them.
- `[SW-2]` The writer MUST NOT change a line's level or split a line during the sweep unless a `[LG]` rule requires it.
- `[SW-3]` The sweep MUST NOT touch `src/frost/`, the `println!` reports, or the tests.

### 8. Tools `[TL]`

`src/bin/depositor.rs` and `src/bin/register_pool.rs`.

- `[TL-1]` A tool line MUST follow `[LG-8]` to `[LG-20]`.
- `[TL-2]` A tool line MUST NOT carry the `[pool label epoch=E]` prefix.
- `[TL-3]` The aligned `key:   value` report lines MUST keep their alignment.
- `[TL-4]` `submitted: tx_hash=<hex>` MUST become `submitted: txid <hex>`.
- `[TL-5]` `discovered <n> UTXO(s) via listunspent` MUST become `found <plural(n, "UTxO", "UTxOs")> via listunspent`.
- `[TL-6]` `(dry run — pass --submit to broadcast)` MUST become `dry run: nothing was broadcast; pass --submit to broadcast`.

### 9. Tests, docs and the relay `[TS]`

- `[TS-1]` `src/logging.rs` tests that pin `[spo=1 epoch=307]` MUST be updated to a pool-label prefix, with the reason in the test's doc comment.
- `[TS-2]` `tools/heimdall-discord/src/record.rs` test literals MUST be updated the same way; the parser MUST NOT change.
- `[TS-3]` The event inventory tripwire in `src/epoch/log.rs` MUST be updated with the new counts and the list of events that moved, if any count changes.
- `[TS-4]` `src/epoch/log.rs` MUST gain unit tests for `[HL-1]`, `[HL-2]`, `[HL-4]`, `[HL-5]`, `[HL-7]`, `[HL-8]`, `[HL-10]`, `[HL-11]` and for the threshold line of `[RS-6]` and `[RS-7]`. These are pure functions over their inputs, so the tests pin behaviour rather than wording.
- `[TS-5]` The tests MUST cover the pure helpers only; they MUST NOT capture rendered log output to assert on a call site's wording. *Withdrawn from the original draft:* a machine test across the `[PR-2]` boundary.
- `[TS-6]` Withdrawn, for the reason in `[TS-5]`: a signing test asserting the below-threshold close names its absentees. `[TS-4]` covers the helper that renders them.

**Why `[TS-5]`:** A test that pins a sentence fails on every rewording, which is the whole of this work, and it passes while saying nothing about whether the sentence is any good — the reader is the only judge of that. Holding the PURE helpers exactly (truncation, pluralisation, countdown boundaries, the threshold derivation) catches the class of bug a reader would not spot, and leaves the prose free to improve.
- `[TS-7]` `docs/operator-guide.md` §"Reading the log" MUST be rewritten around the new grammar and MUST gain a glossary that maps each §Definitions term to one sentence, and SHOULD carry the anchor table of `[GR-5]`.
- `[TS-8]` The six troubleshooting rows in `docs/operator-guide.md` that quote line text (`⚠ EXCLUDING`, `candidate set reduced`, `N of M candidates excluded at the pre-ceremony handshake`, `TEST RUN`, lines 1355 to 1359, 1598, 1729) MUST quote the new text.
- `[TS-9]` `tools/heimdall-discord/README.md` examples MUST show the new prefix.
- `[TS-10]` `/health`'s `registry` string MUST continue to equal `describe_registry`'s output, so the two cannot disagree.

### 10. Delivery order

| PR | Content | Size |
|---|---|---|
| 1 | `[PR-13]` epoch on failure lines; `[PR-10]` absentees named on the below-threshold close. Bug fixes only, current wording. | about 2 hours |
| 2 | `[HL]`, `[LG-1]` to `[LG-5]`, `[LG-21]`, `[ST]`, `[RS]`, `[PR]`, `[IN]`, `[TS-1]` to `[TS-4]`, `[TS-10]` | about 1.5 days |
| 3 | `[SW]`, `[TL]`, `[TS-7]` to `[TS-9]` | about 1 day |

**Why:** PR 1 is the fix an operator running the live node needs today, and it must not wait for a style change. PR 2 is one coherent change to the six macros and the lines that use them; splitting it would leave the log with two prefixes at once. PR 3 is mechanical and reviewable on its own.

---

## Rejected alternatives

- **Typed event enum with one `Display`.** Consistent by construction, but about 180 variants and a diff at every call site. The rules in `[LG]` plus the tripwire test give most of the consistency for a tenth of the churn.
- **Structured tracing fields.** `info!(pool = %p, batch = 3, "batch opened")` is what a log shipper wants, but the plain and journal formatters render fields after the message, which breaks the `[prefix] sentence` layout humans and the relay read. It can be layered later without undoing this design.
- **Index per line plus a legend line.** Shorter lines, but the index moves every epoch and the reader has to find the legend. The operator chose the pool label per line.
- **Full pool id per line.** Unambiguous, but 56 characters on every line and 400-character peer lists.
- **5-minute heartbeat in wall-clock time.** Fixes the units but keeps 288 identical lines a day. `/health` carries the live state; the log carries milestones and an hourly pulse.
- **Cardano epoch in the prefix.** The ceremony, batches and persisted state are keyed by the bridge epoch. Line 2 of the startup block and the roster header give the mapping once.
