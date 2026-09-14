# Reconcile the tries where the divergence is detected

**Status:** Design — amended 2026-09-14 (§Before implementing); implement from this document, no separate plan
**Date:** 2026-09-12
**Driver:** WI-20260912-8DDEA — a node whose tries fall behind the chain *while it is running* stays inert until an operator restarts it. PR #104 (`feat/tries-catch-up-at-startup`) covers only the restart.

---

## Goal

A node whose cumulative tries (`cpo-trie.json`, `spi-trie.json`) go behind the bridge-state singleton while the daemon is up reconciles itself at the next batch opportunity and resumes building, with no restart and no operator. The reconciliation is visible on `/health` and in the log. A node that cannot reconcile says so once, not every minute. The co-sign gate's behaviour is decided explicitly.

## Out of scope

- A node with no `protocol.state_dir`. It keeps no tries at all and is warned once per movement by `record_movement_phase`; nothing here changes that.
- The leader-proposes-TM wire format (`/sign/{epoch}/tm.json`). It does not exist; the co-sign decision below is written so it survives its arrival.
- Changing what `reconstruct` / `reconstruct_spi` compute. The walk, its cross-checks and its refusal to persist an unattested root are reused verbatim; the repairer harvests once for both tries and reads back the singleton state the walk verified against (§A).

---

## What the code does today

Read from `src/epoch/machine.rs`, `src/epoch/signing.rs` and `src/main.rs` on this branch (`033e7b6`).

### How the tries advance

`pending-tm.json` is a write-ahead journal of **this node's own** last movement. `record_movement_phase` writes it after `submit_phase`; `settle_pending_tm`, called from inside `collect_pegins_phase` at every batch opportunity, folds it once `query_treasury` shows the head has moved off the outpoint the movement spends. The fold is checked, not replayed: `advance_cpo_trie` / `advance_spi_trie` insert the journal's entries and refuse to persist unless the result equals the roots the movement committed.

Nothing else advances the tries. A movement this node did not post leaves no journal entry, so a movement that confirms without this node's participation is invisible to it until a comparison against the singleton fails.

### How a running node goes behind

The triggers are ordinary, not exotic:

1. **Excluded from a ceremony** — the WI-067 handshake dropped it, DKG did not qualify it, or a round timed out — while the rest of the roster built, signed and confirmed a movement. No journal entry.
2. **Failed between build and record** — its own submit failed locally, but the movement is deterministic and a peer's submit landed. No journal entry.
3. **Stale journal entry** — it posted a movement that never mined, and the chain later confirmed a *different* movement on top of the same head (a later batch it was excluded from, or a federation spend). The entry exists and the fold is refused.

Case 3 is the WI's "refused FOLD"; cases 1 and 2 are its "refused BUILD".

### What each refusal costs, precisely

This is worse than "inert". The retry ramp in `drive_to_movement` treats both refusals as transient, because `rejects_the_batch` fires only for `BuildTm` + `EpochError::BatchRejected`, and both refusals are `EpochError::TmBuild`.

| Refusal | Site | Phase | What the loop does |
|---|---|---|---|
| FOLD | `advance_cpo_trie` / `advance_spi_trie` via `settle_pending_tm` | `CollectPegins` | Opportunity handed back. Back off 2 s → 60 s, re-enter `CollectPegins`, `query_treasury`, refuse again. `PendingTm::clear` is never reached. Nothing downstream ever runs. |
| BUILD | `cross_check_bridge_roots` | `BuildTm` | Opportunity handed back. Back off 2 s → 60 s, re-enter `CollectPegins` (full peg-in scan), enter `BuildTm` (treasury and peg-out reads), refuse again. |
| CO-SIGN | `verify_cpo_root` / `verify_spi_root` | `Sign` round 1 | Only reachable if the on-disk trie changed *between* build and sign — the TM is self-built from the same trie moments earlier. Near-tautological today. |

So a behind node runs one refusal per `retry_backoff_max` (60 s) for the rest of the process's life: ~60 log lines and, for the BUILD case, ~60 full chain-read passes per hour, on every opportunity, until someone restarts it. The ramp WI-097 added bounds the *rate*; nothing bounds the *duration*, and nothing heals.

### What PR #104 added, and its edges

`catch_up_tries` in `main.rs` runs once at startup, after step 3 has resolved the Config: `local_tries_status` against `fetch_bridge_state`, keep a copy on `Diverged`/`Unreadable`, `run_reconstruct_cpo_trie` then `run_reconstruct_spi_trie`, clear `pending-tm.json` unless the status was `Unreadable`, set `tries_rebuilt_at_startup` on `/health`.

Two properties of that code decide the shape of the runtime path:

- **It is in the binary crate and cannot run inside the daemon.** `run_reconstruct_*` and `resolve_bridge_contracts` each build their own `tokio::runtime::Runtime` and `block_on` it, and print with `println!`. Called from a tokio worker thread that panics. The epoch machine lives in the library crate and cannot see `main.rs` anyway. The async cores it wraps — `cpo_trie::reconstruct`, `cpo_trie::reconstruct_spi`, `CpoHistorySource` — are in the library and are directly awaitable.
- **It writes the cpo trie before it starts the spi walk.** If the spi walk fails, the node holds a rebuilt cpo trie, the old spi trie and its journal entry. `settle_pending_tm` then inserts the entry's peg-outs into a trie that already contains them, reaches a different root and refuses — the 60 s loop above — until the next restart, whose status is `Diverged` on spi and repairs both. A narrow startup-only window, recoverable by restart, but the runtime path must not inherit it.

---

## Before implementing

*Added 2026-09-14, after checking this document against the code at `3faf16a`. The sections below are amended to match.* No separate implementation plan: "Changes by file", "Tests" and "Rollout" are the plan. Three things had to be settled first.

### A. The roots must come from the state whose head the movement spends

**The gap.** The head and the roots are two fields of one singleton UTxO, read by two paths. `query_treasury` reads the head through the Blockfrost-compatible API (`query_config_singleton`). `query_bridge_roots` reads the roots, and both reconstruction walks read their history, through Kupo when `cardano.kupo_url` is set. Each walk checks itself only against its own read of the singleton (`harvest_confirmed_chain`). No comparison looks at the head. So "the tries match the chain" means "the tries match the state the roots backend is serving", which can be older than the head the batch spends. Hosted Blockfrost's load-balanced replicas can do the same without Kupo.

**On `main` today.** A node that missed movement M has no journal entry for it. It passes `cross_check_bridge_roots` whenever its roots backend has not yet seen M's Confirm and its head backend has. `build_tm_phase` then spends M's output with a cpo trie that lacks M's peg-outs. Since WI-031 that trie is the only already-paid record, and M's requests stay open on Cardano until their owners complete them, so the batch pays them again. Only nodes that missed M are exposed. They build a movement their up-to-date peers do not, so the usual cost is their round — unless enough of them to reach the threshold share the stale view.

**What this item would add.** `reconcile_tries` is a second writer of the tries, and it follows the roots backend. With that backend behind a Confirm, it would rewind a node that signed M and folded it correctly, which makes a threshold of stale nodes far easier to reach.

**Decision.** Enforce the invariant wherever the tries are compared or written:

- `BridgeRoots` gains `head: bitcoin::OutPoint`, decoded from the same `fetch_bridge_state` read as the roots. One `BridgeState::treasury_outpoint()` does the decoding, and `query_treasury` switches to it, so the two sides cannot disagree about byte order.
- `cross_check_bridge_roots` takes the head `build_tm_phase` just read and refuses when `roots.head` differs.
- `reconcile_tries` compares heads before roots, and on a mismatch compares and writes nothing.
- The repairer takes the head the caller will spend and saves nothing unless its walk attests that head. Both tries come from ONE `harvest_confirmed_chain`, so one singleton read attests the pair, and the TM address history is walked once, not twice. `reconstruct` / `reconstruct_spi` keep their CLI signatures.

A head mismatch is chain-read skew, not a verdict on the tries. It returns `EpochError::Chain`, goes to the ramp like any failed read and retries within the window. It is never `TriesBehind`. Lag heals in seconds. A stuck indexer produces one warning per `retry_backoff_max` naming both heads, the same cadence a folded node gets from `cross_check_bridge_roots` today.

It ships first, in #104 itself (Rollout 0). #104 exists because a node's tries and the chain disagreed, and this is the deeper half of that fault, found while fixing it.

### B. Any fold error goes to the singleton, not only a root mismatch

`settle_pending_tm` returns `EpochError::TmBuild(String)` for all of these alike: an unreadable journal, an unreadable trie, a `Conflict`, a root mismatch, a failed write. "The divergence error" cannot be picked out without parsing strings.

**Decision: no typed refusal.** The fold becomes the fast path, and the gate is the singleton comparison: the tries must equal the roots attested at the head this batch spends (A). That is what `cross_check_bridge_roots` already enforces, so proceeding past a fold error is no weaker than today. The fold's error is kept as the reason, and step 2 decides:

| After a fold error, the tries are | Then |
|---|---|
| `InSync` | The journal describes nothing still owed, because the tries already match the chain at the head being spent. Move `pending-tm.json` aside as `pending-tm.json.superseded-<stamp>`, kept as evidence like the trie copies. Log once, continue, no walk. |
| `Diverged` / `NeverSeeded` / `Unreadable` | Repair, with #104's record-clearing rule unchanged. |
| not comparable: `query_bridge_roots` is `None`, which only mocks and the demo reach, since `run_spo` always configures the singleton | The fold error propagates exactly as today. |

The rejected alternative, a typed refusal, heals only the root mismatch. A corrupt `pending-tm.json` or trie file would stay on the 60 s loop this item exists to end.

### C. Measure the repair over the backends nodes run, before fixing its budget

The only number we have is the operator guide's "seconds on this bridge" (§4), which says nothing about growth. Time `reconstruct-tries --dry-run` on the shared preprod bridge over Dolos, hosted Blockfrost and Kupo. That settles `TRIES_REPAIR_BUDGET` and the Blockfrost-refusal question before Rollout 3.

Dolos matters most. It is the backend SPOs are meant to run (WI-064), and it now serves the walk's endpoints (rssh, 2026-09-14).

---

## Design

### One reconciliation point, not three

The WI lists three sites. Two of them share one cause and one detection: the local roots differ from the singleton's. That fact is readable at `CollectPegins`, before the batch is frozen and before the peg-in scan, which is where `settle_pending_tm` already runs and which its own doc names as "wherever the head is read". Healing there is strictly earlier and strictly cheaper than healing at `BuildTm`, and it makes `cross_check_bridge_roots` what a safety gate should be: a check that fires only if the state changed between two reads a few seconds apart.

So:

- **`CollectPegins`** gets `reconcile_tries`, replacing the bare `settle_pending_tm` call. It heals both the refused FOLD and the would-be refused BUILD.
- **`BuildTm`**'s `cross_check_bridge_roots` keeps its refusal and gains the head check (§A). It is now expected never to fire; when it does, refusing is correct.
- **`Sign`**'s `verify_cpo_root` / `verify_spi_root` are unchanged, by decision (below).

### `reconcile_tries` — the runtime site

Called inside the opportunity loop of `collect_pegins_phase`, exactly where `settle_pending_tm(config, &treasury)?` is today:

1. `settle_pending_tm(config, &treasury)`, the fast path. On any error, keep the error text (it *is* the diagnosis) and continue to 2 (§B).
2. `chain.query_bridge_roots().await?`.
   - `None`: no singleton is configured, which only mocks and the demo reach. Nothing to compare against, so a fold error from 1 propagates as today. Otherwise return `Ok` and let `BuildTm` report `CpoTrust::Unverified` as it does now.
   - `Some(roots)` with `roots.head != treasury.outpoint`: the two reads describe different singleton states. Return a retriable `EpochError::Chain` naming both heads, and compare and write nothing (§A).
   - Otherwise `local_tries_status(state_dir, roots.cpo_root, roots.spi_root)`. `InSync` → move aside a journal the fold refused (§B) and return `Ok`. Anything else → 3.
3. Repair, once, under a budget (below), for the head `treasury.outpoint`. On success, log at event level, record it on `/health` and return `Ok`; the phase continues into the peg-in scan on tries that now match the chain. On `RepairError::HeadMoved`, return the same retriable error as step 2. On any other failure, return `EpochError::TriesBehind { why }`.

The record-clearing rule is #104's, unchanged: cleared on `Diverged` and `NeverSeeded` (the chain has moved past this node), kept on `Unreadable` (a movement may still be in flight and the record is the only thing that will fold it). It must clear on the refused-FOLD path too, or the node wedges exactly as the comment in `catch_up_tries` describes.

`query_treasury` and `query_bridge_roots` are two reads, on two backends when `kupo_url` is set, so they can describe different singleton states. On roots alone neither order is safe. The head comparison in step 2 makes it safe: a Confirm landing between the reads, or one indexer behind the other, becomes a retry instead of a repair (§A).

Cost in the steady state: one `query_bridge_roots` and two small file loads per opportunity, every ~6 h. Nothing new is read on the retry loop.

### The repair core moves into the library

New module `crate::cardano::tries_repair`:

```rust
#[async_trait]
pub trait TriesRepairer: Send + Sync + std::fmt::Debug {
    /// Rebuild both tries from chain history into `state_dir`, replacing what is
    /// there. `status` is what the caller found; it decides keep-a-copy and
    /// whether pending-tm.json may be dropped. `head` is the treasury head the
    /// caller will spend: nothing is saved unless the walk attests exactly that
    /// head (§A). Returns the one-line reason for the health surface.
    async fn repair(
        &self,
        state_dir: &Path,
        status: &TriesStatus,
        why: &str,
        head: bitcoin::OutPoint,
    ) -> Result<String, RepairError>;
}

pub enum RepairError {
    /// The walk's singleton read is at another head: chain-read skew, retriable.
    HeadMoved { walked: bitcoin::OutPoint, expected: bitcoin::OutPoint },
    /// The walk failed, ran out of budget, or could not save. Spends the opportunity.
    Failed(String),
}

pub struct ChainTriesRepairer {
    source: Box<dyn CpoHistorySource>,   // Kupo if cardano.kupo_url, else Blockfrost
    recon: ReconstructConfig,            // from BridgeContracts, resolved once at startup
    budget: Duration,
}
```

`ChainTriesRepairer::repair` does, in order:

1. Keep a copy on `Diverged`/`Unreadable`.
2. Under `tokio::time::timeout(budget, ..)`, run **one** `harvest_confirmed_chain` and both replays from it, in memory.
3. Return `HeadMoved` unless the harvested singleton's head is `head`.
4. Save both files, so a failed replay leaves both untouched.
5. `PendingTm::clear` per the rule above.

It logs through `tracing`, never `println!`.

Three callers, one core:

- `catch_up_tries` (startup) becomes: build the repairer, `local_tries_status`, `repair`. Same log lines and gauge as today. Its early-return reasons ("could not even look") stay, because the preflight gate reads them.
- `reconstruct-tries` / `reconstruct-cpo-trie` / `reconstruct-spi-trie` (CLI) keep their `println!` reporting around the same `reconstruct*` calls. They do not go through `TriesRepairer`; they are the operator's read-and-write tool and their output is their interface.
- `reconcile_tries` (runtime) calls it through `EpochConfig`.

`EpochConfig` gains `tries_repair: Option<Arc<dyn TriesRepairer>>`. `to_epoch_config` sets `None`; `run_spo` sets it after the Config has resolved and only when `state_dir` is set — the same gate #104 put on the startup repair, for the same reason: the rebuild writes state derived from whichever bridge the config names. Mocks and tests use a fake repairer that writes known files; `None` means "cannot repair", which reaches the operator as `TriesBehind`.

### Budget

`TRIES_REPAIR_BUDGET`, compiled in beside `RETRY_BACKOFF_MAX`, not an operator key. Starting value **10 minutes**: far inside the ~6 h grid pitch, far beyond any Kupo walk (one request per address), and enough for a Blockfrost walk of a preprod-sized history. **Measure `reconstruct-tries` on preprod over Blockfrost before fixing the number.** A timeout is a failure with a message that names Kupo, because a bridge whose history no longer fits the budget over Blockfrost is a node that should be running the recommended backend.

### Failure policy: spend the opportunity, say it once

A failed repair returns `EpochError::TriesBehind`. Two changes make it terminal for the opportunity rather than a 60 s loop:

- `rejects_the_batch` gains the arm `stepped == "CollectPegins" && matches!(cause, TriesBehind)`. The existing phase condition was written to keep a transient trie-write blip from spending an opportunity; a repair that ran to failure under its budget is not a blip. `spends_the_opportunity` already hands the opportunity back on a no-grid chain, so demo and mock configurations keep the ramp instead.
- The `deterministic` arm's warning says "failed on the frozen batch"; `TriesBehind` gets its own wording, because at `CollectPegins` nothing is frozen.

The node therefore attempts one repair per opportunity, logs one warning per attempt, and waits for the next grid line. That is honest: a node whose tries are behind can neither build nor co-sign at this opportunity, so sitting it out costs nothing the loop could have recovered. If a within-window retry is wanted later, the alternative is a memo keyed on `(epoch, batch index)` that re-raises the last error without walking the chain; it is more state for a benefit that only shows on a transient failure in the first minutes of a window.

A head mismatch, whether from step 2 or `RepairError::HeadMoved`, is not a failed repair and gets none of this. It is chain-read skew, and the ramp retries it within the window (§A).

Log on change, gauge in health, as for `stranded_pegins`: a repeat failure with the same reason logs at debug; the standing condition lives on `/health`.

### Health surface

`tries_rebuilt_at_startup: Option<String>` stays as documented. Alongside it:

```rust
/// Runtime repairs this process has done, newest last, as
/// "epoch <n> B_<i>: <why>". Capped (last 8).
pub tries_rebuilt_at_runtime: Vec<String>,
/// The standing reason the last runtime repair failed; cleared on success.
pub tries_repair_failed: Option<String>,
```

`heimdall status` prints both. Operator guidance: one runtime repair is a node that missed a ceremony and healed; a runtime repair every epoch is a node that is being *excluded* every epoch, and the cause is on the same page under `dkg_qualified` and the WI-067 exclusion reason. A `tries_repair_failed` that stands across two opportunities is an operator's problem: run `reconstruct-tries --dry-run` and read why.

### The co-sign gate stays as it is — decision

`verify_cpo_root` and `verify_spi_root` keep refusing without repairing, and the call site in `signing.rs` gets a comment saying so and why:

1. It runs mid-ceremony, before the first nonce commitment, against round deadlines measured in minutes. A chain walk there can cost the round for every other participant, not only this node. A node that misses one ceremony and heals at the next opportunity is strictly better than one that stalls inside it.
2. Today it can only fire if the on-disk trie changed between build and sign — a concurrent `reconstruct-*`, an operator edit, a corrupt file. Repairing there races with whatever changed the file.
3. Once a leader-proposed TM arrives over the wire, this is the one place where "rebuild until I agree with the proposer" would be exactly wrong. The gate's value is that it is an *independent* recomputation; a co-signer that reconciles itself to the proposal is not independent. With `reconcile_tries` upstream, an honest co-signer that disagrees here is either racing a file change or looking at a dishonest proposal, and refusing is right in both.

---

## Changes by file

### `src/cardano/tries_repair.rs` (new)
`TriesRepairer`, `RepairError`, `ChainTriesRepairer`, `TRIES_REPAIR_BUDGET`. Keep-a-copy, one harvest for both tries, the attested-head check, both-or-neither saves, record-clearing rule, `tracing` output.

### `src/cardano/bridge_state.rs`
- `BridgeState::treasury_outpoint()`, the one decoding of field 2. `query_treasury` and `main.rs`'s other hand-rolled copy switch to it.

### `src/cardano/cpo_trie.rs`
- Harvest once and replay both tries from it, returning the attested `BridgeState` with them. `reconstruct` / `reconstruct_spi` stay as the CLI's wrappers.

### `src/epoch/traits.rs`, `src/cardano/blockfrost_chain.rs`, `src/epoch/mocks.rs`
- `BridgeRoots.head: bitcoin::OutPoint`, filled from the same `fetch_bridge_state` read as the roots. The mock stores only the roots (`MockBridgeRoots`) and reports the head `query_treasury` reads, so a test can put them out of step only on purpose, through `with_roots_read_at` (tests 10 and 11).

### `src/main.rs`
- `catch_up_tries`: build `ChainTriesRepairer` from `cfg` + `resolve_bridge_contracts`, and call `repair` with the head from the singleton read it already makes. Delete the copy/clear logic it duplicates.
- `run_spo`: construct the repairer after the Config resolves, when `state_dir` is set, and put it on the `EpochConfig`.
- `run_reconstruct_cpo_trie` / `run_reconstruct_spi_trie`: unchanged in behaviour; share the backend-selection helper with the repairer.

### `src/epoch/state.rs`
- `EpochConfig.tries_repair: Option<Arc<dyn TriesRepairer>>`; `demo_default` and `to_epoch_config` set `None`.
- `EpochError::TriesBehind { why: String }`.

### `src/epoch/machine.rs`
- `reconcile_tries` (new), called from `collect_pegins_phase` in place of the bare `settle_pending_tm` call: fold, head check, status, then move a refused journal aside or repair (§A, §B).
- `cross_check_bridge_roots`: takes the head `build_tm_phase` read and refuses when `roots.head` differs (§A, Rollout 0).
- `rejects_the_batch`: the `CollectPegins` + `TriesBehind` arm.
- `drive_to_movement`: `TriesBehind` wording in the deterministic arm; health update on success and failure.
- `advance_cpo_trie` / `advance_spi_trie`: message no longer tells the operator to run `reconstruct-cpo-trie`; it says the node will reconcile at this opportunity.

### `src/epoch/signing.rs`
- Comment at the `verify_cpo_root` / `verify_spi_root` call site recording the decision above. No code change.

### `src/health.rs`
- The two fields; `status` rendering.

### `docs/operator-guide.md`
- New subsection after "The node seeds its own state": "The node reconciles while running" — what triggers it, what the log and `/health` show, what a repeat means, what a standing failure means.
- The troubleshooting row for `trie diverged` / `trie is out of sync`: "the node reconciles itself at the next opportunity; if `tries_repair_failed` is set, run `reconstruct-tries --dry-run` to see why".

---

## Tests (acceptance: `cargo test`)

`machine.rs`, with the existing mock chain and a fake `TriesRepairer` that writes files whose roots equal the mock's `query_bridge_roots`:

1. **No journal, roots differ** → `collect_pegins_phase` calls the repairer once and returns `BuildTm`; the tries on disk match; the health list has one entry.
2. **Stale journal, refused fold** → repairer called once, `pending-tm.json` gone, phase continues; the fold error text is in the health entry.
3. **Journal for an in-flight movement, roots match** → repairer not called; journal kept.
4. **`Unreadable` file** → repairer called, journal kept, copy exists.
5. **Repairer returns `Err`** → `TriesBehind`; through `drive_to_movement` with the fast config the opportunity is spent (`built` still marked), the repairer was called exactly once, `tries_repair_failed` is set; the next opportunity calls it again and a success clears the field.
6. **Repairer exceeds the budget** (fake sleeps past a test-sized budget) → same as 5, message names the budget.
7. **`tries_repair: None`, roots differ** → `TriesBehind` with "this node cannot rebuild"; opportunity spent.
8. **No `cpo_policy_id`** (`query_bridge_roots` → `None`) → repairer not called; `BuildTm` reports `Unverified` as today. With a refused fold, the fold's error propagates unchanged (§B).

`tries_repair.rs`:

9. **spi replay fails after the cpo replay succeeds** → neither file changed, journal kept.

Added by §A and §B:

10. **Head skew at `BuildTm`**: the tries equal the roots, but `roots.head` differs from the treasury head → `cross_check_bridge_roots` refuses with a `Chain` error naming both heads (`bridge_roots_cross_check_refuses_roots_read_at_another_head`), and `build_tm_phase` with a withdrawal waiting builds nothing (`a_withdrawal_is_not_paid_on_roots_read_at_another_head`). This is the regression test for the gap on `main`, and it shipped in Rollout 0.
11. **Head skew at `CollectPegins`**: `roots.head` differs and the tries differ → the repairer is not called, nothing is written, the journal is kept; through `drive_to_movement` the opportunity is handed back, not spent.
12. **Refused fold, tries already `InSync`** → the repairer is not called, `pending-tm.json` is moved aside, and the phase continues.
13. **Unreadable `pending-tm.json`, tries `InSync`** → the same as 12, instead of today's 60 s loop.
14. (`tries_repair.rs`) **The harvested singleton is at another head** → `HeadMoved`, neither file written, journal kept.

`signing.rs`: existing `verify_committed_root_refuses_*` tests unchanged, plus one asserting `verify_cpo_root` refuses with a repairer configured — the gate must not become reachable to the repairer by accident.

---

## Rollout

0. **Done, in #104.** The head check: `BridgeState::treasury_outpoint`, `BridgeRoots.head`, `cross_check_bridge_roots` refusing on a mismatch, and test 10. It closes a gap `main` has today.
1. Measure (§C), in parallel with 0, and confirm or change `TRIES_REPAIR_BUDGET` before step 3.
2. Extract the core into `tries_repair.rs` (one harvest, the attested head, both-or-neither) and point `catch_up_tries` at it. No behaviour change beyond refusing a half-saved pair and a walk at another head. Branch off `main` once #104 has merged, not stacked on it: merging a base branch with `--delete-branch` closes the PR stacked on it.
3. `EpochConfig.tries_repair`, `TriesBehind`, `reconcile_tries`, ramp arm, health fields, tests 1–9 and 11–14.
4. Signing comment, operator guide.

## Open questions

- **Budget value.** 10 min is a proposal, not a measurement. Step 1 settles it.
- **Blockfrost quota.** A Blockfrost rebuild is ~1 request per transaction in the TM and peg-out address histories and grows with the bridge's age. Kupo is the production answer and already the documented recommendation; the runtime path inherits the CLI's backend selection, so a Kupo node pays one request. The intended SPO shape, though, is Dolos (WI-064), which now serves the walk (§C). Whether to *refuse* runtime repair over Blockfrost above some history size, rather than let the budget catch it, is a call for after the measurement.
- **Same-window retry.** Spending the opportunity is proposed for its simplicity. If a transient failure early in a window turns out to be common on preprod, the memo alternative above restores in-window retries without restoring chain walks.
