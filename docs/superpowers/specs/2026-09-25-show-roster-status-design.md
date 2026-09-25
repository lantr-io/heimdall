# `show-roster`: stake, health and cascade per pool

Date: 2026-09-25. Status: implemented.

## Purpose

`show-roster` tells an operator who is in the roster. It does not tell them who
holds the stake, which peers are up, or who posts the next Treasury Movement. An
operator who asks "which SPO stopped participating?" today reads journal logs on
several hosts. This change puts those answers in one read-only command.

## Definitions

- **Roster** – the DKG participants for the current epoch, as `derive_dkg_context`
  derives them today (registry minus active bans, stake-filtered).
- **SPO index** – the FROST identifier of a roster member: its 1-based rank when the
  roster is sorted lexicographically by `bifrost_id_pk`.
- **Stake source** – where the per-pool stake comes from: the epoch snapshot
  (`active_stake`), or `live_stake` when `cardano.demo_live_stake` is set.
- **Stake share** – the stake of one roster member divided by the total stake of the
  roster, as a percentage.
- **Probe** – one `GET /health` request to the `bifrost_url` of a roster member.
- **Own build** – the `PeerBuild` this node would serve from its own `/health`.
- **Next TM** – the Treasury Movement for the next batch opportunity `B_i` after the
  current slot.
- **Cascade** – the posting order that `Cascade::elect` computes for the next TM:
  the leader, then hop 1, hop 2, and so on.

## Scope

In scope: the default output of `show-roster`, and a new `--verbose` flag.

Out of scope:

- A git commit field in `/health`. The version column shows `CARGO_PKG_VERSION` only.
- JSON output.
- `--urls`. Its output does not change.
- Roster, threshold and ban derivation. This change only displays them.
- `Specification.md:580` omits `tm_sequence` from the leader hash. That is a
  separate spec fix.

## Operation: print the roster status

1. **Purpose** – print the roster with stake, health and cascade position per pool.
2. **Who** – an operator, on any node with a valid config.
3. **Trigger** – `heimdall show-roster --config <path>`, without `--urls`.
4. **Structure**

   | Input | Source |
   |---|---|
   | Registry, bans, roster, threshold | the existing `run_show_roster` path |
   | Stake source | `cardano.demo_live_stake`, `cardano.stake_source` |
   | Batch grid | Config schedule (`GridParams`) and the current slot |
   | `prev_tm_txid` | txid of the treasury outpoint the chain names now |
   | Health | one probe per roster member |

   | Output | Form |
   |---|---|
   | Header | 3 lines, see [SR-1]..[SR-4] |
   | Pool blocks | one per roster member, see [SR-5]..[SR-14] |
   | Excluded list | see [SR-15] |
   | Details | only with `--verbose`, see [SR-16] |

5. **Checks enforced here** – below.
6. **Checks delegated elsewhere** – None. The command posts nothing and gates nothing.

### Header

- `show-roster` MUST print the current epoch, the stake source, and the threshold as `t of n`. `[SR-1]`
- On a virtual-epoch deployment, `show-roster` MUST print the bridge epoch after the Cardano epoch, as `epoch 315 (bridge epoch 1558)`. `[SR-1a]`
- `show-roster` MUST print the stake source as `epoch snapshot` or `live_stake (TEST RUN)`. `[SR-2]`
- `show-roster` MUST print the total roster stake in ADA and the count of active bans. `[SR-3]`
- `show-roster` MUST print the next TM line: batch index, UTC time of `B_i`, `prev_tm_txid`, and the cascade as SPO indices. `[SR-4]`
- `show-roster` MUST print `no batch left this epoch` when `GridParams::next` returns `None`. `[SR-4a]`

*Example, illustrative.*

```
epoch 315 (bridge epoch 1558) · stake: live_stake (TEST RUN) · threshold 6 of 7 (20% security threshold)
total stake 2,347,561.96 ADA · bans: 0 active
next TM: batch B_3 at 09:00 UTC, spends 0067141b…7f27 · cascade #5 → #1 → #7 → #2 → #3 → #6 → #4
```

**Why:** the stake source changes who clears the threshold. A test run that
looks like a snapshot run misleads the reader about the security of the roster.

### Pool blocks

- `show-roster` MUST print one block per roster member. `[SR-5]`
- `show-roster` MUST sort the blocks by stake, descending. `[SR-6]`
- `show-roster` MUST break a stake tie by SPO index, ascending. `[SR-7]`
- The first line of a block MUST hold the SPO index, the bech32 pool id, the stake in ADA and the stake share. `[SR-8]`
- `show-roster` MUST print the stake in ADA with 2 decimals and the share with 2 decimals. `[SR-9]`
- A block MUST print `bifrost_id_pk` and `bifrost_url` in full. `[SR-10]`
- A block MUST NOT print the element UTxO. `[SR-11]`

**Why:** the sort answers "who holds the stake", and the index answers "which
FROST identifier is this". Both are needed, so the index stays on each line
while the order follows stake. Full keys stay copyable into other commands.

*Example, illustrative.*

```
#5  pool1yzwxetclm2l48xzvmnwwf6x48a5qze0nx4t6glz5k8wk50xl006  stake 1,403,765.24 ADA (59.80%)
    bifrost_id_pk: a873dffb8f996938fcb633c450b8bcd39c8e43e829301db59ddfc908fb2192bb
    bifrost_url:   https://bifrost.xstakepool.com
    health:  up 132ms · v0.9.3 · blueprint ✓ roster ✓ · dkg 1557/17
    cascade: leader
```

#### Health line

- `show-roster` MUST send the probes in parallel through `PeerNetwork::check_health`. `[SR-12]`
- The health line MUST read `up <ms>ms` for a reachable peer, with the latency measured around the probe. `[SR-12a]`
- The health line MUST read `down` for an unreachable peer, and nothing more. `[SR-12b]`
- A reachable health line MUST show the version, the blueprint mark, the roster mark and the last DKG. `[SR-12c]`
- A mark MUST be `✓` when the peer field equals the own-build field, `✗` when it differs, and `?` when the peer omits it. `[SR-12d]`
- The last DKG MUST read `dkg <epoch>/<attempt>` from `published_dkg`, or `dkg -` when absent. `[SR-12e]`
- A failed probe MUST NOT change the exit status of `show-roster`. `[SR-13]`

**Why:** `check_health` already gives the pre-ceremony gate its verdict. Reusing
it means the table and the gate cannot disagree about a peer. It returns no
failure reason, so `down` carries none. Adding one is a change to the gate.

*Example, illustrative.* Own `roster_digest = ab12…`:

| Peer `roster_digest` | Mark |
|---|---|
| `ab12…` | `✓` |
| `cd34…` | `✗` |
| field absent (older build) | `?` |

#### Cascade line

- `show-roster` MUST compute the cascade with `Roster::cascade(prev_tm_txid, TmSequence::Tm(i))`, where `i` is the next batch index. `[SR-14]`
- The cascade line MUST read `leader` for the elected member, and `hop N (+N×leader_slot_t slots)` for the others. `[SR-14a]`
- The cascade line MUST NOT print an absolute slot. `[SR-14b]`

**Why:** the eligible slot is `signing_complete_slot + hops × leader_slot_t`.
`signing_complete_slot` does not exist until signing ends, so an absolute slot
would be a guess.

*Example, illustrative.* `leader_slot_t = 600`, roster of 7, leader `#5`:

| Member | Cascade line |
|---|---|
| `#5` | `leader` |
| `#1` | `hop 1 (+600 slots)` |
| `#4` | `hop 6 (+3600 slots)` |

### Excluded pools

- `show-roster` MUST list the registered pools that are not in the roster after the pool blocks, each with its reason and without an SPO index. `[SR-15]`

### Verbose details

- With `--verbose`, `show-roster` MUST also print the registry policy, the registry address, the `treasury_info` address, the registry source and the identity-root check. `[SR-16]`

**Why:** those lines prove the roster came from the right contracts. An auditor
needs them. An operator who checks liveness does not.

## Testing

- Unit tests on the formatter, with a fixed roster, fixed probe results and a known `prev_tm_txid`. They cover [SR-2], [SR-6], [SR-7], [SR-9], [SR-12a]..[SR-12e] and [SR-14a].
- A unit test in which one peer is `down` and the command still renders every block. It covers [SR-13].
- A manual run on fed1 against preprod before merge.
