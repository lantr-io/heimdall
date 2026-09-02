# SPO preprod pilot — overview

This pilot tests whether independent stake pool operators can join and operate the Heimdall SPO
program on Cardano preprod by following the published [operator guide](operator-guide.md).
The pilot uses the Testnet Bifrost deployment at https://bifrost.fluidtokens.com/.

---

## What we are testing

| Stage | What it should demonstrate |
|---|---|
| 0. Setup | An SPO can install, configure, validate and expose a Heimdall node from the guide. |
| 1. Registration and DKG | The SPO can register on chain, appear in the roster and qualify in a DKG ceremony. |
| 2. Upgrade | The node can move from the initial release to the target release without losing configuration, identity or protocol state. |
| 3. Crash and recovery | The node returns to a healthy state after an assigned interruption and behaves correctly for the point in the protocol at which it stopped. |
| 4. Deregistration | The SPO can leave using the published procedure and all nodes observe the updated roster. |
| 5. Federation recovery | The bridge follows the documented post-DKG federation recovery procedure when the active SPO signing group is unavailable. |

Throughout the pilot, the coordination team will initiate a small number of deposits and
withdrawals. SPO nodes will observe and participate in the resulting protocol activity.

---

## Participants and responsibilities

The target topology is **five external SPO nodes plus three coordination-team nodes**.

| Role | Responsibilities |
|---|---|
| Coordination team | Deploy and monitor the bridge, publish the configuration pack, operate three nodes, schedule stage gates, initiate test transactions, maintain the test ledger and coordinate federation recovery. |
| External SPO | Follow the operator guide, run one Heimdall node, preserve its keys and state, perform assigned test actions, report each checkpoint and raise problems promptly. |
| Stage lead | Announce the start and end of each stage, decide whether the group advances, and record transaction IDs, epoch/cycle numbers and known issues. |

Telegram is the live support channel. After every stage, each operator submits the
[short feedback form](https://forms.gle/etc4vRVaQbTkekEJ9).

---

## Timeline

The pilot runs from **2 to 13 September 2026**.

| When | Stage | Main activity |
|---|---|---|
| 2–6 Sep | 0. Prerequisites and setup | Prepare the preprod pool, test funds and delegation, Cardano provider, public endpoint, configuration pack and release artifacts. Install, configure and validate each node. |
| 7–8 Sep | 1. Registration and DKG | Register operators in two waves, confirm the roster and complete a DKG ceremony. Establish normal deposit and withdrawal behaviour. |
| 9–10 Sep | 2–3. Upgrade and recovery | Upgrade nodes in controlled waves, run assigned interruption scenarios and confirm recovery. |
| 11–12 Sep | 4. Deregistration | Follow the published deregistration procedure and confirm roster changes. This stage depends on the procedure being ready before the pilot. |
| 13 Sep | 5. Federation recovery and close | Make the active SPO signing group unavailable, perform the post-DKG federation recovery drill and collect final feedback. |
