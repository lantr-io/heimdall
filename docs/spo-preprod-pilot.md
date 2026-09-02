# Heimdall SPO preprod pilot — execution plan

- [Pilot overview](spo-preprod-overview.md)
- [Operator guide](operator-guide.md)
- [SPO feedback form](https://forms.gle/etc4vRVaQbTkekEJ9)

---

## Before the pilot

Each operator completes **Before you start** in the operator guide, arranges preprod test ADA and
delegation, and sends the coordination team their pool ID and public endpoint. The coordination
team confirms that every pool has visible live stake before Stage 0.

### Pilot rules

- Follow the security and dry-run instructions in the operator guide. Never share secrets or an
  unredacted config or log.
- Record times in UTC and keep local logs until the pilot closes.
- Wait for the stage lead before registration, interruption, deregistration or recovery actions.
- Report blockers immediately and submit one short feedback response after every stage.

---

## Stage 0 — Setup

Complete Quick path steps 1–5 in the operator guide using the assigned initial release, then stop
before registration.

The stage passes when:

- the installed version matches the assigned build;
- `doctor` matches the guide's expected pre-registration result; and
- the node configuration, identity key, persistent state and backup are ready.

Record the installation route, duration, outcome and any point where the guide was unclear.

---

## Stage 1 — Registration and DKG

The coordination-team nodes register first. External operators then complete Quick path steps 6–8
in two waves: two operators in Wave A and three in Wave B. All nodes must be running before the
announced virtual-cycle boundary.

The stage passes when:

- each registration transaction, roster entry and public endpoint is confirmed;
- `doctor` reports the node as registered; and
- after the target ceremony, every expected node is qualified with no unexplained peer exclusion,
  all nodes report the same cycle, and the expected key handoff is visible on chain.

Record the registration transaction ID, time to roster visibility and final DKG status.

### Test transactions

The coordination team runs one baseline deposit and one baseline withdrawal after Stage 1, then
keeps one request in flight during Stage 2 or 3. Record the request, Treasury Movement, Cardano and
Bitcoin transaction IDs in the coordinator ledger. Keep the volume low so failures remain
attributable.

---

## Stage 2 — Upgrade

Follow **Upgrades** in the operator guide. Upgrade within one maintenance window in three waves:
one coordination-team canary, two external operators, then the remaining nodes.

The stage passes when every node runs the target build, retains its identity, configuration and
state, returns to a healthy status, and no test transaction is lost or duplicated.

Record the old and new versions, downtime, state preservation and any manual workaround.

---

## Stage 3 — Crash and recovery

The stage lead assigns one scenario to each external operator:

| Scenario | Assignment |
|---|---|
| Process interruption and automatic restart | Two external nodes |
| Host reboot | Two external nodes |
| Container replacement with the same state volume | One external Docker node |

The coordination team may separately test a backup restore. Distribute interruptions across idle,
DKG and pending-movement periods, but never take enough nodes down simultaneously to cross the
active signing threshold.

The stage passes when each node returns to the healthy state described in **Operating it**, resumes
progress, and any DKG or signing impact is understood and recorded.

Record the scenario, interruption and recovery times, automatic or manual steps, and protocol
impact.

---

## Stage 4 — Deregistration

Follow **Deregistration** in the operator guide. Deregister external operators in waves of one, two and two. The stage passes when the transactions confirm, remaining nodes agree on the new roster, and departed nodes no longer
join new ceremonies.

Record each transaction ID, effective removal time and resulting roster.

---

## Stage 5 — Federation recovery

This is a coordination-team drill. Record the current roster key and treasury state, then stop
enough active SPO nodes to make the signing group unavailable. Confirm that the under-threshold
group cannot produce a movement. Once the CSV delay is satisfied, follow **Using the key later**
in the operator guide to produce and broadcast the federation recovery transaction, then reconcile
the final Cardano and Bitcoin state. Restore a healthy SPO roster if that is included in scope.

The stage passes when the threshold and CSV protections are enforced, one valid recovery movement
is confirmed, no duplicate payment occurs, and the final treasury state is agreed.

Record the signer threshold, CSV wait, transaction IDs, final treasury state and any manual step.

---

## Feedback and stage gates

After every assigned stage, submit the
[SPO feedback form](https://forms.gle/etc4vRVaQbTkekEJ9). A clean pass should take less than one
minute; add details only when something was unclear or unexpected.

The form records the operator, stage, outcome, active time and guide clarity. If something was
unexpected, briefly describe what happened and any workaround. Logs, screenshots and improvement
suggestions are optional. Redact all secrets before sharing evidence.

For a live blocker, post:

```text
Pilot / stage / UTC time:
SPO / version / install route:
Guide section:
Expected:
Observed:
Redacted error:
Blocking the stage? yes/no
```

The stage lead closes a stage after recording every operator's result, the expected roster and
cycle, relevant transaction IDs, unresolved issues and a decision to proceed, repeat or stop. Stop
the pilot for any risk of secret exposure, invalid signing, lost funds, duplicate payment or
unrecoverable state.
