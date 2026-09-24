# heimdall-discord

Relays a heimdall node's protocol events and warnings from its **log** to a
Discord channel. It is a separate program, not part of heimdall.

## Why it is separate

heimdall is the security-critical process: it holds the signing share and
talks to its peers, and an operator will not want it opening an outbound
connection to a chat service from inside their network. So heimdall sends
nothing anywhere. It marks the handful of lines worth an interruption with
the tracing target `heimdall::event`, files everything else at a level, and
that is the whole interface.

This tool reads what heimdall wrote and nothing else: no config, no key, no
chain access. It can run as a different user, under its own sandbox, or on
another host that receives the logs. The webhook URL is the one secret it
holds, and it comes from the environment or a file — never the command line,
where `ps` would show it.

## What gets relayed

The `heimdall::event` lines — one line each, self-contained. Nearly all are `info`;
the failure counterpart of an event is `warn` on the same target. Being an EVENT is
what keeps it wherever its successful twin is kept — otherwise `--min-level error`
shows every `treasury movement posted` and none of the misses. Being `warn` earns it the ⚠️ and
keeps it under `--no-events --min-level warn`:

| event | when |
|---|---|
| `key generation round 1 opened (attempt N): 4 members, threshold 2. Participants: pool1… (http://…), …` | the ceremony opens; the participant list is the roster |
| `key generation round 2 opened (attempt N): round 1 packages in from 3 of 4 — pool1… (http://…), …` | who made it into round 2, named |
| `key generation round 3 opened (attempt N): round 2 shares in from 3 of 4 — pool1… (http://…), …` | whose shares arrived |
| `key generation complete (attempt N): group key … — 3 share holders, threshold 2. Final roster: pool1… (http://…), …` | the group key, and who holds a share of it |
| `⚠️ key generation ABORTED (attempt N): 2 of 4 eligible qualified — …. Excluded: …` | this ceremony produced no key, naming who was excluded; a later attempt this epoch still may succeed |
| `registry: 5 registered, 4 eligible: pool1… (http://…), … — NOT eligible: pool1… (no stake at this epoch's snapshot …)` | only when it CHANGES: someone joined, left, was banned, or their stake activated |
| `⚠️ FAULT BAN FAILED: a <kind> by pool … could not be published (…)` | a misbehaving SPO stays in the roster and enters the next ceremony |
| `group key for bridge epoch E: …; the treasury address it produces is tb1p…` | where this epoch's handoff pays the treasury |
| `key handoff posted: Cardano tx … — the treasury key becomes …, was …` | the rotation is on Cardano (also the federation-handoff form) |
| `⚠️ Update-Y FAILED: the key handoff has failed N retries running this epoch — parking until the next boundary` | this node has stopped expecting a rotation; the epoch's whole batch grid goes with it |
| `⚠️ Update-Y DID NOT TAKE: the rotation to … was accepted by Cardano but …` | posted and accepted, but the datum never caught up |
| `treasury movement built: txid …; sweeps 2 deposits, pays 1 peg-out, 2 outputs. Signing starts` | a treasury movement is assembled |
| `⚠️ treasury movement NOT SIGNED: the SPO roster could not sign it (…) — N in a row` | the roster could not sign what it built; no daemon resolves this |
| `treasury movement posted: txid … (… bytes); pays …, sweeps …. Waiting for Bitcoin …` | the movement is posted |
| `⚠️ treasury movement post FAILED: txid … — this node could not finish posting it` | a signed movement did not go out; the Cardano submit may still have been accepted, so the movement may yet confirm |
| `treasury movement confirmed: txid …; the treasury is now … — N completed, N swept` | the chain shows it as the head |

Four steps appear both ways, so the channel cannot show only the good half of
them: the key generation, the rotation, the signing and the post. `registry`,
`group key for bridge epoch` and `treasury movement confirmed` report what the
chain now says rather than an action this node took, so there is no outcome for
them to fail at.

`treasury movement built` has no ⚠️ counterpart, and deliberately so. The two
ways a movement does not get built are both already `warn`s, which the default
`--min-level warn` forwards:

- the opportunity is never taken, because a movement is still in flight against
  the tip — `batch B_i skipped: treasury movement <txid> is still waiting for Bitcoin confirmation …`;
- the build is entered and refuses, over roots or trie state — the phase driver's
  `building the treasury movement failed on the frozen batch (…)`.

The first of those fires on a HEALTHY bridge: with a ~6 h grid pitch and ~17 h to
confirm a movement, up to three opportunities in a row pass while the last one
confirms, and that is the schedule working rather than a stall. So read a run of
them, not a single one — and note that an in-flight movement is always released
by `tm_recovery_window`, while a TM record this node cannot READ has no deadline
and holds the gate until someone looks.

**A rejected Update-Y is deliberately NOT an event.** `submit_update_y` returns on
Cardano acceptance while the plan is read from the confirmed datum, so a cascade
follower — and every federation member, which has no cascade at all — can be
rejected as a conflicting spend for a rotation that is landing. A rejection means
nothing on its own, so `Update-Y FAILED` is raised where the node has stopped
expecting a rotation at all: once per epoch, after the handoff retries are spent.
A node that took part in signing the rotation does not stop expecting it there —
its peers' posts can still land it — so instead of the event it logs a `warn` and
watches `treasury_info` until the handoff lands or the epoch ends.
`Update-Y DID NOT TAKE` likewise comes only from the node whose own rotation it
was; on the federation path every member watches the same one and logs it at
`warn` instead.

plus every line at `--min-level` or above (`warn` by default), whatever it
says: a peer dropped from a round, a provider rate-limiting the node, a
movement that could not be posted. `--min-level error` keeps only failures;
`--min-level off` keeps only the events; `--no-events` keeps only the levels.

heimdall keeps `heimdall::event` at `info` under any bare `--log-level` /
`RUST_LOG`, so a node running at `warn` still writes them. Only a full
directive (`warn,heimdall=warn`) silences them.

## Sources

Any mix of these; every message says which one a line came from.

- `--file [LABEL=]PATH` — followed like `tail -F`: starts at the end, survives
  logrotate and truncation, waits for a file that does not exist yet.
  Repeatable. The label defaults to the file name without its extension.
- `--unit UNIT` — a systemd unit, through `journalctl --follow --output=json`.
  Repeatable (`--unit heimdall@spo1 --unit heimdall@spo2`). Needs read access
  to the journal: the `systemd-journal` group.
- stdin — the default when neither is given; `--label` names it.

It understands all three formats heimdall writes (plain, journal `<N>`
prefixed, `--log-format json`) and the journal's JSON wrapper, per line,
without being told which. Lines it does not recognise count as `info`, so an
unexpected shape shows up as too much rather than as silence.

## Build

```bash
cd tools/heimdall-discord
cargo build --release          # → target/release/heimdall-discord
```

One small binary; the only network dependency is `reqwest` with rustls, so no
OpenSSL is needed to build or run it.

## Use

Create a webhook in the channel (Channel settings → Integrations → Webhooks)
and put its URL in the environment or a file:

```bash
export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/<id>/<token>'
heimdall-discord --test                                   # posts one message and exits

heimdall-discord --unit heimdall                          # the .deb's unit
heimdall-discord --unit heimdall@spo1 --unit heimdall@spo2 --unit heimdall@spo3
heimdall-discord --file spo1=/var/log/heimdall/spo1.log --file spo2=/var/log/heimdall/spo2.log
journalctl -fu heimdall -o json | heimdall-discord --label preprod

heimdall-discord --file node.log --from-start --dry-run   # see what WOULD be posted
```

Every start posts one line saying what is being followed and relayed, so a
broken webhook is visible at once, and `--dry-run` prints to stdout instead
of posting, with no webhook needed. Lines that arrive within `--coalesce-ms`
(1.5 s) of each other share one message; messages are code blocks, so pool
ids and keys with `_` in them are not read as markdown, and nothing in a log
line can ping anyone. Discord's rate limit is waited out rather than tripped.
While Discord is unreachable up to 500 lines are kept and retried every
30 s; beyond that the oldest are dropped and the drop is reported.

## Running it as a service

`deploy/heimdall-discord.service` and `deploy/default` are a systemd unit and
its environment file. They run the relay as a dynamic user with journal read
access, which is all `--unit` needs:

```bash
sudo install -m 0755 target/release/heimdall-discord /usr/local/bin/
sudo install -m 0644 deploy/heimdall-discord.service /etc/systemd/system/
sudo install -m 0600 deploy/default /etc/default/heimdall-discord
sudo $EDITOR /etc/default/heimdall-discord      # the webhook URL, and which units
sudo systemctl daemon-reload
sudo systemctl enable --now heimdall-discord
journalctl -u heimdall-discord -f
```

For `--file` sources, give the unit read access to the files instead
(`ReadOnlyPaths=` and a matching group).
