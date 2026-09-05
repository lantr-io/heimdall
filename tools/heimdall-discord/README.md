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

The `heimdall::event` lines, at `info` — one line each, self-contained:

| event | when |
|---|---|
| `DKG round1 (attempt N) started: n=… t=…, participants: #1 pool1… http://…, …` | the ceremony opens; the participant list is the roster, in index order |
| `DKG round2 (attempt N) started: round1 packages in from 3 of 3 (#1 #2 #3)` | who made it into round 2 |
| `DKG part3 (attempt N) started: round2 shares in from 3 of 3` | shares in, combining |
| `DKG complete (attempt N): Y_51=…, 3 share-holder(s), threshold 2` | the group key |
| `New treasury address tb1p… (Y_51=…)` | where this epoch's handoff pays the treasury |
| `Update-Y posted: cardano tx … — treasury key … -> …` | the rotation is on Cardano (also the federation-handoff form) |
| `TM built: txid … — 3 input(s) (2 deposit(s) swept), 2 output(s), 1 peg-out(s) paid; signing starts` | a treasury movement is assembled |
| `TM posted: txid … — Post-TM submitted (… bytes; …); awaiting Bitcoin confirmation` | the movement is posted |
| `TM confirmed: txid … — treasury head is now …` | the chain shows it as the head |

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
