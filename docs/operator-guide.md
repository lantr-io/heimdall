# Running a Heimdall SPO node

Heimdall is the SPO program for the Bifrost Bridge. Running it makes your Cardano stake pool one
of the distributed custodians of the bridge's Bitcoin treasury: your node takes part in each
epoch's distributed key generation and co-signs Treasury Movements with FROST threshold signatures.

This guide goes from a clean machine to a registered, running, monitored daemon. Follow it top to
bottom — the order matters, and **registration is not part of starting**: a node that is installed,
configured and enabled but never registered will run quietly forever and contribute nothing.

> **This describes what is true today, not the target.** Some steps exist only because the daemon
> cannot yet discover a value it could derive. Those are marked **[will be removed]** with the work
> item that removes them, so you can tell which parts of this document are load-bearing and which
> are scaffolding.

---

## Before you start

You need:

| | |
|---|---|
| A registered Cardano stake pool | With active stake. Your pool's **cold signing key** is needed once, at registration. |
| A Blockfrost project id | For the network the bridge runs on. This is how the daemon reads Cardano. |
| A funded Cardano wallet | A mnemonic. Pays fees and holds the registration's locked ADA. |
| A host reachable from the internet | On one TCP port, for the SPO-to-SPO protocol. See [step 5](#5-make-your-endpoint-reachable). |
| The bridge's deployment notes | Roughly twenty values identifying the bridge you are joining, from whoever deployed it. |

You do **not** need a Bitcoin node. Heimdall posts Treasury Movements to Cardano and the
watchtowers relay them to Bitcoin. `bitcoin.submit` stays `false`; a second broadcaster is not
redundancy here, it is a way to publish a movement the Cardano side has not recorded.

---

## 1. Install

Two routes, same binary, same config file content. They differ only in where the config lives and
how it gets there. Pick one — do not run both against the same bridge.

### Debian package

```bash
curl -LO https://github.com/lantr-io/heimdall/releases/download/v<version>/heimdall_<version>-1_amd64.deb
curl -LO https://github.com/lantr-io/heimdall/releases/download/v<version>/heimdall.deb.sha256
sha256sum -c heimdall.deb.sha256
sudo apt install ./heimdall_<version>-1_amd64.deb
```

This creates the `heimdall` system user, `/var/lib/heimdall` (mode `0700`), the `heimdall.service`
unit, and two config files. It deliberately does **not** start the service — the daemon cannot run
before you have configured and registered it.

| path | what it is |
|---|---|
| `/usr/bin/heimdall` | the binary |
| `/etc/heimdall/heimdall.toml` | configuration, `0640 root:heimdall`, a dpkg **conffile** |
| `/etc/default/heimdall` | environment for the unit — where secrets go |
| `/var/lib/heimdall` | state, `0700 heimdall:heimdall` |

### Docker

```bash
docker pull ghcr.io/lantr-io/heimdall:<version>
docker run --rm ghcr.io/lantr-io/heimdall:<version> \
    cat /usr/share/heimdall/heimdall.toml.example > heimdall.toml
```

The image ships no config and no secrets. You bind-mount the config read-only and name a volume
for state; the full `docker run` line is in [step 7](#7-start-it).

There is **no APT repository** — upgrading means downloading the next `.deb`. See
[deploy/README.md](../deploy/README.md) for the per-route reference, including the NixOS module.

---

## 2. Create your Bifrost identity key

This is your long-lived secp256k1 identity. It is bound on-chain at registration, and the daemon
signs every DKG and signing payload with it. **Losing it means re-registering; leaking it means
someone else can sign as you.**

```bash
sudo -u heimdall sh -c 'umask 077 && openssl rand -hex 32 > /var/lib/heimdall/bifrost.skey'
sudo -u heimdall ls -l /var/lib/heimdall/bifrost.skey     # must be -rw-------
```

Heimdall refuses to load this file if it is readable by group or other. Back it up somewhere the
daemon cannot reach.

For Docker, create it on the host inside the directory you will mount as the state volume, or
`docker exec` into the running container.

---

## 3. Fill in the config

Edit `/etc/heimdall/heimdall.toml` (or your local `heimdall.toml` for Docker). Every bridge-specific
value ships commented out, because there is no sane default for it — the daemon names what is
missing rather than guessing.

The values fall into three groups.

**About you.** `cardano.blockfrost_project_id`, `bifrost.skey_path` (the file from step 2), and
`protocol.state_dir` — which the package already sets to `/var/lib/heimdall`. Leave `state_dir`
set: without it the completed-peg-outs trie is rebuilt **empty** on every start, and on a bridge
that has already paid peg-outs the node would treat them as unpaid.

**About the bridge.** Copy these from the bridge's deployment notes. The Config UTxO is the
discovery root — `config_address`, `config_nft_policy_id` and `config_nft_asset_name` are what let
the daemon find the bridge's operational parameters and its batch schedule.

**The daemon will not start without them.** Step 3 of the next check is a hard failure, not a
warning. That is deliberate: a node that cannot see the batch grid would fall back to a wall-clock
cadence, and two SPOs ticking on wall clocks scan different chain states and build different
Treasury Movement bytes — so no co-signer can reproduce them. Refusing to start is the only safe
behaviour, and it is why these three cannot be left blank.

**[will be removed — WI-055, WI-056]** Most of the remaining ~20 values (`pegin_script_address`,
`pegout_script_address`, `bridged_token_unit`, the treasury and registry identifiers) are things
the Config UTxO already knows. Step 4 checks what you typed against the chain, so a mistake is
caught at startup rather than by a failed transaction — but you still have to type them.

**Secrets.** Two, and neither belongs in the TOML if you can avoid it:

| secret | where to put it |
|---|---|
| wallet mnemonic | `HEIMDALL_MNEMONIC` in `/etc/default/heimdall` (Debian) or `-e HEIMDALL_MNEMONIC` (Docker) |
| bifrost identity key | the `0600` file from step 2, referenced by path |

Heimdall reads `$HEIMDALL_MNEMONIC` **only when `cardano.mnemonic` is absent** from the config
file. Leaving that key commented out is what activates the environment variable — and keeps the
seed out of the file dpkg tracks and diffs on upgrade.

The Blockfrost project id is also a credential. It lives in the TOML, which is why the package
installs that file `0640 root:heimdall` rather than world-readable.

---

## 4. Check it before going further

```bash
sudo -u heimdall heimdall run-mover --config /etc/heimdall/heimdall.toml --once
```

Run it as the `heimdall` user: the config is `0640 root:heimdall` so you cannot read it as
yourself, and running as root would leave root-owned files in the state directory.

This runs six startup checks and prints all of them, then refuses to start if any failed. It is a
dry run — it reads the chain and builds nothing.

```
[1/6] local preflight              PASS  mnemonic from $HEIMDALL_MNEMONIC; bifrost identity key loaded
[2/6] cardano connectivity         PASS  https://cardano-preprod.blockfrost.io/api/v0 answering, epoch 306
[3/6] resolve the Config           PASS  2dce4027…#0 (17 fields, min_stake 0)
[4/6] verify the contract set      PASS  6 identifier(s) agree with the Config
[5/6] reference script             …
[6/6] registration status          …
```

Step 4 is the one that earns its keep: it compares every contract identifier you typed against the
Config UTxO on chain and names any that disagree, with both values. Steps 5 and 6 tell you what is
still missing for registration — they never spend; they name the command and stop.

Only `FAIL` blocks startup. A `WARN` is worth reading: `protocol.state_dir is unset` in particular
is the one that silently costs money later.

Do not continue until this passes.

---

## 5. Make your endpoint reachable

**This is the one piece of networking you can get wrong silently.** Your node serves its DKG and
signing rounds over HTTP, and peers *fetch* from it. If they cannot reach you, you drop out of the
epoch's qualified set: the ceremony proceeds without you, and nothing in your own log says so.

Two settings, and they are not what the names suggest:

- **`http.bind_address`** — the local interface to bind. It defaults to `0.0.0.0` (every
  interface), because this endpoint has to be reachable for the node to be useful. Narrow it to a
  specific NIC, or to `127.0.0.1` when a reverse proxy in front is the only thing that should reach
  heimdall directly. Do not set loopback on a directly-exposed node — and inside a container
  loopback is unreachable *even with `-p`*.
- **The advertised address is the `bifrost_url` you register**, not a config setting. Peers fetch
  from it, so it must be reachable and it must be right.
- **Where the process listens is separate.** By default it listens on the port inside that URL,
  which is what you want when the node is exposed directly. Behind a reverse proxy or a container
  port map, set **`http.listen_port`**: the advertised URL stays as registered, only the local port
  changes. That also lets you register a clean `https://spo.example.com` and terminate TLS at
  nginx — without `listen_port` the URL must carry an explicit `:<port>`, because it is the only
  place the daemon can learn one.

```toml
# nginx owns :443 in front; heimdall listens privately.
[http]
bind_address = "127.0.0.1"
listen_port  = 18500
# and you registered --bifrost-url https://spo.example.com
```

So the URL you register in step 6 is the single source of truth for your port. Register a URL with
an explicit `:<port>` — the daemon refuses to start without one, because it cannot guess which
local port to serve on — open that port, and make sure the hostname resolves publicly.

```bash
# from another machine, once the daemon is running:
curl -sS -o /dev/null -w '%{http_code}\n' http://<your-host>:<your-port>/health
```

That is not an approximation of the test your peers run — it *is* the test: the DKG health gate
fetches `<bifrost_url>/health` from every other node before starting a ceremony. A `200` from
outside your network means peers can see you.

---

## 6. Register

Registration binds your pool's cold-key identity to your Bifrost identity, mints your membership
token, and inserts you into the on-chain registry. **It is a separate act from starting the
daemon.** Do it now, before enabling the service.

> **This spends real ADA.** The registration transaction locks at least 2 ADA in your registry node
> (sized to the datum) and pays fees. It is not a dry run. Step 1 below locks more, but at your own
> address, and is reclaimable.

Every command below prints the transaction and stops unless you add `--submit`. Run each without
`--submit` first and read what it is about to do.

**1. Deploy the registry reference script.** The registry script is ~12 KB and would not fit in the
registration transaction twice, so it goes on chain once and is referenced.

```bash
sudo -u heimdall heimdall deploy-registry-ref \
    --config /etc/heimdall/heimdall.toml \
    --blueprint /var/lib/heimdall/plutus.json \
    --registry-bootstrap <tx_hash>:<index> \
    --submit
```

It prints the reference UTxO it created:

```
registry ref UTxO:    <tx_hash>:0  (pass as --registry-ref to register-spo)
```

**Copy that outpoint.** **[will be removed — WI-056]** The next command cannot yet discover it.

**2. Register.**

```bash
sudo -u heimdall heimdall register-spo \
    --config /etc/heimdall/heimdall.toml \
    --blueprint /var/lib/heimdall/plutus.json \
    --registry-bootstrap <tx_hash>:<index> \
    --treasury-nft-name <hex> \
    --registry-ref <the outpoint from step 1> \
    --cold-skey /path/to/pool-cold.skey \
    --bifrost-skey /var/lib/heimdall/bifrost.skey \
    --bifrost-url http://<your-host>:<your-port> \
    --submit
```

`--bifrost-url` is what step 5 was about: it is published on chain, peers fetch from it, and its
port is the port your daemon will bind.

Submission is gated on a minimum-stake check against your pool's epoch-snapshot active stake. If it
fails, the command prints the dry-run transaction and refuses — it will not submit.

Your cold key is used only here. For an air-gapped pool, omit `--cold-skey` and `--bifrost-skey`;
the command prints the exact message to sign and takes `--cold-vkey`/`--cold-sig` and
`--bifrost-id-pk`/`--bifrost-sig` on the next run.

**3. Confirm you are in the roster.**

```bash
sudo -u heimdall heimdall show-roster --config /etc/heimdall/heimdall.toml
```

Read-only. Your pool id and `bifrost_url` should appear. Re-running the step-4 check now should
show `[6/6] registration status` satisfied.

---

## 7. Start it

**Debian:**

```bash
sudo systemctl enable --now heimdall
systemctl status heimdall
```

A fresh install runs **without** `--broadcast`: every tick is a dry run. That is the right way to
watch a new node for a cycle. When you are satisfied, add `--broadcast` to `HEIMDALL_ARGS` in
`/etc/default/heimdall` and restart.

**Docker:**

```bash
docker run -d --name heimdall \
    -v "$PWD/heimdall.toml:/etc/heimdall/heimdall.toml:ro" \
    -v heimdall-state:/var/lib/heimdall \
    -e HEIMDALL_MNEMONIC="..." \
    -p <your-port>:<your-port> \
    --restart unless-stopped \
    ghcr.io/lantr-io/heimdall:<version>
```

Name the volume. `/var/lib/heimdall` holds the epoch's DKG signing share; a container replaced
without it comes back unable to resume.

---

## 8. Operating it

### Reading the log

Every line carries a level, and journald files it at the matching priority:

```bash
journalctl -u heimdall -f          # follow
journalctl -u heimdall -p err      # what failed
journalctl -u heimdall -p warning  # what degraded first
docker logs -f heimdall            # the container equivalent
```

Turn detail up without editing a conffile — set `RUST_LOG` in `/etc/default/heimdall` (or
`systemctl edit heimdall`) and restart. A bare level is scoped to heimdall and leaves its
dependencies quiet; `RUST_LOG="warn,heimdall::cardano::blockfrost_chain=debug"` follows one
subsystem.

### Quiet is normal

**The bridge runs on multi-day cycles.** Treasury Movements span one or more Cardano epochs (5+
days), peg-ins wait for ~100 Bitcoin confirmations (~12 hours), and the mover follows the
protocol's on-chain **batch grid** rather than a wall-clock interval — so it acts when the schedule
opens an opportunity, not every `--interval-secs`. Shortening that interval produces more
Blockfrost scans, not more movements.

A healthy idle node therefore says very little. Long silences are correct behaviour. What tells you
it is alive is `systemctl status` and the absence of `-p err` output — **[will be improved —
WI-058]**, which adds a periodic heartbeat and a `heimdall status` command, because "silent" and
"wedged" currently look the same.

### State

`/var/lib/heimdall` (`0700`) holds your bifrost identity key and the current epoch's DKG signing
share. Losing it means the node cannot resume the epoch it was in and must sit out until the next
one; losing the identity key means re-registering. Back it up.

### Upgrades

```bash
sudo apt install ./heimdall_<newer>-1_amd64.deb
```

Your edited `/etc/heimdall/heimdall.toml` survives — dpkg tracks it as a conffile, so a changed
shipped default is offered as a merge rather than applied silently. `/etc/default/heimdall` is not
diffed at all. The service restarts only if it was already running. `apt purge` deliberately leaves
`/var/lib/heimdall` and the `heimdall` user in place.

---

## 9. What not to expose

Open **one** port: the peer endpoint from step 5. It is public by construction — its URL is on
chain — and it is the only surface that needs to be.

That port serves `/health` plus the DKG and signing round payloads, and nothing else. `/health` is
a peer-liveness probe — it answers "is this process up", not "is this node healthy" — so do not
mistake a `200` for the node being in the roster and keeping up.

There is no operator-facing health or metrics surface yet (**[coming — WI-058]**, and deliberately
on a *separate*, loopback-by-default port when it lands, so operator state is never served from the
public peer endpoint).

Do not expose your Blockfrost credentials, your config file, or `/var/lib/heimdall`.

---

## When something is wrong

| symptom | look at |
|---|---|
| the service will not start | `journalctl -u heimdall -p err`, then re-run the step-4 check — it names the failing check and what to fix |
| starts, then nothing happens for days | expected; see *Quiet is normal* |
| peers seem not to see you | step 5 — is the registered port open and reachable *from outside*? |
| `[4/6] verify the contract set FAIL` | your config disagrees with the chain; the check prints both values for each mismatch |
| a transaction is refused | read the whole message: the min-stake gate and the preflight both refuse loudly rather than submitting something wrong |

For building heimdall or cutting a release, see [CONTRIBUTING.md](../CONTRIBUTING.md). For the
per-route deployment reference, see [deploy/README.md](../deploy/README.md).
