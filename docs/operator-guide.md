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

You do **not** need a Bitcoin node, and heimdall could not use one if you had it. It never
*reads* Bitcoin — the treasury's outpoint and value come from the bridge-state singleton on
Cardano — and it never *sends* a transaction to Bitcoin. It builds and signs the Treasury
Movement's Bitcoin transaction, then posts it to **Cardano** inside the UnconfirmedTm record,
which is what that record carries it for; a watchtower relays it. There is no setting that
changes this: a second broadcaster was never redundancy, only a way to move BTC that the Cardano
side has no record of.

---

## 1. Install

Two routes, same binary, same config file content. They differ only in where the config lives and
how it gets there. Pick one — do not run both against the same bridge. A third route, building
from source, is [below](#building-from-source).

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

### Building from source

You do not have to trust the release artifact. The published binary, the one in the `.deb` and
the one in the container image are the same file, produced by `deploy/build-musl.sh` — so
building it yourself is a matter of running the same script the release does.

```bash
git clone https://github.com/lantr-io/heimdall
cd heimdall
git checkout v<version>          # a release tag, not main, unless you mean to run main
deploy/build-linux.sh            # → deploy/out/heimdall
```

`build-linux.sh` runs `build-musl.sh` inside a `rust:alpine` container, which is what CI does
(`.github/workflows/release.yml`). That matters for two reasons: Alpine is musl-native on amd64,
so this is a *native* build for the deploy target rather than a cross-compile, and OpenSSL is
linked statically — the result is a fully static ELF with no runtime dependencies, which is why
the same file works on Debian, on NixOS and in a `scratch`-adjacent image. You need Docker; you
do not need a Rust toolchain on the host. Add `--clean` to wipe the cached cargo/target volumes
and rebuild from nothing.

To go straight to a package or an image from that binary:

```bash
deploy/debian/build-deb.sh       # → deploy/out/heimdall_<version>-1_amd64.deb
deploy/docker/build-image.sh     # → a local heimdall image
```

Neither compiles anything: both wrap the binary `build-musl.sh` produced, deliberately, so the
artifact in the package cannot drift from the one you built and checked. `VERSION` defaults to
the `Cargo.toml` version plus the git sha (`0.1.0+4d1386f`), which is how a locally built package
stays distinguishable from a release.

If you would rather build on the host with your own toolchain, `cargo build --release` works and
produces a dynamically linked binary at `target/release/heimdall` — fine for a machine you also
develop on, and *not* what the packaging path ships. Rust edition 2024, so a recent stable
toolchain.

Verify whichever way you got here — the version string carries the git sha, so it tells you
exactly what you are running:

```bash
heimdall --version
```

---

## Forming the initial federation

**Skip this if you are joining an existing bridge** — you are an SPO, the federation key already
exists, and you read it from the Config. This section is for the people standing a bridge up, and
it happens before everything else in this guide.

The **federation setup key** `federation_setup_Y` is the key in the CSV recovery leaf of both
Taproot trees — the treasury's and every peg-in deposit's. It is the way the treasury moves when
the FROST group is dark, after `federation_csv_blocks` have passed. It is also an *input* to
genesis: the treasury address the genesis anchor is funded at is derived from it. So it must exist
before the bridge does, which is why nothing in this section reads a chain.

**The setup name applies only here.** Genesis publishes this key as **Config #11**, and from that
point on it is called `y_federation` and *everyone reads it from the chain* — no SPO ever types it
into a config file, and heimdall refuses a local value that disagrees with the published one. The
two names are the same 32 bytes; what differs is whether anything but your own machine knows them
yet. If you are joining an existing bridge, `y_federation` is all you will ever meet.

It is generated by the federation *together*: a `t`-of-`n` FROST key, so that the mechanism which
exists *because* the signing group might be unavailable is not itself one person's secret. No
member can move the treasury alone, and no member's failure takes the recovery path with it.

Every member does this on their own machine. Read the whole section first — the members have to
agree on two things before anyone runs anything.

### 1. Each member creates their identity key

The ceremony authenticates every payload under your Bifrost identity key, so make it first — this
is [step 2](#2-create-your-bifrost-identity-key) below, and it is the same key you will register
with later. Then print its public half:

```bash
heimdall bifrost-id --config heimdall.toml
#   bifrost_id_pk: <64 hex>          ← give this, and your endpoint URL, to the others
```

Also decide your endpoint URL now (`https://spo1.example.com`, or `http://host:18500` in a test
network) and make it reachable — [step 5](#5-make-your-endpoint-reachable) covers this, and the
ceremony needs it working, not just decided.

### 2. Everyone agrees on the same member list and threshold

Exchange the `(bifrost_id_pk, bifrost_url)` pairs out of band and check them against each other —
these are the identities the whole ceremony rests on. Then **every** member puts the **identical**
block in their config:

```toml
[federation]
# How many members it takes to sign a recovery spend. REQUIRED, no default.
min_signers = 4

members = [
  { bifrost_id_pk = "<64 hex>", bifrost_url = "https://spo1.example.com" },
  { bifrost_id_pk = "<64 hex>", bifrost_url = "https://spo2.example.com" },
  { bifrost_id_pk = "<64 hex>", bifrost_url = "https://spo3.example.com" },
  { bifrost_id_pk = "<64 hex>", bifrost_url = "https://spo4.example.com" },
  { bifrost_id_pk = "<64 hex>", bifrost_url = "https://spo5.example.com" },
]
```

The order does not matter — members are numbered by key order, so everyone computes the same
numbering — but the *set* and `min_signers` must match exactly. `heimdall bifrost-id` prints the
numbering and a digest of the list; compare the digest with the others and you have checked the
whole thing in one line.

**Choosing `min_signers`.** It is baked into the key at generation: changing it later means a new
key, a new treasury address, and moving the funds. There is no default, deliberately.

- **`n - 1` is the recommendation.** One dark member cannot brick the path that exists *because*
  members go dark, and it still takes nearly the whole federation to move the treasury.
- **`n`** means nobody can move the treasury without everybody — the strongest custody, and the
  weakest availability: one lost share and the recovery path is gone.
- **`t` at or below `n/2`** is accepted but warned about loudly: a *minority* of the federation
  could then sweep the whole treasury once the CSV delay passes.

### 3. Everyone runs the ceremony

```bash
heimdall federation-dkg --config heimdall.toml
```

It waits for **every** listed member — there is no reduced set to fall back to, because a member
absent from the ceremony can never sign the key it produces. While it waits it names who it is
waiting for, so a member who has not started yet, or is unreachable, is visible immediately rather
than as a stall. It has no deadline of its own; `--timeout-secs N` gives it one.

Each member ends with the same line:

```
federation key formed.
federation_setup_Y: <64 hex>
                    ↳ genesis publishes this as Config #11 y_federation (binocular bridge.y-federation-hex)
share:              /var/lib/heimdall/federation-key.json (0600 — losing every copy loses the recovery path)
```

**Compare the `federation_setup_Y` values across all members before going further.** They must be
identical. That check costs one message and is the only thing that proves the ceremony you all
just ran was the same ceremony.

**Back up `federation-key.json`.** It is the only copy of your share, and unlike the epoch signing
share it never regenerates: a re-run produces a *different* key, hence a different treasury
address, which the existing funds are not in. Below the threshold in surviving shares, the recovery
path is gone for good.

### 4. Derive the genesis treasury address

```bash
heimdall bootstrap-treasury --config heimdall.toml
#   bcrt1p…                                          ← fund the genesis anchor here
#   y_federation:          <64 hex>  (the 4-of-5 federation ceremony key)
#   federation_csv_blocks: 144
```

That value goes into binocular's `bridge.y-federation-hex`, and `deploy-bridge` publishes it at
Config #11 — after which it is `y_federation`, every SPO and every depositor reads it from the
chain rather than being told it, and this is the last command that took it from a local file.

### If the ceremony fails partway

If some members finished and one did not, that cannot be repaired by re-running on the member that
failed: the round payloads are not kept after a ceremony ends, so the members who finished have
nothing left to serve. Everyone deletes their `federation-key.json` and the whole federation runs
the ceremony again. Do this *before* any BTC is sent to an address derived from the abandoned key.

### Using the key later

The federation's own spend of the treasury — the recovery path, once the FROST group is dark and
the CSV delay has passed — is a signing session among the members, not one person's transaction:

```bash
# every participating member runs this, with the SAME arguments:
heimdall federation-spend --config heimdall.toml \
  --outpoint <txid>:<vout> --amount-sat <sats> --y51 <the treasury's current FROST key> \
  --signers 1,3,4
```

`--signers` names who will sign, by the numbering `bifrost-id` printed (it defaults to everyone).
Every participant must pass the same list: FROST binds each share to the exact set of co-signers,
so two members assuming different sets produce a signature that verifies against nothing. Each
member prints the identical signed transaction; any one of them can broadcast it — heimdall does
not send transactions to Bitcoin.

The key and the CSV delay it rebuilds the treasury tree from come from the **Config datum** (#11
and `params[7]`), not from anyone's config file — the command prints which source it used. Your
share is the secret half and a cross-check: if it disagrees with what the bridge publishes,
heimdall refuses rather than signing for an address the other members are not using. Only before
genesis, when there is no Config to read, do the local values apply.

For the authorizations that are not Bitcoin transactions — today, rotating the treasury's FROST
key as the federation (`update-y --federation`, the dead-roster recovery) — `federation-sign` does
the same thing to a plain 32-byte message:

```bash
heimdall update-y --federation …                 # prints "sign message: <64 hex>", then refuses
heimdall federation-sign --config heimdall.toml \
  --message <that value> --signers 1,3,4         # every signer runs this
heimdall update-y --federation … --signature <the printed signature>
```

### The single-key federation

A bridge may instead be locked with one seed held by one party (`bitcoin.y_fed_seed_hex`), which
is what the ceremony above replaces. It still works, and every command above behaves the same way
with it, but say plainly what it means: **whoever holds that seed can sweep the whole treasury
alone once the CSV delay passes.** A node holding both a seed and a ceremony share is refused —
they are different keys locking different treasuries, and nothing can tell which one is this
bridge's.

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

**[will be removed — WI-070]** Most of the remaining ~20 values (`pegin_script_address`,
`pegout_script_address`, `bridged_token_unit`, the treasury and registry identifiers) are things
the Config UTxO already knows. Step 4 checks what you typed against the chain, so a mistake is
caught at startup rather than by a failed transaction — but you still have to type them.

**The registry and the ban list: usually nothing to type.** On a bridge deployed by
`binocular deploy-bridge` at or after WI-068, the Config publishes the ban policy (#8), the
registry policy (#9) and the `treasury_info` policy (#10) — so `registry_blueprint`,
`registry_bootstrap` and `treasury_info_asset_name` are not needed either. The `treasury_info`
state NFT has no Config field: its name is the protocol constant `"BFRTRY"` ([CFG-4]), which is
why `treasury_info_asset_name` is ignored on any bridge of this vintage. Genesis mints both
linked-list roots *before* the Config exists, so a bridge cannot exist without them;
`heimdall bootstrap-registry` and `bootstrap-ban-list` are legacy, for bridges that predate that
and for recovering a genesis that failed part-way.

> Field numbers here are the rev-5.5 datum: twelve fields, `params` nested at #1, identities at
> #2-#11. Older notes number them differently — the datum was renumbered when `params` moved to
> the front ([CFG-5]) — so trust `src/cardano/config_params.rs`, which is what actually parses it,
> over any number written in prose.

One thing the published ids do NOT cover: performing the DKG **key handoff** (Update-Y) spends the
`treasury_info` state UTxO, and spending needs the compiled script rather than its hash. A node
that does handoffs still needs a blueprint; what it derives is checked against the published #10,
so a mismatch is a startup error instead of a handoff written where no one reads it.

**The ban list specifically.** The eligible roster is the registry *minus* active bans,
so a node that cannot read that list computes a different DKG participant set from everyone else —
which is why the daemon refuses to start without one. But on a bridge whose Config publishes the
ban policy (#8), there is nothing to configure: the node reads the policy id from the
Config, and the ban script address follows from it. `show-config-params` prints the address it
resolved, and startup step 6 names the source.

Only on a bridge whose Config *predates* that field do you still copy `ban_bootstrap` and
`fault_proof_policies` from the deployment notes. Copy them exactly: they are inputs to the ban
policy's own identifier, so a wrong value yields a valid-looking address holding an empty list —
banned SPOs back in your roster with nothing in any log. On a bridge that *does* publish #8,
leftover local keys are simply unused; if they happen to derive a different policy the daemon says
so and stops rather than picking one.

**Do not add the ban SCHEDULE to your config, on any bridge.** `base_ban_duration_ms`,
`max_faults_before_permanent` and `max_validity_window_ms` under `[cardano]` are *refused*:
heimdall names them and exits before it reads anything else, because a key that silently did
nothing would leave you believing a value you typed was in force. They come from the Config's
`params` on every bridge. Older deployment notes still list them — leave them out.

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

### Running next to your own node

You already run a Cardano node. Heimdall should read from *it*, not from a third-party API — the
bridge's safety rests on what each SPO independently observes on chain, and routing that through a
hosted service makes your bridge duties depend on someone else's uptime, rate limits, and view of
the chain.

Heimdall speaks the Blockfrost HTTP API, so the way to do this is a Blockfrost-compatible server in
front of your node. [Dolos](https://github.com/txpipe/dolos) is the one to reach for: a local data
node that follows your node and serves that API. The shape is:

```
heimdall  →  Dolos  →  your cardano-node
```

Point heimdall at it with two keys:

```toml
[cardano]
blockfrost_url = "http://localhost:3000/api/v0"   # your Dolos
network        = "mainnet"                        # or preprod / preview / testnet
```

`blockfrost_url` covers every call heimdall makes, reads and transaction submission alike.
`blockfrost_project_id` is still required by the config, but a local backend generally ignores its
value — put whatever Dolos expects, or a placeholder.

**`network` is mandatory as soon as `blockfrost_url` is set, and heimdall refuses to start
without it.** Against hosted blockfrost.io the network can be read off the project-id prefix,
because the key itself encodes it. A local backend has no such prefix to read, so the old inference
would quietly conclude "testnet" on a mainnet machine — every derived script address would come out
with a testnet bech32 prefix, and the fault-proof safety gate described in
[the fault-proof trusted setup](fault-proof-srs.md) would fail open. Refusing to guess is the only
safe behaviour.

Verify your backend serves what heimdall needs before switching over: step 4 below exercises the
read paths against whatever you configured, so run it after the change and read every line.

---

## 4. Check it before going further

```bash
sudo -u heimdall heimdall run-mover --config /etc/heimdall/heimdall.toml --once
```

Run it as the `heimdall` user: the config is `0640 root:heimdall` so you cannot read it as
yourself, and running as root would leave root-owned files in the state directory.

This runs eight startup checks and prints all of them, then refuses to start if any failed. It is a
dry run — it reads the chain and builds nothing.

```
[1/8] local preflight              PASS  mnemonic from $HEIMDALL_MNEMONIC; bifrost identity key loaded
[2/8] cardano connectivity         PASS  https://cardano-preprod.blockfrost.io/api/v0 answering, epoch 306
[3/8] resolve the Config           PASS  2dce4027…#0 (12 fields, fee_rate 1 sat/vB)
[4/8] verify the contract set      PASS  every configured contract identifier matches the Config UTxO
[5/8] reference script             …
[6/8] ban list                     PASS  roster is ban-filtered against addr_test1… — published by the bridge Config (detection only)
[7/8] registration status          …
[8/8] key handoff (Update-Y)       …
```

Step 3's field count is the datum's, and **more than twelve is normal** — the Config grows by
appending, and a reader decodes the twelve it knows and ignores the rest. Fewer than twelve is a
bridge older than this build, and it fails.

Step 4 is the one that earns its keep: it compares every contract identifier you typed against the
Config UTxO on chain and names any that disagree, with both values. Step 6 confirms your roster is
ban-filtered — it fails if the registry is configured without a ban list, since that node could not
agree with its peers on who is in the DKG. Step 7 tells you whether this node is registered; it
never spends — it names the command and stops.

Only `FAIL` blocks startup. A `WARN` is worth reading, and steps 5 and 8 are the two you will most
often see one on:

- **Step 5 (`reference script`)** warns when the registry reference script is not deployed at your
  wallet. That script is only needed to *register*; a running daemon reads the roster without it.
- **Step 8 (`key handoff`)** warns when this node has no compiled `treasury_info` script. It still
  runs DKG and signs — but if it is elected leader for an epoch, the Update-Y that hands the
  treasury to the new group key fails, and the handoff does not happen. Set
  `cardano.registry_blueprint` and `cardano.treasury_policy_id` to clear it.
- `protocol.state_dir is unset` is the one that silently costs money later.

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
registry ref UTxO:    <tx_hash>#0
                      register-spo finds this on its own — it is key-locked here, at
                      this wallet. Nothing to copy.
```

Nothing to copy: the script stays key-locked at your own wallet address, and the next command looks
for it there. If you keep a reference script somewhere else — at another address of yours, or
another SPO's — pass it as `--registry-ref <tx_hash>:<index>` and that is used instead.

**2. Register.**

```bash
sudo -u heimdall heimdall register-spo \
    --config /etc/heimdall/heimdall.toml \
    --blueprint /var/lib/heimdall/plutus.json \
    --registry-bootstrap <tx_hash>:<index> \
    --treasury-nft-name <hex> \
    --cold-skey /path/to/pool-cold.skey \
    --bifrost-skey /var/lib/heimdall/bifrost.skey \
    --bifrost-url http://<your-host>:<your-port> \
    --submit
```

It prints which reference script it picked, so you can see it found the one step 1 made:

```
registry ref:      <tx_hash>#0 (discovered at this wallet)
```

If step 1 was skipped, this command stops before building anything and prints the
`deploy-registry-ref` line to run — it does not build a transaction that would be too large to
submit.

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
show `[7/8] registration status` satisfied.

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
| `[4/8] verify the contract set FAIL` | your config disagrees with the chain; the check prints both values for each mismatch |
| a transaction is refused | read the whole message: the min-stake gate and the preflight both refuse loudly rather than submitting something wrong |
| it refuses to start over `cardano.fault_proof_srs_path` | you have DKG fault enforcement configured on mainnet against a setup that is not trustworthy — see [the fault-proof trusted setup](fault-proof-srs.md) |

For building heimdall or cutting a release, see [CONTRIBUTING.md](../CONTRIBUTING.md). For the
per-route deployment reference, see [deploy/README.md](../deploy/README.md). If you configure the
DKG fault verifiers — the packaged config does not, and most operators never will — read
[the fault-proof trusted setup](fault-proof-srs.md) first.
