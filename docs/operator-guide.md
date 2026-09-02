# Running a Heimdall SPO node

Heimdall is the SPO program for the Bifrost Bridge. Running it makes your Cardano stake pool one
of the distributed custodians of the bridge's Bitcoin treasury: your node takes part in each
epoch's distributed key generation and co-signs Treasury Movements with FROST threshold signatures.

This guide goes from a clean machine to a registered, running, monitored daemon. Follow it top to
bottom — the order matters, and **registration is not part of starting**: a node that is installed,
configured and enabled but never registered will run quietly forever and contribute nothing. The
two appendices at the end are off that path: one for standing a bridge up rather than joining one,
one for running a test bridge on a shorter cycle.

Done this before? The [Quick path](#quick-path) is the whole join on one screen, every block
copy-pastable, each step linking to the section that explains it.

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

Standing a bridge up rather than joining one? You have no deployment notes to be given, because you
are the one who produces them. Read
[Forming the initial federation](#appendix-forming-the-initial-federation) first — the federation
key it generates is the first thing that has to exist.

You do **not** need a Bitcoin node, and heimdall could not use one if you had it. It never
*reads* Bitcoin — the treasury's outpoint and value come from the bridge-state singleton on
Cardano — and it never *sends* a transaction to Bitcoin. It builds and signs the Treasury
Movement's Bitcoin transaction, then posts it to **Cardano** inside the UnconfirmedTm record,
which is what that record carries it for; a watchtower relays it. There is no setting that
changes this: a second broadcaster was never redundancy, only a way to move BTC that the Cardano
side has no record of.

---

## Quick path

The join, compressed. Set the variables once; every block below then pastes as is. Each step
names the section that explains it – read that section the first time an `Expect` line does not
match what you see. This path follows the Debian package route; Docker differs only in where the
config lives ([step 1](#1-install), [step 7](#7-start-it)).

```bash
# The bridge to join. These defaults name the shared preprod test bridge as deployed
# today; joining any other bridge, replace them from its deployment notes.
export BRIDGE_CONFIG_ADDRESS="addr_test1wrvvq6mstvqgnwx6xts6za2shsxn5nl20xv4pr37j4nf6yqgpyh9f"
export BRIDGE_CONFIG_POLICY="d8c06b705b0089b8da32e1a17550bc0d3a4fea7999508e3e95669d10"
# Yours:
export BLOCKFROST_PROJECT_ID="preprod…"              # or a Dolos in front of your own node, see §3
export MY_URL="http://spo.example.com:18500"         # public, and WITH an explicit :port
export HEIMDALL_MNEMONIC="…"                         # the funded wallet – never goes in the TOML
```

**1. Install** – [§1](#1-install). Run the build the rest of the roster runs, not the newest one.

```bash
sudo apt install ./heimdall_<version>-1_amd64.deb
heimdall --version
curl -s http://<any registered peer>:<port>/health     # its version and blueprint_digest must equal yours
```

Expect: `heimdall <sha> (<sha> <date>)`, and the peer's `"version"` and `"blueprint_digest"`
match what your node will publish (step 7 shows yours).

**2. Identity key** – [§2](#2-create-your-bifrost-identity-key).

```bash
sudo -u heimdall sh -c 'umask 077 && openssl rand -hex 32 > /var/lib/heimdall/bifrost.skey'
sudo -u heimdall ls -l /var/lib/heimdall/bifrost.skey
```

Expect: `-rw------- 1 heimdall heimdall 65 …`. Back the file up somewhere the daemon cannot reach.

**3. Config** – [§3](#3-fill-in-the-config). Three values name the bridge; everything else is read
from the chain.

```bash
sudo tee /etc/heimdall/heimdall.toml >/dev/null <<EOF
[protocol]
state_dir = "/var/lib/heimdall"

[bifrost]
skey_path = "/var/lib/heimdall/bifrost.skey"
url = "$MY_URL"

[bitcoin]
network = "testnet4"                # the Bitcoin network the bridge settles on

[cardano]
blockfrost_project_id = "$BLOCKFROST_PROJECT_ID"
network = "preprod"
config_address = "$BRIDGE_CONFIG_ADDRESS"
config_nft_policy_id = "$BRIDGE_CONFIG_POLICY"
config_nft_asset_name = "424946434647"   # "BIFCFG"
min_stake_lovelace = 1000000000          # your own registration gate, in lovelace
cold_skey_path = "/etc/heimdall/pool-cold.skey"   # or cold_vkey_path, for the air-gapped flow

[http]
bind_address = "0.0.0.0"
EOF
sudo chown root:heimdall /etc/heimdall/heimdall.toml && sudo chmod 640 /etc/heimdall/heimdall.toml
printf 'HEIMDALL_MNEMONIC=%s\n' "$HEIMDALL_MNEMONIC" | sudo tee -a /etc/default/heimdall >/dev/null
```

Copy the exact bytes of `config_address` and `config_nft_policy_id` – never retype them. One
wrong character passes the TOML parser and fails at `[3/9]`.

**4. Check** – [§4](#4-check-it-before-going-further). The mnemonic has to be in *this* command's
environment: `/etc/default/heimdall` is read by the unit, not by your shell.

```bash
sudo -u heimdall env HEIMDALL_MNEMONIC="$HEIMDALL_MNEMONIC" \
    heimdall doctor --config /etc/heimdall/heimdall.toml
```

Expect: `PASS` on every line except `[6/9] registration status  FAIL  NOT REGISTERED YET`, which
is correct before step 6. A `WARN` on `[4/9] reference script` is normal.

**5. Open the port** – [§5](#5-make-your-endpoint-reachable). The port inside `$MY_URL` is the
one the daemon binds. Open it in your firewall now; the test is in step 7, from another machine.

**6. Register** – [§6](#6-register). Spends real ADA. Put the pool cold key at the path from step 3
(`0600`, owned by `heimdall`), or use the air-gapped flow in §6. Dry run first:

```bash
sudo -u heimdall env HEIMDALL_MNEMONIC="$HEIMDALL_MNEMONIC" \
    heimdall register-spo --config /etc/heimdall/heimdall.toml
```

Expect: `pool id:  <hex> (pool1…)` **equal to your pool's real id**, `min-stake gate: … → PASS`,
and a `registry ref:` line. Then add `--submit`.

If it stops with `no reference script for the registry` instead, deploy one, then register with
the outpoint it prints:

```bash
sudo -u heimdall env HEIMDALL_MNEMONIC="$HEIMDALL_MNEMONIC" \
    heimdall deploy-registry-ref --config /etc/heimdall/heimdall.toml --submit
#   registry ref UTxO:    <tx_hash>#0
sudo -u heimdall env HEIMDALL_MNEMONIC="$HEIMDALL_MNEMONIC" \
    heimdall register-spo --config /etc/heimdall/heimdall.toml \
    --registry-ref <tx_hash>:0 --submit
```

Expect: `submitted: tx_hash=…`. A minute later, `heimdall show-roster` lists your pool and
`$MY_URL`, and the step-4 check reports `[6/9] registration status  PASS  registered as …`.

**7. Start** – [§7](#7-start-it).

```bash
sudo systemctl enable --now heimdall
systemctl status heimdall
# from ANOTHER machine:
curl -sS http://<your-host>:<your-port>/health
```

Expect: `active (running)`, and from outside a JSON body with `"status":"ok"` whose `"version"`
and `"blueprint_digest"` equal the peer's from step 1. That curl is the test your peers run
before every ceremony.

**8. Then** – [§8](#8-operating-it). `heimdall status` answers "am I healthy?". A freshly
registered pool holds no active stake for about two Cardano epochs and is **not in the roster
until it does** – `show-roster` lists it as excluded with the reason, and nothing is wrong. Long
silences after that are normal too.

---

## 1. Install

Two routes, same binary, same config file content. They differ only in where the config lives and
how it gets there. Pick one — do not run both against the same bridge. A third route, building
from source, is [below](#building-from-source).

### Where the releases are

**<https://github.com/lantr-io/heimdall/releases>** — that page is what tells you the `<version>`
to substitute into the commands below. `…/releases/latest` redirects to the newest one.

Every release is one workflow run over one commit, and it publishes the same binary three ways:

| where | what |
|---|---|
| release assets | `heimdall` — the static x86_64 musl binary — plus `heimdall.sha256` |
| release assets | `heimdall_<version>-1_amd64.deb` plus `heimdall.deb.sha256` |
| [Packages](https://github.com/lantr-io/heimdall/pkgs/container/heimdall) | `ghcr.io/lantr-io/heimdall:<version>`, the image — listed under the repository, not on the release page |

They are not three builds. The `.deb` wraps the published binary and the image copies it, so the
checksum you verify below is the same file in all three, and `heimdall --version` prints the same
string — the version plus the commit it was built from — whichever route you took.

Versions are milestones (`0.1-M5`), not semantic-versioning promises. This bridge has not run on
mainnet; the on-chain protocol can still change between releases, and a node that no longer speaks
the bridge's protocol drops out of the roster rather than failing loudly. Read the release notes
before upgrading a node that is registered and signing. To hear about new ones without polling:
**Watch → Custom → Releases** on the repository.

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

There is **no APT repository** — upgrading means downloading the next `.deb` from the same
releases page. See [deploy/README.md](../deploy/README.md) for the per-route reference, including
the NixOS module.

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

**Run what the roster runs.** Before every ceremony each node compares its peers' `/health` with
its own: `major.minor` of the version, the digest of the embedded blueprint, the security
threshold, and the test-bridge settings. A peer that differs is excluded, by name. What that check
cannot see is everything else – a scheduling change, a payload layout – and two builds that pass
it can still run a ceremony that never converges. So build the commit the other operators run,
not the newest `main`, and read it off them: `heimdall --version` on their node, or `"version"`
and `"blueprint_digest"` on their `/health`. Upgrading is a roster-wide act – see
[Upgrades](#upgrades).

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
that has already paid peg-outs the node would treat them as unpaid and pay them again. **The
daemon refuses to start without it** — that is a hard failure at step 1, not a warning, because
the symptom of getting it wrong shows up an epoch later as a double payment.

**About the bridge — three values, and that is all.** `config_address`,
`config_nft_policy_id` and `config_nft_asset_name`, from the bridge's deployment notes. The Config
UTxO is the discovery root: the daemon finds the single UTxO holding that token and reads
everything else from its datum — the peg-in and peg-out script addresses, the bridged-token unit,
the TM validator and its state token, the bridge-state singleton, the registry and ban identities,
and the operational parameters and batch schedule. **The daemon will not start until all three are
set** — the check in the next section reports a missing one as a hard failure, not a warning.


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

### A complete config

Everything above, in one file. This is the whole of what an SPO joining a bridge sets:

```toml
[protocol]
state_dir = "/var/lib/heimdall"

[bifrost]
skey_path = "/var/lib/heimdall/bifrost.skey"
# Your endpoint. Published on chain at registration, and — unless [http].listen_port
# says otherwise — its port is the one this process binds.
url = "http://spo1.example.com:18500"

[bitcoin]
# The Bitcoin network the bridge settles on.
network = "testnet4"

[cardano]
blockfrost_project_id = "preprod…"
network = "preprod"

# The bridge — from its deployment notes. Everything else about it is read
# from the UTxO these three identify.
config_address = "addr_test1…"
config_nft_policy_id = "…"
config_nft_asset_name = "424946434647"   # "BIFCFG"

# Your own minimum-stake gate for registration, in lovelace.
min_stake_lovelace = 1000000000

# Registration only, and only one of these. The cold key is your existing Cardano
# stake-pool key: `cold_skey_path` signs here, `cold_vkey_path` is the public half
# for the flow where the signature is made on the machine that holds the secret.
# Neither has a default location — unset means "not on this machine".
#cold_skey_path = "/etc/heimdall/pool-cold.skey"
#cold_vkey_path = "/etc/heimdall/pool-cold.vkey"

[http]
# 0.0.0.0 is the default; set listen_port only if the port peers connect to
# differs from the one this process binds (a reverse proxy, a container map).
bind_address = "0.0.0.0"
listen_port = 18500
```

The mnemonic is deliberately absent — it comes from `$HEIMDALL_MNEMONIC`, as above.

**Running more than one instance on a machine.** Nothing prevents it — there is no lock file and no
hardcoded path — but five values must differ per instance, and one of them fails quietly. Give each
its own `--config`, its own `[http].listen_port`, its own `[bifrost].skey_path`, its own
`[health].bind` (the operator surface defaults to `127.0.0.1:18580`, and a second instance that
cannot bind it runs on without one, so `heimdall status` reports the live half as unavailable), and
above all its own `protocol.state_dir`: the filenames inside it are fixed (`cpo-trie.json`, `spi-trie.json`, the
DKG share), so two instances pointed at one directory overwrite each other's state without saying
so. Note also that `$HEIMDALL_MNEMONIC` is process-environment: exported once in a shell, every
instance launched from it shares a wallet and they will contend for the same UTxOs. Set
`cardano.mnemonic` per file, or give each process its own environment.

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

**Verified:** Dolos **v1.6.0** answers every read heimdall makes, checked against preprod with real
data — address UTxOs, `/blocks/latest`, `/epochs/latest` and its parameters, `/pools/{id}`,
`/accounts/{stake_address}`, script and datum resolution, and `/txs/{hash}` with its UTxOs.
Pagination follows Blockfrost's convention — pages start at 1 — which is what heimdall expects.
Transaction submission goes to the same `blockfrost_url`, but was not exercised in that run; the
first movement your node posts is what proves it.

Older builds are not equivalent. `/epochs/latest` is a recent addition to Dolos, and it is the first
call heimdall makes of any provider, so a build without it fails at startup rather than partway
through. Whatever backend you run, the check below exercises the read paths against it — run it
after the change and read every line.

---

## 4. Check it before going further

```bash
sudo -u heimdall heimdall doctor --config /etc/heimdall/heimdall.toml
```

Run it as the `heimdall` user: the config is `0640 root:heimdall` so you cannot read it as
yourself, and running as root would leave root-owned files in the state directory.

Give it the mnemonic. `/etc/default/heimdall` is read by the systemd unit, not by your shell, so
run as `sudo -u heimdall env HEIMDALL_MNEMONIC="…" heimdall doctor …` or step 1 reports `no
wallet mnemonic` and step 4 cannot look for the reference script. That is the first FAIL every
operator sees, and it is not a misconfiguration.

This runs nine startup checks and prints all of them with the exact command that fixes each one,
then exits non-zero if any failed. It reads the chain and **posts nothing** — a missing reference
script and an unregistered SPO are both reported, never deployed or registered for you.

`heimdall doctor` runs the same checks the daemon runs when it starts, by calling the same code, so
the two cannot disagree about what is wrong. `run-spo --check` is the same thing reached from the
other direction, if you would rather not type a second command name. When something goes wrong
later, `heimdall doctor` is the first output to capture.

```
[1/9] local preflight              PASS  mnemonic from $HEIMDALL_MNEMONIC; bifrost identity key loaded
[2/9] cardano connectivity         PASS  https://cardano-preprod.blockfrost.io/api/v0 answering, epoch 306
[3/9] resolve the Config           PASS  2dce4027…#0 (12 fields, fee_rate 1 sat/vB); peg-in requests at addr_test1…
[4/9] reference script             …
[5/9] ban list                     PASS  roster is ban-filtered against addr_test1… — published by the bridge Config (detection only)
[6/9] registration status          …
[7/9] key handoff (Update-Y)       …
[8/9] federation identity          PASS  Y_fed 37b381ac…, csv 144 blocks — published in the Config datum
[9/9] post a movement              PASS  TM validator f691433e… on chain, 4032 bytes, verified against Config #5
```

Step 3's field count is the datum's, and **more than twelve is normal** — the Config grows by
appending, and a reader decodes the twelve it knows and ignores the rest. Fewer than twelve is a
bridge older than this build, and it fails.

Step 3 is the one that earns its keep: it resolves the Config UTxO, and everything the node knows
about the bridge follows from it. Step 5 confirms your roster is ban-filtered — it fails if the
registry is configured without a ban list, since that node could not agree with its peers on who is
in the DKG.
Step 6 tells you whether this node is registered; it never spends — it names the command and stops.

Step 9 asks the question the rest of the report does not: **can this node actually post the
movement it would sign?** Minting the TM NFT needs the treasury-movement validator itself, not
just its hash, and the node fetches it from the chain by the hash the Config publishes (#5),
refusing any bytes that do not hash back to it. Nothing here is yours to configure — that is the
point. It used to be a CBOR string pasted into the config file, and a node missing it passed every
other check, took a full turn in a signing ceremony, and failed at the mint, having already
broadcast the Bitcoin transaction. That is why this one is a **FAIL** and not a warning.

Only `FAIL` blocks startup. A `WARN` is worth reading, and steps 4 and 7 are the two you will most
often see one on:

- **Step 4 (`reference script`)** warns when the registry reference script is not deployed at your
  wallet. That script is only needed to *register*; a running daemon reads the roster without it.
- **Step 7 (`key handoff`)** warns when this node cannot compile the `treasury_info` script. It
  still runs DKG and signs — but if it is elected leader for an epoch, the Update-Y that hands the
  treasury to the new group key fails, and the handoff does not happen. Set
  `cardano.config_nft_policy_id` to clear it — the one-shot the script compiles from is Config
  #12, and the node reads it from there.

`protocol.state_dir` is **not** in that list any more. It used to warn; it is now a step 1
**FAIL**, because what it costs is a second payment of an already-paid peg-out rather than a
degraded feature, and a warning is the wrong instrument for a fault whose symptom arrives an
epoch later on a different machine.

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

It is also reversible: [Leaving the bridge](#leaving-the-bridge) in step 8 gives the registry node's
ADA back and frees your Bifrost identity to register again.

Every command below prints the transaction and stops unless you add `--submit`. Run each without
`--submit` first and read what it is about to do.

**1. Deploy the registry reference script — only if your bridge has none.** The registry script is
~12 KB and would not fit in the registration transaction twice, so it goes on chain once and is
referenced. Both commands below compile that script from the outpoint the bridge publishes at Config
#12, so there is nothing about it to type.

Try step 2 first. `register-spo` looks for the script at your wallet and then at the wallet the
bridge was deployed from — whoever ran `binocular deploy-script-refs` published it there for the
whole bridge, and finding it means you deploy nothing and lock no ADA. It prints which one it used.
Run this command only if it reports finding neither.

```bash
sudo -u heimdall heimdall deploy-registry-ref \
    --config /etc/heimdall/heimdall.toml \
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

**If `register-spo` still reports no reference script after you deployed one, pass the outpoint
it printed:** `--registry-ref <tx_hash>:0`. Discovery reads the provider's address-UTxO listing,
and hosted Blockfrost has been seen to return the UTxO without its `reference_script_hash` for
well over ten minutes after confirmation, while the transaction view shows it. The flag skips the
listing and names the UTxO directly; the script inside it is verified by hash either way, so
nothing is trusted that was not checked.

**2. Register.** This step binds two keys together, and they are not the same kind of thing:

- **your pool cold key** — the Cardano stake pool key you already have. Nothing bridge-specific and
  nothing to generate: it is what `cardano-cli node key-gen --cold-verification-key-file cold.vkey
  --cold-signing-key-file cold.skey --operational-certificate-issue-counter-file cold.counter`
  produced when you created the pool, and it lives wherever you keep your pool's cold material. Your
  pool ID *is* its hash, which is why it is the only key that can speak for your pool. If you need
  the background, it is standard stake-pool operations material and not something this document
  defines — see the Cardano Developer Portal's operator handbook,
  <https://developers.cardano.org/docs/operators/>, whose pool-registration page
  (<https://developers.cardano.org/docs/operators/block-producer/register-stake-pool/>) is where
  `cold.vkey` / `cold.skey` come from and states the same thing this guide does: they live on your
  air-gapped machine.
- **your Bifrost identity key** — the new one from step 3, at `[bifrost].skey_path`. Every protocol
  operation after this uses it, and it stays on this machine.

Registration is the cold key signing *"this pool authorizes this Bifrost identity"*. That is the
whole purpose of the step, and the only time the cold key is used.

```bash
sudo -u heimdall heimdall register-spo \
    --config /etc/heimdall/heimdall.toml \
    --submit
```

Everything it needs is in the config file:

| key | what |
|---|---|
| `bifrost.url` | your endpoint, published on chain |
| `bifrost.skey_path` | your Bifrost identity key — the same one the daemon runs on |
| `cardano.cold_skey_path` | your pool cold key, for the on-machine flow |
| `cardano.cold_vkey_path` | the public half, for the air-gapped flow |

Each has a `--flag` that overrides it. `bifrost.url` matters most: the registration message commits
to those exact bytes, so a trailing slash or a different port between this command and
`sign-registration` invalidates both signatures — one value, read by both, cannot drift.

The cold-key paths take the `cold.skey` / `cold.vkey` files as cardano-cli wrote them — TextEnvelopes
— or raw 32-byte hex. `cold_skey_path` has no default location, and unset does not mean "look in the
usual place": it means the cold key is not on this machine.

**Check the pool ID it prints before you submit.** The command derives your pool ID from the cold
key you gave it and prints it:

```
pool id:           <hex> (pool1...)
```

That must equal your pool's real ID — `cardano-cli stake-pool id --cold-verification-key-file
cold.vkey --output-format hex`, or the ID on your pool's page. If it does not, you pointed at the wrong file, and what
you are about to register is a Bifrost identity for a pool that is not yours. Nothing later catches
this: the transaction is well formed, it just speaks for someone else.

It also prints which reference script it picked, so you can see it found the one step 1 made:

```
registry ref:      <tx_hash>#0 (discovered at this wallet)
```

If no reference script exists anywhere it can see, this command stops before building anything and
prints the `deploy-registry-ref` line to run — it does not build a transaction that would be too
large to submit.

If it reports the deployer's copy rather than your own, note what you are depending on: that UTxO
sits at their wallet and is deliberately kept spendable, so they can reclaim it. Nothing breaks
retroactively — your registration is already on chain — but a later `register-spo` or `apply-ban`
would have to fall back to deploying your own.

`--bifrost-url` is what step 5 was about: it is published on chain, peers fetch from it, and its
port is the port your daemon will bind.

Submission is gated on a minimum-stake check against your pool's epoch-snapshot active stake. If it
fails, the command prints the dry-run transaction and refuses — it will not submit.

Your cold key is used only here, and by revocation. The daemon never reads it.

**Keeping the cold key off this machine.** Preferred, and the reason the key type exists: the cold
key signs registration and revocation and nothing else, so it has no business on a networked block
producer. Sign beside the key instead, and carry four public values across.

On the machine that holds `cold.skey`:

```bash
heimdall sign-registration --config /path/to/heimdall.toml
```

It touches no chain and no network. It prints the pool ID it derived — check that against your pool
before going further — and then the four flags to copy:

```
    --bifrost-url http://<your-host>:<your-port> \
    --cold-vkey <64 hex> \
    --cold-sig <128 hex> \
    --bifrost-id-pk <64 hex> \
    --bifrost-sig <128 hex>
```

Pass those to `register-spo` on the node in place of `--cold-skey` and `--bifrost-skey`. The
`--bifrost-url` must be **byte-identical** in both commands: it is signed over, so a trailing slash
or a different port silently invalidates both signatures. `sign-registration` verifies them before
printing — the same check the on-chain validator performs — so a mistake fails beside your cold key
rather than after a fee is spent.

Do not try to produce these signatures with a general-purpose signing tool. The cold half is a raw
Ed25519 signature over exact bytes, and the usual community signer's CIP-8 mode signs a *wrapped*
payload — different bytes, so the result verifies nowhere and nothing tells you why.


**3. Confirm you are in the roster.**

```bash
sudo -u heimdall heimdall show-roster --config /etc/heimdall/heimdall.toml
```

Read-only. Your pool id and `bifrost_url` should appear. Re-running the step-4 check now should
show `[6/9] registration status` satisfied.

Before you register, that step FAILS and the daemon refuses to start. That is expected, not a
misconfiguration: an unregistered node is in no roster and would contribute nothing, so it says so
rather than running as an idle process that looks healthy. The check names the command.

### Registering is not the same as joining the roster

Cardano snapshots stake at an epoch boundary and **activates it two boundaries later**, so a pool
registered today holds no active stake for about ten days. Until it does, it is registered but
**not in the DKG roster**, and `show-roster` lists it as excluded with the reason.

That is deliberate. A member holding no stake is not a neutral extra: the threshold is the
smallest `t` whose weakest `t` members exceed the security percentage, so a zero-stake member
would raise `t` by one while holding a signing share and carrying no stake. Three staked pools sit
at 2-of-3; two zero-stake members would make it 4-of-5, where the three holding *every* lovelace
of stake can no longer reach the threshold on their own. Influence has to cost stake, so a pool
joins the roster when its stake activates and not before.

Nothing is wrong during the wait. Check where you stand — excluded pools are listed with their
reason:

```bash
sudo -u heimdall heimdall show-roster --config /etc/heimdall/heimdall.toml
```

If **every** pool is still unactivated there is no roster to form at all, and the node says so and
falls back to the Phase-1 federation rather than inventing one.

### On a test bridge

Everything above is written for a bridge with real stake and a five-day epoch. A test bridge can
weight the roster by live delegation and run a shorter cycle; both are roster-wide settings and
refused on mainnet. See [Running a test bridge](#appendix-running-a-test-bridge).

---

## 7. Start it

**Debian:**

```bash
sudo systemctl enable --now heimdall
systemctl status heimdall
```

**There is no dry-run mode to enable it in.** Once started, a registered node participates: it
joins the DKG, co-signs Treasury Movements, and posts them. `HEIMDALL_ARGS` in
`/etc/default/heimdall` ships empty and should stay that way — `run-spo` has no `--broadcast` and
no `--interval-secs` (movements fall on the bridge's on-chain batch grid, which is not a local
setting), and it rejects unknown arguments, so a stray flag there stops the unit outright.

The look-before-you-leap step is the `heimdall doctor` run above, which performs every startup check
and exits without joining anything. Do that; then enable the service.

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

### Is it healthy?

```bash
sudo -u heimdall heimdall status --config /etc/heimdall/heimdall.toml
```

`status` answers **"am I healthy?"** where `doctor` answers **"can I start?"**, and it prints two
halves. The first is the same startup report `doctor` renders, from the same code — registration,
the bridge this node resolved, the ban list, the provider, the key material. The second is what only
a running daemon knows: the epoch, whether this node **qualified in the ceremony**, where it stands
on the batch grid, and any peer excluded from it.

If the daemon is not running, `status` says so and still prints the first half. That is a fact worth
reporting, not an error.

The live half comes from the operator surface on `health.bind` (loopback, `127.0.0.1:18580` by
default). It is **not** the peer endpoint from step 5 — that one's address is on chain and every SPO
fetches from it, so your own node's state does not belong there. Point your monitoring at
`http://127.0.0.1:18580/` and **alert on `last_progress_ms` failing to advance**.

> **Why there is no systemd watchdog.** `WatchdogSec`/`sd_notify` would prove the process is
> scheduling and calling home. It cannot distinguish a node co-signing movements from one stuck in a
> loop, because the same code answers either way — so it would turn `active (running)` into a green
> light that means no more than it already does, and a false signal gets trusted where a missing one
> does not. `last_progress_ms` is the honest version of that check.

The two failures worth knowing about early, because the node keeps running and looks fine through
both:

* **`dkg NOT in the qualified set`** — this node is up but not signing. Usually its endpoint was
  unreachable from outside when the ceremony ran (step 5), so peers could not fetch its round-1
  payload.
* **`peers excluded`** — a peer this node will not run a ceremony with. Both sides log it, so the
  operator on the other end sees the same line, and **the line says which of three things it is**:
  a different version or blueprint (upgrade the lagging node); a different `demo_live_stake` or
  `demo_virtual_epoch_slots` (match the setting across the roster); or only a different derived
  threshold, which is `live_stake` drifting between two reads and needs nothing done — it clears at
  the next ceremony entry. Do not upgrade a node for the third one.

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

**The bridge runs on multi-day cycles.** Peg-ins wait for ~100 Bitcoin confirmations (~12 hours),
and the daemon follows the protocol's on-chain **batch schedule** (the one from step 3) rather than
a wall-clock interval: opportunities fall on a fixed slot grid, `B_i = epoch_start +
i × tm_batch_interval`, and at each one every SPO applies the same test — is the treasury free, is
anything in flight. An opportunity that fails it passes unused, and with a 6-hour grid against
~17 hours to confirm a movement, most of them do. There is nothing to tune locally; the numbers are
the bridge's, not the node's.

The **ceremony** is the slower of the two clocks: the DKG and its Update-Y run once per Cardano
epoch (5+ days), and every batch inside that epoch is signed by the roster it produced.

A healthy idle node therefore says very little. Long silences are correct behaviour. What tells you
it is alive is `systemctl status` and the absence of `-p err` output — **[will be improved —
WI-058]**, which adds a periodic heartbeat and a `heimdall status` command, because "silent" and
"wedged" currently look the same.

### State

`/var/lib/heimdall` (`0700`) holds four things, and they are not equally replaceable:

| file | losing it costs |
|---|---|
| bifrost identity key | re-registration |
| DKG signing share | the current epoch — the node sits out until the next boundary |
| `cpo-trie.json`, `spi-trie.json` | a rebuild: `heimdall reconstruct-cpo-trie` / `reconstruct-spi-trie` walk chain history and refuse anything they cannot explain |
| `pending-tm.json` | the fold for one posted movement, which then needs the same rebuild |

Back the directory up. The two tries are **cumulative** — they are the bridge's record of what has
already been paid and already been swept — so a node whose tries are behind the chain refuses to
build rather than sign a root the chain does not hold. That refusal is loud and it names the
command; it is not a state you can wait out.

`pending-tm.json` is the movement this node has posted and not yet folded. It exists because
confirmation takes ~17 hours, and the node must be free to restart during them.

### Upgrades

New versions appear at <https://github.com/lantr-io/heimdall/releases> — same four assets, same
verification as [step 1](#where-the-releases-are). Nothing on this machine polls for them.

```bash
sudo apt install ./heimdall_<newer>-1_amd64.deb
```

Your edited `/etc/heimdall/heimdall.toml` survives — dpkg tracks it as a conffile, so a changed
shipped default is offered as a merge rather than applied silently. `/etc/default/heimdall` is not
diffed at all. The service restarts only if it was already running. `apt purge` deliberately leaves
`/var/lib/heimdall` and the `heimdall` user in place.

**Upgrade the roster together.** A node whose build the others will not run a ceremony with is
excluded from every ceremony until they match – and the exclusion is reported on *both* sides as
the other one lagging. Agree a commit and an epoch boundary with the other operators, and restart
every node before it. Upgrading one node ahead of the roster removes it from the roster.

### Leaving the bridge

Registration is reversible, and leaving is a sequence, not a command: **exit on chain first, keep
running to the epoch boundary, stop after it.** Doing those in the other order is a fault.

**1. Post the exit.** `deregister-spo` burns your membership token, unlinks your registry node from
the on-chain list and removes your Bifrost identity from the treasury's identity root — freeing
that identity, so the same key can register again later.

```bash
sudo -u heimdall heimdall deregister-spo --config /etc/heimdall/heimdall.toml
# prints what it is about to do; add --submit to actually post it
```

Your **cold** key authorises the exit, alone — nothing signs with the Bifrost identity, so losing
that key does not trap you in the registry, and there is no minimum-stake check on the way out. If
the cold key lives on another machine, which is where it should live, sign there and submit here:

```bash
# on the machine holding the cold key:
heimdall sign-revocation --cold-skey /path/to/cold.skey
# prints --cold-vkey / --cold-sig; pass both to deregister-spo on the node
```

**2. Keep the node running until the next epoch boundary.** The roster for the current epoch was
frozen before your exit and this transaction does not reach back into it: you still owe that
epoch's DKG rounds and your signature on its Treasury Movements. A node that stops here looks
exactly like a node that failed, and is treated as one. Watch for the boundary, then confirm you
are out:

```bash
sudo -u heimdall heimdall show-roster --config /etc/heimdall/heimdall.toml
```

**3. Stop it.**

```bash
sudo systemctl disable --now heimdall
```

The state directory still holds your DKG shares from the epochs you served. Keep it if you might
come back or may be asked to prove what you did; `sudo apt purge heimdall` deliberately leaves
`/var/lib/heimdall` and the `heimdall` user behind, so removing the package is not enough to erase
it — see [State](#state).

Two more things worth knowing:

- **The deposit comes back to whoever pays for the transaction.** Your registry node's locked ADA
  is freed into the change output, so it lands at the wallet that funded the exit — not
  automatically at the address that registered you, if those differ.
- **This is the voluntary door.** A roster-initiated removal for misbehaviour (`apply-ban`) is a
  different mechanism with different consequences: you do not use this command for it, and it
  cannot undo one.

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
| `[3/9] resolve the Config FAIL` | the node cannot read the bridge Config — check `config_address`, `config_nft_policy_id` and your provider |
| `[6/9] registration status FAIL` on a fresh install | expected, and not a misconfiguration — you have not registered yet. Step 6 prints the `register-spo` command. (If you *have* registered, `[bifrost].skey_path` points at a different key than the one you registered.) |
| `no reference script for the registry` right after `deploy-registry-ref` succeeded | the provider's address listing has not shown the script yet – pass the outpoint the deploy printed, `--registry-ref <tx_hash>:0` (step 6) |
| `N of M candidates run an incompatible build` at every epoch start | this node and its peers disagree on version, blueprint, threshold or a test-bridge setting; both sides report the other as lagging. Compare `/health` across the roster and change the odd one out, together – see *Upgrades* |
| `[9/9] post a movement FAIL` | this bridge has never published its treasury-movement validator on chain, so no SPO can post — `binocular deploy-script-refs`, re-run, publishes it and skips what already exists. Not something one operator's config can fix |
| a key you set is `refused` at load | it names a value the Config publishes; delete it, and `show-config-params` prints what the chain says |
| `trie diverged` or `trie is out of sync with the chain` | this node's cumulative state is behind the bridge's — run the `reconstruct-…` command the message names; it rebuilds from chain history and refuses anything it cannot explain |
| a transaction is refused | read the whole message: the min-stake gate and the preflight both refuse loudly rather than submitting something wrong |
| it refuses to start over `cardano.fault_proof_srs_path` | you have DKG fault enforcement configured on mainnet against a setup that is not trustworthy — see [the fault-proof trusted setup](fault-proof-srs.md) |

For building heimdall or cutting a release, see [CONTRIBUTING.md](../CONTRIBUTING.md). For the
per-route deployment reference, see [deploy/README.md](../deploy/README.md). If you configure the
DKG fault verifiers — the packaged config does not, and most operators never will — read
[the fault-proof trusted setup](fault-proof-srs.md) first.

---

## Appendix: forming the initial federation

**This is not part of joining a bridge.** If you are an SPO, the federation key already exists,
you read it from the Config, and nothing here applies to you — the nine steps above are your whole
path. This appendix is for the people *standing a bridge up*, and for them it comes first: it runs
before genesis, so before there is a bridge for anyone to join.

It is an appendix rather than step 0 because it needs two things the numbered steps give you —
your Bifrost identity key ([step 2](#2-create-your-bifrost-identity-key)) and a reachable endpoint
([step 5](#5-make-your-endpoint-reachable)) — and because everyone else should skip it. Do those
two steps, come back here, then continue from [step 3](#3-fill-in-the-config).

The **federation setup key** `federation_setup_Y` is the key in the CSV recovery leaf of both
Taproot trees — the treasury's and every peg-in deposit's. It is the way the treasury moves when
the FROST group is dark, after `federation_csv_blocks` have passed. It is also an *input* to
genesis: the treasury address the genesis anchor is funded at is derived from it. So it must exist
before the bridge does, which is why nothing in this appendix reads a chain.

**The setup name applies only here.** Genesis publishes this key as **Config #11**, and from that
point on it is called `y_federation` and *everyone reads it from the chain* — no SPO ever types it
into a config file, and heimdall refuses a local value that disagrees with the published one. The
two names are the same 32 bytes; what differs is whether anything but your own machine knows them
yet. If you are joining an existing bridge, `y_federation` is all you will ever meet.

It is generated by the federation *together*: a `t`-of-`n` FROST key, so that the mechanism which
exists *because* the signing group might be unavailable is not itself one person's secret. No
member can move the treasury alone, and no member's failure takes the recovery path with it.

Every member does this on their own machine. Read the whole appendix first — the members have to
agree on two things before anyone runs anything.

### Step 1 — each member creates their identity key

The ceremony authenticates every payload under your Bifrost identity key — the one
[step 2](#2-create-your-bifrost-identity-key) creates, and the same key you will register with
later. Print its public half:

```bash
heimdall bifrost-id --config heimdall.toml
#   bifrost_id_pk: <64 hex>          ← give this, and your endpoint URL, to the others
```

Your endpoint URL (`https://spo1.example.com`, or `http://host:18500` in a test network) has to be
reachable before the ceremony, not merely decided — the other members fetch from it.
[Step 5](#5-make-your-endpoint-reachable) is that step; do it now if you have not.

### Step 2 — everyone agrees on the same member list and threshold

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

### Step 3 — everyone runs the ceremony

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

### Step 4 — derive the genesis treasury address

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
  --y51 <the treasury's current FROST key> \
  --signers 1,3,4
```

There is no `--outpoint` or `--amount-sat` to look up: the treasury is read from the bridge state
on Cardano, the same read `show-treasury` and the auto-mover use. You *can* pass both — for a
treasury the bridge state does not know about — but a value that disagrees with the chain is
refused rather than preferred. When you and the chain disagree about where the treasury is, one of
you is wrong, and this is the command you run when the FROST group is dark and nobody is left to
catch it.

Before any signing starts, the command checks the CSV delay: the recovery leaf is a *relative*
timelock, so the treasury UTxO must be `federation_csv_blocks` deep. Too shallow and it stops there
and says how many blocks remain — otherwise a whole signing session among the members is spent
before the network rejects the result. If `bitcoin.rpc_url` is unset heimdall cannot read Bitcoin
from your machine, so it prints the requirement and continues rather than blocking recovery on a
node an SPO is not expected to run.

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

## Appendix: running a test bridge

**This is not part of joining a bridge.** Nothing here is set on a production node: every setting
below is refused on mainnet, and each is a roster-wide value that every node must carry
identically or the roster splits. It exists for the people running a test bridge, who need a first
ceremony before stake activates and a key rotation more often than every five days.

### Not waiting for stake to activate

If you are standing up a test bridge, this is not a delay to sit through: with every pool
registered in the same epoch there is no usable roster at all until stake activates. Weight the
roster by `live_stake` — the delegation as it is right now — instead of the snapshot:

```toml
[cardano]
demo_live_stake = true      # TEST BRIDGES ONLY
```

Your delegation then counts from the moment it lands.

This needs a backend that reports it. A **yaci-devkit devnet** (`stake_source = "yaci_store"`)
publishes no `live_stake`, so the flag does nothing there and the node says so at startup — on a
devnet there is no shortening the wait.

**Every node of the roster must set this identically.** It is not a display setting: it decides
each pool's weight, and therefore the FROST threshold. `live_stake` also drifts continuously as
delegation moves, which is exactly why the normal path uses the epoch snapshot — two SPOs reading
it seconds apart can derive different thresholds and produce signatures that never aggregate.

Four things make a mistake here visible rather than mysterious:

- Each node logs a `TEST RUN` warning at startup naming the flag.
- Each node publishes the flag, **and the threshold it derived**, on its `/health` — and every
  node checks its peers' before the ceremony starts. A peer that disagrees is named by pool id
  and left out of that ceremony; the ones that agree carry on without it, over a threshold
  re-derived across whoever is left, and without burning an attempt. This matters because a
  weight disagreement does **not** show up as a candidate-set disagreement: both nodes see the
  same members, so without that check it looks like agreement right up until the ceremony fails
  to aggregate. The same check catches a `stake_source` or `demo_exclude_unstaked` difference —
  both are published and compared by name — and drift between two correctly-configured nodes.
- `network = "mainnet"` **refuses to start** with the flag set. It is not warned about, because a
  warning in a journal is not something anyone reads before the first ceremony fails. A network
  heimdall cannot resolve — an unknown spelling, or one that disagrees with your
  `config_address` — is treated as mainnet, so the guard cannot be slipped by a capital letter.
- `heimdall doctor` and `run-spo --check` report it, so it cannot hide behind "all checks passed".

Two nodes that both set the flag **correctly** can still derive different thresholds, because
`live_stake` moves between their two reads. That is caught by the same check, and the log line
says so explicitly — it is drift, not a build problem, and **do not upgrade anything**; the next
ceremony entry re-reads and normally agrees. It is the reason this is a test-bridge setting and
not a way to run a bridge.

### Turning it off again

Once stake has activated, `active_stake` is what you wanted all along, and leaving the flag on
keeps a drifting value in a consensus decision for no benefit.

**Do not turn it off one node at a time.** It is the same roster-wide value going the other way:
a node that switches mid-epoch re-derives a different threshold from its peers, publishes a
Round-1 commitment vector of the wrong length, and is dropped from the ceremony by every other
node — which will report *the honest majority* as the side that disagrees.

Stake also activates per-pool at different epochs, so "once your stake has activated" is not a
moment the roster shares. Agree an epoch boundary with the other operators, change the flag on
every node before it, and restart them together.

### Not waiting five days per rotation

`demo_live_stake` gets a test roster to its first ceremony. The next wall is the cycle itself: a
Cardano epoch is **five days on preprod exactly as on mainnet**, and the DKG, the Update-Y and the
whole batch grid hang off the epoch boundary. Watching one key rotation end to end therefore costs
five days per attempt.

A test bridge can run a shorter cycle of its own:

```toml
[cardano]
demo_virtual_epoch_slots = 86400    # TEST BRIDGES ONLY — a 24-hour cycle
```

The cycle is derived from the chain, not from your clock: it is `tip_slot / 86400`, counted from
slot 0, so every node computes the same number from the same tip with nothing to agree on
beforehand. It must be at least 43200 slots (twelve hours) and shorter than a real epoch; anything
else is refused when the config loads.

**The ceremony deadlines rescale with it, automatically.** The Config publishes a schedule written
for a five-day epoch, whose last batch opportunity is four days in — dropped unchanged into a
24-hour cycle that sits three days past the end of the cycle it belongs to. So the four values
measured as an offset from the cycle start are scaled by `demo_virtual_epoch_slots / 432000`:
`dkg_r1_deadline`, `dkg_r2_deadline`, `update_y_deadline` and `final_tm_cutoff`. You do not
hand-tune anything, which is the point: a rescale derived from two agreed numbers cannot diverge
between nodes, and hand-copied Config values would.

**Nothing else is scaled, and that is deliberate.** Every other value in the schedule is measured
against something a shorter bridge cycle does not shorten:

- `tm_batch_interval` stays at the published pitch. It is tied to `stability_window` by
  `C_i = B_i − stability_window`, and it must stay *above* it — the deposits a cycle leaves over
  are picked up by the next cycle's **first** batch, which is the last one that runs before the
  treasury key rotates. Push the pitch below the window and those deposits miss that batch, the
  key rotates, and they are unsweepable for good. A shorter cycle therefore gets **fewer batch
  opportunities**, not smaller ones.
- `tm_recovery_window` stays put: it is how long a submitted Bitcoin transaction may go unconfirmed
  before the bridge replaces it, and Bitcoin does not confirm faster on a test bridge.
- `sign_r1_window`, `sign_r2_window` and `leader_slot_t` stay put: they are network round-trip
  budgets, and peers do not answer faster either.

heimdall refuses to start a cycle its schedule cannot fit — one holding no batch opportunity, one
whose rotation deadline falls inside the ceremony window a node cannot start before, or one on a
bridge whose `stability_window` already exceeds its own batch pitch. Each refusal names the value
and what to change.

**Every node of the roster must set this identically — more so than any other setting in this
guide.** The DKG namespace is `(epoch, threshold, attempt)`. Two nodes on different cycles compute
different epoch numbers, so they publish into namespaces that never fetch each other: nothing
errors on either side, and each simply waits for a ceremony the other cannot see. This is why the
check is on `/health` and runs before anything is published — a mismatched peer is named and
excluded up front, rather than discovered by a ceremony that quietly never converges.

The same guards as `demo_live_stake` apply: a `TEST RUN` warning at startup naming the value,
`heimdall doctor` reporting it, and a **refusal to start** on `network = "mainnet"` (or on any
network heimdall cannot resolve).

### Choosing the number

The floor and ceiling are checked for you (43200 slots to just under a real epoch), but they leave a
wide range, and the value that matters is not the cycle length — it is **how many batch
opportunities the cycle contains**, because that is how many chances a deposit gets.

Only `final_tm_cutoff` shrinks; `tm_batch_interval` does not. So the count is
`final_tm_cutoff ÷ tm_batch_interval` after the rescale, and it falls away faster than the cycle
does. Against the schedule the shared preprod bridge publishes today — pitch 21600, cutoff 345600 —
that gives:

| `demo_virtual_epoch_slots` | cycle | `final_tm_cutoff` | batch opportunities | `update_y_deadline` |
|---|---|---|---|---|
| 43200 | 12 h | 34560 (9.6 h) | **1** | 1080 (18 min) |
| 86400 | 24 h | 69120 (19.2 h) | **3** | 2160 (36 min) |
| 172800 | 48 h | 138240 (38.4 h) | **6** | 4320 (72 min) |

Read your own bridge's numbers with `heimdall show-config-params` rather than copying these — the
schedule is governance-set and the rescale is `published × slots ÷ 432000`.

**A 12-hour cycle gives you one opportunity, and that is usually the wrong trade.** One movement per
cycle means a deposit that misses it waits a whole cycle, and a cycle whose single opportunity passes
unused — a movement still in flight, a peer late to round 1 — moves nothing at all. 86400 is the
value to reach for first: it rotates the key daily, which is the thing you are usually trying to
watch, and still leaves three chances to move coins.

One trap worth knowing before you hit it. The rotation deadline must clear the window a node cannot
enter a ceremony before (`dkg_window_secs + dkg_join_wait_secs`, 900 slots by default), and it
rescales while that floor does not. With the published schedule the scaled deadline is
`slots ÷ 40`, so the usable minimum is **40 × your ceremony floor** — 36000 slots at the default,
comfortably under the 43200 floor. Widen `dkg_window_secs` to 20 minutes and the requirement moves to
48000, at which point a 12-hour cycle is refused and 86400 is your smallest option. The refusal names
`update_y_deadline` and the ceremony window, so you will not have to work this out from symptoms.

### Confirming it took

Three places say so, and it is worth checking all three, because the failure this setting causes is
silent on both sides.

1. **At startup**, every node logs a `TEST RUN` warning naming the slot count:

   ```
   [epoch] TEST RUN: the bridge cycle is a 86400-slot VIRTUAL epoch
   (cardano.demo_virtual_epoch_slots), not Cardano's five-day one, and the ceremony
   deadlines are rescaled to fit it. EVERY node of this roster must set the same value —
   a mismatch splits the DKG namespace. It is refused on mainnet
   ```

   A node missing this line is on real epochs, whatever its config file says — a misspelled key
   parses as unset.

2. **`heimdall doctor`** reports it as an advisory (a `WARN`, not a failure — the node still
   starts).

3. **Across the roster**, `/health` carries the value and peers compare it before publishing
   anything. A node whose cycle differs is named and excluded up front. This is the check that
   matters: a namespace split produces no error on either side, so without it you would see only
   two rosters each waiting for a ceremony the other cannot see.

### What a shorter cycle does not change

- **`stability_window` does not rescale.** It is a property of Cardano — how far a transaction must
  be behind the tip before it is safe to build on — and Cardano does not settle faster because your
  bridge's cycle is shorter. A deposit still has to age the published window (currently 2 hours on
  the shared preprod bridge) before any batch will pick it up, so the wait for a deposit is set by
  the window, never by the cycle. A bridge whose published window is **larger than its batch
  interval** is refused a virtual epoch outright: such a bridge already strands the deposits each
  cycle leaves over, and running its rotation five times as often would only multiply that.
- **Cardano's own epoch is still the real one.** The stake snapshot, the ban cutoff time and
  `max_tx_size` are all read under the real Cardano epoch. Only the bridge's own schedule is
  virtual.
- **It does not replace `demo_live_stake`.** Stake activation is still two real Cardano boundaries;
  a shorter bridge cycle does nothing about that.

Turning it off follows the same rule as the flag above: it is a roster-wide value, so change it on
every node and restart them together, or the roster splits into two cycles that cannot see each
other. Note that epoch numbers do not line up across the change — a virtual cycle counts from slot
0 and is a much larger number than a Cardano epoch — so treat the switch as a restart of the
bridge's ceremony history, not as a continuation of it.
