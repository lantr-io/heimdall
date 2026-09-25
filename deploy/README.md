# Deploying Heimdall

Two shapes off the same static musl binary, both running the SPO daemon (`heimdall run-spo`),
which joins the DKG and co-signs Treasury Movements with the rest of the roster.

- **[Debian package](#debian-package)** — `heimdall.service`, config in `/etc/heimdall`. The
  general-purpose route, published on each release.
- **[Docker image](#docker-image)** — `ghcr.io/lantr-io/heimdall`, config bind-mounted into
  `/etc/heimdall`. Same binary, no systemd; published on each release.

A third shape, the `heimdall-mover` NixOS module, was removed on 2026-09-19. It ran `run-mover`,
a single-process devnet tool that could not sign a real bridge's treasury, and `dev.lantr.io`
had moved to the SPO daemon long before: the mover spent its last three weeks skipping every
tick against a treasury head the bridge had already orphaned. The `run-mover` command itself is
untouched — run it by hand where you want it. Git history has the module and its `deploy.sh`.

New to heimdall? Read the [operator guide](../docs/operator-guide.md) first — it walks the whole
path from a clean machine to a registered, running node, and links back here for the details. This
page is the per-route reference.

---

## Debian package

```bash
sudo apt install ./heimdall_<version>_amd64.deb    # or: sudo dpkg -i … && sudo apt -f install
```

Grab the `.deb` from the [releases page](https://github.com/lantr-io/heimdall/releases) (alongside
`heimdall` and the checksums), or build one from a binary you already have:

```bash
deploy/build-linux.sh                # → deploy/out/heimdall (static musl)
sh deploy/debian/build-deb.sh        # → deploy/out/heimdall_<version>_amd64.deb
```

`build-deb.sh` never compiles: it wraps an existing binary, so the package and the loose release
asset are the same file. The release workflow calls it with `VERSION` set to the dispatched
version; locally the version defaults to the `Cargo.toml` version plus the commit
(`0.1.0+8a60fd3-1`).

What it installs:

| Path | Contents |
|---|---|
| `/usr/bin/heimdall` | the static binary — no dependency chain |
| `/lib/systemd/system/heimdall.service` | the unit |
| `/etc/heimdall/heimdall.toml` | bridge config, dpkg conffile, `0640 root:heimdall` |
| `/etc/default/heimdall` | `$HEIMDALL_ARGS` + `$HEIMDALL_MNEMONIC`, conffile, `0640` |
| `/var/lib/heimdall` | state (`state_dir`), `0700 heimdall` |

The package installs no wallet key. If you use `cardano.payment_skey_path` instead of a
mnemonic, put your own `payment.skey` wherever that key points and make it readable by the
unit's user: `chown heimdall: … && chmod 600 …`. A root-owned `0600` key is unreadable to
`User=heimdall` and the daemon reports only `Permission denied`.

**The service is installed disabled, and that is deliberate.** heimdall cannot run before it has a
bridge configuration and key material, so enabling it on install would guarantee a failed unit on
every fresh machine. After configuring:

```bash
# One dry-run tick, AS THE SERVICE USER: the config is 0640 root:heimdall and
# /var/lib/heimdall is 0700 heimdall, so running this as yourself cannot read the
# config, and running it as root would leave root-owned files in the state dir.
# And WITH THE UNIT'S ENVIRONMENT: the mnemonic is in /etc/default/heimdall, which
# `sudo -u heimdall heimdall …` does not read — it would report "no wallet key".
sudo systemd-run --pipe --wait --quiet --collect -p User=heimdall \
    -p EnvironmentFile=/etc/default/heimdall \
    /usr/bin/heimdall run-spo --config /etc/heimdall/heimdall.toml --check

sudo systemctl enable --now heimdall
journalctl -u heimdall -f
```

Notes:

- **Errors are greppable.** Every line carries a level and journald files it at the matching
  priority, so `journalctl -u heimdall -p err` shows what failed and `-p warning` what degraded
  first. Turn detail up without editing a conffile by setting `RUST_LOG` in
  `/etc/default/heimdall` (or `systemctl edit heimdall`) and restarting.
- **Secrets belong in `/etc/default/heimdall`,** not in the TOML. heimdall reads
  `$HEIMDALL_MNEMONIC` only when `cardano.mnemonic` is absent from the config file, so leaving that
  key commented out is what activates the environment variable — and keeps the seed out of a file
  dpkg tracks and diffs on upgrade.
- **`$HEIMDALL_ARGS` ships empty, and for a normal node it stays empty.** `run-spo` has no
  cadence flag — movements fall on the bridge's on-chain batch grid, which is not a local
  setting — and no `--broadcast`: a configured, registered node participates from its first
  start. The way to look before enabling is `--check` above, which joins nothing. (`--broadcast`
  and `--interval-secs` are `run-mover` flags; `run-spo` rejects unknown arguments, so leaving one
  in this file stops the unit before any check runs.)
- **No Bitcoin node is needed.** The unit orders after `network-online.target` only. heimdall posts
  Treasury Movements to Cardano; the watchtowers relay them to Bitcoin.
- **`apt purge` leaves `/var/lib/heimdall` and the `heimdall` user alone** — the directory holds the
  bifrost identity key and the current epoch's DKG share, neither of which a package manager should
  delete without being asked. `postrm` prints a reminder; remove it by hand.
- Upgrades restart the service only if it was already running, and keep your edited conffiles.

---

## Docker image

Same static binary as the `.deb`, wrapped for hosts that run containers instead of systemd units.
The release workflow builds it from the binary it just *published* and verifies the checksum, so
the image, the package and the release asset are provably one file.

```bash
docker pull ghcr.io/lantr-io/heimdall:<version>

# Start from the commented template shipped inside the image.
docker run --rm ghcr.io/lantr-io/heimdall:<version> \
    cat /usr/share/heimdall/heimdall.toml.example > heimdall.toml
$EDITOR heimdall.toml

docker run -d --name heimdall \
    -v "$PWD/heimdall.toml:/etc/heimdall/heimdall.toml:ro" \
    -v heimdall-state:/var/lib/heimdall \
    -e HEIMDALL_MNEMONIC="word word word ..." \
    -p 18500:18500 \
    --restart unless-stopped \
    ghcr.io/lantr-io/heimdall:<version>

docker logs -f heimdall
```

`docker run` with no config exits 78 immediately, printing the commands above rather than
crash-looping with a stack of unexplained failures. Note that a restart policy still restarts it —
it just restarts printing a legible reason.

The image is the same CLI, so anything else is a subcommand:

```bash
docker run --rm ghcr.io/lantr-io/heimdall:<version> --version
docker run --rm -v "$PWD/heimdall.toml:/etc/heimdall/heimdall.toml:ro" \
    ghcr.io/lantr-io/heimdall:<version> show-treasury --config /etc/heimdall/heimdall.toml
docker exec -it heimdall sh          # a shell, for when it misbehaves
```

Notes:

- **Do not narrow `bind_address` to loopback in a container.** It defaults to `0.0.0.0`, which is
  what you want here: `127.0.0.1` inside a container is invisible even with `-p`, so peers cannot
  fetch this node's DKG rounds and it drops out of the qualified set contributing nothing. The
  entrypoint warns if it finds loopback, but it cannot know what you registered.
- **The port comes from your registered `bifrost_url` unless you set `http.listen_port`.** By
  default the daemon binds the port inside that URL; `listen_port` decouples the two, which is what
  you want when the published container port differs from the one heimdall listens on.
- **Name the state volume.** `/var/lib/heimdall` holds the per-epoch DKG signing share and the
  completed-peg-outs trie. A container replaced without a named volume comes back unable to resume
  its epoch and believing every completed peg-out is unpaid. The directory is `0700`, owned by the
  in-image `heimdall` user (uid 950).
- **Mount the config read-only, and never bake it into an image.** It carries a wallet mnemonic and
  a Blockfrost project id; an image that contains it will push them to a registry. Prefer
  `-e HEIMDALL_MNEMONIC` and leave `cardano.mnemonic` commented out — heimdall reads the
  environment only when the config key is absent.
- **The image runs as non-root** and contains no config and no secrets: `/etc/heimdall` ships empty.
- **The base is alpine, not `scratch`.** heimdall reads Cardano over HTTPS and OpenSSL loads its
  trust store from `/etc/ssl/certs`, which `scratch` does not have — measured: a `scratch` image
  prints `--version` correctly and then fails preflight step 2 on every Blockfrost request. Since a
  CA bundle has to be copied in either way, the remaining difference is a shell for diagnosing a
  daemon in production, which is worth ~8 MB on top of a 26 MB binary.

Building it locally (consumes an already-built binary; it never runs cargo):

```bash
deploy/build-linux.sh                  # produces deploy/out/heimdall
sh deploy/docker/build-image.sh        # wraps it as heimdall:<version>
```

---

## Building only

```bash
deploy/build-linux.sh          # incremental (cached cargo + target Docker volumes)
deploy/build-linux.sh --clean  # wipe caches, full rebuild
```

Produces a fully static `x86_64-linux` (musl) ELF at `deploy/out/heimdall` via a linux/amd64
`rust:alpine` container — a native musl build, no cross toolchain. openssl (from
reqwest → native-tls) is linked statically, so the binary has no runtime deps.

## Watching logs

```bash
journalctl -fu heimdall -o cat
```

Each batch opportunity prints a `═══ batch B_i @ slot N ═══` banner and what it froze. A batch
with nothing eligible, or one whose previous movement is still unconfirmed on Bitcoin, passes
unused and says so.

Everything the daemon says carries a level, and journald files it at the matching syslog
priority — so the two questions worth asking have direct answers:

```bash
journalctl -u heimdall -p err      # did anything fail?
journalctl -u heimdall -p warning  # ...and what degraded before it did?
```

That works because heimdall prefixes each line with `<N>` when systemd is capturing its stdout
(it detects `JOURNAL_STREAM`); without the prefix systemd files *both* stdout and stderr at
priority 6, and `-p err` finds nothing on a broken node. Nothing in the unit configures this.

To turn up the detail on a running node, without a rebuild and without editing the config:

```bash
systemctl edit heimdall     # [Service] Environment=RUST_LOG=debug
systemctl restart heimdall
```

A bare level is scoped to heimdall and leaves reqwest/hyper at `warn`; pass a full directive
(`RUST_LOG=warn,heimdall::cardano::blockfrost_chain=debug`) to aim at one module. `--log-format
json` emits one object per event for a shipper. Interactively, `heimdall --log-level debug …`
does the same thing for a single run.

Note what is *not* a log: `show-treasury`, `show-roster`, `show-config-params` and the signed-tx
output of the one-shot commands are reports printed on stdout, untimestamped and never silenced
by a log level, so they stay parseable by a script.

### The event lines

The few lines worth an interruption — a DKG round opening and who is in it, the group key and
treasury address it produced, an Update-Y posted, a treasury movement built, posted or
confirmed — are written at `info` under the tracing target `heimdall::event`, one line each:

```bash
journalctl -u heimdall -o cat | grep 'heimdall::event:'
```

A bare `RUST_LOG`/`--log-level` keeps that target at `info` however quiet the rest is, so a node
at `warn` still records what it did; only a full directive (`warn,heimdall=warn`) silences it.

## Discord notifications

heimdall itself posts nothing anywhere: it is the security-critical process and should not be
opening connections to a chat service from inside an operator's network. The relay is a separate
program, [`tools/heimdall-discord`](../tools/heimdall-discord/README.md), that reads the log — a
file, a unit's journal, or stdin — and posts the event lines plus everything at `warn` or above
to a webhook. It needs no config, no key and no chain access, and can run as another user or on
another host.

```bash
export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/<id>/<token>'
heimdall-discord --unit heimdall                                   # this package's unit
heimdall-discord --unit heimdall@spo1 --unit heimdall@spo2         # template instances
heimdall-discord --file spo1=/var/log/heimdall/spo1.log --dry-run  # a file; print, don't post
```

## Notes

- **Config is secret.** It holds the Blockfrost project id and the wallet mnemonic. Install it
  `0640 root:heimdall` at most, and keep the mnemonic in `/etc/default/heimdall` instead where
  the route allows it.
- **Look before joining.** `run-spo --check` resolves the config, the roster and the key material
  and then exits, joining no DKG and posting nothing.
- **One node per registered identity.** Each member is a distinct registration with its own key,
  port and state dir; do not run two processes as the same registered SPO.
