# Deploying Heimdall

Two supported shapes, both running `heimdall run-mover` as a systemd service off the same static
musl binary:

- **[Debian package](#debian-package)** — `heimdall.service`, config in `/etc/heimdall`. The
  general-purpose route, published on each release.
- **[NixOS module](#deploying-the-heimdall-auto-mover-to-a-nixos-box)** — `heimdall-mover.service`,
  binary and config in `/var/lib/heimdall`. What `dev.lantr.io` runs.
- **[Docker image](#docker-image)** — `ghcr.io/lantr-io/heimdall`, config bind-mounted into
  `/etc/heimdall`. Same binary, no systemd; published on each release.

They are separate deployments with different unit names and different config paths; do not mix
their instructions. Running both against one bridge is a mistake — see *One instance per bridge*
below.

---

## Debian package

```bash
sudo apt install ./heimdall_<version>_amd64.deb    # or: sudo dpkg -i … && sudo apt -f install
```

Grab the `.deb` from the release page (alongside `heimdall` and the checksums), or build one from
a binary you already have:

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

**The service is installed disabled, and that is deliberate.** heimdall cannot run before it has a
bridge configuration and key material, so enabling it on install would guarantee a failed unit on
every fresh machine. After configuring:

```bash
# One dry-run tick, AS THE SERVICE USER: the config is 0640 root:heimdall and
# /var/lib/heimdall is 0700 heimdall, so running this as yourself cannot read the
# config, and running it as root would leave root-owned files in the state dir.
sudo -u heimdall heimdall run-mover --config /etc/heimdall/heimdall.toml --once

sudo systemctl enable --now heimdall
journalctl -u heimdall -f
```

Notes:

- **Secrets belong in `/etc/default/heimdall`,** not in the TOML. heimdall reads
  `$HEIMDALL_MNEMONIC` only when `cardano.mnemonic` is absent from the config file, so leaving that
  key commented out is what activates the environment variable — and keeps the seed out of a file
  dpkg tracks and diffs on upgrade.
- **Extra CLI flags go in `$HEIMDALL_ARGS`,** so `--broadcast` and `--interval-secs` can change
  without editing the unit. A fresh install runs *without* `--broadcast`: every tick is a dry run
  until you add it.
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

- **`bind_address` must not be loopback.** `127.0.0.1` inside a container is invisible even with
  `-p`, so peers cannot fetch this node's DKG rounds and it drops out of the qualified set
  contributing nothing. Set `http.bind_address = "0.0.0.0"` and publish the port your registered
  `bifrost_url` names — `base_port + signer_index`, so a node at index 3 is on 18503, not 18500.
  The entrypoint warns about this on startup, but it cannot know what you registered.
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

## Deploying the Heimdall auto-mover to a NixOS box

Runs the WI-028 treasury auto-mover (`heimdall run-mover`) as a systemd service
(`heimdall-mover`) against the preprod BIP-322 bridge. The static binary and config live in
`/var/lib/heimdall` (out of the Nix store); only the service definition is declarative.

The mover chain-sources the treasury from Cardano and reads every bridge identifier from the
config's `[cardano]` section, so it needs only `--config heimdall-bip322.toml`. It talks to
Blockfrost (preprod) and the box's local `bitcoind` (RPC `127.0.0.1:48332`, provided by the
existing `bitcoind-watchtower` service). BTC broadcast stays off (`bitcoin.submit = false`) —
binocular's relay broadcasts the Bitcoin side; Cardano posting is gated by
`cardano.submit_oracle = true`.

## One-time setup on the box

1. Add the module to your host's NixOS configuration (e.g. copy it into `/etc/nixos/`):

   ```nix
   imports = [ ./heimdall-mover.nix ];
   services.heimdall-mover.enable = true;
   ```

   Then `nixos-rebuild switch`. This creates the `heimdall` user, `/var/lib/heimdall`, and the
   `heimdall-mover` service. The service will fail to start until the binary + config are present —
   that's expected.

2. First deploy (binary + config):

   ```bash
   deploy/deploy.sh root@dev.lantr.io --with-config
   ```

## Routine deploys (new binary only)

```bash
deploy/deploy.sh root@dev.lantr.io
```

Builds the static musl binary (`deploy/build-linux.sh`), copies it to
`/var/lib/heimdall/heimdall`, and restarts the service. No `nixos-rebuild` needed — that's only
for changes to the service definition.

## Deploying a published release (no local build)

Cut a release from the **Release** GitHub Action (Actions tab → Release → Run workflow, enter a
version like `0.2.0`). It builds the same static musl binary in `rust:alpine` — via the shared
`deploy/build-musl.sh` recipe — and publishes it as `heimdall` (+ `heimdall.sha256`) on a
`v0.2.0` release. Then ship that exact artifact to the box:

```bash
deploy/deploy.sh root@dev.lantr.io --release v0.2.0
```

This downloads the release asset with `gh release download`, verifies the checksum, and installs +
restarts as usual (no local Docker build). Requires the `gh` CLI authenticated to `lantr-io/heimdall`.
Confirm what's running with `ssh root@dev.lantr.io '/var/lib/heimdall/heimdall --version'` — it
prints the embedded version + commit, e.g. `heimdall 0.2.0 (abc1234 2026-07-09)`.

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
ssh root@dev.lantr.io 'journalctl -fu heimdall-mover -o cat'
```

Each tick prints a `═══ auto-mover tick #N ═══` banner and the treasury scan / peg-in / peg-out
collection results. Ticks that find nothing pending (or a movement already in flight) skip.

Everything the daemon says carries a level, and journald files it at the matching syslog
priority — so the two questions worth asking have direct answers:

```bash
journalctl -u heimdall-mover -p err      # did anything fail?
journalctl -u heimdall-mover -p warning  # ...and what degraded before it did?
```

That works because heimdall prefixes each line with `<N>` when systemd is capturing its stdout
(it detects `JOURNAL_STREAM`); without the prefix systemd files *both* stdout and stderr at
priority 6, and `-p err` finds nothing on a broken node. Nothing in the unit configures this.

To turn up the detail on a running node, without a rebuild and without editing the config:

```bash
systemctl edit heimdall-mover     # [Service] Environment=RUST_LOG=debug
systemctl restart heimdall-mover
```

A bare level is scoped to heimdall and leaves reqwest/hyper at `warn`; pass a full directive
(`RUST_LOG=warn,heimdall::cardano::blockfrost_chain=debug`) to aim at one module. `--log-format
json` emits one object per event for a shipper. Interactively, `heimdall --log-level debug …`
does the same thing for a single run.

Note what is *not* a log: `show-treasury`, `show-roster`, `show-config-params` and the signed-tx
output of the one-shot commands are reports printed on stdout, untimestamped and never silenced
by a log level, so they stay parseable by a script.

## Notes

- **Config is secret.** `heimdall-bip322.toml` holds the Blockfrost project id and the wallet
  mnemonic; `deploy.sh` installs it mode 600 owned by `heimdall`. It is not in the Nix store.
- **Dry-run first.** To watch ticks without posting, set `services.heimdall-mover.broadcast = false`
  and rebuild, or run `heimdall run-mover --config … --once` by hand as the `heimdall` user.
- **One instance per bridge.** The mover runs on the current contracts with no leader election —
  do not run a second instance against the same bridge.
