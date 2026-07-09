# Deploying the Heimdall auto-mover to a NixOS box

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

## Notes

- **Config is secret.** `heimdall-bip322.toml` holds the Blockfrost project id and the wallet
  mnemonic; `deploy.sh` installs it mode 600 owned by `heimdall`. It is not in the Nix store.
- **Dry-run first.** To watch ticks without posting, set `services.heimdall-mover.broadcast = false`
  and rebuild, or run `heimdall run-mover --config … --once` by hand as the `heimdall` user.
- **One instance per bridge.** The mover runs on the current contracts with no leader election —
  do not run a second instance against the same bridge.
