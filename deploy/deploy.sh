#!/usr/bin/env bash
# Build the static musl heimdall binary on this machine and ship it to the mover box.
#
#   deploy/deploy.sh root@host                 # build + copy binary + restart service
#   deploy/deploy.sh root@host --with-config   # also copy heimdall-bip322.toml (first deploy / config change)
#   deploy/deploy.sh root@host --no-build      # skip the build, ship the existing deploy/out/heimdall
#
# The binary and config live in /var/lib/heimdall on the box (out of the Nix store).
# The config carries the Blockfrost id + wallet mnemonic, so it is installed mode 600.
set -euo pipefail

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
    echo "usage: $0 user@host [--with-config] [--no-build]" >&2
    exit 1
fi
shift

WITH_CONFIG=0
BUILD=1
for arg in "$@"; do
    case "$arg" in
        --with-config) WITH_CONFIG=1 ;;
        --no-build) BUILD=0 ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/deploy/out/heimdall"
CONFIG="heimdall-bip322.toml"
STATE_DIR="/var/lib/heimdall"
USER_NAME="heimdall"

if [[ "$BUILD" == "1" ]]; then
    "$ROOT/deploy/build-linux.sh"
fi

if [[ ! -f "$BIN" ]]; then
    echo "binary not found at $BIN — run without --no-build" >&2
    exit 1
fi

echo "==> Staging binary to $HOST:/tmp"
scp "$BIN" "$HOST:/tmp/heimdall"
if [[ "$WITH_CONFIG" == "1" ]]; then
    scp "$ROOT/$CONFIG" "$HOST:/tmp/$CONFIG"
fi

echo "==> Installing into $STATE_DIR and restarting service (on the box)"
# shellcheck disable=SC2087
ssh "$HOST" "install -o $USER_NAME -g $USER_NAME -m 755 /tmp/heimdall $STATE_DIR/heimdall && \
    if [ -f /tmp/$CONFIG ]; then install -o $USER_NAME -g $USER_NAME -m 600 /tmp/$CONFIG $STATE_DIR/$CONFIG && rm -f /tmp/$CONFIG; fi && \
    rm -f /tmp/heimdall && \
    systemctl restart heimdall-mover && \
    systemctl --no-pager --lines=0 status heimdall-mover"

echo "==> Done. Watch logs with:  ssh $HOST 'journalctl -fu heimdall-mover -o cat'"
