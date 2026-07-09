#!/usr/bin/env bash
# Build (or download) the static musl heimdall binary and ship it to the mover box.
#
#   deploy/deploy.sh root@host                 # build locally + copy binary + restart service
#   deploy/deploy.sh root@host --with-config   # also copy heimdall-bip322.toml (first deploy / config change)
#   deploy/deploy.sh root@host --no-build      # skip the build, ship the existing deploy/out/heimdall
#   deploy/deploy.sh root@host --release v0.2.0 # download the binary from a GitHub release instead of building
#
# The binary and config live in /var/lib/heimdall on the box (out of the Nix store).
# The config carries the Blockfrost id + wallet mnemonic, so it is installed mode 600.
set -euo pipefail

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
    echo "usage: $0 user@host [--with-config] [--no-build] [--release <tag>]" >&2
    exit 1
fi
shift

REPO="lantr-io/heimdall"
WITH_CONFIG=0
BUILD=1
RELEASE_TAG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-config) WITH_CONFIG=1 ;;
        --no-build) BUILD=0 ;;
        --release) shift; RELEASE_TAG="${1:-}"; [[ -z "$RELEASE_TAG" ]] && { echo "--release needs a tag, e.g. --release v0.2.0" >&2; exit 1; } ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/deploy/out/heimdall"
CONFIG="heimdall-bip322.toml"
STATE_DIR="/var/lib/heimdall"
USER_NAME="heimdall"

if [[ -n "$RELEASE_TAG" ]]; then
    # Pull the published binary + checksum from the GitHub release instead of building.
    mkdir -p "$ROOT/deploy/out"
    echo "==> Downloading heimdall $RELEASE_TAG from $REPO"
    gh release download "$RELEASE_TAG" --repo "$REPO" \
        --pattern heimdall --pattern heimdall.sha256 \
        --dir "$ROOT/deploy/out" --clobber
    echo "==> Verifying checksum"
    ( cd "$ROOT/deploy/out" && shasum -a 256 -c heimdall.sha256 )
elif [[ "$BUILD" == "1" ]]; then
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
