#!/usr/bin/env bash
# Build a static x86_64-linux (musl) `heimdall` binary on this machine (Mac/arm64 OK)
# using a linux/amd64 rust:alpine container, and drop it at deploy/out/heimdall.
#
#   deploy/build-linux.sh            # incremental build (cached cargo + target volumes)
#   deploy/build-linux.sh --clean    # wipe the cache volumes first (full rebuild)
#
# Alpine is musl-native on amd64, so this is a NATIVE build for the deploy target —
# no cross toolchain. openssl (pulled in by reqwest -> native-tls) is linked statically,
# so the result is a fully static ELF that runs on the NixOS box with no runtime deps.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="rust:alpine"
CARGO_VOL="heimdall-cargo"      # CARGO_HOME (registry + git deps) cache
TARGET_VOL="heimdall-target"    # build target dir cache (musl artifacts, separate from host target/)

for arg in "$@"; do
    case "$arg" in
        --clean) echo "==> Removing cache volumes"; docker volume rm -f "$CARGO_VOL" "$TARGET_VOL" >/dev/null 2>&1 || true ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done

mkdir -p "$ROOT/deploy/out"

echo "==> Building static musl heimdall in $IMAGE (linux/amd64)"
# The actual build recipe lives in deploy/build-musl.sh so local and CI builds stay identical.
docker run --rm -i --platform linux/amd64 \
    -v "$ROOT":/src:ro \
    -v "$CARGO_VOL":/cargo \
    -v "$TARGET_VOL":/target \
    -v "$ROOT/deploy/out":/out \
    -e CARGO_HOME=/cargo \
    -e CARGO_TARGET_DIR=/target \
    -e OUT_DIR=/out \
    -w /src \
    "$IMAGE" sh -eus < "$ROOT/deploy/build-musl.sh"

echo "==> Done. Binary at deploy/out/heimdall"
file "$ROOT/deploy/out/heimdall"
