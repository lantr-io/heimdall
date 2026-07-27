#!/usr/bin/env sh
# Build a static x86_64 musl `heimdall` binary FROM INSIDE a rust:alpine (amd64) container.
#
# This is the single source of truth for how the deploy binary is produced. It is invoked:
#   - locally  by deploy/build-linux.sh, via `docker run … rust:alpine … build-musl.sh`
#   - in CI    by .github/workflows/release.yml, run directly inside a rust:alpine job
#
# Alpine is musl-native on amd64, so this is a NATIVE build for the deploy target (no cross
# toolchain). openssl (pulled in by reqwest -> native-tls) is linked statically, so the result
# is a fully static ELF that runs on the NixOS box with no runtime deps.
#
# Env knobs (all optional):
#   OUT_DIR            where to drop the final `heimdall` binary        (default: ./out)
#   CARGO_TARGET_DIR   cargo target dir (cache-friendly to override)    (default: ./target)
#   HEIMDALL_VERSION_OVERRIDE  baked-in version string (release builds)
set -eu

OUT_DIR="${OUT_DIR:-out}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"

echo "--> Installing build deps"
# `git` is needed by build.rs to embed the commit SHA/date in --version output.
apk add --no-cache build-base musl-dev perl make pkgconfig git file \
    openssl-dev openssl-libs-static >/dev/null

# Repo may be owned by a different uid than the container user (CI checkout, mounted volume).
git config --global --add safe.directory "$PWD" 2>/dev/null || true

echo "--> cargo build --release --locked --bin heimdall"
OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1 PKG_CONFIG_ALL_STATIC=1 \
    cargo build --release --locked --bin heimdall

BIN="$TARGET_DIR/release/heimdall"

echo "--> Verifying the binary is static"
file "$BIN"
# `ldd` on a static musl binary prints "Not a valid dynamic program" / no deps — that's success.
ldd "$BIN" 2>&1 || true

mkdir -p "$OUT_DIR"
cp "$BIN" "$OUT_DIR/heimdall"
strip "$OUT_DIR/heimdall" || true
echo "--> Wrote $OUT_DIR/heimdall"
ls -lh "$OUT_DIR/heimdall"
