#!/usr/bin/env sh
# Assemble the heimdall runtime image from an ALREADY-BUILT binary.
#
# Same contract as deploy/debian/build-deb.sh, for the same reason: this script
# does not compile anything. deploy/build-musl.sh owns how the deploy binary is
# produced, and .github/workflows/release.yml publishes that exact artifact — so
# the binary in the image, the binary in the .deb and the binary on the release
# page are one file.
#
# Usage:
#   deploy/build-linux.sh                    # produces deploy/out/heimdall
#   sh deploy/docker/build-image.sh          # wraps it as heimdall:<version>
#
# Env knobs (all optional):
#   BIN       path to the built binary, relative to the repo root
#                                            (default: deploy/out/heimdall)
#   IMAGE     image name without a tag        (default: heimdall)
#   VERSION   tag + OCI version label         (default: from the binary's --version)
#   PLATFORM  target platform                 (default: linux/amd64 — build-musl.sh
#                                              only produces x86_64)
set -eu

BIN="${BIN:-deploy/out/heimdall}"
IMAGE="${IMAGE:-heimdall}"
PLATFORM="${PLATFORM:-linux/amd64}"
HERE="$(dirname "$0")"
ROOT="$(cd "$HERE/../.." && pwd)"

cd "$ROOT"

[ -f "$BIN" ] || {
    echo "error: no binary at '$BIN' — run deploy/build-linux.sh first, or set BIN." >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || {
    echo "error: docker not found." >&2
    exit 1
}

# Ask the binary what it is rather than re-deriving it: build.rs embedded the
# version and commit at compile time, and that is the number the release carries.
if [ -z "${VERSION:-}" ]; then
    VERSION="$("./$BIN" --version 2>/dev/null | awk '{print $2}')"
    [ -n "$VERSION" ] || {
        echo "error: could not read a version from '$BIN --version'; set VERSION." >&2
        exit 1
    }
fi

echo "==> building $IMAGE:$VERSION for $PLATFORM from $BIN"
docker build \
    --platform "$PLATFORM" \
    --build-arg "BIN=$BIN" \
    --build-arg "VERSION=$VERSION" \
    -f deploy/docker/Dockerfile \
    -t "$IMAGE:$VERSION" \
    .

echo "==> $IMAGE:$VERSION"
docker run --rm "$IMAGE:$VERSION" /usr/bin/heimdall --version
