#!/usr/bin/env sh
# Assemble the heimdall Debian package from an ALREADY-BUILT binary.
#
# This script deliberately does NOT compile anything. deploy/build-musl.sh is the
# single source of truth for how the deploy binary is produced (static musl, built
# in rust:alpine), and .github/workflows/release.yml publishes that exact artifact.
# The .deb wraps the same file, so the binary in the package and the binary on the
# release page can never drift. That is also why cargo-deb is not used here: it
# wants to run cargo itself.
#
# Usage:
#   deploy/build-linux.sh                 # produces deploy/out/heimdall
#   sh deploy/debian/build-deb.sh         # wraps it as deploy/out/heimdall_<ver>_amd64.deb
#
# Env knobs (all optional):
#   BIN              path to the built binary        (default: deploy/out/heimdall)
#   OUT_DIR          where to write the .deb         (default: dirname of BIN)
#   VERSION          upstream version, e.g. 0.2.0    (default: Cargo.toml version +
#                                                    commit date, count and sha)
#   DEB_EPOCH        debian epoch, '' for none       (default: 1 — see below)
#   DEB_REVISION     debian revision                 (default: 1)
#   ARCH             package architecture            (default: amd64)
#   DEB_MAINTAINER   "Name <email>"                  (default: git config, else Lantr)
set -eu

BIN="${BIN:-deploy/out/heimdall}"
OUT_DIR="${OUT_DIR:-$(dirname "$BIN")}"
ARCH="${ARCH:-amd64}"
DEB_REVISION="${DEB_REVISION:-1}"
HERE="$(dirname "$0")"

[ -f "$BIN" ] || {
    echo "error: no binary at '$BIN' — run deploy/build-linux.sh first, or set BIN." >&2
    exit 1
}

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "error: dpkg-deb not found. Debian/Ubuntu: apt-get install dpkg." >&2
    echo "       Alpine (the release container): apk add --no-cache dpkg." >&2
    exit 1
}

# ── Version ─────────────────────────────────────────────────────────────────
# A Debian upstream_version must start with a digit, so a bare short SHA
# ("abc1234") cannot be used on its own. It also must not be used as the ONLY
# thing that varies, which is what this used to do: a sha is hex, and hex does
# not order. "b8a6e25" compares GREATER than the "1162f34" committed twelve days
# later, so dpkg announced every deploy as
#
#     dpkg: warning: downgrading heimdall from 0.1.0+b8a6e25-1 to 0.1.0+1162f34-1
#
# which `dpkg -i` tolerates but `apt upgrade` refuses outright.
#
# So order by something that only ever increases: the commit's own date first,
# then the number of commits behind it, which breaks same-day ties and is
# monotonic along a branch. The sha stays on the end as what it actually is —
# an identifier, not an ordinal.
if [ -z "${VERSION:-}" ]; then
    base="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)"
    [ -n "$base" ] || base="0.0.0"
    stamp="$(git show -s --format=%cd --date=format:%Y%m%d HEAD 2>/dev/null || true)"
    count="$(git rev-list --count HEAD 2>/dev/null || true)"
    sha="$(git rev-parse --short HEAD 2>/dev/null || true)"
    if [ -n "$stamp" ] && [ -n "$count" ] && [ -n "$sha" ]; then
        VERSION="${base}+${stamp}.${count}.g${sha}"
    elif [ -n "$sha" ]; then
        # No usable history (a shallow or exported tree). Still legal, still
        # unique, just not ordered — better than refusing to build.
        VERSION="${base}+g${sha}"
    else
        VERSION="$base"
    fi
fi
case "$VERSION" in
[0-9]*) ;;
*)
    echo "error: VERSION '$VERSION' does not start with a digit; Debian forbids that." >&2
    exit 1
    ;;
esac
PKG_VERSION="${VERSION}-${DEB_REVISION}"

# ── Epoch ───────────────────────────────────────────────────────────────────
# Debian's escape hatch for "the versioning scheme itself was wrong". Every
# version carrying an epoch sorts above every version without one, whatever the
# rest says — which is the only way out of the hole the sha-named packages dug:
# the fixed scheme starts with a digit, and dpkg sorts a digit-initial part
# BELOW a letter-initial one, so `0.1.0+20260907…` is still "older" than the
# `0.1.0+b8a6e25` already installed on the preprod boxes. With the epoch it is
# not, and every future build orders normally.
#
# An epoch is permanent: it can never be removed, only carried. That is the
# price, and it is the standard one for this mistake. Set DEB_EPOCH= (empty) to
# build without it.
DEB_EPOCH="${DEB_EPOCH-1}"
if [ -n "$DEB_EPOCH" ]; then
    CONTROL_VERSION="${DEB_EPOCH}:${PKG_VERSION}"
else
    CONTROL_VERSION="$PKG_VERSION"
fi

# ── Maintainer ──────────────────────────────────────────────────────────────
if [ -z "${DEB_MAINTAINER:-}" ]; then
    m_name="$(git config user.name 2>/dev/null || true)"
    m_mail="$(git config user.email 2>/dev/null || true)"
    if [ -n "$m_name" ] && [ -n "$m_mail" ]; then
        DEB_MAINTAINER="$m_name <$m_mail>"
    else
        DEB_MAINTAINER="Lantr <https://github.com/lantr-io/heimdall>"
    fi
fi

# ── Sanity: the whole point of the musl build is no dependency chain ────────
if command -v file >/dev/null 2>&1; then
    if file -L "$BIN" | grep -q "dynamically linked"; then
        echo "warning: '$BIN' is dynamically linked. The release .deb is expected to" >&2
        echo "         wrap the STATIC musl build (deploy/build-musl.sh); this package" >&2
        echo "         will only run where its libraries happen to exist." >&2
    fi
fi

# ── Staging tree ────────────────────────────────────────────────────────────
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
# mktemp -d gives 0700, and the staging root is packaged as './' — which dpkg maps
# to '/'. Left alone, installing this package would chmod the filesystem root to
# 0700 and take the machine apart.
chmod 0755 "$STAGE"

install -d -m 0755 "$STAGE/DEBIAN"
install -d -m 0755 "$STAGE/usr/bin"
install -d -m 0755 "$STAGE/lib/systemd/system"
install -d -m 0755 "$STAGE/etc/heimdall"
install -d -m 0755 "$STAGE/etc/default"
# 0700 and owned by root here; postinst chowns it to heimdall. Shipping it in the
# package (rather than relying on systemd's StateDirectory=) means the operator has
# somewhere to put the identity key before the first start.
install -d -m 0700 "$STAGE/var/lib/heimdall"

install -m 0755 "$BIN" "$STAGE/usr/bin/heimdall"
install -m 0644 "$HERE/heimdall.service" "$STAGE/lib/systemd/system/heimdall.service"
# Conffiles ship 0640; postinst re-owns them root:heimdall once the group exists.
install -m 0640 "$HERE/heimdall.toml" "$STAGE/etc/heimdall/heimdall.toml"
install -m 0640 "$HERE/default" "$STAGE/etc/default/heimdall"

install -m 0644 "$HERE/conffiles" "$STAGE/DEBIAN/conffiles"
for s in postinst prerm postrm; do
    install -m 0755 "$HERE/$s" "$STAGE/DEBIAN/$s"
done

# Installed-Size is in KiB and dpkg-deb does not compute it. Sum the shipped
# trees rather than the staging root so DEBIAN/ is not counted (and so this works
# with busybox du, which has no --exclude).
INSTALLED_SIZE="$(du -sk "$STAGE/usr" "$STAGE/etc" "$STAGE/lib" "$STAGE/var" | awk '{s+=$1} END {print s}')"

cat >"$STAGE/DEBIAN/control" <<EOF
Package: heimdall
Version: $CONTROL_VERSION
Architecture: $ARCH
Maintainer: $DEB_MAINTAINER
Installed-Size: $INSTALLED_SIZE
Depends: adduser, ca-certificates
Recommends: systemd
Section: net
Priority: optional
Homepage: https://github.com/lantr-io/heimdall
Description: SPO daemon for the Bifrost Bitcoin-Cardano bridge
 Heimdall is the stake-pool-operator program for the Bifrost bridge, which uses
 Cardano SPOs as distributed custodians for BTC transfers. It follows the bridge
 contracts on Cardano, batches peg-ins and peg-outs onto the protocol slot grid,
 and takes part in the FROST threshold-Schnorr ceremonies that authorise each
 Bitcoin treasury movement.
 .
 The service is installed disabled: it needs a bridge configuration and key
 material before it can start. Configure /etc/heimdall/heimdall.toml, then
 enable it.
EOF

# gzip rather than the default (xz/zstd, depending on the dpkg build) so the
# package is readable by older dpkg and by `ar x` on a machine without xz.
DEB="$OUT_DIR/heimdall_${PKG_VERSION}_${ARCH}.deb"
mkdir -p "$OUT_DIR"
dpkg-deb --root-owner-group -Zgzip --build "$STAGE" "$DEB" >/dev/null

echo "--> Wrote $DEB"
dpkg-deb --info "$DEB" | sed -n '1,12p'
echo "--> Contents"
dpkg-deb --contents "$DEB"
