# Runtime image for the heimdall SPO daemon.
#
# This image does NOT compile anything. It wraps the binary deploy/build-musl.sh
# already produced — the same file the .deb wraps and the same file the release
# page serves — so the three artifacts cannot drift. Build it with
# deploy/docker/build-image.sh, which builds the binary first and then calls this.
#
# WHY alpine AND NOT scratch. The binary is a static-pie ELF with no runtime
# dependencies, so `FROM scratch` runs it — but it does not run the *daemon*:
#
#   1. heimdall reads Cardano over HTTPS. reqwest → native-tls → OpenSSL loads the
#      trust store from /etc/ssl/certs, which scratch does not have. Measured, not
#      assumed: a scratch image printed `--version` correctly and then failed
#      preflight step 2 with "error sending request for url
#      (https://cardano-preprod.blockfrost.io/api/v0/epochs/latest)". So a scratch
#      image needs ca-certificates copied in regardless.
#   2. An SPO has to diagnose this daemon in production. `docker exec -it … sh` to
#      inspect /var/lib/heimdall, or to re-run `heimdall run-mover --once` against
#      the live config, is worth more than the bytes it costs.
#
# Which makes the real choice "ca-certificates on scratch" versus "alpine", and
# alpine wins for ~8 MB on top of a 26 MB binary.

FROM alpine:3.20

# Path to the already-built static binary, relative to the build context.
ARG BIN=deploy/out/heimdall
ARG VERSION=dev

LABEL org.opencontainers.image.title="heimdall" \
      org.opencontainers.image.description="Bifrost Bridge SPO daemon" \
      org.opencontainers.image.source="https://github.com/lantr-io/heimdall" \
      org.opencontainers.image.version="${VERSION}"

# tini so `docker stop` works: heimdall installs no SIGTERM handler, and a process
# running as PID 1 does not get the default disposition, so without an init the
# stop would sit out its whole timeout and then be SIGKILLed mid-tick.
RUN apk add --no-cache ca-certificates tini \
 && addgroup -S -g 950 heimdall \
 && adduser -S -u 950 -G heimdall -H -h /var/lib/heimdall heimdall \
 && mkdir -p /etc/heimdall /var/lib/heimdall \
 && chown heimdall:heimdall /var/lib/heimdall \
 && chmod 0700 /var/lib/heimdall

COPY ${BIN} /usr/bin/heimdall
COPY deploy/docker/entrypoint.sh /usr/local/bin/heimdall-entrypoint
# The .deb's conffile, shipped as an example. It is entirely commented out and
# holds no secrets — it is what the entrypoint points at when no config is mounted.
COPY deploy/debian/heimdall.toml /usr/share/heimdall/heimdall.toml.example
RUN chmod 0755 /usr/bin/heimdall /usr/local/bin/heimdall-entrypoint

# Holds the per-epoch DKG signing share (0600) and the completed-peg-outs trie.
# A container that loses this cannot resume the epoch it was in the middle of, and
# comes back believing every completed peg-out is unpaid — name a volume.
VOLUME ["/var/lib/heimdall"]

# The SPO-to-SPO protocol surface: public by construction, since its URL is on
# chain and peers must fetch this node's DKG rounds from it.
#
# The port is NOT configured here or in heimdall.toml — the daemon binds the port
# in its own registered `bifrost_url`. 18500 is only a conventional default to
# declare; publish whatever port your registration actually names.
EXPOSE 18500

USER heimdall
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/heimdall-entrypoint"]
