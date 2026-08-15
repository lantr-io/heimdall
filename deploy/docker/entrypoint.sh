#!/bin/sh
# Container entrypoint for heimdall.
#
# Three jobs. First, refuse to start the daemon without a config and say exactly
# why: the .deb can install-but-not-start because heimdall cannot run before it
# has been told which bridge to join, and a container has no equivalent —
# `docker run` IS the start — so the failure has to be legible in the first lines
# of `docker logs`. Second, default the command, so `docker run <image>` runs the
# SPO daemon. Third, warn about the one networking mistake that is specific to
# containers and silent when made.
set -eu

CONFIG="${HEIMDALL_CONFIG:-/etc/heimdall/heimdall.toml}"

case "${1:-}" in
    "")
        # No command: the daemon. Falls through to the config check below.
        ;;
    -*)
        # A global flag, so `docker run <image> --version` and `--help` behave
        # like the CLI rather than being told to mount a config they do not need.
        exec /usr/bin/heimdall "$@"
        ;;
    *)
        # Anything that names a real executable is one — `sh`, `/usr/bin/heimdall`,
        # or any tool an operator reaches for while diagnosing. heimdall's own
        # subcommands (run-spo, show-treasury, …) are not on PATH, so they fall
        # through to the config check, which is what should happen: they all need
        # the config too.
        if command -v "$1" >/dev/null 2>&1; then
            exec "$@"
        fi
        ;;
esac

if [ ! -f "$CONFIG" ]; then
    cat >&2 <<EOF
heimdall: no configuration at $CONFIG

The daemon cannot start without one: it has no default for the bridge it is
meant to join, and guessing would post transactions against the wrong contracts.
Nothing is baked into this image, because the config holds a wallet mnemonic and
a Blockfrost project id and neither belongs in a layer or a registry.

Start from the commented template inside this image:

  docker run --rm <image> cat /usr/share/heimdall/heimdall.toml.example > heimdall.toml
  \$EDITOR heimdall.toml

then mount it read-only, alongside a NAMED volume for the DKG share:

  docker run -d --name heimdall \\
      -v \$PWD/heimdall.toml:$CONFIG:ro \\
      -v heimdall-state:/var/lib/heimdall \\
      -p 18500:18500 \\
      <image>

If you keep the mnemonic out of the file (recommended), pass it as
-e HEIMDALL_MNEMONIC=... instead.
EOF
    # EX_CONFIG. This does not by itself defeat a restart policy — docker restarts
    # on any non-zero exit — so under --restart=always a missing config loops. It
    # loops printing the message above, which is the legible failure the .deb gets
    # from not starting at all.
    exit 78
fi

# In a container, `bind_address = "127.0.0.1"` is loopback INSIDE the namespace:
# -p publishes nothing, peers cannot fetch this node's DKG rounds, and the node
# silently drops out of the qualified set. It is the default in the shipped
# template because that is right for a local trial, and wrong here. Advisory
# rather than fatal — a local trial is a legitimate thing to do.
if grep -Eq '^[[:space:]]*bind_address[[:space:]]*=[[:space:]]*"(127\.|localhost)' "$CONFIG"; then
    echo "heimdall: warning: $CONFIG binds a loopback address. Inside a container that" >&2
    echo "  is unreachable even with -p, so peers cannot fetch this node's DKG rounds" >&2
    echo "  and it will contribute nothing to the epoch. Set http.bind_address to" >&2
    echo "  0.0.0.0 and publish the port your registered bifrost_url names." >&2
fi

if [ "$#" -eq 0 ]; then
    # `run-spo`, matching the .deb's unit — this image is the same binary doing
    # the same job, and every note in deploy/README.md about it (DKG rounds, the
    # registered bifrost_url, resuming an epoch from the state volume) describes
    # the SPO daemon. It defaulted to `run-mover` until 2026-08-15, which is a
    # different program: run-mover builds and signs a movement in a SINGLE
    # process from a key reproduced off a constant seed, so on any bridge not
    # deployed with that key its signatures verify against nothing. Pass it
    # explicitly if that is really what you want.
    #
    # Unquoted on purpose: HEIMDALL_ARGS carries multiple words, exactly as it
    # does in /etc/default/heimdall for the systemd unit.
    # shellcheck disable=SC2086
    set -- run-spo --config "$CONFIG" ${HEIMDALL_ARGS:-}
fi

exec /usr/bin/heimdall "$@"
