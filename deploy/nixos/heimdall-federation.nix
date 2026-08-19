# NixOS module: the Phase-1 federation SPO daemons (`run-spo`).
#
# THIS IS NOT THE MOVER. `heimdall-mover.nix` runs `run-mover`, which builds and
# signs in a single process from a key reproduced off a constant seed, and can only
# spend a treasury deployed with that key. These units run `run-spo`: the epoch loop
# that co-signs Treasury Movements with the rest of the roster over the authenticated
# HTTP peer transport. The two modules can be enabled on one host - they share
# nothing but the service user, and deliberately not the binary or the state dir.
#
# WHY SEVERAL UNITS. A federation is t-of-n, and the signing rounds poll EVERY peer
# rather than the first t to answer, so all n must be up to produce a movement. Each
# member is its own process with its own identity key, share, port and state dir; the
# filenames inside a state dir are fixed (`federation-key.json`, `cpo-trie.json`), so
# two members sharing one directory would overwrite each other's state in silence.
#
# WHY THEY CAN RUN AT ALL WITH NO REGISTRY. Before the first Update-Y the treasury is
# locked under `y_federation` and the movements are the federation's to sign, so a
# member takes a Phase-1 seat with no registry entry (WI-098). The DKG is still
# attempted every epoch and the federation is reached only when it aborts, so this
# grants no authority the chain has not already granted the key.
#
# Out-of-store files, deployed by hand (deploy/build-linux.sh + scp):
#   /var/lib/heimdall-fed/heimdall           the shared static binary
#   /var/lib/heimdall-fed/secrets.env        HEIMDALL_MNEMONIC (mode 600)
#   /var/lib/heimdall-fed<N>/heimdall.toml   per-member config (mode 640 root:heimdall)
#   /var/lib/heimdall-fed<N>/bifrost.skey    per-member identity key (mode 600)
#   /var/lib/heimdall-fed<N>/federation-key.json   the ceremony share (mode 600)
#
# Each config MUST carry `cardano.blockfrost_project_id`. It is a CLI flag on the
# command line only for interactive runs; a unit has no shell to interpolate one from
# an environment file into an argument, and the alternative - wrapping ExecStart in
# `sh -c` - puts the id in the process table for every user on the box to read.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.heimdall-federation;

  # One member's out-of-store state directory. The binary and the shared secrets
  # live in `stateDir`; everything a member owns alone lives in `stateDir<N>`.
  instanceDir = n: "${cfg.stateDir}${toString n}";

  mkMember = n: {
    name = "heimdall-fed${toString n}";
    value = {
      description = "Heimdall federation SPO daemon, member ${toString n} (run-spo)";
      after = [ "network-online.target" ]
        ++ lib.optional cfg.requiresBitcoind "bitcoind-watchtower.service";
      wants = [ "network-online.target" ]
        ++ lib.optional cfg.requiresBitcoind "bitcoind-watchtower.service";
      wantedBy = lib.optional cfg.autoStart "multi-user.target";

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.user;
        # Creates/owns /var/lib/heimdall-fed<N> and makes it writable under
        # ProtectSystem=strict. Holds the share, the identity key and the tries.
        # Derived from `stateDir`, not hardcoded: systemd resolves StateDirectory
        # relative to /var/lib, so a literal name here silently creates
        # /var/lib/heimdall-fed<N> while ExecStart and ReadWritePaths point at
        # ${cfg.stateDir}<N>. Under ProtectSystem=strict that mismatch fails the
        # mount namespace with "No such file or directory" and nothing names the
        # option that caused it. The assertion below keeps stateDir under
        # /var/lib so the two can never diverge.
        StateDirectory = "${baseNameOf cfg.stateDir}${toString n}";
        # 0700, not systemd's 0755 default: this directory holds the ceremony
        # share (federation-key.json), the identity key (bifrost.skey) and the
        # tries. `preflight` tells operators it "must be 0700 and owned by the
        # user the daemon runs as", and the daemon cannot repair it —
        # `create_dir_0700` returns early when the directory already exists,
        # which it always does once systemd has made it.
        StateDirectoryMode = "0700";
        # The mnemonic only. Everything else a member needs is in its own config,
        # which is why this file can be shared by all of them.
        EnvironmentFile = cfg.secretsFile;
        ExecStart = lib.escapeShellArgs ([
          "${cfg.stateDir}/heimdall"
          "run-spo"
          "--config"
          "${instanceDir n}/heimdall.toml"
        ] ++ cfg.extraArgs);
        # A member that dies is a member the others wait for: the rounds poll every
        # peer, so one down instance stalls the whole federation rather than being
        # signed around. Restart quickly and always.
        Restart = "always";
        RestartSec = 10;
        # The startup gate exits non-zero on a misconfiguration it cannot fix by
        # retrying. Let it restart anyway: the commonest cause on this deployment is
        # a chain read that failed once, and a unit that stays dead until someone
        # notices is the failure mode `heimdall status` exists to make visible.

        # Hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadWritePaths = [ (instanceDir n) ];
      };
    };
  };
in
{
  options.services.heimdall-federation = {
    enable = lib.mkEnableOption "Heimdall Phase-1 federation SPO daemons";

    members = lib.mkOption {
      type = lib.types.listOf lib.types.int;
      default = [ 1 2 3 ];
      description = ''
        Member indices to run on this host, one unit each. These are LOCAL suffixes
        (state dir, unit name) and not FROST identifiers: the ceremony numbers members
        by `bifrost_id_pk` order, so member 1 here is whichever index the roster
        assigned that key. `heimdall bifrost-id` prints the mapping.

        A federation spread over several hosts sets this to the subset each host runs.
      '';
    };

    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/heimdall-fed";
      description = ''
        Directory holding the shared binary and secrets file. Each member's own state
        dir is this path with its index appended (`/var/lib/heimdall-fed1`).

        Deliberately NOT `/var/lib/heimdall`: that belongs to `heimdall-mover.nix`,
        whose binary is a different build and whose config is a different bridge.
      '';
    };

    secretsFile = lib.mkOption {
      type = lib.types.str;
      default = "${cfg.stateDir}/secrets.env";
      defaultText = lib.literalExpression ''"''${config.services.heimdall-federation.stateDir}/secrets.env"'';
      description = ''
        EnvironmentFile holding `HEIMDALL_MNEMONIC` (mode 600). Shared by every member
        on this host, which means they share a Cardano wallet and will contend for its
        UTxOs - acceptable because only the elected leader posts a movement. Give each
        member its own file, and its own wallet, to remove even that.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "heimdall";
      description = ''
        Service user. Defaults to the one `heimdall-mover.nix` also declares, so the
        two modules coexist on one host; see the `home` note where the user is
        defined for how the overlap is resolved.
      '';
    };

    autoStart = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Pull the units into `multi-user.target`, so they start on boot and on the
        `nixos-rebuild switch` that enables them.

        Set false to INSTALL without STARTING. A federation is not a set of
        independent daemons - the signing rounds poll every peer, so members that
        come up one rebuild apart simply wait for each other - and the state each
        one needs (its share, its identity key, a config naming the right bridge) is
        deployed out of band. Installing first makes the unit files, the ordering and
        the hardening reviewable with `systemctl cat` before anything holds a key and
        talks to peers.
      '';
    };

    requiresBitcoind = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Order the units after `bitcoind-watchtower.service`. Each member's
        `bitcoin.rpc_url` points at 127.0.0.1:48332, which that service provides.
      '';
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "--timeout-secs" "300" ];
      description = "Extra CLI arguments appended to every member's `run-spo`.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
      # mkDefault because heimdall-mover.nix declares this same user with its OWN
      # home (/var/lib/heimdall), and two plain definitions of one option are a
      # conflict the evaluator refuses rather than merges. The mover's value wins
      # when both modules are enabled; this one applies when the federation runs
      # alone. `home` is not load-bearing for either - each unit is given its
      # working state through StateDirectory - so yielding costs nothing.
      home = lib.mkDefault cfg.stateDir;
    };
    users.groups.${cfg.user} = { };

    assertions = [
      {
        assertion = lib.hasPrefix "/var/lib/" cfg.stateDir;
        message =
          "services.heimdall-federation.stateDir must be under /var/lib "
          + "(got ${cfg.stateDir}): each member's directory is created by "
          + "systemd's StateDirectory=, which resolves relative to /var/lib. "
          + "A path elsewhere would be created in the wrong place and the unit "
          + "would fail its mount namespace with no hint that this option "
          + "caused it.";
      }
    ];

    systemd.services = lib.listToAttrs (map mkMember cfg.members);
  };
}
