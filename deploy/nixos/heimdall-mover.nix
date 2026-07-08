# NixOS module: Heimdall WI-028 auto-mover (run-mover) for the preprod BIP-322 bridge.
#
# Import this into your host configuration and set the options under `services.heimdall-mover`.
# The binary and config live OUT of the Nix store (they are deployed with deploy.sh):
#   /var/lib/heimdall/heimdall              (static musl x86_64 binary; built on your Mac)
#   /var/lib/heimdall/heimdall-bip322.toml  (config: Blockfrost id + wallet mnemonic; mode 600)
#
# The config carries the Blockfrost project id and the wallet mnemonic, so it is installed
# mode 600 and NOTHING secret is placed in the Nix store.
#
# The mover chain-sources the treasury from Cardano and reads every bridge identifier
# (pegin/pegout script addresses, policy id, bridged-token unit) from the config's [cardano]
# section, so the ExecStart is just `run-mover --config <file> [--broadcast]`.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.heimdall-mover;
in
{
  options.services.heimdall-mover = {
    enable = lib.mkEnableOption "Heimdall auto-mover daemon";

    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/heimdall";
      description = "Out-of-store directory holding the binary and config.";
    };

    configFile = lib.mkOption {
      type = lib.types.str;
      default = "heimdall-bip322.toml";
      description = "Config filename within stateDir passed to --config.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "heimdall";
      description = "Service user (also owns stateDir and reads the config file).";
    };

    intervalSecs = lib.mkOption {
      type = lib.types.int;
      default = 60;
      description = "Seconds between auto-mover ticks (--interval-secs).";
    };

    broadcast = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Post the built Treasury Movement (--broadcast). Cardano posting is gated by
        cardano.submit_oracle in the config; Bitcoin broadcast is gated by bitcoin.submit
        (kept false — binocular's relay broadcasts BTC). Set false here for pure dry-run ticks.
      '';
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "--exclude-pegin" "abcd…:0" ];
      description = "Extra CLI args appended to the run-mover invocation.";
    };

    requiresBitcoind = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Order the service after the local bitcoind-watchtower.service (the mover's
        bitcoin.rpc_url points at 127.0.0.1:48332, which that service provides).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
      home = cfg.stateDir;
    };
    users.groups.${cfg.user} = { };

    systemd.services.heimdall-mover = {
      description = "Heimdall auto-mover (WI-028 treasury movement loop)";
      after = [ "network-online.target" ]
        ++ lib.optional cfg.requiresBitcoind "bitcoind-watchtower.service";
      wants = [ "network-online.target" ]
        ++ lib.optional cfg.requiresBitcoind "bitcoind-watchtower.service";
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.user;
        StateDirectory = "heimdall"; # ensures /var/lib/heimdall exists, owned by the user
        ExecStart = lib.escapeShellArgs ([
          "${cfg.stateDir}/heimdall"
          "run-mover"
          "--config"
          "${cfg.stateDir}/${cfg.configFile}"
          "--interval-secs"
          (toString cfg.intervalSecs)
        ]
        ++ lib.optional cfg.broadcast "--broadcast"
        ++ cfg.extraArgs);
        Restart = "always";
        RestartSec = 10;

        # Hardening
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadWritePaths = [ cfg.stateDir ];
      };
    };
  };
}
