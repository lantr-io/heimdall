# scripts/dkz — run-dkz screencast

Scripts for the SPO identity + key-generation screencast: show the on-chain SPO list, then run a
3-instance stake-weighted DKG off the live preprod registry (all deriving the common key
`Y_51 = b1e15a53…`). Full write-up: `internal-docs/bitfrost/experiments/2026-06-30-run-dkz-screencast.md`.

## Prereqs
- `cargo build --bin heimdall`
- `heimdall-preprod.toml` + `heimdall-spo{1,2,3}.toml` + `.spo{1,2,3}.bifrost.skey` present
  (gitignored; they pin the `b814cca` registry blueprint, `min_stake_lovelace=1`,
  `demo_exclude_unstaked=true`). The scripts auto-extract `.b814cca.plutus.json` if missing.
- ports `18500-18502` free.

## The screencast (DKG-only)

    # Step 1 — the SPO list + stake-weighted 2-of-3 roster (1 terminal)
    ./show-roster.sh

    # Step 2 — the DKG (3 terminals, start within ~60s of each other)
    ./demo-spo-1.sh
    ./demo-spo-2.sh
    ./demo-spo-3.sh

All three print the identical `PublishKeys: group_key = b1e15a53…`; Ctrl-C there (ignore
`CollectPegins`/`BuildTm` after — not part of the key-gen story).

## Registration (already done on preprod 2026-06-30)

`register-spo-{1,2,3}.sh` are the exact, reproducible registration commands (they added the 3 pools to
the registry). Run now they report `registry: pool_id already registered` (proof they're on-chain);
`--submit` only builds/broadcasts against a *fresh* registry.
