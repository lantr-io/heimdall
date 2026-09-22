# Vendored contract blueprint

`plutus.json` is the Aiken blueprint of the Bifrost contracts, compiled and committed upstream.
heimdall embeds it with `include_str!` (see `src/cardano/blueprint.rs`) rather than asking each
operator for a file path.

**It is not a per-bridge value.** The registry policy id is `hash(compiled code ++ bootstrap
outref)`, so the code is a build artifact of a contracts *release* and the outref is what
distinguishes one bridge from another. An operator supplying this file by hand is being asked for a
value with exactly one correct answer per heimdall version — and a stale copy does not error, it
derives a policy id no deployment has and reads an empty registry.

| | |
|---|---|
| upstream | `FluidTokens/ft-bifrost-bridge` |
| commit | `096f76c22e7e6143ec2ae26603061fc3aa32208f` |
| path | `onchain/plutus.json` |
| aiken | `v1.1.23+8949565` (from the blueprint preamble) |
| sha256 | `a13e9161539dcf58dcbda1902e5cf276e4d6b8e6ed0e344c31597a94eb90962c` |

## Refreshing it

This is a **release-coupling decision, not a routine bump**: replacing this file changes the policy
ids heimdall derives, so a heimdall built with it can only join bridges deployed from the same
contracts release.

```bash
cp ../ft-bifrost-bridge/onchain/plutus.json assets/plutus.json   # the COMMITTED file, not a rebuild
cargo test --lib blueprint                                        # pins the derived policy ids
```

Copy the committed `plutus.json`; do not rebuild it. A pristine rebuild of the same source moves
several config/treasury hashes, so a rebuilt blueprint is not the one the deployed bridges were
derived from.
