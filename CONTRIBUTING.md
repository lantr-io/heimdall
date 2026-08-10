# Contributing to Heimdall

Heimdall is the SPO daemon for the Bifrost Bridge. This file is for people **working on** it:
the everyday loop, the conventions, and how a release is cut.

If you are trying to **run** heimdall rather than change it, you want
[`deploy/README.md`](deploy/README.md) instead — it owns the operator's view (installing the
package, the container, the NixOS module, watching logs). This file does not repeat it.

---

## The everyday loop

```bash
cargo fmt --all --check
cargo clippy --all-targets --locked
cargo test --locked
```

That is exactly what CI runs, in two jobs (`fmt + clippy`, `build + test`) on every push to `main`
and every pull request. A full `cargo test` is **512 tests across 10 targets** and takes a couple of
minutes; the bulk is `--lib`, so `cargo test --lib` is the fast inner loop.

Three tests are `#[ignore]`d on purpose, and `cargo test -- --ignored --list` names them. Two
generate ZK proofs and are slow enough to plan around (`k=18` ≈ 19 s, `k=22` ≈ 311 s); the third
cross-checks script hashes against an Aiken build, so it needs the `ft-bifrost-bridge` toolchain
present. Run them deliberately, not by accident.

`clippy` is **advisory** in CI: the step has no `-D warnings`, so warnings do not fail the build.
There is a standing backlog of them. Do not add to it — check your own files are clean, and if the
total moves, that was you.

Security-critical code lives here. Correctness over performance, and when a fact matters (a byte
order, a priority mapping, a contract field index), verify it against the source or measure it
rather than asserting it.

---

## Commits and pull requests

- **Never** add attribution or session trailers: no `Co-Authored-By`, no `Claude-Session`, no
  "Generated with …" footer, no session URL. This applies to commit messages **and** PR
  descriptions, here and in the sibling repos (`ft-bifrost-bridge`, `binocular`, `internal-docs`).
  A commit message should read as the change's own rationale, with nothing pointing at how it was
  produced.
- One paragraph, two at most. Subject line in the imperative, scoped:
  `feat(logging): give every log line a level that survives journald (WI-057)`.
- Work items live in `anthill-todo/` (see the `anthill-todo` CLI). Reference `WI-NNN` in the
  subject when there is one.
- Branch, PR, merge — `main` is protected by CI, not by policy, so keep it green.

**Stacked PRs need care when merging.** If PR B is based on PR A's branch, merging A with
`--delete-branch` **closes** B rather than retargeting it, and a closed PR whose base ref is gone
cannot be reopened. Merge A *without* `--delete-branch`, retarget B first
(`gh api -X PATCH repos/lantr-io/heimdall/pulls/<B> -f base=main` — `gh pr edit --base` trips on a
deprecated Projects GraphQL field), wait for `mergeStateStatus` to leave `UNKNOWN`, then merge B and
delete both branches.

---

## What a release produces

| artifact | where it lands |
|---|---|
| `heimdall` — static x86-64 musl binary | GitHub release assets |
| `heimdall.sha256` | GitHub release assets |
| `heimdall_<version>-1_amd64.deb` | GitHub release assets |
| `heimdall.deb.sha256` | GitHub release assets |
| `ghcr.io/lantr-io/heimdall:<version>` | GHCR (plus `:latest`, **only** if not a prerelease) |

Two checksum files, not one, because `deploy/deploy.sh` downloads only the bare binary and runs
`shasum -c heimdall.sha256` on it. A second line naming the `.deb` would make that verification fail
on a file it never fetched.

### Where it is *not* published

There is **no APT repository**. The `.deb` is a loose release asset: operators download it and run
`apt install ./heimdall_<version>-1_amd64.deb`. There is no `apt update && apt upgrade` path, so
upgrading means fetching the next file by hand.

There is **no signing** beyond the `.sha256` files — no GPG signature on the `.deb`, no `cosign`
attestation on the image. Integrity rests on the operator checking a checksum they fetched from the
same place as the artifact.

Both are deliberate choices for the current audience (a handful of known SPOs), and both are worth
revisiting before the operator guide goes to strangers. Neither is baked in: adding an apt repo or
signatures changes only the publishing step, not how any artifact is built.

---

## Cutting a release

Everything is driven from the **Release** workflow — Actions tab → *Release* → *Run workflow*:

- **`version`** — no leading `v`, e.g. `0.2.0`. The workflow tags `v0.2.0`.
- **`prerelease`** — marks the GitHub release as a pre-release **and** suppresses the `:latest`
  container tag. `docker pull ghcr.io/lantr-io/heimdall` is what an operator following the guide
  types, so `latest` must always land on a real release.

Or from the CLI:

```bash
gh workflow run release.yml -f version=0.2.0 -f prerelease=true
```

### One-time prerequisites

- **GHCR visibility.** The first successful run *creates* the container package, and it is
  **private**. Someone with org rights has to make it public in the package settings before anyone
  can `docker pull` it. Nothing in the workflow can do this.
- **Permissions.** The workflow's built-in `GITHUB_TOKEN` is enough: `contents: write` at the top
  level to create the release, `packages: write` on the `image` job to push to GHCR. No PAT.
- **`DISCORD_WEBHOOK`** is optional. Absent, the notify step is skipped.

### What the workflow does, in order

1. **`release`** (inside `container: rust:alpine`) builds the static binary via
   `deploy/build-musl.sh`, checksums it, builds the `.deb` around that same file, and creates the
   GitHub release with all four assets.
2. **`image`** (on a plain runner, because the alpine job has no docker daemon) *downloads the
   binary that was just published*, verifies its checksum, builds the container from it, and pushes.
3. **`notify`** reports to Discord, red if **either** job failed.

---

## Versioning

`build.rs` resolves the version at compile time, first match wins:

1. `HEIMDALL_VERSION_OVERRIDE` — what the release workflow sets from the dispatched `version`.
2. `git describe --tags --always --dirty`.
3. `CARGO_PKG_VERSION` from `Cargo.toml`, when git is unavailable (a tarball build).

So `heimdall --version` on a release reports the release version, and a local build reports what git
says. **Until the first tag exists, `git describe --tags --always` falls back to a bare short SHA** —
a local build today prints `heimdall 52e8d55 (52e8d55 2026-08-10)` and `build-image.sh` tags the
image `heimdall:52e8d55`, which looks nothing like a release tag. That is expected, not a bug.

An uncommitted tree appends `-dirty`. Never ship one.

Note the release workflow does **not** bump `Cargo.toml`; the version there is the fallback only.

---

## Building the artifacts locally

Three steps, in order. Each consumes the previous one's output:

```bash
deploy/build-linux.sh                  # → deploy/out/heimdall  (static musl, in rust:alpine)
sh deploy/debian/build-deb.sh          # → deploy/out/heimdall_<version>-1_amd64.deb
sh deploy/docker/build-image.sh        # → heimdall:<version>   (local image)
```

`deploy/build-linux.sh --clean` wipes the cargo and target Docker volumes for a full rebuild.

Env knobs, all optional:

| script | knobs |
|---|---|
| `build-linux.sh` / `build-musl.sh` | `OUT_DIR`, `HEIMDALL_VERSION_OVERRIDE` |
| `debian/build-deb.sh` | `BIN`, `OUT_DIR`, `VERSION`, `DEB_REVISION`, `ARCH`, `DEB_MAINTAINER` |
| `docker/build-image.sh` | `BIN`, `IMAGE`, `VERSION`, `PLATFORM` |

A local `.deb` is stamped with **your** git identity as `Maintainer`; the workflow overrides it with
`Lantr <https://github.com/lantr-io/heimdall>`. Do not hand out locally built packages.

### The invariant: nothing recompiles

`deploy/build-musl.sh` is the **single source of truth** for the deploy binary. Everything
downstream wraps that exact file:

- `build-deb.sh` refuses to run cargo — which is also why `cargo-deb` is not used here; it insists
  on driving the build itself.
- `build-image.sh` and the workflow's `image` job copy an already-built binary. The job goes further
  and re-downloads the *published* asset, so the check is against what shipped.

That is what makes the three artifacts one file, and it is checkable:

```bash
sha256sum deploy/out/heimdall
dpkg-deb --fsys-tarfile deploy/out/*.deb | tar -xO ./usr/bin/heimdall | sha256sum
docker run --rm --entrypoint sha256sum heimdall:<version> /usr/bin/heimdall
```

All three print the same hash. If you are tempted to add a `cargo build` to any script downstream
of `build-musl.sh`, this is what you would be breaking.

---

## Verifying a release after cutting it

```bash
gh release download v0.2.0 --repo lantr-io/heimdall
sha256sum -c heimdall.sha256
sha256sum -c heimdall.deb.sha256

./heimdall --version                              # must print 0.2.0
dpkg-deb -I heimdall_0.2.0-1_amd64.deb            # version, deps, Installed-Size
docker run --rm ghcr.io/lantr-io/heimdall:0.2.0 --version
```

Then the package lifecycle on a throwaway Debian box — install, verify the unit is present and
**not** started, upgrade over it, confirm an edited conffile survived, and `apt purge` leaving
`/var/lib/heimdall` and the `heimdall` user alone. `deploy/README.md` documents what each of those
should look like.
