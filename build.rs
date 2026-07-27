// Bakes a human-readable version string into the binary at compile time and
// exposes it as the `HEIMDALL_VERSION` env var (read by `main.rs` via env!()).
//
// Precedence for the base version:
//   1. HEIMDALL_VERSION_OVERRIDE  — set by the release workflow to the dispatched
//      version (e.g. "0.2.0"); wins so release builds are labeled exactly.
//   2. `git describe --tags --always --dirty` — e.g. "0.1.0-5-gabc1234" once tags
//      exist, a bare short SHA before that.
//   3. CARGO_PKG_VERSION ("0.1.0") — when git is unavailable (e.g. tarball build).
//
// When git is present the short SHA and commit date are appended, yielding e.g.
//   heimdall 0.2.0 (abc1234 2026-07-09)
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn main() {
    // Re-run when HEAD moves or the index changes so the embedded SHA stays fresh.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-env-changed=HEIMDALL_VERSION_OVERRIDE");

    let base = std::env::var("HEIMDALL_VERSION_OVERRIDE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| git(&["describe", "--tags", "--always", "--dirty"]))
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    let short_sha = git(&["rev-parse", "--short", "HEAD"]);
    let date = git(&["show", "-s", "--format=%cd", "--date=short", "HEAD"]);

    let version = match (short_sha, date) {
        (Some(sha), Some(d)) => format!("{base} ({sha} {d})"),
        (Some(sha), None) => format!("{base} ({sha})"),
        _ => base,
    };

    println!("cargo:rustc-env=HEIMDALL_VERSION={version}");
}
