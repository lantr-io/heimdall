//! The on-disk discipline shared by heimdall's Cardano trie state files.
//!
//! `cpo-trie.json` and `spi-trie.json` are not secret, but they decide what
//! this node signs, so they get the same tamper surface as the DKG state: a
//! 0700 directory, a 0600 file, and a temp+rename write so a crash mid-write
//! never leaves a torn file.
//!
//! Errors come back as plain strings. Each caller wraps them in its own
//! `State` error variant, so the message a reader sees is the same as when
//! every trie module carried its own copy of this code.
//!
//! `epoch::persist` deliberately keeps its own variant: it force-chmods a
//! pre-existing temp file and tolerates a failed `sync_all`, which this one
//! does not.

use std::path::Path;

/// Write `bytes` to `path` atomically: create `dir` (0700), write a sibling
/// `.tmp` file (0600), then rename it into place. `path` must live in `dir`.
pub fn write_atomic_0600(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
    create_dir_0700(dir)?;
    let tmp = path.with_extension("tmp");
    write_file_0600(&tmp, bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))
}

#[cfg(unix)]
fn create_dir_0700(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("create {}: {e}", dir.display()))
}

#[cfg(not(unix))]
fn create_dir_0700(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))
}

#[cfg(unix)]
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}
