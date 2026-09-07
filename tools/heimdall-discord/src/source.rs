//! Where lines come from: log files, followed like `tail -F`; systemd units,
//! through `journalctl`; or stdin. Every source pushes [`Line`]s into one
//! channel, and the relay loop does not know which it is talking to.

use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use crate::say;

/// One line of log and, when the source knows it, where it came from. Journal
/// lines carry their unit inside the JSON, so they arrive unlabelled.
pub struct Line {
    pub from: Option<String>,
    pub text: String,
}

/// Follow a file on its own thread, like `tail -F`: start at the end (unless
/// `from_start`), read what is appended, and when the path comes to name a
/// different inode or a shorter file — logrotate, or a truncating restart —
/// finish the old one and reopen the new from its beginning. A file that does
/// not exist yet is waited for, and read from the start once it appears.
///
/// A thread rather than a task because it is plain blocking file IO with a
/// sleep in it, and there is at most a handful of them.
pub fn follow_file(
    path: PathBuf,
    label: String,
    from_start: bool,
    poll: Duration,
    tx: mpsc::Sender<Line>,
) {
    std::thread::spawn(move || follow_file_loop(path, label, from_start, poll, tx));
}

fn follow_file_loop(
    path: PathBuf,
    label: String,
    from_start: bool,
    poll: Duration,
    tx: mpsc::Sender<Line>,
) {
    struct Open {
        file: File,
        inode: u64,
        pos: u64,
    }
    let mut open: Option<Open> = None;
    let mut start_at_end = !from_start;
    let mut said_missing = false;
    let mut partial: Vec<u8> = Vec::new();

    loop {
        if open.is_none() {
            match File::open(&path) {
                Ok(mut file) => {
                    let meta = match file.metadata() {
                        Ok(m) => m,
                        Err(e) => {
                            say::warn(&format!("{}: cannot stat: {e}", path.display()));
                            std::thread::sleep(poll);
                            continue;
                        }
                    };
                    let mut pos = 0;
                    if start_at_end {
                        pos = meta.len();
                        if let Err(e) = file.seek(SeekFrom::Start(pos)) {
                            say::warn(&format!("{}: cannot seek: {e}", path.display()));
                        }
                    }
                    // Only the file present at startup is skipped to its end;
                    // anything that appears or rotates in later is all new.
                    start_at_end = false;
                    said_missing = false;
                    partial.clear();
                    open = Some(Open {
                        file,
                        inode: meta.ino(),
                        pos,
                    });
                }
                Err(_) => {
                    if !said_missing {
                        say::info(&format!(
                            "{}: not there yet, waiting for it",
                            path.display()
                        ));
                        said_missing = true;
                    }
                    start_at_end = false;
                    std::thread::sleep(poll);
                    continue;
                }
            }
        }
        let current = open.as_mut().expect("opened above");

        // Drain what has been appended. Every complete line is sent; a trailing
        // fragment waits for its newline.
        let mut chunk = [0u8; 8192];
        loop {
            match current.file.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    current.pos += n as u64;
                    partial.extend_from_slice(&chunk[..n]);
                    while let Some(nl) = partial.iter().position(|&b| b == b'\n') {
                        let text = String::from_utf8_lossy(&partial[..nl]).into_owned();
                        partial.drain(..=nl);
                        let line = Line {
                            from: Some(label.clone()),
                            text,
                        };
                        if tx.blocking_send(line).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    say::warn(&format!("{}: read error: {e}; reopening", path.display()));
                    open = None;
                    break;
                }
            }
        }

        // Rotation or truncation: judged by the PATH, after draining the old
        // descriptor, so nothing written to the old file just before the swap
        // is lost. A path that has vanished (rotation in progress) is left to
        // reappear.
        if let Some(current) = &open
            && let Ok(meta) = std::fs::metadata(&path)
            && (meta.ino() != current.inode || meta.len() < current.pos)
        {
            say::info(&format!(
                "{}: rotated or truncated, reading the new file from its start",
                path.display()
            ));
            open = None;
            continue;
        }
        std::thread::sleep(poll);
    }
}

/// Follow systemd units through `journalctl --follow --output=json`, which
/// carries the unit and priority of every line. Needs read access to the
/// journal (the `systemd-journal` group, or root). When journalctl exits, its
/// sender is dropped, and a relay with no other source ends.
pub fn follow_journal(
    units: &[String],
    from_start: bool,
    tx: mpsc::Sender<Line>,
) -> Result<(), String> {
    let mut command = tokio::process::Command::new("journalctl");
    command.args(["--follow", "--output=json", "--no-pager", "--quiet"]);
    command.arg(if from_start {
        "--lines=all"
    } else {
        "--lines=0"
    });
    for unit in units {
        command.arg("--unit").arg(unit);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run journalctl: {e}"))?;
    let stdout = child.stdout.take().expect("stdout was piped");
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(text)) => {
                    if tx.send(Line { from: None, text }).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    say::warn(&format!("journalctl: read error: {e}"));
                    break;
                }
            }
        }
        match child.wait().await {
            Ok(status) => say::warn(&format!("journalctl exited: {status}")),
            Err(e) => say::warn(&format!("journalctl: {e}")),
        }
    });
    Ok(())
}

/// Read stdin to its end on its own thread.
pub fn read_stdin(label: Option<String>, tx: mpsc::Sender<Line>) {
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(text) = line else { break };
            let line = Line {
                from: label.clone(),
                text,
            };
            if tx.blocking_send(line).is_err() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "heimdall-discord-test-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("node.log")
    }

    async fn next(rx: &mut mpsc::Receiver<Line>) -> String {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a line within 5 s")
            .expect("source still open")
            .text
    }

    #[tokio::test]
    async fn only_lines_written_after_the_start_are_sent_and_rotation_is_survived() {
        let path = temp_path("rotate");
        std::fs::write(&path, "old line\n").unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        follow_file(
            path.clone(),
            "node".into(),
            false,
            Duration::from_millis(20),
            tx,
        );
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"first\nsecond\npartial").unwrap();
        drop(f);
        assert_eq!(next(&mut rx).await, "first");
        assert_eq!(next(&mut rx).await, "second");
        // The fragment waits for its newline.
        assert!(
            tokio::time::timeout(Duration::from_millis(150), rx.recv())
                .await
                .is_err()
        );
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b" done\n").unwrap();
        drop(f);
        assert_eq!(next(&mut rx).await, "partial done");

        // logrotate: the path now names a fresh file, read from its start.
        let rotated = path.with_extension("log.1");
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, "after rotation\n").unwrap();
        assert_eq!(next(&mut rx).await, "after rotation");

        // Truncation in place (a restart with `>`), likewise.
        std::fs::write(&path, "").unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        std::fs::write(&path, "after truncation\n").unwrap();
        assert_eq!(next(&mut rx).await, "after truncation");
    }

    #[tokio::test]
    async fn a_file_that_appears_later_is_read_from_its_start() {
        let path = temp_path("late");
        let _ = std::fs::remove_file(&path);
        let (tx, mut rx) = mpsc::channel(64);
        follow_file(
            path.clone(),
            "node".into(),
            false,
            Duration::from_millis(20),
            tx,
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        std::fs::write(&path, "born\n").unwrap();
        assert_eq!(next(&mut rx).await, "born");
    }

    #[tokio::test]
    async fn from_start_replays_the_existing_file() {
        let path = temp_path("replay");
        std::fs::write(&path, "one\ntwo\n").unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        follow_file(path, "node".into(), true, Duration::from_millis(20), tx);
        assert_eq!(next(&mut rx).await, "one");
        assert_eq!(next(&mut rx).await, "two");
    }
}
