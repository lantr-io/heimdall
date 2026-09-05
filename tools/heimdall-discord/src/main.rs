//! heimdall-discord — relay a heimdall node's protocol events and warnings from
//! its log to a Discord channel.
//!
//! An SPO running one or more heimdall nodes does not tail their journals all
//! day, and the lines worth an interruption are few: a DKG round opening and
//! who is in it, the key and treasury address the ceremony produced, a treasury
//! movement built, posted or confirmed — and anything the node warns about.
//! heimdall marks the first kind with the tracing target `heimdall::event` and
//! files everything else at a level; this tool reads the log, keeps those two
//! kinds, and posts them to a webhook.
//!
//! It is a separate program on purpose. heimdall holds the signing share and
//! talks to its peers, and an operator will not want it opening an outbound
//! connection to a chat service from inside their network. This tool reads what
//! heimdall wrote and nothing else: no config, no key, no chain. It can run as
//! another user, in its own sandbox, or on another host that receives the logs.
//! The webhook URL is the one secret it holds, and it comes from the
//! environment or a file — never the command line, where `ps` would show it.
//!
//! Sources: `--file` (followed like `tail -F`, surviving rotation), `--unit`
//! (through `journalctl`), or stdin. Any mix; every message says which one it
//! came from.

mod discord;
mod record;
mod source;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::discord::{MAX_CONTENT, Webhook, pack_front, split_line};
use crate::record::{Level, Selector, parse_line, render};
use crate::source::Line;

/// Lines kept while Discord is unreachable. Beyond this the oldest are dropped
/// and the drop is reported — a relay is not a log store.
const MAX_PENDING: usize = 500;
/// How long to wait before trying Discord again after a failed post.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30);
/// The gap between two messages of one flush. The webhook limit is five posts
/// per two seconds; this stays well under it without making a flush crawl.
const GAP_BETWEEN_MESSAGES: Duration = Duration::from_millis(500);
/// How often a followed file is checked for new lines.
const FILE_POLL: Duration = Duration::from_millis(500);

#[derive(Parser)]
#[command(
    name = "heimdall-discord",
    version,
    about = "Relay a heimdall node's protocol events and warnings to a Discord channel",
    long_about = "Reads heimdall's log — a file, a systemd unit's journal, or stdin — keeps the \
                  `heimdall::event` lines (a DKG round opening and its participants, the key and \
                  treasury address it produced, a treasury movement built, posted or confirmed) \
                  plus every line at --min-level or above, and posts them to a Discord webhook.\n\n\
                  The webhook URL is read from $DISCORD_WEBHOOK_URL or --webhook-file, never from \
                  the command line."
)]
struct Cli {
    /// Log file to follow, like `tail -F` (rotation and truncation survive);
    /// repeatable. `LABEL=PATH` sets the label messages carry, else the file
    /// name without its extension.
    #[arg(long = "file", value_name = "[LABEL=]PATH")]
    files: Vec<String>,

    /// systemd unit to follow through journalctl (`heimdall`, `heimdall@spo1`);
    /// repeatable. Needs read access to the journal: the systemd-journal group.
    #[arg(long = "unit", value_name = "UNIT")]
    units: Vec<String>,

    /// Read the log from stdin. The default when no --file or --unit is given.
    #[arg(long)]
    stdin: bool,

    /// Label for stdin lines. Files carry their own, journal lines their unit.
    #[arg(long, value_name = "TEXT")]
    label: Option<String>,

    /// Also relay every line at this level or above: warn (default), error, or
    /// off for the event lines only.
    #[arg(long, default_value = "warn", value_name = "LEVEL")]
    min_level: String,

    /// Leave out the heimdall::event lines (warnings and errors only).
    #[arg(long)]
    no_events: bool,

    /// Start from the beginning of each file, and from the start of the journal,
    /// instead of from what is written from now on.
    #[arg(long)]
    from_start: bool,

    /// Wait this long for more lines before posting, so lines that arrive
    /// together share one message.
    #[arg(long, default_value_t = 1500, value_name = "MS")]
    coalesce_ms: u64,

    /// File holding the webhook URL, instead of $DISCORD_WEBHOOK_URL.
    #[arg(long, value_name = "PATH")]
    webhook_file: Option<PathBuf>,

    /// The name the messages are posted under.
    #[arg(long, default_value = "heimdall", value_name = "NAME")]
    username: String,

    /// Print what would be posted instead of posting it. Needs no webhook.
    #[arg(long)]
    dry_run: bool,

    /// Post one test message and exit.
    #[arg(long)]
    test: bool,
}

/// The relay's own few lines, to stderr. Under systemd, with the `<N>` prefix
/// journald files at the matching priority (heimdall does the same); on a
/// terminal, with the level word.
pub mod say {
    fn under_journald() -> bool {
        std::env::var_os("JOURNAL_STREAM").is_some_and(|v| !v.is_empty())
    }
    fn line(priority: u8, word: &str, text: &str) {
        if under_journald() {
            eprintln!("<{priority}>{text}");
        } else {
            eprintln!("heimdall-discord: {word}: {text}");
        }
    }
    pub fn info(text: &str) {
        line(6, "info", text);
    }
    pub fn warn(text: &str) {
        line(4, "warning", text);
    }
    pub fn error(text: &str) {
        line(3, "error", text);
    }
}

/// Where the messages go.
enum Sink {
    Discord(Webhook),
    /// `--dry-run`: stdout.
    Print,
}

impl Sink {
    async fn post(&self, content: &str) -> Result<(), String> {
        match self {
            Self::Discord(hook) => hook.post(content).await,
            Self::Print => {
                println!("{content}");
                Ok(())
            }
        }
    }
}

fn webhook_url(file: Option<&Path>) -> Result<String, String> {
    if let Some(path) = file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read --webhook-file {}: {e}", path.display()))?;
        let url = text.trim();
        if url.is_empty() {
            return Err(format!("--webhook-file {} is empty", path.display()));
        }
        return Ok(url.to_string());
    }
    match std::env::var("DISCORD_WEBHOOK_URL") {
        Ok(url) if !url.trim().is_empty() => Ok(url),
        _ => {
            Err("no webhook: set DISCORD_WEBHOOK_URL, pass --webhook-file, or use --dry-run".into())
        }
    }
}

/// `LABEL=PATH`, or a bare path labelled by its file stem.
fn file_source(spec: &str) -> (String, PathBuf) {
    if let Some((label, path)) = spec.split_once('=')
        && !label.is_empty()
        && !label.contains('/')
    {
        return (label.to_string(), PathBuf::from(path));
    }
    let path = PathBuf::from(spec);
    let label = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| spec.to_string());
    (label, path)
}

/// Post everything queued, oldest first, as few messages as fit. On a failure
/// the unsent lines stay queued and a retry is scheduled; on success the queue
/// is empty and no flush is pending.
async fn flush(
    pending: &mut VecDeque<String>,
    dropped: &mut usize,
    sink: &Sink,
    flush_at: &mut Option<Instant>,
) {
    if *dropped > 0 {
        pending.push_front(format!(
            "… {dropped} line(s) dropped while Discord was unreachable"
        ));
        *dropped = 0;
    }
    let mut first = true;
    while let Some((message, taken)) = pack_front(pending, MAX_CONTENT) {
        if !first {
            tokio::time::sleep(GAP_BETWEEN_MESSAGES).await;
        }
        first = false;
        if let Err(e) = sink.post(&message).await {
            say::warn(&format!(
                "{e} — {} line(s) kept, retrying in {}s",
                pending.len(),
                RETRY_AFTER_FAILURE.as_secs()
            ));
            *flush_at = Some(Instant::now() + RETRY_AFTER_FAILURE);
            return;
        }
        pending.drain(..taken);
    }
    *flush_at = None;
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let min_level = match cli.min_level.trim().to_ascii_lowercase().as_str() {
        "off" | "none" => None,
        other => match other.parse::<Level>() {
            Ok(level) => Some(level),
            Err(e) => {
                say::error(&format!("--min-level: {e}"));
                std::process::exit(2);
            }
        },
    };
    let selector = Selector {
        events: !cli.no_events,
        min_level,
    };

    let sink = if cli.dry_run {
        Sink::Print
    } else {
        let url = webhook_url(cli.webhook_file.as_deref()).unwrap_or_else(|e| {
            say::error(&e);
            std::process::exit(2);
        });
        match Webhook::new(&url, &cli.username) {
            Ok(hook) => Sink::Discord(hook),
            Err(e) => {
                say::error(&e);
                std::process::exit(2);
            }
        }
    };

    if cli.test {
        let text = "```\nheimdall-discord: test message — the webhook works\n```";
        if let Err(e) = sink.post(text).await {
            say::error(&e);
            std::process::exit(1);
        }
        say::info("test message posted");
        return;
    }

    // Sources. Each holds a sender; the receiver ends when the last of them
    // is gone, which for stdin is the end of the input and for anything else
    // is a failure.
    let (tx, mut rx) = mpsc::channel::<Line>(1024);
    let mut following: Vec<String> = Vec::new();
    for spec in &cli.files {
        let (label, path) = file_source(spec);
        following.push(format!("file {} as [{label}]", path.display()));
        source::follow_file(path, label, cli.from_start, FILE_POLL, tx.clone());
    }
    if !cli.units.is_empty() {
        following.push(format!("journal of {}", cli.units.join(", ")));
        if let Err(e) = source::follow_journal(&cli.units, cli.from_start, tx.clone()) {
            say::error(&e);
            std::process::exit(1);
        }
    }
    let use_stdin = cli.stdin || (cli.files.is_empty() && cli.units.is_empty());
    if use_stdin {
        following.push(match &cli.label {
            Some(label) => format!("stdin as [{label}]"),
            None => "stdin".to_string(),
        });
        source::read_stdin(cli.label.clone(), tx.clone());
    }
    drop(tx);

    let started = format!(
        "```\nheimdall-discord started: {} — relaying {}\n```",
        following.join("; "),
        selector.describe()
    );
    say::info(&format!(
        "following {}; relaying {}",
        following.join("; "),
        selector.describe()
    ));
    if let Err(e) = sink.post(&started).await {
        say::error(&format!("cannot post to Discord: {e}"));
        std::process::exit(1);
    }

    let coalesce = Duration::from_millis(cli.coalesce_ms);
    let mut pending: VecDeque<String> = VecDeque::new();
    let mut dropped = 0usize;
    let mut flush_at: Option<Instant> = None;

    loop {
        let next = match flush_at {
            None => rx.recv().await,
            Some(at) => tokio::select! {
                line = rx.recv() => line,
                _ = tokio::time::sleep_until(at) => {
                    flush(&mut pending, &mut dropped, &sink, &mut flush_at).await;
                    continue;
                }
            },
        };
        match next {
            Some(line) => {
                let Some(record) = parse_line(&line.text) else {
                    continue;
                };
                if !selector.wants(&record) {
                    continue;
                }
                let rendered = render(&record, line.from.as_deref());
                pending.extend(split_line(&rendered, MAX_CONTENT));
                while pending.len() > MAX_PENDING {
                    pending.pop_front();
                    dropped += 1;
                }
                if flush_at.is_none() {
                    flush_at = Some(Instant::now() + coalesce);
                }
            }
            None => {
                flush(&mut pending, &mut dropped, &sink, &mut flush_at).await;
                if use_stdin && cli.files.is_empty() && cli.units.is_empty() {
                    return;
                }
                say::error("every source has ended");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_spec_is_labelled_explicitly_or_by_its_stem() {
        let (label, path) = file_source("/var/log/heimdall/spo1.log");
        assert_eq!(label, "spo1");
        assert_eq!(path, PathBuf::from("/var/log/heimdall/spo1.log"));

        let (label, path) = file_source("node-a=/var/log/heimdall/spo1.log");
        assert_eq!(label, "node-a");
        assert_eq!(path, PathBuf::from("/var/log/heimdall/spo1.log"));

        // A path with '=' in a directory name is a path, not a label.
        let (label, path) = file_source("/srv/a=b/heimdall.log");
        assert_eq!(label, "heimdall");
        assert_eq!(path, PathBuf::from("/srv/a=b/heimdall.log"));
    }

    #[tokio::test]
    async fn a_flush_posts_the_queue_in_order_and_reports_drops() {
        let sink = Sink::Print;
        let mut pending: VecDeque<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let mut dropped = 3;
        let mut flush_at = Some(Instant::now());
        flush(&mut pending, &mut dropped, &sink, &mut flush_at).await;
        assert!(pending.is_empty());
        assert_eq!(dropped, 0);
        assert!(flush_at.is_none());
    }

    #[tokio::test]
    async fn a_failed_flush_keeps_the_lines_and_schedules_a_retry() {
        let sink = Sink::Discord(Webhook::new("http://127.0.0.1:1/hook", "h").unwrap());
        let mut pending: VecDeque<String> = ["a"].iter().map(|s| s.to_string()).collect();
        let mut dropped = 0;
        let mut flush_at = Some(Instant::now());
        flush(&mut pending, &mut dropped, &sink, &mut flush_at).await;
        assert_eq!(pending.len(), 1);
        assert!(flush_at.is_some_and(|at| at > Instant::now() + Duration::from_secs(20)));
    }
}
