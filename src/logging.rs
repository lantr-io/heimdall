//! Process-wide log subscriber.
//!
//! heimdall runs unattended, so the log is the only account an operator gets of
//! what the node did. Three properties drive the design:
//!
//! **Severity has to survive the trip to journald.** Under systemd both stdout
//! and stderr are recorded at priority 6 (info) — measured, not assumed — so an
//! `eprintln!` error is indistinguishable from a progress line and
//! `journalctl -p err` on a broken node shows nothing. systemd's fix is
//! `SyslogLevelPrefix` (on by default): a line beginning with `<N>` is filed at
//! syslog priority `N` and the prefix is stripped. The `journal` format emits
//! that prefix, per line, so a multi-line event does not lose its level after
//! its first newline.
//!
//! **One stream.** Everything goes to stdout. A second stream is what creates
//! the ordering problem this module exists to remove, and journald owns
//! rotation, permissions and disk-full behaviour, so there is no log file.
//!
//! **Verbosity without a rebuild.** `--log-level`, else `RUST_LOG`, else
//! `[log] level` in the config file.
//!
//! Logs are not the same thing as command output: `heimdall show-treasury`
//! prints a report because the operator asked for it, and that stays on stdout
//! as plain text — untimestamped, and never silenced by a log level.

use std::fmt;
use std::sync::OnceLock;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

use crate::config::LogConfig;

// ── Format selection ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Timestamped human-readable lines. The default when not under systemd.
    Plain,
    /// `<N>`-prefixed lines for journald: no timestamp (journald stamps its
    /// own), severity carried in the prefix.
    Journal,
    /// One JSON object per event, for a log shipper.
    Json,
}

impl LogFormat {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "plain" | "text" => Some(Self::Plain),
            "journal" | "systemd" => Some(Self::Journal),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// systemd sets `JOURNAL_STREAM` on a service whose stdout it captures, and
/// documents it as exactly this test (systemd.exec(5)). Detecting the journal
/// rather than requiring the operator to configure it means the Debian unit and
/// an interactive `heimdall run-mover` each get the right format with no flag.
fn under_journald() -> bool {
    std::env::var_os("JOURNAL_STREAM").is_some_and(|v| !v.is_empty())
}

// ── CLI overrides ───────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct CliOverrides {
    level: Option<String>,
    format: Option<String>,
}

static CLI: OnceLock<CliOverrides> = OnceLock::new();

/// Record the global `--log-level` / `--log-format` flags before any config is
/// loaded. `init` reads them back; they outrank both the environment and the
/// config file.
pub fn set_cli_overrides(level: Option<String>, format: Option<String>) {
    let _ = CLI.set(CliOverrides { level, format });
}

fn cli() -> &'static CliOverrides {
    CLI.get_or_init(CliOverrides::default)
}

// ── Filter ──────────────────────────────────────────────────────────

/// Turn a level directive into an `EnvFilter` string.
///
/// A bare word (`debug`) is scoped to heimdall and leaves the dependency tree at
/// `warn`. `RUST_LOG=debug` conventionally means *everything* at debug, but for
/// this binary that is reqwest, hyper and rustls drowning the thing the operator
/// was trying to read. Anything that looks like a real directive — it contains
/// `=` or `,` — is passed through untouched, so `RUST_LOG=debug,heimdall=trace`
/// still does what a Rust developer expects.
fn filter_directive(raw: &str) -> String {
    let raw = raw.trim();
    if raw.contains('=') || raw.contains(',') {
        raw.to_string()
    } else {
        format!("warn,heimdall={raw}")
    }
}

fn resolve_filter(cfg: &LogConfig) -> EnvFilter {
    let raw = cli()
        .level
        .clone()
        .or_else(|| {
            std::env::var("RUST_LOG")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| cfg.level.clone());
    let directive = filter_directive(&raw);
    // A typo in a level must not silently disable logging, and it is too early
    // to log the complaint — fall back to the default and say so on stderr.
    EnvFilter::try_new(&directive).unwrap_or_else(|e| {
        eprintln!("warning: ignoring invalid log level {raw:?} ({e}); using \"info\"");
        EnvFilter::new(filter_directive("info"))
    })
}

fn resolve_format(cfg: &LogConfig) -> LogFormat {
    let raw = cli()
        .format
        .clone()
        .or_else(|| {
            std::env::var("HEIMDALL_LOG_FORMAT")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| cfg.format.clone());
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" | "" => {
            if under_journald() {
                LogFormat::Journal
            } else {
                LogFormat::Plain
            }
        }
        other => LogFormat::parse(other).unwrap_or_else(|| {
            eprintln!("warning: ignoring unknown log format {raw:?}; using \"plain\"");
            LogFormat::Plain
        }),
    }
}

// ── Init ────────────────────────────────────────────────────────────

fn install<W>(cfg: &LogConfig, writer: W)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = resolve_filter(cfg);
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer);
    let _ = match resolve_format(cfg) {
        LogFormat::Json => builder
            .json()
            .with_timer(UtcTime)
            .with_current_span(false)
            .with_span_list(false)
            .try_init(),
        LogFormat::Plain => builder
            .event_format(TextFormat { journal: false })
            .try_init(),
        LogFormat::Journal => builder
            .event_format(TextFormat { journal: true })
            .try_init(),
    };
}

/// Install the process-wide subscriber, logging to stdout. Idempotent: a second
/// call is a no-op, so a test or a tool that loads two configs does not panic.
pub fn init(cfg: &LogConfig) {
    install(cfg, std::io::stdout);
}

/// Install the subscriber for a pipe-friendly one-shot tool, logging to
/// **stderr**.
///
/// `depositor` and `register-pool` put exactly one thing on stdout — the signed
/// transaction hex — so that `depositor … | bitcoin-cli sendrawtransaction` is
/// the intended usage. Their diagnostics have always gone to stderr, and that
/// split is the tool's interface, not the accident this module exists to fix.
/// The daemon's one-stream rule is about journald ordering; a tool at the head
/// of a pipeline has no journald and no ordering problem.
pub fn init_tool() {
    install(&LogConfig::default(), std::io::stderr);
}

// ── Text formatter ──────────────────────────────────────────────────

/// syslog priorities, as journald files them (`journalctl -p`).
fn syslog_priority(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 3, // err
        Level::WARN => 4,  // warning
        Level::INFO => 6,  // info
        // journald has no separate debug/trace: both are 7.
        Level::DEBUG | Level::TRACE => 7,
    }
}

struct TextFormat {
    journal: bool,
}

impl<S, N> FormatEvent<S, N> for TextFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();

        // Render the fields first: an event can be several lines long (a decoded
        // datum, a rendered report), and in journal mode every one of those lines
        // needs its own `<N>` or journald files the tail at the default priority.
        let mut body = String::new();
        ctx.field_format()
            .format_fields(Writer::new(&mut body), event)?;

        // A module path (`heimdall::cardano::blockfrost_chain`) says which
        // subsystem spoke and is what `RUST_LOG` aims at, so it earns its space.
        // The bare crate root does not: journald already tags every record with
        // the syslog identifier `heimdall`, and printing it again would render
        // as `heimdall[123]: heimdall: …`.
        let target = match meta.target() {
            env!("CARGO_CRATE_NAME") => "",
            t => t,
        };

        for line in body.split('\n') {
            if self.journal {
                // No timestamp and no level word: journald stamps its own, and
                // the prefix it strips is what sets the priority.
                write!(writer, "<{}>", syslog_priority(meta.level()))?;
            } else {
                UtcTime.format_time(&mut writer)?;
                write!(writer, " {:>5} ", meta.level())?;
            }
            if !target.is_empty() {
                write!(writer, "{target}: ")?;
            }
            writeln!(writer, "{line}")?;
        }
        Ok(())
    }
}

// ── Timestamps ──────────────────────────────────────────────────────

/// RFC-3339 UTC to the second.
///
/// Local time is deliberately not offered: a daemon's log is read next to
/// Cardano slots and Bitcoin block times, both of which are UTC, and the `time`
/// crate refuses to resolve a local offset from a multi-threaded process anyway.
struct UtcTime;

impl FormatTime for UtcTime {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        write!(w, "{}", format_unix_utc(secs))
    }
}

/// Format a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
fn format_unix_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, min, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
}

/// Days since the Unix epoch → (year, month, day). Howard Hinnant's
/// `civil_from_days`, which is exact for the whole proleptic Gregorian range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Collect a subscriber's output so the rendered bytes can be asserted on.
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn render(journal: bool, f: impl FnOnce()) -> String {
        let buf = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(Level::TRACE)
            .event_format(TextFormat { journal })
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        buf.contents()
    }

    #[test]
    fn journal_format_files_each_level_at_its_syslog_priority() {
        let out = render(true, || {
            tracing::error!("boom");
            tracing::warn!("careful");
            tracing::info!("progress");
            tracing::debug!("detail");
        });
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4, "{out}");
        assert!(lines[0].starts_with("<3>"), "{}", lines[0]);
        assert!(lines[1].starts_with("<4>"), "{}", lines[1]);
        assert!(lines[2].starts_with("<6>"), "{}", lines[2]);
        assert!(lines[3].starts_with("<7>"), "{}", lines[3]);
        // The target survives, so `journalctl` output still says which module spoke.
        assert!(lines[0].contains("heimdall::logging"), "{}", lines[0]);
        assert!(lines[0].ends_with("boom"), "{}", lines[0]);
    }

    /// journald already tags each record `heimdall`; repeating the crate root as
    /// a target would render `heimdall[123]: heimdall: …`.
    #[test]
    fn the_bare_crate_root_is_not_repeated_as_a_target() {
        let out = render(true, || {
            tracing::error!(target: "heimdall", "boom");
            tracing::error!(target: "heimdall::cardano", "bang");
        });
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "<3>boom", "{}", lines[0]);
        assert_eq!(lines[1], "<3>heimdall::cardano: bang", "{}", lines[1]);
    }

    /// The reason the formatter renders the body before writing anything:
    /// journald splits on newlines and files each resulting line separately, so
    /// an unprefixed continuation line would silently drop back to the default
    /// priority and escape `journalctl -p err`.
    #[test]
    fn every_line_of_a_multi_line_event_carries_the_prefix() {
        let out = render(true, || tracing::error!("first\nsecond\nthird"));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        for line in &lines {
            assert!(line.starts_with("<3>"), "{line}");
        }
        assert!(lines[1].ends_with("second"), "{}", lines[1]);
    }

    #[test]
    fn plain_format_carries_a_timestamp_and_level_and_no_syslog_prefix() {
        let out = render(false, || tracing::warn!("careful"));
        let line = out.lines().next().unwrap();
        assert!(!line.starts_with('<'), "{line}");
        assert!(line.contains(" WARN "), "{line}");
        assert!(line.contains("heimdall::logging::tests: careful"), "{line}");
        // `YYYY-MM-DDTHH:MM:SSZ` leads the line.
        let stamp = &line[..20];
        assert!(stamp.ends_with('Z') && stamp.contains('T'), "{stamp}");
    }

    #[test]
    fn events_carry_their_fields() {
        let out = render(true, || tracing::info!(tick = 7, "batch built"));
        assert!(out.contains("batch built"), "{out}");
        assert!(out.contains("tick=7"), "{out}");
    }

    #[test]
    fn unix_epoch_and_known_instants() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_utc(1), "1970-01-01T00:00:01Z");
        // `date -u -d @1234567890` / the canonical "1234567890" instant.
        assert_eq!(format_unix_utc(1_234_567_890), "2009-02-13T23:31:30Z");
        // Leap day, and the day after.
        assert_eq!(format_unix_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(format_unix_utc(1_709_251_199), "2024-02-29T23:59:59Z");
        assert_eq!(format_unix_utc(1_709_251_200), "2024-03-01T00:00:00Z");
        // Century non-leap year: 2100 is not a leap year, 2000 was.
        assert_eq!(format_unix_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_unix_utc(4_107_542_400), "2100-03-01T00:00:00Z");
    }

    #[test]
    fn month_boundaries_round_trip_for_a_decade() {
        // Walk every day from 2020-01-01 to 2030-01-01 and check the formatted
        // date advances by exactly one day, never repeating or skipping.
        let start = 1_577_836_800i64; // 2020-01-01T00:00:00Z
        let mut prev = format_unix_utc(start);
        for i in 1..3653 {
            let cur = format_unix_utc(start + i * 86_400);
            assert!(cur > prev, "{cur} did not advance past {prev}");
            prev = cur;
        }
        assert_eq!(prev, "2029-12-31T00:00:00Z");
    }

    #[test]
    fn priorities_match_journalctl_p_names() {
        assert_eq!(syslog_priority(&Level::ERROR), 3);
        assert_eq!(syslog_priority(&Level::WARN), 4);
        assert_eq!(syslog_priority(&Level::INFO), 6);
        assert_eq!(syslog_priority(&Level::DEBUG), 7);
        assert_eq!(syslog_priority(&Level::TRACE), 7);
    }

    #[test]
    fn bare_level_is_scoped_to_heimdall_but_directives_pass_through() {
        assert_eq!(filter_directive("debug"), "warn,heimdall=debug");
        assert_eq!(filter_directive("  info "), "warn,heimdall=info");
        assert_eq!(filter_directive("heimdall=trace"), "heimdall=trace");
        assert_eq!(
            filter_directive("debug,heimdall::cardano=trace"),
            "debug,heimdall::cardano=trace"
        );
    }

    #[test]
    fn format_names_and_their_aliases() {
        assert_eq!(LogFormat::parse("plain"), Some(LogFormat::Plain));
        assert_eq!(LogFormat::parse("TEXT"), Some(LogFormat::Plain));
        assert_eq!(LogFormat::parse("journal"), Some(LogFormat::Journal));
        assert_eq!(LogFormat::parse("systemd"), Some(LogFormat::Journal));
        assert_eq!(LogFormat::parse("json"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse("auto"), None); // resolved separately
        assert_eq!(LogFormat::parse("nonsense"), None);
    }
}
