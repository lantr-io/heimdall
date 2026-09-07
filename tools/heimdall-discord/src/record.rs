//! One log line → one [`Record`]: which level, which target, what it said, and
//! which unit it came from.
//!
//! heimdall writes three shapes (`src/logging.rs` in the heimdall repo) and the
//! journal wraps them in a fourth. All four are recognised here, per line, with
//! no configuration, because which one arrives depends on how the node was
//! started and not on anything this tool can know:
//!
//! - journal JSON, from `journalctl -o json`: the message in `MESSAGE`, the
//!   priority in `PRIORITY`, the unit in `_SYSTEMD_UNIT`. The `<N>` prefix
//!   heimdall wrote is already stripped by journald.
//! - heimdall's `--log-format json`:
//!   `{"level":"INFO","target":"heimdall::event","fields":{"message":"…"}}`
//! - plain: `2026-09-05T10:00:00Z  INFO heimdall::event: [spo=1 epoch=307] …`
//! - journal text as heimdall writes it to a pipe or a file: `<6>heimdall::event: …`
//!
//! A line that matches none of these is still a record — `info`, no target,
//! the line as its message — so `--min-level` never depends on parsing
//! succeeding, and an unexpected shape shows up as too much rather than as
//! silence.

use std::fmt;
use std::str::FromStr;

use serde_json::Value;

/// The tracing target heimdall gives its operator-facing protocol events
/// (`heimdall::logging::EVENT_TARGET`): a DKG round opening with its
/// participants, the key and treasury address it produced, a treasury movement
/// built, posted or confirmed.
pub const EVENT_TARGET: &str = "heimdall::event";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    /// The level word as heimdall's plain and JSON formats spell it.
    fn from_word(word: &str) -> Option<Self> {
        match word {
            "TRACE" => Some(Self::Trace),
            "DEBUG" => Some(Self::Debug),
            "INFO" => Some(Self::Info),
            "WARN" | "WARNING" => Some(Self::Warn),
            "ERROR" => Some(Self::Error),
            _ => None,
        }
    }

    /// syslog priority → level, the mapping heimdall's journal format uses
    /// (0–3 err, 4 warning, 6 info, 7 debug) read back.
    fn from_priority(priority: u8) -> Self {
        match priority {
            0..=3 => Self::Error,
            4 => Self::Warn,
            5 | 6 => Self::Info,
            _ => Self::Debug,
        }
    }
}

impl FromStr for Level {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" | "err" => Ok(Self::Error),
            other => Err(format!(
                "unknown level {other:?} (expected error, warn, info, debug or trace)"
            )),
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub level: Level,
    /// The tracing target, when the line carried one (`heimdall::event`,
    /// `heimdall::cardano::blockfrost_chain`, …). heimdall omits its bare crate
    /// root, so a line from `main.rs` has none.
    pub target: Option<String>,
    pub message: String,
    /// The systemd unit, for a journal line; `.service` stripped.
    pub unit: Option<String>,
}

impl Record {
    pub fn is_event(&self) -> bool {
        self.target.as_deref() == Some(EVENT_TARGET)
    }
}

/// Parse one line in whichever of the four shapes it is in. `None` only for a
/// blank line or a journal entry whose message is not text.
pub fn parse_line(line: &str) -> Option<Record> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return None;
    }
    if line.starts_with('{')
        && let Ok(value) = serde_json::from_str::<Value>(line)
    {
        if value.get("MESSAGE").is_some() {
            return parse_journal_json(&value);
        }
        if let Some(record) = parse_tracing_json(&value) {
            return Some(record);
        }
    }
    Some(parse_text(line).0)
}

/// `journalctl -o json`. The level comes from the message text when it names
/// one (a node started with `--log-format plain` under systemd — everything on
/// its stdout is then filed at priority 6, and the text is the only place the
/// real level survives), else from `PRIORITY`.
fn parse_journal_json(value: &Value) -> Option<Record> {
    // A message journald could not decode as UTF-8 arrives as a byte array.
    let message = value.get("MESSAGE")?.as_str()?;
    let (mut record, explicit_level) = parse_text(message);
    if !explicit_level
        && let Some(priority) = value
            .get("PRIORITY")
            .and_then(Value::as_str)
            .and_then(|p| p.parse::<u8>().ok())
    {
        record.level = Level::from_priority(priority);
    }
    record.unit = value
        .get("_SYSTEMD_UNIT")
        .and_then(Value::as_str)
        .map(|u| u.strip_suffix(".service").unwrap_or(u).to_string());
    Some(record)
}

/// heimdall's `--log-format json`: tracing-subscriber's JSON event, the message
/// under `fields.message` and any other fields beside it.
fn parse_tracing_json(value: &Value) -> Option<Record> {
    let level = value.get("level")?.as_str().and_then(Level::from_word)?;
    let fields = value.get("fields")?.as_object()?;
    let mut message = fields
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let extra: Vec<String> = fields
        .iter()
        .filter(|(key, _)| key.as_str() != "message")
        .map(|(key, val)| match val {
            Value::String(s) => format!("{key}={s}"),
            other => format!("{key}={other}"),
        })
        .collect();
    if !extra.is_empty() {
        if !message.is_empty() {
            message.push(' ');
        }
        message.push_str(&extra.join(" "));
    }
    let target = value
        .get("target")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(Record {
        level,
        target,
        message,
        unit: None,
    })
}

/// The two text shapes, and anything else as an `info` line. The flag says
/// whether the text itself named a level.
pub fn parse_text(line: &str) -> (Record, bool) {
    let mut rest = line;
    let mut level = None;

    // `<6>heimdall::event: …` — the journal format on a pipe or in a file.
    if let Some(after) = rest.strip_prefix('<')
        && let Some((digits, tail)) = after.split_once('>')
        && let Ok(priority) = digits.parse::<u8>()
    {
        level = Some(Level::from_priority(priority));
        rest = tail;
    }

    // `2026-09-05T10:00:00Z  INFO …` — the plain format.
    if level.is_none()
        && let Some((stamp, tail)) = rest.split_once(' ')
        && looks_like_timestamp(stamp)
    {
        let tail = tail.trim_start();
        let (word, after) = tail.split_once(' ').unwrap_or((tail, ""));
        if let Some(found) = Level::from_word(word) {
            level = Some(found);
            rest = after;
        }
    }

    let (target, message) = split_target(rest);
    let record = Record {
        level: level.unwrap_or(Level::Info),
        target,
        message: message.to_string(),
        unit: None,
    };
    (record, level.is_some())
}

/// `YYYY-MM-DDTHH:MM:SSZ`, or anything else RFC-3339-shaped.
fn looks_like_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 19 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[10] == b'T'
}

/// `heimdall::event: rest` → `(Some("heimdall::event"), "rest")`.
///
/// A target is a Rust module path — lowercase, digits, `_`, and at least one
/// `::` — which is what keeps `Error: boom` and `txid: …` as message text.
fn split_target(body: &str) -> (Option<String>, &str) {
    if let Some((head, tail)) = body.split_once(": ") {
        let path_like = head
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == ':');
        if !head.is_empty() && head.contains("::") && path_like {
            return (Some(head.to_string()), tail);
        }
    }
    (None, body)
}

/// Which records go to the channel.
#[derive(Debug, Clone, Copy)]
pub struct Selector {
    /// The `heimdall::event` lines.
    pub events: bool,
    /// Every line at this level or above, whatever its target.
    pub min_level: Option<Level>,
}

impl Selector {
    pub fn wants(&self, record: &Record) -> bool {
        (self.events && record.is_event())
            || self.min_level.is_some_and(|floor| record.level >= floor)
    }

    /// For the startup message.
    pub fn describe(&self) -> String {
        match (self.events, self.min_level) {
            (true, Some(level)) => format!("events + {level} and above"),
            (true, None) => "events only".to_string(),
            (false, Some(level)) => format!("{level} and above"),
            (false, None) => "nothing (both filters off)".to_string(),
        }
    }
}

/// One channel line: a severity mark, where it came from, then the message —
/// with the module of a non-event line kept, since "connection reset" means one
/// thing from reqwest and another from the DKG.
pub fn render(record: &Record, label: Option<&str>) -> String {
    let mut out = String::new();
    match record.level {
        Level::Error => out.push_str("🔴 "),
        Level::Warn => out.push_str("⚠️ "),
        _ => {}
    }
    if let Some(from) = record.unit.as_deref().or(label) {
        out.push('[');
        out.push_str(from);
        out.push_str("] ");
    }
    if !record.is_event()
        && let Some(target) = &record.target
    {
        out.push_str(target);
        out.push_str(": ");
    }
    out.push_str(&record.message);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The literals heimdall's own `logging` tests pin
    // (`event_lines_keep_the_shape_the_relay_parses`).
    const JOURNAL_TEXT: &str = "<6>heimdall::event: [spo=1 epoch=307] DKG complete";
    const PLAIN: &str =
        "2026-09-05T10:00:00Z  INFO heimdall::event: [spo=1 epoch=307] DKG complete";
    const TRACING_JSON: &str = r#"{"timestamp":"2026-09-05T10:00:00Z","level":"INFO","fields":{"message":"[spo=1 epoch=307] DKG complete"},"target":"heimdall::event"}"#;

    fn event(level: Level, unit: Option<&str>) -> Record {
        Record {
            level,
            target: Some(EVENT_TARGET.to_string()),
            message: "[spo=1 epoch=307] DKG complete".to_string(),
            unit: unit.map(str::to_string),
        }
    }

    #[test]
    fn the_three_heimdall_shapes_parse_to_the_same_record() {
        assert_eq!(parse_line(JOURNAL_TEXT), Some(event(Level::Info, None)));
        assert_eq!(parse_line(PLAIN), Some(event(Level::Info, None)));
        assert_eq!(parse_line(TRACING_JSON), Some(event(Level::Info, None)));
    }

    #[test]
    fn journal_json_carries_unit_and_priority() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1757066400000000","PRIORITY":"4","_SYSTEMD_UNIT":"heimdall@spo1.service","SYSLOG_IDENTIFIER":"heimdall","MESSAGE":"heimdall::epoch::dkg: [spo=1 epoch=307] dropping round1 from 2"}"#;
        let record = parse_line(line).unwrap();
        assert_eq!(record.level, Level::Warn);
        assert_eq!(record.unit.as_deref(), Some("heimdall@spo1"));
        assert_eq!(record.target.as_deref(), Some("heimdall::epoch::dkg"));
        assert_eq!(record.message, "[spo=1 epoch=307] dropping round1 from 2");
        assert!(!record.is_event());
    }

    /// A node started with `--log-format plain` under systemd: journald files
    /// everything at 6, and the level in the text is the only true one.
    #[test]
    fn a_level_in_the_text_beats_the_journal_priority() {
        let line = r#"{"PRIORITY":"6","_SYSTEMD_UNIT":"heimdall.service","MESSAGE":"2026-09-05T10:00:00Z ERROR heimdall::cardano: boom"}"#;
        let record = parse_line(line).unwrap();
        assert_eq!(record.level, Level::Error);
        assert_eq!(record.message, "boom");
    }

    #[test]
    fn a_journal_message_that_is_not_text_is_skipped() {
        let line = r#"{"PRIORITY":"6","MESSAGE":[104,105,255]}"#;
        assert_eq!(parse_line(line), None);
    }

    #[test]
    fn tracing_json_keeps_extra_fields() {
        let line = r#"{"level":"WARN","fields":{"message":"batch built","tick":7},"target":"heimdall::epoch::machine"}"#;
        let record = parse_line(line).unwrap();
        assert_eq!(record.level, Level::Warn);
        assert_eq!(record.message, "batch built tick=7");
        assert_eq!(record.target.as_deref(), Some("heimdall::epoch::machine"));
    }

    #[test]
    fn text_levels_map_from_syslog_priorities_and_words() {
        assert_eq!(parse_line("<3>boom").unwrap().level, Level::Error);
        assert_eq!(parse_line("<4>careful").unwrap().level, Level::Warn);
        assert_eq!(parse_line("<6>fine").unwrap().level, Level::Info);
        assert_eq!(parse_line("<7>detail").unwrap().level, Level::Debug);
        assert_eq!(
            parse_line("2026-09-05T10:00:00Z ERROR heimdall::x: boom")
                .unwrap()
                .level,
            Level::Error
        );
        assert_eq!(
            parse_line("2026-09-05T10:00:00Z DEBUG heimdall::x: detail")
                .unwrap()
                .level,
            Level::Debug
        );
    }

    /// The bare crate root prints no target, and message text that happens to
    /// contain `: ` must not become one.
    #[test]
    fn only_module_paths_are_targets() {
        let record = parse_line("<3>Error: something broke").unwrap();
        assert_eq!(record.target, None);
        assert_eq!(record.message, "Error: something broke");

        let record = parse_line("<6>txid: abc").unwrap();
        assert_eq!(record.target, None);

        let record = parse_line("<6>[run-spo] epoch loop returned: boom").unwrap();
        assert_eq!(record.target, None);

        let record =
            parse_line("<6>hyper_util::client::legacy::connect::http: connecting").unwrap();
        assert_eq!(
            record.target.as_deref(),
            Some("hyper_util::client::legacy::connect::http")
        );
        assert_eq!(record.message, "connecting");
    }

    /// An unrecognised line is an `info` record, never a dropped one.
    #[test]
    fn an_unknown_shape_is_still_a_record() {
        let record = parse_line("Cardano wallet address: addr_test1qz2f").unwrap();
        assert_eq!(record.level, Level::Info);
        assert_eq!(record.target, None);
        assert_eq!(record.message, "Cardano wallet address: addr_test1qz2f");
        assert_eq!(parse_line("   "), None);
        assert_eq!(parse_line(""), None);
    }

    #[test]
    fn selector_takes_events_and_the_level_floor_independently() {
        let events_and_warn = Selector {
            events: true,
            min_level: Some(Level::Warn),
        };
        let info_line = parse_line("<6>heimdall::x: progress").unwrap();
        let warn_line = parse_line("<4>heimdall::x: degraded").unwrap();
        assert!(events_and_warn.wants(&event(Level::Info, None)));
        assert!(!events_and_warn.wants(&info_line));
        assert!(events_and_warn.wants(&warn_line));

        let errors_only = Selector {
            events: false,
            min_level: Some(Level::Error),
        };
        assert!(!errors_only.wants(&event(Level::Info, None)));
        assert!(!errors_only.wants(&warn_line));
        assert!(errors_only.wants(&parse_line("<3>heimdall::x: gone").unwrap()));

        let events_only = Selector {
            events: true,
            min_level: None,
        };
        assert!(events_only.wants(&event(Level::Info, None)));
        assert!(!events_only.wants(&warn_line));
        assert_eq!(events_only.describe(), "events only");
        assert_eq!(events_and_warn.describe(), "events + warn and above");
    }

    #[test]
    fn render_marks_severity_and_source_and_keeps_non_event_targets() {
        assert_eq!(
            render(&event(Level::Info, Some("heimdall@spo1")), None),
            "[heimdall@spo1] [spo=1 epoch=307] DKG complete"
        );
        // A file label stands in when the record has no unit; a unit wins over it.
        assert_eq!(
            render(&event(Level::Info, None), Some("spo2")),
            "[spo2] [spo=1 epoch=307] DKG complete"
        );
        assert_eq!(
            render(&event(Level::Info, Some("heimdall")), Some("ignored")),
            "[heimdall] [spo=1 epoch=307] DKG complete"
        );
        let warn =
            parse_line("<4>heimdall::cardano::blockfrost_chain: 429 from Blockfrost").unwrap();
        assert_eq!(
            render(&warn, None),
            "⚠️ heimdall::cardano::blockfrost_chain: 429 from Blockfrost"
        );
        let err = parse_line("<3>[run-spo] epoch loop returned unexpectedly").unwrap();
        assert_eq!(
            render(&err, Some("spo1")),
            "🔴 [spo1] [run-spo] epoch loop returned unexpectedly"
        );
    }

    #[test]
    fn level_words_for_the_flag() {
        assert_eq!("warn".parse::<Level>(), Ok(Level::Warn));
        assert_eq!(" Error ".parse::<Level>(), Ok(Level::Error));
        assert_eq!("warning".parse::<Level>(), Ok(Level::Warn));
        assert!("loud".parse::<Level>().is_err());
        assert!(Level::Error > Level::Warn && Level::Warn > Level::Info);
    }
}
