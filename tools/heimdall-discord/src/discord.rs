//! The Discord side: packing lines into messages under the content cap, and a
//! webhook client that waits out the rate limit instead of tripping it.

use std::collections::VecDeque;
use std::time::Duration;

/// Discord's cap on a message's `content`, in characters. Bytes are counted
/// here, which is never more permissive.
pub const MAX_CONTENT: usize = 2000;

const FENCE: &str = "```";

/// What a message can hold once fenced: `"```\n" + body + "\n```"`.
fn body_budget(max_content: usize) -> usize {
    max_content.saturating_sub(FENCE.len() * 2 + 2).max(16)
}

/// Cut one line into pieces that each fit a message, and neutralise a fence
/// inside it — a line longer than a whole message is rare (a very long roster)
/// but must arrive, not vanish. Whole lines come back as one piece.
pub fn split_line(line: &str, max_content: usize) -> Vec<String> {
    let line = line.replace(FENCE, "'''");
    let max = body_budget(max_content);
    let mut pieces = Vec::new();
    let mut start = 0;
    while line.len() - start > max {
        let mut end = start + max;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        pieces.push(line[start..end].to_string());
        start = end;
    }
    pieces.push(line[start..].to_string());
    pieces
}

/// Take as many lines off the front of the queue as fit in one message — at
/// least one, since every queued line was cut to size by [`split_line`] — and
/// fence them as a code block, so `_` and `*` in keys and pool ids are not read
/// as markdown. Returns the message and how many lines it consumed; the caller
/// drains them only once the post succeeded.
pub fn pack_front(lines: &VecDeque<String>, max_content: usize) -> Option<(String, usize)> {
    let budget = body_budget(max_content);
    let mut body = String::new();
    let mut taken = 0;
    for line in lines {
        let need = if body.is_empty() {
            line.len()
        } else {
            body.len() + 1 + line.len()
        };
        if need > budget && taken > 0 {
            break;
        }
        if taken > 0 {
            body.push('\n');
        }
        body.push_str(line);
        taken += 1;
    }
    (taken > 0).then(|| (format!("{FENCE}\n{body}\n{FENCE}"), taken))
}

/// A Discord webhook. The URL is a bearer secret — anyone holding it can post
/// to the channel — so it is never printed, and a transport error is reported
/// with the URL stripped (reqwest would otherwise quote it).
pub struct Webhook {
    url: String,
    username: String,
    client: reqwest::Client,
}

impl Webhook {
    pub fn new(url: &str, username: &str) -> Result<Self, String> {
        let url = url.trim();
        let local = url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost");
        if !(url.starts_with("https://") || local) {
            return Err("the webhook URL must start with https://".to_string());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| format!("http client: {}", e.without_url()))?;
        Ok(Self {
            url: url.to_string(),
            username: username.to_string(),
            client,
        })
    }

    /// Post one message. A 429 is waited out — `retry_after` from the body,
    /// else the `Retry-After` header, else 2 s, capped at a minute — and
    /// retried a few times. Anything else that is not 2xx is an error: a 400 or
    /// a 404 comes back the same on a re-send, so it is the caller's to report.
    pub async fn post(&self, content: &str) -> Result<(), String> {
        let body = serde_json::json!({
            "content": content,
            "username": self.username,
            // Log text must never ping anyone, whatever it contains.
            "allowed_mentions": { "parse": [] },
        });
        for _ in 0..5 {
            let response = self
                .client
                .post(&self.url)
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("sending to Discord: {}", e.without_url()))?;
            let status = response.status();
            if status.is_success() {
                return Ok(());
            }
            if status.as_u16() == 429 {
                let from_header = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<f64>().ok());
                let text = response.text().await.unwrap_or_default();
                let from_body = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("retry_after").and_then(|r| r.as_f64()));
                let secs = from_body.or(from_header).unwrap_or(2.0).clamp(0.1, 60.0);
                tokio::time::sleep(Duration::from_secs_f64(secs)).await;
                continue;
            }
            let text = response.text().await.unwrap_or_default();
            let text: String = text.trim().chars().take(200).collect();
            return Err(format!("Discord answered {status}: {text}"));
        }
        Err("Discord kept rate-limiting this webhook (5 tries)".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn queue(lines: &[&str]) -> VecDeque<String> {
        lines.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn lines_that_fit_share_one_fenced_message() {
        let lines = queue(&["one", "two", "three"]);
        let (message, taken) = pack_front(&lines, MAX_CONTENT).unwrap();
        assert_eq!(message, "```\none\ntwo\nthree\n```");
        assert_eq!(taken, 3);
        assert!(pack_front(&VecDeque::new(), MAX_CONTENT).is_none());
    }

    #[test]
    fn a_message_stops_where_the_next_line_would_overflow() {
        // Budget 40 - 8 = 32 bytes of body: "aaaaaaaaaa\nbbbbbbbbbb" is 21,
        // adding "\ncccccccccc" makes 32 — fits; a fourth does not.
        let lines = queue(&["aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc", "dddddddddd"]);
        let (message, taken) = pack_front(&lines, 40).unwrap();
        assert_eq!(taken, 3, "{message}");
        assert!(message.len() <= 40, "{}", message.len());
        assert!(message.ends_with("cccccccccc\n```"), "{message}");
    }

    #[test]
    fn an_overlong_line_is_cut_at_character_boundaries_and_fences_are_neutralised() {
        // 32 bytes of body per message; 'é' is two bytes and must not be split.
        let long = "é".repeat(40);
        let pieces = split_line(&long, 40);
        assert_eq!(pieces.len(), 3, "{pieces:?}");
        assert!(pieces.iter().all(|p| p.len() <= 32));
        assert_eq!(pieces.concat(), long);

        assert_eq!(split_line("short", 40), vec!["short".to_string()]);
        assert_eq!(split_line("a ``` b", 40), vec!["a ''' b".to_string()]);
    }

    /// A stand-in for the webhook endpoint: answers each request with the next
    /// scripted status, and keeps every request body it saw.
    async fn fake_discord(script: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://127.0.0.1:{}/hook",
            listener.local_addr().unwrap().port()
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_server = seen.clone();
        tokio::spawn(async move {
            let mut script = script.into_iter();
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let (head_end, content_length) = loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        break (end + 4, len);
                    }
                };
                while raw.len() < head_end + content_length {
                    let n = socket.read(&mut buf).await.unwrap();
                    raw.extend_from_slice(&buf[..n]);
                }
                seen_by_server
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&raw[head_end..]).into_owned());
                let (status, body) = script.next().unwrap_or((204, ""));
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(reply.as_bytes()).await.unwrap();
                socket.shutdown().await.ok();
            }
        });
        (url, seen)
    }

    #[tokio::test]
    async fn a_rate_limit_is_waited_out_and_the_post_retried() {
        let (url, seen) = fake_discord(vec![
            (429, r#"{"retry_after":0.05,"global":false}"#),
            (204, ""),
        ])
        .await;
        let hook = Webhook::new(&url, "heimdall").unwrap();
        hook.post("```\nhello\n```").await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
        let body: serde_json::Value = serde_json::from_str(&seen[1]).unwrap();
        assert_eq!(body["content"], "```\nhello\n```");
        assert_eq!(body["username"], "heimdall");
        assert_eq!(body["allowed_mentions"]["parse"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn a_bad_request_is_an_error_and_is_not_retried() {
        let (url, seen) =
            fake_discord(vec![(400, r#"{"message":"Cannot send an empty message"}"#)]).await;
        let hook = Webhook::new(&url, "heimdall").unwrap();
        let err = hook.post("").await.unwrap_err();
        assert!(err.contains("400"), "{err}");
        assert!(err.contains("empty message"), "{err}");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_webhook_must_be_https_off_the_loopback() {
        assert!(Webhook::new("http://discord.com/api/webhooks/1/x", "h").is_err());
        assert!(Webhook::new("https://discord.com/api/webhooks/1/x", "h").is_ok());
        assert!(Webhook::new("http://127.0.0.1:9/hook", "h").is_ok());
    }
}
