//! Transient-failure retry for chain reads.
//!
//! Several chain reads (the registry/treasury snapshot, the ban list, and —
//! once WI-009 lands — the config UTxO) fail the same two ways: a network
//! blip, or a torn read when a tx confirms between/within the paginated
//! fetches. Both clear on a re-read, and the epoch state machine treats a
//! failed read as fatal, so each read absorbs them here rather than killing
//! the SPO. Persistent errors (bad config, corrupt state) pass straight
//! through — each caller decides which is which via `is_transient`.

use std::future::Future;
use std::time::Duration;

/// Default backoff schedule (attempts = delays + 1). Epoch-scale timing
/// tolerates seconds of latency.
pub const DEFAULT_DELAYS: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(5)];

/// Run `op`, retrying while it returns a transient error and `delays` are
/// left. `label` tags the progress line; `is_transient` classifies the error.
pub async fn retry_transient<T, E, F, Fut>(
    delays: &[Duration],
    label: &str,
    is_transient: impl Fn(&E) -> bool,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut delays = delays.iter();
    loop {
        match op().await {
            Err(e) if is_transient(&e) => match delays.next() {
                Some(delay) => {
                    eprintln!("[{label}] transient failure: {e} — retrying in {delay:?}");
                    tokio::time::sleep(*delay).await;
                }
                None => return Err(e),
            },
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Millisecond delays: these tests assert the SCHEDULE, not wall time.
    const FAST: [Duration; 2] = [Duration::from_millis(1), Duration::from_millis(1)];

    /// Run `op` counting attempts. The error is a `&str` so `is_transient` can
    /// classify by content, the way every real caller does.
    async fn run(
        delays: &[Duration],
        answers: Vec<Result<u32, &'static str>>,
    ) -> (Result<u32, &'static str>, usize) {
        let calls = AtomicUsize::new(0);
        let result = retry_transient(
            delays,
            "test",
            |e: &&str| *e == "transient",
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                let answer = answers.get(n).copied().unwrap_or(Err("exhausted"));
                async move { answer }
            },
        )
        .await;
        (result, calls.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn a_first_try_success_is_not_retried() {
        assert_eq!(run(&FAST, vec![Ok(7)]).await, (Ok(7), 1));
    }

    // The whole point: a blip costs a delay, not the caller's operation.
    #[tokio::test]
    async fn a_transient_failure_is_retried_until_it_succeeds() {
        let answers = vec![Err("transient"), Err("transient"), Ok(9)];
        assert_eq!(run(&FAST, answers).await, (Ok(9), 3));
    }

    // Attempts = delays + 1. Past that the error must SURFACE — silently
    // returning a stale or empty result would be worse than failing.
    #[tokio::test]
    async fn a_transient_failure_gives_up_after_the_schedule() {
        let answers = vec![Err("transient"); 10];
        assert_eq!(run(&FAST, answers).await, (Err("transient"), 3));
    }

    // A permanent error repeats identically, so retrying only wastes time.
    #[tokio::test]
    async fn a_permanent_failure_is_returned_at_once() {
        let answers = vec![Err("permanent"), Ok(1)];
        assert_eq!(run(&FAST, answers).await, (Err("permanent"), 1));
    }

    // An empty schedule means "try once". It must not mean "never try".
    #[tokio::test]
    async fn an_empty_schedule_still_makes_one_attempt() {
        assert_eq!(
            run(&[], vec![Err("transient")]).await,
            (Err("transient"), 1)
        );
        assert_eq!(run(&[], vec![Ok(3)]).await, (Ok(3), 1));
    }

    #[test]
    fn the_default_schedule_is_two_delays() {
        assert_eq!(DEFAULT_DELAYS.len(), 2, "so callers get 3 attempts");
    }
}
