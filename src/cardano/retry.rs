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
