//! In-memory `CardanoPegInSource` for tests and the `--mock-pegin-source`
//! demo mode. Peg-in requests are scheduled with a release `Instant`;
//! `query_pegin_requests` only returns those whose release time has
//! elapsed, so a test can model a deposit landing part-way through a run.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use async_trait::async_trait;

use crate::cardano::pegin_source::{CardanoPegInRequest, CardanoPegInSource};
use crate::epoch::state::{EpochError, EpochResult};

#[derive(Debug)]
struct Scheduled {
    release_at: Instant,
    request: CardanoPegInRequest,
}

#[derive(Debug, Default)]
pub struct MockCardanoPegInSource {
    scheduled: Mutex<Vec<Scheduled>>,
    /// How many further queries fail before the source starts answering — the
    /// stand-in for a provider hiccup, so a test can drive the epoch loop's
    /// retriable-error path instead of only its happy one.
    fail_next: AtomicU32,
}

impl MockCardanoPegInSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Schedule a peg-in request to become visible at `release_at`.
    /// Pass `Instant::now()` for "visible immediately".
    pub fn push(&self, release_at: Instant, request: CardanoPegInRequest) {
        self.scheduled.lock().unwrap().push(Scheduled {
            release_at,
            request,
        });
    }

    /// Fail the next `n` queries with a retriable chain error.
    pub fn fail_next(&self, n: u32) {
        self.fail_next.store(n, Ordering::Release);
    }
}

#[async_trait]
impl CardanoPegInSource for MockCardanoPegInSource {
    async fn query_pegin_requests(
        &self,
        _policy_id: &[u8; 28],
    ) -> EpochResult<Vec<CardanoPegInRequest>> {
        if self
            .fail_next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(EpochError::Chain("mock peg-in source: injected".into()));
        }
        // The mock ignores `policy_id` — the real impl filters by it.
        let now = Instant::now();
        let g = self.scheduled.lock().unwrap();
        let mut out: Vec<CardanoPegInRequest> = g
            .iter()
            .filter(|s| s.release_at <= now)
            .map(|s| s.request.clone())
            .collect();
        // Deterministic ordering: the trait contract requires sort by
        // `cardano_utxo`, so the frozen set is identical across SPOs.
        out.sort_by(|a, b| a.cardano_utxo.cmp(&b.cardano_utxo));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::pegin_source::CardanoOutRef;
    use std::time::Duration;

    fn req(tag: u8) -> CardanoPegInRequest {
        CardanoPegInRequest {
            cardano_utxo: CardanoOutRef {
                tx_hash: [tag; 32],
                output_index: 0,
            },
            datum_cbor: vec![tag],
            created_slot: Some(u64::from(tag)),
        }
    }

    #[tokio::test]
    async fn empty_source_returns_empty() {
        let src = MockCardanoPegInSource::new();
        let out = src.query_pegin_requests(&[0u8; 28]).await.unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn immediate_releases_are_visible() {
        let src = MockCardanoPegInSource::new();
        src.push(Instant::now(), req(1));
        src.push(Instant::now(), req(2));
        let out = src.query_pegin_requests(&[0u8; 28]).await.unwrap();
        assert_eq!(out.len(), 2);
    }

    #[tokio::test]
    async fn future_releases_are_hidden_until_elapsed() {
        let src = MockCardanoPegInSource::new();
        src.push(Instant::now() + Duration::from_millis(80), req(1));
        let out1 = src.query_pegin_requests(&[0u8; 28]).await.unwrap();
        assert!(out1.is_empty());
        tokio::time::sleep(Duration::from_millis(120)).await;
        let out2 = src.query_pegin_requests(&[0u8; 28]).await.unwrap();
        assert_eq!(out2.len(), 1);
    }

    #[tokio::test]
    async fn output_is_sorted_by_cardano_utxo() {
        let src = MockCardanoPegInSource::new();
        // Insert out of order; expect sorted output.
        src.push(Instant::now(), req(3));
        src.push(Instant::now(), req(1));
        src.push(Instant::now(), req(2));
        let out = src.query_pegin_requests(&[0u8; 28]).await.unwrap();
        let tags: Vec<u8> = out.iter().map(|r| r.cardano_utxo.tx_hash[0]).collect();
        assert_eq!(tags, vec![1, 2, 3]);
    }
}
