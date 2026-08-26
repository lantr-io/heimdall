//! The operator-facing health surface (WI-058): what a node reports about
//! ITSELF, to whoever runs it.
//!
//! ## Why this is not on the peer listener
//!
//! heimdall's HTTP surface is the SPO-to-SPO protocol. Its address is on chain —
//! it is this node's registered `bifrost_url` — so every other SPO, and anyone
//! else, can reach it. `/health` there is a PEER-LIVENESS probe: the DKG health
//! gate fetches it from every roster member before a ceremony, and since WI-067
//! it also carries this build's version so peers can refuse to run a ceremony
//! with an incompatible one. It answers "is this process up, and is it the same
//! software as me" — deliberately nothing else.
//!
//! What an operator needs is a different question with a different audience:
//! whether registration still holds, whether this node took part in the epoch's
//! ceremony, how close it is to a ban, whether it is keeping up with the batch
//! grid. That is operator state, and publishing it on an address the whole
//! network can reach would be both a disclosure and a wider attack surface for
//! the peer endpoint. So it binds separately, and to loopback by default.
//!
//! ## The two halves, and why both exist
//!
//! * **Static** — the WI-053 preflight [`Report`](crate::preflight::Report).
//!   Answers "could this node start, and is it still configured for this
//!   bridge". Any process can compute it from the config and the chain, so
//!   `heimdall status` and `heimdall doctor` both render it without a daemon.
//! * **Live** — [`NodeState`], which only the running daemon knows: which epoch
//!   it is in, whether it qualified in the DKG, where it stands on the batch
//!   grid, and which peers it excluded for their software. A separate process
//!   cannot compute this, which is exactly why the endpoint exists.
//!
//! `heimdall status` prints both, and says plainly when the live half is
//! missing — a node that is not running is a fact worth reporting, not an error
//! to hide.
//!
//! ## The watchdog question, answered
//!
//! **This does not add `sd_notify`/`WatchdogSec`, and that is a decision rather
//! than an omission.** systemd's watchdog proves a process is scheduling and
//! calling home; it cannot tell a node that is co-signing movements from one
//! wedged in a loop, because the same code pings either way. Wiring it would
//! turn today's honest `active (running)` into a green light that means no more
//! than it does now, which is worse: a false signal is consulted, a missing one
//! is not. The question "is this node doing its job" is answered by the state
//! below — `last_progress_ms` moves or it does not — and that is what an
//! operator's monitoring should alert on.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// What only the running daemon knows about itself.
///
/// Every field is written by the epoch loop as it passes the point that knows
/// it, and read by the loopback endpoint. Deliberately small: this is a report,
/// not a mirror of the state machine, and anything reconstructable from the
/// config or the chain belongs in the preflight [`Report`](crate::preflight::Report)
/// instead so there is one place to change it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeState {
    /// The epoch this node is working on, once it has resolved one.
    pub epoch: Option<u64>,
    /// Where it stands on the TM batch grid, in words an operator can act on.
    pub grid: Option<GridPosition>,
    /// Whether this node is in the epoch's qualified DKG set.
    ///
    /// `None` before the ceremony, `Some(false)` after being dropped from it —
    /// which is the thing it hurts most to learn late, because the node keeps
    /// running and looks fine.
    pub dkg_qualified: Option<bool>,
    /// Peers excluded from the ceremony by the pre-ceremony handshake (WI-067),
    /// as `"spo=<short id>: <reason>"`.
    ///
    /// The reason distinguishes the three causes, because the fix is different
    /// for each: a version or blueprint difference wants an upgrade, a settings
    /// difference (`demo_live_stake`, `demo_virtual_epoch_slots`) wants the
    /// setting matched across the roster, and a bare derived-threshold
    /// difference wants nothing done — it is `live_stake` drift and clears at
    /// the next ceremony entry.
    ///
    /// Here because it is the one problem that is INVISIBLE from the excluded
    /// node's chain state: it is registered, unbanned, reachable, and simply not
    /// being talked to.
    pub excluded_peers: Vec<String>,
    /// POSIX ms when the loop last did something worth calling progress —
    /// reached a batch opportunity, finished a ceremony, posted a movement.
    ///
    /// The field to alert on. A node that is up but stuck shows a
    /// `last_progress_ms` that stops moving while everything else looks healthy.
    pub last_progress_ms: Option<i64>,
    /// What the loop is doing right now, in one phrase.
    pub activity: String,
}

/// This node's place on the batch grid, and when it next has work.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GridPosition {
    /// Absolute Cardano slot this node last read.
    pub slot: u64,
    /// `i` of the opportunity in force, when one is open.
    pub batch: Option<u64>,
    /// Slot of the next opportunity, when the epoch has one left.
    pub next_slot: Option<u64>,
}

/// A handle the epoch loop writes and the endpoint reads.
///
/// Cheap to clone and never blocks the loop: an operator surface that could slow
/// the ceremony down would be a bad trade, so every update is a short lock and
/// nothing here is awaited.
#[derive(Debug, Clone, Default)]
pub struct HealthHandle(Arc<Mutex<NodeState>>);

impl HealthHandle {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current state.
    #[must_use]
    pub fn snapshot(&self) -> NodeState {
        self.0.lock().expect("health state").clone()
    }

    /// Mutate it in place.
    pub fn update(&self, f: impl FnOnce(&mut NodeState)) {
        f(&mut self.0.lock().expect("health state"));
    }

    /// Record what the loop is doing, and that it got this far.
    ///
    /// `now_ms` is passed in rather than read here so the caller's chain time is
    /// used where it has one — the same reason nothing else in this codebase
    /// reaches for a local clock when a chain time is in hand.
    pub fn progress(&self, activity: impl Into<String>, now_ms: i64) {
        self.update(|s| {
            s.activity = activity.into();
            s.last_progress_ms = Some(now_ms);
        });
    }
}

/// Render the live state for a human, or say why there is none.
#[must_use]
pub fn render(state: &NodeState) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "epoch           {}\n",
        state.epoch.map_or("—".into(), |e| e.to_string())
    ));
    out.push_str(&format!(
        "activity        {}\n",
        if state.activity.is_empty() {
            "—"
        } else {
            &state.activity
        }
    ));
    match &state.grid {
        Some(g) => {
            out.push_str(&format!(
                "grid            slot {}{}{}\n",
                g.slot,
                g.batch
                    .map_or(String::new(), |b| format!(", batch B_{b} open")),
                g.next_slot
                    .map_or(String::new(), |n| format!(", next opportunity at slot {n}")),
            ));
        }
        None => out.push_str("grid            — (no batch grid resolved yet)\n"),
    }
    out.push_str(&format!(
        "dkg             {}\n",
        match state.dkg_qualified {
            Some(true) => "qualified in this epoch's ceremony",
            // The line worth reading twice: the node is running and excluded.
            Some(false) => "NOT in the qualified set — this node is running but not signing",
            None => "— (no ceremony yet this epoch)",
        }
    ));
    out.push_str(&format!(
        "last progress   {}\n",
        state
            .last_progress_ms
            .map_or("—".into(), |ms| format!("{ms} (POSIX ms)"))
    ));
    if state.excluded_peers.is_empty() {
        out.push_str("peers excluded  none\n");
    } else {
        out.push_str("peers excluded  (the reason says whether to act — WI-067)\n");
        for p in &state.excluded_peers {
            out.push_str(&format!("         -> {p}\n"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The loopback endpoint
// ---------------------------------------------------------------------------

/// Serve [`NodeState`] as JSON at `GET /` on `bind`, until the process ends.
///
/// `bind` defaults to loopback (see [`crate::config::HealthConfig`]) and MUST
/// stay separate from the peer listener — see the module note. Nothing here
/// authenticates, because nothing here is expected to be reachable: an operator
/// who exposes this deliberately is choosing to, and the config key that lets
/// them says so.
///
/// A bind failure is reported and swallowed rather than killing the daemon. The
/// node's job is co-signing movements; losing the surface that tells an operator
/// about that is bad, but stopping the bridge because a diagnostic port was
/// taken would be worse.
pub async fn serve(bind: String, handle: HealthHandle) {
    use axum::{Router, routing::get};

    let app = Router::new()
        .route(
            "/",
            get({
                let h = handle.clone();
                move || {
                    let h = h.clone();
                    async move { axum::Json(h.snapshot()) }
                }
            }),
        )
        .route("/live", get(|| async { "ok" }));

    match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => {
            tracing::info!("[health] operator surface on http://{bind} (loopback by default)");
            if let Err(e) = axum::serve(listener, app).await {
                tracing::warn!("[health] surface stopped: {e}");
            }
        }
        Err(e) => tracing::warn!(
            "[health] could not bind {bind}: {e} — the daemon runs on without it; \
             `heimdall status` will report the live half as unavailable"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_records_both_what_and_when() {
        let h = HealthHandle::new();
        h.progress("waiting for batch B_3", 1_700_000_000_000);
        let s = h.snapshot();
        assert_eq!(s.activity, "waiting for batch B_3");
        assert_eq!(s.last_progress_ms, Some(1_700_000_000_000));
    }

    /// The handle is shared, not copied: an update through one clone is visible
    /// through another, which is what lets the loop write and the endpoint read.
    #[test]
    fn clones_share_one_state() {
        let a = HealthHandle::new();
        let b = a.clone();
        a.update(|s| s.epoch = Some(7));
        assert_eq!(b.snapshot().epoch, Some(7));
    }

    /// A fresh node renders every line rather than an empty page — "nothing has
    /// happened yet" is an answer, and a blank output is not.
    #[test]
    fn an_untouched_state_still_renders_every_line() {
        let text = render(&NodeState::default());
        for field in [
            "epoch",
            "activity",
            "grid",
            "dkg",
            "last progress",
            "peers excluded",
        ] {
            assert!(text.contains(field), "missing {field} in:\n{text}");
        }
    }

    /// Being dropped from the qualified set is the thing it hurts most to learn
    /// late, so it must not read like a neutral status word.
    #[test]
    fn being_unqualified_is_stated_plainly() {
        let state = NodeState {
            dkg_qualified: Some(false),
            ..Default::default()
        };
        let text = render(&state);
        assert!(text.contains("NOT in the qualified set"), "{text}");
        assert!(text.contains("not signing"), "{text}");
    }

    /// An excluded peer is reported with its reason, because that failure is
    /// invisible from the excluded node's own chain state.
    #[test]
    fn excluded_peers_are_listed_with_their_reason() {
        let state = NodeState {
            excluded_peers: vec!["spo=ab12: version 0.2.0 against our 0.1.0".into()],
            ..Default::default()
        };
        let text = render(&state);
        assert!(text.contains("0.2.0"), "{text}");
        assert!(text.contains("ab12"), "{text}");
    }

    /// End to end: the surface really serves what the loop wrote, over a real
    /// socket, in the shape `heimdall status` parses.
    ///
    /// Worth a real listener rather than a handler call — the thing that breaks
    /// in practice is the wiring (which handle, which route, which encoding),
    /// and a test that calls the closure directly would pass through all of it.
    #[tokio::test]
    async fn the_surface_serves_what_the_loop_wrote() {
        let handle = HealthHandle::new();
        handle.update(|s| {
            s.epoch = Some(42);
            s.dkg_qualified = Some(true);
            s.excluded_peers.push("spo=ab12: version 0.2.0".into());
        });
        // Port 0 lets the OS pick, so the test cannot collide with a real daemon
        // or with itself under parallel runs.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        tokio::spawn(serve(addr.to_string(), handle.clone()));

        // The bind races the request; retry briefly rather than sleep a fixed
        // guess.
        let url = format!("http://{addr}/");
        let mut last = String::new();
        for _ in 0..50 {
            match reqwest::get(&url).await {
                Ok(r) => {
                    let got: NodeState = r.json().await.expect("parses as NodeState");
                    assert_eq!(got, handle.snapshot(), "served state must be the live one");
                    assert_eq!(got.epoch, Some(42));
                    assert_eq!(got.excluded_peers.len(), 1);
                    return;
                }
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the surface never answered: {last}");
    }

    /// It binds where it is told, and the default is loopback — the property the
    /// whole separation from the peer listener rests on.
    #[test]
    fn the_default_bind_is_loopback() {
        let cfg = crate::config::HealthConfig::default();
        assert!(
            cfg.bind.starts_with("127.0.0.1:"),
            "operator state must not default to a public interface: {}",
            cfg.bind
        );
        assert!(cfg.enabled, "on by default, or nobody discovers it exists");
    }

    /// The wire form round-trips, so `heimdall status` reads exactly what the
    /// daemon reports.
    #[test]
    fn the_state_round_trips_as_json() {
        let state = NodeState {
            epoch: Some(9),
            grid: Some(GridPosition {
                slot: 5_000_000,
                batch: Some(2),
                next_slot: Some(5_021_600),
            }),
            dkg_qualified: Some(true),
            excluded_peers: vec!["spo=cd34: blueprint differs".into()],
            last_progress_ms: Some(1_700_000_000_000),
            activity: "waiting".into(),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<NodeState>(&json).unwrap(), state);
    }
}
