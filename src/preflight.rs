//! The daemon's startup gate (WI-053).
//!
//! `run-mover` used to call `load_config`, resolve each operator-supplied value,
//! and start working. The first sign that anything was wrong was a failed
//! transaction — or worse, no sign at all: a node missing any of the three Config
//! locator keys silently dropped to a wall-clock cadence instead of the protocol's
//! batch grid, which does not agree with the other SPOs, and nothing said so.
//!
//! This module runs eight checks in order and reports each one. It is the single
//! state reader behind the startup gate; `heimdall doctor` (WI-054) and
//! `heimdall status` (WI-058) are meant to render the same [`Report`] rather than
//! grow their own opinion of what "healthy" means, because three readers that can
//! disagree is worse than none.
//!
//! ## What it no longer checks
//!
//! There used to be a ninth step cross-checking each `[cardano]` contract
//! identifier against the Config UTxO. WI-070 deleted those keys, and the check
//! with them: heimdall derives every one of the identifiers from the Config now,
//! so there is no second copy to disagree. A check over values that no longer
//! exist would pass unconditionally and read as coverage. What survives is the
//! part that was never a check — step 3 NAMES the contracts it derived, because
//! which bridge this node resolved is something an operator has to be able to
//! see.
//!
//! ## It never spends
//!
//! Steps 4 and 6 discover and *report*. A missing reference script and an
//! unregistered SPO both name the exact command to run and stop. Deploying the
//! `spos_registry` reference script parks ~55 ADA and registering locks a security
//! deposit; neither belongs to a service start, however convenient. That rule is
//! binding on this module: no function here builds or submits a transaction.

use bitcoin::secp256k1::Secp256k1;

use crate::cardano::bf_http::{self, BfUtxo};
use crate::cardano::config_params::{ConfigView, config_view_from_utxo};
use crate::cardano::ref_script::RefScriptUtxo;
use crate::config::HeimdallConfig;

/// Outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    /// Something is wrong but the daemon can still run correctly enough to start.
    /// Used where failing would break a deployment that is merely unusual, not
    /// broken — see `state_dir` in step 1.
    Warn,
    /// Startup must not continue.
    Fail,
    /// Not applicable, or an earlier step did not produce what this one needs.
    Skipped,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Skipped => "SKIP",
        }
    }
}

/// One check's result, plus how to fix it when it did not pass.
#[derive(Debug, Clone)]
pub struct Step {
    pub n: u8,
    pub title: &'static str,
    pub status: Status,
    /// What was actually found — the value, the count, the endpoint.
    pub detail: String,
    /// Values this step resolved, one per line, when there are too many to fit in
    /// `detail`. Not a diagnosis: step 3 lists the contract addresses it derived
    /// from the Config, which is the only place an operator ever sees which
    /// bridge this node is on.
    pub notes: Vec<String>,
    /// The exact command or config key that resolves this. Never a suggestion to
    /// "check your configuration".
    pub fix: Option<String>,
}

/// The whole preflight, in the order the steps ran.
#[derive(Debug, Clone)]
pub struct Report {
    pub steps: Vec<Step>,
}

impl Report {
    /// True when nothing failed. `Warn` does not block startup; `Fail` does.
    #[must_use]
    pub fn ok(&self) -> bool {
        !self.steps.iter().any(|s| s.status == Status::Fail)
    }

    /// The first failure, for a one-line abort message.
    #[must_use]
    pub fn first_failure(&self) -> Option<&Step> {
        self.steps.iter().find(|s| s.status == Status::Fail)
    }

    /// Human-readable, one line per step plus an indented fix under any step that
    /// has one. Stable enough to paste into a bug report.
    #[must_use]
    pub fn render(&self) -> String {
        let total = self.steps.len();
        let mut out = String::new();
        for s in &self.steps {
            out.push_str(&format!(
                "[{}/{total}] {:<28} {}  {}\n",
                s.n,
                s.title,
                s.status.label(),
                s.detail
            ));
            for line in &s.notes {
                out.push_str(&format!("            {line}\n"));
            }
            if let Some(fix) = &s.fix {
                for line in fix.lines() {
                    out.push_str(&format!("         -> {line}\n"));
                }
            }
        }
        out
    }
}

struct Builder {
    steps: Vec<Step>,
}

impl Builder {
    fn push(&mut self, n: u8, title: &'static str, status: Status, detail: impl Into<String>) {
        self.steps.push(Step {
            n,
            title,
            status,
            detail: detail.into(),
            notes: Vec::new(),
            fix: None,
        });
    }

    fn push_notes(
        &mut self,
        n: u8,
        title: &'static str,
        status: Status,
        detail: impl Into<String>,
        notes: Vec<String>,
    ) {
        self.steps.push(Step {
            n,
            title,
            status,
            detail: detail.into(),
            notes,
            fix: None,
        });
    }

    fn push_fix(
        &mut self,
        n: u8,
        title: &'static str,
        status: Status,
        detail: impl Into<String>,
        fix: impl Into<String>,
    ) {
        self.steps.push(Step {
            n,
            title,
            status,
            detail: detail.into(),
            notes: Vec::new(),
            fix: Some(fix.into()),
        });
    }
}

/// The three `[cardano]` keys that together locate the Config UTxO. Missing any
/// one of them is what makes `config_locator` return `None`, which is what drops
/// the mover onto a wall-clock cadence.
fn missing_locator_keys(cfg: &HeimdallConfig) -> Vec<&'static str> {
    let c = &cfg.cardano;
    let mut missing = Vec::new();
    if c.blockfrost_project_id.is_none() {
        missing.push("cardano.blockfrost_project_id");
    }
    if c.config_address.is_none() {
        missing.push("cardano.config_address");
    }
    if c.config_nft_policy_id.is_none() {
        missing.push("cardano.config_nft_policy_id");
    }
    missing
}

/// Whether a wallet mnemonic is reachable, and from where.
///
/// Mirrors the binary's precedence exactly — `cardano.mnemonic` wins over
/// `$HEIMDALL_MNEMONIC` — because reporting a different source than the one the
/// daemon will actually use is worse than not reporting at all.
fn mnemonic_source(cfg: &HeimdallConfig) -> Option<&'static str> {
    if cfg.cardano.mnemonic.is_some() {
        return Some("cardano.mnemonic");
    }
    match std::env::var("HEIMDALL_MNEMONIC") {
        Ok(v) if !v.trim().is_empty() => Some("$HEIMDALL_MNEMONIC"),
        _ => None,
    }
}

/// Locate the Config UTxO and require it to be **unique**.
///
/// `config_params::find_config_utxo` takes the first match, which is right on the
/// hot batch path where a decision has to be made every poll. At startup the
/// stricter rule applies: two UTxOs answering to the same Config NFT means the
/// deployment is ambiguous, and picking one silently is how a node ends up reading
/// a different bridge than its peers.
fn find_unique_config_utxo<'a>(utxos: &'a [BfUtxo], nft_unit: &str) -> Result<&'a BfUtxo, String> {
    let matches: Vec<&BfUtxo> = utxos
        .iter()
        .filter(|u| u.inline_datum.is_some() && u.amount.iter().any(|a| a.unit == nft_unit))
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(format!(
            "no UTxO carries Config NFT {nft_unit} with an inline datum"
        )),
        n => Err(format!(
            "{n} UTxOs carry Config NFT {nft_unit} ({}) — the Config must be a singleton",
            matches
                .iter()
                .map(|u| format!("{}#{}", u.tx_hash, u.output_index))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Run every check, in order, and collect the results.
///
/// Always runs to the end: a step whose input is missing records `Skipped` with
/// the reason rather than short-circuiting, so one run always produces the whole
/// picture. Deciding what to do about a `Fail` is the caller's job — the startup
/// gate aborts, `heimdall doctor` prints and exits non-zero.
pub async fn preflight(cfg: &HeimdallConfig) -> Report {
    let mut b = Builder { steps: Vec::new() };

    // ── 1. Local preflight ────────────────────────────────────────────────
    // Cheapest checks, worst failures if deferred: everything below needs the
    // network, and a missing key only shows up when something is being signed.
    {
        let mut notes = Vec::new();
        let mut problems = Vec::new();

        match mnemonic_source(cfg) {
            Some(src) => notes.push(format!("mnemonic from {src}")),
            None => problems.push(
                "no wallet mnemonic: set cardano.mnemonic or $HEIMDALL_MNEMONIC \
                 (/etc/default/heimdall in the Debian package)"
                    .to_string(),
            ),
        }

        match &cfg.bifrost.skey_path {
            Some(p) => {
                let secp = Secp256k1::new();
                match cfg.load_bifrost_keypair(&secp) {
                    Ok(_) => notes.push(format!("bifrost identity key {p}")),
                    // Configured-but-unloadable is a real fault (wrong path, or
                    // the 0600 check failed). Unconfigured is merely a node that
                    // does not take part in DKG.
                    Err(e) => problems.push(format!("[bifrost].skey_path {p}: {e}")),
                }
            }
            None => notes.push("no bifrost identity key (DKG participation disabled)".to_string()),
        }

        if let Some(bp) = &cfg.cardano.registry_blueprint {
            if std::fs::metadata(bp).is_err() {
                problems.push(format!("cardano.registry_blueprint {bp}: not readable"));
            } else {
                notes.push(format!("blueprint {bp}"));
            }
        }

        let state_dir_warning = match &cfg.protocol.state_dir {
            Some(d) => {
                notes.push(format!("state_dir {d}"));
                None
            }
            // Not fatal: deployments predating WI-014 persistence run without it.
            // But unset means the completed-peg-outs trie is rebuilt EMPTY on every
            // start, which is only correct on a bridge that has completed no
            // peg-outs — on any other it re-pays them.
            None => Some(
                "protocol.state_dir is unset: the DKG share is memory-only and the \
                 completed-peg-outs trie is rebuilt empty on every start"
                    .to_string(),
            ),
        };

        if problems.is_empty() {
            let (status, warn) = match &state_dir_warning {
                Some(w) => (Status::Warn, Some(w.clone())),
                None => (Status::Pass, None),
            };
            match warn {
                Some(w) => b.push_fix(1, "local preflight", status, notes.join("; "), w),
                None => b.push(1, "local preflight", status, notes.join("; ")),
            }
        } else {
            // The detail line summarises; the fix lines carry the problems. Putting
            // the benign notes in `detail` here would print a FAIL whose one visible
            // line reads like everything is fine.
            b.push_fix(
                1,
                "local preflight",
                Status::Fail,
                format!(
                    "{} problem{}",
                    problems.len(),
                    if problems.len() == 1 { "" } else { "s" }
                ),
                problems.join("\n"),
            );
        }
    }

    // ── 2. Cardano connectivity ───────────────────────────────────────────
    let Some(project_id) = cfg.cardano.blockfrost_project_id.clone() else {
        b.push_fix(
            2,
            "cardano connectivity",
            Status::Fail,
            "no provider configured",
            "set cardano.blockfrost_project_id",
        );
        // Every step this early return skips, so the report is always the whole
        // picture and `render`'s "[n/total]" counts what it printed. Steps 7 and 8
        // used to be missing here and step 6 carried step 7's title.
        for (n, title) in [
            (3u8, "resolve the Config"),
            (4, "reference script"),
            (5, "ban list"),
            (6, "registration status"),
            (7, "key handoff (Update-Y)"),
            (8, "federation identity"),
        ] {
            b.push(n, title, Status::Skipped, "needs a Cardano provider");
        }
        return Report { steps: b.steps };
    };
    let base_url = bf_http::base_url(&project_id, cfg.cardano.blockfrost_url.as_deref());
    let epoch = match bf_http::fetch_current_epoch(&base_url, &project_id).await {
        Ok(e) => {
            b.push(
                2,
                "cardano connectivity",
                Status::Pass,
                format!("{base_url} answering, epoch {e}"),
            );
            Some(e)
        }
        Err(e) => {
            b.push_fix(
                2,
                "cardano connectivity",
                Status::Fail,
                format!("{base_url}: {e}"),
                "check cardano.blockfrost_project_id / cardano.blockfrost_url and network access",
            );
            None
        }
    };

    // ── 3. Resolve the Config ─────────────────────────────────────────────
    // Not "check the policy id is set" — derive the address, find the singleton
    // UTxO holding the token, read the datum. This is what makes the config file
    // shrinkable, and it is FATAL: a node that cannot read the Config cannot agree
    // with its peers about the batch grid or the fee rate, and running anyway is
    // how two SPOs sign different bytes.
    let missing = missing_locator_keys(cfg);
    let config: Option<ConfigView> =
        if epoch.is_none() {
            b.push(
                3,
                "resolve the Config",
                Status::Skipped,
                "provider unreachable",
            );
            None
        } else if !missing.is_empty() {
            b.push_fix(
                3,
                "resolve the Config",
                Status::Fail,
                format!("not configured: {} unset", missing.join(", ")),
                format!(
                    "set {} in heimdall.toml — without all of them the mover cannot see the \
                 protocol batch grid and falls back to a wall-clock cadence, which does not \
                 agree with the other SPOs",
                    missing.join(", ")
                ),
            );
            None
        } else {
            let address = cfg.cardano.config_address.clone().unwrap_or_default();
            let nft_unit = format!(
                "{}{}",
                cfg.cardano.config_nft_policy_id.clone().unwrap_or_default(),
                cfg.cardano.config_nft_asset_name.as_deref().unwrap_or("")
            );
            match bf_http::fetch_address_utxos(&base_url, &project_id, &address).await {
                Err(e) => {
                    b.push_fix(
                        3,
                        "resolve the Config",
                        Status::Fail,
                        format!("UTxO query at {address}: {e}"),
                        "check cardano.config_address and provider access",
                    );
                    None
                }
                Ok(utxos) => {
                    match find_unique_config_utxo(&utxos, &nft_unit) {
                        Err(e) => {
                            b.push_fix(
                                3,
                                "resolve the Config",
                                Status::Fail,
                                format!("{e} at {address}"),
                                "check cardano.config_address, cardano.config_nft_policy_id and \
                         cardano.config_nft_asset_name against the bridge's deployment notes",
                            );
                            None
                        }
                        Ok(utxo) => match config_view_from_utxo(utxo) {
                            Err(e) => {
                                b.push_fix(
                            3,
                            "resolve the Config",
                            Status::Fail,
                            format!("Config datum: {e}"),
                            "the located UTxO does not decode as a Config datum — check the \
                             NFT policy id points at this bridge's Config",
                        );
                                None
                            }
                            // The report NAMES the contracts it derived. Since WI-070
                            // there is no local copy left to cross-check them against —
                            // and no check that could stand in for showing an operator,
                            // on a fresh install, which bridge this node just resolved.
                            Ok(view) => match cfg.cardano.is_mainnet() {
                                Err(e) => {
                                    b.push_fix(3, "resolve the Config", Status::Fail, e,
                                "every address this node derives from the Config — the peg-in \
                                 and peg-out scripts, the TM validator, the registry, the ban \
                                 list — carries this network's tag, and the wrong one resolves \
                                 to a valid-looking address holding nothing");
                                    None
                                }
                                Ok(mainnet) => {
                                    let c = view.params.bridge_contracts(mainnet);
                                    b.push_notes(
                                        3,
                                        "resolve the Config",
                                        Status::Pass,
                                        format!(
                                            "{} ({} fields, fee_rate {} sat/vB)",
                                            view.utxo,
                                            view.params.field_count,
                                            view.params.tunables.fee_rate_sat_per_vb
                                        ),
                                        vec![
                                            format!("peg-in    {}", c.pegin_script_address),
                                            format!("peg-out   {}", c.pegout_script_address),
                                            format!("TM        {}", c.tm_address),
                                            format!("fBTC      {}", c.bridged_token_unit),
                                            format!(
                                                "bridge state policy {}",
                                                c.bridge_state_policy_id
                                            ),
                                        ],
                                    );
                                    Some(view)
                                }
                            },
                        },
                    }
                }
            }
        };

    // ── 4. Reference script — discover and report, never deploy ───────────
    // `resolve` returns None only when there is no Config to read the registry
    // identity (#11-#13) from — the fixture-roster deployment, which legitimately
    // has no reference script — and an error when a locally compiled
    // `treasury_info` contradicts the published #12.
    //
    // NOT a startup gate. The registry reference script is what `register-spo`
    // spends against; a running daemon reads the roster from UTxOs and never
    // needs it. Failing here would exit(1) a packaged daemon on a bridge whose
    // Config publishes the registry identity — exactly the deployment WI-068
    // exists to make configuration-free — and systemd would crash-loop it.
    let registry = crate::cardano::roster::RegistryRosterSource::resolve(
        &cfg.cardano,
        config.as_ref().map(|v| &v.params),
    );
    match &registry {
        Ok(None) => b.push(
            4,
            "reference script",
            Status::Skipped,
            "no on-chain registry configured (fixture roster)",
        ),
        Err(e) => b.push_fix(
            4,
            "reference script",
            Status::Fail,
            format!("cannot derive the registry script: {e}"),
            "the registry identity comes from the bridge Config (#11-#13) and needs no keys \
             of its own. This is the one thing that can still disagree: cardano.registry_blueprint \
             compiles a treasury_info script whose hash must equal the published #12. Point it \
             at the blueprint this bridge was deployed from, or unset it — a node without one \
             still reads the roster and signs, it just cannot perform the Update-Y handoff",
        ),
        Ok(Some(src)) => {
            let hash = &src.registry_policy_hex;
            match wallet_ref_script(cfg, &base_url, &project_id, hash).await {
                Err(e) => b.push(4, "reference script", Status::Warn, e),
                Ok(Some(r)) => b.push(
                    4,
                    "reference script",
                    Status::Pass,
                    format!("registry script {hash} deployed at {r}"),
                ),
                Ok(None) => b.push_fix(
                    4,
                    "reference script",
                    Status::Warn,
                    format!("registry script {hash} is not deployed at this wallet"),
                    "only needed to REGISTER — the daemon reads the roster without it, and \
                     step 6 below says whether this node is already registered. To deploy it \
                     you need the compiled script, so this one command still takes the \
                     blueprint and the bootstrap outref:\n\
                     heimdall deploy-registry-ref --config <file> --blueprint <plutus.json> \
                     --registry-bootstrap <txid:ix> --submit\n\
                     (~55 ADA, reclaimable — the daemon will not spend this for you)",
                ),
            }
        }
    }

    // ── 5. Ban list — consensus-relevant, so its absence is a failure ─────
    // The eligible roster is the registry MINUS active bans, so two nodes that
    // disagree about whether the list is read enumerate different participant
    // sets and their DKG cannot converge — invisible from either node's own
    // log. `BanListSource::from_config` refuses that combination (WI-060);
    // surface it here so it is caught before the service is ever enabled,
    // rather than at the next epoch boundary.
    match &registry {
        Ok(None) | Err(_) => b.push(
            5,
            "ban list",
            Status::Skipped,
            "no on-chain registry configured (fixture roster)",
        ),
        Ok(Some(_)) => match crate::cardano::ban_list::BanListSource::resolve(
            &cfg.cardano,
            config.as_ref().map(|v| &v.params),
        ) {
            Ok(Some(src)) => {
                // Ask the enforcement half itself rather than inferring from one
                // of its keys: a half-configured publish path answers
                // `Err` here, which the daemon exits on, and reporting it as
                // "enforcement configured" would hide exactly that.
                let enforcement = crate::cardano::blockfrost_chain::DkgFaultBanFlow::from_config(
                    &cfg.cardano,
                    config.as_ref().map(|v| &v.params),
                );
                let (status, enforcement_note) = match &enforcement {
                    Ok(Some(_)) => (Status::Pass, "fault enforcement configured".to_string()),
                    Ok(None) => (
                        Status::Pass,
                        "detection only — faults excluded, not published".to_string(),
                    ),
                    Err(e) => (
                        Status::Fail,
                        format!("fault enforcement half-configured: {e}"),
                    ),
                };
                b.push(
                    5,
                    "ban list",
                    status,
                    format!(
                        "roster is ban-filtered against {} — {} ({enforcement_note})",
                        src.ban_address, src.origin,
                    ),
                );
            }
            Ok(None) => b.push_fix(
                5,
                "ban list",
                Status::Fail,
                "the registry roster is configured but no ban list resolved".to_string(),
                "this bridge's Config publishes no ban policy at #7 — point \
                 cardano.config_address at a bridge that does. There is no local route any \
                 more: the schedule the ban policy id is derived from lives only in the Config",
            ),
            Err(e) => b.push_fix(
                5,
                "ban list",
                Status::Fail,
                format!("cannot derive the ban list: {e}"),
                "the eligible roster is the registry MINUS active bans — a node that cannot \
                 read the list computes a different DKG participant set from one that can.\n\
                 A bridge whose Config publishes the ban policy (#7) needs NO ban keys here; \
                 otherwise:\n\
                 heimdall bootstrap-ban-list --config <file> ... --submit  (once per bridge)",
            ),
        },
    }

    // ── 6. Registration status — report, never register ───────────────────
    let bifrost_pk = {
        let secp = Secp256k1::new();
        cfg.load_bifrost_keypair(&secp)
            .ok()
            .map(|kp| kp.x_only_public_key().0.serialize())
    };
    // ONE read serves steps 6 and 8: the snapshot carries both the registered SPO
    // set and the `treasury_info` datum the federation identity lives in. Fetched
    // here rather than inside step 6 because step 8 needs it even on a node with
    // no bifrost key, and asking twice invites the two steps to see different
    // chain states.
    let snapshot = match &registry {
        Ok(Some(src)) => Some(src.fetch_snapshot(&base_url, &project_id).await),
        _ => None,
    };

    match (&snapshot, bifrost_pk) {
        (None, _) => b.push(
            6,
            "registration status",
            Status::Skipped,
            "no usable on-chain registry (step 4)",
        ),
        (Some(_), None) => b.push(
            6,
            "registration status",
            Status::Skipped,
            "no [bifrost].skey_path — cannot tell which registry entry is ours",
        ),
        (Some(read), Some(pk)) => match read {
            Err(e) => b.push_fix(
                6,
                "registration status",
                Status::Fail,
                format!("registry unreadable: {e}"),
                "the registry or its treasury_info state could not be read or verified at \
                 the addresses the Config publishes (#11-#13) — check cardano.config_address \
                 points at this bridge, and cardano.network at its network",
            ),
            Ok(snapshot) => {
                if snapshot.spos.iter().any(|s| s.bifrost_id_pk == pk) {
                    b.push(
                        6,
                        "registration status",
                        Status::Pass,
                        format!(
                            "registered as {} ({} SPOs in the registry)",
                            hex::encode(pk),
                            snapshot.spos.len()
                        ),
                    );
                } else {
                    b.push_fix(
                        6,
                        "registration status",
                        Status::Fail,
                        format!(
                            "bifrost_id_pk {} is not among the {} registered SPOs",
                            hex::encode(pk),
                            snapshot.spos.len()
                        ),
                        "heimdall register-spo --config <file> --blueprint <plutus.json> \
                         --registry-bootstrap <txid:ix> --treasury-nft-name <hex> \
                         --cold-skey <pool-cold.skey> --bifrost-skey <bifrost.skey> \
                         --bifrost-url http://<host>:<port> --submit\n\
                         (run it without --submit first — it prints the transaction and stops. \
                         The registry reference script it needs is found automatically once \
                         deploy-registry-ref has put one at this wallet; see step 4.)\n\
                         Locks a security deposit — the daemon will not do this for you.",
                    );
                }
            }
        },
    }

    // ── 7. Key handoff (Update-Y) — a capability, reported not assumed ────
    // A completed DKG only becomes consequential when `treasury_info` is rotated
    // to the new group key, and SPENDING that state UTxO needs the compiled
    // script — not just the policy id the Config publishes at #12. Reading the
    // roster does not, so this is the one thing a fully published-route node
    // still cannot do, and the one thing whose absence is invisible until it
    // costs a whole ceremony: the leader fails at submission AFTER a full DKG and
    // a distributed FROST authorization, and repeats that every cycle.
    //
    // A Warn, not a Fail: this node still runs and signs, and whether it is ever
    // elected leader depends on the roster. Failing here would exit(1) a daemon
    // that participates correctly.
    match &registry {
        Ok(None) | Err(_) => b.push(
            7,
            "key handoff (Update-Y)",
            Status::Skipped,
            "no on-chain registry configured (fixture roster)",
        ),
        Ok(Some(src)) if src.can_hand_off_key() => b.push(
            7,
            "key handoff (Update-Y)",
            Status::Pass,
            format!(
                "treasury_info {} is compiled locally — this node can rotate the group key",
                src.treasury_info_policy_hex
            ),
        ),
        Ok(Some(_)) => b.push_fix(
            7,
            "key handoff (Update-Y)",
            Status::Warn,
            "no compiled treasury_info script — if this node is elected leader the \
             Update-Y fails after a full DKG and the treasury is not handed over",
            "set cardano.registry_blueprint to the plutus.json this bridge was deployed from. \
             It is the ONLY thing needed — treasury_info's one parameter is the registry policy \
             the Config publishes at #11 — and the derived hash is checked against #12, so a \
             wrong blueprint is refused rather than used",
        ),
    }

    // ── 8. Federation identity — the treasury's own address (WI-069) ──────
    // A Fail, unlike steps 4 and 7: this is not a capability the node can do
    // without. Y_fed and the CSV delay are what the treasury scriptPubKey is
    // built from, so a node that cannot resolve them — or whose local seed
    // contradicts what the chain publishes — would sign for an address no other
    // SPO is using, and produce nothing resembling an error while doing it.
    //
    // The published copy is the `treasury_info` datum read above, NOT a separate
    // fetch: a step that reports the identity healthy must be looking at the
    // bytes the mover will actually build the tree from. A failed read stays a
    // failure — never silently "the bridge publishes nothing", which would take
    // the local seed and reintroduce the divergence this replaces.
    match &snapshot {
        Some(Err(e)) => b.push_fix(
            8,
            "federation identity",
            Status::Fail,
            format!("treasury_info unreadable, so the treasury address cannot be derived: {e}"),
            "this is the same read step 6 failed on — fix that first",
        ),
        published => {
            let datum = published
                .as_ref()
                .and_then(|r| r.as_ref().ok())
                .map(|s| &s.treasury_state.datum);
            match crate::cardano::federation::resolve(&cfg.bitcoin, datum) {
                Ok(id) => b.push(
                    8,
                    "federation identity",
                    Status::Pass,
                    format!(
                        "Y_fed {}, csv {} blocks — {}",
                        hex::encode(id.y_fed.serialize()),
                        id.csv_blocks,
                        id.origin
                    ),
                ),
                Err(e) => b.push_fix(
                    8,
                    "federation identity",
                    Status::Fail,
                    e.to_string(),
                    e.fix(),
                ),
            }
        }
    }

    Report { steps: b.steps }
}

/// Look for the registry reference script at the operator's own wallet address —
/// `deploy-registry-ref` key-locks it there so it stays reclaimable.
///
/// The lookup itself lives in [`crate::cardano::ref_script`] because `register-spo`
/// performs the same one to build its transaction (WI-056): a step that reports the
/// reference script healthy must be looking at the UTxO the transaction will
/// actually reference.
async fn wallet_ref_script(
    cfg: &HeimdallConfig,
    base_url: &str,
    project_id: &str,
    script_hash: &str,
) -> Result<Option<RefScriptUtxo>, String> {
    let Some(src) = mnemonic_source(cfg) else {
        return Err("no wallet mnemonic — cannot locate the reference script".into());
    };
    let mnemonic = match src {
        "cardano.mnemonic" => cfg.cardano.mnemonic.clone().unwrap_or_default(),
        _ => std::env::var("HEIMDALL_MNEMONIC").unwrap_or_default(),
    };
    let addr = crate::cardano::wallet::wallet_address_from_mnemonic(&mnemonic)
        .map_err(|e| format!("derive wallet address: {e}"))?;
    crate::cardano::ref_script::wallet_ref_script(base_url, project_id, &addr, script_hash).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HeimdallConfig;

    #[test]
    fn every_locator_key_is_reported_when_none_are_set() {
        let cfg = HeimdallConfig::default();
        assert_eq!(
            missing_locator_keys(&cfg),
            vec![
                "cardano.blockfrost_project_id",
                "cardano.config_address",
                "cardano.config_nft_policy_id"
            ]
        );
    }

    #[test]
    fn a_partially_configured_locator_still_fails() {
        // The exact shape that used to degrade silently: two of three set, so the
        // node looks configured and runs on a wall-clock cadence.
        let mut cfg = HeimdallConfig::default();
        cfg.cardano.blockfrost_project_id = Some("preprodXXX".into());
        cfg.cardano.config_address = Some("addr_test1...".into());
        assert_eq!(
            missing_locator_keys(&cfg),
            vec!["cardano.config_nft_policy_id"]
        );
    }

    fn utxo_with(unit: &str, tx: &str, datum: bool) -> BfUtxo {
        BfUtxo {
            tx_hash: tx.into(),
            output_index: 0,
            amount: vec![crate::cardano::bf_http::BfAmount {
                unit: unit.into(),
                quantity: "1".into(),
            }],
            inline_datum: datum.then(|| "d8799f".to_string()),
            reference_script_hash: None,
        }
    }

    #[test]
    fn two_config_utxos_are_refused_rather_than_picked_between() {
        let utxos = vec![
            utxo_with("polNFT", &"aa".repeat(32), true),
            utxo_with("polNFT", &"bb".repeat(32), true),
        ];
        let err = find_unique_config_utxo(&utxos, "polNFT").unwrap_err();
        assert!(err.contains("2 UTxOs"), "{err}");
        assert!(err.contains("singleton"), "{err}");
    }

    #[test]
    fn one_config_utxo_resolves() {
        let utxos = vec![utxo_with("polNFT", &"aa".repeat(32), true)];
        assert!(find_unique_config_utxo(&utxos, "polNFT").is_ok());
    }

    fn step(n: u8, title: &'static str, status: Status) -> Step {
        Step {
            n,
            title,
            status,
            detail: String::new(),
            notes: Vec::new(),
            fix: None,
        }
    }

    #[test]
    fn a_report_with_a_failure_is_not_ok_but_a_warning_is() {
        let warn = Report {
            steps: vec![step(1, "local preflight", Status::Warn)],
        };
        assert!(warn.ok());
        let fail = Report {
            steps: vec![step(3, "resolve the Config", Status::Fail)],
        };
        assert!(!fail.ok());
        assert_eq!(fail.first_failure().map(|s| s.n), Some(3));
    }

    /// The no-provider early return must still account for EVERY step, because
    /// `render` derives its "[n/total]" from `steps.len()`. It used to push four
    /// (3,4,5,6) while nine exist, so adding a step made the last line read
    /// "[9/7]" — and its entry for 6 carried step 7's title, so the ban-list check
    /// was reported as "registration status". WI-070 dropped the contract-set
    /// cross-check, so there are eight.
    #[tokio::test]
    async fn the_no_provider_report_accounts_for_every_step() {
        let cfg = HeimdallConfig::default();
        assert!(
            cfg.cardano.blockfrost_project_id.is_none(),
            "fixture must take the no-provider path"
        );
        let report = preflight(&cfg).await;
        let numbers: Vec<u8> = report.steps.iter().map(|s| s.n).collect();
        assert_eq!(numbers, (1..=8).collect::<Vec<u8>>(), "{numbers:?}");
        // Every rendered line's step number is within the total it prints.
        let total = report.steps.len();
        assert_eq!(total, 8);
        for s in &report.steps {
            assert!(usize::from(s.n) <= total, "step {} of {total}", s.n);
        }
        // Titles line up with the steps the main path actually pushes.
        let titled: Vec<&str> = report.steps.iter().map(|s| s.title).collect();
        assert_eq!(titled[3], "reference script");
        assert_eq!(titled[4], "ban list");
        assert_eq!(titled[5], "registration status");
        assert_eq!(titled[7], "federation identity");
    }

    /// Step 3 is the only place an operator is told WHICH bridge this node
    /// resolved, now that nothing cross-checks a local copy of it.
    #[test]
    fn render_lists_the_resolved_contracts_under_their_step() {
        let r = Report {
            steps: vec![Step {
                notes: vec![
                    "peg-in    addr_test1wq808aas".into(),
                    "fBTC      aabbcc66534154".into(),
                ],
                ..step(3, "resolve the Config", Status::Pass)
            }],
        };
        let out = r.render();
        assert!(out.contains("peg-in    addr_test1wq808aas"), "{out}");
        assert!(out.contains("fBTC      aabbcc66534154"), "{out}");
        // Not marked as a fix — nothing here is broken.
        assert!(!out.contains("-> peg-in"), "{out}");
    }

    #[test]
    fn render_shows_the_fix_under_its_step() {
        let r = Report {
            steps: vec![Step {
                detail: "not deployed".into(),
                fix: Some("heimdall deploy-registry-ref ...".into()),
                ..step(4, "reference script", Status::Fail)
            }],
        };
        let out = r.render();
        assert!(out.contains("FAIL"));
        assert!(out.contains("-> heimdall deploy-registry-ref"));
    }
}
