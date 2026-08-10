//! The daemon's startup gate (WI-053).
//!
//! `run-mover` used to call `load_config`, resolve each operator-supplied value,
//! and start working. The first sign that anything was wrong was a failed
//! transaction — or worse, no sign at all: a node missing any of the three Config
//! locator keys silently dropped to a wall-clock cadence instead of the protocol's
//! batch grid, which does not agree with the other SPOs, and nothing said so.
//!
//! This module runs seven checks in order and reports each one. It is the single
//! state reader behind the startup gate; `heimdall doctor` (WI-054) and
//! `heimdall status` (WI-058) are meant to render the same [`Report`] rather than
//! grow their own opinion of what "healthy" means, because three readers that can
//! disagree is worse than none.
//!
//! ## It never spends
//!
//! Steps 5 and 7 discover and *report*. A missing reference script and an
//! unregistered SPO both name the exact command to run and stop. Deploying the
//! `spos_registry` reference script parks ~55 ADA and registering locks a security
//! deposit; neither belongs to a service start, however convenient. That rule is
//! binding on this module: no function here builds or submits a transaction.

use bitcoin::secp256k1::Secp256k1;

use crate::cardano::bf_http::{self, BfUtxo};
use crate::cardano::config_params::{ConfigView, Contracts, config_view_from_utxo};
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

/// One operator-supplied value that disagrees with the Config UTxO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// The `heimdall.toml` key holding the stale copy.
    pub key: &'static str,
    /// Which Config field is authoritative.
    pub config_field: &'static str,
    pub configured: String,
    pub on_chain: String,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: config file has {}, Config {} has {}",
            self.key, self.configured, self.config_field, self.on_chain
        )
    }
}

/// The payment credential of a Shelley script address, lower-hex.
fn address_script_hash(addr: &str) -> Option<String> {
    match pallas_addresses::Address::from_bech32(addr) {
        Ok(pallas_addresses::Address::Shelley(s)) => Some(hex::encode(s.payment().as_hash())),
        _ => None,
    }
}

/// Cross-check every operator-typed duplicate against the Config UTxO.
///
/// Only values the operator actually set are checked: an unset key is not a
/// disagreement, it is a value the daemon will take from the Config. Comparison
/// is case-insensitive because hex is written both ways in practice.
#[must_use]
pub fn contract_mismatches(cfg: &HeimdallConfig, on_chain: &Contracts) -> Vec<Mismatch> {
    let c = &cfg.cardano;
    let mut out = Vec::new();

    let mut check = |key, field, configured: Option<String>, expected: String| {
        if let Some(got) = configured
            && !got.eq_ignore_ascii_case(&expected)
        {
            {
                out.push(Mismatch {
                    key,
                    config_field: field,
                    configured: got,
                    on_chain: expected,
                });
            }
        }
    };

    check(
        "cardano.bridged_token_unit",
        "#0‖#1 (bridged_token)",
        c.bridged_token_unit.clone(),
        on_chain.bridged_token_unit(),
    );
    check(
        "cardano.pegin_policy_id",
        "#4 (peg_in_withdraw_script_hash)",
        c.pegin_policy_id.clone(),
        hex::encode(&on_chain.peg_in_script_hash),
    );
    check(
        "cardano.cpo_policy_id",
        "#3 (completed_peg_outs_merkle_tree_policy_id)",
        c.cpo_policy_id.clone(),
        hex::encode(&on_chain.completed_peg_outs_policy_id),
    );
    // Addresses carry the script hash in their payment credential. An address we
    // cannot decode is left alone rather than reported as a mismatch — that is a
    // malformed-address problem, and inventing a hash to compare against would
    // turn it into a confusing one.
    check(
        "cardano.pegin_script_address",
        "#4 (peg_in_withdraw_script_hash)",
        c.pegin_script_address
            .as_deref()
            .and_then(address_script_hash),
        hex::encode(&on_chain.peg_in_script_hash),
    );
    check(
        "cardano.pegout_script_address",
        "#5 (peg_out_withdraw_script_hash)",
        c.pegout_script_address
            .as_deref()
            .and_then(address_script_hash),
        hex::encode(&on_chain.peg_out_script_hash),
    );

    out
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
        for (n, title) in [
            (3u8, "resolve the Config"),
            (4, "verify the contract set"),
            (5, "reference script"),
            (6, "registration status"),
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
    let config: Option<ConfigView> = if epoch.is_none() {
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
            Ok(utxos) => match find_unique_config_utxo(&utxos, &nft_unit) {
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
                    Ok(view) => {
                        b.push(
                            3,
                            "resolve the Config",
                            Status::Pass,
                            format!(
                                "{} ({} fields, min_stake {})",
                                view.utxo, view.params.field_count, view.params.min_stake
                            ),
                        );
                        Some(view)
                    }
                },
            },
        }
    };

    // ── 4. Verify the derived contract set against reality ────────────────
    // The Config's contract identifiers are authoritative; everything in
    // `[cardano]` naming a contract is an operator-typed duplicate. Checking them
    // here is what makes those copies verified rather than trusted, and it catches
    // a stale copy on first run instead of at transaction time.
    match &config {
        None => b.push(
            4,
            "verify the contract set",
            Status::Skipped,
            "needs the Config from step 3",
        ),
        Some(view) => {
            let mismatches = contract_mismatches(cfg, &view.params.contracts);
            if mismatches.is_empty() {
                b.push(
                    4,
                    "verify the contract set",
                    Status::Pass,
                    "every configured contract identifier matches the Config UTxO",
                );
            } else {
                b.push_fix(
                    4,
                    "verify the contract set",
                    Status::Fail,
                    format!(
                        "{} identifier(s) disagree with the Config",
                        mismatches.len()
                    ),
                    mismatches
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
        }
    }

    // ── 5. Reference script — discover and report, never deploy ───────────
    // `from_config` returns None only when NONE of the registry keys are set (the
    // fixture-roster deployment, which legitimately has no reference script), and
    // an error when only some are — that half-configured state is a fault, not a
    // fixture.
    let registry = crate::cardano::roster::RegistryRosterSource::from_config(&cfg.cardano);
    match &registry {
        Ok(None) => b.push(
            5,
            "reference script",
            Status::Skipped,
            "no on-chain registry configured (fixture roster)",
        ),
        Err(e) => b.push_fix(
            5,
            "reference script",
            Status::Fail,
            format!("cannot derive the registry script: {e}"),
            "set all of cardano.registry_blueprint, cardano.registry_bootstrap and \
             cardano.treasury_info_asset_name — or none of them, for the fixture roster",
        ),
        Ok(Some(src)) => {
            let hash = &src.registry_policy_hex;
            match wallet_ref_script(cfg, &base_url, &project_id, hash).await {
                Err(e) => b.push(5, "reference script", Status::Fail, e),
                Ok(Some(r)) => b.push(
                    5,
                    "reference script",
                    Status::Pass,
                    format!("registry script {hash} deployed at {r}"),
                ),
                Ok(None) => b.push_fix(
                    5,
                    "reference script",
                    Status::Fail,
                    format!("registry script {hash} is not deployed at this wallet"),
                    "heimdall deploy-registry-ref --config <file> --blueprint <plutus.json> \
                     --registry-bootstrap <txid:ix> --submit\n\
                     (~55 ADA, reclaimable — the daemon will not spend this for you)",
                ),
            }
        }
    }

    // ── 6. Ban list — consensus-relevant, so its absence is a failure ─────
    // The eligible roster is the registry MINUS active bans, so two nodes that
    // disagree about whether the list is read enumerate different participant
    // sets and their DKG cannot converge — invisible from either node's own
    // log. `BanListSource::from_config` refuses that combination (WI-060);
    // surface it here so it is caught before the service is ever enabled,
    // rather than at the next epoch boundary.
    match &registry {
        Ok(None) | Err(_) => b.push(
            6,
            "ban list",
            Status::Skipped,
            "no on-chain registry configured (fixture roster)",
        ),
        Ok(Some(_)) => match crate::cardano::ban_list::BanListSource::from_config(&cfg.cardano) {
            Ok(Some(src)) => {
                let enforcing = cfg.cardano.fault_proof_srs_path.is_some();
                b.push(
                    6,
                    "ban list",
                    Status::Pass,
                    format!(
                        "roster is ban-filtered against {} ({})",
                        src.ban_address,
                        if enforcing {
                            "fault enforcement configured"
                        } else {
                            "detection only — faults excluded, not published"
                        }
                    ),
                );
            }
            Ok(None) => b.push_fix(
                6,
                "ban list",
                Status::Fail,
                "the registry roster is configured but no ban list resolved".to_string(),
                "set cardano.ban_bootstrap to the ban-list bootstrap outref",
            ),
            Err(e) => b.push_fix(
                6,
                "ban list",
                Status::Fail,
                format!("cannot derive the ban list: {e}"),
                "the eligible roster is the registry MINUS active bans — a node that cannot \
                 read the list computes a different DKG participant set from one that can.\n\
                 heimdall bootstrap-ban-list --config <file> ... --submit  (once per bridge)",
            ),
        },
    }

    // ── 7. Registration status — report, never register ───────────────────
    let bifrost_pk = {
        let secp = Secp256k1::new();
        cfg.load_bifrost_keypair(&secp)
            .ok()
            .map(|kp| kp.x_only_public_key().0.serialize())
    };
    match (&registry, bifrost_pk) {
        (Ok(None), _) | (Err(_), _) => b.push(
            7,
            "registration status",
            Status::Skipped,
            "no usable on-chain registry (step 5)",
        ),
        (Ok(Some(_)), None) => b.push(
            7,
            "registration status",
            Status::Skipped,
            "no [bifrost].skey_path — cannot tell which registry entry is ours",
        ),
        (Ok(Some(src)), Some(pk)) => match src.fetch_snapshot(&base_url, &project_id).await {
            Err(e) => b.push_fix(
                7,
                "registration status",
                Status::Fail,
                format!("registry unreadable: {e}"),
                "the registry or its treasury_info state could not be read or verified — \
                 check cardano.registry_bootstrap and cardano.treasury_info_asset_name",
            ),
            Ok(snapshot) => {
                if snapshot.spos.iter().any(|s| s.bifrost_id_pk == pk) {
                    b.push(
                        7,
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
                        7,
                        "registration status",
                        Status::Fail,
                        format!(
                            "bifrost_id_pk {} is not among the {} registered SPOs",
                            hex::encode(pk),
                            snapshot.spos.len()
                        ),
                        "heimdall register-spo --config <file> ... --submit\n\
                         (locks a security deposit — the daemon will not do this for you)",
                    );
                }
            }
        },
    }

    Report { steps: b.steps }
}

/// Look for the registry reference script at the operator's own wallet address —
/// `deploy-registry-ref` key-locks it there so it stays reclaimable.
async fn wallet_ref_script(
    cfg: &HeimdallConfig,
    base_url: &str,
    project_id: &str,
    script_hash: &str,
) -> Result<Option<String>, String> {
    let Some(src) = mnemonic_source(cfg) else {
        return Err("no wallet mnemonic — cannot locate the reference script".into());
    };
    let mnemonic = match src {
        "cardano.mnemonic" => cfg.cardano.mnemonic.clone().unwrap_or_default(),
        _ => std::env::var("HEIMDALL_MNEMONIC").unwrap_or_default(),
    };
    let addr = crate::cardano::wallet::wallet_address_from_mnemonic(&mnemonic)
        .map_err(|e| format!("derive wallet address: {e}"))?;
    let utxos = bf_http::fetch_address_utxos(base_url, project_id, &addr)
        .await
        .map_err(|e| format!("wallet UTxO query: {e}"))?;
    Ok(utxos
        .iter()
        .find(|u| {
            u.reference_script_hash
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(script_hash))
        })
        .map(|u| format!("{}#{}", u.tx_hash, u.output_index)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HeimdallConfig;

    fn contracts() -> Contracts {
        Contracts {
            bridged_token_policy_id: vec![0xAA; 28],
            bridged_token_asset_name: b"fBTC".to_vec(),
            completed_peg_ins_policy_id: vec![0xBB; 28],
            completed_peg_outs_policy_id: vec![0xCC; 28],
            peg_in_script_hash: vec![0xDD; 28],
            peg_out_script_hash: vec![0xEE; 28],
        }
    }

    #[test]
    fn an_unset_key_is_not_a_mismatch() {
        let cfg = HeimdallConfig::default();
        assert!(contract_mismatches(&cfg, &contracts()).is_empty());
    }

    #[test]
    fn a_matching_key_is_not_a_mismatch_whatever_its_case() {
        let mut cfg = HeimdallConfig::default();
        cfg.cardano.pegin_policy_id = Some(hex::encode(vec![0xDD; 28]).to_uppercase());
        cfg.cardano.bridged_token_unit = Some(contracts().bridged_token_unit());
        assert!(contract_mismatches(&cfg, &contracts()).is_empty());
    }

    #[test]
    fn a_stale_copy_is_reported_with_both_values() {
        let mut cfg = HeimdallConfig::default();
        cfg.cardano.pegin_policy_id = Some(hex::encode(vec![0x01; 28]));
        let m = contract_mismatches(&cfg, &contracts());
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].key, "cardano.pegin_policy_id");
        // Both sides must appear, or the operator cannot tell which to change.
        let rendered = m[0].to_string();
        assert!(rendered.contains(&hex::encode(vec![0x01; 28])));
        assert!(rendered.contains(&hex::encode(vec![0xDD; 28])));
    }

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

    #[test]
    fn a_report_with_a_failure_is_not_ok_but_a_warning_is() {
        let warn = Report {
            steps: vec![Step {
                n: 1,
                title: "local preflight",
                status: Status::Warn,
                detail: String::new(),
                fix: None,
            }],
        };
        assert!(warn.ok());
        let fail = Report {
            steps: vec![Step {
                n: 3,
                title: "resolve the Config",
                status: Status::Fail,
                detail: String::new(),
                fix: None,
            }],
        };
        assert!(!fail.ok());
        assert_eq!(fail.first_failure().map(|s| s.n), Some(3));
    }

    #[test]
    fn render_shows_the_fix_under_its_step() {
        let r = Report {
            steps: vec![Step {
                n: 5,
                title: "reference script",
                status: Status::Fail,
                detail: "not deployed".into(),
                fix: Some("heimdall deploy-registry-ref ...".into()),
            }],
        };
        let out = r.render();
        assert!(out.contains("FAIL"));
        assert!(out.contains("-> heimdall deploy-registry-ref"));
    }
}
