//! The bridge **Config** UTxO, read off-chain (spec §Operational parameters).
//!
//! The Config UTxO is the NFT-authenticated singleton at `config.ak` that carries
//! the bridge's wiring (script hashes, token identities) and — appended after
//! upstream's field #11 — the **operational parameters**: the tunables that no
//! Aiken validator reads and every off-chain consumer must agree on. They are
//! governance-updatable through an authorized Config `Update` (field #10,
//! `update_auth`).
//!
//! ## Why heimdall reads them here and not from `heimdall.toml`
//!
//! FROST aggregation requires every SPO to build **byte-identical** TM bytes. The
//! fee rate decides the treasury change amount, and the two floors (#13/#14) decide
//! the skip set — so a value that differs per operator makes the co-signers sign
//! different messages and the round simply cannot converge. Sourcing them from a
//! single on-chain UTxO is what makes them a consensus input rather than a local
//! opinion. The `bitcoin.fee_rate_sat_per_vb` / `bitcoin.per_pegout_fee_sat` config
//! keys survive only as the dev/offline override for the paths that have no
//! co-signers at all (see [`resolve_tm_params`]).
//!
//! ## The snapshot rule
//!
//! The spec's determinism rule is that consumers read the params **as of the
//! relevant TM batch's snapshot slot**, so "an update takes effect from the next
//! batch, never retroactively". [`fetch_param_snapshot`] implements that: it reads
//! the Cardano tip FIRST, then the Config UTxO, and accepts the pair only if the
//! Config UTxO was already on-chain at that tip. A Config Update that lands in the
//! middle of the read makes the batch's parameter set ambiguous — one SPO would see
//! the old datum and another the new one — so the snapshot is retaken rather than
//! guessed.
//!
//! The snapshot is currently the chain tip at the moment the batch is frozen. When
//! the batch grid lands (plan N19) the slot becomes a grid point and every SPO
//! reads the *same* slot; the seam is [`ParamSnapshot::slot`], not this decoder.
//!
//! ## Field numbering
//!
//! Indexes are the ones `bifrost/types/config.ak` pins with its
//! `config_getters_match_datum_fields` test. Positions are a frozen contract —
//! the datum evolves by APPENDING only — so a reader may safely decode a prefix
//! and ignore what it does not know:
//!
//! | # | field | read here |
//! |---|-------|-----------|
//! | 9 | `min_stake` (lovelace) | register-spo's R2 gate |
//! | 11 | `initial_btc_treasury_utxo` (36 bytes) | the TM chain's genesis anchor |
//! | 12 | `fee_rate_sat_per_vb` | TM miner fee |
//! | 13 | `per_pegout_fee` (floor) | TM skip rule |
//! | 14 | `min_peg_out_fbtc` | TM skip rule |
//! | 15 | `leader_reward` (lovelace) | pinned into the posted TM datum |
//! | 16 | `schedule` (`ScheduleParams`) | surfaced; consumed by the N19 batch grid |
//! | 17 | `spo_bans_policy_id` | the ban script address the roster is filtered against |
//! | 18–20 | ban schedule (`base_ban_duration_ms`, `max_faults_before_permanent`, `max_validity_window_ms`) | the ApplyBan builder |
//!
//! ## Why the ban policy id is PUBLISHED rather than derived (#17)
//!
//! Every other ban value an operator could type — the three schedule numbers, the
//! fault-verifier policy set, the bootstrap outref — is an *input* to the
//! `spo_bans` policy id, not an output of it. So a node cannot derive the address
//! it would read them from without already having them, and getting any one wrong
//! derives a ban address no deployment has: a silently EMPTY ban list, and banned
//! SPOs back in the roster with nothing in any log. Publishing the finished policy
//! id breaks that cycle — a reader trusts the authenticated Config exactly as it
//! already trusts the contract identifiers #0–#5, and needs no ban configuration
//! whatsoever. A node that *does* still carry the local keys (for enforcement)
//! cross-checks what it derives against #17 instead, so a stale copy is a startup
//! error rather than an empty list. |

use bitcoin::Amount;
use pallas_codec::minicbor;
use pallas_primitives::PlutusData;

use crate::bitcoin::tm_builder::TmParams;
use crate::cardano::bf_http::{self, BfUtxo};
use crate::cardano::plutus;
use crate::epoch::batch::{BatchWindow, GridParams};
use tracing::{info, warn};

/// Field count of a Config datum carrying the operational-parameter append
/// (#12–#16 on top of upstream's 12 fields, `initial_btc_treasury_utxo` last).
pub const CONFIG_FIELDS_WITH_TUNABLES: usize = 17;

/// Field count of a Config datum carrying the ban-policy append (#17–#20) on top
/// of the tunables.
pub const CONFIG_FIELDS_WITH_BANS: usize = 21;

/// Field count of the upstream Config before the tunables were appended.
const CONFIG_FIELDS_UPSTREAM: usize = 12;

/// Config #16 — the tunable protocol schedule, E-relative slot values (spec
/// §TM batches and the protocol schedule).
///
/// Off-chain readers only, and unlike every other tunable it takes effect from the
/// next EPOCH boundary rather than the next batch. heimdall decodes and reports it;
/// the batch grid that consumes it is plan N19 (`run-mover`'s interval is still a
/// local `--interval-secs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleParams {
    pub dkg_r1_deadline: i64,
    pub dkg_r2_deadline: i64,
    pub update_y_deadline: i64,
    pub tm_batch_interval: i64,
    pub sign_r1_window: i64,
    pub sign_r2_window: i64,
    pub leader_slot_t: i64,
    pub tm_recovery_window: i64,
    pub final_tm_cutoff: i64,
    pub stability_window: i64,
}

/// Config #12–#16 — the operational parameters, present together or not at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunables {
    /// #12, sat/vB. The EXACT miner fee rate, not an estimate.
    pub fee_rate_sat_per_vb: u64,
    /// #13, satoshi. Floor for a request's own datum-pinned `per_pegout_fee`.
    pub per_pegout_fee_floor: u64,
    /// #14, satoshi. Minimum fBTC a PegOut request may lock.
    pub min_peg_out_fbtc: u64,
    /// #15, lovelace. Copied into the TM record datum at post time.
    pub leader_reward: u64,
    /// #16.
    pub schedule: ScheduleParams,
}

/// Config #17–#20 — the ban policy, published so no SPO has to configure one.
///
/// Split by who needs what: #17 alone serves the MANDATORY read half (the roster
/// is the registry minus active bans, so every node must read the same list), and
/// #18–#20 serve the optional enforcement half — `apply_ban` computes a ban's end
/// time from #18/#19 and bounds the ApplyBan validity interval by #20.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanParams {
    /// #17. The `spo_bans` policy id; the ban script address follows from it, so
    /// this one field is the whole read half.
    pub spo_bans_policy_id: [u8; 28],
    /// #18, milliseconds. `base_ban_duration_ms * 2^(n-1)` is the nth ban's length.
    pub base_ban_duration_ms: i64,
    /// #19. A pool is banned permanently at this many faults.
    pub max_faults_before_permanent: i64,
    /// #20, milliseconds. Upper bound on an ApplyBan tx's validity interval.
    pub max_validity_window_ms: i64,
}

/// Config #0–#5 — the bridge's contract identifiers.
///
/// These are the AUTHORITATIVE copies. Everything heimdall carries in its own
/// `[cardano]` section — `bridged_token_unit`, `pegin_policy_id`,
/// `pegin_script_address`, `pegout_script_address`, `cpo_policy_id` — is an
/// operator-typed duplicate of one of them, which is exactly the kind of copy
/// that goes stale after a redeploy and is discovered at transaction time. The
/// startup gate (WI-053 step 4) cross-checks the duplicates against these, so a
/// wrong one is caught on first run instead.
///
/// Present in every Config version: they are upstream fields #0–#5, and the datum
/// only ever grows by appending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contracts {
    /// #0
    pub bridged_token_policy_id: Vec<u8>,
    /// #1
    pub bridged_token_asset_name: Vec<u8>,
    /// #2
    pub completed_peg_ins_policy_id: Vec<u8>,
    /// #3
    pub completed_peg_outs_policy_id: Vec<u8>,
    /// #4. One Aiken validator serves `mint`, `withdraw` and `spend`, so this
    /// single hash is both heimdall's `pegin_policy_id` and the payment
    /// credential of `pegin_script_address`.
    pub peg_in_script_hash: Vec<u8>,
    /// #5. Likewise the payment credential of `pegout_script_address`.
    pub peg_out_script_hash: Vec<u8>,
}

impl Contracts {
    /// The bridged token's `unit` as Blockfrost spells it: policy id ‖ asset name.
    #[must_use]
    pub fn bridged_token_unit(&self) -> String {
        format!(
            "{}{}",
            hex::encode(&self.bridged_token_policy_id),
            hex::encode(&self.bridged_token_asset_name)
        )
    }
}

/// The Config datum as heimdall reads it: the fields it consumes, plus the raw
/// field count that decided whether the tunables were there to consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigParams {
    /// Number of fields in the deployed datum (the append-only version marker).
    pub field_count: usize,
    /// #0–#5 — the contract identifiers the operator's config duplicates.
    pub contracts: Contracts,
    /// #9 — the DKG candidate-set stake threshold (lovelace).
    pub min_stake: u64,
    /// #11 — the anchor outpoint the first TM must spend: txid (internal byte
    /// order) ‖ vout (4-byte LE). `None` on a Config older than the anchor field.
    pub initial_btc_treasury_utxo: Option<[u8; 36]>,
    /// #12–#16, or `None` on a Config that predates the append.
    pub tunables: Option<Tunables>,
    /// #17–#20, or `None` on a Config that predates the ban append — on which a
    /// node falls back to its local `[cardano]` ban keys.
    pub bans: Option<BanParams>,
}

/// Which Config UTxO a [`ConfigParams`] was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigUtxoRef {
    pub tx_hash: String,
    pub index: u32,
}

impl std::fmt::Display for ConfigUtxoRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.tx_hash, self.index)
    }
}

/// A Config read: the decoded params and the UTxO they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigView {
    pub params: ConfigParams,
    pub utxo: ConfigUtxoRef,
}

/// The parameter state a TM batch is built against — the Config read, pinned to
/// the chain point it was read at.
#[derive(Debug, Clone)]
pub struct ParamSnapshot {
    /// Cardano tip slot at the read. Every value below is "as of" this slot.
    pub slot: u64,
    /// Cardano tip block time, POSIX **milliseconds** — the consensus "now" the
    /// peg-out freshness filter must use (never the local clock).
    pub time_ms: i64,
    pub config: ConfigView,
    /// Block time (POSIX ms) of the transaction that created the Config UTxO, when
    /// the backend could report it. `None` means the ordering check was skipped —
    /// see [`fetch_param_snapshot`].
    pub config_created_ms: Option<i64>,
}

/// Where the TM parameters in force actually came from. Carried into logs so a
/// node running on the dev override is never mistaken for one reading the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamSource {
    /// The Config UTxO's operational parameters, as of `slot`.
    Config { utxo: ConfigUtxoRef, slot: u64 },
    /// The node's own `heimdall.toml`. Dev/offline only: a node signing with these
    /// agrees with its peers only by coincidence.
    LocalOverride(&'static str),
}

impl std::fmt::Display for ParamSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config { utxo, slot } => write!(f, "Config UTxO {utxo} @ slot {slot}"),
            Self::LocalOverride(why) => write!(f, "LOCAL heimdall.toml override ({why})"),
        }
    }
}

/// The TM parameters to build a batch with, and where they came from.
///
/// With Config tunables the local `bitcoin.fee_rate_sat_per_vb` is ignored
/// outright — that is the whole point of the item: two operators who disagree in
/// their TOML still produce byte-identical TMs. Without them (a Config that
/// predates the append, or no Config configured at all) the local value is the
/// only value there is, and both floors stay zero so the skip rules they drive
/// are inert.
#[must_use]
pub fn resolve_tm_params(
    snapshot: Option<&ParamSnapshot>,
    local_fee_rate_sat_per_vb: u64,
) -> (TmParams, ParamSource) {
    match snapshot {
        Some(s) => match &s.config.params.tunables {
            Some(t) => (
                TmParams {
                    fee_rate_sat_per_vb: t.fee_rate_sat_per_vb,
                    per_pegout_fee_floor: Amount::from_sat(t.per_pegout_fee_floor),
                    min_peg_out_fbtc: Amount::from_sat(t.min_peg_out_fbtc),
                },
                ParamSource::Config {
                    utxo: s.config.utxo.clone(),
                    slot: s.slot,
                },
            ),
            None => (
                TmParams::fee_rate_only(local_fee_rate_sat_per_vb),
                ParamSource::LocalOverride(
                    "the deployed Config predates the operational-parameter fields",
                ),
            ),
        },
        None => (
            TmParams::fee_rate_only(local_fee_rate_sat_per_vb),
            ParamSource::LocalOverride("no Config UTxO configured"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode a Config datum.
///
/// Reads a PREFIX of the fields and tolerates unknown trailing ones — the datum
/// evolves by appending, and a reader that insisted on an exact arity would have
/// to be redeployed for every governance addition (the same reasoning that keeps
/// the Aiken side on positional getters instead of a full `expect` cast).
pub fn parse_config_datum(datum: &PlutusData) -> Result<ConfigParams, String> {
    let fields = plutus::constr_fields(datum, 0).map_err(|e| format!("config datum: {e}"))?;
    let field_count = fields.len();

    let contract_field = |i: usize, name: &str| -> Result<Vec<u8>, String> {
        plutus::field_bytes(fields, i).map_err(|e| format!("config #{i} ({name}): {e}"))
    };
    let contracts = Contracts {
        bridged_token_policy_id: contract_field(0, "bridged_token_policy_id")?,
        bridged_token_asset_name: contract_field(1, "bridged_token_asset_name")?,
        completed_peg_ins_policy_id: contract_field(2, "completed_peg_ins_merkle_tree_policy_id")?,
        completed_peg_outs_policy_id: contract_field(
            3,
            "completed_peg_outs_merkle_tree_policy_id",
        )?,
        peg_in_script_hash: contract_field(4, "peg_in_withdraw_script_hash")?,
        peg_out_script_hash: contract_field(5, "peg_out_withdraw_script_hash")?,
    };

    let min_stake = nonneg(
        plutus::field_int(fields, 9).map_err(|e| format!("config #9 (min_stake): {e}"))?,
        "config #9 (min_stake)",
    )?;

    let initial_btc_treasury_utxo = if field_count > 11 {
        let raw = plutus::field_bytes(fields, 11)
            .map_err(|e| format!("config #11 (initial_btc_treasury_utxo): {e}"))?;
        let len = raw.len();
        Some(<[u8; 36]>::try_from(raw).map_err(|_| {
            format!("config #11 (initial_btc_treasury_utxo) must be 36 bytes, got {len}")
        })?)
    } else {
        None
    };

    // All five tunables landed in one append, so a datum stopping inside them is a
    // botched governance Update, not a version this reader should interpret. Fail
    // loudly instead of silently substituting local values for the missing half.
    let tunables = if field_count >= CONFIG_FIELDS_WITH_TUNABLES {
        Some(Tunables {
            fee_rate_sat_per_vb: positive(
                plutus::field_int(fields, 12)
                    .map_err(|e| format!("config #12 (fee_rate_sat_per_vb): {e}"))?,
                "config #12 (fee_rate_sat_per_vb)",
            )?,
            per_pegout_fee_floor: nonneg(
                plutus::field_int(fields, 13)
                    .map_err(|e| format!("config #13 (per_pegout_fee): {e}"))?,
                "config #13 (per_pegout_fee)",
            )?,
            min_peg_out_fbtc: nonneg(
                plutus::field_int(fields, 14)
                    .map_err(|e| format!("config #14 (min_peg_out_fbtc): {e}"))?,
                "config #14 (min_peg_out_fbtc)",
            )?,
            leader_reward: nonneg(
                plutus::field_int(fields, 15)
                    .map_err(|e| format!("config #15 (leader_reward): {e}"))?,
                "config #15 (leader_reward)",
            )?,
            schedule: parse_schedule(&fields[16])?,
        })
    } else if field_count > CONFIG_FIELDS_UPSTREAM {
        return Err(format!(
            "config datum has {field_count} fields — the operational parameters are fields \
             #12-#16, so a datum between {} and {} fields is a partially-applied governance \
             Update. Refusing to guess which half is missing",
            CONFIG_FIELDS_UPSTREAM + 1,
            CONFIG_FIELDS_WITH_TUNABLES - 1,
        ));
    } else {
        None
    };

    // Same rule one append later: #17-#20 landed together, so a datum stopping
    // inside them is a botched Update. Refusing beats deriving a ban address from
    // half a record — the failure that would produce is an empty ban list, which
    // looks exactly like a bridge with no bans.
    let bans = if field_count >= CONFIG_FIELDS_WITH_BANS {
        Some(parse_bans(fields)?)
    } else if field_count > CONFIG_FIELDS_WITH_TUNABLES {
        return Err(format!(
            "config datum has {field_count} fields — the ban policy is fields #17-#20, so a \
             datum between {} and {} fields is a partially-applied governance Update. Refusing \
             to guess which half is missing",
            CONFIG_FIELDS_WITH_TUNABLES + 1,
            CONFIG_FIELDS_WITH_BANS - 1,
        ));
    } else {
        None
    };

    Ok(ConfigParams {
        field_count,
        contracts,
        min_stake,
        initial_btc_treasury_utxo,
        tunables,
        bans,
    })
}

/// Decode #17–#20.
///
/// The bounds are `spo_bans`' own `ban_config_ok` bounds, checked here for the
/// same reason the decoder rejects a zero fee rate: governance sanity is
/// upstream's job, and refusing to act on a value the contract could not have
/// been deployed with is ours. A zero `base_ban_duration_ms` would apply bans
/// that expire the instant they start.
fn parse_bans(fields: &[PlutusData]) -> Result<BanParams, String> {
    let raw = plutus::field_bytes(fields, 17)
        .map_err(|e| format!("config #17 (spo_bans_policy_id): {e}"))?;
    let len = raw.len();
    let spo_bans_policy_id = <[u8; 28]>::try_from(raw).map_err(|_| {
        format!("config #17 (spo_bans_policy_id) must be a 28-byte policy id, got {len} bytes")
    })?;
    let at = |i: usize, name: &str| -> Result<i64, String> {
        plutus::field_int(fields, i).map_err(|e| format!("config #{i} ({name}): {e}"))
    };
    let base_ban_duration_ms = at(18, "base_ban_duration_ms")?;
    let max_faults_before_permanent = at(19, "max_faults_before_permanent")?;
    let max_validity_window_ms = at(20, "max_validity_window_ms")?;
    if base_ban_duration_ms <= 0 {
        return Err(format!(
            "config #18 (base_ban_duration_ms) must be > 0, got {base_ban_duration_ms}"
        ));
    }
    if max_faults_before_permanent <= 0 {
        return Err(format!(
            "config #19 (max_faults_before_permanent) must be > 0, got {max_faults_before_permanent}"
        ));
    }
    if max_validity_window_ms < 0 {
        return Err(format!(
            "config #20 (max_validity_window_ms) must be >= 0, got {max_validity_window_ms}"
        ));
    }
    Ok(BanParams {
        spo_bans_policy_id,
        base_ban_duration_ms,
        max_faults_before_permanent,
        max_validity_window_ms,
    })
}

fn parse_schedule(data: &PlutusData) -> Result<ScheduleParams, String> {
    let f = plutus::constr_fields(data, 0).map_err(|e| format!("config #16 (schedule): {e}"))?;
    let at = |i: usize, name: &str| -> Result<i64, String> {
        plutus::field_int(f, i).map_err(|e| format!("config #16 (schedule.{name}): {e}"))
    };
    Ok(ScheduleParams {
        dkg_r1_deadline: at(0, "dkg_r1_deadline")?,
        dkg_r2_deadline: at(1, "dkg_r2_deadline")?,
        update_y_deadline: at(2, "update_y_deadline")?,
        tm_batch_interval: at(3, "tm_batch_interval")?,
        sign_r1_window: at(4, "sign_r1_window")?,
        sign_r2_window: at(5, "sign_r2_window")?,
        leader_slot_t: at(6, "leader_slot_t")?,
        tm_recovery_window: at(7, "tm_recovery_window")?,
        final_tm_cutoff: at(8, "final_tm_cutoff")?,
        stability_window: at(9, "stability_window")?,
    })
}

fn nonneg(v: i64, what: &str) -> Result<u64, String> {
    u64::try_from(v).map_err(|_| format!("{what} is negative ({v})"))
}

/// A zero fee rate would build a TM that pays no miner fee — unrelayable, so the
/// whole batch is wasted. Governance sanity is upstream's job; refusing to sign
/// the result is ours.
fn positive(v: i64, what: &str) -> Result<u64, String> {
    match v {
        v if v > 0 => Ok(v as u64),
        _ => Err(format!("{what} must be > 0, got {v}")),
    }
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/// Locate the Config UTxO among `utxos`: the one holding the config NFT and an
/// inline datum.
fn find_config_utxo<'a>(utxos: &'a [BfUtxo], nft_unit: &str) -> Result<&'a BfUtxo, String> {
    utxos
        .iter()
        .find(|u| u.inline_datum.is_some() && u.amount.iter().any(|a| a.unit == nft_unit))
        .ok_or_else(|| format!("no Config UTxO with NFT {nft_unit} and an inline datum"))
}

/// Decode a located Config UTxO.
pub fn config_view_from_utxo(utxo: &BfUtxo) -> Result<ConfigView, String> {
    let inline = utxo.inline_datum.as_deref().ok_or_else(|| {
        format!(
            "Config UTxO {}#{} carries no inline datum",
            utxo.tx_hash, utxo.output_index
        )
    })?;
    let datum_cbor = hex::decode(inline).map_err(|e| format!("config datum hex decode: {e}"))?;
    let datum: PlutusData =
        minicbor::decode(&datum_cbor).map_err(|e| format!("config datum CBOR decode: {e}"))?;
    Ok(ConfigView {
        params: parse_config_datum(&datum)?,
        utxo: ConfigUtxoRef {
            tx_hash: utxo.tx_hash.clone(),
            index: utxo.output_index,
        },
    })
}

/// Read + decode the Config UTxO at `address` carrying `nft_unit`.
pub async fn fetch_config(
    bf_base_url: &str,
    bf_project_id: &str,
    address: &str,
    nft_unit: &str,
) -> Result<ConfigView, String> {
    // Lenient raw-HTTP parse (tolerates yaci-devkit, which omits `tx_index`) — the
    // SDK's addresses_utxos requires it and errors on that backend.
    let utxos = bf_http::fetch_address_utxos(bf_base_url, bf_project_id, address)
        .await
        .map_err(|e| format!("config UTxO query: {e}"))?;
    let utxo = find_config_utxo(&utxos, nft_unit).map_err(|e| format!("{e} at {address}"))?;
    config_view_from_utxo(utxo)
}

/// How many times [`fetch_param_snapshot`] retakes the snapshot before giving up
/// on a Config Update that keeps landing after the tip it read.
const SNAPSHOT_ATTEMPTS: usize = 3;

/// Wait between snapshot attempts. Long enough for a tip endpoint that lags the
/// UTxO index by a moment to catch up, so a cosmetic backend lag cannot look like
/// a permanent mid-batch Config Update and stall the bridge.
const SNAPSHOT_RETRY_SECS: u64 = 3;

/// Read the Config UTxO **as of the current chain tip** — the batch snapshot.
///
/// Order matters: the tip is read FIRST, so a Config Update that lands between the
/// two reads is visible as `config_created_ms > time_ms` and the snapshot is
/// retaken rather than silently mixing a new datum into a batch pinned to an older
/// slot. (Retaking converges immediately: the next tip is past the update.)
///
/// If the backend cannot report the Config UTxO's creation time the ordering check
/// is skipped with a warning rather than failing the batch — the check guards a
/// narrow governance race, and a missing endpoint must not stop the bridge.
pub async fn fetch_param_snapshot(
    bf_base_url: &str,
    bf_project_id: &str,
    address: &str,
    nft_unit: &str,
) -> Result<ParamSnapshot, String> {
    let mut last: Option<ParamSnapshot> = None;
    for attempt in 1..=SNAPSHOT_ATTEMPTS {
        let (slot, tip_secs) = bf_http::fetch_latest_block_slot_time(bf_base_url, bf_project_id)
            .await
            .map_err(|e| format!("batch snapshot (blocks/latest): {e}"))?;
        let time_ms = tip_secs.saturating_mul(1000);
        let config = fetch_config(bf_base_url, bf_project_id, address, nft_unit).await?;

        let config_created_ms =
            match bf_http::fetch_tx_block_time(bf_base_url, bf_project_id, &config.utxo.tx_hash)
                .await
            {
                Ok(secs) => Some(secs.saturating_mul(1000)),
                Err(e) => {
                    warn!(
                        "[config] WARNING: could not read the Config UTxO's creation time \
                         ({e}) — cannot check it predates this batch's snapshot slot {slot}"
                    );
                    None
                }
            };

        let snapshot = ParamSnapshot {
            slot,
            time_ms,
            config,
            config_created_ms,
        };
        match snapshot.config_created_ms {
            Some(created) if created > time_ms => {
                warn!(
                    "[config] Config UTxO {} was created after this batch's snapshot (created \
                     {created} ms > tip {time_ms} ms) — a governance Update landed mid-read; \
                     retaking the snapshot ({attempt}/{SNAPSHOT_ATTEMPTS})",
                    snapshot.config.utxo,
                );
                last = Some(snapshot);
                tokio::time::sleep(std::time::Duration::from_secs(SNAPSHOT_RETRY_SECS)).await;
            }
            _ => return Ok(snapshot),
        }
    }
    Err(format!(
        "the Config UTxO kept moving ahead of the chain tip over {SNAPSHOT_ATTEMPTS} attempts \
         (last read {}) — refusing to build a batch whose parameters no other SPO would \
         reproduce",
        last.map_or_else(|| "<none>".to_string(), |s| s.config.utxo.to_string()),
    ))
}

/// Where `snapshot` stands on the TM batch grid (spec §TM batches; plan N19).
///
/// Shared by both TM drivers — the epoch-machine daemon and the CLI sweep — because
/// a grid derived two ways is a grid two SPOs can disagree about. The anchor (the
/// epoch boundary) and the pitch (the Config `schedule`) both come from the chain: a
/// node deriving either locally would freeze a different batch than its peers, which
/// is the failure this whole mechanism exists to prevent. A missing schedule
/// (pre-append Config) or an unreadable epoch boundary is reported and degrades to
/// "no cutoff", never to a guessed one.
pub async fn batch_at(
    bf_base_url: &str,
    bf_project_id: &str,
    snapshot: &ParamSnapshot,
) -> BatchWindow {
    let Some(schedule) = snapshot
        .config
        .params
        .tunables
        .as_ref()
        .map(|t| &t.schedule)
    else {
        return BatchWindow::NoGrid;
    };
    let epoch_start_slot = match epoch_start_slot(bf_base_url, bf_project_id, snapshot).await {
        Ok(slot) => slot,
        Err(e) => {
            warn!(
                "[batch] no epoch anchor ({e}) — building without the batch membership cutoff; \
                 peg-out selection falls back to whatever is open at this instant"
            );
            return BatchWindow::NoGrid;
        }
    };
    let Ok(interval) = u64::try_from(schedule.tm_batch_interval) else {
        return BatchWindow::NoGrid;
    };
    let stability = u64::try_from(schedule.stability_window).unwrap_or(0);
    let final_cutoff = u64::try_from(schedule.final_tm_cutoff)
        .ok()
        .map(|c| epoch_start_slot.saturating_add(c));
    let grid = match GridParams::new(epoch_start_slot, interval, stability, final_cutoff) {
        Ok(g) => g,
        Err(e) => {
            warn!("[batch] unusable schedule ({e}) — building without the cutoff");
            return BatchWindow::NoGrid;
        }
    };
    match grid.current(snapshot.slot) {
        Some(b) => BatchWindow::Open(b),
        None => {
            let next = grid.next(snapshot.slot);
            info!(
                "[batch] slot {} is outside this epoch's batch grid (before B_1, or past \
                 final_tm_cutoff) — the opportunity passes unused; next: {}",
                snapshot.slot,
                next.map_or_else(
                    || "none this epoch".to_string(),
                    |b| format!("B_{} at slot {}", b.index, b.slot)
                )
            );
            BatchWindow::Closed { next }
        }
    }
}

/// Absolute slot of the current epoch's boundary.
///
/// Blockfrost reports the boundary as a TIME, so it is converted with the exact
/// post-Shelley 1-slot-per-second identity against the snapshot's own (slot, time)
/// pair — the same conversion every other SPO performs on the same chain facts.
async fn epoch_start_slot(
    bf_base_url: &str,
    bf_project_id: &str,
    snapshot: &ParamSnapshot,
) -> Result<u64, String> {
    let epoch = bf_http::fetch_current_epoch(bf_base_url, bf_project_id).await?;
    let start_ms = bf_http::fetch_epoch_start_ms(bf_base_url, bf_project_id, epoch).await?;
    Ok(bf_http::slot_at_time(
        snapshot.slot,
        snapshot.time_ms,
        start_ms,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::plutus::{bytes, constr, int, int_from_u64};

    fn schedule_data() -> PlutusData {
        constr(
            0,
            vec![
                int(3600),
                int(7200),
                int(10800),
                int(21600),
                int(1800),
                int(1801),
                int(600),
                int(129600),
                int(345600),
                int(129601),
            ],
        )
    }

    /// The deployed 17-field shape (upstream #0-#11 + the tunables append).
    fn config_datum(fee_rate: i64, floor: i64, min_peg_out: i64) -> PlutusData {
        let mut fields = vec![
            bytes(&[0xaa, 0x00]), // #0  bridged_token_policy_id
            bytes(&[0xaa, 0x01]), // #1  bridged_token_asset_name
            bytes(&[0xaa, 0x02]), // #2  completed_peg_ins policy
            bytes(&[0xaa, 0x03]), // #3  completed_peg_outs policy
            bytes(&[0xaa, 0x04]), // #4  peg_in withdraw script hash
            bytes(&[0xaa, 0x05]), // #5  peg_out withdraw script hash
            bytes(&[0xaa, 0x06]), // #6  peg_in close verifier
            bytes(&[0xaa, 0x07]), // #7  TM + peg-out produced verifier
            bytes(&[0xaa, 0x08]), // #8  TM + peg-out NOT produced verifier
            int(60_000_000),      // #9  min_stake
            constr(1, vec![]),    // #10 update_auth = None
            bytes(&[0x11; 36]),   // #11 initial_btc_treasury_utxo
        ];
        fields.push(int(fee_rate)); // #12
        fields.push(int(floor)); // #13
        fields.push(int(min_peg_out)); // #14
        fields.push(int_from_u64(2_000_000)); // #15 leader_reward
        fields.push(schedule_data()); // #16
        constr(0, fields)
    }

    /// The 17-field shape plus the ban append (#17-#20).
    fn config_datum_with_bans(policy: [u8; 28]) -> PlutusData {
        let mut fields = plutus::constr_fields(&config_datum(7, 1_000, 100_000), 0)
            .unwrap()
            .to_vec();
        fields.push(bytes(&policy)); // #17 spo_bans_policy_id
        fields.push(int(600_000)); // #18 base_ban_duration_ms
        fields.push(int(3)); // #19 max_faults_before_permanent
        fields.push(int(3_600_000)); // #20 max_validity_window_ms
        constr(0, fields)
    }

    fn snapshot_of(datum: &PlutusData) -> ParamSnapshot {
        ParamSnapshot {
            slot: 12_345,
            time_ms: 1_700_000_000_000,
            config: ConfigView {
                params: parse_config_datum(datum).unwrap(),
                utxo: ConfigUtxoRef {
                    tx_hash: "ab".repeat(32),
                    index: 0,
                },
            },
            config_created_ms: Some(1_699_000_000_000),
        }
    }

    #[test]
    fn decodes_the_contract_identifiers() {
        let p = parse_config_datum(&config_datum(7, 1_000, 100_000)).unwrap();
        let c = &p.contracts;
        assert_eq!(c.bridged_token_policy_id, vec![0xaa, 0x00]);
        assert_eq!(c.bridged_token_asset_name, vec![0xaa, 0x01]);
        assert_eq!(c.completed_peg_ins_policy_id, vec![0xaa, 0x02]);
        assert_eq!(c.completed_peg_outs_policy_id, vec![0xaa, 0x03]);
        assert_eq!(c.peg_in_script_hash, vec![0xaa, 0x04]);
        assert_eq!(c.peg_out_script_hash, vec![0xaa, 0x05]);
        // The unit is the concatenation Blockfrost uses, not a tuple.
        assert_eq!(c.bridged_token_unit(), "aa00aa01");
    }

    #[test]
    fn contract_identifiers_decode_on_a_pre_tunables_config_too() {
        // They are upstream fields #0-#5, so every Config version has them —
        // the startup cross-check must work against an older bridge as well.
        let mut fields = match config_datum(1, 0, 0) {
            PlutusData::Constr(c) => c.fields.to_vec(),
            _ => unreachable!(),
        };
        fields.truncate(CONFIG_FIELDS_UPSTREAM);
        let p = parse_config_datum(&constr(0, fields)).unwrap();
        assert_eq!(p.field_count, CONFIG_FIELDS_UPSTREAM);
        assert!(p.tunables.is_none());
        assert_eq!(p.contracts.peg_in_script_hash, vec![0xaa, 0x04]);
    }

    #[test]
    fn decodes_the_deployed_17_field_config() {
        let p = parse_config_datum(&config_datum(7, 1_000, 100_000)).unwrap();
        assert_eq!(p.field_count, CONFIG_FIELDS_WITH_TUNABLES);
        assert_eq!(p.min_stake, 60_000_000);
        assert_eq!(p.initial_btc_treasury_utxo, Some([0x11; 36]));
        let t = p.tunables.unwrap();
        assert_eq!(t.fee_rate_sat_per_vb, 7);
        assert_eq!(t.per_pegout_fee_floor, 1_000);
        assert_eq!(t.min_peg_out_fbtc, 100_000);
        assert_eq!(t.leader_reward, 2_000_000);
        assert_eq!(t.schedule.tm_batch_interval, 21_600);
        assert_eq!(t.schedule.stability_window, 129_601);
    }

    /// A Config deployed before the append still resolves — it just has no
    /// tunables, which is what makes the local override legitimate there.
    #[test]
    fn a_pre_append_config_has_no_tunables() {
        let full = config_datum(7, 1_000, 100_000);
        let fields = plutus::constr_fields(&full, 0).unwrap()[..12].to_vec();
        let p = parse_config_datum(&constr(0, fields)).unwrap();
        assert_eq!(p.field_count, 12);
        assert_eq!(p.initial_btc_treasury_utxo, Some([0x11; 36]));
        assert!(p.tunables.is_none());
    }

    /// Half an append is a botched governance Update, not a datum version.
    #[test]
    fn a_partial_tunables_append_is_rejected() {
        let full = config_datum(7, 1_000, 100_000);
        let fields = plutus::constr_fields(&full, 0).unwrap()[..15].to_vec();
        let err = parse_config_datum(&constr(0, fields)).unwrap_err();
        assert!(err.contains("partially-applied"), "{err}");
    }

    #[test]
    fn decodes_the_published_ban_policy() {
        let p = parse_config_datum(&config_datum_with_bans([0xbb; 28])).unwrap();
        assert_eq!(p.field_count, CONFIG_FIELDS_WITH_BANS);
        let b = p.bans.unwrap();
        assert_eq!(b.spo_bans_policy_id, [0xbb; 28]);
        assert_eq!(b.base_ban_duration_ms, 600_000);
        assert_eq!(b.max_faults_before_permanent, 3);
        assert_eq!(b.max_validity_window_ms, 3_600_000);
        // …and the tunables below it still decode: the ban fields are an append,
        // not a replacement.
        assert_eq!(p.tunables.unwrap().fee_rate_sat_per_vb, 7);
    }

    /// The deployed preprod shape, until the migrating Update lands. It must keep
    /// working — a reader that required #17 would brick every node on the bridge
    /// the moment it shipped.
    #[test]
    fn the_17_field_config_has_no_published_bans() {
        let p = parse_config_datum(&config_datum(7, 1_000, 100_000)).unwrap();
        assert_eq!(p.field_count, CONFIG_FIELDS_WITH_TUNABLES);
        assert!(p.bans.is_none());
    }

    /// Half the ban append is a botched Update. Guessing would derive a ban
    /// address from a partial record — a valid-looking address holding no bans,
    /// which reads exactly like a bridge that has never banned anyone.
    #[test]
    fn a_partial_ban_append_is_rejected() {
        let full = config_datum_with_bans([0xbb; 28]);
        for n in [18usize, 19, 20] {
            let fields = plutus::constr_fields(&full, 0).unwrap()[..n].to_vec();
            let err = parse_config_datum(&constr(0, fields)).unwrap_err();
            assert!(err.contains("partially-applied"), "{n} fields: {err}");
        }
    }

    #[test]
    fn a_ban_policy_id_of_the_wrong_length_is_rejected() {
        let mut fields = plutus::constr_fields(&config_datum_with_bans([0xbb; 28]), 0)
            .unwrap()
            .to_vec();
        fields[17] = bytes(&[0xbb; 27]);
        let err = parse_config_datum(&constr(0, fields)).unwrap_err();
        assert!(err.contains("28-byte policy id"), "{err}");
    }

    /// `ban_config_ok`'s own bounds: a value the contract could not have been
    /// deployed with means the reader is looking at the wrong thing.
    #[test]
    fn out_of_range_ban_schedule_values_are_rejected() {
        let bad = |i: usize, v: i64| {
            let mut fields = plutus::constr_fields(&config_datum_with_bans([0xbb; 28]), 0)
                .unwrap()
                .to_vec();
            fields[i] = int(v);
            parse_config_datum(&constr(0, fields)).unwrap_err()
        };
        assert!(bad(18, 0).contains("base_ban_duration_ms"));
        assert!(bad(19, 0).contains("max_faults_before_permanent"));
        assert!(bad(20, -1).contains("max_validity_window_ms"));
    }

    /// The cross-repo check: this is the datum `binocular update-config` actually
    /// produces when it appends the ban policy to a 17-field Config, emitted from
    /// `UpdateConfigCommand.rewriteFields` and serialised with Scalus. Two
    /// independent encoders of one datum is exactly where a positional record
    /// goes wrong, and the failure mode — a reader that mis-decodes #17 — is a
    /// wrong ban address holding no bans.
    #[test]
    fn decodes_the_datum_binocular_update_config_writes() {
        const VECTOR: &str = concat!(
            "d8799f4100410141024103410441054106410741081a03938700410a58241111111111111111",
            "11111111111111111111111111111111111111111111111111111111021903e81927101a001e",
            "8480d8799f190e10191c20192a301954601907081907081902581a0001fa401a000546001a00",
            "01fa40ff581cbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1a000927",
            "c0031a0036ee80ff",
        );
        let cbor = hex::decode(VECTOR).unwrap();
        let datum: PlutusData = minicbor::decode(&cbor).unwrap();
        let p = parse_config_datum(&datum).unwrap();

        assert_eq!(p.field_count, CONFIG_FIELDS_WITH_BANS);
        let b = p.bans.expect("the appended ban policy");
        assert_eq!(b.spo_bans_policy_id, [0xbb; 28]);
        assert_eq!(b.base_ban_duration_ms, 600_000);
        assert_eq!(b.max_faults_before_permanent, 3);
        assert_eq!(b.max_validity_window_ms, 3_600_000);
        // The append did not disturb what was already there.
        assert_eq!(p.min_stake, 60_000_000);
        assert_eq!(p.initial_btc_treasury_utxo, Some([0x11; 36]));
        let t = p.tunables.expect("the tunables survive the append");
        assert_eq!(t.fee_rate_sat_per_vb, 2);
        assert_eq!(t.leader_reward, 2_000_000);
        assert_eq!(t.schedule.tm_batch_interval, 21_600);
    }

    #[test]
    fn a_zero_fee_rate_is_rejected() {
        let err = parse_config_datum(&config_datum(0, 1_000, 100_000)).unwrap_err();
        assert!(err.contains("fee_rate_sat_per_vb"), "{err}");
    }

    /// The acceptance criterion, at the resolver: the Config decides the TM
    /// parameters and the node's own `bitcoin.fee_rate_sat_per_vb` is not consulted.
    #[test]
    fn config_tunables_ignore_the_local_fee_override() {
        let snap = snapshot_of(&config_datum(7, 1_000, 100_000));
        let (a, src_a) = resolve_tm_params(Some(&snap), 1);
        let (b, src_b) = resolve_tm_params(Some(&snap), 999);
        assert_eq!(a, b, "two operators, two TOMLs, one parameter set");
        assert_eq!(a.fee_rate_sat_per_vb, 7);
        assert_eq!(a.per_pegout_fee_floor, Amount::from_sat(1_000));
        assert_eq!(a.min_peg_out_fbtc, Amount::from_sat(100_000));
        assert_eq!(src_a, src_b);
        assert!(matches!(src_a, ParamSource::Config { slot: 12_345, .. }));
    }

    /// …and without a Config the local value is used, but the source says so —
    /// both floors stay zero, so no skip rule runs on a node-local number.
    #[test]
    fn no_config_falls_back_to_the_local_override() {
        let (p, src) = resolve_tm_params(None, 3);
        assert_eq!(p, TmParams::fee_rate_only(3));
        assert!(matches!(src, ParamSource::LocalOverride(_)));
        assert!(src.to_string().contains("LOCAL"));
    }

    #[test]
    fn a_pre_append_config_falls_back_to_the_local_override() {
        let full = config_datum(7, 1_000, 100_000);
        let fields = plutus::constr_fields(&full, 0).unwrap()[..12].to_vec();
        let snap = snapshot_of(&constr(0, fields));
        let (p, src) = resolve_tm_params(Some(&snap), 3);
        assert_eq!(p, TmParams::fee_rate_only(3), "local fee rate, zero floors");
        assert!(matches!(src, ParamSource::LocalOverride(_)));
    }

    /// The acceptance criterion end to end: two nodes whose `heimdall.toml` fee
    /// rates disagree build BYTE-IDENTICAL Treasury Movements off one Config UTxO —
    /// which is the whole reason the parameters moved on-chain, since FROST signs
    /// the transaction's sighashes and different bytes mean different messages.
    #[test]
    fn two_local_fee_rates_one_config_produce_identical_tm_bytes() {
        use crate::bitcoin::taproot::treasury_spend_info;
        use crate::bitcoin::tm_builder::{
            Freshness, TreasuryInput, build_tm, cpo_commitment_script,
        };
        use bitcoin::key::Secp256k1;
        use bitcoin::secp256k1::SecretKey;

        let secp = Secp256k1::new();
        let y = SecretKey::from_slice(&[0x42; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0;
        let build = |params: &TmParams| {
            let spend_info = treasury_spend_info(&secp, y, y, 144);
            let change = bitcoin::ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
            build_tm(
                TreasuryInput {
                    outpoint: bitcoin::OutPoint::null(),
                    value: Amount::from_sat(10_000_000),
                    spend_info,
                },
                vec![],
                vec![],
                change,
                params,
                &Freshness {
                    now_ms: 0,
                    margin_ms: 0,
                },
                &crate::bitcoin::tm_builder::FixedCpoRoot([0u8; 32]),
            )
            .unwrap()
            .tx
        };

        let snap = snapshot_of(&config_datum(7, 1_000, 100_000));
        let a = build(&resolve_tm_params(Some(&snap), 1).0);
        let b = build(&resolve_tm_params(Some(&snap), 999).0);
        assert_eq!(
            bitcoin::consensus::encode::serialize(&a),
            bitcoin::consensus::encode::serialize(&b),
        );

        // Control: the local rate is what WOULD have differed. Without a Config the
        // same two nodes build different bytes — the defect this item closes.
        let c = build(&resolve_tm_params(None, 1).0);
        let d = build(&resolve_tm_params(None, 999).0);
        assert_ne!(c.compute_txid(), d.compute_txid());

        // …and it is the CONFIG's rate that was charged, not some constant: the
        // treasury change is `inputs − vsize × rate`, so doubling the Config rate
        // doubles the miner fee the change gives up.
        let miner_fee = |tx: &bitcoin::Transaction| {
            let change = tx
                .output
                .iter()
                .find(|o| o.script_pubkey != cpo_commitment_script(&[0u8; 32]))
                .unwrap();
            10_000_000 - change.value.to_sat()
        };
        let at_14 =
            build(&resolve_tm_params(Some(&snapshot_of(&config_datum(14, 1_000, 100_000))), 1).0);
        assert_eq!(miner_fee(&at_14), 2 * miner_fee(&a));
    }

    #[test]
    fn finds_the_config_utxo_by_nft_and_datum() {
        use crate::cardano::bf_http::{BfAmount, BfUtxo};
        let mk = |tx: &str, unit: &str, datum: Option<&str>| BfUtxo {
            tx_hash: tx.to_string(),
            output_index: 0,
            amount: vec![BfAmount {
                unit: unit.to_string(),
                quantity: "1".to_string(),
            }],
            inline_datum: datum.map(str::to_string),
            reference_script_hash: None,
        };
        let utxos = vec![
            mk("aa", "lovelace", Some("d8")),
            // Right NFT, no datum: not the Config.
            mk("bb", "cafe01", None),
            mk("cc", "cafe01", Some("d8")),
        ];
        assert_eq!(find_config_utxo(&utxos, "cafe01").unwrap().tx_hash, "cc");
        assert!(find_config_utxo(&utxos, "beef02").is_err());
    }
}
