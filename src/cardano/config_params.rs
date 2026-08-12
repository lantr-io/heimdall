//! The bridge **Config** UTxO, read off-chain (spec §Operational parameters).
//!
//! The Config UTxO is the NFT-authenticated singleton at `config.ak` that carries
//! the bridge's wiring (script hashes, token identities) and — nested as field #14
//! — the **operational parameters**: the tunables that no Aiken validator reads
//! and every off-chain consumer must agree on. They are governance-updatable
//! through an authorized Config `Update` (field #0, `update_auth`).
//!
//! ## Why heimdall reads them here and not from `heimdall.toml`
//!
//! FROST aggregation requires every SPO to build **byte-identical** TM bytes. The
//! fee rate decides the treasury change amount, and the two floors decide the
//! skip set — so a value that differs per operator makes the co-signers sign
//! different messages and the round simply cannot converge. Sourcing them from a
//! single on-chain UTxO is what makes them a consensus input rather than a local
//! opinion. The `bitcoin.fee_rate_sat_per_vb` / `bitcoin.per_pegout_fee_sat`
//! config keys survive only as the dev/offline override for the paths that have
//! no co-signers at all (see [`resolve_tm_params`]).
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
//! ## Field numbering (rev 5.4, spec §Config datum — fifteen fields)
//!
//! Positions are a frozen contract — the datum evolves by APPENDING only — so a
//! reader may safely decode the fifteen fields it knows and ignore trailing ones:
//!
//! | # | field | read here |
//! |---|-------|-----------|
//! | 0 | `update_auth` | no |
//! | 1 | `bridged_token_policy` | no (heimdall.toml carries it) |
//! | 2 | `completed_peg_ins_policy` | no |
//! | 3 | `bridge_state_policy` | locate the bridge-state singleton ([PAR-1]) |
//! | 4 | `tm_script_hash` | the TM validator hash = TM address ([CFG-2]) |
//! | 5 | `peg_in_script_hash` | no |
//! | 6 | `peg_out_script_hash` | no |
//! | 7 | `spo_bans_policy_id` | the ban script address the roster is filtered against |
//! | 8–10 | ban schedule (`base_ban_duration_ms`, `max_faults_before_permanent`, `max_validity_window_ms`) | the ApplyBan builder |
//! | 11–13 | `spos_registry_policy_id`, `treasury_info_policy_id`, `treasury_info_asset_name` | the roster addresses |
//! | 14 | `params` (nested [`Tunables`]) | TM fee rate + skip floors + schedule |
//!
//! `params` is LAST on purpose (spec §Config datum): every field before it is a
//! scalar at a frozen index, so the datum grows by appending after the nested
//! record instead of pushing it along.
//!
//! ## Why the policy ids are PUBLISHED rather than derived (#7, #11–#13)
//!
//! Every other ban value an operator could type — the three schedule numbers, the
//! fault-verifier policy set, the bootstrap outref — is an *input* to the
//! `spo_bans` policy id, not an output of it. So a node cannot derive the address
//! it would read them from without already having them, and getting any one wrong
//! derives a ban address no deployment has: a silently EMPTY ban list, and banned
//! SPOs back in the roster with nothing in any log. Publishing the finished policy
//! id breaks that cycle — a reader trusts the authenticated Config exactly as it
//! already trusts the contract identifiers #1–#6, and needs no ban configuration
//! whatsoever. A node that *does* still carry the local keys (for enforcement)
//! cross-checks what it derives against #7 instead, so a stale copy is a startup
//! error rather than an empty list.
//!
//! Gone from rev 5.1: `min_stake` (the register-spo R2 gate reads the local
//! `cardano.min_stake_lovelace` now — it never had an on-chain reader),
//! `initial_btc_treasury_utxo` (the treasury head lives in the bridge-state
//! singleton) and `leader_reward` (spec §Leader reward: DEFERRED).

use bitcoin::Amount;
use pallas_codec::minicbor;
use pallas_primitives::PlutusData;

use crate::bitcoin::tm_builder::TmParams;
use crate::cardano::bf_http::{self, BfUtxo};
use crate::cardano::plutus;
use crate::epoch::batch::{BatchWindow, GridParams};
use tracing::{info, warn};

/// Field count of the rev-5.4 Config datum (spec §Config datum). Appends are the
/// legal evolution, so a reader accepts MORE fields and refuses fewer.
pub const CONFIG_FIELDS: usize = 15;

/// `params[3]` — the tunable protocol schedule, E-relative slot values (spec
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

/// Config #14 — the nested operational-parameter record, positional:
/// `[fee_rate_sat_per_vb, per_pegout_fee, min_peg_out_fbtc, schedule]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunables {
    /// params[0], sat/vB. The EXACT miner fee rate, not an estimate.
    pub fee_rate_sat_per_vb: u64,
    /// params[1], satoshi. Floor for a request's own datum-pinned `per_pegout_fee`.
    pub per_pegout_fee_floor: u64,
    /// params[2], satoshi. Minimum fBTC a PegOut request may lock.
    pub min_peg_out_fbtc: u64,
    /// params[3].
    pub schedule: ScheduleParams,
}

/// The bridged token's asset name — the [CFG-1] protocol constant, not a Config
/// field (rev 5.4 removed the field: one token is one satoshi, so the name is a
/// property of the protocol, not of a deployment).
pub const BRIDGED_TOKEN_ASSET_NAME: &[u8] = b"fSAT";

/// Config #7–#10 — the ban policy, published so no SPO has to configure one.
///
/// Split by who needs what: #7 alone serves the MANDATORY read half (the roster
/// is the registry minus active bans, so every node must read the same list), and
/// #8–#10 serve the optional enforcement half — `apply_ban` computes a ban's end
/// time from #8/#9 and bounds the ApplyBan validity interval by #10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanParams {
    /// #7. The `spo_bans` policy id; the ban script address follows from it, so
    /// this one field is the whole read half.
    pub spo_bans_policy_id: [u8; 28],
    /// #8, milliseconds. `base_ban_duration_ms * 2^(n-1)` is the nth ban's length.
    pub base_ban_duration_ms: i64,
    /// #9. A pool is banned permanently at this many faults.
    pub max_faults_before_permanent: i64,
    /// #10, milliseconds. Upper bound on an ApplyBan tx's validity interval.
    pub max_validity_window_ms: i64,
}

/// Config #11–#13 — the SPO registry's identity, published for the same reason
/// as the ban policy: these are the values an SPO would otherwise hand-copy to
/// locate the roster, and a wrong one yields a well-formed address holding
/// nothing rather than an error.
///
/// Same read/spend split as the ban policy. READING the roster needs only what
/// is here — no blueprint and no bootstrap outref. SPENDING the `treasury_info`
/// state UTxO (the Update-Y key handoff) still needs the compiled script, so a
/// node that performs handoffs also needs the blueprint; #12 becomes the
/// cross-check on what it derives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryParams {
    /// #11. The `spos_registry` policy id; the registry address follows from it.
    pub spos_registry_policy_id: [u8; 28],
    /// #12. The `treasury_info` policy id. A pure function of #11 alone since
    /// rev 5.4 dropped `treasury_info`'s TM-NFT-policy parameter, but published
    /// anyway: a reader must still apply that parameter to the same blueprint,
    /// and drift yields a different hash, a different address and an unfindable
    /// state UTxO rather than an error.
    pub treasury_info_policy_id: [u8; 28],
    /// #13. Asset name of the `treasury_info` state NFT — chosen at bootstrap
    /// and derivable from nothing at all, so publishing it is the only way an
    /// SPO can avoid typing it.
    pub treasury_info_asset_name: Vec<u8>,
}

/// Config #1–#6 — the bridge's contract identifiers.
///
/// These are the ONLY copies. heimdall's `[cardano]` section used to carry
/// `bridged_token_unit`, `pegin_policy_id`, `pegin_script_address`,
/// `pegout_script_address` and `cpo_policy_id` alongside them, and the startup
/// gate cross-checked the two. WI-070 deleted that half: a value the Config
/// publishes is not an operator setting, and the second copy — not the typo in it
/// — was the defect. [`ConfigParams::bridge_contracts`] derives every one of them
/// from the datum instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contracts {
    /// #1
    pub bridged_token_policy_id: Vec<u8>,
    /// #2
    pub completed_peg_ins_policy_id: Vec<u8>,
    /// #5. One Aiken validator serves `mint`, `withdraw` and `spend`, so this
    /// single hash is both the peg-in NFT policy id and the payment credential
    /// of the peg-in script address.
    ///
    /// Length-checked at parse time, not at use: it is derived straight into a
    /// bech32 address, and there is no sensible way to render a short one.
    pub peg_in_script_hash: [u8; 28],
    /// #6. Likewise the payment credential of the peg-out script address.
    pub peg_out_script_hash: [u8; 28],
}

impl Contracts {
    /// The bridged token's `unit` as Blockfrost spells it: policy id ‖ asset
    /// name. The name is the [CFG-1] constant, not a datum field.
    #[must_use]
    pub fn bridged_token_unit(&self) -> String {
        format!(
            "{}{}",
            hex::encode(&self.bridged_token_policy_id),
            hex::encode(BRIDGED_TOKEN_ASSET_NAME)
        )
    }
}

/// The TM state token's asset name — empty, a protocol constant like
/// [`BRIDGED_TOKEN_ASSET_NAME`]. The TreasuryMovementValidator counts the
/// empty-name token under its own script hash, so there is nothing per-bridge
/// about it and nothing for an operator to set.
pub const TM_ASSET_NAME_HEX: &str = "";

/// Every bridge identifier heimdall works from, derived from the authenticated
/// Config datum (WI-070).
///
/// Each field used to be a `[cardano]` key an operator copied out of the bridge's
/// deployment notes. That made every one of them a value two SPOs could disagree
/// about, and disagreement is never an error here — a mistyped script hash yields
/// a well-formed address holding nothing, which reads as "no peg-ins pending" and
/// "no peg-outs pending" while the node keeps signing. Deriving them from the one
/// NFT-authenticated UTxO removes the second source rather than checking it.
///
/// The network tag is the sole local input, and [`crate::config::CardanoConfig::is_mainnet`]
/// already cross-checks it against the Config address's own bech32 prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeContracts {
    /// #5, hex. The peg-in NFT policy id.
    pub pegin_policy_id: String,
    /// #5 as a bech32 enterprise address — where PegInRequest UTxOs sit.
    pub pegin_script_address: String,
    /// #6 as a bech32 enterprise address — where PegOut UTxOs sit.
    pub pegout_script_address: String,
    /// #1 ‖ [`BRIDGED_TOKEN_ASSET_NAME`] — the fBTC unit whose quantity is a
    /// PegOut request's locked amount.
    pub bridged_token_unit: String,
    /// #3, hex. The bridge-state singleton's NFT policy.
    pub bridge_state_policy_id: String,
    /// #4, hex. The TM validator script hash = the TM NFT policy id.
    pub tm_policy_id: String,
    /// #4 as a bech32 enterprise address — the TM validator address every
    /// UnconfirmedTm/Confirmed record is posted to.
    pub tm_address: String,
}

impl BridgeContracts {
    /// The `(policy, asset name)` unit identifying a TM state token.
    #[must_use]
    pub fn tm_asset_unit(&self) -> String {
        format!("{}{TM_ASSET_NAME_HEX}", self.tm_policy_id)
    }
}

impl ConfigParams {
    /// Derive every bridge identifier from this Config datum.
    ///
    /// `mainnet` decides only the bech32 network tag of the three derived
    /// addresses; the hashes themselves are the datum's.
    #[must_use]
    pub fn bridge_contracts(&self, mainnet: bool) -> BridgeContracts {
        use crate::cardano::blueprint::script_enterprise_address;
        let network = if mainnet {
            pallas_addresses::Network::Mainnet
        } else {
            pallas_addresses::Network::Testnet
        };
        let peg_in = self.contracts.peg_in_script_hash;
        let peg_out = self.contracts.peg_out_script_hash;
        BridgeContracts {
            pegin_policy_id: hex::encode(peg_in),
            pegin_script_address: script_enterprise_address(&peg_in, network),
            pegout_script_address: script_enterprise_address(&peg_out, network),
            bridged_token_unit: self.contracts.bridged_token_unit(),
            bridge_state_policy_id: hex::encode(self.bridge_state_policy),
            tm_policy_id: hex::encode(self.tm_script_hash),
            tm_address: script_enterprise_address(&self.tm_script_hash, network),
        }
    }
}

/// The Config datum as heimdall reads it: the fields it consumes, plus the raw
/// field count (the append-only version marker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigParams {
    /// Number of fields in the deployed datum (>= [`CONFIG_FIELDS`]).
    pub field_count: usize,
    /// #1–#6 — the contract identifiers the operator's config duplicates.
    pub contracts: Contracts,
    /// #3 — the NFT policy of the bridge-state singleton. Every reader locates
    /// the singleton through this at runtime ([PAR-1]), never a pinned constant.
    pub bridge_state_policy: [u8; 28],
    /// #4 — the TM validator script hash = the TM NFT policy = the TM address
    /// payment credential ([CFG-2]: published so off-chain readers stop pinning
    /// a build-time constant; no on-chain reader).
    pub tm_script_hash: [u8; 28],
    /// #7–#10. Not optional: [`CONFIG_FIELDS`] refuses a datum that lacks them,
    /// so a rev-5.4 Config always publishes the ban policy.
    pub bans: BanParams,
    /// #11–#13, present for the same reason as [`Self::bans`].
    pub registry: RegistryParams,
    /// #14 — always present in the rev-5.4 layout.
    pub tunables: Tunables,
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
        Some(s) => {
            let t = &s.config.params.tunables;
            (
                TmParams {
                    fee_rate_sat_per_vb: t.fee_rate_sat_per_vb,
                    per_pegout_fee_floor: Amount::from_sat(t.per_pegout_fee_floor),
                    min_peg_out_fbtc: Amount::from_sat(t.min_peg_out_fbtc),
                },
                ParamSource::Config {
                    utxo: s.config.utxo.clone(),
                    slot: s.slot,
                },
            )
        }
        None => (
            TmParams::fee_rate_only(local_fee_rate_sat_per_vb),
            ParamSource::LocalOverride("no Config UTxO configured"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode a Config datum (rev 5.4, fifteen fields).
///
/// Reads the fields it knows and tolerates unknown TRAILING ones — the datum
/// evolves by appending, and a reader that insisted on an exact arity would have
/// to be redeployed for every governance addition. Fewer than [`CONFIG_FIELDS`]
/// fields is a different (older or foreign) datum and is refused.
pub fn parse_config_datum(datum: &PlutusData) -> Result<ConfigParams, String> {
    let fields = plutus::constr_fields(datum, 0).map_err(|e| format!("config datum: {e}"))?;
    let field_count = fields.len();
    if field_count < CONFIG_FIELDS {
        return Err(format!(
            "config datum has {field_count} fields, expected >= {CONFIG_FIELDS} (rev 5.4) — \
             this deployment predates the bridge-state singleton layout"
        ));
    }

    let contract_field = |i: usize, name: &str| -> Result<Vec<u8>, String> {
        plutus::field_bytes(fields, i).map_err(|e| format!("config #{i} ({name}): {e}"))
    };
    let contracts = Contracts {
        // #1 is a policy id, so length-check it at parse like #5/#6 rather than
        // at use. Callers concatenate it with an asset name and split the result
        // back at 56 hex chars (run_reconstruct_cpo_trie), which panics rather
        // than erroring on a short one.
        bridged_token_policy_id: field_hash28(fields, 1, "bridged_token_policy")?.to_vec(),
        completed_peg_ins_policy_id: contract_field(2, "completed_peg_ins_policy")?,
        peg_in_script_hash: field_hash28(fields, 5, "peg_in_script_hash")?,
        peg_out_script_hash: field_hash28(fields, 6, "peg_out_script_hash")?,
    };

    let bridge_state_policy = field_hash28(fields, 3, "bridge_state_policy")?;
    let tm_script_hash = field_hash28(fields, 4, "tm_script_hash")?;

    let config_int = |i: usize, name: &str| -> Result<i64, String> {
        plutus::field_int(fields, i).map_err(|e| format!("config #{i} ({name}): {e}"))
    };
    // Range-check the ban schedule here, the way BanPolicyParams::from_config used
    // to before these moved on chain. The three values are INPUTS to the spo_bans
    // policy id, so an out-of-range one derives the wrong ban address and yields a
    // silently empty ban list — the exact failure WI-065 exists to remove. Bounds
    // match the contract's own ban_config_ok.
    let bans = BanParams {
        spo_bans_policy_id: field_hash28(fields, 7, "spo_bans_policy_id")?,
        base_ban_duration_ms: positive(
            config_int(8, "base_ban_duration_ms")?,
            "config #8 (base_ban_duration_ms)",
        )? as i64,
        max_faults_before_permanent: positive(
            config_int(9, "max_faults_before_permanent")?,
            "config #9 (max_faults_before_permanent)",
        )? as i64,
        max_validity_window_ms: nonneg(
            config_int(10, "max_validity_window_ms")?,
            "config #10 (max_validity_window_ms)",
        )? as i64,
    };
    let registry = RegistryParams {
        spos_registry_policy_id: field_hash28(fields, 11, "spos_registry_policy_id")?,
        treasury_info_policy_id: field_hash28(fields, 12, "treasury_info_policy_id")?,
        treasury_info_asset_name: plutus::field_bytes(fields, 13)
            .map_err(|e| format!("config #13 (treasury_info_asset_name): {e}"))?,
    };

    let params =
        plutus::constr_fields(&fields[14], 0).map_err(|e| format!("config #14 (params): {e}"))?;
    if params.len() != 4 {
        return Err(format!(
            "config #14 (params) has {} slots, expected 4 \
             [fee_rate, per_pegout_fee, min_peg_out_fbtc, schedule]",
            params.len()
        ));
    }
    let tunables = Tunables {
        fee_rate_sat_per_vb: positive(
            plutus::field_int(params, 0)
                .map_err(|e| format!("config params[0] (fee_rate_sat_per_vb): {e}"))?,
            "config params[0] (fee_rate_sat_per_vb)",
        )?,
        per_pegout_fee_floor: nonneg(
            plutus::field_int(params, 1)
                .map_err(|e| format!("config params[1] (per_pegout_fee): {e}"))?,
            "config params[1] (per_pegout_fee)",
        )?,
        min_peg_out_fbtc: nonneg(
            plutus::field_int(params, 2)
                .map_err(|e| format!("config params[2] (min_peg_out_fbtc): {e}"))?,
            "config params[2] (min_peg_out_fbtc)",
        )?,
        schedule: parse_schedule(&params[3])?,
    };

    Ok(ConfigParams {
        field_count,
        contracts,
        bridge_state_policy,
        tm_script_hash,
        bans,
        registry,
        tunables,
    })
}

/// A minimal, valid rev-5.4 [`ConfigParams`] for unit tests in sibling modules.
///
/// Rev 5.4 makes every field mandatory, so a fixture can no longer express "this
/// Config predates the append" — [`parse_config_datum`] refuses such a datum
/// outright. A test that cares about a field overrides it on the returned value.
#[cfg(test)]
#[must_use]
pub(crate) fn test_config_params() -> ConfigParams {
    ConfigParams {
        field_count: CONFIG_FIELDS,
        contracts: Contracts {
            bridged_token_policy_id: Vec::new(),
            completed_peg_ins_policy_id: Vec::new(),
            peg_in_script_hash: [0; 28],
            peg_out_script_hash: [0; 28],
        },
        bridge_state_policy: [0; 28],
        tm_script_hash: [0; 28],
        bans: BanParams {
            spo_bans_policy_id: [0; 28],
            base_ban_duration_ms: 0,
            max_faults_before_permanent: 0,
            max_validity_window_ms: 0,
        },
        registry: RegistryParams {
            spos_registry_policy_id: [0; 28],
            treasury_info_policy_id: [0; 28],
            treasury_info_asset_name: Vec::new(),
        },
        tunables: Tunables {
            fee_rate_sat_per_vb: 1,
            per_pegout_fee_floor: 0,
            min_peg_out_fbtc: 0,
            schedule: ScheduleParams {
                dkg_r1_deadline: 0,
                dkg_r2_deadline: 0,
                update_y_deadline: 0,
                tm_batch_interval: 0,
                sign_r1_window: 0,
                sign_r2_window: 0,
                leader_slot_t: 0,
                tm_recovery_window: 0,
                final_tm_cutoff: 0,
                stability_window: 0,
            },
        },
    }
}

/// The `ByteArray` field at index `i`, required to be a 28-byte script hash.
fn field_hash28(fields: &[PlutusData], i: usize, name: &str) -> Result<[u8; 28], String> {
    let raw = plutus::field_bytes(fields, i).map_err(|e| format!("config #{i} ({name}): {e}"))?;
    let len = raw.len();
    <[u8; 28]>::try_from(raw)
        .map_err(|_| format!("config #{i} ({name}) must be a 28-byte script hash, got {len}"))
}

fn parse_schedule(data: &PlutusData) -> Result<ScheduleParams, String> {
    let f =
        plutus::constr_fields(data, 0).map_err(|e| format!("config params[3] (schedule): {e}"))?;
    let at = |i: usize, name: &str| -> Result<i64, String> {
        plutus::field_int(f, i).map_err(|e| format!("config params[3] (schedule.{name}): {e}"))
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
                        "[config] could not read the Config UTxO's creation time \
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
    let schedule = &snapshot.config.params.tunables.schedule;
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
    use crate::cardano::plutus::{bytes, constr, int};

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

    /// The deployed rev-5.4 eight-field shape (spec §Config datum).
    fn config_datum(fee_rate: i64, floor: i64, min_peg_out: i64) -> PlutusData {
        constr(
            0,
            vec![
                constr(1, vec![]),  // #0 update_auth = None
                bytes(&[0xaa; 28]), // #1 bridged_token_policy
                bytes(&[0xab; 28]), // #2 completed_peg_ins_policy
                bytes(&[0xb5; 28]), // #3 bridge_state_policy
                bytes(&[0xac; 28]), // #4 tm_script_hash
                bytes(&[0xad; 28]), // #5 peg_in_script_hash
                bytes(&[0xae; 28]), // #6 peg_out_script_hash
                bytes(&[0xbb; 28]), // #7 spo_bans_policy_id
                int(600_000),       // #8 base_ban_duration_ms
                int(3),             // #9 max_faults_before_permanent
                int(3_600_000),     // #10 max_validity_window_ms
                bytes(&[0xc1; 28]), // #11 spos_registry_policy_id
                bytes(&[0xc2; 28]), // #12 treasury_info_policy_id
                bytes(b"TMTx"),     // #13 treasury_info_asset_name
                constr(
                    0,
                    vec![int(fee_rate), int(floor), int(min_peg_out), schedule_data()],
                ), // #14 params
            ],
        )
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
        assert_eq!(c.bridged_token_policy_id, vec![0xaa; 28]);
        assert_eq!(c.completed_peg_ins_policy_id, vec![0xab; 28]);
        assert_eq!(c.peg_in_script_hash, [0xad; 28]);
        assert_eq!(c.peg_out_script_hash, [0xae; 28]);
        // The unit is the Blockfrost concatenation, with the [CFG-1] constant name.
        assert_eq!(
            c.bridged_token_unit(),
            format!("{}{}", "aa".repeat(28), hex::encode(b"fSAT"))
        );
    }

    /// WI-070: every identifier the operator used to type is a pure function of
    /// this datum. The two script hashes appear TWICE in each derivation — once
    /// as a policy id and once as the payment credential of an address — so a
    /// derivation that crossed them would still look well-formed. Pin both.
    #[test]
    fn derives_every_bridge_identifier_from_the_datum() {
        let p = parse_config_datum(&config_datum(7, 1_000, 100_000)).unwrap();
        let b = p.bridge_contracts(false);

        assert_eq!(b.pegin_policy_id, "ad".repeat(28));
        assert_eq!(b.bridge_state_policy_id, "b5".repeat(28));
        assert_eq!(b.tm_policy_id, "ac".repeat(28));
        assert_eq!(
            b.bridged_token_unit,
            format!("{}{}", "aa".repeat(28), hex::encode(b"fSAT"))
        );
        // The TM state token has no per-bridge name.
        assert_eq!(b.tm_asset_unit(), "ac".repeat(28));

        // Each address is the enterprise script address of its own hash, and the
        // three are distinct — a swapped pair would pass a "looks like bech32" test.
        let addr_of = |h: [u8; 28]| {
            crate::cardano::blueprint::script_enterprise_address(
                &h,
                pallas_addresses::Network::Testnet,
            )
        };
        assert_eq!(b.pegin_script_address, addr_of([0xad; 28]));
        assert_eq!(b.pegout_script_address, addr_of([0xae; 28]));
        assert_eq!(b.tm_address, addr_of([0xac; 28]));
        for a in [
            &b.pegin_script_address,
            &b.pegout_script_address,
            &b.tm_address,
        ] {
            assert!(a.starts_with("addr_test1w"), "{a}");
        }

        // The network tag is the one local input, and it must actually move.
        assert!(
            p.bridge_contracts(true)
                .pegin_script_address
                .starts_with("addr1w")
        );
    }

    /// #5/#6 are script hashes, and a datum carrying something else is refused at
    /// parse time rather than turned into a short, valid-looking address.
    #[test]
    fn a_contract_field_that_is_not_a_script_hash_is_refused() {
        let full = config_datum(7, 1_000, 100_000);
        let mut fields = plutus::constr_fields(&full, 0).unwrap().to_vec();
        fields[5] = bytes(&[0xad; 20]);
        let err = parse_config_datum(&constr(0, fields)).unwrap_err();
        assert!(err.contains("peg_in_script_hash"), "{err}");
    }

    #[test]
    fn decodes_the_deployed_15_field_config() {
        let p = parse_config_datum(&config_datum(7, 1_000, 100_000)).unwrap();
        assert_eq!(p.field_count, CONFIG_FIELDS);
        assert_eq!(p.bridge_state_policy, [0xb5; 28]);
        assert_eq!(p.tm_script_hash, [0xac; 28]);
        let t = &p.tunables;
        assert_eq!(t.fee_rate_sat_per_vb, 7);
        assert_eq!(t.per_pegout_fee_floor, 1_000);
        assert_eq!(t.min_peg_out_fbtc, 100_000);
        assert_eq!(t.schedule.tm_batch_interval, 21_600);
        assert_eq!(t.schedule.stability_window, 129_601);
    }

    /// Appending is the legal evolution: unknown trailing fields are ignored.
    #[test]
    fn a_config_grown_past_15_fields_still_decodes() {
        let full = config_datum(7, 1_000, 100_000);
        let mut fields = plutus::constr_fields(&full, 0).unwrap().to_vec();
        fields.push(int(99));
        let p = parse_config_datum(&constr(0, fields)).unwrap();
        assert_eq!(p.field_count, CONFIG_FIELDS + 1);
        assert_eq!(p.tunables.fee_rate_sat_per_vb, 7);
    }

    /// A shorter datum is an OLDER layout, not a version this reader guesses at.
    #[test]
    fn a_pre_rev_5_4_config_is_refused() {
        let full = config_datum(7, 1_000, 100_000);
        let fields = plutus::constr_fields(&full, 0).unwrap()[..7].to_vec();
        let err = parse_config_datum(&constr(0, fields)).unwrap_err();
        assert!(err.contains("predates"), "{err}");
    }

    /// The nested params record's arity is exact: a fifth slot is a layout this
    /// reader does not know, and half a record is a botched Update.
    #[test]
    fn a_params_record_with_the_wrong_arity_is_rejected() {
        let err = parse_config_datum(&constr(
            0,
            vec![
                constr(1, vec![]),
                bytes(&[0xaa; 28]),
                bytes(&[0xab; 28]),
                bytes(&[0xb5; 28]),
                bytes(&[0xac; 28]),
                bytes(&[0xad; 28]),
                bytes(&[0xae; 28]),
                bytes(&[0xbb; 28]),
                int(600_000),
                int(3),
                int(3_600_000),
                bytes(&[0xc1; 28]),
                bytes(&[0xc2; 28]),
                bytes(b"TMTx"),
                constr(0, vec![int(7), int(1_000), int(100_000)]),
            ],
        ))
        .unwrap_err();
        assert!(err.contains("expected 4"), "{err}");
    }

    /// A wrong-width script hash at #3/#4 is a wrong VALUE, not a shorter one.
    #[test]
    fn a_short_bridge_state_policy_is_rejected() {
        let mut fields = plutus::constr_fields(&config_datum(7, 1, 2), 0)
            .unwrap()
            .to_vec();
        fields[3] = bytes(&[0xb5; 27]);
        let err = parse_config_datum(&constr(0, fields)).unwrap_err();
        assert!(err.contains("bridge_state_policy"), "{err}");
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

    /// The acceptance criterion end to end: two nodes whose `heimdall.toml` fee
    /// rates disagree build BYTE-IDENTICAL Treasury Movements off one Config UTxO —
    /// which is the whole reason the parameters moved on-chain, since FROST signs
    /// the transaction's sighashes and different bytes mean different messages.
    #[test]
    fn two_local_fee_rates_one_config_produce_identical_tm_bytes() {
        use crate::bitcoin::taproot::treasury_spend_info;
        use crate::bitcoin::tm_builder::{
            Freshness, TreasuryInput, btmr1_commitment_script, build_tm,
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
                &Freshness::inert(),
                &crate::bitcoin::tm_builder::FixedCpoRoot([0u8; 32]),
                &crate::bitcoin::tm_builder::FixedSpiRoot([0u8; 32]),
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
                .find(|o| o.script_pubkey != btmr1_commitment_script(&[0u8; 32], &[0u8; 32]))
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
