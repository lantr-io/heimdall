//! TOML configuration file support.
//!
//! `HeimdallConfig` is the root struct deserialized from `heimdall.toml`.
//! Every field has a serde default so a partial or empty file is valid.
//! CLI flags override individual fields after deserialization.

use std::time::Duration;

use serde::Deserialize;

use crate::epoch::state::{EpochConfig, SpoIdentity};

// ── Root ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HeimdallConfig {
    pub protocol: ProtocolConfig,
    pub bitcoin: BitcoinConfig,
    pub cardano: CardanoConfig,
    pub http: HttpConfig,
    pub health: HealthConfig,
    pub demo: DemoConfig,
    pub bifrost: BifrostConfig,
    pub federation: FederationConfig,
    pub log: LogConfig,
}

impl Default for HeimdallConfig {
    fn default() -> Self {
        Self {
            protocol: ProtocolConfig::default(),
            bitcoin: BitcoinConfig::default(),
            cardano: CardanoConfig::default(),
            http: HttpConfig::default(),
            health: HealthConfig::default(),
            demo: DemoConfig::default(),
            bifrost: BifrostConfig::default(),
            federation: FederationConfig::default(),
            log: LogConfig::default(),
        }
    }
}

// ── [log] ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// A bare level (`error`/`warn`/`info`/`debug`/`trace`), which is scoped to
    /// heimdall's own modules, or a full `RUST_LOG` directive such as
    /// `warn,heimdall::cardano=debug` — anything containing `=` or `,` is used
    /// verbatim. Overridden by `--log-level` and `RUST_LOG`.
    pub level: String,
    /// `auto` (journal when systemd captures stdout, else plain), `plain`,
    /// `journal`, or `json`. Overridden by `--log-format` and
    /// `HEIMDALL_LOG_FORMAT`.
    pub format: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "auto".to_string(),
        }
    }
}

// ── [bifrost] ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BifrostConfig {
    /// Path to a `0600` file holding this SPO's 32-byte bifrost identity
    /// secret key, hex-encoded. This is the long-lived secp256k1 key bound
    /// on-chain at registration; the running process needs it to BIP-340
    /// sign published DKG/signing payloads. Required for live participation;
    /// `None` is fine for read-only / air-gapped-registration commands.
    pub skey_path: Option<String>,
    /// This node's own Bifrost endpoint URL — where peers fetch its DKG and
    /// signing rounds from. Used by `register-spo`, which publishes it on chain,
    /// and by `sign-registration`, which signs over it.
    ///
    /// It is an INPUT to registration, not a second copy of a chain value: once
    /// registered, the URL on chain is what peers use and what this node's
    /// listen port comes from. Nothing reads this afterwards.
    ///
    /// Having it here is what makes the two commands agree. The registration
    /// message commits to these exact bytes, so a trailing slash or a different
    /// port between `sign-registration` and `register-spo` silently invalidates
    /// both signatures — one value typed once removes that entirely.
    pub url: Option<String>,
}

impl Default for BifrostConfig {
    fn default() -> Self {
        Self {
            skey_path: None,
            url: None,
        }
    }
}

// ── [federation] ────────────────────────────────────────────────────

/// The federation key ceremony's inputs (WI-087): who is in the federation, and
/// how many of them it takes to sign.
///
/// This is the ONE roster in heimdall that is typed in rather than read from a
/// chain, and it has to be: `Y_federation` is Config #11 and an input to the
/// treasury ADDRESS the genesis anchor is funded at, so it must exist before the
/// bridge does. There is no registry to enumerate, no ban list to filter by and
/// no stake to weight — see [`crate::federation`].
///
/// Every member's node holds the SAME list. Order does not matter: participants
/// are sorted by `bifrost_id_pk` to assign FROST indices, the same lexicographic
/// rule the epoch DKG uses, so every node derives the identical numbering from
/// the same set.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FederationConfig {
    /// FROST threshold `t` of the federation key — how many members it takes to
    /// sign a recovery spend.
    ///
    /// REQUIRED, with no default, and deliberately so: it is baked into the key
    /// at generation and cannot be changed afterwards without re-running the
    /// ceremony and moving the treasury to a new address. A default here would
    /// be a consensus value decided by whoever left a key unset.
    ///
    /// Recommended `n - 1`: one dark member must not brick the path that exists
    /// *because* members can go dark, and it still takes nearly everyone to move
    /// the treasury. `t <= n/2` is accepted but warned about loudly — it lets a
    /// minority sweep the whole treasury once the CSV delay passes.
    pub min_signers: Option<u16>,
    /// Every federation member, including this node. Empty means no federation
    /// is configured (the legacy single-seed deployment).
    pub members: Vec<FederationMemberConfig>,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            min_signers: None,
            members: Vec::new(),
        }
    }
}

/// One federation member: the two facts the ceremony's authenticated transport
/// needs — where to fetch its payloads from, and which key signs them.
///
/// No `pool_id`: a federation member need not be a Cardano SPO, and at genesis
/// there is no registry to look one up in. The transport's 28-byte member
/// address is derived from `bifrost_id_pk` instead (see
/// [`crate::federation::roster`]), so the typed list stays the whole input.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct FederationMemberConfig {
    /// The member's 32-byte x-only secp256k1 identity key, hex.
    pub bifrost_id_pk: String,
    /// Where this member serves its ceremony payloads, e.g.
    /// `https://spo1.example.com`.
    pub bifrost_url: String,
}

// ── [protocol] ──────────────────────────────────────────────────────

/// Upper bound on how long the epoch machine's batch loop sleeps between grid
/// checks ([`EpochConfig::batch_poll_ceiling`]).
///
/// Not an operator key on purpose. It decides read rate and nothing else: the
/// loop sleeps `min(slots until the next opportunity, this)`, and that hop
/// shrinks as the opportunity approaches, so the sleep that lands on it is exact
/// whatever this value is. Every value an operator CAN type is a value two
/// operators can differ on, and this one must not be able to move a freeze point.
/// Five minutes is ~70 grid reads over the spec's 6 h example pitch.
/// Ceiling on the epoch loop's retriable-error backoff. Compiled in for the same
/// reason as [`BATCH_POLL_CEILING`]: it decides a re-read cadence, not a protocol
/// value, and a per-operator copy could only make one node abandon a key handoff
/// sooner than its peers.
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(60);

const BATCH_POLL_CEILING: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProtocolConfig {
    pub dkg_round_timeout_secs: u64,
    /// Ceremony-window grid pitch (N21): a node entering DKG sleeps to the
    /// next `epoch_boundary + k·dkg_window` line so staggered starts and
    /// abort-retries all join the same ceremony schedule. MUST exceed
    /// `dkg_round2_offset_secs` by more than the ~2 s retry backoff — a node
    /// aborting a window must reach the very next grid line, or cohorts one
    /// line apart can cycle phase-locked and never merge.
    pub dkg_window_secs: u64,
    /// Pre-ceremony health gate (N21): how long to wait for the whole DKG
    /// roster to answer `/health` before starting without the missing peers.
    pub dkg_join_wait_secs: u64,
    /// DKG Round 1/2 deadlines as offsets (seconds) from the epoch boundary
    /// (WI-014 #6). Tunable for preprod; the spec budget is ~minutes.
    pub dkg_round1_offset_secs: u64,
    pub dkg_round2_offset_secs: u64,
    /// Settling back-off (seconds) taken instead of the blind exponential when a
    /// DKG fails while THIS node is the stale side of a chain-view disagreement,
    /// so the next chain re-read lands after the disagreeing event settles
    /// (post-ban recovery — see heimdall `EpochConfig::dkg_reconcile_backoff`).
    /// Devnet-tight by default; mainnet wants it near the settlement depth.
    pub dkg_reconcile_backoff_secs: u64,
    pub poll_interval_ms: u64,
    /// Directory for 0600 DKG-state persistence so the signing share survives
    /// restarts for the epoch (WI-014).
    ///
    /// Also the home of the completed-peg-outs trie (`cpo-trie.json`). Unset, the
    /// trie is rebuilt EMPTY on every start and an already-paid peg-out reads as
    /// unpaid — so unset is **refused at startup**, not warned about: see
    /// [`crate::preflight::unset_state_dir`]. `Option` only because the type
    /// predates the refusal; every path that runs a daemon requires it.
    pub state_dir: Option<String>,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            dkg_round_timeout_secs: 300,
            dkg_window_secs: 600,
            dkg_join_wait_secs: 300,
            dkg_round1_offset_secs: 120,
            dkg_round2_offset_secs: 240,
            dkg_reconcile_backoff_secs: 30,
            poll_interval_ms: 5000,
            state_dir: None,
            // 7 days. Large enough that a request selected now cannot reach its
            // 30-day cancel deadline before the TM confirms, even after a long
            // Bitcoin fee-market stall; small enough that a request stays payable
            // for most of its life.
        }
    }
}

// ── [bitcoin] ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BitcoinConfig {
    /// `"regtest"`, `"testnet4"`, `"signet"`, `"mainnet"`.
    pub network: String,
    /// **DEV OVERRIDE.** Bitcoin miner fee rate (sat/vB) for the paths that cannot
    /// read the chain's: the single-signer admin spends (`treasury-self-send`,
    /// `federation-spend`), the mock/fixture demo, and a deployment whose Config
    /// UTxO is unset or predates the operational-parameter fields.
    ///
    /// A production TM does NOT read this. Since WI-040 the fee rate is Config
    /// datum params record (field 7), read from the Config UTxO at the batch snapshot slot
    /// (`cardano::config_params`): it multiplies into the treasury change output, so
    /// two SPOs holding different values sign different bytes and the FROST round
    /// cannot converge. `show-config-params` reports which of the two is in force.
    pub fee_rate_sat_per_vb: u64,
    /// **DEV OVERRIDE.** Per-peg-out protocol fee (satoshi) this node's own
    /// `pegout-request` CLI pins into a request it creates, and the fee the demo
    /// `StaticFixture` peg-outs carry.
    ///
    /// A real TM does NOT read this — in either of its two roles. The fee it PAYS is
    /// the one each PegOut request pins in its own datum (rev 5.1): `peg-out.ak`
    /// binds the completed-peg-outs trie value against THAT value, so a TM paying
    /// `gross − some_local_config` would produce an entry the Complete branch cannot
    /// match, spending BTC for a completion nobody can prove. The FLOOR that fee
    /// must clear is the Config's `params[2]`, read at the batch snapshot slot — a
    /// skip rule, so it too must be identical across SPOs.
    pub per_pegout_fee_sat: u64,
    /// Relative-timelock delay (blocks) of the treasury's federation recovery
    /// leaf. `None` = take it from the `treasury_info` datum, which is where a
    /// bridge with a readable registry identity publishes it (WI-069).
    ///
    /// It defaulted to 144, and that was the bug: it is an input to the treasury
    /// ADDRESS, so a node that left it alone did not fail — it derived a
    /// well-formed address nobody else was using. Setting it against a chain that
    /// publishes a different value is now fatal, not silently preferred.
    pub federation_csv_blocks: Option<u32>,
    /// 32-byte hex seed for the Y_federation key. `None` = take the derived
    /// PUBLIC key from the `treasury_info` datum (WI-069).
    ///
    /// This is a SPENDING SECRET, not an identifier: `federation-spend` signs the
    /// treasury's recovery path with it, which is why the chain carries only the
    /// public half. Keep it set on a node that performs federation operations —
    /// there it also cross-checks the published key, the one check no other
    /// reader can make, and a disagreement is fatal. On every other node it
    /// should be absent.
    pub y_fed_seed_hex: Option<String>,
    /// Optional bitcoind JSON-RPC endpoint, read by the `depositor` tool ALONE.
    ///
    /// Nothing in heimdall proper reads it. Every Bitcoin fact reaches heimdall
    /// through Cardano (PIR datums carry the raw deposit txs, UnconfirmedTm records
    /// carry the raw TMs, the bridge-state singleton carries the treasury head), and
    /// heimdall never sends a transaction to Bitcoin (WI-086) — it prints signed
    /// bytes and a watchtower, or `bitcoin-cli`, sends them. The depositor is the one
    /// exception because it READS the UTxO set to choose funding inputs, which no
    /// amount of piping replaces; `--funding-txid`/`--funding-vout`/
    /// `--funding-amount-sat` let even it run without a node.
    pub rpc_url: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,
    /// Depositor refund timelock (BTC blocks) in the peg-in Taproot's refund leaf.
    ///
    /// OPTIONAL, and no default — [CFG-9] publishes it in the Config as
    /// `params[8]`, so a correctly configured node leaves this unset and reads the
    /// bridge's value. Set, it becomes a CROSS-CHECK and a disagreement with the
    /// published value is FATAL, exactly like `federation_csv_blocks` beside it.
    ///
    /// It used to be a plain `u16` defaulting to 4320, which is the worst shape for
    /// a value every SPO must agree on byte for byte: a node that simply never set
    /// the key silently diverged from one that did, the two reconstructed different
    /// deposit addresses, froze different peg-in sets, and the ceremony stalled with
    /// nothing naming the cause.
    pub pegin_refund_timeout_blocks: Option<u16>,
    /// Opt-in staleness deadline (seconds). An Unconfirmed TM still on-chain this
    /// long after its Cardano block (chain time − block time) is treated as DEAD —
    /// it never confirmed, so it stops blocking the tip and reserving its peg-ins.
    /// Catches never-confirmable movements heimdall can't otherwise see (a peg-in
    /// refunded/spent outside a Confirmed TM). `None` = disabled (block forever).
    /// MUST exceed the worst-case confirmation time (oracle maturation window +
    /// margin) so a live movement always confirms before the deadline.
    pub inflight_deadline_secs: Option<u64>,
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            network: "regtest".to_string(),
            fee_rate_sat_per_vb: 1,
            per_pegout_fee_sat: 1000,
            // No defaults, deliberately (WI-069): both are inputs to the
            // treasury address, so a guessed value produces a well-formed
            // address holding nothing rather than an error. Unset means "read
            // the treasury_info datum".
            federation_csv_blocks: None,
            y_fed_seed_hex: None,
            rpc_url: None,
            rpc_user: None,
            rpc_pass: None,
            pegin_refund_timeout_blocks: None,
            inflight_deadline_secs: None,
        }
    }
}

impl BitcoinConfig {
    pub fn parsed_network(&self) -> bitcoin::Network {
        match self.network.as_str() {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet4" => bitcoin::Network::Testnet4,
            "signet" => bitcoin::Network::Signet,
            "regtest" => bitcoin::Network::Regtest,
            other => panic!("unknown bitcoin.network: {other:?}"),
        }
    }
}

// ── [cardano] ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CardanoConfig {
    pub blockfrost_project_id: Option<String>,
    /// Custom Blockfrost-compatible API base URL — a local Dolos or a
    /// yaci-devkit devnet (`http://localhost:8080/api/v1`). None → public
    /// blockfrost.io.
    ///
    /// The intended production shape is heimdall → Dolos → your own node, so
    /// an SPO's bridge duties do not depend on a third-party API. Setting
    /// this makes [`CardanoConfig::network`] mandatory: see
    /// [`CardanoConfig::is_mainnet`].
    pub blockfrost_url: Option<String>,
    /// Which Cardano network this node is on: `"mainnet"`, `"preprod"`,
    /// `"preview"` or `"testnet"`.
    ///
    /// Optional only when talking to hosted blockfrost.io, where the
    /// project-id prefix already identifies the network. Required alongside
    /// [`CardanoConfig::blockfrost_url`] — see [`CardanoConfig::is_mainnet`].
    pub network: Option<String>,
    /// Kupo base URL, e.g. `http://localhost:1442`. OPTIONAL.
    ///
    /// Used ONLY to rebuild the completed-peg-outs trie from chain history
    /// (`reconstruct-cpo-trie`): that read wants the inline datums of already-SPENT
    /// outputs, which a Blockfrost-compatible UTxO-set API cannot serve. Steady-state
    /// operation never touches it, so a node with a healthy `cpo-trie.json` runs
    /// without Kupo configured.
    ///
    /// Set → reconstruction reads Kupo. Unset → it falls back to the
    /// Blockfrost-compatible transaction-history endpoints
    /// (`blockfrost_project_id`). Both produce the same trie under the same
    /// checks, but a production SPO SHOULD run Kupo: it answers a whole address
    /// history in one request, whereas the Blockfrost path issues roughly one
    /// request per transaction that ever touched the address. See
    /// `cardano::cpo_history`.
    pub kupo_url: Option<String>,
    pub socket_path: Option<String>,
    pub network_magic: Option<u64>,
    pub mnemonic: Option<String>,
    /// Path to this pool's Ed25519 COLD signing key, used by `register-spo`
    /// (and revocation) when `--cold-skey` is not given.
    ///
    /// NO default, deliberately. The cold key's whole design is minimal exposure
    /// — registration and revocation, nothing else — and heimdall can register
    /// without it ever being on this machine at all (`--cold-vkey` +
    /// `--cold-sig`, signed elsewhere). A well-known default path would make the
    /// weaker route the normal one, and a default that RESOLVED would mean
    /// heimdall silently signing with a key nobody named in this file.
    ///
    /// Unset therefore means "the cold key is not on this machine", which is the
    /// state a careful operator is in, not a missing setting. The daemon never
    /// reads it under any flag — only an explicit one-shot command does.
    pub cold_skey_path: Option<String>,
    /// Path to this pool's Ed25519 cold VERIFICATION key (`cold.vkey`), used by
    /// `register-spo` when `--cold-vkey` is not given.
    ///
    /// The public half, and the one a node keeps in the air-gapped flow: the
    /// signature comes from the machine that holds `cold.skey`, while the node
    /// needs only this to derive the pool id and check what it was handed. A
    /// Cardano TextEnvelope is accepted as-is; so is raw 32-byte hex.
    ///
    /// Unlike [`Self::cold_skey_path`] this is not a secret, so setting it on a
    /// networked node costs nothing.
    pub cold_vkey_path: Option<String>,
    /// register_spo R2 min-stake threshold (lovelace). A registering pool's
    /// `active_stake` must be `>=` this to build register_spo / join the DKG
    /// candidate set. `None` → no gate configured.
    ///
    /// A LOCAL operational policy: rev 5.4 removed `min_stake` from the Config
    /// datum (it never had an on-chain reader — it gated this registration
    /// off-chain only), so there is no chain value to defer to any more.
    pub min_stake_lovelace: Option<u64>,
    /// Where the DKG roster threshold + R2 gate read per-pool active stake.
    /// `None`/`"blockfrost"` (default) → Blockfrost `/pools/{id}.active_stake`
    /// (preprod/mainnet). `"yaci_store"` → a local yaci-devkit devnet, which
    /// has no `/pools/{id}`; stake is read from
    /// `/epochs/{epoch}/pools/{id}/stake`. See `cardano::stake::StakeSource`.
    pub stake_source: Option<String>,
    /// DEMO-ONLY. When true, an eligible registered SPO whose Cardano stake
    /// cannot be resolved (404 / retired / not a real stake pool) is *excluded*
    /// from the DKG roster instead of making the whole stake-weighted derivation
    /// fatal (`MissingStake`). Lets a screencast run the registry-driven DKG over
    /// the real-stake pools while a legacy synthetic SPO sits in the registry.
    /// Default false — production must never silently drop a registered member.
    pub demo_exclude_unstaked: bool,
    /// TEST-RUN ONLY. Weight the DKG roster by `live_stake` instead of the
    /// epoch-snapshot `active_stake`.
    ///
    /// Cardano activates a newly registered pool's stake only two epoch
    /// boundaries later, so on preprod a tester who registers an SPO weighs ZERO
    /// for about ten days and cannot meaningfully take part in a ceremony. This
    /// makes the delegation count from the moment it lands.
    ///
    /// It is a CONSENSUS input, and `cardano::stake`'s module doc explains why the
    /// production path does not do this: `live_stake` drifts continuously, so two
    /// SPOs reading seconds apart derive different weights, a different threshold
    /// and a ceremony that never aggregates. Every node of the roster must
    /// therefore set it identically. A mismatch is published on `/health` and
    /// caught by the pre-ceremony handshake — the peer is named and left out
    /// before anything is generated, rather than the roster discovering it as a
    /// stalled ceremony — and the flag is refused outright on mainnet.
    ///
    /// Default false. Never set it on a bridge holding real funds.
    pub demo_live_stake: bool,
    /// TEST-RUN ONLY. Run the bridge's cycle on a VIRTUAL epoch of this many
    /// Cardano slots instead of the real five-day one.
    ///
    /// A test bridge cannot otherwise exercise a key rotation faster than one
    /// Cardano epoch, because the DKG, the Update-Y and the whole batch grid hang
    /// off `epoch_start`. With this set the cycle is `tip_slot / slots`, anchored
    /// at slot 0 so no anchor has to be agreed, and the Config `schedule` is
    /// rescaled in proportion — see [`crate::epoch::virtual_epoch`].
    ///
    /// It is a CONSENSUS input, and the most total one in this file: the DKG
    /// namespace is `(epoch, threshold, attempt)`, so two nodes on different
    /// cycles publish into namespaces that never fetch each other and each waits
    /// for a ceremony the other cannot see. Every node of the roster must set it
    /// identically; a mismatch is caught in the pre-ceremony handshake and named,
    /// and the flag is refused outright on mainnet.
    ///
    /// Unset (the default) means real Cardano epochs. Never set it on a bridge
    /// holding real funds.
    pub demo_virtual_epoch_slots: Option<u64>,
    /// Whether to publish an oracle-update UTxO to Cardano after signing.
    /// Requires `blockfrost_project_id` and `mnemonic`. Default: true.
    pub submit_oracle: bool,
    /// Validity window (seconds) for posted TM txs (`invalid_hereafter`/`created` = latest +
    /// window). `None` → 1800 (preprod/mainnet). MUST be small (e.g. 90) on a short-epoch
    /// devnet, whose era-forecast horizon is only ~tens-to-hundreds of slots ahead — a large
    /// window lands past it (TimeTranslationPastHorizon at submit).
    pub tm_validity_window_secs: Option<u64>,
    /// Bech32 address of the bridge Config UTxO (the config script address, from
    /// `binocular deploy-bridge`). The Config UTxO's field 3 (bridge_state_policy)
    /// locates the bridge-state singleton whose head is the current treasury
    /// outpoint; every TM mint references both UTxOs.
    ///
    /// It also carries the **operational parameters** (the nested field-7 record)
    /// every TM is built from, so setting this + [`Self::config_nft_policy_id`]
    /// is what moves a node off its local `bitcoin.fee_rate_sat_per_vb` and onto the value its
    /// co-signers use — see `cardano::config_params` and `show-config-params`.
    pub config_address: Option<String>,
    /// Config NFT policy id (56 hex chars) locating the Config UTxO. Required
    /// alongside `config_address`.
    pub config_nft_policy_id: Option<String>,
    /// Config NFT asset name (hex). Required alongside `config_nft_policy_id`.
    pub config_nft_asset_name: Option<String>,
    /// Path to the bifrost Aiken blueprint (plutus.json) holding the compiled
    /// spos_registry + treasury_info validators. An OVERRIDE since WI-066: the
    /// blueprint is embedded in the binary, so leaving this unset is normal.
    pub registry_blueprint: Option<String>,
    /// The one-shot outpoint `<tx_hash>:<index>` that parameterizes EVERY
    /// federation script — `spos_registry`, `spo_bans` and the three DKG fault
    /// verifiers — together with the Config NFT policy id ([PRE-3]).
    ///
    /// NOT an operator key: `#[serde(skip)]`, so no TOML file can set it. It is
    /// filled from Config #12 (WI-090). It used to be three separate typed keys
    /// — `registry_bootstrap`, `treasury_bootstrap`, `ban_bootstrap` — which
    /// were the SAME value on every bridge `deploy-bridge` stood up, since all
    /// three genesis mints share one outpoint, so an operator typed one number
    /// three times and any two of them could disagree.
    ///
    /// Rev 5.5 runs the derivation Config → treasury → registry (it used to run
    /// registry → treasury, which made the dependency a cycle and the [REG-6]
    /// pin impossible), so this one value feeds every step.
    #[serde(skip)]
    pub federation_one_shot: Option<String>,
    /// The authorized fault-verifier policy ids (hex), in the exact order the
    /// deployed `spo_bans` was parameterized with. The contract's
    /// `ban_config_ok` requires **exactly 3 distinct** policies, and they are
    /// baked into the ban policy id — a wrong/missing entry derives the wrong
    /// ban address (and a silently empty ban list). Required alongside
    /// `ban_bootstrap`.
    pub fault_proof_policies: Vec<String>,
    /// Reference-script UTxO `<tx_hash>:<index>` carrying the `spo_bans`
    /// validator. Required for automatic DKG fault banning because ApplyBan
    /// uses the script through withdraw/spend/mint paths.
    pub spo_bans_ref: Option<String>,
    /// Reference-script UTxOs `<tx_hash>:<index>` for the three specialized
    /// fault verifier policies. The Round 1 and Round 2 publish transactions
    /// do not fit reliably when the verifier script is embedded.
    pub fault_verifier_round1_ref: Option<String>,
    pub fault_verifier_round2_ref: Option<String>,
    pub fault_verifier_equivocation_ref: Option<String>,
    /// Path to a trusted BLS12-381 KZG SRS file serialized with the Axiom Halo2
    /// `ParamsKZG::write_custom(..., SerdeFormat::Processed)` format. Required
    /// for automatic Round 1/Round 2 DKG fault proof generation.
    pub fault_proof_srs_path: Option<String>,
}

impl CardanoConfig {
    /// The values this node must agree with its peers about and publishes on
    /// `/health`, as of configuration alone.
    ///
    /// All four decide the roster or the epoch it is derived for, and none of
    /// them is on chain — so a difference is invisible until a ceremony fails to
    /// converge. Derivable from process start, deliberately: the peer server is
    /// listening long before the first ceremony entry, and a peer that reads
    /// these as absent while this node is still booting would exclude it for
    /// running settings it does not have.
    ///
    /// An unparseable `stake_source` reports `None` rather than a guess — the
    /// daemon refuses to start on one anyway, and a wrong label here would be
    /// worse than an absent one.
    #[must_use]
    pub fn node_facts(&self) -> crate::http::compat::NodeFacts {
        crate::http::compat::NodeFacts {
            virtual_epoch_slots: self.demo_virtual_epoch_slots,
            live_stake: Some(self.demo_live_stake),
            stake_source: crate::cardano::stake::StakeSource::from_config(
                self.stake_source.as_deref(),
            )
            .ok()
            .map(crate::cardano::stake::StakeSource::label),
            exclude_unstaked: Some(self.demo_exclude_unstaked),
            epoch: None,
            threshold: None,
        }
    }
}

impl ProtocolConfig {
    /// How far into a cycle a node can first ENTER a ceremony, in Cardano slots.
    ///
    /// `next_window` puts the earliest join at `cycle_start + dkg_window`, and a
    /// node then waits up to `dkg_join_wait` for the roster's health gate. Slots
    /// are one second post-Shelley, so the seconds convert directly.
    ///
    /// Only a virtual epoch consults it (see
    /// [`crate::epoch::virtual_epoch::EpochScheme::schedule`]): on a real epoch
    /// every deadline is days away and the floor cannot bind.
    #[must_use]
    pub fn ceremony_floor_slots(&self) -> u64 {
        self.dkg_window_secs.saturating_add(self.dkg_join_wait_secs)
    }
}

impl Default for CardanoConfig {
    fn default() -> Self {
        Self {
            blockfrost_project_id: None,
            blockfrost_url: None,
            network: None,
            kupo_url: None,
            socket_path: None,
            network_magic: None,
            mnemonic: None,
            cold_skey_path: None,
            cold_vkey_path: None,
            min_stake_lovelace: None,
            stake_source: None,
            demo_exclude_unstaked: false,
            demo_live_stake: false,
            demo_virtual_epoch_slots: None,
            submit_oracle: true,
            tm_validity_window_secs: None,
            config_address: None,
            config_nft_policy_id: None,
            config_nft_asset_name: None,
            registry_blueprint: None,
            federation_one_shot: None,
            fault_proof_policies: Vec::new(),
            spo_bans_ref: None,
            fault_verifier_round1_ref: None,
            fault_verifier_round2_ref: None,
            fault_verifier_equivocation_ref: None,
            fault_proof_srs_path: None,
        }
    }
}

impl CardanoConfig {
    /// This config with [`Self::federation_one_shot`] filled in from `one_shot`,
    /// unless it already carries one.
    ///
    /// Already-set WINS, so an explicit `--registry-bootstrap` still overrides
    /// the chain — the one case that needs it is deriving a script for a bridge
    /// whose Config you are not reading (recovery, or a deploy in progress).
    #[must_use]
    pub fn with_one_shot(&self, one_shot: &str) -> Self {
        let mut out = self.clone();
        if out.federation_one_shot.is_none() {
            out.federation_one_shot = Some(one_shot.to_string());
        }
        out
    }

    /// This config with [`Self::federation_one_shot`] taken from an
    /// AUTHENTICATED Config datum (#12). The ordinary path: every federation
    /// script hash derives from this one value, and it reaches a node by being
    /// published rather than typed (WI-090).
    #[must_use]
    pub fn with_published_one_shot(
        &self,
        config: Option<&crate::cardano::config_params::ConfigParams>,
    ) -> Self {
        match config {
            Some(p) => self.with_one_shot(&p.federation_one_shot),
            None => self.clone(),
        }
    }

    /// Whether this node is on Cardano mainnet.
    ///
    /// Explicit `cardano.network` is authoritative. Without it the network is
    /// inferred from the Blockfrost project-id prefix — which identifies the
    /// network only because a hosted blockfrost.io key encodes it.
    ///
    /// That inference breaks against a local Blockfrost-compatible backend
    /// (Dolos, yaci-devkit), where the project id is a placeholder the backend
    /// may ignore entirely. Inferring there would silently answer "testnet" on
    /// a mainnet node: every derived script address would carry a testnet
    /// bech32 prefix, and the fault-proof SRS gate would fail open. So when
    /// `cardano.blockfrost_url` is set, `cardano.network` is required rather
    /// than guessed.
    pub fn is_mainnet(&self) -> Result<bool, String> {
        if let Some(network) = self.network.as_deref() {
            let mainnet = match network {
                "mainnet" => true,
                "preprod" | "preview" | "testnet" => false,
                other => {
                    return Err(format!(
                        "unknown cardano.network {other:?} — expected \"mainnet\", \
                         \"preprod\", \"preview\" or \"testnet\""
                    ));
                }
            };
            // Cross-check against the bridge itself. This value is the network
            // TAG of every address this node derives, and it is the last input to
            // those addresses still taken purely from local config — so a typo
            // does not error, it produces a well-formed address on the other
            // network that holds nothing. Where the roster and the ban list are
            // concerned, "holds nothing" reads as "nobody is registered" and
            // "nobody is banned", which is silent and wrong.
            //
            // The Config UTxO's own bech32 address is the bridge's own statement
            // of which network it is on, so any disagreement is decisive.
            if let Some(addr) = self.config_address.as_deref() {
                let addr_mainnet = addr.starts_with("addr1") || addr.starts_with("stake1");
                let addr_testnet =
                    addr.starts_with("addr_test1") || addr.starts_with("stake_test1");
                if (addr_mainnet || addr_testnet) && addr_mainnet != mainnet {
                    return Err(format!(
                        "cardano.network = {network:?} disagrees with cardano.config_address \
                         {addr}, which is {} — every address this node derives (the registry, \
                         the ban list, treasury_info) would carry the wrong network tag and \
                         resolve to a valid-looking address holding nothing at all",
                        if addr_mainnet { "mainnet" } else { "a testnet" }
                    ));
                }
            }
            return Ok(mainnet);
        }
        if self.blockfrost_url.is_some() {
            return Err(
                "cardano.network is required when cardano.blockfrost_url is set: the \
                 project-id prefix identifies the network only for hosted blockfrost.io, \
                 and a local backend (Dolos, yaci-devkit) may ignore the project id \
                 entirely. Set cardano.network = \"mainnet\" | \"preprod\" | \"preview\" \
                 | \"testnet\"."
                    .to_string(),
            );
        }
        Ok(self
            .blockfrost_project_id
            .as_deref()
            .is_some_and(|p| p.starts_with("mainnet")))
    }
}

// ── [http] ──────────────────────────────────────────────────────────

/// The OPERATOR-facing health surface (WI-058).
///
/// Separate from [`HttpConfig`] on purpose, and the separation is the point:
/// that one is the peer protocol, its address is on chain, and everyone can
/// reach it. This one reports operator state — registration, ceremony
/// participation, grid position — and defaults to loopback so it is reachable by
/// the machine's own monitoring and nobody else.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HealthConfig {
    /// `address:port` for the operator surface. Loopback by default; point it at
    /// a LAN address only if you mean to, since nothing here authenticates.
    pub bind: String,
    /// Turn the surface off entirely. `heimdall status` then reports only the
    /// static half — the startup checks — and says the live half is unavailable.
    pub enabled: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:18580".to_string(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    /// Local interface to bind. Defaults to `0.0.0.0`, because the peer endpoint
    /// is public by construction — its URL is on chain and every other SPO has to
    /// fetch this node's DKG rounds from it. Narrow it (to a specific NIC, or to
    /// loopback behind a reverse proxy) when you have a reason to.
    pub bind_address: String,
    /// Local port to bind, when it must differ from the one in this node's
    /// registered `bifrost_url`.
    ///
    /// The registered URL is the ADVERTISED address — it is on chain and peers
    /// fetch from it. Unset, the node also listens on the port inside that URL,
    /// which forces the public and local ports to be the same number and leaves
    /// no room for a reverse proxy. Set this and the two become independent:
    /// register `https://spo.example.com`, terminate TLS at nginx, and have
    /// heimdall listen on `127.0.0.1:18500`.
    pub listen_port: Option<u16>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            listen_port: None,
        }
    }
}

// ── [demo] ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DemoConfig {
    pub min_signers: u16,
    pub max_signers: u16,
    /// The local fixture roster hands simulated SPO `i` the port
    /// `base_port + i - 1`, so several can share one machine. Demo only — a
    /// registered node takes its port from `http.listen_port` or from the port
    /// in its own registered `bifrost_url`.
    pub base_port: u16,
}

impl Default for DemoConfig {
    fn default() -> Self {
        Self {
            min_signers: 2,
            max_signers: 3,
            base_port: 18500,
        }
    }
}

/// Keys the bridge Config publishes, and which heimdall therefore refuses.
///
/// The ban schedule is not an operator setting and never was: the three values
/// are INPUTS to the `spo_bans` policy id, so a node cannot derive the address it
/// would read them from without already having them, and one wrong digit derives
/// a ban address no deployment has — a silently EMPTY ban list, with banned SPOs
/// back in the roster and nothing in any log. That had already happened in three
/// checked-in fixtures. The Config publishes them at `params[4..6]`, authenticated
/// by the Config NFT, so every SPO reads the same numbers or none at all.
///
/// `(section, key, what replaced it)`.
pub type RetiredKey = (&'static str, &'static str, &'static str);

const RETIRED_KEYS: &[RetiredKey] = &[
    // WI-097: the peg-in freeze is the batch grid's, so a local timer in front of
    // it could only be a second freeze rule that disagrees — two nodes entering
    // the window at different moments accumulated different unions of the same
    // source, and the later of the two also delayed every batch by its own value.
    (
        "protocol",
        "pegin_collection_window_secs",
        "the Config schedule's tm_batch_interval — the freeze point is the batch opportunity B_i, \
         not a local timer",
    ),
    (
        "protocol",
        "pegin_poll_interval_ms",
        "nothing — the peg-in source is read once, at the batch opportunity",
    ),
    // WI-032: the machine no longer waits for the confirmation, so there is no
    // deadline to set. It could never be set correctly anyway — the confirmation
    // is ~100 Bitcoin blocks plus the oracle's challenge-aging window away, so any
    // workable value wedged the node and any honest one blocked the batch loop for
    // most of a day. The wait it nominally guarded is redundant: the batch gate
    // already refuses to build while a movement is in flight.
    (
        "protocol",
        "tm_confirmation_timeout_secs",
        "nothing — a posted movement is recorded in state_dir/pending-tm.json and folded into the \
         tries when the chain shows the head has moved, however long that takes",
    ),
    // WI-071: a TM SELECTION rule, so it decides the TM bytes — two operators on
    // different values freeze different peg-out sets and their FROST round never
    // converges, with neither log able to say why. Compiled in for good, not
    // pending a Config field: publishing it was proposed and rejected, because
    // nothing outside heimdall reads the value and divergence costs liveness
    // rather than safety. The reasoning is beside the constant.
    (
        "protocol",
        "pegout_freshness_margin_ms",
        "the compiled-in PEG_OUT_FRESHNESS_MARGIN_MS (7 days) — a TM selection rule is not an \
         operator setting",
    ),
    // WI-090: the federation one-shot outpoint, typed three times under three
    // names. All three were the SAME value on any bridge `deploy-bridge` stood
    // up — the genesis mints share one outpoint — so the only thing three keys
    // could add was a disagreement between them. Config #12 publishes it.
    (
        "cardano",
        "registry_bootstrap",
        "Config #12 (federation_one_shot)",
    ),
    (
        "cardano",
        "treasury_bootstrap",
        "Config #12 (federation_one_shot) — the same outpoint as registry_bootstrap",
    ),
    (
        "cardano",
        "ban_bootstrap",
        "Config #12 (federation_one_shot) — the same outpoint again",
    ),
    // WI-HJ1N5: the TM validator's own bytes. The one artifact left on the
    // posting path that an operator pasted in, and the one whose absence was
    // silent — a node without it passed all 8 preflight steps, ran a full signing
    // ceremony, and only then could not post the movement it had just signed.
    // Config #5 names the script and the chain holds it, so nothing is typed.
    (
        "cardano",
        "tm_script_cbor",
        "Config #5 (tm_script_hash) — the validator is fetched from the chain by that hash and \
         refused unless blake2b224(0x03 || cbor) equals it",
    ),
    // WI-070: the bridge's own identifiers. Every one was an operator-typed copy
    // of a Config field, and a copy that can disagree is the whole defect — a
    // mistyped script hash yields a well-formed address holding nothing, which
    // reads as "nothing pending" while the node keeps signing.
    (
        "cardano",
        "pegin_script_address",
        "Config #6 (peg_in_script_hash), as an enterprise address",
    ),
    (
        "cardano",
        "pegin_policy_id",
        "Config #6 (peg_in_script_hash)",
    ),
    (
        "cardano",
        "pegout_script_address",
        "Config #7 (peg_out_script_hash), as an enterprise address",
    ),
    (
        "cardano",
        "bridged_token_unit",
        "Config #2 (bridged_token_policy) ++ the \"fSAT\" constant",
    ),
    (
        "cardano",
        "cpo_policy_id",
        "Config #4 (bridge_state_policy)",
    ),
    (
        "cardano",
        "treasury_address",
        "Config #5 (tm_script_hash), as an enterprise address",
    ),
    (
        "cardano",
        "treasury_policy_id",
        "Config #5 (tm_script_hash)",
    ),
    (
        "cardano",
        "treasury_asset_name",
        "nothing — the TM state token's name is the empty protocol constant, not a per-bridge \
         value",
    ),
    (
        "cardano",
        "treasury_info_asset_name",
        "nothing — the treasury_info NFT's name is the [CFG-4] constant \"BFRTRY\"",
    ),
    (
        "bitcoin",
        "submit",
        "nothing — heimdall never sends a transaction to Bitcoin (WI-086). It prints the \
         signed bytes; a watchtower relays them from the UnconfirmedTm record, or you send \
         them with `bitcoin-cli sendrawtransaction`",
    ),
    (
        "cardano",
        "base_ban_duration_ms",
        "Config params[4] (base_ban_duration_ms)",
    ),
    (
        "cardano",
        "max_faults_before_permanent",
        "Config params[5] (max_faults_before_permanent)",
    ),
    (
        "cardano",
        "max_validity_window_ms",
        "Config params[6] (max_validity_window_ms)",
    ),
    (
        "protocol",
        "quorum51_timeout_secs",
        "Config params[0].sign_r1_window / sign_r2_window — the FROST round deadlines are absolute \
         slots off the batch opportunity, so that every SPO closes the signing subset S1 at the \
         same moment. A per-operator timeout decided MEMBERSHIP of S1 once WI-047 made the round \
         proceed on a threshold, and two operators on different values disagree silently (WI-077)",
    ),
    (
        "protocol",
        "leader_timeout_secs",
        "Config params[0].leader_slot_t — the cascade hop is slot arithmetic on a value the \
         bridge publishes, and every SPO must step through the roster together. A per-operator \
         timeout would have each node decide on its own when its turn began (WI-104)",
    ),
];

/// The retired keys this document still sets, in the order listed above.
fn retired_keys_in(doc: &toml::Value) -> Vec<RetiredKey> {
    RETIRED_KEYS
        .iter()
        .filter(|(section, key, _)| {
            doc.get(*section)
                .and_then(toml::Value::as_table)
                .is_some_and(|t| t.contains_key(*key))
        })
        .copied()
        .collect()
}

// ── Loading ─────────────────────────────────────────────────────────

impl HeimdallConfig {
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.display().to_string(), e))?;
        Self::from_toml_str(&contents).map_err(|e| e.with_path(path.display().to_string().as_str()))
    }

    /// Parse a `heimdall.toml`, REFUSING any key the bridge Config now publishes.
    ///
    /// The check runs before deserialization so the diagnostic can name the key
    /// and its replacement. Refusing rather than ignoring is the point: a key
    /// that silently does nothing leaves the operator believing a value they
    /// typed is in force, which is the same failure in a quieter form.
    pub fn from_toml_str(contents: &str) -> Result<Self, ConfigError> {
        let doc: toml::Value =
            toml::from_str(contents).map_err(|e| ConfigError::Parse(String::new(), e))?;
        let retired = retired_keys_in(&doc);
        if !retired.is_empty() {
            return Err(ConfigError::RetiredKeys(retired));
        }
        let cfg: Self = doc
            .try_into()
            .map_err(|e| ConfigError::Parse(String::new(), e))?;
        cfg.refuse_test_flags_on_mainnet()?;
        Ok(cfg)
    }

    /// Refuse a test-run flag on a network holding real funds.
    ///
    /// `cardano.demo_live_stake` weights the DKG roster by a value that drifts
    /// intra-epoch. On a test bridge that is a deliberate trade for not waiting two
    /// epoch boundaries; on mainnet it is a threshold no two SPOs agree on, so it
    /// is refused at load rather than warned about — a warning in a unit's journal
    /// is not something an operator reads before the first ceremony fails.
    fn refuse_test_flags_on_mainnet(&self) -> Result<(), ConfigError> {
        // Unresolvable is not "no". `is_mainnet` errs on an unrecognised network
        // string, on a network/config_address disagreement, and on `network` unset
        // beside a `blockfrost_url` — and `unwrap_or(false)` would read every one of
        // those as "not mainnet", so `network = "Mainnet"` would carry a
        // consensus-breaking test flag onto a real-funds bridge. preflight.rs
        // documents this exact bug being fixed on the sibling guard; do not
        // reintroduce it here. Hold to the answer that cannot be ruled out.
        // The value's own sanity, checked here rather than at first use: a
        // zero-slot or longer-than-an-epoch cycle is a typo, and finding out at
        // the first ceremony means finding out five days late.
        if let Err(why) = crate::epoch::virtual_epoch::EpochScheme::from_slots(
            self.cardano.demo_virtual_epoch_slots,
        ) {
            return Err(ConfigError::UnusableVirtualEpoch(why));
        }
        let mainnet = self.cardano.is_mainnet().unwrap_or(true);
        if self.cardano.demo_virtual_epoch_slots.is_some() && mainnet {
            return Err(ConfigError::TestFlagOnMainnet(
                "cardano.demo_virtual_epoch_slots runs the bridge on a virtual epoch shorter \
                 than Cardano's. It exists so a test bridge can exercise a rotation without \
                 waiting five days, and it renumbers the epoch every ceremony binds to — on a \
                 real-funds bridge that is a roster split, not a speed-up. If this is NOT a \
                 mainnet node, cardano.network could not be resolved — an unknown spelling, or \
                 a network that disagrees with cardano.config_address — and an unresolvable \
                 network is treated as mainnet here rather than waved through",
            ));
        }
        if self.cardano.demo_live_stake && mainnet {
            return Err(ConfigError::TestFlagOnMainnet(
                "cardano.demo_live_stake weights the DKG roster by live_stake, which drifts \
                 intra-epoch — two SPOs reading moments apart derive different thresholds and \
                 the ceremony cannot aggregate. It exists so a test SPO need not wait two epoch \
                 boundaries for its stake to activate, and has no place on mainnet. If this \
                 is NOT a mainnet node, cardano.network could not be resolved — an unknown \
                 spelling, or a network that disagrees with cardano.config_address — and an \
                 unresolvable network is treated as mainnet here rather than waved through",
            ));
        }
        Ok(())
    }

    /// Load this SPO's bifrost identity keypair from `[bifrost].skey_path`.
    /// Errors if the path is unset or (on unix) the key file is readable by
    /// group/other.
    pub fn load_bifrost_keypair(
        &self,
        secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Result<bitcoin::secp256k1::Keypair, ConfigError> {
        let path = self
            .bifrost
            .skey_path
            .as_deref()
            .ok_or(ConfigError::MissingBifrostKey)?;
        load_bifrost_keypair_from(secp, std::path::Path::new(path))
    }

    /// Build an `EpochConfig` from the merged configuration plus the
    /// per-instance identity.
    ///
    /// `pegin_policy_id` is a parameter rather than a config key since WI-070:
    /// it is Config #6, so the caller — which has already read the Config to get
    /// here — supplies it. `[0u8; 28]` is the mock/fixture value, where there is
    /// no bridge and nothing to scan for.
    pub fn to_epoch_config(&self, identity: SpoIdentity, pegin_policy_id: [u8; 28]) -> EpochConfig {
        EpochConfig {
            health: crate::health::HealthHandle::new(),
            dkg_round_timeout: Duration::from_secs(self.protocol.dkg_round_timeout_secs),
            dkg_window: Duration::from_secs(self.protocol.dkg_window_secs),
            dkg_join_wait: Duration::from_secs(self.protocol.dkg_join_wait_secs),
            dkg_round1_offset: Duration::from_secs(self.protocol.dkg_round1_offset_secs),
            dkg_round2_offset: Duration::from_secs(self.protocol.dkg_round2_offset_secs),
            dkg_reconcile_backoff: Duration::from_secs(self.protocol.dkg_reconcile_backoff_secs),
            poll_interval: Duration::from_millis(self.protocol.poll_interval_ms),
            retry_backoff_max: RETRY_BACKOFF_MAX,
            bitcoin_network: self.bitcoin.parsed_network(),
            identity,
            pegin_policy_id,
            // Carried so the machine can PUBLISH them in the handshake; the chain
            // adapter is what actually derives the cycle and reads the stake.
            node_facts: self.cardano.node_facts(),
            batch_poll_ceiling: BATCH_POLL_CEILING,
            // EpochConfig keeps a concrete value for the demo/mock paths; the daemon reads
            // the published one off the treasury oracle ([CFG-9]).
            pegin_refund_timeout_blocks: self.bitcoin.pegin_refund_timeout_blocks.unwrap_or(4320),
            state_dir: self
                .protocol
                .state_dir
                .as_deref()
                .map(std::path::PathBuf::from),
            // Only ever used if it turns out to BE the treasury's current key —
            // i.e. the bootstrap handoff. See `EpochConfig::y_fed_seed`.
            y_fed_seed: self
                .bitcoin
                .y_fed_seed_hex
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok()),
            // Set by the caller, like `inject_fault`: loading it reads the
            // persisted share off disk and cross-checks it against the typed-in
            // `[federation]` roster, either of which can fail — and this
            // conversion has no way to report that.
            phase1_signer: None,
            // Demo-only; the harness/CLI sets this after building the config.
            inject_fault: None,
        }
    }
}

/// Load a bifrost identity keypair from a `0600` hex key file.
///
/// On unix the file must not be group/other-accessible (any bit in `0o077`
/// is rejected) — this is a long-lived signing secret. The file holds the
/// 32-byte secret key as hex (whitespace trimmed).
pub fn load_bifrost_keypair_from(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    path: &std::path::Path,
) -> Result<bitcoin::secp256k1::Keypair, ConfigError> {
    let display = path.display().to_string();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| ConfigError::Io(display.clone(), e))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConfigError::KeyPermsTooOpen {
                path: display,
                mode,
            });
        }
    }
    let contents =
        std::fs::read_to_string(path).map_err(|e| ConfigError::Io(display.clone(), e))?;
    let bytes = hex::decode(contents.trim())
        .map_err(|e| ConfigError::KeyParse(format!("{display}: not valid hex: {e}")))?;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes)
        .map_err(|e| ConfigError::KeyParse(format!("{display}: {e}")))?;
    Ok(bitcoin::secp256k1::Keypair::from_secret_key(secp, &sk))
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ConfigError {
    Io(String, std::io::Error),
    Parse(String, toml::de::Error),
    /// `[bifrost].skey_path` was needed but not configured.
    MissingBifrostKey,
    /// The key file is readable by group/other (unix mode has `0o077` bits).
    KeyPermsTooOpen {
        path: String,
        mode: u32,
    },
    /// The key file's contents are not a valid 32-byte secp256k1 secret.
    KeyParse(String),
    /// A test-run flag is set on a network holding real funds.
    TestFlagOnMainnet(&'static str),
    /// `cardano.demo_virtual_epoch_slots` holds a cycle length nothing can run.
    UnusableVirtualEpoch(String),
    /// The document sets keys the bridge Config now publishes.
    RetiredKeys(Vec<RetiredKey>),
}

impl ConfigError {
    /// Attach the file path to a parse-time error raised before it was known.
    fn with_path(self, path: &str) -> Self {
        match self {
            Self::Parse(_, e) => Self::Parse(path.to_string(), e),
            other => other,
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "reading config {path}: {e}"),
            Self::Parse(path, e) => write!(f, "parsing config {path}: {e}"),
            Self::MissingBifrostKey => {
                write!(f, "[bifrost].skey_path is required but not set")
            }
            Self::KeyPermsTooOpen { path, mode } => write!(
                f,
                "bifrost key file {path} has mode {mode:o}; must be 0600 (not group/other readable)"
            ),
            Self::KeyParse(s) => write!(f, "bifrost key: {s}"),
            Self::TestFlagOnMainnet(why) => write!(
                f,
                "a test-run flag is set on mainnet, and is refused rather than warned about: {why}"
            ),
            Self::UnusableVirtualEpoch(why) => {
                write!(f, "cardano.demo_virtual_epoch_slots: {why}")
            }
            Self::RetiredKeys(keys) => {
                writeln!(
                    f,
                    "this config sets {} key(s) that no longer exist. They are refused rather \
                     than ignored, because a key that silently does nothing leaves you \
                     believing a value you typed is in force. Each is followed by what \
                     replaced it:",
                    keys.len()
                )?;
                for (section, key, replacement) in keys {
                    writeln!(f, "  [{section}].{key}  ->  {replacement}")?;
                }
                write!(
                    f,
                    "Delete them. Each held a value every node must agree on, so a per-operator \
                     copy was never a convenience: it can disagree, and disagreement here is \
                     SILENT — a wrong contract identifier names an address that holds nothing \
                     (which reads exactly like a bridge with no pending work), and a wrong \
                     selection rule makes co-signers freeze different sets and never converge. \
                     `heimdall show-config-params` prints what this node resolves from the chain"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The three ban-schedule keys are REFUSED, not ignored. Ignoring them is
    /// how an operator ends up believing a ban duration they typed is in force
    /// while the node enforces the bridge's — or worse, derives a ban address no
    /// deployment has and reads back an empty ban list.
    #[test]
    fn retired_ban_schedule_keys_are_refused_with_their_replacement() {
        for key in [
            "base_ban_duration_ms",
            "max_faults_before_permanent",
            "max_validity_window_ms",
        ] {
            let doc = format!("[cardano]\n{key} = 1\n");
            let err = HeimdallConfig::from_toml_str(&doc)
                .expect_err("a retired key must be refused, not ignored");
            let rendered = format!("{err}");
            assert!(
                rendered.contains(key) && rendered.contains("params["),
                "the diagnostic must name the key and where it moved: {rendered}"
            );
        }
    }

    /// WI-070/WI-071: the bridge's own identifiers, and the peg-out selection
    /// rule, are refused too — each naming what supersedes it.
    ///
    /// Refusing rather than ignoring is the whole point. These decide which
    /// ADDRESSES the node scans, and a stale copy does not fail — it finds
    /// nothing, which is indistinguishable from a quiet bridge. An operator who
    /// upgrades into this must be told their key is gone, not left believing a
    /// value they can still see in their own file is in force.
    #[test]
    fn retired_contract_keys_are_refused_with_their_config_field() {
        for (key, expect) in [
            ("pegin_script_address", "#6"),
            ("pegin_policy_id", "#6"),
            ("pegout_script_address", "#7"),
            ("bridged_token_unit", "#2"),
            ("cpo_policy_id", "#4"),
            ("treasury_address", "#5"),
            ("treasury_policy_id", "#5"),
            ("treasury_asset_name", "constant"),
            ("treasury_info_asset_name", "BFRTRY"),
        ] {
            let doc = format!("[cardano]\n{key} = \"x\"\n");
            let err = HeimdallConfig::from_toml_str(&doc)
                .expect_err("a retired key must be refused, not ignored");
            let rendered = format!("{err}");
            assert!(
                rendered.contains(key) && rendered.contains(expect),
                "the diagnostic must name the key and what replaced it: {rendered}"
            );
        }
    }

    /// The TM validator's bytes were the last artifact on the posting path that
    /// an operator pasted in, and the only one whose absence was SILENT: a node
    /// without it passed every startup check, ran a whole signing ceremony, and
    /// failed at the mint — after the batch opportunity was spent and the Bitcoin
    /// transaction was already broadcast. Refusing the key is how an operator who
    /// upgrades into this learns their pasted copy is no longer what the node
    /// uses; the node fetches the script by Config #5 and verifies it.
    #[test]
    fn the_retired_tm_script_cbor_is_refused_and_points_at_the_chain() {
        let err = HeimdallConfig::from_toml_str("[cardano]\ntm_script_cbor = \"59ab\"\n")
            .expect_err("a retired key must be refused, not ignored");
        let rendered = format!("{err}");
        assert!(rendered.contains("tm_script_cbor"), "{rendered}");
        // Naming the field is what makes the diagnostic actionable: the operator
        // has to know the value still exists, just not here.
        assert!(rendered.contains("#5"), "{rendered}");
        assert!(rendered.contains("tm_script_hash"), "{rendered}");
    }

    /// WI-071's key is in `[protocol]`, and what replaced it is a compiled-in
    /// constant rather than a Config field — so this also pins that the refusal
    /// is section-aware and does not claim everything is published.
    #[test]
    fn the_retired_freshness_margin_is_refused_and_names_the_constant() {
        let err = HeimdallConfig::from_toml_str("[protocol]\npegout_freshness_margin_ms = 1\n")
            .expect_err("a retired key must be refused, not ignored");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("pegout_freshness_margin_ms"),
            "{rendered}"
        );
        assert!(
            rendered.contains("PEG_OUT_FRESHNESS_MARGIN_MS"),
            "{rendered}"
        );
        // The same key name under another section is NOT this key.
        HeimdallConfig::from_toml_str("[cardano]\npegout_freshness_margin_ms = 1\n")
            .expect("a stray key in another section is not the retired one");
    }

    /// A test-run flag must not be expressible on a bridge holding real funds, and
    /// must be refused at LOAD rather than warned about: a warning in a unit's
    /// journal is not something anyone reads before the first ceremony fails.
    #[test]
    fn the_live_stake_test_flag_is_refused_on_mainnet_and_allowed_elsewhere() {
        let toml = |network: &str| {
            format!(
                r#"
[cardano]
network = "{network}"
blockfrost_url = "http://localhost:3000/api/v0"
demo_live_stake = true
"#
            )
        };
        let err =
            HeimdallConfig::from_toml_str(&toml("mainnet")).expect_err("mainnet must refuse it");
        let msg = err.to_string();
        assert!(msg.contains("demo_live_stake"), "{msg}");
        assert!(msg.contains("drifts intra-epoch"), "names WHY: {msg}");

        // Every other network is a test bridge as far as this flag is concerned.
        for n in ["preprod", "preview", "testnet"] {
            HeimdallConfig::from_toml_str(&toml(n))
                .unwrap_or_else(|e| panic!("{n} must allow it: {e}"));
        }

        // AND an unresolvable network is refused, not waved through. A capital
        // letter is an unknown string, so `is_mainnet` errs — reading that as
        // "not mainnet" is how the sibling guard in preflight.rs was once
        // bypassable, and the failure is silent on a real-funds bridge.
        let err = HeimdallConfig::from_toml_str(&toml("Mainnet"))
            .expect_err("an unresolvable network must not open the gate");
        assert!(err.to_string().contains("demo_live_stake"), "{err}");
    }

    /// The virtual epoch is refused on mainnet by the same rule, and for a
    /// stronger reason: it renumbers the epoch every ceremony binds to, so a
    /// roster where only some nodes have it does not run a degraded ceremony —
    /// it runs two, in namespaces that never meet.
    #[test]
    fn the_virtual_epoch_is_refused_on_mainnet_and_allowed_elsewhere() {
        let toml = |network: &str| {
            format!(
                r#"
[cardano]
network = "{network}"
blockfrost_url = "http://localhost:3000/api/v0"
demo_virtual_epoch_slots = 86400
"#
            )
        };
        let msg = HeimdallConfig::from_toml_str(&toml("mainnet"))
            .expect_err("mainnet must refuse it")
            .to_string();
        assert!(msg.contains("demo_virtual_epoch_slots"), "{msg}");
        assert!(msg.contains("roster split"), "names WHY: {msg}");

        for n in ["preprod", "preview", "testnet"] {
            let cfg = HeimdallConfig::from_toml_str(&toml(n))
                .unwrap_or_else(|e| panic!("{n} must allow it: {e}"));
            assert_eq!(cfg.cardano.demo_virtual_epoch_slots, Some(86_400));
        }

        // Same trap as the sibling guard: an unresolvable network is treated as
        // mainnet, never waved through.
        let err = HeimdallConfig::from_toml_str(&toml("Mainnet"))
            .expect_err("an unresolvable network must not open the gate");
        assert!(
            err.to_string().contains("demo_virtual_epoch_slots"),
            "{err}"
        );
    }

    /// A cycle length nothing can run is refused at LOAD, not at the first
    /// ceremony — which on a five-day epoch would mean finding out five days
    /// late.
    #[test]
    fn an_unusable_virtual_epoch_length_is_refused_at_load() {
        let toml = |slots: u64| {
            format!("[cardano]\nnetwork = \"preprod\"\ndemo_virtual_epoch_slots = {slots}\n")
        };
        for bad in [0, 60, 432_000, 900_000] {
            let err = HeimdallConfig::from_toml_str(&toml(bad))
                .expect_err("an unusable cycle length must be refused")
                .to_string();
            assert!(err.contains("demo_virtual_epoch_slots"), "{bad}: {err}");
        }
        HeimdallConfig::from_toml_str(&toml(86_400)).expect("a day is usable");
    }

    /// ...and a config that sets none of them still loads.
    #[test]
    fn a_config_without_the_retired_keys_loads() {
        let cfg = HeimdallConfig::from_toml_str("[cardano]\nnetwork = \"preprod\"\n").unwrap();
        assert_eq!(cfg.cardano.network.as_deref(), Some("preprod"));
    }

    /// Every config file COMMITTED to this repo must still load.
    ///
    /// Three of them had been unloadable since WI-086 retired `bitcoin.submit`,
    /// and nothing noticed — a retired key is refused at load, so a config that
    /// still sets one is not "slightly stale", it does not start at all. The
    /// files are examples operators copy, so shipping a broken one teaches the
    /// wrong thing at the worst moment.
    #[test]
    fn every_committed_config_still_loads() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for rel in [
            "heimdall.toml",
            "heimdall.localdkg.toml",
            "heimdall.testnet4.toml",
            "deploy/debian/heimdall.toml",
        ] {
            let path = root.join(rel);
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
            HeimdallConfig::from_toml_str(&text)
                .unwrap_or_else(|e| panic!("{rel} does not load:\n{e}"));
        }
    }

    /// WI-090: all three bootstrap outrefs are refused, each naming Config #12.
    ///
    /// Refused rather than accepted-and-ignored, because they were the SAME
    /// outpoint under three names — an operator who sets one has a mental model
    /// in which these are three independent bridge inputs, and a node that
    /// silently ignored them would read a bridge they did not mean.
    #[test]
    fn the_three_bootstrap_outrefs_are_refused_and_name_config_12() {
        for key in ["registry_bootstrap", "treasury_bootstrap", "ban_bootstrap"] {
            let toml = format!("[cardano]\n{key} = \"{}:0\"\n", "ab".repeat(32));
            let err = HeimdallConfig::from_toml_str(&toml)
                .expect_err("a retired key must refuse startup")
                .to_string();
            assert!(err.contains(key), "{key}: {err}");
            assert!(
                err.contains("#12"),
                "{key} must name its replacement: {err}"
            );
        }
    }

    /// …and the field that replaced them cannot be set from TOML at all: it is
    /// `#[serde(skip)]`, filled only from an authenticated Config datum. A file
    /// that names it is ignored rather than honoured, so there is no back door
    /// to the value every federation script hash derives from.
    #[test]
    fn the_federation_one_shot_cannot_come_from_a_file() {
        let toml = format!(
            "[cardano]\nfederation_one_shot = \"{}:7\"\n",
            "ab".repeat(32)
        );
        let cfg = HeimdallConfig::from_toml_str(&toml).expect("an unknown key is not fatal");
        assert_eq!(cfg.cardano.federation_one_shot, None);
    }

    #[test]
    fn empty_toml_uses_defaults() {
        let cfg: HeimdallConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.protocol.dkg_round_timeout_secs, 300);
        assert_eq!(cfg.protocol.poll_interval_ms, 5000);
        assert_eq!(cfg.bitcoin.network, "regtest");
        // No default (WI-069): both federation values are inputs to the treasury
        // ADDRESS, so a guess yields a well-formed address holding nothing. Unset
        // means "read the treasury_info datum".
        assert_eq!(cfg.bitcoin.federation_csv_blocks, None);
        assert_eq!(cfg.bitcoin.y_fed_seed_hex, None);
        assert_eq!(cfg.demo.base_port, 18500);
        assert_eq!(cfg.demo.min_signers, 2);
        assert_eq!(cfg.demo.max_signers, 3);
    }

    #[test]
    fn partial_toml_overrides() {
        let toml_str = r#"
[protocol]
dkg_round_timeout_secs = 60

[bitcoin]
network = "testnet4"
fee_rate_sat_per_vb = 5
"#;
        let cfg: HeimdallConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.protocol.dkg_round_timeout_secs, 60);
        // Other protocol fields keep defaults.
        assert_eq!(cfg.protocol.poll_interval_ms, 5000);
        assert_eq!(cfg.bitcoin.network, "testnet4");
        assert_eq!(cfg.bitcoin.fee_rate_sat_per_vb, 5);
        // Other bitcoin fields keep defaults.
        assert_eq!(cfg.bitcoin.per_pegout_fee_sat, 1000);
    }

    #[test]
    fn cardano_network_explicit_wins_and_is_required_with_a_custom_backend() {
        // Hosted blockfrost.io: the project-id prefix still decides.
        let mut cfg = CardanoConfig {
            blockfrost_project_id: Some("mainnetAbC123".to_string()),
            ..Default::default()
        };
        assert!(cfg.is_mainnet().expect("prefix inference"));
        cfg.blockfrost_project_id = Some("preprodAbC123".to_string());
        assert!(!cfg.is_mainnet().expect("prefix inference"));

        // An explicit network overrides a misleading prefix.
        cfg.network = Some("mainnet".to_string());
        assert!(cfg.is_mainnet().expect("explicit network"));

        // A local Dolos / yaci backend must not be guessed at: without an
        // explicit network this is the case that would silently answer
        // "testnet" on a mainnet node.
        let mut local = CardanoConfig {
            blockfrost_project_id: Some("dolos".to_string()),
            blockfrost_url: Some("http://localhost:3000/api/v0".to_string()),
            ..Default::default()
        };
        let err = local.is_mainnet().expect_err("must refuse to guess");
        assert!(err.contains("cardano.network is required"), "{err}");

        local.network = Some("mainnet".to_string());
        assert!(local.is_mainnet().expect("explicit network"));

        local.network = Some("nonsense".to_string());
        let err = local.is_mainnet().expect_err("unknown network");
        assert!(err.contains("unknown cardano.network"), "{err}");
    }

    /// `cardano.network` is the network TAG of every address this node derives,
    /// and the last input to those addresses still taken purely from local
    /// config. A typo does not error on its own — it yields a well-formed address
    /// on the other network holding nothing, which the roster reads as "nobody
    /// registered" and the ban list as "nobody banned". The bridge's own Config
    /// address states which network it is on, so the disagreement is decisive.
    #[test]
    fn a_network_disagreeing_with_the_bridges_own_address_is_refused() {
        let testnet_addr = "addr_test1wq9dxvdxsmqcz9nk8w2n7tt6mkgvx8lsvkjy3kx0jkzmhtcxwvvhs";
        let mainnet_addr = "addr1wx9dxvdxsmqcz9nk8w2n7tt6mkgvx8lsvkjy3kx0jkzmhtcqvvvhs";

        let cfg = |network: &str, addr: &str| CardanoConfig {
            network: Some(network.to_string()),
            config_address: Some(addr.to_string()),
            ..Default::default()
        };

        // Agreement, both ways round.
        assert!(!cfg("preprod", testnet_addr).is_mainnet().unwrap());
        assert!(cfg("mainnet", mainnet_addr).is_mainnet().unwrap());

        // Disagreement, both ways round — and the message names both sides.
        for (network, addr) in [("mainnet", testnet_addr), ("preprod", mainnet_addr)] {
            let err = cfg(network, addr)
                .is_mainnet()
                .expect_err("the bridge's own address contradicts cardano.network");
            assert!(err.contains(network), "{err}");
            assert!(err.contains(addr), "{err}");
        }

        // No Config address to check against → nothing to contradict, and the
        // fixture/demo deployments that set none keep working.
        assert!(
            CardanoConfig {
                network: Some("mainnet".to_string()),
                ..Default::default()
            }
            .is_mainnet()
            .unwrap()
        );
    }

    #[test]
    fn bitcoin_network_parsing() {
        let cfg = BitcoinConfig::default();
        assert_eq!(cfg.parsed_network(), bitcoin::Network::Regtest);

        let mut cfg2 = BitcoinConfig::default();
        cfg2.network = "mainnet".to_string();
        assert_eq!(cfg2.parsed_network(), bitcoin::Network::Bitcoin);

        cfg2.network = "testnet4".to_string();
        assert_eq!(cfg2.parsed_network(), bitcoin::Network::Testnet4);
    }

    #[test]
    fn epoch_config_matches_demo_default() {
        let cfg = HeimdallConfig::default();
        let id = frost_secp256k1_tr::Identifier::try_from(1u16).unwrap();
        let identity = SpoIdentity {
            identifier: id,
            bifrost_id_pk: Vec::new(),
            port: 18500,
        };
        let epoch = cfg.to_epoch_config(identity.clone(), [0u8; 28]);
        let demo = EpochConfig::demo_default(identity);

        assert_eq!(epoch.dkg_round_timeout, demo.dkg_round_timeout);
        assert_eq!(epoch.poll_interval, demo.poll_interval);
        assert_eq!(epoch.pegin_policy_id, demo.pegin_policy_id);
        assert_eq!(epoch.batch_poll_ceiling, demo.batch_poll_ceiling);
        assert_eq!(
            epoch.pegin_refund_timeout_blocks,
            demo.pegin_refund_timeout_blocks
        );
    }

    #[test]
    fn bifrost_keypair_loads_from_file() {
        use std::io::Write;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let path = std::env::temp_dir().join("heimdall_test_bifrost_ok.hex");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(sk_hex.as_bytes())
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let kp = load_bifrost_keypair_from(&secp, &path).unwrap();
        let expected = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&hex::decode(sk_hex).unwrap()).unwrap(),
        );
        assert_eq!(kp.x_only_public_key().0, expected.x_only_public_key().0);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn bifrost_keypair_rejects_group_readable_file() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let path = std::env::temp_dir().join("heimdall_test_bifrost_open.hex");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"0101010101010101010101010101010101010101010101010101010101010101")
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_bifrost_keypair_from(&secp, &path);
        assert!(matches!(err, Err(ConfigError::KeyPermsTooOpen { .. })));
        let _ = std::fs::remove_file(&path);
    }
}
