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
    pub demo: DemoConfig,
    pub bifrost: BifrostConfig,
    pub log: LogConfig,
}

impl Default for HeimdallConfig {
    fn default() -> Self {
        Self {
            protocol: ProtocolConfig::default(),
            bitcoin: BitcoinConfig::default(),
            cardano: CardanoConfig::default(),
            http: HttpConfig::default(),
            demo: DemoConfig::default(),
            bifrost: BifrostConfig::default(),
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
}

impl Default for BifrostConfig {
    fn default() -> Self {
        Self { skey_path: None }
    }
}

// ── [protocol] ──────────────────────────────────────────────────────

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
    pub quorum51_timeout_secs: u64,
    pub leader_timeout_secs: u64,
    /// Maximum time to wait for the submitted treasury movement to become the
    /// confirmed chain tip before rebuilding from fresh chain state.
    pub tm_confirmation_timeout_secs: u64,
    pub pegin_collection_window_secs: u64,
    pub pegin_poll_interval_ms: u64,
    /// Directory for 0600 DKG-state persistence so the signing share survives
    /// restarts for the epoch (WI-014). Unset → in-memory only.
    ///
    /// Also the home of the completed-peg-outs trie (`cpo-trie.json`). Unset means
    /// the trie is rebuilt as empty on every start, which is correct only on a
    /// bridge that has completed no peg-outs — set this in any real deployment.
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
            quorum51_timeout_secs: 300,
            leader_timeout_secs: 10000,
            tm_confirmation_timeout_secs: 1800,
            pegin_collection_window_secs: 5,
            pegin_poll_interval_ms: 1000,
            state_dir: None,
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
    /// must clear is Config datum field #13, read at the batch snapshot slot — a
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
    /// Optional bitcoind JSON-RPC endpoint. DEV / FEDERATION-OPS ONLY: the SPO
    /// runtime never requires a Bitcoin node — every Bitcoin fact reaches
    /// heimdall through Cardano (PIR datums carry the raw deposit txs,
    /// UnconfirmedTm records carry the raw TMs, the bridge-state singleton
    /// carries the treasury head). This endpoint serves only the opt-in dev
    /// broadcast below and the federation ops tools (treasury-self-send,
    /// federation-spend).
    pub rpc_url: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,
    /// DEV-ONLY: broadcast the signed BTC tx to `rpc_url` via
    /// `sendrawtransaction`. Default FALSE — in production the SPO never
    /// broadcasts; watchtowers relay `signed_btc_tx` from the UnconfirmedTm
    /// record (that is what the record is for).
    pub submit: bool,
    /// Depositor refund timelock (BTC blocks) in the peg-in Taproot's
    /// refund leaf. Spec default 4320 (~30 days); override for
    /// testnet4/preprod which use shorter timeouts.
    pub pegin_refund_timeout_blocks: u16,
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
            submit: false,
            pegin_refund_timeout_blocks: 4320,
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
    /// Whether to publish an oracle-update UTxO to Cardano after signing.
    /// Requires `blockfrost_project_id` and `mnemonic`. Default: true.
    pub submit_oracle: bool,
    /// TreasuryMovementValidator CBOR (from `binocular tm-script`). REQUIRED to POST a
    /// TM; SIGNING one does not need it.
    ///
    /// The Config publishes this validator's HASH (#4), which is what locates and reads
    /// the TM address — but MINTING the TM NFT needs the code, and the always-ok scaffold
    /// fallback is gone. So this is the compiled artifact, not an identifier: nothing here
    /// can name a different bridge than the `config_*` fields below do.
    pub tm_script_cbor: Option<String>,
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
    /// Config NFT policy id (56 hex chars) locating the Config UTxO. Required alongside
    /// `tm_script_cbor` and `config_address`.
    pub config_nft_policy_id: Option<String>,
    /// Config NFT asset name (hex). Required alongside `config_nft_policy_id`.
    pub config_nft_asset_name: Option<String>,
    /// Path to the bifrost Aiken blueprint (plutus.json) holding the compiled
    /// spos_registry + treasury_info validators.
    ///
    /// A build artifact of the contracts release, not a per-bridge value — which
    /// is why it survives WI-070 while every identifier it used to sit beside was
    /// deleted. READING the roster needs none of it (the Config publishes the
    /// registry and treasury_info policy ids at #11–#12). It buys exactly one
    /// capability: SPENDING the `treasury_info` state UTxO, i.e. the Update-Y key
    /// handoff, which needs the compiled script. What it derives is checked
    /// against #12.
    pub registry_blueprint: Option<String>,
    /// The spos_registry one-shot bootstrap outref `<tx_hash>:<index>` that
    /// parameterizes the registry policy — and through it the `spo_bans` policy,
    /// which is the only thing still reading it: the fault-enforcement half needs
    /// to re-derive the ban policy it publishes proofs under.
    pub registry_bootstrap: Option<String>,
    /// The spo_bans one-shot bootstrap outref `<tx_hash>:<index>` that
    /// parameterizes the ban-list policy (the policy is also parameterized
    /// by the registry policy, so `registry_blueprint` + `registry_bootstrap`
    /// must be set alongside).
    ///
    /// **Only for a bridge whose Config predates the ban-policy append.** Where
    /// the Config publishes the finished policy id (#7) that value wins and this
    /// key is not needed at all — see [`crate::cardano::ban_list::BanListSource::resolve`].
    /// Left set on such a bridge it is unused, and a startup error if it derives
    /// a different policy than the one published.
    pub ban_bootstrap: Option<String>,
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
            min_stake_lovelace: None,
            stake_source: None,
            demo_exclude_unstaked: false,
            submit_oracle: true,
            tm_script_cbor: None,
            tm_validity_window_secs: None,
            config_address: None,
            config_nft_policy_id: None,
            config_nft_asset_name: None,
            registry_blueprint: None,
            registry_bootstrap: None,
            ban_bootstrap: None,
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

// ── Retired keys ────────────────────────────────────────────────────

/// One key this file no longer has, as `(section, key, what replaced it)`.
///
/// Every one of them named a value the whole BRIDGE has to agree on — a script
/// hash, an address, a token, a ban duration, a selection rule. Carrying an
/// operator-typed copy of such a value means two sources that can disagree, and
/// disagreement here is never an error: a mistyped script hash yields a
/// well-formed address holding nothing, which reads as "nothing pending" rather
/// than "wrong bridge", and a divergent selection rule just makes the FROST round
/// fail to converge with nothing in any log naming the cause.
///
/// Most were deleted by WI-070 in favour of the Config UTxO, which publishes them
/// and is identical for every SPO. One — the peg-out freshness margin — has no
/// Config field yet and became a compiled-in constant instead (WI-071); that
/// makes it uniform per RELEASE rather than per bridge, which is weaker but is
/// still a coordinated value rather than a per-operator one.
///
/// They are REFUSED rather than ignored. A key that silently does nothing leaves
/// the operator believing a value they typed is in force — the same failure in a
/// quieter form.
/// `(section, key, what replaced it)`.
pub type RetiredKey = (&'static str, &'static str, &'static str);

const RETIRED_KEYS: &[RetiredKey] = &[
    (
        "protocol",
        "pegout_freshness_margin_ms",
        "the compiled-in PEG_OUT_FRESHNESS_MARGIN_MS (7 days) — a TM selection \
         rule, so it must be identical on every SPO",
    ),
    (
        "cardano",
        "pegin_script_address",
        "Config #5 (peg_in_script_hash)",
    ),
    (
        "cardano",
        "pegin_policy_id",
        "Config #5 (peg_in_script_hash)",
    ),
    (
        "cardano",
        "pegout_script_address",
        "Config #6 (peg_out_script_hash)",
    ),
    (
        "cardano",
        "bridged_token_unit",
        "Config #1 (bridged_token_policy) ++ \"fSAT\"",
    ),
    (
        "cardano",
        "cpo_policy_id",
        "Config #3 (bridge_state_policy)",
    ),
    ("cardano", "treasury_address", "Config #4 (tm_script_hash)"),
    (
        "cardano",
        "treasury_policy_id",
        "Config #4 (tm_script_hash)",
    ),
    (
        "cardano",
        "treasury_asset_name",
        "Config #4 (tm_script_hash), empty name",
    ),
    (
        "cardano",
        "treasury_info_asset_name",
        "Config #13 (treasury_info_asset_name)",
    ),
    (
        "cardano",
        "base_ban_duration_ms",
        "Config #8 (base_ban_duration_ms)",
    ),
    (
        "cardano",
        "max_faults_before_permanent",
        "Config #9 (max_faults_before_permanent)",
    ),
    (
        "cardano",
        "max_validity_window_ms",
        "Config #10 (max_validity_window_ms)",
    ),
];

/// The retired keys this document still sets, in the order they are listed above.
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

    /// Parse a `heimdall.toml` document, refusing any key WI-070 retired.
    ///
    /// The check runs BEFORE deserialization so the diagnostic names the key and
    /// its replacement, rather than the daemon starting on a config half of which
    /// the operator believes is in force.
    pub fn from_toml_str(contents: &str) -> Result<Self, ConfigError> {
        let doc: toml::Value =
            toml::from_str(contents).map_err(|e| ConfigError::Parse(String::new(), e))?;
        let retired = retired_keys_in(&doc);
        if !retired.is_empty() {
            return Err(ConfigError::RetiredKeys(retired));
        }
        doc.try_into()
            .map_err(|e| ConfigError::Parse(String::new(), e))
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
    /// per-instance identity and the bridge's peg-in policy id.
    ///
    /// `pegin_policy_id` is Config #5, passed in rather than read from a key of
    /// its own (WI-070): it identifies the bridge, not this operator. The
    /// fixture/mock demo, which has no bridge to read, passes `[0u8; 28]`.
    pub fn to_epoch_config(&self, identity: SpoIdentity, pegin_policy_id: [u8; 28]) -> EpochConfig {
        EpochConfig {
            dkg_round_timeout: Duration::from_secs(self.protocol.dkg_round_timeout_secs),
            dkg_window: Duration::from_secs(self.protocol.dkg_window_secs),
            dkg_join_wait: Duration::from_secs(self.protocol.dkg_join_wait_secs),
            dkg_round1_offset: Duration::from_secs(self.protocol.dkg_round1_offset_secs),
            dkg_round2_offset: Duration::from_secs(self.protocol.dkg_round2_offset_secs),
            dkg_reconcile_backoff: Duration::from_secs(self.protocol.dkg_reconcile_backoff_secs),
            poll_interval: Duration::from_millis(self.protocol.poll_interval_ms),
            quorum51_timeout: Duration::from_secs(self.protocol.quorum51_timeout_secs),
            leader_timeout: Duration::from_secs(self.protocol.leader_timeout_secs),
            tm_confirmation_timeout: Duration::from_secs(
                self.protocol.tm_confirmation_timeout_secs,
            ),
            identity,
            pegin_policy_id,
            pegin_collection_window: Duration::from_secs(
                self.protocol.pegin_collection_window_secs,
            ),
            pegin_poll_interval: Duration::from_millis(self.protocol.pegin_poll_interval_ms),
            pegin_refund_timeout_blocks: self.bitcoin.pegin_refund_timeout_blocks,
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
    /// The file still sets keys that no longer exist; each is listed with what
    /// supersedes it. See [`RETIRED_KEYS`].
    RetiredKeys(Vec<RetiredKey>),
}

impl ConfigError {
    /// Attach the file this error came from, for the variants that carry a path.
    ///
    /// [`HeimdallConfig::from_toml_str`] parses a string and has no path to name;
    /// [`HeimdallConfig::from_file`] does, and an operator with several configs
    /// needs to be told which one is wrong.
    #[must_use]
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
            Self::RetiredKeys(keys) => {
                writeln!(
                    f,
                    "this config sets {} key(s) that no longer exist. Each held a value the \
                     whole bridge must agree on, so a per-operator copy could only disagree \
                     with the other SPOs — and disagreement here is silent, not an error. \
                     Delete each line:",
                    keys.len()
                )?;
                for (section, key, replacement) in keys {
                    writeln!(f, "  {section}.{key}  ->  {replacement}")?;
                }
                write!(
                    f,
                    "`heimdall show-config-params` prints what this node resolves from the chain."
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

    /// WI-070: a key the Config publishes is refused, not ignored. Ignoring it
    /// leaves the operator believing a value they typed is in force, which is the
    /// original divergence in a quieter form — so the message has to name both the
    /// dead key and the thing that replaced it.
    #[test]
    fn a_config_still_setting_a_retired_key_is_refused_by_name() {
        let err = HeimdallConfig::from_toml_str(
            r#"
[protocol]
poll_interval_ms = 5000
pegout_freshness_margin_ms = 604800000

[cardano]
blockfrost_project_id = "preprodXXX"
treasury_address = "addr_test1wq3ywdhmjku42uv2pcmy0dwcnycl2slcnswnfapsg7f5z4cd30duu"
cpo_policy_id = "aa"
"#,
        )
        .expect_err("retired keys must not be silently ignored");
        let msg = err.to_string();
        assert!(msg.contains("cardano.treasury_address"), "{msg}");
        assert!(msg.contains("Config #4 (tm_script_hash)"), "{msg}");
        assert!(msg.contains("cardano.cpo_policy_id"), "{msg}");
        assert!(msg.contains("Config #3 (bridge_state_policy)"), "{msg}");
        // WI-071's half: retired in favour of a compiled-in constant rather than
        // a Config field, and the message must not claim otherwise.
        assert!(msg.contains("protocol.pegout_freshness_margin_ms"), "{msg}");
        assert!(msg.contains("PEG_OUT_FRESHNESS_MARGIN_MS"), "{msg}");
        // The keys that survive are not swept up with them.
        assert!(!msg.contains("blockfrost_project_id"), "{msg}");
        assert!(!msg.contains("poll_interval_ms"), "{msg}");
    }

    /// Every retired key is refused, and the message names each one — a partial
    /// list would send an operator through this error once per key.
    #[test]
    fn every_retired_key_is_named() {
        let mut doc = String::new();
        for section in ["protocol", "cardano"] {
            doc.push_str(&format!("[{section}]\n"));
            for (s, key, _) in RETIRED_KEYS.iter().filter(|(s, ..)| *s == section) {
                assert_eq!(*s, section);
                doc.push_str(&format!("{key} = \"x\"\n"));
            }
        }
        let err = HeimdallConfig::from_toml_str(&doc).expect_err("every retired key is refused");
        let msg = err.to_string();
        for (section, key, replacement) in RETIRED_KEYS {
            assert!(msg.contains(&format!("{section}.{key}")), "{key}: {msg}");
            assert!(msg.contains(replacement), "{key}: {msg}");
        }
    }

    /// A config that sets none of them still loads — including one with no
    /// `[cardano]` section at all (the local fixture demo).
    #[test]
    fn a_config_without_the_retired_keys_loads() {
        HeimdallConfig::from_toml_str("[demo]\nbase_port = 18500\n").expect("fixture demo config");
        HeimdallConfig::from_toml_str(
            "[cardano]\nblockfrost_project_id = \"preprodXXX\"\nconfig_address = \"addr_test1x\"\n",
        )
        .expect("locator-only config");
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
        assert_eq!(epoch.quorum51_timeout, demo.quorum51_timeout);
        assert_eq!(epoch.leader_timeout, demo.leader_timeout);
        assert_eq!(epoch.pegin_policy_id, demo.pegin_policy_id);
        assert_eq!(epoch.pegin_collection_window, demo.pegin_collection_window);
        assert_eq!(epoch.pegin_poll_interval, demo.pegin_poll_interval);
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
