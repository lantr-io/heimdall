//! TOML configuration file support.
//!
//! `HeimdallConfig` is the root struct deserialized from `heimdall.toml`.
//! Every field has a serde default so a partial or empty file is valid.
//! CLI flags override individual fields after deserialization.

use std::time::Duration;

use serde::Deserialize;

use crate::cardano::always_ok::always_ok_script_hash;
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
}

impl Default for HeimdallConfig {
    fn default() -> Self {
        Self {
            protocol: ProtocolConfig::default(),
            bitcoin: BitcoinConfig::default(),
            cardano: CardanoConfig::default(),
            http: HttpConfig::default(),
            demo: DemoConfig::default(),
        }
    }
}

// ── [protocol] ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProtocolConfig {
    pub dkg_round_timeout_secs: u64,
    pub poll_interval_ms: u64,
    pub quorum67_timeout_secs: u64,
    pub quorum51_timeout_secs: u64,
    pub federation_timeout_secs: u64,
    pub leader_timeout_secs: u64,
    pub pegin_collection_window_secs: u64,
    pub pegin_poll_interval_ms: u64,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            dkg_round_timeout_secs: 300,
            poll_interval_ms: 5000,
            quorum67_timeout_secs: 300,
            quorum51_timeout_secs: 300,
            federation_timeout_secs: 300,
            leader_timeout_secs: 10000,
            pegin_collection_window_secs: 5,
            pegin_poll_interval_ms: 1000,
        }
    }
}

// ── [bitcoin] ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BitcoinConfig {
    /// `"regtest"`, `"testnet4"`, `"signet"`, `"mainnet"`.
    pub network: String,
    pub fee_rate_sat_per_vb: u64,
    pub per_pegout_fee_sat: u64,
    pub federation_csv_blocks: u32,
    /// 32-byte hex seed for the Y_67 placeholder key.
    pub y_67_seed_hex: String,
    /// 32-byte hex seed for the Y_federation key.
    pub y_fed_seed_hex: String,
    /// Optional bitcoind JSON-RPC endpoint for direct tx broadcast.
    pub rpc_url: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,
    /// Whether to broadcast the signed BTC tx to the Bitcoin node via
    /// `sendrawtransaction`. Requires `rpc_url`. Default: true (when rpc_url set).
    pub submit: bool,
    /// Override the demo mock treasury UTXO with a real on-chain UTXO.
    pub treasury_txid: Option<String>,
    pub treasury_vout: Option<u32>,
    pub treasury_amount_sat: Option<u64>,
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            network: "regtest".to_string(),
            fee_rate_sat_per_vb: 1,
            per_pegout_fee_sat: 1000,
            federation_csv_blocks: 144,
            y_67_seed_hex: hex::encode([0x67u8; 32]),
            y_fed_seed_hex: hex::encode([0xFEu8; 32]),
            rpc_url: None,
            rpc_user: None,
            rpc_pass: None,
            submit: true,
            treasury_txid: None,
            treasury_vout: None,
            treasury_amount_sat: None,
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
    pub socket_path: Option<String>,
    pub network_magic: Option<u64>,
    pub pegin_script_address: Option<String>,
    pub pegin_policy_id: Option<String>,
    pub treasury_address: Option<String>,
    pub treasury_policy_id: Option<String>,
    pub treasury_asset_name: Option<String>,
    pub mnemonic: Option<String>,
    /// Whether to publish an oracle-update UTxO to Cardano after signing.
    /// Requires `blockfrost_project_id` and `mnemonic`. Default: true.
    pub submit_oracle: bool,
    /// Constructor tag to use in the oracle datum.
    /// 0 = unconfirmed TM tx (Binocular will update to 1 on Bitcoin confirmation).
    /// Default: 0.
    pub oracle_constructor: u8,
}

impl Default for CardanoConfig {
    fn default() -> Self {
        Self {
            blockfrost_project_id: None,
            socket_path: None,
            network_magic: None,
            pegin_script_address: None,
            pegin_policy_id: None,
            treasury_address: None,
            treasury_policy_id: None,
            treasury_asset_name: None,
            mnemonic: None,
            submit_oracle: true,
            oracle_constructor: 0,
        }
    }
}

// ── [http] ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub bind_address: String,
    pub base_port: u16,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            base_port: 18500,
        }
    }
}

// ── [demo] ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DemoConfig {
    pub min_signers: u16,
    pub max_signers: u16,
}

impl Default for DemoConfig {
    fn default() -> Self {
        Self {
            min_signers: 2,
            max_signers: 3,
        }
    }
}

// ── Loading ─────────────────────────────────────────────────────────

impl HeimdallConfig {
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.display().to_string(), e))?;
        toml::from_str(&contents)
            .map_err(|e| ConfigError::Parse(path.display().to_string(), e))
    }

    /// Build an `EpochConfig` from the merged configuration plus the
    /// per-instance identity.
    pub fn to_epoch_config(&self, identity: SpoIdentity) -> EpochConfig {
        let pegin_policy_id = self
            .cardano
            .pegin_policy_id
            .as_deref()
            .map(|hex_str| {
                let v = hex::decode(hex_str).expect("pegin_policy_id must be hex");
                assert_eq!(v.len(), 28, "pegin_policy_id must be 28 bytes");
                let mut out = [0u8; 28];
                out.copy_from_slice(&v);
                out
            })
            .unwrap_or_else(always_ok_script_hash);

        EpochConfig {
            dkg_round_timeout: Duration::from_secs(self.protocol.dkg_round_timeout_secs),
            poll_interval: Duration::from_millis(self.protocol.poll_interval_ms),
            quorum67_timeout: Duration::from_secs(self.protocol.quorum67_timeout_secs),
            quorum51_timeout: Duration::from_secs(self.protocol.quorum51_timeout_secs),
            federation_timeout: Duration::from_secs(self.protocol.federation_timeout_secs),
            leader_timeout: Duration::from_secs(self.protocol.leader_timeout_secs),
            identity,
            pegin_policy_id,
            pegin_collection_window: Duration::from_secs(
                self.protocol.pegin_collection_window_secs,
            ),
            pegin_poll_interval: Duration::from_millis(self.protocol.pegin_poll_interval_ms),
        }
    }
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ConfigError {
    Io(String, std::io::Error),
    Parse(String, toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "reading config {path}: {e}"),
            Self::Parse(path, e) => write!(f, "parsing config {path}: {e}"),
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
        assert_eq!(cfg.bitcoin.federation_csv_blocks, 144);
        assert_eq!(cfg.http.base_port, 18500);
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
            port: 18500,
        };
        let epoch = cfg.to_epoch_config(identity.clone());
        let demo = EpochConfig::demo_default(identity);

        assert_eq!(epoch.dkg_round_timeout, demo.dkg_round_timeout);
        assert_eq!(epoch.poll_interval, demo.poll_interval);
        assert_eq!(epoch.quorum67_timeout, demo.quorum67_timeout);
        assert_eq!(epoch.quorum51_timeout, demo.quorum51_timeout);
        assert_eq!(epoch.federation_timeout, demo.federation_timeout);
        assert_eq!(epoch.leader_timeout, demo.leader_timeout);
        assert_eq!(epoch.pegin_policy_id, demo.pegin_policy_id);
        assert_eq!(
            epoch.pegin_collection_window,
            demo.pegin_collection_window
        );
        assert_eq!(epoch.pegin_poll_interval, demo.pegin_poll_interval);
    }
}
