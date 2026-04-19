//! Real `CardanoPegInSource` backed by `pallas-network` N2C.
//!
//! Connects to a local Cardano node's Unix socket, runs
//! `LocalStateQuery::GetUTxOByAddress` against the configured peg-in
//! script address, filters the returned UTxOs by policy ID, and
//! hands each inline datum's raw CBOR bytes to the parser (which
//! decodes the `PegInDatum` Constr shape).
//!
//! See `tests/pallas_spike.rs` for the compile-time API shape this
//! module mirrors.
//!
//! TODO: today each `query_pegin_requests` call opens a fresh
//! `NodeClient`. Reusing a single long-lived connection across polls
//! would be cheaper; the one-shot shape is the v0.2 simplification.

use async_trait::async_trait;
use pallas_addresses::Address;
use pallas_network::facades::NodeClient;
use pallas_network::miniprotocols::localstate::queries_v16::{
    self, Addrs, TransactionOutput, Value,
};
use tokio::sync::Mutex;

use crate::cardano::pegin_source::{
    CardanoOutRef, CardanoPegInRequest, CardanoPegInSource,
};
use crate::epoch::state::{EpochError, EpochResult};

/// Cardano network magic.
#[derive(Debug, Clone, Copy)]
pub struct NetworkMagic(pub u64);

/// `CardanoPegInSource` backed by a local Cardano node socket.
pub struct PallasPegInSource {
    socket_path: String,
    magic: u64,
    script_address: Address,
    /// Serialize access to the node socket — pallas' `NodeClient` is
    /// not `Sync`, and the state-query miniprotocol is sequential.
    lock: Mutex<()>,
}

impl PallasPegInSource {
    /// `socket_path` is the Unix socket of a running cardano-node;
    /// `script_address` is the bech32 address of the peg-in script
    /// carrying the request UTxOs.
    pub fn new(
        socket_path: impl Into<String>,
        magic: NetworkMagic,
        script_address: Address,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            magic: magic.0,
            script_address,
            lock: Mutex::new(()),
        }
    }

    /// Parse a bech32 address and construct a source. Convenience
    /// wrapper over `new`.
    pub fn from_bech32(
        socket_path: impl Into<String>,
        magic: NetworkMagic,
        bech32: &str,
    ) -> EpochResult<Self> {
        let addr = Address::from_bech32(bech32)
            .map_err(|e| EpochError::Chain(format!("bech32: {e}")))?;
        Ok(Self::new(socket_path, magic, addr))
    }
}

#[async_trait]
impl CardanoPegInSource for PallasPegInSource {
    async fn query_pegin_requests(
        &self,
        policy_id: &[u8; 28],
    ) -> EpochResult<Vec<CardanoPegInRequest>> {
        let _guard = self.lock.lock().await;

        // --- Connect + acquire local state ---
        let mut client = NodeClient::connect(&self.socket_path, self.magic)
            .await
            .map_err(|e| EpochError::Chain(format!("node connect: {e}")))?;
        let sq = client.statequery();
        sq.acquire(None)
            .await
            .map_err(|e| EpochError::Chain(format!("statequery acquire: {e}")))?;

        let era: u16 = queries_v16::get_current_era(sq)
            .await
            .map_err(|e| EpochError::Chain(format!("get_current_era: {e}")))?;

        let addrs: Addrs = vec![self.script_address.to_vec().into()];
        let utxos = queries_v16::get_utxo_by_address(sq, era, addrs)
            .await
            .map_err(|e| EpochError::Chain(format!("get_utxo_by_address: {e}")))?;

        // Release the state query before doing any CPU-bound work.
        sq.send_release()
            .await
            .map_err(|e| EpochError::Chain(format!("statequery release: {e}")))?;
        client.abort().await;

        // --- Filter + decode ---
        let mut out = Vec::new();
        for (utxo, output) in utxos.utxo.iter() {
            let post = match output {
                TransactionOutput::Current(p) => p,
                // Legacy outputs have no inline datum; can't carry a
                // peg-in request payload. Silently skip.
                TransactionOutput::Legacy(_) => continue,
            };

            // Policy-ID filter: require the output carries at least
            // one asset minted under `policy_id`. Lovelace-only
            // outputs at the script address are ignored.
            let has_policy = match &post.amount {
                Value::Coin(_) => false,
                Value::Multiasset(_coin, assets) => assets
                    .iter()
                    .any(|(pid, _)| pid.as_slice() == policy_id),
            };
            if !has_policy {
                continue;
            }

            // Inline datum: `(Era, TagWrap<Bytes, 24>)`; the tag-wrapped
            // bytes are CBOR-encoded `PlutusData`. We pass them through
            // raw — the parser knows the `PegInDatum` Constr shape.
            let Some((_datum_era, tag_wrap)) = &post.inline_datum else {
                continue;
            };
            let datum_slice: &[u8] = tag_wrap.as_ref();
            let datum_cbor: Vec<u8> = datum_slice.to_vec();

            let tx_hash: [u8; 32] = (*utxo.transaction_id).into();
            let output_index: u64 = (&utxo.index).into();
            let output_index: u32 = match output_index.try_into() {
                Ok(i) => i,
                // Cardano output indices are well below u32; skip any
                // malformed record rather than fail the whole poll.
                Err(_) => continue,
            };

            out.push(CardanoPegInRequest {
                cardano_utxo: CardanoOutRef {
                    tx_hash,
                    output_index,
                },
                datum_cbor,
            });
        }

        // Deterministic order: the trait contract requires sort by
        // `cardano_utxo` so every SPO freezes the same set.
        out.sort_by(|a, b| a.cardano_utxo.cmp(&b.cardano_utxo));
        Ok(out)
    }
}
