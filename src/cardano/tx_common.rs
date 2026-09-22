//! Transaction-building helpers shared across the tx builders (`register_spo`,
//! `apply_ban`, `fault_proof`, `treasury_bootstrap`, `publish`).
//!
//! Centralizes pieces that were independently open-coded in every builder:
//! network selection (from a wallet address, and the whisky cost-model param),
//! the min-UTxO and Conway ref-script fee formulas, collateral selection
//! (ada-only and disjoint from the spending inputs), body signing, and the
//! one-shot linked-list bootstrap tx (the registry and ban lists share an
//! identical skeleton, differing only in root datum, root asset name, and the
//! mint `Bootstrap` redeemer).

use pallas_codec::minicbor;
use pallas_codec::utils::{Bytes, NonEmptySet};
use pallas_primitives::conway::{Tx, VKeyWitness};
use pallas_traverse::ComputeHash;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::publish::WalletUtxo;
use crate::cardano::wallet::pub_key_hash_hex;

/// The 36 bytes an outpoint contributes to a signed message: the 32-byte
/// transaction id followed by the output index as 4-byte little-endian.
///
/// ONE encoding, matching `utils.serialise_output_reference` in the Aiken tree.
/// Two messages commit to an outpoint this way — `treasury.ak`'s Update-Y
/// rotation preimage and, since rev 5.6, `spos-registry.ak`'s registration and
/// revocation nonces ([REG-10], [DRG-6]) — and a signer that matched one
/// endianness and not the other would produce signatures the chain rejects with
/// nothing to point at.
#[must_use]
pub fn serialise_outpoint(tx_hash: &[u8; 32], index: u32) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..32].copy_from_slice(tx_hash);
    out[32..].copy_from_slice(&index.to_le_bytes());
    out
}

/// The UTxO a registration or revocation signature is bound to ([REG-10],
/// [DRG-6]).
///
/// An ordinary outpoint under the registrant's own payment key, which the
/// transaction carrying the signatures must spend. An outpoint is spendable
/// once, so the signatures fit exactly one transaction; spending it needs the
/// registrant's payment witness, so a signature file that leaks is useless from
/// any other wallet; and a failed attempt spends nothing, so a retry reuses the
/// same signatures with no second trip to the air-gapped cold key.
///
/// Rendered as `<txid hex>#<index>`, the form `cardano-cli` prints and the form
/// the air-gapped request file carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceOutpoint {
    pub tx_hash: [u8; 32],
    pub index: u32,
}

impl NonceOutpoint {
    #[must_use]
    pub fn new(tx_hash: [u8; 32], index: u32) -> Self {
        Self { tx_hash, index }
    }

    /// The 36 bytes the signed message ends with.
    #[must_use]
    pub fn to_message_bytes(&self) -> [u8; 36] {
        serialise_outpoint(&self.tx_hash, self.index)
    }

    /// Parse `<txid hex>#<index>`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (tx, idx) = s
            .trim()
            .rsplit_once('#')
            .ok_or_else(|| format!("outpoint must be <txid hex>#<index>, got {s:?}"))?;
        let tx_hash: [u8; 32] = hex::decode(tx.trim())
            .map_err(|e| format!("outpoint tx id is not hex: {e}"))?
            .try_into()
            .map_err(|_| "outpoint tx id is not 32 bytes".to_string())?;
        let index: u32 = idx
            .trim()
            .parse()
            .map_err(|_| format!("outpoint index is not a number: {idx:?}"))?;
        Ok(Self { tx_hash, index })
    }
}

impl std::fmt::Display for NonceOutpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", hex::encode(self.tx_hash), self.index)
    }
}

/// What a collateral UTxO must hold. Generous next to the ledger's floor (150%
/// of the fee, so a few hundred thousand lovelace), and deliberately so: it is
/// what a phase-2 failure would forfeit, and it is the size `ensure-collateral`
/// hands out, so the two must agree.
pub const COLLATERAL_LOVELACE: u64 = 5_000_000;

/// How many ada-only UTxOs a wallet needs to keep building script transactions:
/// one to pay the fee, one to point at as collateral, and the ledger will not
/// let a single UTxO be both.
pub const COLLATERAL_UTXOS_WANTED: usize = 2;

/// Lovelace to hold back for the change output when an input carries native
/// tokens. The change inherits them, and Conway prices an output by its
/// serialized size, so a multi-asset change output's min-UTxO is well above a
/// bare one's ~0.86 ADA — each distinct asset adds a policy id, an asset name
/// and map overhead. Budgeted loosely on purpose: over-reserving costs an
/// operator nothing, under-reserving costs a rejected transaction whose only
/// message is whisky's "inputs less than outputs + fee".
///
/// Zero for an ada-only input, so every ada-only path keeps the margins it was
/// tuned with.
#[must_use]
pub fn token_change_floor(tokens: usize) -> u64 {
    if tokens == 0 {
        0
    } else {
        1_000_000 + 500_000 * tokens as u64
    }
}

/// The wallet's usable collateral candidates: ada-only, no reference script,
/// and fat enough to post.
pub fn collateral_candidates(wallet_utxos: &[WalletUtxo]) -> Vec<&WalletUtxo> {
    wallet_utxos
        .iter()
        .filter(|u| u.pure_ada() && !u.reserved && u.lovelace >= COLLATERAL_LOVELACE)
        .collect()
}

/// What `ensure-collateral` built, for the caller to report and submit.
#[derive(Debug, Clone)]
pub struct CollateralTopUp {
    pub signed_tx_hex: String,
    /// Ada-only outputs the tx creates, each of [`COLLATERAL_LOVELACE`].
    pub created: usize,
}

/// Build a self-payment that splits the wallet enough ada-only UTxOs to keep
/// posting script transactions, or `Ok(None)` when it already has them.
///
/// This is the way out of the trap described in WI-20260910-5DRP6. A wallet
/// whose ADA all sits behind native tokens has no ada-only UTxO to offer as
/// collateral, and whisky cannot emit the `collateral_return` that would let a
/// token-bearing one serve. But THIS tx runs no script, so it needs no
/// collateral at all — only a fee input, and since a fee input may now carry
/// tokens, it can always be built. The tokens ride through to the change
/// output; what comes back is clean ADA.
///
/// Spends the wallet's OTHER UTxOs in preference to its existing collateral
/// candidates, and mints only the shortfall. Consuming a candidate to re-create
/// it would be pure loss, and demanding the full set from a wallet that is one
/// short turns a workable top-up into "fund the wallet".
pub fn build_collateral_top_up(
    wallet_utxos: &[WalletUtxo],
    wallet_address: &str,
    key: &PrivateKey,
    cost_models: &Option<Vec<Vec<i64>>>,
) -> Result<Option<CollateralTopUp>, String> {
    let candidates = collateral_candidates(wallet_utxos);
    let had = candidates.len();
    if had >= COLLATERAL_UTXOS_WANTED {
        return Ok(None);
    }
    let is_candidate = |u: &WalletUtxo| {
        candidates
            .iter()
            .any(|c| c.tx_hash == u.tx_hash && c.output_index == u.output_index)
    };

    // Two passes. The first leaves the existing candidates alone and mints only
    // what is missing; it is what almost every wallet needs. The second is for
    // a wallet whose funds ARE its candidates, where preserving them is not an
    // option and the whole set has to be re-cut.
    let mut plan = None;
    for spend_candidates in [false, true] {
        let created = if spend_candidates {
            COLLATERAL_UTXOS_WANTED
        } else {
            COLLATERAL_UTXOS_WANTED - had
        };
        // `!u.reserved` matters more here than in `select_fee`, and for the
        // opposite reason: this builder reaches for SMALL UTxOs to consolidate,
        // and a reserved nonce is a small UTxO. `select_fee` takes the richest
        // and would rarely touch it by accident; this one would take it first.
        // The shape that made it real: an operator reserves a nonce, leaves for
        // the safe, preflight reports collateral short, and somebody runs
        // `ensure-collateral` — which consumes the nonce, killing a signature
        // whose trip has already been made ([REG-10], [DRG-6]).
        let mut pool: Vec<&WalletUtxo> = wallet_utxos
            .iter()
            .filter(|u| !u.has_ref_script && !u.reserved && (spend_candidates || !is_candidate(u)))
            .collect();
        pool.sort_by_key(|u| std::cmp::Reverse(u.lovelace));

        let mut picked: Vec<&WalletUtxo> = Vec::new();
        let mut sum = 0u64;
        let mut kinds: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let split = created as u64 * COLLATERAL_LOVELACE;
        for u in pool {
            let needed = split + 1_000_000 + token_change_floor(kinds.len());
            if sum >= needed {
                break;
            }
            sum = sum.saturating_add(u.lovelace);
            kinds.extend(u.tokens.keys().map(String::as_str));
            picked.push(u);
        }
        if sum >= split + 1_000_000 + token_change_floor(kinds.len()) {
            plan = Some((created, picked));
            break;
        }
    }

    let Some((created, picked)) = plan else {
        let total: u64 = wallet_utxos
            .iter()
            .filter(|u| !u.has_ref_script && !u.reserved)
            .map(|u| u.lovelace)
            .sum();
        return Err(format!(
            "wallet holds {total} lovelace in spendable UTxOs — not enough to split \
             {} ada-only UTxO(s) of {COLLATERAL_LOVELACE} plus fees and the change output's \
             min-UTxO. Fund the wallet",
            COLLATERAL_UTXOS_WANTED - had
        ));
    };

    let body = TxBuilderBody {
        inputs: picked
            .iter()
            .map(|u| {
                TxIn::PubKeyTxIn(PubKeyTxIn {
                    tx_in: TxInParameter {
                        tx_hash: u.tx_hash.clone(),
                        tx_index: u.output_index,
                        amount: Some(wallet_input_amount(u)),
                        address: Some(wallet_address.to_string()),
                    },
                })
            })
            .collect(),
        outputs: (0..created)
            .map(|_| Output {
                address: wallet_address.to_string(),
                amount: vec![Asset::new_from_str(
                    "lovelace",
                    &COLLATERAL_LOVELACE.to_string(),
                )],
                datum: None,
                reference_script: None,
            })
            .collect(),
        // No script runs here — which is the whole point.
        collaterals: vec![],
        required_signatures: vec![pub_key_hash_hex(key)],
        change_address: wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(cost_models)),
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![],
        certificates: vec![],
        votes: vec![],
        fee: None,
        change_datum: None,
        metadata: vec![],
        validity_range: ValidityRange {
            invalid_before: None,
            invalid_hereafter: None,
        },
        total_collateral: None,
        collateral_return_address: None,
    };

    let mut pallas = WhiskyPallas::new(None);
    pallas.tx_builder_body = body;
    let unsigned_hex = pallas
        .serialize_tx_body()
        .map_err(|e| format!("whisky tx build: {e:?}"))?;
    let signed_tx_hex = sign_built_tx(&unsigned_hex, key)?;

    Ok(Some(CollateralTopUp {
        signed_tx_hex,
        created,
    }))
}

/// The lovelace a reserved nonce UTxO carries. Big enough to clear the
/// ada-only min-UTxO with room to spare, small enough that tying it up for a
/// round trip to a safe costs an operator nothing worth thinking about.
pub const NONCE_RESERVATION_LOVELACE: u64 = 2_000_000;

/// A nonce UTxO, created and ready to submit.
#[derive(Debug, Clone)]
pub struct NonceReservationTx {
    pub signed_tx_hex: String,
    /// The outpoint the reserved output WILL have. Known before the transaction
    /// is submitted, because an output's index is chosen here and the tx id is
    /// the hash of the body that is now fixed.
    pub outpoint: NonceOutpoint,
}

/// Build a self-payment whose first output is a dedicated UTxO for a
/// registration or exit signature to be bound to ([REG-10], [DRG-6]).
///
/// One ordinary transaction, no scripts, so it needs no collateral — the same
/// shape as `ensure-collateral`'s top-up.
///
/// Why create one rather than reserve a UTxO the wallet already holds: the
/// wallet's existing ada-only UTxOs are its COLLATERAL, and a wallet typically
/// has exactly the two it needs. Reserving one of those for a round trip to an
/// air-gapped machine would stop the daemon posting movements for the duration,
/// which is the opposite of what the reservation is for. A fresh 2 ADA output
/// costs a fee and takes nothing away.
///
/// The returned outpoint is usable immediately: the request file can name it
/// before the transaction confirms, because the registration that spends it is
/// hours away in the air-gapped flow, and in the one-machine flow the caller
/// uses the fee input directly instead of coming here.
pub fn build_nonce_reservation_tx(
    wallet_address: &str,
    wallet_utxos: &[WalletUtxo],
    key: &PrivateKey,
    cost_models: &Option<Vec<Vec<i64>>>,
) -> Result<NonceReservationTx, String> {
    // A plain fee selection: this spends one UTxO and hands most of it back as
    // change, so the margin only has to cover the new output plus the fee.
    let funder = select_fee(wallet_utxos, NONCE_RESERVATION_LOVELACE + 1_000_000)?;

    let body = TxBuilderBody {
        inputs: vec![TxIn::PubKeyTxIn(PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: funder.tx_hash.clone(),
                tx_index: funder.output_index,
                amount: Some(wallet_input_amount(funder)),
                address: Some(wallet_address.to_string()),
            },
        })],
        // Index 0, and nothing else before it: the change output whisky appends
        // comes after, so the reserved outpoint's index is fixed at 0.
        outputs: vec![Output {
            address: wallet_address.to_string(),
            amount: vec![Asset::new_from_str(
                "lovelace",
                &NONCE_RESERVATION_LOVELACE.to_string(),
            )],
            datum: None,
            reference_script: None,
        }],
        collaterals: vec![],
        required_signatures: vec![pub_key_hash_hex(key)],
        change_address: wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(cost_models)),
        reference_inputs: vec![],
        withdrawals: vec![],
        mints: vec![],
        certificates: vec![],
        votes: vec![],
        fee: None,
        change_datum: None,
        metadata: vec![],
        validity_range: ValidityRange {
            invalid_before: None,
            invalid_hereafter: None,
        },
        total_collateral: None,
        collateral_return_address: None,
    };

    let mut pallas = WhiskyPallas::new(None);
    pallas.tx_builder_body = body;
    let unsigned_hex = pallas
        .serialize_tx_body()
        .map_err(|e| format!("whisky tx build: {e:?}"))?;
    let signed_tx_hex = sign_built_tx(&unsigned_hex, key)?;

    // The id of the transaction that will create the output: the hash of the
    // body, computed from the SIGNED bytes so it is the id the node will report.
    let bytes = hex::decode(&signed_tx_hex).map_err(|e| format!("signed tx hex decode: {e}"))?;
    let tx: Tx = minicbor::decode(&bytes).map_err(|e| format!("signed tx minicbor decode: {e}"))?;
    let tx_hash: [u8; 32] = *tx.transaction_body.compute_hash();

    Ok(NonceReservationTx {
        signed_tx_hex,
        outpoint: NonceOutpoint { tx_hash, index: 0 },
    })
}

/// Whether a bech32 address is a testnet address (`addr_test…` HRP).
#[must_use]
pub fn is_testnet_address(wallet_address: &str) -> bool {
    // Case-INSENSITIVE: bech32 is defined over either case, and an all-uppercase
    // address is valid and parses fine. A `starts_with("addr_test")` on one of
    // those reads as mainnet, which would tag every derived script address for
    // the wrong network. `resolve_wallet` canonicalizes the wallet address, so
    // this is belt-and-braces for the other things that reach here.
    // `as_bytes().get(..9)` rather than `a[..9]`: this is `pub`, reached from
    // six call sites with operator- and chain-supplied strings, and slicing a
    // str at a byte index that is not a char boundary PANICS. The old
    // `starts_with` could not, and neither may its replacement.
    wallet_address
        .trim()
        .as_bytes()
        .get(..9)
        .is_some_and(|b| b.eq_ignore_ascii_case(b"addr_test"))
}

/// The `pallas_addresses::Network` implied by a bech32 wallet address.
#[must_use]
pub fn network_from_address(wallet_address: &str) -> pallas_addresses::Network {
    if is_testnet_address(wallet_address) {
        pallas_addresses::Network::Testnet
    } else {
        pallas_addresses::Network::Mainnet
    }
}

/// The whisky `Network` to evaluate scripts against: the caller's live `[V1, V2,
/// V3]` cost models when fetched, else whisky's built-in Preprod set.
#[must_use]
pub fn whisky_network(cost_models: &Option<Vec<Vec<i64>>>) -> whisky::Network {
    match cost_models {
        Some(cm) => whisky::Network::Custom(cm.clone()),
        None => whisky::Network::Preprod,
    }
}

/// Min-UTxO for a datum-carrying script output — the conservative datum-scaled
/// formula shared by the registry / ban / treasury elements (the locked value
/// persists for the element's whole on-chain life).
#[must_use]
pub fn element_lovelace(datum_cbor_len: usize) -> u64 {
    std::cmp::max(2_000_000u64, (datum_cbor_len as u64 + 600) * 4310)
}

/// Conway `minFeeRefScriptCostPerByte` (preprod + mainnet). Charged on reference
/// scripts attached to SPENT inputs — which whisky's fee estimation does not
/// model; the bootstrap/apply builders add it explicitly when the one-shot is
/// forced to be a ref-script UTxO.
const REF_SCRIPT_FEE_PER_BYTE: u64 = 15;

/// The Conway tiered ref-script fee (×1.2 per started 25600-byte tier).
#[must_use]
pub fn ref_script_fee(script_size: u64) -> u64 {
    const TIER: u64 = 25_600;
    let mut fee = 0f64;
    let mut multiplier = 1f64;
    let mut remaining = script_size;
    while remaining >= TIER {
        fee += TIER as f64 * multiplier * REF_SCRIPT_FEE_PER_BYTE as f64;
        remaining -= TIER;
        multiplier *= 1.2;
    }
    fee += remaining as f64 * multiplier * REF_SCRIPT_FEE_PER_BYTE as f64;
    fee.ceil() as u64
}

/// Pick the fee input: the richest wallet UTxO that carries no reference
/// script, requiring it to cover `min_fee_lovelace` (the outputs plus a fee
/// margin).
///
/// Native tokens on the fee input are FINE. Every caller declares the input's
/// full value (`wallet_input_amount`), so whisky carries the tokens into the
/// change output and the tx balances. This used to demand pure-ADA, which left
/// a wallet whose ADA all sat behind tokens unable to pay a fee at all — and
/// therefore unable to split itself a clean UTxO to get out of it
/// (WI-20260910-5DRP6). A reference script is still disqualifying: the Conway
/// per-byte ref-script fee is invisible to generic fee estimation.
pub fn select_fee(
    wallet_utxos: &[WalletUtxo],
    min_fee_lovelace: u64,
) -> Result<&WalletUtxo, String> {
    // `reserved` is skipped for the same reason `has_ref_script` is: spending
    // this UTxO for anything else destroys something the wallet still needs —
    // here, the nonce a cold signature is already bound to ([REG-10], [DRG-6]).
    let fee = wallet_utxos
        .iter()
        .filter(|u| !u.has_ref_script && !u.reserved)
        .max_by_key(|u| u.lovelace)
        .ok_or_else(|| "no wallet UTxO available for the fee input".to_string())?;
    // A token-bearing fee input means the change output carries those tokens,
    // and its min-UTxO is higher than the bare one every caller's margin was
    // sized against. Charge for it here, once, rather than in six call sites.
    let needed = min_fee_lovelace.saturating_add(token_change_floor(fee.tokens.len()));
    if fee.lovelace < needed {
        return Err(format!(
            "largest wallet UTxO ({} lovelace, {} token kind(s)) cannot cover the outputs, \
             fees and the change output's min-UTxO (needs >= {needed}) — fund the wallet or \
             consolidate UTxOs",
            fee.lovelace,
            fee.tokens.len()
        ));
    }
    Ok(fee)
}

/// The whisky input amount for a wallet UTxO: its lovelace AND every native
/// token it holds.
///
/// Declaring the full value is what lets a token-bearing UTxO be spent at all.
/// whisky's change math is a multi-asset `Value`, so anything declared here
/// that the outputs do not claim comes back in the change output; anything NOT
/// declared is simply missing from the balance, and the node rejects the tx.
#[must_use]
pub fn wallet_input_amount(u: &WalletUtxo) -> Vec<Asset> {
    let mut amount = vec![Asset::new_from_str("lovelace", &u.lovelace.to_string())];
    amount.extend(
        u.tokens
            .iter()
            .map(|(unit, quantity)| Asset::new_from_str(unit, quantity)),
    );
    amount
}

/// Find a pure-ADA collateral UTxO (>= 5 ADA) that is NOT among `spent_inputs`.
///
/// Pure-ADA is OUR restriction, not the ledger's. Since Babbage (CIP-40) the
/// ada-only rule applies to the collateral BALANCE — `sum(collateral inputs) -
/// collateral_return` — so a token-bearing UTxO is legal collateral as long as
/// the tx carries a `collateral_return` (body field 16) handing every token
/// back. We cannot emit one: whisky's pallas backend ignores
/// `collateral_return_address` and hardcodes the body's `collateral_return` to
/// `None`, so `set_collateral_return_address` is a silent no-op here. Until
/// that changes, token-bearing UTxOs are unusable as collateral and a wallet
/// whose ADA all sits behind native tokens cannot post a script tx (WI-20260910-5DRP6).
///
/// Disjointness from the regular inputs is belt-and-braces, not a ledger rule:
/// no phase-1 predicate forbids the overlap (collateral is only consumed when
/// the inputs are not), but every wallet keeps them apart and so do we.
pub fn select_collateral<'a>(
    wallet_utxos: &'a [WalletUtxo],
    spent_inputs: &[&WalletUtxo],
) -> Result<&'a WalletUtxo, String> {
    wallet_utxos
        .iter()
        .find(|u| {
            u.lovelace >= COLLATERAL_LOVELACE
                && u.pure_ada()
                && !u.reserved
                && !spent_inputs
                    .iter()
                    .any(|s| s.tx_hash == u.tx_hash && s.output_index == u.output_index)
        })
        .ok_or_else(|| {
            "no ada-only wallet UTxO with >= 5 ADA for collateral, distinct from the \
             spending inputs — run `heimdall ensure-collateral`"
                .to_string()
        })
}

/// Sign a whisky-built tx body with the wallet key and splice in the vkey
/// witness (the flow every builder uses after `serialize_tx_body`).
pub fn sign_built_tx(unsigned_hex: &str, key: &PrivateKey) -> Result<String, String> {
    let bytes = hex::decode(unsigned_hex).map_err(|e| format!("unsigned tx hex decode: {e}"))?;
    let mut tx: Tx = minicbor::decode(&bytes).map_err(|e| format!("tx minicbor decode: {e}"))?;
    let body_hash = tx.transaction_body.compute_hash();
    let signature = key.sign(body_hash);
    let pk: [u8; 32] = key.public_key().into();
    let vkw = VKeyWitness {
        vkey: Bytes::from(pk.to_vec()),
        signature: Bytes::from(signature.as_ref().to_vec()),
    };
    let mut vkeys: Vec<VKeyWitness> = tx
        .transaction_witness_set
        .vkeywitness
        .take()
        .map(|s| s.to_vec())
        .unwrap_or_default();
    vkeys.push(vkw);
    tx.transaction_witness_set.vkeywitness = NonEmptySet::from_vec(vkeys);
    let signed = minicbor::to_vec(&tx).map_err(|e| format!("signed tx encode: {e}"))?;
    Ok(hex::encode(signed))
}

/// Error from [`build_oneshot_bootstrap_tx`]. Split so each caller can map it
/// onto its own module error preserving the wallet/build distinction.
#[derive(Debug)]
pub enum BootstrapError {
    /// Wallet/coin-selection problem (one-shot missing, no collateral, etc.).
    Wallet(String),
    /// whisky tx build / CBOR (de)code / signing failure.
    Build(String),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wallet(e) => write!(f, "wallet: {e}"),
            Self::Build(e) => write!(f, "tx build: {e}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// A built (signed, unsubmitted) one-shot linked-list bootstrap tx.
#[derive(Debug, Clone)]
pub struct OneShotBootstrapTx {
    pub signed_tx_hex: String,
    /// The minting-policy script hash (= the list policy id).
    pub policy_id_hex: String,
    /// Enterprise script address holding the list elements.
    pub script_address: String,
}

/// Inputs to [`build_oneshot_bootstrap_tx`]. The varying pieces — root datum,
/// root asset name, and mint redeemer — are precomputed by the caller; the
/// shared skeleton (one-shot spend, fee/collateral selection, root output mint,
/// two-pass ref-script fee, signing) is identical for registry and ban.
pub struct OneShotBootstrapParams<'a> {
    /// The list minting policy (cbor + hash), parameterized by the one-shot.
    pub policy_script: &'a ParameterizedScript,
    pub bootstrap_tx_hash: &'a str,
    pub bootstrap_output_index: u32,
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    pub key: &'a PrivateKey,
    pub one_shot_ref_script_size: Option<u64>,
    /// Live `[V1, V2, V3]` cost models; `None` → whisky's built-in Preprod.
    pub cost_models: Option<Vec<Vec<i64>>>,
    /// CBOR of the `Element{Root, link: None}` datum locked at the script.
    pub root_datum_cbor: Vec<u8>,
    /// The root anchor NFT asset name (`"reg-root"` / `"ban-root"`).
    pub root_asset_name: &'a [u8],
    /// CBOR of the mint `Bootstrap` redeemer (registry: field-less; ban: carries
    /// the one-shot `OutputReference`).
    pub mint_redeemer_cbor: String,
    /// Short noun for error messages (`"registry"` / `"ban"`).
    pub outref_label: &'a str,
}

/// Build + sign the one-shot bootstrap: spend the outref that parameterizes the
/// `policy_script` (it MUST be among `wallet_utxos`) and mint the root anchor
/// NFT to the script address with the inline root datum. This initializes the
/// linked list (the precondition for any insert).
pub fn build_oneshot_bootstrap_tx(
    p: OneShotBootstrapParams,
) -> Result<OneShotBootstrapTx, BootstrapError> {
    let one_shot = p
        .wallet_utxos
        .iter()
        .find(|u| u.tx_hash == p.bootstrap_tx_hash && u.output_index == p.bootstrap_output_index)
        .ok_or_else(|| {
            BootstrapError::Wallet(format!(
                "{} bootstrap outref {}#{} is not an unspent wallet UTxO — the parameterized \
                 policy can only validate a tx spending exactly that outpoint",
                p.outref_label, p.bootstrap_tx_hash, p.bootstrap_output_index
            ))
        })?;
    // The one-shot cannot be swapped (it parameterizes the policy). It MAY carry
    // a reference script — that case is handled by `one_shot_ref_script_size`,
    // which prices the Conway ref-script fee in below.
    //
    // Tokens on it are refused, but no longer because they would be dropped:
    // the input declares its full value a few lines down and whisky balances
    // them into the change. This is a ceremony path that runs once per bridge
    // against an outpoint the protocol dictates, so it stays narrow on purpose
    // — there is no coin selection here to be flexible about, and a surprise in
    // the value of the one-shot is worth stopping for.
    if !one_shot.tokens.is_empty() {
        return Err(BootstrapError::Wallet(format!(
            "{} bootstrap outref {}#{} carries native tokens — the one-shot for a bridge \
             bootstrap must hold only ADA",
            p.outref_label, p.bootstrap_tx_hash, p.bootstrap_output_index
        )));
    }
    if one_shot.has_ref_script && p.one_shot_ref_script_size.is_none() {
        return Err(BootstrapError::Wallet(format!(
            "{} bootstrap outref {}#{} carries a reference script and no size was supplied — \
             without it the Conway per-byte ref-script fee is unpriced and the tx underpays",
            p.outref_label, p.bootstrap_tx_hash, p.bootstrap_output_index
        )));
    }

    let network = network_from_address(p.wallet_address);
    let policy_id_hex = p.policy_script.hash_hex();
    let script_address = p.policy_script.enterprise_address(network);
    let root_lovelace = element_lovelace(p.root_datum_cbor.len());

    // The one-shot doubles as the fee input when rich enough; otherwise add the
    // richest other wallet UTxO alongside it. Tokens on that one are fine —
    // its full value is declared and they come back in the change.
    let mut inputs: Vec<&WalletUtxo> = vec![one_shot];
    if one_shot.lovelace < root_lovelace + 1_000_000 {
        let extra = p
            .wallet_utxos
            .iter()
            .filter(|u| {
                let is_one_shot =
                    u.tx_hash == one_shot.tx_hash && u.output_index == one_shot.output_index;
                // `!u.reserved` for the reason every other selector has it: the
                // nonce a cold signature is bound to is spoken for. Genesis-only,
                // so it has never mattered — but it was the last selector in the
                // tree that took a marked set and then ignored the mark.
                !(u.has_ref_script || u.reserved || is_one_shot)
            })
            .max_by_key(|u| u.lovelace)
            .filter(|u| one_shot.lovelace + u.lovelace >= root_lovelace + 1_000_000)
            .ok_or_else(|| {
                BootstrapError::Wallet(format!(
                    "wallet cannot cover the {root_lovelace}-lovelace root output plus fees — \
                     fund the wallet"
                ))
            })?;
        inputs.push(extra);
    }
    // Collateral must be pure-ADA AND disjoint from the spending inputs above
    // (the one-shot, plus the extra fee input if added) — the same outpoint
    // cannot be both spent and collateral.
    let coll_utxo = select_collateral(p.wallet_utxos, &inputs).map_err(BootstrapError::Wallet)?;

    let root_unit = format!("{policy_id_hex}{}", hex::encode(p.root_asset_name));

    let build = |fee: Option<String>| -> Result<String, BootstrapError> {
        let body = TxBuilderBody {
            inputs: inputs
                .iter()
                .map(|u| {
                    TxIn::PubKeyTxIn(PubKeyTxIn {
                        tx_in: TxInParameter {
                            tx_hash: u.tx_hash.clone(),
                            tx_index: u.output_index,
                            amount: Some(wallet_input_amount(u)),
                            address: Some(p.wallet_address.to_string()),
                        },
                    })
                })
                .collect(),
            outputs: vec![Output {
                address: script_address.clone(),
                amount: vec![
                    Asset::new_from_str("lovelace", &root_lovelace.to_string()),
                    Asset::new_from_str(&root_unit, "1"),
                ],
                datum: Some(Datum::Inline(hex::encode(&p.root_datum_cbor))),
                reference_script: None,
            }],
            collaterals: vec![PubKeyTxIn {
                tx_in: TxInParameter {
                    tx_hash: coll_utxo.tx_hash.clone(),
                    tx_index: coll_utxo.output_index,
                    amount: Some(wallet_input_amount(coll_utxo)),
                    address: Some(p.wallet_address.to_string()),
                },
            }],
            required_signatures: vec![pub_key_hash_hex(p.key)],
            change_address: p.wallet_address.to_string(),
            signing_key: vec![],
            network: Some(whisky_network(&p.cost_models)),
            reference_inputs: vec![],
            withdrawals: vec![],
            mints: vec![MintItem::ScriptMint(ScriptMint {
                mint: MintParameter {
                    policy_id: policy_id_hex.clone(),
                    asset_name: hex::encode(p.root_asset_name),
                    amount: 1,
                },
                redeemer: Some(Redeemer {
                    data: p.mint_redeemer_cbor.clone(),
                    // Bootstrap checks the one-shot is spent + the root output
                    // shape and runs linked_list.init — light.
                    ex_units: Budget {
                        mem: 2_000_000,
                        steps: 900_000_000,
                    },
                }),
                script_source: Some(ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
                    script_cbor: p.policy_script.cbor_hex(),
                    language_version: LanguageVersion::V3,
                })),
            })],
            certificates: vec![],
            votes: vec![],
            fee,
            change_datum: None,
            metadata: vec![],
            validity_range: ValidityRange {
                invalid_before: None,
                invalid_hereafter: None,
            },
            total_collateral: None,
            collateral_return_address: None,
        };
        let mut pallas = WhiskyPallas::new(None);
        pallas.tx_builder_body = body;
        pallas
            .serialize_tx_body()
            .map_err(|e| BootstrapError::Build(format!("whisky tx build: {e:?}")))
    };

    // Pass 1: whisky's own fee estimate. When the one-shot carries a reference
    // script, rebuild with that fee plus the ledger's ref-script charge (and a
    // small margin for the changed fee bytes).
    let mut unsigned_hex = build(None)?;
    if let Some(script_size) = p.one_shot_ref_script_size {
        let tx_bytes = hex::decode(&unsigned_hex)
            .map_err(|e| BootstrapError::Build(format!("unsigned tx hex decode: {e}")))?;
        let tx: Tx = minicbor::decode(&tx_bytes)
            .map_err(|e| BootstrapError::Build(format!("tx minicbor decode: {e}")))?;
        let auto_fee = tx.transaction_body.fee;
        let fee = auto_fee + ref_script_fee(script_size) + 4_400;
        unsigned_hex = build(Some(fee.to_string()))?;
    }
    let signed_tx_hex = sign_built_tx(&unsigned_hex, p.key).map_err(BootstrapError::Build)?;

    Ok(OneShotBootstrapTx {
        signed_tx_hex,
        policy_id_hex,
        script_address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::wallet::{derive_payment_key, wallet_address_from_mnemonic};
    use std::collections::BTreeMap;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const FSAT: &str = "d8c06b705b0089b8da32e1a17550bc0d3a4fea7999508e3e95669d1066534154";

    fn utxo(ix: u32, lovelace: u64, tokens: &[(&str, &str)]) -> WalletUtxo {
        WalletUtxo {
            tx_hash: format!("{ix:064x}"),
            output_index: ix,
            lovelace,
            tokens: tokens
                .iter()
                .map(|(u, q)| ((*u).to_string(), (*q).to_string()))
                .collect::<BTreeMap<_, _>>(),
            has_ref_script: false,
            reserved: false,
        }
    }

    /// The asymmetry this whole change rests on: a fee input may carry native
    /// tokens, a collateral input may not.
    ///
    /// Not a preference. The tokens on a fee input are declared and come back
    /// in the change, so the tx balances. Collateral has no such escape here —
    /// the ledger would take it with a `collateral_return` (Babbage/CIP-40
    /// puts the ada-only test on the BALANCE, not the inputs), but whisky's
    /// pallas backend cannot emit that field.
    #[test]
    fn a_fee_input_may_carry_tokens_but_collateral_may_not() {
        let wallet = vec![utxo(0, 11_000_000_000, &[(FSAT, "42")])];

        let fee = select_fee(&wallet, 2_000_000).expect("a token-bearing UTxO can pay the fee");
        assert_eq!(fee.output_index, 0);

        let err = select_collateral(&wallet, &[]).expect_err("but it cannot be collateral");
        assert!(err.contains("collateral"), "{err}");
        assert!(collateral_candidates(&wallet).is_empty());
    }

    /// A reference script still disqualifies a UTxO from both, for a reason
    /// that has nothing to do with tokens: the Conway per-byte ref-script fee
    /// is invisible to generic fee estimation.
    #[test]
    fn a_reference_script_utxo_is_skipped_whatever_else_it_holds() {
        let mut clean = utxo(0, 100_000_000, &[]);
        clean.has_ref_script = true;
        assert!(!clean.pure_ada());
        let err = select_fee(std::slice::from_ref(&clean), 1).expect_err("not a fee input");
        assert!(err.contains("no wallet UTxO"), "{err}");
    }

    /// Whatever a UTxO holds is declared on the input. Anything left out is
    /// missing from the value balance and the node rejects the tx — which is
    /// exactly how token-bearing UTxOs became unspendable.
    #[test]
    fn the_input_amount_declares_every_token() {
        let amount = wallet_input_amount(&utxo(0, 5_000_000, &[(FSAT, "42")]));
        assert_eq!(amount.len(), 2);
        assert_eq!(amount[0].unit(), "lovelace");
        assert_eq!(amount[0].quantity(), "5000000");
        assert_eq!(amount[1].unit(), FSAT);
        assert_eq!(amount[1].quantity(), "42");
    }

    /// Decode a built body into `(lovelace, distinct asset count)` per output,
    /// so the tests can assert what actually reaches the chain rather than
    /// that a hex string is non-empty.
    fn outputs_of(signed_tx_hex: &str) -> Vec<(u64, usize)> {
        use pallas_primitives::conway::{PseudoTransactionOutput, Tx, Value};
        let bytes = hex::decode(signed_tx_hex).expect("hex");
        let tx: Tx = minicbor::decode(&bytes).expect("cbor");
        tx.transaction_body
            .outputs
            .iter()
            .map(|o| {
                let value = match o {
                    PseudoTransactionOutput::PostAlonzo(o) => &o.value,
                    PseudoTransactionOutput::Legacy(_) => panic!("unexpected legacy output"),
                };
                match value {
                    Value::Coin(c) => (*c, 0),
                    Value::Multiasset(c, assets) => {
                        (*c, assets.iter().map(|(_, a)| a.len()).sum::<usize>())
                    }
                }
            })
            .collect()
    }

    fn signer() -> (PrivateKey, String) {
        (
            derive_payment_key(TEST_MNEMONIC).unwrap(),
            wallet_address_from_mnemonic(TEST_MNEMONIC, pallas_addresses::Network::Testnet)
                .unwrap(),
        )
    }

    #[test]
    fn a_wallet_that_can_already_post_collateral_is_left_alone() {
        let wallet = vec![
            utxo(0, COLLATERAL_LOVELACE, &[]),
            utxo(1, COLLATERAL_LOVELACE, &[]),
        ];
        let (key, addr) = signer();
        let built = build_collateral_top_up(&wallet, &addr, &key, &None).unwrap();
        assert!(built.is_none(), "nothing to split");
    }

    /// The spo4 case, and the point of the whole exercise: every lovelace sits
    /// behind a native token, so there is no collateral and — before this — no
    /// way to make one, because making one needed one. This tx runs no script,
    /// so it needs no collateral to build.
    ///
    /// Asserts the OUTPUTS, not just that something was built: two ada-only
    /// UTxOs of exactly the collateral size, and the token landing in the
    /// change. A wrong value balance here is the failure mode this change
    /// introduces, so it is the thing worth pinning.
    #[test]
    fn a_wallet_whose_ada_is_all_behind_tokens_can_still_split_itself_collateral() {
        let wallet = vec![utxo(0, 11_000_000_000, &[(FSAT, "42")])];
        assert!(collateral_candidates(&wallet).is_empty(), "stuck, before");

        let (key, addr) = signer();
        let built = build_collateral_top_up(&wallet, &addr, &key, &None)
            .expect("builds")
            .expect("something to do");
        assert_eq!(built.created, COLLATERAL_UTXOS_WANTED);

        let outs = outputs_of(&built.signed_tx_hex);
        let collateral: Vec<_> = outs
            .iter()
            .filter(|(c, n)| *c == COLLATERAL_LOVELACE && *n == 0)
            .collect();
        assert_eq!(
            collateral.len(),
            COLLATERAL_UTXOS_WANTED,
            "two ada-only outputs of exactly the collateral size: {outs:?}"
        );
        let token_bearing: Vec<_> = outs.iter().filter(|(_, n)| *n > 0).collect();
        assert_eq!(
            token_bearing.len(),
            1,
            "the token rides into exactly one change output: {outs:?}"
        );
        assert!(
            token_bearing[0].0 >= 1_000_000,
            "the change output keeps enough ADA to exist: {outs:?}"
        );
    }

    /// Only the shortfall is minted. Consuming an existing candidate to
    /// re-create it would be pure loss, and demanding the full set turns a
    /// workable top-up into "fund the wallet".
    #[test]
    fn a_wallet_one_short_mints_one_and_keeps_what_it_has() {
        let wallet = vec![
            utxo(0, COLLATERAL_LOVELACE, &[]),
            utxo(1, 50_000_000, &[(FSAT, "42")]),
        ];
        assert_eq!(collateral_candidates(&wallet).len(), 1);

        let (key, addr) = signer();
        let built = build_collateral_top_up(&wallet, &addr, &key, &None)
            .expect("builds")
            .expect("one short");
        assert_eq!(built.created, 1, "mint the shortfall, not the whole set");

        let outs = outputs_of(&built.signed_tx_hex);
        assert_eq!(
            outs.iter()
                .filter(|(c, n)| *c == COLLATERAL_LOVELACE && *n == 0)
                .count(),
            1,
            "{outs:?}"
        );
    }

    /// A token-bearing fee input is charged for the change output it forces,
    /// because that output's min-UTxO is higher than the bare one every
    /// caller's margin was sized against.
    #[test]
    fn a_token_bearing_fee_input_must_also_cover_the_change_output() {
        let bare = vec![utxo(0, 2_000_000, &[])];
        assert!(
            select_fee(&bare, 2_000_000).is_ok(),
            "ada-only: margin as tuned"
        );

        let tokened = vec![utxo(0, 2_000_000, &[(FSAT, "42")])];
        let err = select_fee(&tokened, 2_000_000).expect_err("not enough for the change output");
        assert!(err.contains("min-UTxO"), "{err}");
        assert!(select_fee(&[utxo(0, 9_000_000, &[(FSAT, "42")])], 2_000_000).is_ok());
    }

    /// An empty wallet is a funding problem, and says so rather than failing
    /// somewhere further in.
    #[test]
    fn an_unfunded_wallet_is_named_as_such() {
        let (key, addr) = signer();
        let err = build_collateral_top_up(&[], &addr, &key, &None).expect_err("cannot split");
        assert!(err.contains("Fund the wallet"), "{err}");
        assert!(!err.contains("  "), "no lost line continuations: {err}");
    }
}
