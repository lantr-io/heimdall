//! Deterministic Treasury Movement (TM) transaction builder.
//!
//! Every SPO independently constructs the same unsigned transaction from shared
//! Cardano state. Identical `txid` is required for FROST signing to succeed.

use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, transaction,
};

/// Dust threshold for P2TR outputs (330 sat).
const DUST_THRESHOLD: Amount = Amount::from_sat(330);

/// Sequence value for all TM inputs (0xFFFFFFFD): signals RBF
/// (< 0xFFFFFFFE) and enables nLockTime (< 0xFFFFFFFF).
///
/// Note: this does NOT satisfy OP_CSV (bit 31 is set, so BIP 112
/// treats the relative locktime as disabled). For the federation
/// script-path leaf, the spender must replace this with the actual
/// relative locktime value at signing time.
const TM_SEQUENCE: Sequence = Sequence(0xFFFFFFFD);

// ---------------------------------------------------------------------------
// Input / output types
// ---------------------------------------------------------------------------

/// Current treasury UTXO.
pub struct TreasuryInput {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub spend_info: TaprootSpendInfo,
}

/// A peg-in UTXO to sweep into the treasury.
pub struct PegInInput {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub spend_info: TaprootSpendInfo,
}

/// A peg-out request to fulfil from the treasury.
///
/// Carries its own request identity (`por_id`, `outpoint`) and its own
/// datum-pinned `per_pegout_fee`, because the rev-5.1 completed-peg-outs trie is
/// keyed by `por_id` and valued by `dest_spk ‖ le8(amount − per_pegout_fee)` —
/// `peg-out.ak`'s Complete branch rebuilds exactly those bytes from the request's
/// own datum, never from a live config value.
///
/// `build_tm` owns every skip: non-standard script, sub-dust net, a `created`
/// outside the freshness window, a `por_id` the local trie already records as
/// completed, and a `por_id` repeated within this batch. Since WI-031 there is no
/// separate already-paid filter in the caller — the trie IS that record, and it is
/// the only one keyed by request identity.
pub struct PegOutRequest {
    pub script_pubkey: ScriptBuf,
    /// Gross locked fBTC (satoshi).
    pub amount: Amount,
    /// The request's OWN `per_pegout_fee` datum field. The TM pays
    /// `amount − per_pegout_fee`.
    pub per_pegout_fee: Amount,
    /// `sha256(serialise_data(OutputReference))` of the request UTxO — Aiken
    /// `bifrost/utils.hash_output_ref`. The completed-peg-outs trie key.
    pub por_id: [u8; 32],
    /// The request's Cardano outpoint, 36 bytes: tx hash (32) ++ output index as
    /// 4 little-endian bytes. Published verbatim as the TM datum's
    /// `fulfilled_por_outpoints` hint.
    pub outpoint: [u8; 36],
    /// `created` (POSIX ms) from the request datum — the freshness filter input.
    pub created: i64,
}

/// The Config-resident operational parameters TM construction consumes —
/// `ConfigDatum` fields #12, #13 and #14 — read **as of the batch snapshot slot**
/// (spec §Operational parameters, determinism rule).
///
/// Every field here is a consensus input: it decides either the transaction's
/// amounts or its skip set, so two SPOs holding different values build different
/// TM bytes and FROST signing cannot converge. That is why they live in the
/// Config UTxO rather than each node's `heimdall.toml` — see
/// [`crate::cardano::config_params`], which resolves them (and falls back to the
/// node-local dev override only when no Config UTxO is configured).
///
/// The *effective* per-peg-out protocol fee is NOT here: since rev 5.1 it is
/// pinned per request in the peg-out datum (see [`PegOutRequest::per_pegout_fee`]),
/// and #13 below is only the floor that fee must clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmParams {
    /// Config #12 — the EXACT miner fee rate: `miner fee = vsize × rate`.
    pub fee_rate_sat_per_vb: u64,
    /// Config #13 — the floor for a request's own datum-pinned `per_pegout_fee`.
    /// A request paying less is skipped (it would under-pay the protocol).
    pub per_pegout_fee_floor: Amount,
    /// Config #14 — the minimum fBTC a PegOut request may lock. A request
    /// locking less is skipped.
    pub min_peg_out_fbtc: Amount,
}

impl TmParams {
    /// Fee rate only, both selection floors disabled (zero).
    ///
    /// The shape of a Config that predates the operational-parameter append —
    /// and of the dev/offline paths (`treasury-self-send`, `federation-spend`,
    /// the mock/fixture chain), which are single-signer and so have no
    /// cross-SPO agreement to lose.
    #[must_use]
    pub fn fee_rate_only(fee_rate_sat_per_vb: u64) -> Self {
        Self {
            fee_rate_sat_per_vb,
            per_pegout_fee_floor: Amount::ZERO,
            min_peg_out_fbtc: Amount::ZERO,
        }
    }
}

/// Freshness window for peg-out selection.
///
/// A peg-out this TM pays must still be un-cancellable when the TM confirms:
/// `peg_out.ak::Cancel` refunds the requester's fBTC once
/// `created + peg_out_cancel_timeout_ms` has passed, and a request cancelled after
/// its BTC was paid is a double spend of treasury funds. So a request is payable
/// only while it is at least `margin_ms` away from that deadline.
///
/// DETERMINISM: `now_ms` must be a CHAIN-derived time (the Cardano tip's block
/// time), not the local wall clock, or two SPOs can classify a borderline request
/// differently and build different TM bytes. Callers pass the same tip time they
/// used for the rest of the chain snapshot.
pub struct Freshness {
    /// Chain "now", POSIX milliseconds.
    pub now_ms: i64,
    /// Required distance (ms) from the cancel deadline.
    pub margin_ms: i64,
}

/// `peg_out.ak::peg_out_cancel_timeout_ms` — 30 days in ms. A request may be
/// cancelled by its owner once `created + this` has elapsed.
pub const PEG_OUT_CANCEL_TIMEOUT_MS: i64 = 2_592_000_000;

// ---------------------------------------------------------------------------
// BTMR1 two-root commitment (spi_root ++ cpo_root)
//
// Spec: ft-bifrost-bridge `docs/superpowers/specs/
// 2026-08-06-bridge-state-singleton-design.md`, §Root commitment output, with
// [CTM-26] (exactly one such output per TM) and [OH-3] (the fee constant).
// The tag is "BTMR1", not a "BFR"-prefixed one, BECAUSE watchtowers detect
// peg-in deposits by scanning for "BFR" and a TM pays the treasury address —
// a "BFR" tag here would be read back as a deposit to the treasury.
// ---------------------------------------------------------------------------

/// First 7 bytes of the BTMR1 two-root commitment scriptPubKey:
/// `OP_RETURN`(0x6a) `OP_PUSHBYTES_69`(0x45) `"BTMR1"`. Mirrors
/// `TreasuryMovementValidator.RootCommitmentPrefix` (rev 5.4).
pub const BTMR1_COMMITMENT_PREFIX: [u8; 7] = [0x6a, 0x45, 0x42, 0x54, 0x4d, 0x52, 0x31];

/// Length of a well-formed commitment scriptPubKey:
/// prefix(7) + spi_root(32) + cpo_root(32) = 71.
pub const BTMR1_COMMITMENT_SCRIPT_LEN: usize = 71;

/// Offset of `spi_root` in the commitment scriptPubKey: bytes `[7, 39)`.
const BTMR1_SPI_ROOT_OFFSET: usize = 7;

/// Offset of `cpo_root` in the commitment scriptPubKey: bytes `[39, 71)`.
const BTMR1_CPO_ROOT_OFFSET: usize = 39;

/// [OH-3]: extra vsize the commitment output costs over the 34-byte-scriptPubKey
/// output [`estimate_vsize`] budgets for: its scriptPubKey is 71 bytes, so 37
/// bytes more of non-witness data (weight 4·37, vsize +37).
const CPO_COMMITMENT_EXTRA_VBYTES: u64 = 37;

/// The commitment output's scriptPubKey: prefix ++ `spi_root` ++ `cpo_root`.
#[must_use]
pub fn btmr1_commitment_script(spi_root: &[u8; 32], cpo_root: &[u8; 32]) -> ScriptBuf {
    let mut v = Vec::with_capacity(BTMR1_COMMITMENT_SCRIPT_LEN);
    v.extend_from_slice(&BTMR1_COMMITMENT_PREFIX);
    v.extend_from_slice(spi_root);
    v.extend_from_slice(cpo_root);
    ScriptBuf::from_bytes(v)
}

/// True iff the raw scriptPubKey bytes `spk` are a BTMR1 two-root commitment.
/// Length AND prefix, so a short script cannot be sliced past its end and a
/// 71-byte payment script cannot masquerade as one.
#[must_use]
pub fn is_btmr1_commitment(spk: &[u8]) -> bool {
    spk.len() == BTMR1_COMMITMENT_SCRIPT_LEN
        && spk[..BTMR1_COMMITMENT_PREFIX.len()] == BTMR1_COMMITMENT_PREFIX
}

/// The `(spi_root, cpo_root)` pair a BTMR1 scriptPubKey carries, or `None` when
/// `spk` is not one. The single place the byte offsets live: every reader of a
/// commitment, on Bitcoin bytes or on Cardano datum bytes, goes through here.
#[must_use]
pub fn btmr1_roots(spk: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if !is_btmr1_commitment(spk) {
        return None;
    }
    let mut spi_root = [0u8; 32];
    let mut cpo_root = [0u8; 32];
    spi_root.copy_from_slice(&spk[BTMR1_SPI_ROOT_OFFSET..BTMR1_CPO_ROOT_OFFSET]);
    cpo_root.copy_from_slice(&spk[BTMR1_CPO_ROOT_OFFSET..BTMR1_COMMITMENT_SCRIPT_LEN]);
    Some((spi_root, cpo_root))
}

/// True iff `spk` is a BTMR1 two-root commitment — the `Script`-typed spelling
/// of [`is_btmr1_commitment`].
#[must_use]
pub fn is_cpo_commitment(spk: &bitcoin::Script) -> bool {
    is_btmr1_commitment(spk.as_bytes())
}

/// Both roots a TM attests, read from its outputs: `(spi_root, cpo_root)`.
///
/// Byte-identical rule to `TreasuryMovementValidator.committedRoot`: scan the FULL
/// output list, EXACTLY ONE commitment must be present (at any position);
/// `spi_root` is script bytes `[7, 39)` and `cpo_root` is script bytes `[39, 71)`.
/// Zero fails and two or more fail — the on-chain validator rejects both, so a TM
/// built or received with either is unconfirmable.
pub fn committed_roots(tx: &Transaction) -> Result<([u8; 32], [u8; 32]), String> {
    let mut found: Option<([u8; 32], [u8; 32])> = None;
    let mut count = 0usize;
    for out in &tx.output {
        if let Some(roots) = btmr1_roots(out.script_pubkey.as_bytes()) {
            count += 1;
            found = Some(roots);
        }
    }
    match count {
        1 => Ok(found.expect("count == 1")),
        0 => Err("missing root commitment (no \"BTMR1\" OP_RETURN output)".to_string()),
        n => Err(format!("multiple root commitments ({n} \"BTMR1\" outputs)")),
    }
}

/// The swept peg-ins root a TM attests — script bytes `[7, 39)` of its single
/// BTMR1 commitment output. See [`committed_roots`] for the rule.
pub fn committed_spi_root(tx: &Transaction) -> Result<[u8; 32], String> {
    committed_roots(tx).map(|(spi, _)| spi)
}

/// The completed-peg-outs root a TM attests — script bytes `[39, 71)` of its
/// single BTMR1 commitment output. See [`committed_roots`] for the rule.
pub fn committed_cpo_root(tx: &Transaction) -> Result<[u8; 32], String> {
    committed_roots(tx).map(|(_, cpo)| cpo)
}

// ---------------------------------------------------------------------------
// Completed-peg-outs trie, as the builder sees it
// ---------------------------------------------------------------------------

/// One peg-out this TM fulfils, in the form the completed-peg-outs trie stores.
#[derive(Debug, Clone)]
pub struct FulfilledPegOut {
    /// Trie key.
    pub por_id: [u8; 32],
    /// The request's Cardano outpoint (the TM datum's data-availability hint).
    pub outpoint: [u8; 36],
    /// Destination scriptPubKey, as paid.
    pub script_pubkey: ScriptBuf,
    /// `gross − per_pegout_fee`, as paid.
    pub net_amount: Amount,
}

impl FulfilledPegOut {
    /// Trie value: `scriptPubKey ‖ amount as 8 little-endian bytes`. `peg-out.ak`
    /// rebuilds exactly these bytes, so any change here breaks peg-out completion.
    #[must_use]
    pub fn trie_value(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.script_pubkey.len() + 8);
        v.extend_from_slice(self.script_pubkey.as_bytes());
        v.extend_from_slice(&self.net_amount.to_sat().to_le_bytes());
        v
    }
}

/// The completed-peg-outs trie, as much of it as the builder needs.
///
/// Declared here rather than taking `cardano::cpo_trie::CpoTrie` directly so the
/// `bitcoin` modules keep no dependency on the `cardano` ones (the same reason
/// [`outpoint_sort_key`] is duplicated from `tm_chain`).
pub trait CpoTrieView {
    /// Is this peg-out already recorded as completed? A completed request must
    /// never be paid again — the on-chain trie is append-only, so a second
    /// payment could never be proven and the BTC would simply be gone.
    fn contains(&self, por_id: &[u8; 32]) -> bool;

    /// The root that holds after `fulfilled` is inserted. With an empty slice
    /// this is the CURRENT root — every TM commits a root, including one that
    /// fulfils no peg-out.
    fn root_after(&self, fulfilled: &[FulfilledPegOut]) -> Result<[u8; 32], String>;
}

/// A trie view for callers that have no trie yet: nothing is completed and the
/// root never moves off `root`. Test/bootstrap use only — a TM built against this
/// commits a root that ignores the peg-outs it pays, which co-signers reject.
pub struct FixedCpoRoot(pub [u8; 32]);

impl CpoTrieView for FixedCpoRoot {
    fn contains(&self, _por_id: &[u8; 32]) -> bool {
        false
    }
    fn root_after(&self, _fulfilled: &[FulfilledPegOut]) -> Result<[u8; 32], String> {
        Ok(self.0)
    }
}

/// The swept peg-ins trie, as much of it as the builder needs. Same
/// dependency-direction story as [`CpoTrieView`]: declared here rather than
/// taking `cardano::spi_trie::SpiTrie` directly so the `bitcoin` modules keep no
/// dependency on the `cardano` ones.
pub trait SpiTrieView {
    /// The root that holds after this TM's `inputs` are recorded, per [SPI-1]:
    /// `inputs` is EVERY input in tx order (input 0 first, in the 36-byte
    /// `txid ‖ vout_le` encoding); every input EXCEPT input 0 becomes an entry.
    fn root_after_inputs(&self, inputs: &[[u8; 36]]) -> Result<[u8; 32], String>;
}

/// A swept peg-ins view for callers that have no trie yet: the root never moves
/// off `root`. Test/bootstrap use only — a TM built against this commits a root
/// that ignores the deposits it sweeps, which co-signers reject.
pub struct FixedSpiRoot(pub [u8; 32]);

impl SpiTrieView for FixedSpiRoot {
    fn root_after_inputs(&self, _inputs: &[[u8; 36]]) -> Result<[u8; 32], String> {
        Ok(self.0)
    }
}

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// An unsigned TM transaction ready for FROST signing.
pub struct UnsignedTm {
    pub tx: Transaction,
    pub txid: Txid,
    pub prevouts: Vec<TxOut>,
    pub input_spend_info: Vec<TaprootSpendInfo>,
    /// Peg-out requests dropped from this TM by the skip rules (see
    /// [`SkipReason`]) — including the already-paid ones, which since WI-031 are
    /// recognised here by their `por_id` in the completed-peg-outs trie rather than
    /// pre-filtered by the caller. Surfaced so the operator can see what was
    /// skipped; the user reclaims via `peg_out.ak`'s Cancel path.
    pub skipped_pegouts: Vec<SkippedPegOut>,
    /// The peg-outs this TM pays, in payment-output order (`tx.output[1..=n]`).
    /// Their `(por_id, trie_value())` pairs are exactly what [`Self::cpo_root`]
    /// commits, and their `outpoint`s are the datum hint `publish.rs` writes.
    pub fulfilled: Vec<FulfilledPegOut>,
    /// The completed-peg-outs MPF root this TM commits, i.e. the root that holds
    /// after [`Self::fulfilled`] is inserted. Also readable back out of the tx
    /// with [`committed_cpo_root`] — the two agree by construction.
    pub cpo_root: [u8; 32],
    /// The swept peg-ins MPF root this TM commits: the builder's SPI trie
    /// advanced by every tx input except input 0 ([SPI-1], [SPI-3]). Also
    /// readable back out of the tx with [`committed_spi_root`] — the two agree
    /// by construction.
    pub spi_root: [u8; 32],
}

/// A peg-out request excluded from a TM (see [`UnsignedTm::skipped_pegouts`]).
#[derive(Debug, Clone)]
pub struct SkippedPegOut {
    pub script_pubkey: ScriptBuf,
    /// The gross amount from the PegOut UTxO (before the per-pegout fee).
    pub amount: Amount,
    pub por_id: [u8; 32],
    pub reason: SkipReason,
}

/// Why a peg-out was excluded from the TM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Gross amount minus the per-pegout fee is below the dust threshold — no
    /// valid BTC output can be produced.
    BelowDust,
    /// The destination scriptPubKey is not a standard, spendable output type
    /// (empty / OP_RETURN / bare / non-standard) — unsafe or non-relayable.
    NonStandardScript,
    /// The local completed-peg-outs trie already records this `por_id`. Paying it
    /// again would spend treasury BTC for a completion that is already proven.
    AlreadyCompleted,
    /// `created` is in the future relative to chain now — the request cannot be
    /// evaluated against the cancel deadline yet.
    NotYetCreated,
    /// The request is within the freshness margin of its cancel deadline
    /// (`created + peg_out_cancel_timeout_ms`). Paying it risks the owner
    /// cancelling for the fBTC after taking the BTC.
    NearCancelDeadline,
    /// The same `por_id` appeared earlier in this very batch. Paying it twice
    /// would move BTC that the (idempotent) trie insert never accounts for.
    DuplicateRequest,
    /// The locked fBTC is below `min_peg_out_fbtc` (Config #14) at the batch
    /// snapshot slot — a request smaller than the protocol accepts.
    BelowMinPegOut,
    /// The request's own datum `per_pegout_fee` is below the protocol floor
    /// (Config #13) at the batch snapshot slot. `peg-out.ak` binds completion to
    /// the datum fee, so paying it would settle a withdrawal that never covered
    /// the protocol's cost.
    FeeBelowFloor,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowDust => write!(f, "amount below dust after fee"),
            Self::NonStandardScript => write!(f, "non-standard/unspendable destination script"),
            Self::AlreadyCompleted => write!(f, "already recorded in the completed-peg-outs trie"),
            Self::NotYetCreated => write!(f, "datum `created` is in the future"),
            Self::NearCancelDeadline => {
                write!(f, "too close to the peg-out cancel deadline")
            }
            Self::DuplicateRequest => write!(f, "duplicate request in this TM's batch"),
            Self::BelowMinPegOut => {
                write!(f, "locked amount below the Config min_peg_out_fbtc")
            }
            Self::FeeBelowFloor => {
                write!(f, "datum per_pegout_fee below the Config floor")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum TmBuildError {
    InsufficientFunds {
        available: Amount,
        required: Amount,
    },
    DustOutput {
        index: usize,
        value: Amount,
    },
    MalformedUnsignedTm {
        inputs: usize,
        prevouts: usize,
        spend_infos: usize,
    },
    /// The federation CSV leaf could not be spent script-path — its control
    /// block is absent from the treasury `TaprootSpendInfo` (the leaf handed in
    /// does not belong to this tree).
    FederationLeafSpend(String),
    /// The completed-peg-outs trie could not produce the post-TM root (duplicate
    /// `por_id`, corrupt local state). Fatal: a TM without a correct BTMR1
    /// commitment can never confirm on Cardano.
    CpoRoot(String),
    /// The swept peg-ins trie could not produce the post-TM root (conflicting
    /// entry, corrupt local state). Fatal for the same reason as
    /// [`Self::CpoRoot`]: the BTMR1 commitment needs both roots.
    SpiRoot(String),
}

impl fmt::Display for TmBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientFunds {
                available,
                required,
            } => {
                write!(f, "insufficient funds: have {available}, need {required}")
            }
            Self::DustOutput { index, value } => {
                write!(f, "output [{index}] value {value} below dust threshold")
            }
            Self::MalformedUnsignedTm {
                inputs,
                prevouts,
                spend_infos,
            } => write!(
                f,
                "malformed UnsignedTm: {inputs} inputs but {prevouts} prevouts \
                 and {spend_infos} spend infos (all must match)"
            ),
            Self::FederationLeafSpend(m) => write!(f, "federation leaf spend: {m}"),
            Self::CpoRoot(m) => write!(f, "completed-peg-outs root: {m}"),
            Self::SpiRoot(m) => write!(f, "swept peg-ins root: {m}"),
        }
    }
}

impl std::error::Error for TmBuildError {}

// ---------------------------------------------------------------------------
// Vsize estimation
// ---------------------------------------------------------------------------

/// Estimate the vsize of a key-path-spend Taproot transaction.
///
/// Non-witness per input: outpoint(36) + scriptSig_len(1) + sequence(4) = 41
/// Witness per input: items_count(1) + sig_len(1) + sig(64) = 66
/// Per P2TR output: value(8) + scriptPubKey_len(1) + scriptPubKey(34) = 43
/// Fixed overhead: version(4) + marker(1) + flag(1) + locktime(4) = 10
/// Plus varint for input/output counts (1 byte each for < 253 items).
pub fn estimate_vsize(num_inputs: usize, num_outputs: usize) -> u64 {
    let fixed = 10u64; // version(4) + marker(1) + flag(1) + locktime(4)
    let input_count_varint = varint_size(num_inputs as u64);
    let output_count_varint = varint_size(num_outputs as u64);

    let non_witness = fixed
        + input_count_varint
        + (num_inputs as u64) * 41
        + output_count_varint
        + (num_outputs as u64) * 43;

    let witness = (num_inputs as u64) * 66;

    // vsize = ceil((non_witness * 4 + witness) / 4)
    //       = (non_witness * 4 + witness + 3) / 4
    (non_witness * 4 + witness + 3) / 4
}

fn varint_size(n: u64) -> u64 {
    if n < 0xFD {
        1
    } else if n <= 0xFFFF {
        3
    } else if n <= 0xFFFF_FFFF {
        5
    } else {
        9
    }
}

// ---------------------------------------------------------------------------
// Outpoint sorting key
// ---------------------------------------------------------------------------

/// Total sort key for a [`SkipReason`], so the skip report has a deterministic
/// order across SPOs.
fn skip_reason_sort_key(r: &SkipReason) -> u8 {
    match r {
        SkipReason::BelowDust => 0,
        SkipReason::NonStandardScript => 1,
        SkipReason::AlreadyCompleted => 2,
        SkipReason::NotYetCreated => 3,
        SkipReason::NearCancelDeadline => 4,
        SkipReason::DuplicateRequest => 5,
        SkipReason::BelowMinPegOut => 6,
        SkipReason::FeeBelowFloor => 7,
    }
}

/// 36-byte sort key: txid bytes in **internal** (consensus / `to_byte_array`)
/// order — the REVERSE of the hex you see in explorers — followed by vout (LE).
///
/// Byte-identical to [`crate::cardano::tm_chain::outpoint_bytes`], which is the
/// canonical encoder for this layout and carries the non-palindromic byte-order
/// test. Kept separate only to avoid a `bitcoin` → `cardano` module dependency;
/// if the two ever disagree, `tm_chain` is right.
fn outpoint_sort_key(op: &OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    let txid_bytes = op.txid.to_byte_array();
    key[..32].copy_from_slice(&txid_bytes);
    key[32..36].copy_from_slice(&op.vout.to_le_bytes());
    key
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// True iff `spk` is a standard, spendable Bitcoin output type
/// (P2PKH / P2SH / P2WPKH / P2WSH / P2TR). Rejects empty (anyone-can-spend),
/// OP_RETURN (unspendable), bare multisig / P2PK, and any non-standard script —
/// none of which a TM can safely pay. All accepted types have a scriptPubKey
/// <= 34 bytes, keeping `estimate_vsize` a safe upper bound.
fn is_standard_payable(spk: &bitcoin::Script) -> bool {
    spk.is_p2pkh() || spk.is_p2sh() || spk.is_p2wpkh() || spk.is_p2wsh() || spk.is_p2tr()
}

/// Build a deterministic unsigned Treasury Movement transaction.
///
/// Every honest SPO must produce byte-identical bytes for the same
/// inputs, so construction follows a canonical recipe:
///
/// - **Version:** 2 (needed for OP_CSV in leaf scripts)
/// - **Locktime:** 0
/// - **Inputs:** `[0]` = treasury, `[1..k]` = peg-ins sorted by `(txid || vout_le)`
/// - **Outputs:** `[0]` = treasury change, `[1..m]` = peg-out payments sorted
///   by `(script_pubkey, amount, por_id)`, `[m+1]` = the BTMR1 two-root
///   commitment, always LAST and always present
/// - **Fee:** `vsize * fee_rate_sat_per_vb`
/// - **Change:** `sum(inputs) - sum(peg_out_outputs) - miner_fee`
///
/// Peg-outs this TM cannot fulfil are skipped, never fatal — see the skip rule at
/// the top of the body.
pub fn build_tm(
    treasury: TreasuryInput,
    mut pegins: Vec<PegInInput>,
    mut pegouts: Vec<PegOutRequest>,
    change_script_pubkey: ScriptBuf,
    params: &TmParams,
    freshness: &Freshness,
    cpo: &dyn CpoTrieView,
    spi: &dyn SpiTrieView,
) -> Result<UnsignedTm, TmBuildError> {
    // --- Drop unpayable peg-outs (skip, don't abort) ---
    // The peg-out destination + amount come from attacker-controllable on-chain
    // datum (anyone can lock fBTC at the permissionlessly-payable peg_out.ak
    // address). SKIP a request the TM cannot safely pay rather than fail the
    // whole TM — one tiny/hostile peg-out must not block every peg-in and
    // peg-out (bridge-wide liveness DoS). The user reclaims via Cancel. Five ways
    // a request is unpayable HERE; payment history is the sixth, and since WI-031 it
    // is decided here too, from the `por_id` trie the caller hands in:
    //
    //  (1) Non-standard destination scriptPubKey. An empty script is
    //      anyone-can-spend (treasury BTC claimable by anyone — fund loss),
    //      OP_RETURN is an unspendable burn, and any non-standard/oversized
    //      script makes the whole TM non-relayable (dead on arrival, taking the
    //      batched peg-ins with it). Accepting only P2PKH/P2SH/P2WPKH/P2WSH/P2TR
    //      also caps every peg-out spk at 34 bytes, so estimate_vsize's
    //      per-output assumption stays a safe upper bound — and rules out a
    //      payment that could be mistaken for the 71-byte BTMR1 commitment.
    //  (2) Net (gross − the request's OWN per_pegout_fee) below the dust
    //      threshold — no valid output exists.
    //  (3) Already in the local completed-peg-outs trie. The trie is the record
    //      of what the FROST quorum has attested; re-paying an entry in it spends
    //      treasury BTC for a completion that is already provable.
    //  (4) Outside the freshness window: `created` in the future, or within
    //      `margin_ms` of `created + PEG_OUT_CANCEL_TIMEOUT_MS`. A request the
    //      owner can cancel after taking the BTC is a treasury double spend.
    //  (5) Below an Operational-params floor: locked fBTC under `min_peg_out_fbtc`
    //      (Config #14), or a datum `per_pegout_fee` under the protocol floor
    //      (Config #13). Neither is checked when the request is created — anyone
    //      can write a `PegOutDatum` directly at the permissionless address — so
    //      this skip is where the two governance bounds are actually enforced.
    //
    // DETERMINISM: every SPO must skip the SAME set to build byte-identical TMs
    // for FROST. (1) is network-independent, (2) now reads a datum-pinned fee so
    // it is a consensus value, (3) is consensus once the trie is chain-attested,
    // (4) is consensus only insofar as `freshness.now_ms` is chain-derived —
    // see [`Freshness`] — and (5) is consensus because both floors come from the
    // Config UTxO read at the batch snapshot slot, never from `heimdall.toml`
    // (see [`TmParams`]).
    let mut skipped_pegouts = Vec::new();
    // Every `por_id` already accepted into THIS TM.
    //
    // A `por_id` identifies a request UTxO, so the chain scan cannot produce two —
    // but a caller that concatenated two overlapping scans could. That would pay
    // the same request twice while the trie recorded ONE entry (a trie insert is
    // idempotent on an identical key/value), so the committed root would not
    // account for the second payment and the treasury would be short with no
    // completion to show for it. Dedupe rather than abort: the duplicate describes
    // a request already being paid by this very TM, so dropping it is exactly
    // right, and one caller bug must not block every peg-in and peg-out.
    let mut seen_por_ids: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    pegouts.retain(|po| {
        let mut skip = |reason| {
            skipped_pegouts.push(SkippedPegOut {
                script_pubkey: po.script_pubkey.clone(),
                amount: po.amount,
                por_id: po.por_id,
                reason,
            });
            false
        };
        if !is_standard_payable(&po.script_pubkey) {
            return skip(SkipReason::NonStandardScript);
        }
        if cpo.contains(&po.por_id) {
            return skip(SkipReason::AlreadyCompleted);
        }
        if !seen_por_ids.insert(po.por_id) {
            return skip(SkipReason::DuplicateRequest);
        }
        if po.amount < params.min_peg_out_fbtc {
            return skip(SkipReason::BelowMinPegOut);
        }
        if po.per_pegout_fee < params.per_pegout_fee_floor {
            return skip(SkipReason::FeeBelowFloor);
        }
        if po.created > freshness.now_ms {
            return skip(SkipReason::NotYetCreated);
        }
        // Saturating: a `created` near i64::MAX must not wrap into "fresh".
        let deadline = po.created.saturating_add(PEG_OUT_CANCEL_TIMEOUT_MS);
        if deadline.saturating_sub(freshness.now_ms) < freshness.margin_ms {
            return skip(SkipReason::NearCancelDeadline);
        }
        if !matches!(
            po.amount.checked_sub(po.per_pegout_fee),
            Some(net) if net >= DUST_THRESHOLD
        ) {
            return skip(SkipReason::BelowDust);
        }
        true
    });

    // --- Sort peg-in inputs lexicographically by (txid || vout_le) ---
    pegins.sort_by(|a, b| outpoint_sort_key(&a.outpoint).cmp(&outpoint_sort_key(&b.outpoint)));

    // --- Sort peg-out outputs by (script_pubkey, net amount, por_id) ---
    // Spec orders outputs by raw scriptPubKey; the net amount breaks ties. That
    // tiebreaker is load-bearing: with a spk-only comparator two requests sharing
    // a destination but differing in amount would keep their caller-supplied
    // relative order (sort_by is stable), so the TM bytes — and therefore the
    // FROST message — would depend on the order the chain query happened to
    // return, which is not a consensus input. `por_id` is the final tiebreaker:
    // two requests equal in spk and net amount produce byte-identical TxOuts, so
    // their order cannot change the tx, but it DOES change the order of
    // `UnsignedTm::fulfilled` and hence of the datum hint. Sorting on the unique
    // `por_id` makes that list a function of the selected set alone.
    //
    // Sort on the NET amount (what the output pays), not the gross: two requests
    // with different gross amounts and different datum fees can pay the same net,
    // and it is the paid value that decides output order.
    pegouts.sort_by(|a, b| {
        let net = |p: &PegOutRequest| p.amount.to_sat().saturating_sub(p.per_pegout_fee.to_sat());
        a.script_pubkey
            .as_bytes()
            .cmp(b.script_pubkey.as_bytes())
            .then(net(a).cmp(&net(b)))
            .then(a.por_id.cmp(&b.por_id))
    });

    // --- Build inputs ---
    let num_inputs = 1 + pegins.len();
    let num_pegout_outputs = pegouts.len();
    // +1 change, +1 the mandatory BTMR1 commitment.
    let num_outputs = num_pegout_outputs + 2;

    let mut inputs = Vec::with_capacity(num_inputs);
    let mut prevouts = Vec::with_capacity(num_inputs);
    let mut input_spend_info = Vec::with_capacity(num_inputs);

    // [0] = treasury
    let treasury_script_pubkey = ScriptBuf::new_p2tr_tweaked(treasury.spend_info.output_key());
    inputs.push(TxIn {
        previous_output: treasury.outpoint,
        script_sig: ScriptBuf::default(),
        sequence: TM_SEQUENCE,
        witness: Witness::default(),
    });
    prevouts.push(TxOut {
        value: treasury.value,
        script_pubkey: treasury_script_pubkey,
    });
    input_spend_info.push(treasury.spend_info);

    // [1..k] = peg-ins (already sorted)
    for pi in pegins {
        let pi_script_pubkey = ScriptBuf::new_p2tr_tweaked(pi.spend_info.output_key());
        inputs.push(TxIn {
            previous_output: pi.outpoint,
            script_sig: ScriptBuf::default(),
            sequence: TM_SEQUENCE,
            witness: Witness::default(),
        });
        prevouts.push(TxOut {
            value: pi.value,
            script_pubkey: pi_script_pubkey,
        });
        input_spend_info.push(pi.spend_info);
    }

    // --- Compute total input value ---
    let total_input: Amount = prevouts.iter().map(|p| p.value).sum();

    // --- Compute peg-out totals ---
    let mut total_pegout = Amount::ZERO;
    let mut pegout_outputs = Vec::with_capacity(num_pegout_outputs);
    let mut fulfilled = Vec::with_capacity(num_pegout_outputs);

    for po in pegouts.iter() {
        // `retain` above guarantees net >= DUST_THRESHOLD for every remaining peg-out.
        let net_amount = po
            .amount
            .checked_sub(po.per_pegout_fee)
            .expect("retained => amount > fee");
        total_pegout = total_pegout.checked_add(net_amount).expect("no overflow");
        pegout_outputs.push(TxOut {
            value: net_amount,
            script_pubkey: po.script_pubkey.clone(),
        });
        fulfilled.push(FulfilledPegOut {
            por_id: po.por_id,
            outpoint: po.outpoint,
            script_pubkey: po.script_pubkey.clone(),
            net_amount,
        });
    }

    // --- The attested completed-peg-outs root ---
    // Computed from the SELECTED set, so it is a function of the same skip rules
    // every SPO applies. A zero-peg-out TM re-commits the unchanged root.
    let cpo_root = cpo.root_after(&fulfilled).map_err(TmBuildError::CpoRoot)?;

    // --- The attested swept peg-ins root ---
    // The SPI trie advanced by every input except input 0 ([SPI-1]): the inputs
    // ARE the swept set, so the root is a function of the same input list every
    // SPO builds. A peg-in-free TM re-commits the unchanged root.
    let input_outpoints: Vec<[u8; 36]> = inputs
        .iter()
        .map(|i| outpoint_sort_key(&i.previous_output))
        .collect();
    let spi_root = spi
        .root_after_inputs(&input_outpoints)
        .map_err(TmBuildError::SpiRoot)?;

    // --- Estimate fee ---
    // [OH-3]: the commitment output's scriptPubKey is 71 bytes, 37 more than the
    // 34-byte budget `estimate_vsize` assumes per output.
    let vsize = estimate_vsize(num_inputs, num_outputs) + CPO_COMMITMENT_EXTRA_VBYTES;
    let miner_fee = Amount::from_sat(vsize * params.fee_rate_sat_per_vb);

    let required = total_pegout.checked_add(miner_fee).expect("no overflow");
    if total_input < required {
        return Err(TmBuildError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    // --- Build outputs: [0] = change, [1..m] = peg-outs ---
    let mut outputs = Vec::with_capacity(num_outputs);

    let change_value = total_input.checked_sub(required).expect("checked above");
    // output[0] is always the new treasury, so it must carry a spendable
    // balance. Reject any sub-dust value, including zero (which would mean the
    // inputs exactly covered fee+peg-outs and left nothing for the treasury) —
    // a zero/dust output[0] is non-standard and would be rejected on broadcast.
    if change_value < DUST_THRESHOLD {
        return Err(TmBuildError::DustOutput {
            index: 0,
            value: change_value,
        });
    }

    outputs.push(TxOut {
        value: change_value,
        script_pubkey: change_script_pubkey,
    });
    outputs.extend(pegout_outputs);
    // The commitment is LAST. Its position is free (the validator scans the whole
    // output list), but a fixed position keeps the layout a stated invariant that
    // co-signers and reconstruction can both rely on. Value 0: an OP_RETURN output
    // is provably unspendable, so a zero value is standard and burns nothing.
    outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: btmr1_commitment_script(&spi_root, &cpo_root),
    });

    // --- Assemble transaction ---
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    let txid = tx.compute_txid();

    // The skip report is a cross-SPO divergence signal (the epoch machine logs it
    // on that basis), so order it deterministically too — `retain` above collected
    // these in caller order, which is the chain query's listing order and not a
    // consensus input.
    skipped_pegouts.sort_by(|a, b| {
        a.script_pubkey
            .as_bytes()
            .cmp(b.script_pubkey.as_bytes())
            .then(a.amount.cmp(&b.amount))
            .then_with(|| skip_reason_sort_key(&a.reason).cmp(&skip_reason_sort_key(&b.reason)))
            .then(a.por_id.cmp(&b.por_id))
    });

    Ok(UnsignedTm {
        tx,
        txid,
        prevouts,
        input_spend_info,
        skipped_pegouts,
        fulfilled,
        cpo_root,
        spi_root,
    })
}

/// Re-derive the completed-peg-outs root a TM SHOULD commit and compare it with
/// the root the TM actually commits — the co-signer's pre-signing gate.
///
/// `fulfilled` is the peg-out set the verifier independently determined this TM
/// pays (for a self-built TM, [`UnsignedTm::fulfilled`]; for a peer proposal, the
/// set the verifier resolved from the proposal's payment outputs). `cpo` is the
/// verifier's OWN persisted trie. A mismatch means the proposer's trie disagrees
/// with the verifier's, and signing would attest a root the verifier cannot
/// justify — so the caller MUST refuse to sign.
///
/// This also catches a TM with zero or several BTMR1 outputs, which the
/// on-chain Confirm branch rejects outright. The commitment's OTHER root, the
/// swept peg-ins `spi_root` at script bytes `[7, 39)`, has its own gate:
/// `signing.rs::verify_spi_root` recomputes it and refuses on a mismatch.
pub fn verify_committed_root(
    tx: &Transaction,
    fulfilled: &[FulfilledPegOut],
    cpo: &dyn CpoTrieView,
) -> Result<[u8; 32], String> {
    let committed = committed_cpo_root(tx)?;
    let expected = cpo.root_after(fulfilled)?;
    if committed != expected {
        return Err(format!(
            "completed-peg-outs root mismatch: TM commits {}, local trie expects {} \
             after {} fulfilled peg-out(s)",
            hex::encode(committed),
            hex::encode(expected),
            fulfilled.len(),
        ));
    }
    Ok(committed)
}

// ---------------------------------------------------------------------------
// Sighash computation
// ---------------------------------------------------------------------------

/// Compute the BIP-341 key-path sighash for every input.
///
/// Returns one 32-byte sighash per input, suitable for FROST signing.
pub fn compute_sighashes(unsigned_tm: &UnsignedTm) -> Vec<[u8; 32]> {
    let prevouts = Prevouts::All(&unsigned_tm.prevouts);
    let mut cache = SighashCache::new(&unsigned_tm.tx);

    (0..unsigned_tm.tx.input.len())
        .map(|i| {
            let sighash = cache
                .taproot_key_spend_signature_hash(i, &prevouts, TapSighashType::Default)
                .expect("valid sighash");
            sighash.to_byte_array()
        })
        .collect()
}

/// Sign every input of a key-path-spend TM with a **single** secret key,
/// applying each input's BIP-341 taptweak (`input_spend_info[i].merkle_root()`).
///
/// In the demo the treasury and all peg-in deposits are key-pathed on the same
/// federation key (`Y_fed` = `Y_51`), so one `secret` signs every input; each
/// input is still tweaked with its own script-tree merkle root. Returns the
/// witnessed transaction. A `secret` that does not match an input's internal key
/// produces a signature that won't validate under that input's output key — the
/// caller should verify before broadcasting.
///
/// Returns [`TmBuildError::MalformedUnsignedTm`] if the input/prevout/spend-info
/// counts disagree (e.g. a hand-constructed `UnsignedTm`); a TM built by
/// [`build_tm`] always satisfies the invariant.
pub fn sign_tm_single_key(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    unsigned: &UnsignedTm,
    secret: &bitcoin::secp256k1::SecretKey,
) -> Result<Transaction, TmBuildError> {
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{Keypair, Message};

    let n = unsigned.tx.input.len();
    if unsigned.prevouts.len() != n || unsigned.input_spend_info.len() != n {
        return Err(TmBuildError::MalformedUnsignedTm {
            inputs: n,
            prevouts: unsigned.prevouts.len(),
            spend_infos: unsigned.input_spend_info.len(),
        });
    }

    let sighashes = compute_sighashes(unsigned);
    let keypair = Keypair::from_secret_key(secp, secret);
    let mut tx = unsigned.tx.clone();
    // Zip the three same-length slices so witness assembly carries no `[i]` indexing — the
    // MalformedUnsignedTm guard above already proves the lengths agree, but iterator-zip makes
    // the absence of any panic site syntactically obvious (and stays correct if a future caller
    // bypasses the guard).
    for ((txin, spend_info), sighash) in tx
        .input
        .iter_mut()
        .zip(unsigned.input_spend_info.iter())
        .zip(sighashes.iter())
    {
        let merkle_root = spend_info.merkle_root();
        let tweaked = keypair.tap_tweak(secp, merkle_root);
        let msg = Message::from_digest(*sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
        let tap_sig = bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        };
        txin.witness = Witness::p2tr_key_spend(&tap_sig);
    }
    Ok(tx)
}

/// Sign the treasury input (index 0) via the **federation CSV leaf** — the
/// emergency script-path fallback for when the FROST group is dark (scenario 3,
/// N23). Unlike the key-path signers this reveals the leaf + its control block
/// and signs the **raw** `y_fed` key (the leaf's `OP_CHECKSIG` checks `y_fed`
/// un-tweaked), and it sets the treasury input's `nSequence` to `csv_blocks` so
/// `OP_CSV`'s relative timelock is enabled and satisfied — the treasury UTxO must
/// already be `csv_blocks` deep on Bitcoin. Only input 0 is federation-spent.
///
/// `y_fed_secret` must correspond to the treasury tree's federation-leaf key (the
/// same key passed to [`crate::bitcoin::taproot::treasury_spend_info`]); a
/// mismatch (or wrong `csv_blocks`) means the leaf is not in the tree and yields
/// [`TmBuildError::FederationLeafSpend`]. Changing `nSequence` changes the txid,
/// so this is a standalone federation tx, not a FROST-coordinated one.
pub fn sign_tm_federation_leaf(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    unsigned: &UnsignedTm,
    y_fed_secret: &bitcoin::secp256k1::SecretKey,
    csv_blocks: u16,
) -> Result<Transaction, TmBuildError> {
    use bitcoin::secp256k1::{Keypair, Message};
    use bitcoin::taproot::{LeafVersion, TapLeafHash};

    let n = unsigned.tx.input.len();
    if unsigned.prevouts.len() != n || unsigned.input_spend_info.len() != n {
        return Err(TmBuildError::MalformedUnsignedTm {
            inputs: n,
            prevouts: unsigned.prevouts.len(),
            spend_infos: unsigned.input_spend_info.len(),
        });
    }

    let keypair = Keypair::from_secret_key(secp, y_fed_secret);
    let y_fed_xonly = keypair.x_only_public_key().0;
    // The exact leaf `treasury_spend_info` built: <csv> OP_CSV OP_DROP <y_fed> OP_CHECKSIG.
    let leaf = crate::bitcoin::taproot::build_csv_checksig_script(csv_blocks, y_fed_xonly);
    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let control_block = unsigned.input_spend_info[0]
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .ok_or_else(|| {
            TmBuildError::FederationLeafSpend(
                "control block for the federation leaf not found in the treasury tree — \
                 y_fed / csv_blocks do not match how the treasury was locked"
                    .into(),
            )
        })?;

    // nSequence commits into the sighash AND must satisfy OP_CSV, so set it
    // before hashing. `from_height` => relative-by-block-height, disable bit clear.
    let mut tx = unsigned.tx.clone();
    tx.input[0].sequence = Sequence::from_height(csv_blocks);

    let sighash = {
        let mut cache = SighashCache::new(&tx);
        cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&unsigned.prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| TmBuildError::FederationLeafSpend(format!("sighash: {e}")))?
    };

    let sig =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &keypair);
    let tap_sig = bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    };

    // Script-path witness: [Schnorr signature, revealed leaf script, control block].
    let mut witness = Witness::new();
    witness.push(tap_sig.to_vec());
    witness.push(leaf.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness;

    Ok(tx)
}

/// FROST analogue of [`sign_tm_single_key`]: sign every key-path TM input with a
/// set of FROST signing shares, applying each input's BIP-341 taptweak. Use this
/// when the inputs are keyed to the FROST group key `Y_51` (treasury key-path +
/// `Y_51`-internal peg-ins) rather than a single federation key — a single
/// `secret` cannot produce a valid `Y_51` signature.
///
/// All `key_packages` sign in this process (the demo cohort, reproduced via
/// [`crate::frost::dkg::run_demo_dkg`]); a real multi-SPO deployment drives the
/// identical per-input commit → tweaked-sign → aggregate rounds across the
/// network instead (`epoch::signing::sign_phase`). Returns the witnessed tx.
pub fn sign_tm_frost(
    unsigned: &UnsignedTm,
    key_packages: &std::collections::BTreeMap<
        frost_secp256k1_tr::Identifier,
        frost_secp256k1_tr::keys::KeyPackage,
    >,
    public_key_package: &frost_secp256k1_tr::keys::PublicKeyPackage,
) -> Result<Transaction, String> {
    use crate::frost::participant;
    use bitcoin::hashes::{HashEngine, sha256};
    use frost_secp256k1_tr as frost;
    use rand_core::SeedableRng;
    use std::collections::BTreeMap;

    let n = unsigned.tx.input.len();
    if unsigned.prevouts.len() != n || unsigned.input_spend_info.len() != n {
        return Err(format!(
            "malformed UnsignedTm: {n} inputs but {} prevouts / {} spend-infos",
            unsigned.prevouts.len(),
            unsigned.input_spend_info.len()
        ));
    }
    let sighashes = compute_sighashes(unsigned);
    let mut tx = unsigned.tx.clone();

    for (i, ((txin, spend_info), sighash)) in tx
        .input
        .iter_mut()
        .zip(unsigned.input_spend_info.iter())
        .zip(sighashes.iter())
        .enumerate()
    {
        // The BIP-341 key-path tweak = this input's script-tree merkle root.
        let merkle_root: Option<[u8; 32]> = spend_info.merkle_root().map(|h| h.to_byte_array());
        let mr: Option<&[u8]> = merkle_root.as_ref().map(|b| b.as_slice());

        // Round 1: per-signer nonce + commitment. Deterministic-but-unique nonce
        // per (input, signer) — safe because each signs exactly one message.
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (j, (id, kp)) in key_packages.iter().enumerate() {
            let mut eng = sha256::Hash::engine();
            eng.input(b"heimdall-sweep-nonce-v1");
            eng.input(&(i as u32).to_le_bytes());
            eng.input(&(j as u32).to_le_bytes());
            let mut rng =
                rand_chacha::ChaCha20Rng::from_seed(sha256::Hash::from_engine(eng).to_byte_array());
            let (sn, sc) = participant::sign_round1(kp, &mut rng);
            nonces.insert(*id, sn);
            commitments.insert(*id, sc);
        }

        let signing_package = frost::SigningPackage::new(commitments, sighash);

        // Round 2: tweaked signature share per signer, then aggregate.
        let mut shares = BTreeMap::new();
        for (id, kp) in key_packages.iter() {
            let share = participant::sign_round2_with_tweak(&signing_package, &nonces[id], kp, mr)
                .map_err(|e| format!("input {i} sign_round2: {e}"))?;
            shares.insert(*id, share);
        }
        let sig = participant::sign_aggregate_with_tweak(
            &signing_package,
            &shares,
            public_key_package,
            mr,
        )
        .map_err(|e| format!("input {i} aggregate: {e}"))?;

        let sig_bytes = sig
            .serialize()
            .map_err(|e| format!("input {i} sig serialize: {e}"))?;
        let schnorr = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("input {i} schnorr from_slice: {e}"))?;
        let tap_sig = bitcoin::taproot::Signature {
            signature: schnorr,
            sighash_type: TapSighashType::Default,
        };
        txin.witness = Witness::p2tr_key_spend(&tap_sig);
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::taproot::{pegin_spend_info, treasury_spend_info};
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    fn xonly_from_seed(seed: [u8; 32]) -> bitcoin::key::UntweakedPublicKey {
        use bitcoin::hashes::{Hash as _, sha256};
        let secp = Secp256k1::new();
        // Hash the seed to get a value guaranteed to be in the valid range
        let hash = sha256::Hash::hash(&seed);
        let sk = bitcoin::secp256k1::SecretKey::from_slice(hash.as_ref()).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        kp.x_only_public_key().0
    }

    fn make_treasury_spend_info() -> TaprootSpendInfo {
        let secp = Secp256k1::new();
        let y_51 = xonly_from_seed([1u8; 32]);
        let y_fed = xonly_from_seed([3u8; 32]);
        treasury_spend_info(&secp, y_51, y_fed, 144)
    }

    fn make_txid(b: u8) -> Txid {
        Txid::from_byte_array([b; 32])
    }

    fn make_treasury_input(txid_byte: u8, sats: u64) -> TreasuryInput {
        TreasuryInput {
            outpoint: OutPoint {
                txid: make_txid(txid_byte),
                vout: 0,
            },
            value: Amount::from_sat(sats),
            spend_info: make_treasury_spend_info(),
        }
    }

    fn make_pegin_input(txid_byte: u8, vout: u32, sats: u64) -> PegInInput {
        PegInInput {
            outpoint: OutPoint {
                txid: make_txid(txid_byte),
                vout,
            },
            value: Amount::from_sat(sats),
            spend_info: make_treasury_spend_info(),
        }
    }

    /// Chain "now" every test builds against, and the default 7-day freshness
    /// margin. `make_pegout` dates requests 1 day ago, comfortably inside the
    /// 30-day cancel window.
    const NOW_MS: i64 = 1_700_000_000_000;
    const MARGIN_MS: i64 = 7 * 24 * 3600 * 1000;
    const DAY_MS: i64 = 24 * 3600 * 1000;
    const TEST_FEE: u64 = 1_000;

    fn fresh() -> Freshness {
        Freshness {
            now_ms: NOW_MS,
            margin_ms: MARGIN_MS,
        }
    }

    /// An empty completed-peg-outs trie: nothing completed yet, genesis root.
    fn empty_cpo() -> crate::cardano::cpo_trie::CpoTrie {
        crate::cardano::cpo_trie::CpoTrie::empty()
    }

    /// An empty swept peg-ins trie: nothing swept yet, genesis root.
    fn empty_spi() -> crate::cardano::spi_trie::SpiTrie {
        crate::cardano::spi_trie::SpiTrie::empty()
    }

    /// `build_tm` with the default freshness window and empty tries — the
    /// shape almost every test wants.
    fn build_tm_t(
        treasury: TreasuryInput,
        pegins: Vec<PegInInput>,
        pegouts: Vec<PegOutRequest>,
        change_script_pubkey: ScriptBuf,
        params: &TmParams,
    ) -> Result<UnsignedTm, TmBuildError> {
        build_tm(
            treasury,
            pegins,
            pegouts,
            change_script_pubkey,
            params,
            &fresh(),
            &empty_cpo(),
            &empty_spi(),
        )
    }

    /// A payable peg-out with a valid P2TR-length destination (34 bytes:
    /// OP_1 <32-byte key>). Identity is derived from `(script_byte, sats)` so
    /// two calls with the same arguments describe the same request.
    fn make_pegout(script_byte: u8, sats: u64) -> PegOutRequest {
        make_pegout_full(script_byte, sats, TEST_FEE, NOW_MS - DAY_MS)
    }

    fn make_pegout_full(script_byte: u8, sats: u64, fee: u64, created: i64) -> PegOutRequest {
        use bitcoin::hashes::{Hash as _, sha256};
        let secp = Secp256k1::new();
        let key = xonly_from_seed([script_byte; 32]);
        let mut tag = Vec::new();
        tag.push(script_byte);
        tag.extend_from_slice(&sats.to_le_bytes());
        tag.extend_from_slice(&fee.to_le_bytes());
        let por_id = sha256::Hash::hash(&tag).to_byte_array();
        let mut outpoint = [0u8; 36];
        outpoint[..32].copy_from_slice(&por_id);
        PegOutRequest {
            script_pubkey: ScriptBuf::new_p2tr(&secp, key, None),
            amount: Amount::from_sat(sats),
            per_pegout_fee: Amount::from_sat(fee),
            por_id,
            outpoint,
            created,
        }
    }

    fn default_params() -> TmParams {
        TmParams::fee_rate_only(10)
    }

    fn change_address() -> ScriptBuf {
        let secp = Secp256k1::new();
        let key = xonly_from_seed([0xFFu8; 32]);
        ScriptBuf::new_p2tr(&secp, key, None)
    }

    /// Secret key matching `xonly_from_seed(seed)` (both hash the seed first).
    fn sk_from_seed(seed: [u8; 32]) -> bitcoin::secp256k1::SecretKey {
        use bitcoin::hashes::{Hash as _, sha256};
        bitcoin::secp256k1::SecretKey::from_slice(sha256::Hash::hash(&seed).as_ref()).unwrap()
    }

    // --- Single-key signer ---

    #[test]
    fn test_single_key_signer_verifies_under_output_key() {
        let secp = Secp256k1::new();
        // The test treasury/peg-in spend infos use internal key y_51 = xonly_from_seed([1;32]).
        let sk = sk_from_seed([1u8; 32]);
        assert_eq!(sk.x_only_public_key(&secp).0, xonly_from_seed([1u8; 32]));

        let params = default_params();
        let tm = build_tm_t(
            make_treasury_input(0xAA, 1_000_000),
            vec![make_pegin_input(0xBB, 0, 500_000)],
            vec![],
            change_address(),
            &params,
        )
        .unwrap();

        let signed = sign_tm_single_key(&secp, &tm, &sk).unwrap();
        let sighashes = compute_sighashes(&tm);

        assert_eq!(signed.input.len(), 2);
        for (i, txin) in signed.input.iter().enumerate() {
            let items = txin.witness.to_vec();
            assert_eq!(items.len(), 1, "input {i}: key-path witness is one element");
            assert_eq!(
                items[0].len(),
                64,
                "input {i}: Default-sighash sig is 64 bytes"
            );
            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&items[0]).unwrap();
            let msg = bitcoin::secp256k1::Message::from_digest(sighashes[i]);
            let outkey = tm.input_spend_info[i].output_key().to_x_only_public_key();
            secp.verify_schnorr(&sig, &msg, &outkey)
                .unwrap_or_else(|e| panic!("input {i} sig invalid under output key: {e}"));
        }
    }

    // --- FROST signer (Y_51-keyed inputs) ---

    #[test]
    fn test_frost_signer_verifies_under_output_key() {
        use crate::frost::dkg::run_demo_dkg;

        let secp = Secp256k1::new();
        // Reproduce the demo DKG; the TM inputs are keyed to the group key Y_51,
        // which a single federation key cannot sign for.
        let dkg = run_demo_dkg(b"heimdall-demo-seed-v1-0123456789", 2, 3);
        let vk = dkg.public_key_package.verifying_key().serialize().unwrap();
        let y_51 = bitcoin::key::UntweakedPublicKey::from_slice(&vk[1..33]).unwrap();
        // Sanity: this is the live deployment's Y_51.
        assert_eq!(
            hex::encode(&vk[1..33]),
            "b1e15a532a4e816ec75af608256b0808e36fb7d22560605178850885e53f2854"
        );

        let y_fed = xonly_from_seed([3u8; 32]);
        let depositor = xonly_from_seed([7u8; 32]);
        let treasury_si = treasury_spend_info(&secp, y_51, y_fed, 144);
        let pegin_si = pegin_spend_info(
            &secp,
            &crate::bitcoin::taproot::PeginTreeParams {
                y_51,
                y_federation: y_fed,
                federation_csv_blocks: 144,
                refund_timeout: 720,
            },
            depositor,
        );

        let tm = build_tm_t(
            TreasuryInput {
                outpoint: OutPoint {
                    txid: make_txid(0xAA),
                    vout: 0,
                },
                value: Amount::from_sat(1_000_000),
                spend_info: treasury_si,
            },
            vec![PegInInput {
                outpoint: OutPoint {
                    txid: make_txid(0xBB),
                    vout: 0,
                },
                value: Amount::from_sat(5_714),
                spend_info: pegin_si,
            }],
            vec![],
            change_address(),
            &default_params(),
        )
        .unwrap();

        let signed = sign_tm_frost(&tm, &dkg.key_packages, &dkg.public_key_package).unwrap();
        let sighashes = compute_sighashes(&tm);

        assert_eq!(signed.input.len(), 2);
        for (i, txin) in signed.input.iter().enumerate() {
            let items = txin.witness.to_vec();
            assert_eq!(items.len(), 1, "input {i}: key-path witness is one element");
            assert_eq!(
                items[0].len(),
                64,
                "input {i}: Default-sighash sig is 64 bytes"
            );
            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&items[0]).unwrap();
            let msg = bitcoin::secp256k1::Message::from_digest(sighashes[i]);
            let outkey = tm.input_spend_info[i].output_key().to_x_only_public_key();
            secp.verify_schnorr(&sig, &msg, &outkey)
                .unwrap_or_else(|e| panic!("input {i} FROST sig invalid under output key: {e}"));
        }
    }

    // --- Determinism ---

    #[test]
    fn test_build_tm_deterministic() {
        let params = default_params();
        let change = change_address();

        let build = || {
            build_tm_t(
                make_treasury_input(0xAA, 10_000_000),
                vec![make_pegin_input(0xBB, 0, 5_000_000)],
                vec![make_pegout(0x10, 100_000)],
                change.clone(),
                &params,
            )
            .unwrap()
        };

        let tm1 = build();
        let tm2 = build();
        assert_eq!(tm1.txid, tm2.txid);
    }

    // --- Input ordering ---

    #[test]
    fn test_input_ordering() {
        let params = default_params();
        let change = change_address();
        let treasury_txid_byte = 0xFF;

        // Peg-ins with txid bytes: 0xCC, 0xAA, 0xBB — should be sorted to AA, BB, CC
        let pegins = vec![
            make_pegin_input(0xCC, 0, 1_000_000),
            make_pegin_input(0xAA, 0, 1_000_000),
            make_pegin_input(0xBB, 0, 1_000_000),
        ];

        let tm = build_tm_t(
            make_treasury_input(treasury_txid_byte, 10_000_000),
            pegins,
            vec![make_pegout(0x10, 50_000)],
            change,
            &params,
        )
        .unwrap();

        // Input [0] is treasury
        assert_eq!(
            tm.tx.input[0].previous_output.txid,
            make_txid(treasury_txid_byte)
        );
        // Inputs [1..3] are sorted: AA < BB < CC
        assert_eq!(tm.tx.input[1].previous_output.txid, make_txid(0xAA));
        assert_eq!(tm.tx.input[2].previous_output.txid, make_txid(0xBB));
        assert_eq!(tm.tx.input[3].previous_output.txid, make_txid(0xCC));
    }

    // --- Output ordering ---

    #[test]
    fn test_output_ordering() {
        let params = default_params();
        let change = change_address();

        // Create pegouts with script_pubkeys that sort in a known order
        let po1 = make_pegout(0x30, 100_000);
        let po2 = make_pegout(0x10, 100_000);
        let po3 = make_pegout(0x20, 100_000);

        let expected_order = {
            let mut scripts = vec![
                po1.script_pubkey.clone(),
                po2.script_pubkey.clone(),
                po3.script_pubkey.clone(),
            ];
            scripts.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            scripts
        };

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![po1, po2, po3],
            change.clone(),
            &params,
        )
        .unwrap();

        // Output 0 is change
        assert_eq!(tm.tx.output[0].script_pubkey, change);
        // Outputs 1..3 are peg-outs sorted by scriptPubKey
        for (i, expected) in expected_order.iter().enumerate() {
            assert_eq!(
                &tm.tx.output[i + 1].script_pubkey,
                expected,
                "output {} wrong order",
                i + 1
            );
        }
    }

    // --- Accounting ---

    #[test]
    fn test_fee_deduction() {
        let params = default_params();
        let change = change_address();

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![make_pegin_input(0xBB, 0, 5_000_000)],
            vec![make_pegout(0x10, 100_000)],
            change,
            &params,
        )
        .unwrap();

        let total_in: u64 = tm.prevouts.iter().map(|p| p.value.to_sat()).sum();
        let total_out: u64 = tm.tx.output.iter().map(|o| o.value.to_sat()).sum();
        // The commitment output is budgeted as a normal output PLUS the 37 extra
        // bytes its 71-byte scriptPubKey costs over the 34-byte assumption.
        let vsize =
            estimate_vsize(tm.tx.input.len(), tm.tx.output.len()) + CPO_COMMITMENT_EXTRA_VBYTES;
        let expected_fee = vsize * params.fee_rate_sat_per_vb;

        assert_eq!(total_in - total_out, expected_fee);
    }

    #[test]
    fn test_pegout_protocol_fee() {
        let params = default_params();
        let change = change_address();
        let requested = 100_000u64;

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, requested)],
            change,
            &params,
        )
        .unwrap();

        // Output 0 is change; output 1 is the pegout
        assert_eq!(tm.tx.output[1].value.to_sat(), requested - TEST_FEE);
    }

    // Unfulfillable peg-outs (amount <= fee, or net below dust) are SKIPPED, not
    // fatal: the TM still builds and pays the fulfillable ones. One tiny/hostile
    // peg-out must not block the whole sweep.
    #[test]
    fn test_subdust_pegouts_are_skipped_not_fatal() {
        let params = default_params(); // per_pegout_fee = 1000, dust = 330
        let change = change_address();

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![
                make_pegout(0x10, 100_000), // payable
                make_pegout(0x11, 500),     // amount < fee -> skip
                make_pegout(0x12, 1_200),   // net 200 < dust -> skip
            ],
            change,
            &params,
        )
        .unwrap();

        // Only the payable peg-out is paid (output[0] is change, last is the
        // commitment).
        assert_eq!(tm.tx.output.len(), 3);
        assert_eq!(tm.tx.output[1].value.to_sat(), 100_000 - TEST_FEE);
        assert!(is_cpo_commitment(&tm.tx.output[2].script_pubkey));
        // The two unfulfillable ones are reported as skipped, with gross amounts.
        assert_eq!(tm.skipped_pegouts.len(), 2);
        let mut skipped: Vec<u64> = tm
            .skipped_pegouts
            .iter()
            .map(|s| s.amount.to_sat())
            .collect();
        skipped.sort_unstable();
        assert_eq!(skipped, vec![500, 1_200]);
    }

    // Non-standard / unspendable destination scriptPubKeys (empty, OP_RETURN,
    // junk) are skipped — they come from attacker-controllable datum and would
    // lose funds or make the TM non-relayable.
    #[test]
    fn test_nonstandard_destination_pegouts_are_skipped() {
        let params = default_params();
        let pegouts = vec![
            make_pegout(0x10, 100_000), // P2TR — payable
            PegOutRequest {
                script_pubkey: ScriptBuf::new(), // empty (anyone-can-spend)
                ..make_pegout(0x20, 100_000)
            },
            PegOutRequest {
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x02, 0xde, 0xad]), // OP_RETURN
                ..make_pegout(0x21, 100_000)
            },
        ];
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            pegouts,
            change_address(),
            &params,
        )
        .unwrap();

        assert_eq!(tm.tx.output.len(), 3); // change + the P2TR payment + commitment
        assert_eq!(tm.skipped_pegouts.len(), 2);
        assert!(
            tm.skipped_pegouts
                .iter()
                .all(|s| s.reason == SkipReason::NonStandardScript)
        );
    }

    // Determinism: two SPOs handed the same requests in OPPOSITE order build
    // byte-identical TMs. Peg-outs sharing a destination scriptPubKey are the case
    // a spk-only sort leaves to the caller's ordering.
    #[test]
    fn test_pegout_ordering_is_total_across_equal_destinations() {
        let params = default_params();
        // Same destination, different amounts — plus a second destination.
        let build = |pegouts| {
            build_tm_t(
                make_treasury_input(0xAA, 10_000_000),
                vec![],
                pegouts,
                change_address(),
                &params,
            )
            .unwrap()
        };
        let a = build(vec![
            make_pegout(0x10, 100_000),
            make_pegout(0x10, 200_000),
            make_pegout(0x11, 150_000),
        ]);
        let b = build(vec![
            make_pegout(0x11, 150_000),
            make_pegout(0x10, 200_000),
            make_pegout(0x10, 100_000),
        ]);

        assert_eq!(a.tx.output.len(), 5); // change + 3 payments + commitment
        assert_eq!(a.txid, b.txid, "TM bytes must not depend on input order");
        assert_eq!(a.cpo_root, b.cpo_root);
    }

    // A TM built entirely of unfulfillable peg-outs still succeeds (no payments,
    // all skipped) rather than aborting.
    #[test]
    fn test_all_pegouts_skipped_still_builds() {
        let params = default_params();
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x11, 500), make_pegout(0x12, 900)],
            change_address(),
            &params,
        )
        .unwrap();
        assert_eq!(tm.tx.output.len(), 2); // change + commitment only
        assert_eq!(tm.skipped_pegouts.len(), 2);
        assert!(tm.fulfilled.is_empty());
    }

    // --- BTMR1 two-root commitment ---

    // Byte-exact shape per rev 5.4: a 71-byte scriptPubKey whose first 7 bytes
    // are OP_RETURN OP_PUSHBYTES_69 "BTMR1", then spi_root, then cpo_root.
    #[test]
    fn commitment_script_is_71_bytes_with_btmr1_prefix() {
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![],
            change_address(),
            &default_params(),
        )
        .unwrap();
        let spk = tm.tx.output.last().unwrap().script_pubkey.clone();
        assert_eq!(
            spk.len(),
            71,
            "OP_RETURN(1) + OP_PUSHBYTES_69(1) + \"BTMR1\"(5) + spi_root(32) + cpo_root(32)"
        );
        assert_eq!(
            hex::encode(&spk.as_bytes()[..7]),
            "6a4542544d5231",
            "OP_RETURN OP_PUSHBYTES_69 \"BTMR1\""
        );
        assert_eq!(
            &spk.as_bytes()[7..39],
            &tm.spi_root,
            "spi_root sits at script bytes [7, 39)"
        );
        assert_eq!(
            &spk.as_bytes()[39..71],
            &tm.cpo_root,
            "cpo_root sits at script bytes [39, 71)"
        );
        assert!(is_cpo_commitment(&spk));
    }

    // Extraction offsets: spi_root is script bytes [7, 39), cpo_root is
    // script bytes [39, 71).
    #[test]
    fn roots_extracted_at_offsets_7_39_and_39_71() {
        let spi_root = [0x11u8; 32];
        let cpo_root = [0x22u8; 32];
        let mut v = Vec::with_capacity(71);
        v.push(0x6a); // OP_RETURN
        v.push(0x45); // OP_PUSHBYTES_69
        v.extend_from_slice(b"BTMR1");
        v.extend_from_slice(&spi_root);
        v.extend_from_slice(&cpo_root);
        let spk = ScriptBuf::from_bytes(v);
        assert!(
            is_cpo_commitment(&spk),
            "a 71-byte BTMR1 script is the root commitment"
        );

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: spk,
            }],
        };
        assert_eq!(
            committed_spi_root(&tx).expect("exactly one BTMR1 output"),
            spi_root,
            "spi_root is read from bytes [7, 39), not [39, 71)"
        );
        assert_eq!(
            committed_cpo_root(&tx).expect("exactly one BTMR1 output"),
            cpo_root,
            "cpo_root is read from bytes [39, 71), not [7, 39)"
        );
    }

    // [OH-3]: the 71-byte commitment scriptPubKey costs 37 vbytes over the
    // 34-byte per-output budget `estimate_vsize` assumes. A stale constant
    // underpays every TM's miner fee and sticks the transaction.
    #[test]
    fn extra_vbytes_constant_is_37() {
        assert_eq!(CPO_COMMITMENT_EXTRA_VBYTES, 37);
    }

    // Every TM commits, in the LAST output, at value 0 — including one that
    // fulfils no peg-out (it re-commits the unchanged root).
    #[test]
    fn every_tm_emits_exactly_one_commitment_last_at_value_zero() {
        for pegouts in [vec![], vec![make_pegout(0x10, 100_000)]] {
            let tm = build_tm_t(
                make_treasury_input(0xAA, 10_000_000),
                vec![],
                pegouts,
                change_address(),
                &default_params(),
            )
            .unwrap();
            let last = tm.tx.output.last().unwrap();
            assert!(is_cpo_commitment(&last.script_pubkey), "commitment is last");
            assert_eq!(last.value, Amount::ZERO);
            assert_eq!(
                tm.tx
                    .output
                    .iter()
                    .filter(|o| is_cpo_commitment(&o.script_pubkey))
                    .count(),
                1,
                "exactly one — the validator rejects zero and rejects two"
            );
            assert_eq!(committed_cpo_root(&tm.tx).unwrap(), tm.cpo_root);
        }
    }

    // A zero-peg-out TM commits the trie's CURRENT root, unchanged.
    #[test]
    fn a_zero_pegout_tm_commits_the_unchanged_root() {
        use crate::cardano::cpo_trie::{CpoEntry, CpoTrie};
        let mut trie = CpoTrie::empty();
        trie.insert_batch(&[CpoEntry::new([9u8; 32], &[0xaa; 22], 4242)])
            .unwrap();
        let before = trie.root();

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![],
            change_address(),
            &default_params(),
            &fresh(),
            &trie,
            &empty_spi(),
        )
        .unwrap();
        assert_eq!(tm.cpo_root, before);
        assert_eq!(committed_cpo_root(&tm.tx).unwrap(), before);
    }

    // The root is a function of the SELECTED set only: peg-outs the skip rules
    // dropped must not appear in it, and feeding the same set in a different order
    // must produce the same bytes.
    #[test]
    fn the_committed_root_covers_exactly_the_paid_set() {
        use crate::cardano::cpo_trie::{CpoEntry, CpoTrie};
        let paid = make_pegout(0x10, 100_000);
        let dust = make_pegout(0x11, 500); // below dust after the fee
        let expected_entry = CpoEntry::new(
            paid.por_id,
            paid.script_pubkey.as_bytes(),
            100_000 - TEST_FEE,
        );

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x11, 500), make_pegout(0x10, 100_000)],
            change_address(),
            &default_params(),
        )
        .unwrap();

        assert_eq!(tm.fulfilled.len(), 1);
        assert_eq!(tm.fulfilled[0].por_id, paid.por_id);
        assert_eq!(
            tm.cpo_root,
            CpoTrie::empty().root_after(&[expected_entry]).unwrap(),
            "the skipped peg-out must not be in the root"
        );
        let _ = dust;
    }

    // Determinism: two SPOs handed the same requests in opposite order commit the
    // same root AND build the same bytes.
    #[test]
    fn the_committed_root_does_not_depend_on_input_order() {
        let build = |pegouts| {
            build_tm_t(
                make_treasury_input(0xAA, 10_000_000),
                vec![],
                pegouts,
                change_address(),
                &default_params(),
            )
            .unwrap()
        };
        let a = build(vec![
            make_pegout(0x10, 100_000),
            make_pegout(0x11, 200_000),
            make_pegout(0x12, 300_000),
        ]);
        let b = build(vec![
            make_pegout(0x12, 300_000),
            make_pegout(0x10, 100_000),
            make_pegout(0x11, 200_000),
        ]);
        assert_eq!(a.cpo_root, b.cpo_root);
        assert_eq!(a.txid, b.txid);
        let ids_a: Vec<[u8; 32]> = a.fulfilled.iter().map(|f| f.por_id).collect();
        let ids_b: Vec<[u8; 32]> = b.fulfilled.iter().map(|f| f.por_id).collect();
        assert_eq!(ids_a, ids_b, "the hint order must be a function of the set");
    }

    // Two requests identical in destination and net amount produce byte-identical
    // TxOuts but DIFFERENT por_ids — so `fulfilled` (and hence the datum hint)
    // must still be ordered deterministically, by por_id.
    #[test]
    fn fulfilled_order_is_total_across_identical_payments() {
        let p1 = make_pegout_full(0x10, 100_000, TEST_FEE, NOW_MS - DAY_MS);
        let mut p2 = make_pegout_full(0x10, 100_000, TEST_FEE, NOW_MS - DAY_MS);
        // Same payment, different request identity.
        p2.por_id = [0xff; 32];
        p2.outpoint = [0xff; 36];
        assert_ne!(p1.por_id, p2.por_id);

        let build = |pegouts| {
            build_tm_t(
                make_treasury_input(0xAA, 10_000_000),
                vec![],
                pegouts,
                change_address(),
                &default_params(),
            )
            .unwrap()
        };
        let a = build(vec![
            make_pegout_full(0x10, 100_000, TEST_FEE, NOW_MS - DAY_MS),
            PegOutRequest {
                por_id: [0xff; 32],
                outpoint: [0xff; 36],
                ..make_pegout_full(0x10, 100_000, TEST_FEE, NOW_MS - DAY_MS)
            },
        ]);
        let b = build(vec![
            PegOutRequest {
                por_id: [0xff; 32],
                outpoint: [0xff; 36],
                ..make_pegout_full(0x10, 100_000, TEST_FEE, NOW_MS - DAY_MS)
            },
            make_pegout_full(0x10, 100_000, TEST_FEE, NOW_MS - DAY_MS),
        ]);
        let ids_a: Vec<[u8; 32]> = a.fulfilled.iter().map(|f| f.por_id).collect();
        let ids_b: Vec<[u8; 32]> = b.fulfilled.iter().map(|f| f.por_id).collect();
        assert_eq!(ids_a, ids_b);
        assert_eq!(a.cpo_root, b.cpo_root);
        let _ = (p1, p2);
    }

    // A peg-out cannot smuggle itself in as the commitment: the prefix begins with
    // OP_RETURN, which `is_standard_payable` rejects outright.
    #[test]
    fn a_pegout_cannot_masquerade_as_the_commitment() {
        let hostile = PegOutRequest {
            script_pubkey: btmr1_commitment_script(&[0xde; 32], &[0xde; 32]),
            ..make_pegout(0x10, 100_000)
        };
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![hostile],
            change_address(),
            &default_params(),
        )
        .unwrap();
        assert_eq!(tm.skipped_pegouts.len(), 1);
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::NonStandardScript);
        assert_eq!(committed_cpo_root(&tm.tx).unwrap(), tm.cpo_root);
    }

    #[test]
    fn committed_cpo_root_rejects_zero_and_multiple_commitments() {
        let mut tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![],
            change_address(),
            &default_params(),
        )
        .unwrap();
        // Two commitments — what the on-chain validator refuses to choose between.
        tm.tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: btmr1_commitment_script(&[0x11; 32], &[0x11; 32]),
        });
        assert!(committed_cpo_root(&tm.tx).is_err());
        // None at all.
        tm.tx
            .output
            .retain(|o| !is_cpo_commitment(&o.script_pubkey));
        assert!(committed_cpo_root(&tm.tx).is_err());
    }

    // --- per-request fee ---

    // The fee is per REQUEST now: two peg-outs in one TM with different datum fees
    // each pay their own gross − own fee.
    #[test]
    fn each_pegout_pays_its_own_datum_fee() {
        let a = make_pegout_full(0x10, 100_000, 1_000, NOW_MS - DAY_MS);
        let b = make_pegout_full(0x11, 100_000, 7_500, NOW_MS - DAY_MS);
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![a, b],
            change_address(),
            &default_params(),
        )
        .unwrap();
        let mut paid: Vec<u64> = tm.fulfilled.iter().map(|f| f.net_amount.to_sat()).collect();
        paid.sort_unstable();
        assert_eq!(paid, vec![92_500, 99_000]);
    }

    // The dust rule reads the request's own fee, not a shared one.
    #[test]
    fn dust_is_measured_against_the_requests_own_fee() {
        // Same gross; only the pinned fee differs.
        let payable = make_pegout_full(0x10, 1_500, 1_000, NOW_MS - DAY_MS); // net 500 >= 330
        let dusty = make_pegout_full(0x11, 1_500, 1_400, NOW_MS - DAY_MS); // net 100 < 330
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![payable, dusty],
            change_address(),
            &default_params(),
        )
        .unwrap();
        assert_eq!(tm.fulfilled.len(), 1);
        assert_eq!(tm.fulfilled[0].net_amount.to_sat(), 500);
        assert_eq!(tm.skipped_pegouts.len(), 1);
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::BelowDust);
    }

    // --- freshness filter ---

    // A request close to its 30-day Cancel deadline must be skipped: the owner
    // could take the BTC and then Cancel for the fBTC.
    #[test]
    fn a_pegout_near_its_cancel_deadline_is_skipped() {
        // Cancel fires at created + 30 days. Age it so only 6 days remain, inside
        // the 7-day margin.
        let created = NOW_MS - (PEG_OUT_CANCEL_TIMEOUT_MS - 6 * DAY_MS);
        let stale = make_pegout_full(0x10, 100_000, TEST_FEE, created);
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![stale],
            change_address(),
            &default_params(),
        )
        .unwrap();
        assert!(tm.fulfilled.is_empty());
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::NearCancelDeadline);
    }

    // Exactly at the margin is still payable; one millisecond past it is not.
    #[test]
    fn the_freshness_margin_boundary_is_inclusive() {
        let at_margin = NOW_MS - (PEG_OUT_CANCEL_TIMEOUT_MS - MARGIN_MS);
        let build = |created| {
            build_tm_t(
                make_treasury_input(0xAA, 10_000_000),
                vec![],
                vec![make_pegout_full(0x10, 100_000, TEST_FEE, created)],
                change_address(),
                &default_params(),
            )
            .unwrap()
        };
        assert_eq!(build(at_margin).fulfilled.len(), 1, "exactly at the margin");
        assert!(
            build(at_margin - 1).fulfilled.is_empty(),
            "one ms past the margin"
        );
    }

    // A `created` in the future cannot be evaluated against the deadline. It is
    // also attacker-controllable (the requester writes it), so skip rather than
    // guess.
    #[test]
    fn a_pegout_created_in_the_future_is_skipped() {
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout_full(0x10, 100_000, TEST_FEE, NOW_MS + 1)],
            change_address(),
            &default_params(),
        )
        .unwrap();
        assert!(tm.fulfilled.is_empty());
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::NotYetCreated);
    }

    // `created` at i64::MAX must not wrap the deadline arithmetic into "fresh".
    #[test]
    fn an_absurd_created_does_not_overflow_the_deadline() {
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout_full(0x10, 100_000, TEST_FEE, i64::MAX)],
            change_address(),
            &default_params(),
        )
        .unwrap();
        assert!(tm.fulfilled.is_empty());
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::NotYetCreated);
    }

    // --- already-completed skip ---

    // The trie is the durable record of what has been paid and proven. A request
    // already in it must never be paid again — its BTC would be unrecoverable.
    #[test]
    fn a_pegout_already_in_the_trie_is_skipped() {
        use crate::cardano::cpo_trie::{CpoEntry, CpoTrie};
        let done = make_pegout(0x10, 100_000);
        let open = make_pegout(0x11, 200_000);
        let mut trie = CpoTrie::empty();
        trie.insert_batch(&[CpoEntry::new(
            done.por_id,
            done.script_pubkey.as_bytes(),
            100_000 - TEST_FEE,
        )])
        .unwrap();

        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, 100_000), make_pegout(0x11, 200_000)],
            change_address(),
            &default_params(),
            &fresh(),
            &trie,
            &empty_spi(),
        )
        .unwrap();

        assert_eq!(tm.fulfilled.len(), 1);
        assert_eq!(tm.fulfilled[0].por_id, open.por_id);
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::AlreadyCompleted);
        let _ = done;
    }

    // The same request listed twice would be PAID twice while the trie recorded
    // one entry (inserting an identical key/value is idempotent), so the committed
    // root would not account for the second payment. Unreachable through today's
    // UTxO scan, pinned because the cost of being wrong is treasury BTC.
    #[test]
    fn a_duplicated_request_is_paid_once() {
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, 100_000), make_pegout(0x10, 100_000)],
            change_address(),
            &default_params(),
        )
        .unwrap();

        assert_eq!(tm.fulfilled.len(), 1, "one payment for one request");
        assert_eq!(tm.tx.output.len(), 3, "change + one payment + commitment");
        assert_eq!(tm.skipped_pegouts.len(), 1);
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::DuplicateRequest);
        // The root must still be exactly the root of the one entry that was paid.
        assert_eq!(
            tm.cpo_root,
            empty_cpo()
                .root_after(&[(&tm.fulfilled[0]).into()])
                .unwrap()
        );
    }

    // Config #14: a request locking less fBTC than the protocol minimum is skipped,
    // not paid. Nothing checks this when the request is created — the peg-out
    // address is permissionless — so the TM builder is where the bound bites.
    #[test]
    fn a_pegout_below_min_peg_out_fbtc_is_skipped() {
        let params = TmParams {
            min_peg_out_fbtc: Amount::from_sat(100_000),
            ..default_params()
        };
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            // 99_999 is one satoshi short; 100_000 is exactly at the floor and passes
            // (the bound is inclusive, matching `>=` in the spec's minimum).
            vec![make_pegout(0x10, 99_999), make_pegout(0x11, 100_000)],
            change_address(),
            &params,
        )
        .unwrap();

        assert_eq!(tm.fulfilled.len(), 1);
        assert_eq!(tm.skipped_pegouts.len(), 1);
        assert_eq!(tm.skipped_pegouts[0].amount, Amount::from_sat(99_999));
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::BelowMinPegOut);
    }

    // Config #13: the floor is on the request's OWN datum-pinned fee, which is what
    // `peg-out.ak` binds completion to — so an under-paying request must not be
    // settled at all rather than settled at the floor.
    #[test]
    fn a_pegout_under_the_fee_floor_is_skipped() {
        let params = TmParams {
            per_pegout_fee_floor: Amount::from_sat(TEST_FEE),
            ..default_params()
        };
        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![
                make_pegout_full(0x10, 100_000, TEST_FEE - 1, NOW_MS - DAY_MS),
                make_pegout_full(0x11, 100_000, TEST_FEE, NOW_MS - DAY_MS),
            ],
            change_address(),
            &params,
            &fresh(),
            &empty_cpo(),
            &empty_spi(),
        )
        .unwrap();

        assert_eq!(
            tm.fulfilled.len(),
            1,
            "only the request at the floor is paid"
        );
        assert_eq!(tm.skipped_pegouts.len(), 1);
        assert_eq!(tm.skipped_pegouts[0].reason, SkipReason::FeeBelowFloor);
    }

    // Zero floors (a Config that predates the operational-parameter append, and every
    // single-signer dev path) leave the two rules inert — the pre-WI-040 behaviour.
    #[test]
    fn zero_floors_skip_nothing() {
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout_full(0x10, 1_000, 0, NOW_MS - DAY_MS)],
            change_address(),
            &TmParams::fee_rate_only(10),
        )
        .unwrap();

        assert_eq!(tm.fulfilled.len(), 1);
        assert!(tm.skipped_pegouts.is_empty());
    }

    // Two DISTINCT requests that happen to pay the same destination and amount are
    // not duplicates — the dedupe keys on por_id, not on the payment.
    #[test]
    fn identical_payments_from_distinct_requests_are_both_paid() {
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![
                make_pegout(0x10, 100_000),
                PegOutRequest {
                    por_id: [0xff; 32],
                    outpoint: [0xff; 36],
                    ..make_pegout(0x10, 100_000)
                },
            ],
            change_address(),
            &default_params(),
        )
        .unwrap();
        assert_eq!(tm.fulfilled.len(), 2);
        assert!(tm.skipped_pegouts.is_empty());
    }

    // --- verify_committed_root (the co-signer gate) ---

    #[test]
    fn verify_committed_root_accepts_a_tm_built_from_the_same_trie() {
        use crate::cardano::cpo_trie::CpoTrie;
        let trie = CpoTrie::empty();
        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, 100_000)],
            change_address(),
            &default_params(),
            &fresh(),
            &trie,
            &empty_spi(),
        )
        .unwrap();
        let root = verify_committed_root(&tm.tx, &tm.fulfilled, &trie).unwrap();
        assert_eq!(root, tm.cpo_root);
    }

    // A leader whose trie is AHEAD of ours proposes a root we cannot derive — we
    // must refuse rather than attest it.
    #[test]
    fn verify_committed_root_refuses_a_root_from_a_divergent_trie() {
        use crate::cardano::cpo_trie::{CpoEntry, CpoTrie};
        let mut leader_trie = CpoTrie::empty();
        leader_trie
            .insert_batch(&[CpoEntry::new([0x99; 32], &[0x77; 22], 1234)])
            .unwrap();
        let tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, 100_000)],
            change_address(),
            &default_params(),
            &fresh(),
            &leader_trie,
            &empty_spi(),
        )
        .unwrap();
        let err = verify_committed_root(&tm.tx, &tm.fulfilled, &CpoTrie::empty()).unwrap_err();
        assert!(err.contains("root mismatch"), "{err}");
    }

    // A TM that pays a peg-out but leaves it out of the committed root is the
    // dangerous case: the BTC moves and the completion can never be proven.
    #[test]
    fn verify_committed_root_refuses_a_root_that_omits_a_paid_pegout() {
        use crate::cardano::cpo_trie::CpoTrie;
        let trie = CpoTrie::empty();
        let mut tm = build_tm(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, 100_000)],
            change_address(),
            &default_params(),
            &fresh(),
            &trie,
            &empty_spi(),
        )
        .unwrap();
        // Rewrite the commitment to the pre-payment (empty) root.
        let last = tm.tx.output.len() - 1;
        tm.tx.output[last].script_pubkey = btmr1_commitment_script(&tm.spi_root, &trie.root());
        assert!(verify_committed_root(&tm.tx, &tm.fulfilled, &trie).is_err());
    }

    #[test]
    fn verify_committed_root_refuses_a_tm_with_no_commitment() {
        use crate::cardano::cpo_trie::CpoTrie;
        let trie = CpoTrie::empty();
        let mut tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![],
            change_address(),
            &default_params(),
        )
        .unwrap();
        tm.tx
            .output
            .retain(|o| !is_cpo_commitment(&o.script_pubkey));
        assert!(verify_committed_root(&tm.tx, &[], &trie).is_err());
    }

    #[test]
    fn test_insufficient_funds_error() {
        let params = default_params();
        let change = change_address();

        let result = build_tm_t(
            make_treasury_input(0xAA, 1_000), // very little
            vec![],
            vec![make_pegout(0x10, 100_000)],
            change,
            &params,
        );

        assert!(matches!(
            result,
            Err(TmBuildError::InsufficientFunds { .. })
        ));
    }

    // --- Edge cases ---

    #[test]
    fn test_no_pegins() {
        let params = default_params();
        let change = change_address();

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![make_pegout(0x10, 100_000)],
            change,
            &params,
        )
        .unwrap();

        assert_eq!(tm.tx.input.len(), 1); // just treasury
        assert_eq!(tm.tx.output.len(), 3); // change + pegout + commitment
    }

    #[test]
    fn test_no_pegouts() {
        let params = TmParams::fee_rate_only(10);
        let change = change_address();

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![make_pegin_input(0xBB, 0, 5_000_000)],
            vec![],
            change,
            &params,
        )
        .unwrap();

        assert_eq!(tm.tx.input.len(), 2); // treasury + pegin
        assert_eq!(tm.tx.output.len(), 2); // change + commitment
    }

    #[test]
    fn test_no_pegins_no_pegouts() {
        let params = TmParams::fee_rate_only(10);
        let change = change_address();

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![],
            change,
            &params,
        )
        .unwrap();

        assert_eq!(tm.tx.input.len(), 1); // just treasury
        assert_eq!(tm.tx.output.len(), 2); // change + commitment
    }

    // --- Sighash ---

    #[test]
    fn test_sighash_count_matches_inputs() {
        let params = default_params();
        let change = change_address();

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![make_pegin_input(0xBB, 0, 5_000_000)],
            vec![make_pegout(0x10, 100_000)],
            change,
            &params,
        )
        .unwrap();

        let sighashes = compute_sighashes(&tm);
        assert_eq!(sighashes.len(), tm.tx.input.len());
    }

    #[test]
    fn test_sighash_differs_per_input() {
        let params = default_params();
        let change = change_address();

        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![
                make_pegin_input(0xBB, 0, 2_000_000),
                make_pegin_input(0xCC, 0, 2_000_000),
            ],
            vec![make_pegout(0x10, 100_000)],
            change,
            &params,
        )
        .unwrap();

        let sighashes = compute_sighashes(&tm);
        // All sighashes should be distinct
        for i in 0..sighashes.len() {
            for j in (i + 1)..sighashes.len() {
                assert_ne!(sighashes[i], sighashes[j], "sighash[{i}] == sighash[{j}]");
            }
        }
    }

    #[test]
    fn test_sighash_deterministic() {
        let params = default_params();
        let change = change_address();

        let build = || {
            build_tm_t(
                make_treasury_input(0xAA, 10_000_000),
                vec![make_pegin_input(0xBB, 0, 5_000_000)],
                vec![make_pegout(0x10, 100_000)],
                change.clone(),
                &params,
            )
            .unwrap()
        };

        let sh1 = compute_sighashes(&build());
        let sh2 = compute_sighashes(&build());
        assert_eq!(sh1, sh2);
    }

    // --- FROST integration (unit-level) ---

    #[test]
    fn test_frost_sign_sighash() {
        use crate::frost::dkg::run_dkg_all_completions;
        use crate::frost::signing::run_signing;

        // Small DKG: 3-of-5
        let min_signers = 3u16;
        let max_signers = 5u16;
        println!("  DKG: {min_signers}-of-{max_signers}");
        let dkg_result = run_dkg_all_completions(min_signers, max_signers);

        // Extract the FROST group x-only public key
        let frost_group_key = dkg_result.public_key_package.verifying_key();
        let group_key_bytes = frost_group_key
            .serialize()
            .expect("serialize verifying key");
        // frost-secp256k1-tr serializes as 33-byte compressed point (02/03 || x).
        // Extract the 32-byte x-coordinate for the x-only public key.
        let y_51 = bitcoin::key::UntweakedPublicKey::from_slice(&group_key_bytes[1..33])
            .expect("valid x-only pubkey");

        let secp = Secp256k1::new();
        let y_fed = xonly_from_seed([3u8; 32]);

        let spend_info = treasury_spend_info(&secp, y_51, y_fed, 144);
        let treasury_script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

        // Build a simple TM: one treasury input, one pegout, change back
        let params = default_params();
        let tm = build_tm_t(
            TreasuryInput {
                outpoint: OutPoint {
                    txid: make_txid(0xAA),
                    vout: 0,
                },
                value: Amount::from_sat(10_000_000),
                spend_info,
            },
            vec![],
            vec![make_pegout(0x10, 100_000)],
            treasury_script_pubkey.clone(),
            &params,
        )
        .unwrap();

        // Compute sighash for the treasury input (index 0)
        let sighashes = compute_sighashes(&tm);
        let sighash = &sighashes[0];

        // FROST-sign the sighash
        println!("  FROST signing sighash...");
        let signing_result = run_signing(
            &dkg_result.key_packages,
            &dkg_result.public_key_package,
            sighash,
            min_signers,
        );

        // Convert FROST signature (64 bytes: R || z) to bitcoin::taproot::Signature
        let frost_sig_bytes = signing_result
            .signature
            .serialize()
            .expect("serialize signature");
        assert_eq!(frost_sig_bytes.len(), 64);

        let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&frost_sig_bytes)
            .expect("valid 64-byte schnorr sig");

        let tap_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::Default,
        };

        // Set the witness on a mutable copy
        let mut signed_tx = tm.tx.clone();
        signed_tx.input[0].witness = Witness::p2tr_key_spend(&tap_sig);

        // Verify: the signature should be valid under the *tweaked* output key.
        // The FROST group key is the internal key; the output key includes the
        // taproot tweak. For key-path spends, the signer must apply the tweak
        // to the secret key before signing. Since frost-secp256k1-tr doesn't
        // do Taproot tweaking internally, we verify here that the raw FROST
        // signature validates against the *untweaked* group key (which is what
        // frost::Signature::verify checks). The actual on-chain verification
        // would need the tweak applied during signing — that integration is
        // deferred to the full signing coordinator.
        //
        // For now, verify the FROST signature directly:
        dkg_result
            .public_key_package
            .verifying_key()
            .verify(sighash, &signing_result.signature)
            .expect("FROST signature should verify against group key");

        println!("  FROST signature verified against group public key");
        println!("  txid: {}", tm.txid);
        println!(
            "  signed tx has {} inputs, {} outputs",
            signed_tx.input.len(),
            signed_tx.output.len()
        );
    }

    // --- Federation CSV-leaf (script-path) signer (N23) ---

    /// The federation fallback: sign the treasury via its CSV leaf and prove the
    /// signature validates against `y_fed` under the tapscript sighash, the
    /// witness is the 3-item script-path shape, and `nSequence` enables OP_CSV.
    #[test]
    fn test_federation_leaf_spend_signs_and_verifies() {
        use crate::bitcoin::taproot::build_csv_checksig_script;
        use bitcoin::secp256k1::{Message, Secp256k1};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};

        let secp = Secp256k1::new();
        // treasury locked under (Y_51 = seed[1], y_fed = seed[3], csv = 144)
        let tm = build_tm_t(
            make_treasury_input(0xAA, 10_000_000),
            vec![],
            vec![],
            change_address(),
            &default_params(),
        )
        .unwrap();

        let y_fed_sk = sk_from_seed([3u8; 32]);
        let signed = sign_tm_federation_leaf(&secp, &tm, &y_fed_sk, 144).unwrap();

        // 3-item script-path witness + a relative-timelock nSequence (not the
        // OP_CSV-disabling TM_SEQUENCE).
        assert_eq!(signed.input[0].witness.len(), 3);
        assert_eq!(signed.input[0].sequence, Sequence::from_height(144));
        assert_ne!(signed.input[0].sequence, TM_SEQUENCE);

        // The revealed leaf is exactly the treasury federation leaf.
        let y_fed = xonly_from_seed([3u8; 32]);
        let leaf = build_csv_checksig_script(144, y_fed);
        assert_eq!(signed.input[0].witness.nth(1).unwrap(), leaf.as_bytes());

        // The Schnorr signature validates against y_fed under the tapscript sighash.
        let sig_bytes = signed.input[0].witness.nth(0).unwrap();
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes).unwrap();
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sighash = {
            let mut cache = SighashCache::new(&signed);
            cache
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&tm.prevouts),
                    leaf_hash,
                    TapSighashType::Default,
                )
                .unwrap()
        };
        secp.verify_schnorr(&sig, &Message::from_digest(sighash.to_byte_array()), &y_fed)
            .expect("federation leaf signature must verify against y_fed");

        // A key/csv that is not the tree's leaf has no control block → error.
        assert!(matches!(
            sign_tm_federation_leaf(&secp, &tm, &sk_from_seed([9u8; 32]), 144),
            Err(TmBuildError::FederationLeafSpend(_))
        ));
    }
}
