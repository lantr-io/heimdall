//! Carrying a registration across a registry revision, with no cold key.
//!
//! spec [MIG-1] to [MIG-6], §SPO Registration section 8. A registry revision —
//! the rev-5.6 nonce among them — is a new script hash and so a new
//! membership-token policy. The registrations under the old policy are still
//! the roster's consent and the Treasury state's `bifrost_identity_root` still
//! commits to every one of them, so nothing about them needs re-authorizing.
//! `Migrate` says exactly that: reference the old node, prove its
//! `bifrost_id_pk -> pool_id` against the identity trie, mint the same
//! `pool_id` under the new policy with the old datum verbatim.
//!
//! No cold signature and no Bifrost signature, so ANYONE may submit it. That is
//! what lets an operator cross a revision by installing a package — `run-spo`
//! migrates its own pool at its first roster read — and lets the federation
//! carry the stragglers with `migrate-registration --all`, so the next boundary
//! snapshot of the new list equals the old roster whatever operators do.
//!
//! What this costs: the new node's min ADA, paid by whoever submits, and the
//! old node's min ADA, which stays in the frozen old list. Recovering the
//! latter would need the old cold signature, and once Config #9 has moved the
//! old `Deregister` cannot satisfy [TSY-13] anyway.

use std::collections::BTreeSet;

use pallas_codec::minicbor;
use pallas_primitives::PlutusData;
use pallas_primitives::conway::Tx;
use pallas_wallet::PrivateKey;
use whisky::*;
use whisky_pallas::WhiskyPallas;

use crate::cardano::bf_http::BfUtxo;
use crate::cardano::blueprint::ParameterizedScript;
use crate::cardano::mpf;
use crate::cardano::plutus::{constr, int};
use crate::cardano::publish::WalletUtxo;
use crate::cardano::register_spo::{
    IdentityPair, RegisterSpoError, find_registry_utxos, registration_list_action_redeemer,
    registry_list_from_utxos,
};
use crate::cardano::registry::{RegistrationNodeData, RegistryError, RegistryList};
use crate::cardano::treasury_info::proof_to_plutus_data;
use crate::cardano::treasury_spend::find_treasury_state;
use crate::cardano::tx_common::{
    element_lovelace, network_from_address, select_collateral, select_fee, sign_built_tx,
    wallet_input_amount, whisky_network,
};
use crate::cardano::wallet::pub_key_hash_hex;

/// Where a pool's registration sits relative to a registry revision.
///
/// Derived entirely from the chain — two list reads and a Config field — and
/// nothing is persisted for it. That is deliberate: a node that upgrades a week
/// late finds itself `Current` because somebody else migrated it meanwhile, and
/// a node that remembered "I am migrating" would have to be told otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipState {
    /// Present in the list Config #9 names. Nothing to do.
    Current,
    /// Absent from #9, Config #13 is set, and present in THAT list.
    Migratable { pool_id: Vec<u8> },
    /// In neither list. Today's behaviour: run `register-spo`.
    ///
    /// Reached when Config #13 is unset as well as when it is set and the pool
    /// is in neither list. The two must NOT be conflated with `Migratable`:
    /// telling an operator who never registered to wait for a migration is as
    /// wrong as telling a migrating one to register again with a cold key.
    NotRegistered,
    /// Absent from the current list and present in the previous one, like
    /// `Migratable` — but the binding is gone from the identity trie, so this
    /// pool MIGRATED AND THEN LEFT.
    ///
    /// Worth telling apart rather than reporting as `Migratable`: otherwise a
    /// pool that deliberately exited is told at every restart that it is on its
    /// way across, and `run-spo` logs a warning and a failed build each time,
    /// until somebody clears Config #13.
    AlreadyLeft,
}

/// How far the window search reaches from either end: up to this many pools
/// that migrated and then left, OR up to this many still waiting to cross.
///
/// Both ends, because the two regimes a window passes through are both common.
/// Just after the governance Update almost everyone is still to cross and few
/// have left; after the federation's `--all` pass nobody is left to cross and
/// any number may have left since. A search from one end only would fail the
/// second regime as soon as a third pool exited — and a failed search fails
/// every roster read on the bridge.
///
/// Bounded because the search is over subsets. What it cannot reach is the
/// middle — more than this many departures AND more than this many still to
/// cross — and [`IdentityWindow::one_more_departure_fits`] is what keeps an exit
/// from taking the window there.
pub const SEARCH_DEPTH: usize = 2;

/// The Treasury state's identity root, accounted for by the two registry lists.
///
/// `Migrate` does not move the root, so during a window it commits to the
/// union of the two lists — minus the pools that migrated and then exited,
/// whose binding the exit deleted while their frozen old node stayed behind.
/// This is that set, computed once and used by everything that proves against
/// the root: the roster read and all three builders. Building from the raw
/// union instead, as they once did, made a single mid-window exit stop every
/// registration, exit and migration on the bridge until Config #13 was cleared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityWindow {
    /// The bindings the root commits to — what every proof is built against.
    pub pairs: Vec<IdentityPair>,
    /// Identity keys only the previous list carries whose binding the root
    /// still holds: pools not yet carried across.
    pub unmigrated: BTreeSet<Vec<u8>>,
    /// Identity keys only the previous list carries whose binding the root no
    /// longer holds: pools that migrated and then left.
    pub departed: BTreeSet<Vec<u8>>,
}

impl IdentityWindow {
    /// The identity trie these bindings form.
    pub fn trie(&self) -> Result<mpf::Trie, mpf::MpfError> {
        mpf::Trie::from_pairs(self.pairs.clone())
    }

    /// Whether the window can absorb one more departure and still be explained.
    ///
    /// An exit by a pool whose identity the previous list also carries turns it
    /// into a departure. Past [`SEARCH_DEPTH`] departures the search can only
    /// explain the root from the other end, which needs few pools left to
    /// cross — and if both are many, no node can rebuild the root and every
    /// roster read fails. That is the one exit worth refusing, and running
    /// `migrate-registration --all` first (anyone may) always makes it fit.
    #[must_use]
    pub fn one_more_departure_fits(&self) -> bool {
        self.departed.len() < SEARCH_DEPTH || self.unmigrated.len() <= SEARCH_DEPTH
    }
}

/// Explain `root` by the current list's bindings and, during a migration
/// window, the previous list's.
///
/// `None` means no reachable set of departures does — the lists are not the
/// ones the Treasury state vouches for, and the caller must treat that as it
/// treats any root mismatch. Outside a window (`previous` is `None`) the check
/// is the strict one it always was: the current list alone.
///
/// The security this preserves: only identity keys the previous list carries
/// and the current one does not are ever dropped, so a fabricated element
/// added to the CURRENT list is in every candidate and no candidate matches.
///
/// What it cannot see, inside a window: which pools have crossed. `Migrate`
/// leaves the root alone by design ([MIG-3]), so a current list that omits a
/// migrated pool, or carries an unmigrated pool's exact binding, rebuilds the
/// same root as the true one. That is a property of the contract, not of this
/// search, and it ends when the window does.
#[must_use]
pub fn explain_identity_root(
    current: &[IdentityPair],
    previous: Option<&[IdentityPair]>,
    root: mpf::Hash,
) -> Option<IdentityWindow> {
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut union: Vec<IdentityPair> = Vec::new();
    for (pk, pool_id) in current {
        if seen.insert(pk.clone()) {
            union.push((pk.clone(), pool_id.clone()));
        }
    }
    let mut previous_only: Vec<Vec<u8>> = Vec::new();
    for (pk, pool_id) in previous.unwrap_or_default() {
        if seen.insert(pk.clone()) {
            union.push((pk.clone(), pool_id.clone()));
            previous_only.push(pk.clone());
        }
    }
    let n = previous_only.len();
    // Smallest first from each end: no departures (the start of a window), all
    // departed (the end of one), then one and two from each side.
    let mut candidates: Vec<BTreeSet<usize>> = vec![BTreeSet::new(), (0..n).collect()];
    for i in 0..n {
        candidates.push([i].into_iter().collect());
        candidates.push((0..n).filter(|&k| k != i).collect());
    }
    const _: () = assert!(SEARCH_DEPTH == 2, "the loops enumerate sizes 0, 1 and 2");
    for i in 0..n {
        for j in i + 1..n {
            candidates.push([i, j].into_iter().collect());
            candidates.push((0..n).filter(|&k| k != i && k != j).collect());
        }
    }
    let mut tried: BTreeSet<BTreeSet<usize>> = BTreeSet::new();
    for dropped in candidates {
        if !tried.insert(dropped.clone()) {
            continue;
        }
        let departed: BTreeSet<Vec<u8>> =
            dropped.iter().map(|&k| previous_only[k].clone()).collect();
        let pairs: Vec<IdentityPair> = union
            .iter()
            .filter(|(pk, _)| !departed.contains(pk))
            .cloned()
            .collect();
        let Ok(trie) = mpf::Trie::from_pairs(pairs.clone()) else {
            continue;
        };
        if trie.root_hash() == root {
            let unmigrated = previous_only
                .iter()
                .filter(|pk| !departed.contains(*pk))
                .cloned()
                .collect();
            return Some(IdentityWindow {
                pairs,
                unmigrated,
                departed,
            });
        }
    }
    None
}

/// Classify one Bifrost identity key against the two lists.
///
/// `previous` is `None` when Config #13 is unset — no migration is in progress,
/// so absence from the current list means exactly what it has always meant.
#[must_use]
pub fn classify(
    bifrost_id_pk: &[u8],
    current: &RegistryList,
    previous: Option<&RegistryList>,
) -> MembershipState {
    classify_against_root(bifrost_id_pk, current, previous, None)
}

/// [`classify`], given the window the Treasury state's identity root explains —
/// which is what tells a pool waiting to migrate apart from one that migrated
/// and then left.
///
/// The lists alone cannot: `Migrate` leaves the old node behind, and an exit
/// under the new registry removes only the new one, so both shapes read as
/// "absent from current, present in previous". The root can, because an exit
/// deletes the binding from it.
///
/// Without the window, `Migratable` is the safe guess — a migration that should
/// not happen is refused by the builder, where a missed one leaves a pool out
/// of the roster.
#[must_use]
pub fn classify_against_root(
    bifrost_id_pk: &[u8],
    current: &RegistryList,
    previous: Option<&RegistryList>,
    window: Option<&IdentityWindow>,
) -> MembershipState {
    let find = |list: &RegistryList| -> Option<Vec<u8>> {
        list.iter()
            .find(|(_, data)| data.bifrost_id_pk == bifrost_id_pk)
            .map(|(pool_id, _)| pool_id.to_vec())
    };
    if find(current).is_some() {
        return MembershipState::Current;
    }
    let Some(pool_id) = previous.and_then(find) else {
        return MembershipState::NotRegistered;
    };
    if window.is_some_and(|w| w.departed.contains(bifrost_id_pk)) {
        return MembershipState::AlreadyLeft;
    }
    MembershipState::Migratable { pool_id }
}

/// Parse both lists and the Treasury state's root, and explain the root —
/// the one read every builder starts from.
///
/// Errors name which of the reads failed; a root no reachable window explains
/// is an error here, because a proof built against it is one the validator
/// rejects after the fee.
pub fn read_identity_window(
    current: &RegistryList,
    previous: Option<(&str, &[BfUtxo])>,
    root: mpf::Hash,
) -> Result<(Option<RegistryList>, IdentityWindow), RegisterSpoError> {
    let previous = previous
        .map(|(policy_hex, utxos)| registry_list_from_utxos(utxos, policy_hex))
        .transpose()?;
    let previous_pairs = previous.as_ref().map(RegistryList::identity_pairs);
    let window = explain_identity_root(&current.identity_pairs(), previous_pairs.as_deref(), root)
        .ok_or_else(|| {
            RegisterSpoError::Build(format!(
                "the registry {} not rebuild the Treasury state's identity root ({} in the datum), \
             so a proof built here would be rejected on chain. {}",
                if previous.is_some() {
                    "lists do"
                } else {
                    "list does"
                },
                hex::encode(root),
                if previous.is_some() {
                    "During a migration window that means more pools have both left and still to \
                 cross than any node can account for, or a provider returned a torn read — \
                 retry, and if it persists run `heimdall migrate-registration --all`"
                } else {
                    "The provider's answer is torn or stale — retry"
                },
            ))
        })?;
    Ok((previous, window))
}

/// `SposRegistryMintRedeemer::Migrate` — constructor 3, field order pinned by
/// `bifrost/types/spos-registry.ak`:
/// `{old_node_ref_input_index, config_ref_input_index, treasury_ref_input_index,
/// registration_anchor_input_index, registration_anchor_output_index,
/// bifrost_identity_membership_proof}`.
#[must_use]
pub fn migrate_mint_redeemer(
    old_node_ref_input_index: i64,
    config_ref_input_index: i64,
    treasury_ref_input_index: i64,
    anchor_input_index: i64,
    anchor_output_index: i64,
    membership_proof: &mpf::Proof,
) -> PlutusData {
    constr(
        3,
        vec![
            int(old_node_ref_input_index),
            int(config_ref_input_index),
            int(treasury_ref_input_index),
            int(anchor_input_index),
            int(anchor_output_index),
            proof_to_plutus_data(membership_proof),
        ],
    )
}

/// Everything [`build_migrate_registration_tx`] needs. UTxO sets are
/// caller-fetched so the builder stays pure and testable.
pub struct MigrateRegistrationRequest<'a> {
    /// The CURRENT registry (the policy Config #9 names).
    pub registry_script: &'a ParameterizedScript,
    /// The policy Config #13 names — the list the old node sits in.
    pub previous_registry_policy_hex: &'a str,
    pub treasury_policy_hex: &'a str,
    pub treasury_asset_name_hex: &'a str,
    /// The pool to carry across.
    pub pool_id: &'a [u8],
    /// UTxOs at the CURRENT registry address.
    pub registry_utxos: &'a [BfUtxo],
    /// UTxOs at the PREVIOUS registry address.
    pub previous_registry_utxos: &'a [BfUtxo],
    /// UTxOs at the treasury address (referenced, not spent — [MIG-6]).
    pub treasury_utxos: &'a [BfUtxo],
    pub wallet_address: &'a str,
    pub wallet_utxos: &'a [WalletUtxo],
    pub key: &'a PrivateKey,
    /// `(tx_hash, index)` of the Config UTxO — [MIG-1] reads #13 from it.
    pub config_ref: (String, u32),
    /// `(tx_hash, index)` of the registry reference-script UTxO. As for
    /// register_spo, the ~12 KB script is needed by both the anchor spend and
    /// the mint, so it must be referenced on a real network.
    pub registry_ref: Option<(String, u32)>,
    pub cost_models: Option<Vec<Vec<i64>>>,
}

/// A built (signed, unsubmitted) `migrate_spo` tx.
#[derive(Debug, Clone)]
pub struct MigrateRegistrationTx {
    pub signed_tx_hex: String,
    pub pool_id: Vec<u8>,
    /// The old node's data, carried across verbatim ([MIG-2]).
    pub node_data: RegistrationNodeData,
    /// The spent anchor element's NFT name.
    pub anchor_asset_name: Vec<u8>,
}

fn tx_id_bytes(tx_hash: &str) -> Result<[u8; 32], RegisterSpoError> {
    hex::decode(tx_hash)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| RegisterSpoError::Build(format!("bad tx hash: {tx_hash}")))
}

/// Build + sign the `migrate_spo` tx.
pub fn build_migrate_registration_tx(
    req: &MigrateRegistrationRequest,
) -> Result<MigrateRegistrationTx, RegisterSpoError> {
    let registry_policy_hex = req.registry_script.hash_hex();

    // ── the old node: the registration being carried across ──
    let prev_elements = find_registry_utxos(
        req.previous_registry_utxos,
        req.previous_registry_policy_hex,
    )?;
    // Parsed for its integrity check alone: a previous list that does not form
    // a well-linked chain is not one a registration can be read out of. The
    // bindings come back through `read_identity_window` below, which is the one
    // copy of the rule every builder shares.
    let _prev_list = RegistryList::from_elements(
        prev_elements
            .iter()
            .map(|u| (u.asset_name.clone(), u.element.clone())),
    )?;
    let old_node = prev_elements
        .iter()
        .find(|u| u.asset_name == req.pool_id)
        .ok_or_else(|| {
            RegisterSpoError::Build(format!(
                "no registration node for pool {} under the previous registry policy {}. \
                 Config #13 names that policy as the one a migration comes from; a pool that is \
                 in neither list has never registered",
                hex::encode(req.pool_id),
                req.previous_registry_policy_hex,
            ))
        })?;
    let node_data = match &old_node.element.data {
        crate::cardano::registry::ElementData::Node(data) => data.clone(),
        crate::cardano::registry::ElementData::Root => {
            return Err(RegisterSpoError::Build(
                "the previous registry's element for this pool is the list root, not a node".into(),
            ));
        }
    };

    // ── the insertion into the current list ──
    let elements = find_registry_utxos(req.registry_utxos, &registry_policy_hex)?;
    let list = RegistryList::from_elements(
        elements
            .iter()
            .map(|u| (u.asset_name.clone(), u.element.clone())),
    )?;
    let plan = list
        .plan_insert(req.pool_id, node_data.clone())
        .map_err(|e| match e {
            // The commonest way to reach this command twice: somebody else
            // already migrated this pool, which is a success, not a fault.
            RegistryError::AlreadyRegistered => RegisterSpoError::Build(format!(
                "pool {} is already in the current registry — it has been migrated already, \
                 by this node or by anyone else",
                hex::encode(req.pool_id)
            )),
            other => RegisterSpoError::Registry(other),
        })?;
    let anchor = elements
        .iter()
        .find(|u| u.asset_name == plan.anchor_asset_name)
        .expect("plan_insert anchors on an element from this snapshot");

    // ── [MIG-3]: the membership proof, against the trie the Treasury state's
    // root commits to — during a window, both lists minus the pools that have
    // already left, found by the one rule every builder and the roster read
    // share (`explain_identity_root`).
    //
    // Not the previous list alone: the new registry is live the moment Config
    // #9 moves, and a pool that was never in the old list can register under
    // it, which DOES move the root. And not the raw union: a pool that migrated
    // and then left is gone from the root but not from the frozen old list.
    let state = find_treasury_state(
        req.treasury_utxos,
        req.treasury_policy_hex,
        req.treasury_asset_name_hex,
    )?;
    let (_, window) = read_identity_window(
        &list,
        Some((
            req.previous_registry_policy_hex,
            req.previous_registry_utxos,
        )),
        state.datum.bifrost_identity_root,
    )?;
    if window.departed.contains(&node_data.bifrost_id_pk) {
        return Err(RegisterSpoError::Build(format!(
            "pool {} migrated and then left: its binding is gone from the Treasury state, so \
             there is nothing to carry across. Its node in the previous list is inert. To join \
             again, register",
            hex::encode(req.pool_id)
        )));
    }
    let identity_trie = window
        .trie()
        .map_err(crate::cardano::treasury_info::TreasuryInfoError::Mpf)?;
    let membership_proof = identity_trie
        .prove_membership(&node_data.bifrost_id_pk)
        .map_err(crate::cardano::treasury_info::TreasuryInfoError::Mpf)?;

    let network = network_from_address(req.wallet_address);
    let registry_address = req.registry_script.enterprise_address(network);

    // ── reference inputs, in the order the built tx will carry them ──
    //
    // Three of ours plus whatever whisky adds for the reference script, and the
    // post-build fixup sorts and dedupes the set — so every redeemer index here
    // is computed against that same sort, never assumed.
    let mut reference_inputs = vec![
        RefTxIn {
            tx_hash: old_node.tx_hash.clone(),
            tx_index: old_node.output_index,
            script_size: None,
        },
        RefTxIn {
            tx_hash: state.tx_hash.clone(),
            tx_index: state.output_index,
            script_size: None,
        },
        RefTxIn {
            tx_hash: req.config_ref.0.clone(),
            tx_index: req.config_ref.1,
            script_size: None,
        },
    ];
    if let Some((ref_tx, ref_ix)) = &req.registry_ref {
        reference_inputs.push(RefTxIn {
            tx_hash: ref_tx.clone(),
            tx_index: *ref_ix,
            script_size: None,
        });
    }
    let ref_index_of = |tx_hash: &str, index: u32| -> i64 {
        i64::try_from(crate::cardano::tx_common::reference_input_index(
            &reference_inputs,
            tx_hash,
            index,
        ))
        .unwrap_or(0)
    };
    let old_node_ref_index = ref_index_of(&old_node.tx_hash, old_node.output_index);
    let treasury_ref_index = ref_index_of(&state.tx_hash, state.output_index);
    let config_ref_index = ref_index_of(&req.config_ref.0, req.config_ref.1);

    // ── the new node output ──
    let new_node_datum_cbor = plan.new_node.to_cbor();
    let node_lovelace = element_lovelace(new_node_datum_cbor.len());
    let fee_utxo = select_fee(req.wallet_utxos, node_lovelace + 1_000_000)
        .map_err(RegisterSpoError::Wallet)?;
    let coll_utxo =
        select_collateral(req.wallet_utxos, &[fee_utxo]).map_err(RegisterSpoError::Wallet)?;

    let fee_ref = (tx_id_bytes(&fee_utxo.tx_hash)?, fee_utxo.output_index);
    let anchor_ref = (tx_id_bytes(&anchor.tx_hash)?, anchor.output_index);
    if fee_ref == anchor_ref {
        return Err(RegisterSpoError::Build(
            "fee and anchor inputs must be distinct outpoints".into(),
        ));
    }
    let mut sorted = [fee_ref, anchor_ref];
    sorted.sort();
    let anchor_input_index = sorted.iter().position(|r| *r == anchor_ref).unwrap() as i64;
    // Outputs are ours to order: [0] continued anchor, [1] new node (whisky
    // appends the change after).
    let anchor_output_index = 0i64;

    let registry_source = match &req.registry_ref {
        Some((tx_hash, index)) => ScriptSource::InlineScriptSource(InlineScriptSource {
            ref_tx_in: RefTxIn {
                tx_hash: tx_hash.clone(),
                tx_index: *index,
                script_size: Some(req.registry_script.cbor.len()),
            },
            script_hash: registry_policy_hex.clone(),
            language_version: LanguageVersion::V3,
            script_size: req.registry_script.cbor.len(),
        }),
        None => ScriptSource::ProvidedScriptSource(ProvidedScriptSource {
            script_cbor: req.registry_script.cbor_hex(),
            language_version: LanguageVersion::V3,
        }),
    };

    let anchor_unit = format!(
        "{registry_policy_hex}{}",
        hex::encode(&plan.anchor_asset_name)
    );
    let anchor_value = vec![
        Asset::new_from_str("lovelace", &anchor.lovelace.to_string()),
        Asset::new_from_str(&anchor_unit, "1"),
    ];
    let anchor_redeemer_hex = hex::encode(
        minicbor::to_vec(registration_list_action_redeemer()).expect("redeemer CBOR encode"),
    );
    let anchor_in = TxIn::ScriptTxIn(ScriptTxIn {
        tx_in: TxInParameter {
            tx_hash: anchor.tx_hash.clone(),
            tx_index: anchor.output_index,
            amount: Some(anchor_value.clone()),
            address: Some(registry_address.clone()),
        },
        script_tx_in: ScriptTxInParameter {
            script_source: Some(registry_source.clone()),
            datum_source: Some(DatumSource::InlineDatumSource(InlineDatumSource {
                tx_hash: anchor.tx_hash.clone(),
                tx_index: anchor.output_index,
            })),
            redeemer: Some(Redeemer {
                data: anchor_redeemer_hex,
                ex_units: Budget {
                    mem: 1_000_000,
                    steps: 500_000_000,
                },
            }),
        },
    });

    let continued_anchor_out = Output {
        address: registry_address.clone(),
        amount: anchor_value,
        datum: Some(Datum::Inline(hex::encode(plan.continued_anchor.to_cbor()))),
        reference_script: None,
    };
    let new_node_unit = format!(
        "{registry_policy_hex}{}",
        hex::encode(&plan.new_node_asset_name)
    );
    let new_node_out = Output {
        address: registry_address,
        amount: vec![
            Asset::new_from_str("lovelace", &node_lovelace.to_string()),
            Asset::new_from_str(&new_node_unit, "1"),
        ],
        datum: Some(Datum::Inline(hex::encode(new_node_datum_cbor))),
        reference_script: None,
    };

    let mint_redeemer = migrate_mint_redeemer(
        old_node_ref_index,
        config_ref_index,
        treasury_ref_index,
        anchor_input_index,
        anchor_output_index,
        &membership_proof,
    );
    let mint_redeemer_hex =
        hex::encode(minicbor::to_vec(&mint_redeemer).expect("redeemer CBOR encode"));

    let body = TxBuilderBody {
        inputs: vec![
            TxIn::PubKeyTxIn(PubKeyTxIn {
                tx_in: TxInParameter {
                    tx_hash: fee_utxo.tx_hash.clone(),
                    tx_index: fee_utxo.output_index,
                    amount: Some(wallet_input_amount(fee_utxo)),
                    address: Some(req.wallet_address.to_string()),
                },
            }),
            anchor_in,
        ],
        outputs: vec![continued_anchor_out, new_node_out],
        collaterals: vec![PubKeyTxIn {
            tx_in: TxInParameter {
                tx_hash: coll_utxo.tx_hash.clone(),
                tx_index: coll_utxo.output_index,
                amount: Some(wallet_input_amount(coll_utxo)),
                address: Some(req.wallet_address.to_string()),
            },
        }],
        required_signatures: vec![pub_key_hash_hex(req.key)],
        change_address: req.wallet_address.to_string(),
        signing_key: vec![],
        network: Some(whisky_network(&req.cost_models)),
        reference_inputs: reference_inputs.clone(),
        withdrawals: vec![],
        mints: vec![MintItem::ScriptMint(ScriptMint {
            mint: MintParameter {
                policy_id: registry_policy_hex.clone(),
                asset_name: hex::encode(req.pool_id),
                amount: 1,
            },
            redeemer: Some(Redeemer {
                data: mint_redeemer_hex,
                // Lighter than Register: the linked-list checks and one MPF
                // membership walk, with no Ed25519 and no Schnorr verification.
                ex_units: Budget {
                    mem: 5_000_000,
                    steps: 2_500_000_000,
                },
            }),
            script_source: Some(registry_source.clone()),
        })],
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
        .map_err(|e| RegisterSpoError::Build(format!("whisky tx build: {e:?}")))?;

    // Post-build: dedupe the reference inputs whisky pushed per script use, then
    // check every redeemer index against the transaction that was actually
    // built — the same discipline register_spo applies to its input indices, and
    // needed more here, since this branch locates THREE reference inputs.
    let unsigned_hex = {
        let tx_bytes = hex::decode(&unsigned_hex)
            .map_err(|e| RegisterSpoError::Build(format!("unsigned tx hex decode: {e}")))?;
        let mut tx: Tx = minicbor::decode(&tx_bytes)
            .map_err(|e| RegisterSpoError::Build(format!("tx minicbor decode: {e}")))?;

        if let Some(ref_ins) = tx.transaction_body.reference_inputs.take() {
            let mut v = ref_ins.to_vec();
            v.sort_by_key(|i| (i.transaction_id, i.index));
            v.dedup();
            tx.transaction_body.reference_inputs = pallas_codec::utils::NonEmptySet::from_vec(v);
        }

        {
            let inputs: Vec<_> = tx.transaction_body.inputs.iter().collect();
            let at_input =
                |i: i64, want: &([u8; 32], u32), what: &str| -> Result<(), RegisterSpoError> {
                    let got = inputs.get(i as usize).ok_or_else(|| {
                        RegisterSpoError::Build(format!("{what} input index {i} out of range"))
                    })?;
                    if got.transaction_id.as_slice() != want.0 || got.index != u64::from(want.1) {
                        return Err(RegisterSpoError::Build(format!(
                            "{what} input not at redeemer index {i} — input ordering changed"
                        )));
                    }
                    Ok(())
                };
            at_input(anchor_input_index, &anchor_ref, "anchor")?;

            let at_ref =
                |i: i64, tx_hash: &str, index: u32, what: &str| -> Result<(), RegisterSpoError> {
                    crate::cardano::tx_common::check_reference_at(
                        &tx,
                        u64::try_from(i).unwrap_or(u64::MAX),
                        tx_hash,
                        index,
                        what,
                    )
                    .map_err(RegisterSpoError::Build)
                };
            at_ref(
                old_node_ref_index,
                &old_node.tx_hash,
                old_node.output_index,
                "old node",
            )?;
            at_ref(
                treasury_ref_index,
                &state.tx_hash,
                state.output_index,
                "treasury state",
            )?;
            at_ref(
                config_ref_index,
                &req.config_ref.0,
                req.config_ref.1,
                "Config",
            )?;
        }

        hex::encode(
            minicbor::to_vec(&tx)
                .map_err(|e| RegisterSpoError::Build(format!("tx minicbor re-encode: {e}")))?,
        )
    };

    let signed_tx_hex = sign_built_tx(&unsigned_hex, req.key).map_err(RegisterSpoError::Build)?;

    Ok(MigrateRegistrationTx {
        signed_tx_hex,
        pool_id: req.pool_id.to_vec(),
        node_data,
        anchor_asset_name: plan.anchor_asset_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cardano::registry::{ElementData, RegistryElement};
    use pallas_primitives::PlutusData as PD;

    const ROOT_KEY: &[u8] = crate::cardano::registry::REGISTRATION_ROOT_KEY;

    fn node(pk: &[u8], url: &[u8]) -> RegistryElement {
        RegistryElement {
            data: ElementData::Node(RegistrationNodeData {
                bifrost_id_pk: pk.to_vec(),
                bifrost_url: url.to_vec(),
            }),
            link: None,
        }
    }

    /// A list holding exactly the given `(pool_id, pk)` pairs, in key order.
    fn list(entries: &[(&[u8], &[u8])]) -> RegistryList {
        let mut sorted: Vec<_> = entries.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        let mut elements: Vec<(Vec<u8>, RegistryElement)> = Vec::new();
        elements.push((
            ROOT_KEY.to_vec(),
            RegistryElement {
                data: ElementData::Root,
                link: sorted.first().map(|(p, _)| p.to_vec()),
            },
        ));
        for (i, (pool_id, pk)) in sorted.iter().enumerate() {
            let mut e = node(pk, b"https://spo.example");
            e.link = sorted.get(i + 1).map(|(p, _)| p.to_vec());
            elements.push((pool_id.to_vec(), e));
        }
        RegistryList::from_elements(elements).expect("a well-formed fixture list")
    }

    const POOL_A: &[u8] = &[0xa1; 28];
    const POOL_B: &[u8] = &[0xb2; 28];
    const PK_A: &[u8] = &[0x0a; 32];
    const PK_B: &[u8] = &[0x0b; 32];
    const PK_STRANGER: &[u8] = &[0x0c; 32];

    /// Present in the list Config #9 names: nothing to do, whoever put it there.
    /// That last part matters — a node that upgrades a week late finds itself
    /// `Current` because somebody else's `--all` pass carried it across, and it
    /// must read that as "registered", not as "my migration failed".
    #[test]
    fn a_pool_in_the_current_list_is_current() {
        let current = list(&[(POOL_A, PK_A)]);
        let previous = list(&[(POOL_A, PK_A)]);
        assert_eq!(
            classify(PK_A, &current, Some(&previous)),
            MembershipState::Current
        );
    }

    /// Absent from the current list, present in the previous one: the whole
    /// point of the branch.
    #[test]
    fn a_pool_only_in_the_previous_list_is_migratable() {
        let current = list(&[(POOL_B, PK_B)]);
        let previous = list(&[(POOL_A, PK_A), (POOL_B, PK_B)]);
        assert_eq!(
            classify(PK_A, &current, Some(&previous)),
            MembershipState::Migratable {
                pool_id: POOL_A.to_vec()
            }
        );
    }

    /// In neither list: today's behaviour, unchanged. Telling an operator who
    /// never registered to wait for a migration is as wrong as telling a
    /// migrating one to make a cold-key trip.
    #[test]
    fn a_pool_in_neither_list_is_not_registered() {
        let current = list(&[(POOL_A, PK_A)]);
        let previous = list(&[(POOL_A, PK_A)]);
        assert_eq!(
            classify(PK_STRANGER, &current, Some(&previous)),
            MembershipState::NotRegistered
        );
    }

    /// Config #13 unset — no migration in progress. Absence then means exactly
    /// what it has always meant, and MUST NOT be guessed into a migration.
    #[test]
    fn with_no_migration_in_progress_absence_is_not_registered() {
        let current = list(&[(POOL_B, PK_B)]);
        assert_eq!(
            classify(PK_A, &current, None),
            MembershipState::NotRegistered
        );
    }

    /// The shape the lists alone cannot distinguish: a pool that migrated and
    /// then LEFT looks exactly like one waiting to migrate — absent from the
    /// current list, present in the previous one — because `Migrate` leaves the
    /// old node behind and the exit removes only the new one.
    ///
    /// The identity root tells them apart, because an exit deletes the binding
    /// from it. Without that test an operator who deliberately left is told at
    /// every restart that they are on their way across.
    #[test]
    fn a_pool_that_migrated_and_then_left_is_not_migratable() {
        let current = list(&[(POOL_B, PK_B)]);
        let previous = list(&[(POOL_A, PK_A), (POOL_B, PK_B)]);
        let both: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (PK_A.to_vec(), POOL_A.to_vec()),
            (PK_B.to_vec(), POOL_B.to_vec()),
        ];
        let explain = |root| {
            explain_identity_root(
                &current.identity_pairs(),
                Some(&previous.identity_pairs()),
                root,
            )
            .expect("the root is explained")
        };

        // A has NOT left: the treasury root still holds both bindings.
        let root_with_both = mpf::Trie::from_pairs(both.clone()).unwrap().root_hash();
        assert_eq!(
            classify_against_root(
                PK_A,
                &current,
                Some(&previous),
                Some(&explain(root_with_both))
            ),
            MembershipState::Migratable {
                pool_id: POOL_A.to_vec()
            }
        );

        // A HAS left: the treasury root is the union MINUS A.
        let root_without_a = mpf::Trie::from_pairs(current.identity_pairs())
            .unwrap()
            .root_hash();
        assert_eq!(
            classify_against_root(
                PK_A,
                &current,
                Some(&previous),
                Some(&explain(root_without_a))
            ),
            MembershipState::AlreadyLeft
        );

        // With no window the answer is the safe guess, unchanged: a migration
        // that should not happen is refused by the builder, where a missed one
        // leaves a pool out of the roster.
        assert_eq!(
            classify(PK_A, &current, Some(&previous)),
            MembershipState::Migratable {
                pool_id: POOL_A.to_vec()
            }
        );
    }

    fn pairs_for(ids: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        ids.iter().map(|&i| (vec![i; 32], vec![i; 28])).collect()
    }

    fn root_of(pairs: &[(Vec<u8>, Vec<u8>)]) -> mpf::Hash {
        mpf::Trie::from_pairs(pairs.to_vec()).unwrap().root_hash()
    }

    /// Late in a window everyone has crossed and any number may have left
    /// since. A search that only dropped up to two departures would fail there
    /// on the third exit — and a failed search fails every roster read. The
    /// other end of the search is what covers it.
    #[test]
    fn any_number_of_departures_is_explained_once_nobody_is_left_to_cross() {
        let current = pairs_for(&[1, 2]);
        let mut previous = current.clone();
        previous.extend(pairs_for(&[10, 11, 12, 13, 14]));
        let w = explain_identity_root(&current, Some(&previous), root_of(&current))
            .expect("five departures, nobody to cross");
        assert_eq!(w.departed.len(), 5);
        assert!(w.unmigrated.is_empty());
        assert!(w.one_more_departure_fits(), "and more exits are fine");
    }

    /// Early in a window almost everyone is still to cross.
    #[test]
    fn a_few_departures_are_explained_while_many_are_still_to_cross() {
        let current = pairs_for(&[1]);
        let mut previous = current.clone();
        previous.extend(pairs_for(&[10, 11, 20, 21, 22, 23]));
        let mut root_pairs = current.clone();
        root_pairs.extend(pairs_for(&[20, 21, 22, 23]));
        let w = explain_identity_root(&current, Some(&previous), root_of(&root_pairs))
            .expect("two departures, four to cross");
        assert_eq!(
            w.departed,
            [vec![10u8; 32], vec![11u8; 32]].into_iter().collect()
        );
        assert_eq!(w.unmigrated.len(), 4);
        assert!(
            !w.one_more_departure_fits(),
            "a third departure with four still to cross is past both ends"
        );
    }

    /// A fabricated element in the CURRENT list is in every candidate, so no
    /// set of departures explains it away.
    #[test]
    fn a_fabricated_current_element_is_never_explained() {
        let honest = pairs_for(&[1, 2]);
        let previous = pairs_for(&[1, 2, 3]);
        let mut forged = honest.clone();
        forged.push((vec![0x66; 32], vec![0x66; 28]));
        let mut root_pairs = honest.clone();
        root_pairs.extend(pairs_for(&[3]));
        assert!(explain_identity_root(&forged, Some(&previous), root_of(&root_pairs)).is_none());
        assert!(explain_identity_root(&honest, Some(&previous), root_of(&root_pairs)).is_some());
    }

    /// Outside a window the check is the strict one: the current list alone.
    #[test]
    fn outside_a_window_only_the_current_list_explains_the_root() {
        let current = pairs_for(&[1, 2]);
        assert!(explain_identity_root(&current, None, root_of(&current)).is_some());
        assert!(explain_identity_root(&current, None, root_of(&pairs_for(&[1]))).is_none());
    }

    /// Constructor 3 with the six fields the Aiken type pins, in order. There is
    /// no schema between this and `bifrost/types/spos-registry.ak`, so the order
    /// is the contract.
    #[test]
    fn redeemer_shape_and_canonical_encoding() {
        let proof: mpf::Proof = vec![];
        let r = migrate_mint_redeemer(0, 2, 1, 1, 0, &proof);
        let cbor = pallas_codec::minicbor::to_vec(&r).unwrap();
        let hex_str = hex::encode(&cbor);
        // Constr 3 → tag 124 (0xd87c), indefinite-length fields.
        assert!(hex_str.starts_with("d87c9f"), "{hex_str}");
        assert!(hex_str.ends_with("ff"), "{hex_str}");

        let back: PD = pallas_codec::minicbor::decode(&cbor).unwrap();
        let PD::Constr(c) = back else {
            panic!("expected Constr");
        };
        assert_eq!(c.tag, 124, "Migrate is constructor 3");
        let fields: Vec<_> = c.fields.iter().collect();
        assert_eq!(fields.len(), 6);
        for (i, f) in fields.iter().take(5).enumerate() {
            assert!(
                matches!(f, PD::BigInt(_)),
                "field {i} must be an index integer"
            );
        }
        assert!(
            matches!(fields[5], PD::Array(_)),
            "the membership proof is a list of steps"
        );
    }

    /// The redeemer carries NO signature of any kind. That absence is the
    /// feature — it is what lets anyone submit a migration for anyone, and what
    /// lets an operator cross a registry revision by installing a package.
    #[test]
    fn the_redeemer_carries_no_signature() {
        let proof: mpf::Proof = vec![];
        let r = migrate_mint_redeemer(0, 2, 1, 1, 0, &proof);
        let PD::Constr(c) = r else { panic!() };
        assert!(
            !c.fields.iter().any(|f| matches!(f, PD::BoundedBytes(_))),
            "Migrate must carry no key or signature bytes"
        );
    }
}
