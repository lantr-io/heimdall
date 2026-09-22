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
    RegisterSpoError, find_registry_utxos, registration_list_action_redeemer,
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
    let find = |list: &RegistryList| -> Option<Vec<u8>> {
        list.iter()
            .find(|(_, data)| data.bifrost_id_pk == bifrost_id_pk)
            .map(|(pool_id, _)| pool_id.to_vec())
    };
    if find(current).is_some() {
        return MembershipState::Current;
    }
    match previous.and_then(find) {
        Some(pool_id) => MembershipState::Migratable { pool_id },
        None => MembershipState::NotRegistered,
    }
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
    // bindings come back through `union_identity_pairs` below, which is the one
    // copy of the rule all three builders share.
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
    // root commits to — which during a migration window is the UNION of the two
    // lists, not the previous one alone.
    //
    // `Migrate` does not move the root ([MIG-6]), so every binding written under
    // the previous registry is still in it. But the new registry is live the
    // moment Config #9 moves: a pool that has never been in the old list can
    // register under it, and that insertion DOES move the root. Rebuilding from
    // the previous list alone would then miss that entry, produce a different
    // root, and yield a proof the validator rejects — after the fee.
    //
    // Keyed by `bifrost_id_pk`, so a pool present in both lists (migrated
    // already) contributes once; the trie holds one entry per identity key,
    // which is the uniqueness [REG-5] exists to enforce.
    let state = find_treasury_state(
        req.treasury_utxos,
        req.treasury_policy_hex,
        req.treasury_asset_name_hex,
    )?;
    let identity_pairs = crate::cardano::register_spo::union_identity_pairs(
        &list,
        Some((
            req.previous_registry_policy_hex,
            req.previous_registry_utxos,
        )),
    )?;
    let identity_trie = mpf::Trie::from_pairs(identity_pairs)
        .map_err(crate::cardano::treasury_info::TreasuryInfoError::Mpf)?;
    if identity_trie.root_hash() != state.datum.bifrost_identity_root {
        return Err(RegisterSpoError::Build(format!(
            "the two registry lists do not rebuild the Treasury state's identity root ({} from \
             the lists, {} in the datum), so a membership proof built here would be rejected on \
             chain. The shape that causes it: a pool that migrated and then exited under the new \
             registry is gone from the trie but still sits in the frozen old list, so the union \
             over-counts by that pool. Refusing here costs nothing; spending a fee to find out \
             costs a fee",
            hex::encode(identity_trie.root_hash()),
            hex::encode(state.datum.bifrost_identity_root),
        )));
    }
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
        let mut keys: Vec<(Vec<u8>, u32)> = reference_inputs
            .iter()
            .map(|r| (hex::decode(&r.tx_hash).unwrap_or_default(), r.tx_index))
            .collect();
        keys.sort();
        keys.dedup();
        let want = (hex::decode(tx_hash).unwrap_or_default(), index);
        keys.iter().position(|k| *k == want).unwrap_or(0) as i64
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

            let refs: Vec<_> = tx
                .transaction_body
                .reference_inputs
                .iter()
                .flat_map(|s| s.iter())
                .collect();
            let at_ref = |i: i64,
                          tx_hash: &str,
                          index: u32,
                          what: &str|
             -> Result<(), RegisterSpoError> {
                let got = refs.get(i as usize).ok_or_else(|| {
                    RegisterSpoError::Build(format!("{what} reference index {i} out of range"))
                })?;
                if hex::encode(got.transaction_id.as_slice()) != tx_hash
                    || got.index != u64::from(index)
                {
                    return Err(RegisterSpoError::Build(format!(
                        "{what} not at redeemer reference index {i} — reference ordering changed"
                    )));
                }
                Ok(())
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
