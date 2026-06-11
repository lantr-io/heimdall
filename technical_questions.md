# Technical questions

Discrepancies and open questions to resolve with FluidTokens (upstream
`ft-bifrost-bridge`). Mirrored in
`internal-docs/bitfrost/heimdall/spec_differences.md`.

## 1. Registration linked-list: node key in datum (spec) vs NFT asset name (code)

`documentation/technical_documentation.md` §3.2 "Registration Linked-List"
(added 2026-03-03) sketches the node **datum** as carrying the ordering key:

```json
{ key              :: ByteArray        -- pool_id (ordering key)
, next             :: ByteArray | Null -- key of the next node, or null for the tail
, data             ::
    { bifrost_id_pk :: ByteArray
    , bifrost_url   :: ByteArray
    }
}
```

The implemented contracts (`onchain/validators/bitcoin/spos-registry.ak` +
`aiken_design_patterns/linked_list`, merged 2026-04-20 in M2 PR #15, confirmed
against the compiled `plutus.json` blueprint) store **no key in the datum**.
The element's key is the asset name of the registry-policy NFT held in the
UTxO (`"reg-root"` for the root, `pool_id` for nodes, empty node-key prefix),
and the datum is only:

```text
Element       = Constr(0, [ ElementData, Link ])
ElementData   = Constr(0, [ Constr(0, []) ])                            -- Root{ListRootData}
              | Constr(1, [ Constr(0, [bifrost_id_pk, bifrost_url]) ])  -- Node{RegistrationNodeData}
Link          = Constr(0, [ next_key ]) | Constr(1, [])                 -- Some key / None
```

The difference is not cosmetic. A datum is unauthenticated, mutable state:
anyone can park a UTxO at the script address with a forged `key`, and every
spend path would have to re-check "key unchanged" and "key == token name".
The asset name is minted under the registry policy (validated once, at mint),
immutable without a burn/mint the policy controls, and indexable by chain
indexers (`(policy, pool_id)` lookup). The implemented design is the stronger
one; the spec sketch describes the *logical* record, not the wire format.

Anything decoding registration datums from the spec sketch instead of the
contracts would mis-parse every element. Heimdall follows the contracts
(`src/cardano/registry.rs`, WI-002).

Related naming drift in the same section: §3.2 says the operations correspond
to `ordered.prepend` / `ordered.remove`; the implementation uses
`linked_list.insert_ascending` / `linked_list.remove`.

**Question for FluidTokens:** update §3.2 to the implemented shape (key as
NFT asset name, `Element{data, link}` datum), or is a datum-key redesign
intended? Until answered, the spec/code mismatch is tracked as a heimdall
work item blocking register_spo tx construction (WI-005).

## 2. Peg-out amount: gross vs net, and where the TM fee parameters live

Two related issues found while wiring the Treasury Movement peg-out payments
(heimdall `src/cardano/pegout_datum.rs` + `src/bitcoin/tm_builder.rs`).

### 2a. The spec contradicts itself on the peg-out output amount

- The **peg-out request** sections say the destination is paid the *full*
  locked amount: §"Peg-out (Bitcoin)" — "The peg-out **amount** is simply the
  fBTC quantity held in the UTxO's value"; the Treasury Movement **outputs**
  row — "one payment output per PegOut (pays `btc_destination_scriptPubKey`
  with `amount`)"; and "Each PegOut payment matches the destination **and
  amount in its datum**."
- The **Treasury Movement → "Amounts and fees"** subsection says the opposite:
  "Per-peg-out protocol fee: a fixed fee (protocol parameter) deducted from
  each peg-out output… Each peg-out output: amount from the PegOut UTxO datum
  **minus** the per-peg-out protocol fee."

The reconciliation is almost certainly: the datum amount is the GROSS the user
burns, and the BTC output pays gross − fee (the "Amounts and fees" subsection
is authoritative; the earlier "pays `amount`" is a simplification). On-chain,
`peg-out.ak` binds `redeemer_peg_out_amount == bridged_tokens_to_peg_out` (the
gross), and delegates the actual BTC-output-value check to
`legit_treasury_movement_and_peg_out_produced_verifier` — which is **named in
`ConfigDatum` but not yet implemented**, so whether that verifier will require
`output == gross` or `output == gross − fee` is currently undefined by code.
heimdall follows the "Amounts and fees" model (gross − fee). **Question:**
confirm the gross-minus-fee model and fix the earlier sections to match.

### 2b. The implemented `ConfigDatum` has no fee fields

The spec says `fee_rate_sat_per_vb` is "a protocol parameter stored in the
Config UTxO on Cardano, updated by governance," and the per-peg-out fee is "a
fixed fee (protocol parameter)." But the implemented
`onchain/lib/bifrost/types/config.ak` `ConfigDatum` carries no fee fields at
all (policy ids, verifier script hashes, `min_stake` only). So there is
nowhere on-chain for SPOs to read the agreed fee parameters from.

This matters for FROST determinism: the TM bytes (peg-out outputs + treasury
change) depend on BOTH `fee_rate_sat_per_vb` and the per-peg-out fee, and the
spec's "deterministic since all SPOs build the same transaction" only holds if
every SPO uses identical values. heimdall currently reads both from LOCAL
per-operator config (`bitcoin.fee_rate_sat_per_vb`,
`bitcoin.per_pegout_fee_sat`), which diverges across operators. **Question:**
add `fee_rate_sat_per_vb` (and the per-peg-out fee) to `ConfigDatum` so SPOs
read consensus values, or specify another agreed source? Tracked as a heimdall
work item (source TM fee params from the on-chain Config UTxO) that gates real
multi-SPO TM signing.
