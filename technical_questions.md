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

**Resolved (2026-06-11): spec-ward.** The code is canonical; the spec was
patched to match. `technical_documentation.md` §3.2 (registration) and §3.4
(ban — same `linked_list.Element` shape, same error) now describe the key as
the NFT asset name and the datum as `Element{data, link}`, with the operation
names (`linked_list.insert_ascending`/`remove`) and module reference
corrected. ft-bifrost-bridge commit `4bcc70e` (fork
`feat/b1-confirm-tm-reference`). WI-008 closed; WI-005 unblocked.

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

### 2c. The Config UTxO is undocumented in the spec, and immutable in code

The `config.ak` Config UTxO is the central protocol-parameter oracle in the
implementation — `peg_in.ak` / `peg_out.ak` are parameterized by
`config_nft_policy_id` + `config_nft_asset_name` and read `ConfigDatum` as a
reference input at runtime (verifier script hashes, token policies, `min_stake`).
Yet in the spec:

- `config.ak` / the Config UTxO is **absent from the on-chain components list**
  (which enumerates `spos_registry`, `spo_bans`, `fault_verifier`, `peg_in`,
  `peg_out`, `treasury`, `treasury_movement`, `bridged_asset`). The Config UTxO
  is mentioned exactly **once** in the whole document (the `fee_rate_sat_per_vb`
  line above), with no datum/field/governance description.
- That single mention is wrong on two counts vs the code: (i) `ConfigDatum`
  has no fee field (see 2b); (ii) it says "updated by governance," but
  `config.ak`'s `spend` branch is `False` — the Config UTxO is **immutable**
  once minted and can never be updated by anyone.

So "read the fee from the governance-updated Config UTxO" is **not
implementable against the current contracts**: the field isn't there and the
UTxO can't be updated.

### Resolution direction (decided 2026-06-11): fix CONTRACTS to the spec

Unlike §1 (registration linked-list, where the code is the newer deliberate
artifact and the **spec** is canonical — resolve spec-ward), §2 resolves
**code-ward: the spec's design (a governance-updatable Config UTxO holding the
fee parameters) is canonical, and the contracts are to be brought into
compliance.** Each `spec_differences` entry names its own canonical side so the
two are not later "fixed" in the wrong direction.

These are FluidTokens **upstream** contracts (`ft-bifrost-bridge`); heimdall
cannot change them unilaterally, so a-d below are a change request to / upstream
contribution for FluidTokens, and the spec itself must be elaborated in tandem
(it is currently incomplete and self-contradictory, per 2a-2c). Concrete work
this decision implies:

- **(a) Spec** — document the Config UTxO + `ConfigDatum` field list; add
  `fee_rate_sat_per_vb` + the per-peg-out fee; define the governance update
  mechanism; resolve gross-vs-net (2a); state the per-peg-out fee value and
  whether fees are exact or leader-bounded (see the signing-model note below).
- **(b) Contract** — add the fee fields **and a minimum peg-out fBTC value** to
  `ConfigDatum` (`lib/bifrost/types/config.ak`); see 2d.
- **(c) Contract** — change `config.ak` `spend` from `False` to a
  governance-authorized update path so the Config UTxO is actually updatable.
- **(d) Contract** — implement the
  `legit_treasury_movement_and_peg_out_produced` verifier (today unimplemented)
  to check the BTC output value == gross − fee. This is also the missing piece
  that makes the whole peg-out completion path currently unverifiable.
- **(e) heimdall** — read the fee params from the Config UTxO reference input;
  drop local `bitcoin.*fee*` as the source of truth (keep only as a dev
  override). This is WI-009, gated on (a)-(d).

Dependency: (a) → (b,c,d) → (e).

**Signing-model sub-question (open).** Whether the fee must be an *exact*
consensus value or a governance-set *bound* depends on the FROST signing model:
(A) every SPO independently reconstructs the identical tx (exact value
required), vs (B) a leader proposes the tx and each signer validates-then-signs
(a bound suffices, and signers must NEVER blind-sign — they validate inputs,
peg-out destinations/amounts at gross − fee, treasury next-address, and that
the fee is within bounds). (B) handles real-time Bitcoin fee movement better. A
governance-updatable Config UTxO (c) supports either. To be decided with the
spec elaboration (a).

### 2d. Minimum peg-out fBTC value belongs in the Config (not just off-chain skip)

A peg-out whose locked fBTC is below `per_peg_out_fee + Bitcoin dust (330 sat)`
is **physically unfulfillable** — no valid BTC output can be produced — so the
TM builder must drop it. heimdall now does this defensively off-chain
(`build_tm` skips such peg-outs and reports them in `UnsignedTm.skipped_pegouts`
instead of aborting the whole TM; without it, anyone could park 1 sat of fBTC at
the permissionlessly-payable `peg_out.ak` address and DoS every Treasury
Movement bridge-wide). But the off-chain skip is a liveness band-aid: it leaves
the unfulfillable PegOut UTxO on-chain (the user must Cancel to reclaim), and
the skip threshold is only deterministic across SPOs if `per_peg_out_fee` is a
consensus value (2b).

The proper fix is on-chain: **add a `min_peg_out_fbtc` value to `ConfigDatum`
and have `peg_out.ak` reject a lock whose fBTC value is below it.** Then
sub-dust peg-outs cannot be created in the first place, the griefing vector is
closed at the source, and the off-chain skip becomes a belt-and-suspenders
guard rather than the only defense. The minimum must be ≥ `per_peg_out_fee +
dust` (and realistically higher, since the spec already positions Bifrost for
large liquidity moves, not retail-size withdrawals). **Question for
FluidTokens:** add `min_peg_out_fbtc` to the Config and enforce it in
`peg_out.ak` at lock time — folded into the §2 code-ward contract changes (b).

## 3. Update-Y (key rotation): spec gap RESOLVED upstream; remaining gap is the contract

History: our fork notes (2026-06, `internal-docs/bitfrost/heimdall/`
`key-publication-todo.md`; fork commits `c84f8d3`/`4bc8b34`, since dropped)
flagged Update-Y as a **spec gap** — the transaction existed by name only, with
no Transaction-catalog entry and no authorization rule (no signature scheme,
quorum, or validator check), and noted that a `treasury_movement.ak`-style
leader-election gate would be unsafe here (the payload IS the new group key; a
lone leader could publish an attacker key).

**Resolved in the spec (upstream `main` @ `8b042f9`, 2026-06).**
`technical_documentation.md` now:

- lists **Update Y** in the Transaction catalog: "Publication of the new
  roster's $Y_{51}$ to `treasury.ak`";
- specifies the authorization in the group-key-generation steps: "The
  **current roster** publishes the successfully derived group public key on
  Cardano at `treasury.ak`, **authenticated by a FROST group signature from
  the current roster**" — i.e. the outgoing roster signs the handoff, the
  model our notes called candidate (a);
- states in the Confirm-TM section that "key rotation is done in a separate
  Update-Y transaction after DKG", cleanly separating it from TM confirmation.

**Remaining gap is now CODE-ward.** The implemented `treasury.ak`
(`treasury_info`) has no spend path that can rotate the key: its `spend`
branch only authorizes a datum update when an `spos_registry`-policy token is
minted, and every registry mint branch (`Register`/`Deregister`) requires the
treasury transition to PRESERVE `current_spos_frost_key` (and address/outpoint;
only `bifrost_identity_root` may change). So the spec's FROST-authenticated
Update-Y is not expressible against the current contract. Note the check is
implementable on-chain: the key to verify AGAINST (`current_spos_frost_key`)
is already in the spent datum, so the validator can
`verify_schnorr_signature(current_key, H(new datum fields), frost_sig)`.

**Question for FluidTokens:** add an Update-Y redeemer/spend path to
`treasury.ak` verifying a BIP340 signature by the datum's
`current_spos_frost_key` over the new `(bifrost_identity_root,
current_treasury_address, current_treasury_utxo_id, current_spos_frost_key)`
— with replay protection (e.g. epoch binding or the spent outpoint in the
signed message). Gates heimdall's K2 / `PublishKeys` (treasury handoff at
epoch boundary); until then the group key set at K1 bootstrap is permanent.

## 4. DKG Round 1 σ_i (proof-of-knowledge) byte layout: "challenge ‖ response" (spec) vs frost-native R_x‖μ

`technical_documentation.md` §6.1 "Round 1 Payload" describes the
proof-of-knowledge field as:

> `sigma_i` is the Schnorr proof of knowledge (challenge ‖ response, 64 bytes).

and appends `σ_i (64B)` to the **signed** canonical byte layout
(`"bifrost-dkg-r1" || … || φ_{i(t-1)} (33B) || σ_i (64B)`).

The FROST library heimdall uses (`frost-secp256k1-tr` 3.0.0-rc.0 over
`frost-core` 3.0.0-rc.0) produces the PoK as RFC 9591 σ_i = (R_i, μ_i):
`R_i = g^k` (a nonce commitment **point**), `μ_i = k + a_{i0}·c_i` (the response
scalar), `c_i = H(i, Φ, φ_{i0}, R_i)`. Its public serialization
(`Signature::serialize()` → the `-tr` BIP340 compact hook) is **x-only `R_i`
(32B) ‖ `μ_i` (32B) = 64 bytes** — i.e. *commitment-point ‖ response*, not
*challenge ‖ response*. The width is identical, so that is not the issue: the
**first 32 bytes differ** — R's x-coordinate vs the challenge scalar `c_i`.

This is not cosmetic. `σ_i` sits **inside** the BIP340-signed `canonical_bytes`
for `bifrost-dkg-r1`, and it is the exact object the Round-1 invalid-PoK fault
circuit checks (§9: "the circuit verifies that σ_i is not a valid Schnorr proof
for φ_{i0}"). The layout must be byte-identical across the publisher, every
verifying peer, and the on-chain / Plonk verifier, or both payload
authentication and equivocation evidence break.

No existing implementation pins it: the upstream offchain DKG is a placeholder
(`offchain/spo-demo` uses `@noble/curves` schnorr only for identity/bootstrap),
the Lean proofs are abstract (`opaque validSchnorrSig`), and heimdall's own
circuits cover only the Round-2 Feldman-VSS fault (`src/circuits/commitment.rs`)
and the signing-share fault (`src/circuits/signature.rs`) — **not** the Round-1
PoK fault. Heimdall is effectively the first/reference implementer of DKG
Round 1.

**Proposed resolution (heimdall-ward, pending confirmation): σ_i = x-only R_i ‖
μ_i** — the `frost-secp256k1-tr` `Signature::serialize()` output, used verbatim.
Rationale: it is emitted losslessly by the library (no re-derivation); frost's
verification is the RFC form `R_i ≟ g^{μ_i}·φ_{i0}^{−c_i}`, which needs `R_i`
present in the payload — exactly what an on-chain Round-1 fault circuit will need
too; and "challenge ‖ response" reads as loose wording for the `(R, μ)` proof.
Whichever layout is chosen, `c_i` is computed with frost's domain-separated hash
(the secp256k1-tr context string + `"dkg"` subdomain), so any on-chain Round-1
fault circuit must replicate that exact hash regardless of the field order.

**Question for FluidTokens:** confirm `σ_i = x-only R_i (32B) || μ_i (32B)` as
serialized by `frost-secp256k1-tr` — or, if `challenge ‖ response` (`c_i || μ_i`)
is intended, specify the exact challenge-hash domain separation so the canonical
bytes and the Round-1 fault circuit agree. Tracked by WI-013 (parcel 1 pins the
layout in the canonical-bytes builder); cheap either way, but must be fixed
before WI-013 ships because σ_i is signature-covered and becomes on-chain
evidence.

**Resolved (2026-06-15): in-repo, frost-native `R_x ‖ μ` (Interpretation A).**
Two independent implementations converged on it, so no FluidTokens confirmation
is needed for the layout:

- **Transport (WI-013, PR #4):** `http/frost_bridge.rs` ships
  `proof_of_knowledge().serialize()` = x-only `R_i ‖ μ_i` verbatim.
- **On-chain fault circuit (PR #3, `feat/dkg-fault-circuits`):** the Halo2 DKG
  Round-1 PoK fault prover (`src/circuits/dkg_fault.rs`) reads σ_i the same way —
  `package.proof_of_knowledge().serialize()`, taking `μ = bytes[32..64]` and
  lifting `R = even_y(bytes[0..32])` — and recomputes the challenge via
  `Secp256K1Sha256TR::HDKG(identifier ‖ φ_{i0} ‖ R)` (context
  `FROST-secp256k1-SHA256-TR-v1` + label `dkg`). So the wire σ_i feeds the fault
  prover with no conversion.

The literal-spec `c_i ‖ μ_i` form was never implemented. Note also that PR #3
**supersedes** the "heimdall's circuits don't cover the Round-1 PoK fault"
statement above: it adds that circuit and removes the old dusk-plonk
`src/circuits/{commitment,signature}.rs` + `src/gadgets/*`. (Separately, PR #3's
`fault_token_name = blake2b_256(pool_id ‖ public_input)` diverges from the spec's
`pool_id ‖ epoch_u32_be` that `spo_bans.ak` ApplyBan burns — tracked against
WI-016/017, not WI-013.)
