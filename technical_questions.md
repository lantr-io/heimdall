# Technical questions

Discrepancies and open questions to resolve with FluidTokens (upstream
`ft-bifrost-bridge`). Mirrored in
`internal-docs/bitfrost/heimdall/spec_differences.md`. Resolved items are pruned
to a one-line trace — full history is in git.

## 1. Registration/ban linked-list datum shape — RESOLVED (2026-06-11, spec-ward)

Spec §3.2/§3.4 patched to the implemented `linked_list.Element{data, link}`
shape with the ordering key as the registry-policy NFT asset name (not a datum
field), op names corrected (`linked_list.insert_ascending`/`remove`).
ft-bifrost-bridge `4bcc70e` (also FluidTokens PR #19); WI-008 closed, WI-005
unblocked. heimdall follows the contracts (`src/cardano/registry.rs`, WI-002).

## 2. Peg-out amount (gross vs net) + TM fee parameters in the Config UTxO — OPEN (WI-009)

Two related issues found while wiring the Treasury Movement peg-out payments
(heimdall `src/cardano/pegout_datum.rs` + `src/bitcoin/tm_builder.rs`).

### 2a. The spec contradicts itself on the peg-out output amount

**Still present** in upstream `documentation/technical_documentation.md` (checked
@ `a0fad52`, 2026-06-12). The two sides, with section + line references:

- **"Pays the FULL amount"** —
  - §"Treasury Movement (Bitcoin)" (L558), Outputs row (L580): "one payment
    output per PegOut (pays `btc_destination_scriptPubKey` with **`amount`**)";
  - same §, verification bullet (L598): "Each PegOut payment matches the
    destination **and amount in its datum**";
  - §"Complete peg-out / burn fBTC (Cardano)" (L740), the completion check
    (L772): the `fulfilled_peg_outs` entry must match the destination "with an
    **amount equal to the fBTC held** in the PegOut UTxO".
- **"Pays GROSS − fee"** —
  - §"Deterministic TM construction" (L1671), output rule (L1699): "Each output
    pays the requested **amount minus the protocol fee** (see below)";
  - §"Amounts and fees" (L1701–1706): "Per-peg-out protocol fee … deducted from
    each peg-out output … Each peg-out output: amount from the PegOut UTxO datum
    **minus** the per-peg-out protocol fee".

So the contradiction is internal to the spec: the *request / output-description*
sections (Treasury Movement, Complete peg-out) still say full `amount`, while the
*construction* sections (Deterministic TM construction, Amounts and fees) say
gross − fee. The fee model itself is now self-consistent within the construction
section — the unfixed sentences are the earlier "pays `amount`" descriptions.

**This one bites: the completion check.** §Complete peg-out (L772) says the BTC
output must equal the **full** fBTC — but the TM pays fBTC − fee (L1699/L1706).
So if `bridged_asset.ak` enforces L772 as written, it rejects every fee-deducted
TM and **no peg-out can ever complete**. That's a real spec bug that breaks the
path, not a wording nit.

**Proposed resolution: gross − fee** (the construction sections are
authoritative; the datum `amount` is the GROSS the user burns). Fix the Treasury
Movement / Complete-peg-out sections (esp. L772) to match, and pin it when
implementing the §2 (d) verifier (`legit_treasury_movement_and_peg_out_produced`,
named in `ConfigDatum` but not yet implemented). heimdall already follows
gross − fee.

**How heimdall implements it (code):** `src/bitcoin/tm_builder.rs::build_tm`.
- Each peg-out output value = **gross − per-pegout fee**:
  `net_amount = po.amount.checked_sub(fee_params.per_pegout_fee)`, emitted as
  `TxOut { value: net_amount, script_pubkey }` (one output per surviving
  peg-out). Treasury change = `sum(inputs) − sum(peg-out outputs) − miner_fee`,
  `miner_fee = vsize × fee_rate_sat_per_vb`.
- **Sub-dust skip (the §2d griefing defense):** a peg-out whose
  `gross − per_pegout_fee < 330 sat` (P2TR dust) is dropped into
  `UnsignedTm::skipped_pegouts` (with reason `BelowDust` / `BadScript`) instead
  of aborting the whole TM — so 1-sat fBTC parked at the permissionless
  `peg_out.ak` address cannot DoS the bridge-wide Treasury Movement.
- **Fee params** come from `FeeParams { fee_rate_sat_per_vb, per_pegout_fee }`,
  sourced today from LOCAL operator config (`bitcoin.fee_rate_sat_per_vb`,
  `bitcoin.per_pegout_fee_sat` in `src/config.rs`). That is the §2b divergence
  risk: FROST needs byte-identical TMs, so the skip set and net amounts are only
  deterministic across SPOs if these are consensus values — hence WI-009 moves
  them to the Config UTxO. The builder already flags this inline
  (`tm_builder.rs` comment: "needs `per_pegout_fee` to be a consensus value").
- heimdall does NOT yet verify the completion check (L772) on-chain — that is the
  unimplemented §2 (d) `legit_treasury_movement_and_peg_out_produced` verifier;
  heimdall's TM bytes assume gross − fee, so if that verifier later enforces
  `output == gross` the two would disagree.

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

**Decided 2026-06-11: resolve code-ward** — the spec's design (a
governance-updatable Config UTxO holding the fee parameters) is canonical; bring
the upstream FluidTokens contracts into compliance (a change request to them,
with the spec elaborated in tandem). Concrete work:

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

## 3. Update-Y (treasury key rotation) — contract gap OPEN (spec resolved upstream)

Spec resolved upstream (`8b042f9`): Update-Y is in the Transaction catalog,
authorized by a FROST group signature from the **current** (outgoing) roster,
done as a separate tx after DKG. **Remaining gap is CODE-ward:** the implemented
`treasury.ak` (`treasury_info`) has no spend path that rotates
`current_spos_frost_key` — every `spos_registry` mint branch
(`Register`/`Deregister`) requires the treasury transition to PRESERVE it (only
`bifrost_identity_root` may change). The check is implementable on-chain (the key
to verify against is already in the spent datum).

**Question for FluidTokens:** add an Update-Y spend path to `treasury.ak`
verifying a BIP340 signature by the datum's `current_spos_frost_key` over the new
`(bifrost_identity_root, current_treasury_address, current_treasury_utxo_id,
current_spos_frost_key)`, with replay protection (epoch binding or the spent
outpoint). Gates heimdall's K2 / `PublishKeys` (treasury handoff at epoch
boundary); until then the K1-bootstrap group key is permanent.

## 4. DKG Round 1 σ_i (proof-of-knowledge) byte layout — RESOLVED (2026-06-15, in-repo)

σ_i = x-only `R_i`(32B) ‖ `μ_i`(32B), the `frost-secp256k1-tr`
`Signature::serialize()` form, used verbatim by both the WI-013 transport
(`http/frost_bridge.rs`) and the `dkg_fault` Round-1 PoK fault circuit (which
recomputes the challenge via `Secp256K1Sha256TR::HDKG(id ‖ φ_{i0} ‖ R)`, context
`FROST-secp256k1-SHA256-TR-v1` + label `dkg`). The literal-spec `c_i ‖ μ_i` form
was never implemented; no FluidTokens confirmation needed.

## 5. FaultProof token name + ban policy — RESOLVED upstream (evidence-bound)

Token name = `blake2b_256(pool_id ‖ evidence_hash)`; pool binding by recompute
(ApplyBan carries `accused_pool_id` + `evidence_hash`, `spo_bans.ak` recomputes
+ checks the authorized policy minted/burned it); time-based bans
`ban_until_time = start_time_ms + base_ban_duration_ms·2^(n−1)`; dedup by the ban
node's `evidence_hashes` list with a `permanent` cap at
`max_faults_before_permanent`; multi-policy (separate round1/round2/equivocation
verifiers in `fault_proof_policy_ids`). heimdall matches it — WI-016/017/018
delivered; WI-019 derives the real `evidence_hash`. The one open FluidTokens
question is the §5a InvalidPayload ZK-verify binding.

### 5a. InvalidPayload fault verifier — permissive mock; a FluidTokens binding decision is needed

The `fault_verifier` `PublishProof` (InvalidPayload) branch is still a permissive
mock — it checks only structural shape (token name, 28/32-byte lengths,
datum-on-output), **no ZK verify** — so anyone can mint a forged InvalidPayload
FaultProof against any pool, and ApplyBan trusts it.

**The open question (FluidTokens design call):** a real ZK verify needs the proof
bound to the payload the accused *signed*. The `dkg_fault` circuit's public input
is `Poseidon(structured_fields)`, but the accused signs
`message_hash = SHA256(canonical_bytes)`; nothing ties them, so a generated
verifier is forgeable (fabricate fields → valid proof → ban an honest pool).
Closing it needs either (a) computing `SHA256(canonical_bytes)` **in-circuit** and
exposing `message_hash` as the public input (costly SHA256-in-ZK over a
variable-length preimage), or (b) an alternative binding scheme. Round 2
additionally needs the encrypted↔decrypted share binding. Once chosen, the
per-kind ZK verifier policies can be wired (the heimdall circuits already prove
the fault predicate). Until then the InvalidPayload ban path is functionally
testable but NOT trust-minimized — flag in any preprod/mainnet readiness review.
Tracked as WI-022.

(Equivocation is **not** an open FluidTokens question: the verifier is *our* code
— FluidTokens PR #20, open — implementing their spec §9.2, and its remaining
soundness hardening is *our* WI-020. Tracked there, not here.)
