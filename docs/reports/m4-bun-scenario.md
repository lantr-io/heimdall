# Scenario 2 on PREPROD — DKG cheat → ban → restore (2026-07-23)

## Result

Three SPOs formed a 2-of-3 roster against Cardano preprod through Blockfrost.
One SPO equivocated during DKG, was banned on-chain, and the two remaining SPOs
derived an identical replacement group key.

**Status: GREEN — cheat → detect → FaultProof → ApplyBan → restore, all live on
preprod.**

From an honest node at epoch 302:

```text
EQUIVOCATION: peer 8b041cf4… published two distinct payloads (attempt 56656, Round1)
[fault-ban] built FaultProof mint: policy=5baf6d9a… token=6d89a4b3…
[fault-ban] submitted fault-proof mint: tx_hash=1f7e502d…
[fault-ban] built ApplyBan: first_ban=true counter=1 until=1784828539999
[fault-ban] submitted apply-ban: tx_hash=402c81cc…            ← CONFIRMED (block 4970247, slot 129141155)
[chain-view] … active_bans=[8b041cf4] eligible=[7b27a98e,e8a8dd8d]   ← ban settled, roster 3→2
PublishKeys: group_key = 6bcf3346…                            ← restored (both survivors agree)
```

The two honest nodes (`7b27a98e`, `e8a8dd8d`) derived the same post-ban
two-member key, `6bcf3346…`. No three-member key completed because the third
participant equivocated on every attempt. The confirmed ban is
[`402c81cc…ac9cb9`](https://preprod.cardanoscan.io/transaction/402c81cc48cd7c2bcc54ebac407c8f2cb0480d5b2234b429816d11aadcac9cb9).

## Transactions

All transactions are on Cardano preprod. The run comprises **14 confirmed
transactions**: 10 deployment/precondition transactions and 4 fault/ban
transactions.

### Deployment and prerequisites

| Step | Transaction | Note |
|---|---|---|
| bootstrap-treasury-info (K1) | [`9b400e90…857e05fb`](https://preprod.cardanoscan.io/transaction/9b400e90d5b2652235076ab5f1f06b1bfdc7d813e919a07385c1da0a857e05fb) | treasury_info asset `a8486c3a…` |
| bootstrap-registry | [`5ddc2450…29408a7`](https://preprod.cardanoscan.io/transaction/5ddc24508fcd9b8ce836ded85fc2215b7116ba05520f99f38cbe00a7929408a7) | registry policy `3b1be7b5…` |
| deploy-registry-ref | [`ca8d7a31…cae4d1`](https://preprod.cardanoscan.io/transaction/ca8d7a3142a5cd79a86581d9158884af987d26b0965ad77e230f75c48bcae4d1) | reference script `#0` |
| register SPO `7b27a98e` | [`584ddaeb…bb728`](https://preprod.cardanoscan.io/transaction/584ddaeba737957077812cfc19437bc21b129e802cbb2f6e67ad9ded613bb728) | |
| register SPO `e8a8dd8d` | [`c1a7643e…6817650`](https://preprod.cardanoscan.io/transaction/c1a7643e5f020ba5d358b9c7e4ecccad11aabc49ad1044700de03179f6817650) | |
| register SPO `8b041cf4` | [`840eea70…314ea`](https://preprod.cardanoscan.io/transaction/840eea70c002b31290d0a5773aa219e85159a50f28f0d9a973fa1f4b99a314ea) | participant that later equivocated |
| bootstrap-ban-list | [`52dd6b81…0b16e2`](https://preprod.cardanoscan.io/transaction/52dd6b8137e6ded07b49ae45b63035b2d7b7db25a94e63320dc3de723a0b16e2) | spo_bans policy `cff6637d…` |
| deploy equivocation fault reference | [`f89dd75e…5e75fc`](https://preprod.cardanoscan.io/transaction/f89dd75e8d3a56f24d39ce87bf1655c08a18b67472906ad94663141b095e75fc) | reference script `#0`, policy `5baf6d9a…` |
| deploy spo_bans reference | [`7048461e…3a684df`](https://preprod.cardanoscan.io/transaction/7048461e68c94e7418d3685eed77bce6b6df06c9660335655b23980033a684df) | reference script `#0` |
| initialize ban withdrawal credential | [`caf3a02f…463a3f6`](https://preprod.cardanoscan.io/transaction/caf3a02f3424402bc745b77056a93301b8985e04b9db9cbe2552881ae463a3f6) | required for ApplyBan |

### Fault and ban

| Step | Transaction | Note |
|---|---|---|
| FaultProof mint (counter 1) | [`1f7e502d…8ab91b`](https://preprod.cardanoscan.io/transaction/1f7e502d8b6a185344e672f7335e6ad085de02c744ee8e966f26d670fa8ab91b) | equivocation proof against `8b041cf4` |
| **ApplyBan (first ban, counter 1)** | **[`402c81cc…ac9cb9`](https://preprod.cardanoscan.io/transaction/402c81cc48cd7c2bcc54ebac407c8f2cb0480d5b2234b429816d11aadcac9cb9)** | **confirmed at block 4970247, slot 129141155; changes the roster from 3 to 2.** |
| FaultProof mint (counter 2) | [`e5ccd151…c94c97`](https://preprod.cardanoscan.io/transaction/e5ccd151f7576a13b2a44ce067e990a59f958f3d63bc495f936a660424c94c97) | re-detected while the index lagged |
| ApplyBan (counter 2) | [`e2591c97…fe94da7`](https://preprod.cardanoscan.io/transaction/e2591c971e898243a37f9a04e72d924a374d777197b94e47a070dc37afe94da7) | re-ban, extending the timeout |

## Chain-view reconciliation

The run recorded zero chain-view disagreements, zero settling back-offs, and
zero divergence alarms. That is expected: all three nodes read the same
Blockfrost index, so they observed the confirmed ban in lockstep. The visible
counter-2 churn occurred while that shared index lagged; it was not a split
between node views.

This preprod run therefore demonstrates the end-to-end ban and recovery path.
The cross-view reconciliation path is exercised separately where nodes can
observe different chain tips.

## Operational note

Blockfrost index lag on preprod exceeded ten minutes at times. Deployment steps
and ban recovery therefore required index-aware settling between transactions.

## Scope

This scenario covers the ZK-free equivocation path. It does not exercise the
Round-1 or Round-2 invalid-payload proof paths, or treasury movement.
