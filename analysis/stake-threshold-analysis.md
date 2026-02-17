# Bifrost Stake Threshold Analysis

**Data snapshot:** January 27, 2026

## Overview

This analysis determines the FROST threshold parameter **M-of-N** for Bifrost, where:

- **N** = number of top Cardano stake pools admitted to the Bifrost roster
- **M** = minimum number of signers (from the weakest pools ascending) whose combined stake represents 51% / 60% / 67% of **total network stake**

The question answered: *how many of the smallest pools in the roster must collude to control the signing threshold?*

## Network Summary

| Metric               | Value       |
| -------------------- | ----------- |
| Total network stake  | 21,514M ADA |
| Total pools          | 2,935       |
| Pools with ticker    | 1,998       |
| Pools without ticker | 937         |

### Exchange Pools

| Exchange  | Pools  | Total Stake  | % of Network |
| --------- | ------ | ------------ | ------------ |
| UPBIT     | 15     | 527M ADA     | 2.4%         |
| BNP       | 36     | 461M ADA     | 2.1%         |
| **Total** | **51** | **988M ADA** | **4.6%**     |

## Methodology

1. Filter pools to those with a ticker (proxy for active, identifiable operators)
2. Take the top **N** pools ranked by stake (descending)
3. Sort these N pools by stake **ascending** (smallest first)
4. Accumulate stake from smallest to largest until reaching 51% / 60% / 67% of **total network stake** (21,514M ADA)
5. The count at that point is **M** — the threshold parameter

This models the worst case: the weakest participants in the roster combining to reach the signing threshold.

## Results: Including Exchanges

| N    | Total Stake | % Network | Min Pool Stake | 51% (M/N)      | 60% (M/N)      | 67% (M/N)      |
| ---- | ----------- | --------- | -------------- | -------------- | -------------- | -------------- |
| 1000 | 18,145M     | 84.3%     | 0.43M          | 894/1000 (89%) | 927/1000 (93%) | 950/1000 (95%) |
| 600  | 17,505M     | 81.4%     | 3.95M          | 506/600 (84%)  | 537/600 (90%)  | 559/600 (93%)  |
| 500  | 16,974M     | 78.9%     | 6.69M          | 415/500 (83%)  | 445/500 (89%)  | 467/500 (93%)  |
| 400  | 16,026M     | 74.5%     | 12.61M         | 330/400 (82%)  | 359/400 (90%)  | 380/400 (95%)  |
| 300  | 14,285M     | 66.4%     | 23.20M         | 256/300 (85%)  | 283/300 (94%)  | **Impossible** |
| 200  | 11,260M     | 52.3%     | 35.28M         | 197/200 (98%)  | **Impossible** | **Impossible** |
| 100  | 6,827M      | 31.7%     | 55.74M         | **Impossible** | **Impossible** | **Impossible** |

## Results: Excluding Exchanges (no UPBIT/BNP)

| N    | Total Stake | % Network | Min Pool Stake | 51% (M/N)      | 60% (M/N)      | 67% (M/N)      |
| ---- | ----------- | --------- | -------------- | -------------- | -------------- | -------------- |
| 1000 | 17,171M     | 79.8%     | 0.37M          | 912/1000 (91%) | 942/1000 (94%) | 964/1000 (96%) |
| 600  | 16,625M     | 77.3%     | 3.37M          | 521/600 (87%)  | 550/600 (92%)  | 572/600 (95%)  |
| 500  | 16,171M     | 75.2%     | 5.94M          | 428/500 (86%)  | 457/500 (91%)  | 478/500 (96%)  |
| 400  | 15,377M     | 71.5%     | 10.79M         | 340/400 (85%)  | 368/400 (92%)  | 389/400 (97%)  |
| 300  | 13,911M     | 64.7%     | 19.39M         | 261/300 (87%)  | 288/300 (96%)  | **Impossible** |
| 200  | 11,258M     | 52.3%     | 35.01M         | 197/200 (98%)  | **Impossible** | **Impossible** |
| 100  | 6,827M      | 31.7%     | 55.74M         | **Impossible** | **Impossible** | **Impossible** |

## Feasibility Boundaries

- **N >= 400** required for 67% of network stake to be reachable
- **N >= 300** required for 60% of network stake to be reachable
- **N >= 200** required for 51% of network stake to be reachable (barely — 98% of the roster)
- **N = 100** cannot reach any threshold — top 100 pools only hold 31.7% of network

## Key Observations

1. **Stake concentration is high.** The top 60 pools (in N=400) hold 20.4% of the network by themselves. This means the M/N ratio is always high — small pools are many but carry little weight individually.

2. **Exchanges have minimal impact.** Excluding UPBIT and BNP (51 pools, 4.6% of network) shifts M by only ~10 pools across all configurations. The exchange stake is spread across many small-to-medium pools.

3. **N=500 is the sweet spot.** It captures ~75-79% of network stake with a reasonable minimum pool size (5.94-6.69M ADA). The 67% threshold requires 467-478 of 500 signers (93-96%), leaving only 22-33 pools that can be offline.

4. **N=400 is the practical minimum** for a 67% network-stake threshold. It requires 380-389 of 400 signers (95-97%), meaning only 11-20 pools can be absent.

5. **Below N=300, strong thresholds become impossible.** The roster simply doesn't capture enough of the network stake.

## Tradeoffs

| Config | Pros                                               | Cons                                                            |
| ------ | -------------------------------------------------- | --------------------------------------------------------------- |
| N=1000 | Maximum coverage (84%), lower M/N ratios           | Many tiny pools (<1M), coordination overhead, low min-stake bar |
| N=500  | Good coverage (75-79%), reasonable min stake (~6M) | High M/N ratio (93-96% for 67%)                                 |
| N=400  | Decent coverage (71-75%), higher min stake (~11M)  | Very high M/N ratio (95-97% for 67%), tight availability margin |
| N=300  | Manageable roster size                             | Cannot reach 67% threshold, only 65% of network                 |
