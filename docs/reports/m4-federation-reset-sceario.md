# Federation reset on Cardano preprod (2026-07-24)

## Result

The emergency federation-reset recovery completed end-to-end on public Cardano
preprod. After the active SPO roster became unavailable, a federation sweep
was confirmed and `current_spos_frost_key` was rotated from the dead roster to
the federation key.

Cardano ran on public preprod through Blockfrost. Bitcoin used a regtest bench
for the federation CSV-leaf sweep; that side of the recovery is independent of
the Cardano network and allowed the CSV delay to be mined on demand.

## Transactions

Explorer: <https://preprod.cardanoscan.io/transaction/<hash>>

| # | Cardano preprod transaction | Step | Effect |
|---:|---|---|---|
| 1 | [`f010c0e6…10b80ac`](https://preprod.cardanoscan.io/transaction/f010c0e618d7bc4a5c9211cb490ff3f846391e2a5cccbbdc8d278354410b80ac) | Initialize oracle (one-shot) | Mints the oracle one-shot UTxO. |
| 2 | [`81533399…83b4c06`](https://preprod.cardanoscan.io/transaction/81533399e134cc2b24c0a03eaa002f6f86ded68a81a6bf5bc106e52f983b4c06) | Initialize oracle (reference script) | Deploys the oracle validator as a reference script. |
| 3 | [`3be7f413…1456436`](https://preprod.cardanoscan.io/transaction/3be7f413323a8bd8248e251e1ab5cd4c5fbc4189893b787c23d9f312b1456436) | Initialize oracle | Brings the oracle live with the regtest confirmation range. |
| 4 | [`2dce4027…1011a4`](https://preprod.cardanoscan.io/transaction/2dce40270efdde89079fec122534dd8bf1da799a314d5b6210b83cdcda1011a4) | Deploy bridge | Creates the configuration NFT and bridge reference scripts. |
| 5 | [`b3d846e5…55f3c5f`](https://preprod.cardanoscan.io/transaction/b3d846e5f2f84ecfef1127d9dde4cc6e7e8e9a2aec34786ff361969c155f3c5f) | Bootstrap treasury info | Initializes `current=P′`, `y_federation=P`, CSV `144`, and no prior reset. |
| 6 | [`28fd07df…5e2d5bb`](https://preprod.cardanoscan.io/transaction/28fd07df7f162792e7ba56083d6eeaf96361be6a244d9171cf65147e15e2d5bb) | Sweep peg-ins | Posts the federation treasury movement in `Unconfirmed` state. |
| 7 | [`2d244054…1011a4`](https://preprod.cardanoscan.io/transaction/2d2440540f4c370d1c8b17d842a8b63537053098303e72c1dea7e0399e8f6762) | Confirm treasury movement | Changes the movement to `Confirmed` with `spent_via_federation_leaf=true`. |
| 8 | [`63ccd883…4fdbbd9`](https://preprod.cardanoscan.io/transaction/63ccd8839a3e0fa728c0822ef55895b304a626918a49f31772db7662a4fdbbd8) | Federation reset | Rotates `current_spos_frost_key` from P′ to P and records the reset transaction. |

## Deployed identifiers

| Item | Value |
|---|---|
| Oracle script hash | `ce43a8cd69c697d9648cb3c6e61df963d82abfcf00624379982fe365` |
| Oracle one-shot reference | `f010c0e618d7bc4a5c9211cb490ff3f846391e2a5cccbbdc8d278354410b80ac#0` |
| Configuration NFT policy | `5968f8b10e5377ae5de07f7da042d823f36889020f7d1c53ba358a8f` |
| Treasury-movement validator hash | `187a0cf563470d7ce778bf49db0e1038accd45d6178c20b0ba828e1a` |
| Treasury-info policy | `2fb194bed7e99a19009fd739e2574067f3315ba07b177498377ec56d` |
| Registry policy | `728bc035a33ca053f1e0445ad71630245ca0f44674a269b715504f8b` |

## Bitcoin sweep

The federation CSV-leaf spend used treasury outpoint
`881173f308a6911f5927bd49d0f185f781459d7eaf94baac44df12e33700dec0:0`.
The corresponding regtest spend transaction was
`d21077e9cdfc5c6ff26616e6534d273328ad47cd451fdb5524b3e0af2eb4cbce`.

## On-chain verification

After transaction #8, the `treasury_info` datum showed:

```text
current_spos_frost_key = 4f355bdc…071aa  (federation key)
y_federation           = 4f355bdc…071aa  (unchanged)
federation_csv_blocks   = 144
last_reset_tm_txid      = cecbb42e…10d2
```

## Recovery status

The federation reset is the emergency first step of recovery and is complete.
The recovered or replacement SPO roster must still run DKG and perform the
follow-on `UpdateY` transaction to return treasury control from the federation
key to the new roster key. Those follow-on steps were not part of this run.

## Operational notes

- Allow for Blockfrost UTxO-index lag between dependent transactions.
- The preprod validity window used for the treasury movement was 1,800 seconds.
- Each confirmed transaction took approximately 13–53 seconds.
