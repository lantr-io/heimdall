- assemble TM based on real pegin requests (cap = 15K, sort based on order), accumulate them over an hour, print

query with pallas


pegin request contains bitcoin tx in datum, i parse bitcoin tx, assume that


Now, we need to modify the demo program for the following case:

We need to query the pegin requests for a configured period, and then once the period passes, 
we need to assemble the TM transaction, sign it, and then print it to the console.

The transaction needs to be assembled as either the period passes, or as it's size would reach 15 kilobytes.
As the TM transaction spends the previous treasury, we need to query for an existing treasury or just create a new one.

We're going to query pegin requsts from Cardano. We're going to find them by a configurable policy ID. Each of these contains a bitcoin transaction in its datum.
We need to parse this tx, and its hash is going to be the input to the TM transaction.

Let's plan this change: estimate the size, think about additional interfaces we're going to need, etc.
