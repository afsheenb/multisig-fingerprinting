# Anonymous multisig implementation cohorts

Offline analysis of exported on-chain script and public-key data. **No company is identified by this report.**

Standard CHECKMULTISIG scripts: **39,058**. Distinct anonymous repeated-key cohorts (minimum 5 separate scripts): **23**.

## Shared-key coverage by quorum

| Quorum | Scripts | Linked to reused key (≥5 scripts) | Share |
|---|---:|---:|---:|
| 1/1 | 3,839 | 0 | 0.00% |
| 1/2 | 248 | 187 | 75.40% |
| 2/2 | 6,361 | 3,743 | 58.84% |
| 2/3 | 26,208 | 308 | 1.18% |
| 2/4 | 527 | 129 | 24.48% |
| 2/5 | 24 | 0 | 0.00% |
| 3/4 | 1,576 | 114 | 7.23% |
| 3/5 | 153 | 0 | 0.00% |
| 5/6 | 21 | 0 | 0.00% |
| 5/7 | 41 | 0 | 0.00% |

## Largest exact-key cohorts

| Cohort | Quorum | Unique scripts | Distinct first-seen blocks | Repeated keys | Ordering | Main key position(s) |
|---|---:|---:|---:|---:|---|---|
| `cohort_8100366f6ef1` | 2/2 | 2,221 | 22 | 1 | sorted=1812, unsorted=409 | 1=2221 |
| `cohort_885d3e6273c2` | 2/2 | 722 | 1 | 1 | sorted=618, unsorted=104 | 1=722 |
| `cohort_1ffc3873cf35` | 2/2 | 406 | 1 | 1 | sorted=67, unsorted=339 | 1=406 |
| `cohort_4cde8b95f31d` | 2/2 | 182 | 1 | 1 | sorted=140, unsorted=42 | 1=182 |
| `cohort_6182dd652730` | 1/2 | 175 | 64 | 1 | sorted=89, unsorted=86 | 0=88, 1=87 |
| `cohort_dba8c90141e2` | 2/4 | 129 | 6 | 2 | sorted=129 | 0=19, 1=59, 2=49, 3=2 |
| `cohort_97528c091227` | 2/2 | 117 | 7 | 1 | sorted=87, unsorted=30 | 1=117 |
| `cohort_8f5496c21ee9` | 3/4 | 114 | 1 | 3 | sorted=114 | 0=103, 1=11 |
| `cohort_d6f087b8d8bf` | 2/3 | 84 | 54 | 1 | sorted=20, unsorted=64 | 1=84 |
| `cohort_70512168cf32` | 2/3 | 76 | 11 | 1 | sorted=76 | 0=2, 1=15, 2=59 |
| `cohort_04205fae636f` | 2/3 | 54 | 16 | 2 | sorted=54 | 0=26, 1=28 |
| `cohort_19cb0d281d18` | 2/3 | 40 | 33 | 1 | sorted=8, unsorted=32 | 1=40 |
| `cohort_8f3c236615bf` | 2/3 | 36 | 1 | 2 | unsorted=36 | 2=36 |
| `cohort_d59b06f2e810` | 2/2 | 36 | 17 | 1 | sorted=2, unsorted=34 | 0=36 |
| `cohort_af3c537a2869` | 2/2 | 20 | 13 | 1 | sorted=3, unsorted=17 | 1=20 |
| `cohort_b4c0ef9919ff` | 2/2 | 16 | 5 | 1 | sorted=16 | 1=16 |
| `cohort_c12f87cebe94` | 2/2 | 13 | 6 | 1 | sorted=6, unsorted=7 | 1=13 |
| `cohort_1c4e87d11021` | 1/2 | 12 | 9 | 1 | sorted=12 | 1=12 |
| `cohort_d1baae673948` | 2/3 | 12 | 10 | 1 | sorted=11, unsorted=1 | 0=2, 1=4, 2=6 |
| `cohort_9a46d6713dcb` | 3/6 | 8 | 3 | 5 | unsorted=8 | 4=8 |
| `cohort_932a3ecae424` | 2/3 | 6 | 1 | 3 | unsorted=6 | 2=6 |
| `cohort_4fd0b106de22` | 2/2 | 5 | 5 | 1 | sorted=4, unsorted=1 | 1=5 |
| `cohort_abd5f0fb2514` | 2/2 | 5 | 5 | 1 | unsorted=5 | 1=5 |

**Single-block caveat:** a cohort whose scripts first appear in just one sampled block may be one batch transaction rather than evidence of a persistent service. Compare cohort IDs and scripts against transaction IDs before inferring ongoing operation.

## Exploratory mixture for ordinary P2WSH 2-of-3

5,371 of 19,935 distinct scripts are lexicographically sorted (26.94%).
Under a simplified always-sorted vs randomly-ordered model, the implied deliberately-sorted share is **12.33%**.

**Not a provider estimate.** Assumptions and selection effects may invalidate the mixture.

## Interpretation and next validation

An identical pubkey across distinct scripts is proof of a common script key, but not of company control. Role-based sorting, different thresholds, script forms, and key-reuse shape create anonymous implementation families. They are not automatically one-provider-per-family.

To attach provider names or identify signing roles, recover independently authenticated wallet descriptors/transactions and join full verified signing positions from the local corpus SQLite database. That SQLite corpus is not required for this offline analysis.

All script memberships are exported in `cohort_script_members.csv`. No blockchain API was called.
