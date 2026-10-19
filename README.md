# multisig-fingerprinting

An empirical, evidence-graded study of whether Bitcoin multisig custody
providers leave recognizable fingerprints on mainnet. The study covers
October 2023 through October 2026 and asks three questions: whether
providers' signing policies are observable on chain, whether institutional
keys link otherwise unrelated wallets, and what business intelligence can
be reconstructed from public chain data alone.

All data comes from the Blockchair API free no-key tier, with
mempool.space as a second keyless source for prevout resolution during
signature verification (1 request/second, 30/minute, permanent cache,
run stops on a sustained 429). There is no Bitcoin node: blocks arrive
as raw hex over HTTP and are decoded locally. Findings are graded by
the evidence that supports them, from exact script hash matches down
to statistical co-occurrence.

## Interpretation rules

These rules are binding on every report, chart, and claim produced by this
repository.

- A shared script template never implies a shared owner. Wallet software
  produces identical policy scripts for unrelated users.
- Shared pubkeys link scripts, not people. Key reuse is a script-level
  fact and is reported as one.
- No provider attribution without independent evidence. Template shape
  alone is never sufficient; an attribution needs corroboration outside
  the chain data (public documentation, self-identification, or a
  disclosed address set).
- No customer deanonymization. Findings are aggregates only; the study
  never names or locates individual users of a provider.
- No claims about MuSig2 adoption from key-path signature counts. A
  key-path Taproot spend is cryptographically indistinguishable from a
  single-key spend, so key-path counts bound nothing about multisig use.

## Setup

Requires Python 3.9 or newer.

    python -m venv venv
    ./venv/bin/pip install -r requirements.txt
    cp config.toml.example config.toml

`config.toml` is gitignored and must never be committed. No API key is
needed for the default no-key tier; leave `blockchair.api_key` empty.

## Usage

Run the CLI as a module: `./venv/bin/python -m msfp <command>`. Typical
phase order:

| Command | Purpose |
|---|---|
| `api-status` | Show quota ledger state and remaining daily point budget |
| `probe` | Validate each Blockchair endpoint class before any bulk spend |
| `pin-boundary` | Locate the study-period block-height boundary from raw headers |
| `benchmark-acquisition` | Compare raw-block acquisition against indexed endpoints on cost and yield |
| `scan` | Stratified block sampling plus script extraction (`--sample N`, `--range S E`, or `--resume`) |
| `validate` | Resolve prevouts for a sample and verify commitments and signatures where data allows |
| `classify` | Recompute template classes for all stored scripts |
| `keyindex` | Build the public-key reuse index and link components |
| `report` | Produce preliminary findings and the acquisition cost report |
| `corpus-status` | Show corpus counts, cache size, and disk budget |

Progress persists across interruptions; resumable phases pick up where
they stopped.

## Data layout

- `data/corpus.sqlite3` holds the extracted corpus: tables `blocks`,
  `txs`, `inputs`, `revealed_scripts`, `script_keys`,
  `script_observations`, `api_ledger`, and `plan`.
- `data/cache` is a gzip response cache keyed by request URL.
- `data/probes` stores endpoint probe results.
- `reports/` holds generated findings and cost reports.

## Rate limiting and ethics

The client operates strictly within the free tier and treats the API's
limits as a hard boundary.

- Every request reserves its estimated point cost before dispatch, and
  the reservation is recorded in the persistent `api_ledger` table, then
  reconciled against the cost reported in the response.
- Quota statuses are never retried.
- On HTTP 430 (IP blacklist) the client stops automatic acquisition. It
  waits out the configured cooldown and halts the run after repeated
  throttles.
- The 430 block is never circumvented: no IP rotation, no proxies, no
  multiple identities, no keys purchased without authorization.
- A daily point budget is enforced from `config.toml`, set below the
  documented no-key limits.

Observed endpoint behavior and the HTTP 430 timeline are documented in
`docs/api_notes.md`.

## Test suite

    ./venv/bin/python -m pytest tests/ -q

The suite runs BIP-0340 and BIP-0341 official test vectors plus synthetic
signed-transaction tests, covering decoding, script classification, and
signature verification.

## Anonymous shared-key cohorts (offline)

The `cohorts` command discovers anonymous implementation families **without
knowing the custody provider's keys or identity**:

    python -m msfp cohorts --graph-dir reports/graph --out-dir reports/cohorts

It uses only the existing `nodes_script.csv` and `edges_key_in_script.csv`
exports, with **zero Blockchair or mempool.space requests**, so it also works
when the original `data/corpus.sqlite3` is unavailable. The included ZIP does
not contain the SQLite corpus, but does contain both graph exports.

Outputs:

- `reports/cohorts/anonymous_cohorts.md`: human-readable findings and caveats.
- `reports/cohorts/anonymous_cohorts.json`: machine-readable groups and metrics.
- `reports/cohorts/cohort_script_members.csv`: exact script membership for each
  key-anchored cohort, with stable content-derived cohort IDs.

A *key-anchored cohort* means a public key occurs in at least five distinct
CHECKMULTISIG scripts with the same quorum. Closely co-occurring repeated keys
are consolidated to avoid triple-counting a fixed 3-of-4 institutional quorum.
This is an **exact script-to-key relationship**, not a verified company or
customer attribution. The report also distinguishes purely structural families
that must never be equated with legal entities.

The exported graph contains no per-observation transaction IDs or full
validation records, so the cohort report **does not infer signer behavior**
from signature byte order or claim that a key was the active signer. Join its
script hashes with the local `script_observations` and `validation_results`
tables to verify signing positions and build a transaction-based holdout set.

Standalone tests: `python -m unittest tests.test_cohorts`.
