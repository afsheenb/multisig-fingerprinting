# multisig-fingerprinting

An empirical, evidence-graded study of whether Bitcoin multisig custody
providers leave recognizable fingerprints on mainnet. The study covers
October 2023 through October 2026 and asks three questions: whether
providers' signing policies are observable on chain, whether institutional
keys link otherwise unrelated wallets, and what business intelligence can
be reconstructed from public chain data alone.

All data comes from the Blockchair API free no-key tier. There is no
Bitcoin node: blocks arrive as raw hex over HTTP and are decoded locally.
Findings are graded by the evidence that supports them, from exact script
hash matches down to statistical co-occurrence.

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
