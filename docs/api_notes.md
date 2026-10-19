# API notes (observed behavior, no-key tier)

Part 1 is Blockchair. Part 2 is mempool.space, added 2026-10-18 as the
second prevout-resolution source.

Everything here is what we measured on the free no-key tier on
2026-10-18 from this host, not what the docs claim. Costs are the
`context.request.cost` values returned by the API (authoritative);
our config estimates match so far.

# Blockchair (observed behavior, no-key tier)

## Documented vs observed

| Endpoint | Documented cost | Observed cost | Status |
|---|---|---|---|
| `/bitcoin/stats` | 1 | 1 | OK |
| `/bitcoin/raw/block/{h}` | 1 | 1 | OK |
| `/bitcoin/dashboards/block/{h}` | (1) | HTTP 430 | AVOID on no-key tier |
| `/bitcoin/outputs` | 10 | HTTP 430 (twice, see below) | AVOID on no-key tier |
| `/bitcoin/transactions` | 5 | not yet probed (blocked by outputs 430) | unresolved |
| `/bitcoin/raw/transaction/{txid}` | 1 | empty 200, 1 pt charged | NOT USABLE (soft-blocked) |

## The HTTP 430 problem

HTTP 430 is Blockchair's "Your IP address is temporary blacklisted due
to exceeding usage of API resources". Observed timeline (all 2026-10-18
UTC, all in the persistent `api_ledger`):

- 12:48:09 `/bitcoin/stats` 200
- 12:48:11 `/bitcoin/raw/block/971984` 200
- 12:48:11 `/bitcoin/dashboards/block/971984` **430** — third request,
  ~2 seconds after the first. The documented limits (1440/day, 30/min,
  5/s) were nowhere near exceeded; the dashboard endpoint on the no-key
  tier appears to trip a blacklist essentially immediately.
- 12:54 (manual curl, outside the client) `/bitcoin/raw/block/811800`
  **200** — so the blacklist had lifted ~6 minutes later, and raw block
  requests remained allowed.
- 13:42:49 `/bitcoin/outputs?block=971974&type=witness_v0_scripthash`
  **430** — first client request after a ~48 minute quiet period.
- 14:47:52 `/bitcoin/outputs?block=971984&is_spent=true&limit=10&type=witness_v0_scripthash`
  **430** — second single-probe recheck, after a ~65 minute quiet period.
  The preceding `/bitcoin/stats` check was served from the client's local
  disk cache (saved 12:48), so it made no network request and charged no
  points; the recheck therefore went straight to the outputs probe. The
  430 response again charged the full estimated cost (10 points) and
  again had no `Retry-After` header. No retry, no alternate endpoint,
  no transactions probe followed, per the protocol.

Two readings are consistent with this: (a) index/dashboard endpoints
(`/dashboards/*`, `/outputs`, `/transactions`) are gated on the no-key
tier and answer 430 rather than 402/403, while `/raw/*` and `/stats`
are allowed; or (b) the blacklist is sticky and re-trips easily. The
12:54 success after the 12:48 blacklist argues for (a), and the 14:47
outputs 430 (second recheck after a ~65 minute quiet period) makes (a)
the stronger reading: raw and stats requests succeed while every
index/dashboard request 430s, across three separate attempts spanning
two hours. Reading (b) cannot be fully excluded because the 14:47
recheck's stats step was served from cache and so did not exercise the
network immediately before the outputs probe. Resolution protocol: after
a >= 1 hour quiet period, send exactly one `/bitcoin/stats` (1 pt). If
200, send exactly one `/bitcoin/outputs` probe. Any 430 stops the
recheck. Never retry a 430 automatically, never rotate IPs, never use a
key purchased without authorization. Caveat learned 2026-10-18: the
client's disk cache short-circuits the stats step when a cached stats
payload exists, so a fresh recheck must either clear the cache entry or
accept that the stats step proves nothing about the current blacklist
state.

Other 430 properties observed: `Retry-After` header was absent
(`retry_after=None`), and the response carried a `context.request.cost`
of the estimated cost even though nothing useful was returned.

## Practical consequences for the study

- Raw block decoding is the primary acquisition path (as the research
  spec already prefers). A raw block for a ~2.6k-tx block was ~1.5 MB
  hex (~3 MB binary uncompressed), cost 1 point, and decodes fine with
  python-bitcoinlib locally.
- Block metadata (timestamp, height boundary) comes from the block
  header itself after local decode; the dashboard endpoint is not
  needed. Study-boundary pinning therefore uses raw blocks only.
- The indexed arm is unavailable on this tier, now confirmed by
  measurement: the Phase 1 acquisition benchmark attempted the single
  `/bitcoin/outputs` page for its window at 14:55:49 and received the
  fourth 430 (four index/dashboard attempts, all 430, across two
  hours). It was recorded in the ledger and not retried;
  `reports/benchmark.json` therefore carries `approach_b: null`, and
  the raw-blocks-only plan is the working plan, not the fallback. The
  paid-access memo (Phase 6) quantifies what index access would add.
- Measured raw-block acquisition cost (Phase 1 pilot, 21 consecutive
  blocks at heights 971989..972009, 1 pt each = 21 pts): 159,562
  inputs examined, 7,208 multisig-bearing inputs, i.e. ~343.2
  multisig-bearing inputs per point (~7,598 inputs and ~343
  multisig-bearing inputs per block; every block decoded cleanly).
- Extrapolated cost to cover the full study period (heights 812688
  through 972009, 159,322 blocks at 1 pt each): ~159,322 points,
  about 160 days of the 1000 pt/day budget. The input and
  multisig-bearing per-block rates are upper bounds: recent blocks
  carry more inputs than 2023-era blocks, though the point cost per
  block stays exactly 1.
- The `spending_witness` question (does the indexed-outputs response
  carry the full witness stack hex?) is still unanswered because no
  `/bitcoin/outputs` payload has ever been obtained on this tier. If
  index access is ever authorized (key or paid tier), that check is
  the first thing to run: compare one output's `spending_witness`
  against the witness stack of the spending transaction and compare
  input counts. Until then, raw-block decoding is the only script
  extraction path, and it is sufficient: the raw block contains full
  witness data for every transaction.
- The per-second/per-minute limiter (1 req/s, 20 req/min configured)
  is far below the documented limits, which did NOT prevent the 430s;
  the 430 trigger is endpoint-dependent, not just volume-dependent.

## The raw-transaction endpoint is soft-blocked (2026-10-18)

The Phase 3 validation subset probed `/bitcoin/raw/transaction/{txid}`
for the first time and it does not work on the no-key tier, but in a
different way from the index endpoints: it answers HTTP 200 with
`context.results = 0` and `data` as an empty LIST (the success shape is
a dict keyed by txid) while still charging the full 1-point estimated
cost. Observed on two confirmed txids: one mined months inside the
study period (block 955719, txid independently re-verified by
recomputing the double-SHA256 from the cached raw block) and one from
block 971251, fetched minutes after that block was scanned (the
documented success shape is a dict keyed by txid, never observed on
this tier). Ledger:
15:17:36 and 15:31:0x UTC, both 200, both 1 pt. So unlike the index
endpoints this one does not 430; it silently serves nothing. Client
handling: `msfp/verify.py` treats a non-dict `data` as "not served"
instead of crashing, and aborts the validation run after three
consecutive unserved spending transactions so the budget is not spent
on guaranteed-empty fetches. The validation subset is BLOCKED on this
tier until either (a) the spending/prevout transactions are extracted
from raw blocks already cached or fetched for their heights (1 pt per
block, same as today), or (b) paid access is authorized. Route (a) is
the natural redesign and needs no new endpoint class.

## Manual requests reconciliation

Two requests were made with curl before the client tooling existed
(one `/bitcoin/stats` at ~12:43, one `/bitcoin/raw/block/811800` at
12:54). Both are entered in `api_ledger` with their real costs so the
daily budget reflects them. All other requests went through the client
and are recorded automatically.

## Open questions

1. Are `/bitcoin/outputs` and `/bitcoin/transactions` usable at all on
   the no-key tier? Largely answered: `/bitcoin/outputs` is not usable
   (430 on 13:42:49 and again on 14:47:52, the second after a ~65
   minute quiet period; treated as AVOID on this tier).
   `/bitcoin/transactions` remains unprobed because the protocol stops
   all acquisition on any 430, and the evidence now says it will 430
   the same way; probing it would spend 5 points against the same
   blacklist.
2. Does the blacklist decay time depend on which endpoint tripped it?
   Still open, but the evidence now points at endpoint class rather
   than decay: raw block and stats requests succeed within minutes of
   a 430, while index endpoints 430 again after a full hour of quiet.
   The open gap is that the 14:47 recheck's stats step was cache-served,
   so we have not yet observed a network 200 on stats immediately
   before an index probe.
3. Does an API key change any of this? (Only answerable if a key is
   ever authorized; out of scope by default.)

# mempool.space API (observed behavior, keyless)

Measured 2026-10-18/19 from this host against `https://mempool.space/api`
(esplora-style REST; the service documents no API key, HTTP 429 rate
limiting, and possible bans for repeated abuse). Every request is
recorded in the `mempool_ledger` table and every response body is
cached permanently under `data/cache_mempool/` keyed by URL path, so
confirmed-transaction responses are never downloaded twice.

## Endpoints probed and field shapes

- `GET /tx/{txid}` — full transaction JSON. Per input: `txid`/`vout`
  (prevout pointer), `prevout` containing `scriptpubkey` (hex),
  `scriptpubkey_type`, `scriptpubkey_address`, and `value` in sats,
  plus `witness` as an array of hex items and
  `inner_witnessscript_asm` on segwit inputs. Per output: the same
  script fields plus `value`. Top level carries `fee`, `size`,
  `weight`, `version`, `locktime`, `status` (with `confirmed`,
  `block_height`, `block_hash`, `block_time`). There is NO raw
  transaction `hex` field on this endpoint; the tx is rebuilt locally
  from the JSON (`msfp/verify.py:_tx_from_mempool_json`) and the
  rebuilt txid is checked against the requested one.
- `GET /address/{address}/txs` — up to 50 confirmed chain txs per
  page, same per-tx shape as `/tx/` including full `prevout` objects
  on every input and the `status` block. Sufficient for spot checks;
  the study's prevout resolution uses `/tx/` per spending txid.

## Throttling behavior

No HTTP 429 has ever been observed from this host. All traffic so far
went through the client at 1 request/second and 30 requests/minute
(both enforced by `msfp/mempool.py`, defaults mirrored in
`config.toml.example`). The client's throttle handling is written but
unexercised: a 429 is backed off 5/15/45 seconds with every attempt
recorded in the ledger, and if it still answers 429 the run stops
cleanly (`MempoolThrottled`, exit code 2) instead of pushing through.
One 404 was observed and recorded (see the txid anomaly below); 404
is an unexpected status for the client, not a retry case, and the
response is not cached.

## Transport: Python HTTP stacks are tarpitted to this service

Python `requests` and raw stdlib sockets both take ~70 seconds or
worse per response to mempool.space from this host (sometimes minutes),
while `curl` answers the same URL in ~0.25 s. User-Agent and IPv4/IPv6
ordering changes had no effect, so the client shells out to `curl` per
request. The limiter, ledger, retry ladder, and cache are all
transport-independent, so this costs nothing in discipline.

## The corpus txid field holds wtxids for segwit transactions

The first `/tx/` probe returned 404 for a confirmed corpus txid. Root
cause is local, not the service: `msfp/decode.py` stores
`CTransaction.GetHash()`, which for segwit transactions is the
wtxid (hash including witness data), not the txid. 522 of 4339 txs in
a spot-checked block (971251) matched the service's txid list; the
witness-bearing ones did not. Corpus-internal joins stay consistent
because the same wrong value is used everywhere in the corpus, but any
external lookup needs the real txid. `msfp/verify.py:_real_txid`
resolves it from the already-cached raw block for the input's height
(`CTransaction.GetTxid()`); inputs whose block is not locally cached
cannot be resolved and are logged as failures rather than fetched,
which keeps the mempool client's request count bounded by the
validation plan. This is a decode-layer defect worth its own fix; the
resolution path only papers over it for blocks we already hold.

## Verification observations

mempool.space responses carry everything needed for full signature
verification, which Blockchair's no-key tier never provided (its
raw-transaction endpoint is soft-blocked; see above): witness stacks
and all prevout (amount + scriptPubKey) pairs per input. The
validation run over this source found and fixed a real defect in the
local BIP-341 script-path SigMsg (the TapLeaf digest was replaced by
the raw leaf script); key-path vectors had never exercised that branch.
