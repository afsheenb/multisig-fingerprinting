# Blockchair API notes (observed behavior, no-key tier)

Everything here is what we measured on the free no-key tier on
2026-10-18 from this host, not what the docs claim. Costs are the
`context.request.cost` values returned by the API (authoritative);
our config estimates match so far.

## Documented vs observed

| Endpoint | Documented cost | Observed cost | Status |
|---|---|---|---|
| `/bitcoin/stats` | 1 | 1 | OK |
| `/bitcoin/raw/block/{h}` | 1 | 1 | OK |
| `/bitcoin/dashboards/block/{h}` | (1) | HTTP 430 | AVOID on no-key tier |
| `/bitcoin/outputs` | 10 | HTTP 430 (see below) | unresolved |
| `/bitcoin/transactions` | 5 | not yet probed | unresolved |
| `/bitcoin/raw/transaction/{txid}` | 1 | not yet probed | unresolved |

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

Two readings are consistent with this: (a) index/dashboard endpoints
(`/dashboards/*`, `/outputs`, `/transactions`) are gated on the no-key
tier and answer 430 rather than 402/403, while `/raw/*` and `/stats`
are allowed; or (b) the blacklist is sticky and re-trips easily. The
12:54 success after the 12:48 blacklist argues for (a), but the 13:42
outputs 430 is ambiguous. Resolution protocol: after a >= 1 hour quiet
period, send exactly one `/bitcoin/stats` (1 pt). If 200, send exactly
one `/bitcoin/outputs` probe. Any 430 stops the recheck. Never retry a
430 automatically, never rotate IPs, never use a key purchased without
authorization.

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
- If index endpoints stay unavailable, Phase 1's indexed-outputs
  benchmark arm cannot run on the free tier; the benchmark then
  reports raw-blocks-only numbers and the paid-access memo (Phase 6)
  quantifies what index access would add.
- The per-second/per-minute limiter (1 req/s, 20 req/min configured)
  is far below the documented limits, which did NOT prevent the 430s;
  the 430 trigger is endpoint-dependent, not just volume-dependent.

## Manual requests reconciliation

Two requests were made with curl before the client tooling existed
(one `/bitcoin/stats` at ~12:43, one `/bitcoin/raw/block/811800` at
12:54). Both are entered in `api_ledger` with their real costs so the
daily budget reflects them. All other requests went through the client
and are recorded automatically.

## Open questions

1. Are `/bitcoin/outputs` and `/bitcoin/transactions` usable at all on
   the no-key tier (resolvable by the single-probe recheck protocol)?
2. Does the blacklist decay time depend on which endpoint tripped it?
3. Does an API key change any of this? (Only answerable if a key is
   ever authorized; out of scope by default.)
