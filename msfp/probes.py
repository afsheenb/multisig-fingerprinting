"""Phase 0 endpoint-validation probes.

A small number of permitted test requests; every raw response is saved
under data/probes/ and actual costs are recorded for docs/api_notes.md.
"""

import json
import os

from .ledger import QuotaExhausted, Throttled, IpBlocked


def _save_probe(config, name, payload):
    probes = os.path.join(config.data_dir, "probes")
    os.makedirs(probes, exist_ok=True)
    with open(os.path.join(probes, "%s.json" % name), "w") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)


def run_probes(config, conn, stages=None):
    """stages: optional subset of {'stats','raw_block','dashboard',
    'outputs','transactions'}; default = all. The dashboard probe is
    skipped once it has been observed to trip the IP blacklist."""
    from .client import Client
    client = Client(config, conn)
    stages = stages or ["stats", "raw_block", "dashboard", "outputs",
                        "transactions"]

    # 1. Stats: sanity + current best height (already done once interactively
    # before this tool existed; fetching again is 1 point).
    probe_height = None
    if "stats" in stages or "raw_block" in stages or "dashboard" in stages:
        payload, cost, _ = client.stats(fresh=True)
        _save_probe(config, "stats", payload)
        best = payload["data"]["best_block_height"]
        print("stats: ok, cost=%s, best height=%s" % (cost, best))
        probe_height = best - 10

        # 2. Raw block: verify raw_block hex decodes locally.
        if "raw_block" in stages:
            payload, cost, _ = client.raw_block(probe_height)
            _save_probe(config, "raw_block_%d" % probe_height, payload)
            data = payload["data"].get(str(probe_height), {})
            rb = data.get("raw_block", "")
            print("raw block %d: cost=%s, raw_block hex len=%d (~%d KiB), "
                  "keys=%s" % (probe_height, cost, len(rb), len(rb) // 2048,
                               sorted(data.keys())))

        # 3. Dashboard block: metadata + timestamp. Trips the IP blacklist
        # on the no-key tier; retained only for explicit re-checks.
        if "dashboard" in stages:
            payload, cost, _ = client.dashboard_block([probe_height])
            _save_probe(config, "dash_block_%d" % probe_height, payload)
            print("dashboard block: cost=%s, keys=%s"
                  % (cost, sorted(payload["data"].keys())))

    if probe_height is None:
        # Default the probe window to the known-good cached block height.
        probe_height = 971974

    return _outputs_transactions(config, client, probe_height)


def _outputs_transactions(config, client, probe_height):
    # 4. Indexed outputs: what is filterable, and does spending_witness carry
    # the full stack? Query a tiny window: 1 spent P2WSH output at the probe
    # height's block. p=... filter syntax per docs; verify actual behavior.
    payload, cost, _ = client.indexed_outputs(
        {"block": probe_height, "type": "witness_v0_scripthash", "limit": 10,
         "is_spent": "true"}
    )
    _save_probe(config, "outputs_probe", payload)
    outs = payload["data"] or []
    print("indexed outputs: cost=%s, n=%d, context keys=%s"
          % (cost, len(outs), sorted(payload.get("context", {}).keys())))
    if outs:
        first = outs[0]
        print("  output fields: %s" % sorted(first.keys()))
        witness = first.get("spending_witness")
        print("  spending_witness sample: %s"
              % (json.dumps(witness)[:300] if witness else None))

    # 5. Indexed transactions: filter behavior.
    payload, cost, _ = client.indexed_transactions(
        {"block": probe_height, "limit": 5}
    )
    _save_probe(config, "transactions_probe", payload)
    print("indexed transactions: cost=%s, n=%d"
          % (cost, len(payload["data"] or [])))

    from .ledger import utc_day
    print("points used today: %s" % client.limiter.points_used_today())
