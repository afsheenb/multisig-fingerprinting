"""Reports: preliminary findings + cost report, honoring the section-24
interpretation rules (shared template != shared owner; raw counts for
sampled corpora unless a probability estimate is justified)."""

import json
import os
from datetime import datetime, timezone

from . import db


def _q1(conn, sql, args=()):
    return conn.execute(sql, args).fetchone()


def run_report(config, conn):
    os.makedirs("reports", exist_ok=True)

    blocks = _q1(conn, "SELECT COUNT(*) c, MIN(height) mn, MAX(height) mx "
                       "FROM blocks")
    txs = _q1(conn, "SELECT COUNT(*) c FROM txs")
    inputs = _q1(conn, "SELECT COUNT(*) c FROM inputs")
    forms = conn.execute(
        "SELECT input_form, COUNT(*) c FROM inputs GROUP BY input_form "
        "ORDER BY c DESC").fetchall()
    scripts = _q1(conn, "SELECT COUNT(*) c FROM revealed_scripts")
    obs = _q1(conn, "SELECT COUNT(*) c FROM script_observations")
    keys = _q1(conn, "SELECT COUNT(DISTINCT pubkey_hex) c FROM script_keys")
    reused = _q1(conn,
                 "SELECT COUNT(*) c FROM (SELECT pubkey_hex FROM script_keys "
                 "GROUP BY pubkey_hex HAVING COUNT(DISTINCT script_sha256) > 1)")
    templates = conn.execute(
        "SELECT template_l3, COUNT(*) c FROM revealed_scripts "
        "WHERE script_class IN ('multisig','csa_multisig','taproot_multisig') "
        "GROUP BY template_l3 ORDER BY c DESC LIMIT 15").fetchall()
    families = conn.execute(
        "SELECT family_l4, COUNT(*) c FROM revealed_scripts GROUP BY "
        "family_l4 ORDER BY c DESC").fetchall()
    sorted_counts = conn.execute(
        "SELECT keys_sorted, COUNT(*) c FROM revealed_scripts "
        "WHERE keys_sorted IS NOT NULL GROUP BY keys_sorted").fetchall()
    sources = conn.execute(
        "SELECT source, COUNT(*) c FROM revealed_scripts GROUP BY source"
    ).fetchall()

    ledger = conn.execute(
        "SELECT COUNT(*) n_req, SUM(COALESCE(actual_cost, estimated_cost)) pts "
        "FROM api_ledger").fetchone()
    by_endpoint = conn.execute(
        "SELECT endpoint, COUNT(*) n, SUM(COALESCE(actual_cost, "
        "estimated_cost)) pts FROM api_ledger GROUP BY endpoint").fetchall()
    bytes_down = _q1(conn, "SELECT SUM(raw_bytes) b FROM blocks")

    period_start = db.get_meta(conn, "study_start_height")
    period_end = db.get_meta(conn, "study_end_height")

    # Example transactions: one per interesting construction.
    examples = {}
    for form in ("p2sh_redeem", "p2wsh", "p2sh_p2wsh",
                 "taproot_scriptpath", "taproot_keypath"):
        row = conn.execute(
            "SELECT txid, input_index, block_height FROM inputs "
            "WHERE input_form=? ORDER BY block_height DESC LIMIT 1",
            (form,)).fetchone()
        if row:
            examples[form] = dict(row)

    lines = []
    add = lines.append
    add("# Preliminary findings (pilot corpus)")
    add("")
    add("Generated %s UTC. Sampled corpus: statistics below are RAW COUNTS "
        "over the sampled blocks, not population estimates."
        % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"))
    add("")
    add("## Coverage")
    add("- Blocks scanned: %d (heights %s..%s; study period %s..%s)"
        % (blocks["c"], blocks["mn"], blocks["mx"], period_start, period_end))
    add("- Transactions examined: %d" % txs["c"])
    add("- Inputs examined: %d" % inputs["c"])
    add("- Revealed scripts (deduplicated): %d across %d observations"
        % (scripts["c"], obs["c"]))
    add("- Distinct public keys: %d; keys in 2+ distinct scripts: %s"
        % (keys["c"], reused["c"]))
    add("")
    add("## Input forms")
    for r in forms:
        add("- %s: %d" % (r["input_form"], r["c"]))
    add("")
    add("## Script sources")
    for r in sources:
        add("- %s: %d" % (r["source"], r["c"]))
    add("")
    add("## Wallet families (L4, structural buckets only)")
    for r in families:
        add("- %s: %d" % (r["family_l4"], r["c"]))
    add("")
    add("## Most common parameter-normalized templates (L3)")
    for r in templates:
        add("- %dx `%s`" % (r["c"], (r["template_l3"] or "")[:120]))
    add("")
    add("## BIP67 sorting")
    for r in sorted_counts:
        add("- %s: %d" % ("sorted" if r["keys_sorted"] else "unsorted",
                          r["c"]))
    add("")
    add("## Example transactions")
    for form, ex in examples.items():
        add("- %s: %s input %s (block %s)"
            % (form, ex["txid"], ex["input_index"], ex["block_height"]))
    add("")
    add("## Interpretation rules applied")
    add("- Shared template is NOT shared ownership; shared key is NOT "
        "confirmed identity.")
    add("- Taproot key-path spends are recorded as an opaque negative-control "
        "population; MuSig2 adoption is NOT measurable from them.")
    add("- A revealed script was knowable only from its spend; deposit-side "
        "visibility is not claimed without prevout resolution.")
    add("- No provider attribution appears here; attribution requires "
        "independently verified evidence (see attribute.py grades).")
    add("")
    with open("reports/preliminary_findings.md", "w") as fh:
        fh.write("\n".join(lines))

    # Cost report.
    clines = []
    cadd = clines.append
    cadd("# Blockchair cost report")
    cadd("")
    cadd("- HTTP requests: %d" % ledger["n_req"])
    cadd("- Request points consumed: %s" % ledger["pts"])
    cadd("- Raw blocks retrieved: %d (~%.1f MiB raw)"
         % (blocks["c"], (bytes_down["b"] or 0) / 1048576))
    for r in by_endpoint:
        cadd("- %s: %d requests, %s points" % (r["endpoint"], r["n"], r["pts"]))
    rate = (scripts["c"] / ledger["pts"]) if ledger["pts"] else 0
    cadd("- Revealed scripts per request point: %.3f" % rate)
    cadd("- Useful (multisig-class) scripts per point: see benchmark.json")
    with open("reports/cost_report.md", "w") as fh:
        fh.write("\n".join(clines))

    print("\n".join(lines))
    print("\nwrote reports/preliminary_findings.md, reports/cost_report.md")
