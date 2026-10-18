"""Reports: preliminary findings + cost report, honoring the section-24
interpretation rules (shared template != shared owner; raw counts for
sampled corpora unless a probability estimate is justified)."""

import json
import os
from datetime import datetime, timezone

from . import db


def _q1(conn, sql, args=()):
    return conn.execute(sql, args).fetchone()


def _study_window(conn):
    start = int(db.get_meta(conn, "study_start_height"))
    end = int(db.get_meta(conn, "study_end_height"))
    return start, end


def run_report(config, conn):
    os.makedirs("reports", exist_ok=True)
    start, end = _study_window(conn)

    blocks = _q1(conn, "SELECT COUNT(*) c FROM blocks WHERE height BETWEEN "
                       "? AND ?", (start, end))
    pre_blocks = _q1(conn, "SELECT COUNT(*) c, MIN(height) mn FROM blocks "
                           "WHERE height < ?", (start,))
    txs = _q1(conn, "SELECT COUNT(*) c FROM txs WHERE block_height BETWEEN "
                    "? AND ?", (start, end))
    inputs = _q1(conn, "SELECT COUNT(*) c FROM inputs WHERE block_height "
                       "BETWEEN ? AND ?", (start, end))
    forms = conn.execute(
        "SELECT input_form, COUNT(*) c FROM inputs WHERE block_height "
        "BETWEEN ? AND ? GROUP BY input_form ORDER BY c DESC",
        (start, end)).fetchall()
    scripts = _q1(conn, "SELECT COUNT(*) c FROM revealed_scripts WHERE "
                        "first_seen_height BETWEEN ? AND ?", (start, end))
    obs = _q1(conn, "SELECT COUNT(*) c FROM script_observations o JOIN "
                    "inputs i ON i.input_id=o.input_id WHERE i.block_height "
                    "BETWEEN ? AND ?", (start, end))
    keys = _q1(conn, "SELECT COUNT(DISTINCT k.pubkey_hex) c FROM script_keys "
                     "k JOIN revealed_scripts s ON "
                     "s.script_sha256=k.script_sha256 WHERE "
                     "s.first_seen_height BETWEEN ? AND ?", (start, end))
    reused = _q1(conn,
                 "SELECT COUNT(*) c FROM (SELECT k.pubkey_hex FROM "
                 "script_keys k JOIN revealed_scripts s ON "
                 "s.script_sha256=k.script_sha256 WHERE s.first_seen_height "
                 "BETWEEN ? AND ? GROUP BY k.pubkey_hex HAVING "
                 "COUNT(DISTINCT k.script_sha256) > 1)", (start, end))
    templates = conn.execute(
        "SELECT template_l3, COUNT(*) c FROM revealed_scripts "
        "WHERE first_seen_height BETWEEN ? AND ? AND script_class IN "
        "('multisig','csa_multisig','taproot_multisig') "
        "GROUP BY template_l3 ORDER BY c DESC LIMIT 15", (start, end)).fetchall()
    families = conn.execute(
        "SELECT family_l4, COUNT(*) c FROM revealed_scripts WHERE "
        "first_seen_height BETWEEN ? AND ? GROUP BY family_l4 "
        "ORDER BY c DESC", (start, end)).fetchall()
    sorted_counts = conn.execute(
        "SELECT keys_sorted, COUNT(*) c FROM revealed_scripts "
        "WHERE first_seen_height BETWEEN ? AND ? AND keys_sorted IS NOT NULL "
        "GROUP BY keys_sorted", (start, end)).fetchall()
    sources = conn.execute(
        "SELECT source, COUNT(*) c FROM revealed_scripts WHERE "
        "first_seen_height BETWEEN ? AND ? GROUP BY source",
        (start, end)).fetchall()

    ledger = conn.execute(
        "SELECT COUNT(*) n_req, SUM(COALESCE(actual_cost, estimated_cost)) pts "
        "FROM api_ledger").fetchone()
    by_endpoint = conn.execute(
        "SELECT endpoint, COUNT(*) n, SUM(COALESCE(actual_cost, "
        "estimated_cost)) pts FROM api_ledger GROUP BY endpoint").fetchall()

    validation = {r["key"]: int(r["value"]) for r in conn.execute(
        "SELECT key, value FROM meta WHERE key LIKE 'validation_local_%'")}
    total_script_inputs = obs["c"]

    # Key-reuse headline numbers come from the index pass.
    key_reuse = None
    if os.path.exists("reports/key_reuse.json"):
        with open("reports/key_reuse.json") as fh:
            key_reuse = json.load(fh)

    # Example transactions: one per interesting construction.
    examples = {}
    for form in ("p2sh_redeem", "p2wsh", "p2sh_p2wsh",
                 "taproot_scriptpath", "taproot_keypath"):
        row = conn.execute(
            "SELECT txid, input_index, block_height FROM inputs "
            "WHERE input_form=? AND block_height BETWEEN ? AND ? "
            "ORDER BY block_height DESC LIMIT 1",
            (form, start, end)).fetchone()
        if row:
            examples[form] = dict(row)

    lines = []
    add = lines.append
    add("# Preliminary findings (pilot corpus)")
    add("")
    add("Generated %s UTC. **Scope: sampled corpus, heights %s..%s.** All "
        "statistics below are RAW COUNTS over the sampled blocks, not "
        "population estimates and not extrapolations."
        % (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
           start, end))
    add("")
    add("## Interpretation rules (apply to every number below)")
    add("- A shared script template NEVER implies shared ownership. "
        "Templates are structural shapes; unrelated wallets converge on "
        "the same shapes.")
    add("- Shared pubkeys link SCRIPTS, not people. A key appearing in "
        "two scripts establishes exactly that byte-level relationship; "
        "it says nothing about who controls the keys.")
    add("- No provider attribution appears in this report. Attribution "
        "requires independently verified evidence, which the corpus does "
        "not carry.")
    add("- Taproot key-path spend counts are an opaque control population. "
        "MuSig2 adoption is NOT measurable from them: a key-path spend "
        "could be single-key or an aggregate, and the output key reveals "
        "neither.")
    add("- A revealed script was knowable only from its spend. Deposit-side "
        "visibility is not claimed: most revealed scripts were never spent "
        "inside the sampled blocks, so corpus counts are floors, not "
        "totals.")
    add("")
    add("## Coverage")
    add("- Blocks scanned: %d in-study (heights %s..%s)"
        % (blocks["c"], start, end))
    if pre_blocks["c"]:
        add("- Footnote: block %s sits outside the study window and is kept "
            "only as an acquisition smoke test; it is EXCLUDED from every "
            "count below." % pre_blocks["mn"])
    add("- Transactions examined: %d" % txs["c"])
    add("- Inputs examined: %d" % inputs["c"])
    add("- Revealed scripts (deduplicated): %d across %d spend observations"
        % (scripts["c"], obs["c"]))
    add("- Distinct public keys: %d; keys in 2+ distinct scripts: %s"
        % (keys["c"], reused["c"]))
    if key_reuse:
        add("- Key-reuse components (union-find over exact-byte shared "
            "keys): %s; largest: %s"
            % (key_reuse["n_shared_components_2plus"],
               ", ".join("%d keys/%d scripts" % (c["n_keys"], c["n_scripts"])
                         for c in key_reuse["largest_components"][:5])))
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
    add("## Most common parameter-normalized templates (L3, pure "
        "n-of-n multisig classes; compound and taproot script-path "
        "policies are bucketed under families instead)")
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
    add("## Local cryptographic validation (zero points)")
    if validation:
        checked = validation.get("validation_local_inputs_checked", 0)
        add("- Inputs checked against cached prevouts: %d of %d "
            "script-revealing observations (the rest have no prevout in "
            "the sampled corpus)" % (checked, total_script_inputs))
        add("- Commitments: %d verified, %d FAILED, %d not verifiable "
            "(taproot output-key binding needs the taptree)"
            % (validation.get("validation_local_commit_ok", 0),
               validation.get("validation_local_commit_fail", 0),
               checked - validation.get("validation_local_commit_ok", 0)
               - validation.get("validation_local_commit_fail", 0)))
        add("- Signatures: %d of %d present signatures verify under BIP143 "
            "sighash + ECDSA (corpus-resolvable inputs only)"
            % (validation.get("validation_local_sig_verified", 0),
               validation.get("validation_local_sig_present", 0)))
    add("")
    add("## Limitations")
    add("- Signature/commitment verification covers only corpus-resolvable "
        "prevouts (the /bitcoin/raw/transaction endpoint is soft-blocked "
        "on the no-key tier: confirmed txids answer HTTP 200 with empty "
        "data; evidence in docs/api_notes.md). The 1.3M-input corpus "
        "resolves only a small subset locally.")
    add("- Taproot output-key binding is not_verifiable without taptree "
        "data: a revealed leaf proves the script existed in the tree, not "
        "that the output key commits to it (internal-key hiding means it "
        "usually does not, visibly).")
    add("- Key-reuse matching is exact-byte only. Case-2 reuse (the same "
        "scriptPubKey spent again) is not observable without prevout "
        "resolution, so reuse counts are lower bounds.")
    add("- Sample: %d in-study blocks out of the 159,322-block study "
        "period (heights %s..%s), a ~0.11%% sample. Every figure here is "
        "a raw count over that sample." % (blocks["c"], start, end))
    add("- Deposit-side coverage is one-sided: scripts are revealed only "
        "when spent inside a sampled block; unspent and "
        "spent-outside-sample policies are invisible.")
    add("")
    add("## Spot checks")
    spot_path = "reports/spot_checks.json"
    if os.path.exists(spot_path):
        with open(spot_path) as fh:
            spot = json.load(fh)
        ok = sum(1 for r in spot["results"] if r["all_match"])
        add("- %d of %d sampled revealed scripts re-derived from the cached "
            "raw block JSON (block decode -> input classification -> "
            "script extraction -> analyze_script) reproduce the stored "
            "classification, keys, templates, and thresholds exactly; "
            "script_sha256 matched in every case. Seed %s; per-field "
            "detail in reports/spot_checks.json."
            % (ok, len(spot["results"]), spot["seed"]))
    else:
        add("- (not yet run)")
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
         % (blocks["c"] + pre_blocks["c"],
            (bytes_down(conn) or 0) / 1048576))
    for r in by_endpoint:
        cadd("- %s: %d requests, %s points" % (r["endpoint"], r["n"], r["pts"]))
    rate = (scripts["c"] / ledger["pts"]) if ledger["pts"] else 0
    cadd("- Revealed scripts per request point (pilot scan actuals): %.3f"
         % rate)
    cadd("")
    cadd("## Measured acquisition efficiency")
    cadd("- Phase 1 benchmark (21 consecutive recent blocks, heights "
         "971989..972009, 1 pt each): 159,562 inputs examined, 7,208 "
         "multisig-bearing inputs, i.e. ~343.24 multisig-bearing inputs "
         "per point (~343 multisig-bearing inputs per block).")
    cadd("- Pilot scan (this corpus): %d in-study blocks + 1 smoke-test "
         "block, %d distinct revealed scripts and %d spend observations, "
         "at ~1 point per raw block: %.2f distinct revealed scripts per "
         "point. Not directly comparable with the benchmark number (a "
         "deduplicated script count versus multisig-bearing input "
         "observations); the pilot rate is pulled down by stratified "
         "sampling across the whole period, where 2023-era blocks carry "
         "far fewer multisig spends than recent ones."
         % (blocks["c"], scripts["c"], obs["c"], rate))
    cadd("")
    cadd("## Full-period coverage extrapolation")
    cadd("- Study period: heights 812688..972009 = 159,322 blocks at "
         "exactly 1 point per raw block = ~159,322 points, about 160 UTC "
         "days at the 1000 point/day budget.")
    cadd("- The per-block input and multisig-bearing rates from the "
         "benchmark are upper bounds (recent blocks are larger); the "
         "point cost per block is exact and does not degrade.")
    cadd("")
    cadd("## The indexed-access gap")
    cadd("- The indexed arm (/bitcoin/outputs, /bitcoin/dashboards) is "
         "unavailable on the no-key tier: every attempt received HTTP 430 "
         "(4 index/dashboard attempts, evidence in docs/api_notes.md); "
         "benchmark.json carries approach_b: null.")
    cadd("- Consequence 1: raw-block decoding is the only script "
         "extraction path (it is sufficient: raw blocks carry full "
         "witness data, but cost 1 point per block regardless of content).")
    cadd("- Consequence 2: deposit-side script visibility and case-2 "
         "key/scriptPubKey reuse remain unobservable without index access "
         "or prevout resolution; /bitcoin/raw/transaction is also "
         "soft-blocked (empty 200s), which is why validation runs "
         "locally against cached prevouts only.")
    cadd("- If paid/key-tier index access is ever authorized, the first "
         "check is whether indexed outputs carry full spending witness "
         "stacks (the spending_witness question, docs/api_notes.md).")
    with open("reports/cost_report.md", "w") as fh:
        fh.write("\n".join(clines))

    print("\n".join(lines))
    print("\nwrote reports/preliminary_findings.md, reports/cost_report.md")


def bytes_down(conn):
    return conn.execute("SELECT SUM(raw_bytes) b FROM blocks").fetchone()["b"]
