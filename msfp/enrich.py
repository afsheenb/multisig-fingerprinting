"""Behavioral enrichment pass over the attribution buckets.

Layers spend-behavior evidence on the same-shape buckets: which key
positions actually sign, how deposits arrive, how spending transactions
are batched, and which keys cross bucket shapes. Every input to this
pass is already in the corpus database or the permanent mempool cache;
fresh network requests happen only where a bucket's sample is empty,
always through msfp.mempool (cache-first, ledgered, politely paced).

Reading rules, restated so the numbers are not over-read:

- A script template NEVER implies shared ownership; these buckets are
  same-SHAPE populations, and operator-looking clusters inside them are
  hypotheses, not attributions.
- A key appearing in two bucket shapes links SCRIPTS, not owners.
- Signature-level (verified) crossovers are stronger evidence than
  template-level crossovers and are reported separately.
- The false-positive rate of every behavioral signal is UNKNOWN: no
  labeled held-out corpus exists. Raw counts only, never percentages of
  unsampled populations.
"""

import collections
import hashlib
import json
import os
import random
import re

from .ledger import utc_now_iso

# Blockstream Green's optimized CSV recovery layout, the corpus's only
# C-grade family (strong implementation match, 430 scripts).
GREEN_CSV_TEMPLATE = ("<P> OP_CHECKSIGVERIFY <P> OP_CHECKSIG OP_IFDUP "
                      "OP_NOTIF <T> OP_CHECKSEQUENCEVERIFY OP_ENDIF")

NUM_RE = re.compile(r"NUM:(\d+)")

SEQUENCE_FINAL = 0xFFFFFFFF
SEQUENCE_RBF_CEILING = 0xFFFFFFFD  # sequences below this flag replaceability

GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3}

# Default sampling sizes. Kept small: politeness is the mempool budget.
VERIFY_SAMPLE_TXS = 10          # per bucket with an empty validation sample
DEPOSIT_SAMPLE_TXS = 20         # per deposit-profiled bucket
DEPOSIT_SAMPLE_ADDRESSES = 20   # per deposit-profiled bucket
DEFAULT_REQUEST_BUDGET = 300    # hard cap on fresh network requests per run


# -- bucket construction -------------------------------------------------------

def bucket_shape(source, template_l3, threshold, n_keys, keys_sorted,
                 timelocks):
    """Stable identity of a same-shape bucket."""
    tl = tuple(sorted(timelocks))
    return (source, template_l3 or "", threshold, n_keys, keys_sorted, tl)


def bucket_id(shape):
    source, template_l3, threshold, n_keys, keys_sorted, tl = shape
    parts = [source]
    if threshold is not None and n_keys:
        parts.append("%dof%d" % (threshold, n_keys))
    if keys_sorted is not None:
        parts.append("sorted" if keys_sorted else "unsorted")
    if tl:
        parts.append("csv" + ",".join(str(v) for v in tl))
    # Disambiguate same-shape different-template buckets by a short
    # template digest.
    digest = hashlib.sha256(template_l3.encode("utf-8")).hexdigest()[:8]
    parts.append(digest)
    return "|".join(parts)


def load_script_grades(matches_path):
    """Best non-control grade per script from the attribution output.

    Returns (grades, provider_sets): grades maps script_sha256 to its
    best grade letter over non-control providers; provider_sets maps it
    to the sorted provider ids at that grade.
    """
    with open(matches_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "registry", "providers.json"),
            "r", encoding="utf-8") as fh:
        registry = json.load(fh)
    controls = {p["id"] for p in registry["providers"] if p.get("control_group")}
    best = {}
    for row in data["matches"]:
        pid = row["provider_id"]
        if pid in controls:
            continue
        sha = row["script_sha256"]
        rank = GRADE_RANK[row["grade"]]
        cur = best.get(sha)
        if cur is None or rank < cur[0]:
            best[sha] = (rank, row["grade"], [pid])
        elif rank == cur[0]:
            cur[2].append(pid)
    grades = {sha: g for sha, (_r, g, _p) in best.items()}
    providers = {sha: sorted(p) for sha, (_r, _g, p) in best.items()}
    return grades, providers


def select_buckets(conn, matches_path, top_d=10, min_size=5):
    """The buckets this pass profiles.

    Selection: the Green C-grade CSV family (all scripts carrying the
    optimized CSV template, any grade), plus the top `top_d` buckets by
    script count among scripts whose best non-control grade is D.
    """
    grades, providers = load_script_grades(matches_path)
    green = {"members": set(), "timelocks": collections.Counter()}
    d_buckets = collections.defaultdict(set)
    for sha, grade in grades.items():
        row = conn.execute(
            "SELECT template_l3, template_l2, threshold, n_keys, keys_sorted,"
            " source FROM revealed_scripts WHERE script_sha256 = ?",
            (sha,)).fetchone()
        if row is None:
            continue
        timelocks = sorted(set(int(v) for v in
                               NUM_RE.findall(row["template_l2"] or "")))
        if row["template_l3"] == GREEN_CSV_TEMPLATE:
            green["members"].add(sha)
            for v in timelocks:
                green["timelocks"][v] += 1
        if grade == "D":
            shape = bucket_shape(row["source"], row["template_l3"],
                                 row["threshold"], row["n_keys"],
                                 row["keys_sorted"], timelocks)
            d_buckets[shape].add(sha)

    out = []
    if green["members"]:
        out.append({
            "bucket_id": "green_csv_family",
            "shape": ("p2wsh_witness", GREEN_CSV_TEMPLATE, None, 2, None, ()),
            "members": green["members"],
            "origin": "green C-grade family (grade C scripts plus the same "
                      "template at D)",
            "providers": sorted({p for s in green["members"]
                                 for p in providers.get(s, [])}),
            "timelock_values": dict(green["timelocks"]),
        })
    ranked = sorted(d_buckets.items(), key=lambda kv: (-len(kv[1]), kv[0][0]))
    for shape, members in ranked[:top_d]:
        if len(members) < min_size:
            break
        provs = sorted({p for s in members for p in providers.get(s, [])})
        out.append({
            "bucket_id": bucket_id(shape),
            "shape": shape,
            "members": members,
            "origin": "D-grade bucket",
            "providers": provs,
        })
    return out


# -- witness classification (pure) ---------------------------------------------

def classify_signature_item(item):
    """Classify one witness item as a signature, or None.

    Returns ("ecdsa", hashtype_byte) for DER-encoded signatures (the
    trailing byte is the sighash type) or ("schnorr", hashtype) for
    64/65-byte BIP340 items (65 = explicit sighash type).
    """
    n = len(item)
    if 70 <= n <= 74 and item[0] == 0x30:
        return ("ecdsa", item[-1])
    if n == 64:
        return ("schnorr", 0x00)
    if n == 65 and item[64] <= 0x03:
        return ("schnorr", item[64])
    return None


def classify_witness(items):
    """(ecdsa_items, schnorr_items) counts over one witness stack."""
    ecdsa = schnorr = 0
    for raw in items:
        kind = classify_signature_item(bytes.fromhex(raw))
        if kind is None:
            continue
        if kind[0] == "ecdsa":
            ecdsa += 1
        else:
            schnorr += 1
    return ecdsa, schnorr


def input_bin(n_inputs):
    """Size bin for coin-selection shape."""
    if n_inputs == 1:
        return "1"
    if n_inputs <= 10:
        return "2-10"
    if n_inputs <= 50:
        return "11-50"
    return ">50"


def output_bin(n_outputs):
    """Size bin for payout shape."""
    if n_outputs == 1:
        return "1"
    if n_outputs == 2:
        return "2"
    if n_outputs <= 5:
        return "3-5"
    return ">5"


def sequence_class(sequence):
    """final | rbf_flagged | disabled | timelock (CSV/CLTV-encoded).

    disabled covers 0xfffffffd and 0xfffffffe: the sequence encoding is
    switched off and no replaceability is signaled.
    """
    if sequence == SEQUENCE_FINAL:
        return "final"
    if sequence >= SEQUENCE_RBF_CEILING:
        return "disabled"
    if sequence >= 0x80000000:
        return "rbf_flagged"
    return "timelock"


# -- per-bucket profile from the database --------------------------------------

def _temp_script_table(conn, shas):
    conn.execute("DROP TABLE IF EXISTS temp.bucket_scripts")
    conn.execute("CREATE TEMP TABLE bucket_scripts(script_sha256 TEXT "
                 "PRIMARY KEY)")
    conn.executemany("INSERT OR IGNORE INTO temp.bucket_scripts VALUES(?)",
                     ((s,) for s in shas))


def profile_bucket_db(conn, bucket):
    """Everything derivable without a network request.

    Position identity is only provable from verified spends; signature
    counts and sighash bytes come from every stored observation.
    """
    _temp_script_table(conn, bucket["members"])
    agg = {
        "n_scripts": len(bucket["members"]),
        "n_observations": 0,
        "n_spend_txs": 0,
        "signatures_per_spend": collections.Counter(),
        "sighash_types": collections.Counter(),
        "ecdsa_inputs": 0,
        "schnorr_inputs": 0,
        "ecdsa_hashtype_bytes": collections.Counter(),
        "executed_branch": collections.Counter(),
        "tx_n_outputs": collections.Counter(),
        "tx_n_inputs": collections.Counter(),
        "tx_version": collections.Counter(),
        "tx_locktime": collections.Counter(),
        "tx_sequence_class": collections.Counter(),
        "tx_sequence_values": collections.Counter(),
        "input_forms": collections.Counter(),
        "validation_inputs": 0,
        "verified_key_positions": collections.Counter(),
        "verified_position_combinations": collections.Counter(),
        "verified_via": collections.Counter(),
        "verified_spend_txs": set(),
    }
    spend_txs = set()
    tx_props = {}
    tx_seq = collections.defaultdict(set)
    cur = conn.execute(
        "SELECT o.input_id, o.n_signatures, o.sighash_types, o.executed_branch,"
        " i.txid, i.sequence, i.witness_json, i.input_form,"
        " t.n_outputs, t.n_inputs, t.version, t.locktime"
        " FROM script_observations o"
        " JOIN inputs i ON i.input_id = o.input_id"
        " JOIN txs t ON t.txid = i.txid"
        " WHERE o.script_sha256 IN (SELECT script_sha256"
        " FROM temp.bucket_scripts)")
    for r in cur:
        agg["n_observations"] += 1
        spend_txs.add(r["txid"])
        tx_props[r["txid"]] = (r["n_outputs"], r["n_inputs"], r["version"],
                               r["locktime"])
        tx_seq[r["txid"]].add(sequence_class(r["sequence"]))
        agg["signatures_per_spend"][r["n_signatures"]] += 1
        if r["sighash_types"]:
            for v in json.loads(r["sighash_types"]):
                agg["sighash_types"][str(v)] += 1
        if r["executed_branch"] is not None:
            agg["executed_branch"][str(r["executed_branch"])] += 1
        witness = json.loads(r["witness_json"] or "[]")
        ecdsa, schnorr = classify_witness(witness)
        if ecdsa:
            agg["ecdsa_inputs"] += 1
        if schnorr:
            agg["schnorr_inputs"] += 1
        for raw in witness:
            kind = classify_signature_item(bytes.fromhex(raw))
            if kind and kind[0] == "ecdsa":
                agg["ecdsa_hashtype_bytes"]["0x%02x" % kind[1]] += 1
        agg["input_forms"][r["input_form"]] += 1
        agg["tx_n_outputs"][r["n_outputs"]] += 1
        agg["tx_n_inputs"][r["n_inputs"]] += 1
        agg["tx_version"][r["version"]] += 1
        agg["tx_locktime"][r["locktime"]] += 1
        agg["tx_sequence_class"][sequence_class(r["sequence"])] += 1
        agg["tx_sequence_values"][r["sequence"]] += 1
    agg["n_spend_txs"] = len(spend_txs)

    # Transaction-level operator clusters. Each distinct spending tx
    # counts once regardless of how many bucket inputs it carries.
    agg["tx_clusters"] = collections.Counter()
    agg["tx_n_inputs_ge_50"] = 0
    for txid, (n_out, n_in, version, locktime) in tx_props.items():
        classes = tx_seq[txid]
        seq = ("all_final" if classes == {"final"} else
               "any_rbf" if "rbf_flagged" in classes or
               "timelock" in classes else "disabled")
        agg["tx_clusters"][(version, locktime == 0, seq, input_bin(n_in),
                            output_bin(n_out))] += 1
        if n_in >= 50:
            agg["tx_n_inputs_ge_50"] += 1

    # Verified positions: stored validation results for this bucket.
    cur = conn.execute(
        "SELECT v.verified_key_positions_json, v.verified_via, v.input_id,"
        " i.txid"
        " FROM validation_results v"
        " JOIN inputs i ON i.input_id = v.input_id"
        " JOIN script_observations o ON o.input_id = v.input_id"
        " WHERE o.script_sha256 IN (SELECT script_sha256"
        " FROM temp.bucket_scripts)")
    for r in cur:
        agg["validation_inputs"] += 1
        agg["verified_via"][r["verified_via"]] += 1
        agg["verified_spend_txs"].add(r["txid"])
        positions = sorted(json.loads(
            r["verified_key_positions_json"] or "[]"))
        for pos in positions:
            agg["verified_key_positions"][int(pos)] += 1
        agg["verified_position_combinations"][tuple(positions)] += 1

    out = dict(agg)
    out["verified_spend_txs"] = set(agg["verified_spend_txs"])
    return out


def compact_profile(profile):
    """JSON-safe profile with counters cut to the informative head."""
    def top(counter, n=6):
        return sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))[:n]

    return {
        "n_scripts": profile["n_scripts"],
        "n_observations": profile["n_observations"],
        "n_spend_txs": profile["n_spend_txs"],
        "signatures_per_spend": dict(sorted(
            profile["signatures_per_spend"].items())),
        "sighash_types_top": top(profile["sighash_types"]),
        "ecdsa_inputs": profile["ecdsa_inputs"],
        "schnorr_inputs": profile["schnorr_inputs"],
        "ecdsa_hashtype_bytes_top": top(profile["ecdsa_hashtype_bytes"]),
        "executed_branch_top": top(profile["executed_branch"]),
        "input_forms": dict(profile["input_forms"]),
        "tx_n_outputs_top": top(profile["tx_n_outputs"]),
        "tx_n_inputs_top": top(profile["tx_n_inputs"]),
        "tx_version": dict(profile["tx_version"]),
        "tx_locktime_top": top(profile["tx_locktime"]),
        "tx_sequence_class": dict(profile["tx_sequence_class"]),
        "tx_sequence_values_top": top(profile["tx_sequence_values"]),
        "tx_n_inputs_ge_50": profile["tx_n_inputs_ge_50"],
        "tx_clusters_top": [
            {"version": v, "locktime_zero": lt, "sequence": seq,
             "n_inputs": ni, "n_outputs": no, "n_txs": c}
            for (v, lt, seq, ni, no), c in
            top(profile["tx_clusters"], n=8)],
        "validation_inputs": profile["validation_inputs"],
        "verified_key_positions": dict(sorted(
            profile["verified_key_positions"].items())),
        "verified_position_combinations": {
            ",".join(str(p) for p in combo): c for combo, c in
            sorted(profile["verified_position_combinations"].items())},
        "verified_via": dict(profile["verified_via"]),
    }


# -- mempool-sampled verification ----------------------------------------------

def _verify_payload_input(payload, input_index, script_hex, source,
                          script_sig_hex):
    """Verify one script-revealing input of a fetched transaction.

    Returns a summary dict shaped like the validation run's records, or
    None when the input cannot be verified from this payload.
    """
    from .verify import (check_commitment, verify_input_ecdsa,
                         verify_input_taproot, _tx_from_mempool_json)
    from bitcoin.core import CTransaction

    vin = payload.get("vin") or []
    if input_index >= len(vin):
        return None
    prevout = vin[input_index].get("prevout")
    if not prevout:
        return None
    utxos = []
    for v in vin:
        po = v.get("prevout")
        utxos.append((po["value"], bytes.fromhex(po["scriptpubkey"]))
                     if po else (0, b""))
    tx = CTransaction.deserialize(bytes.fromhex(payload["hex"])) \
        if payload.get("hex") else _tx_from_mempool_json(payload)
    script_bytes = bytes.fromhex(script_hex)
    commitment = check_commitment(script_bytes,
                                  bytes.fromhex(prevout["scriptpubkey"]),
                                  script_sig_hex=script_sig_hex)
    if source == "taproot_leaf":
        summary = verify_input_taproot(tx, input_index, utxos)
        positions = summary.get("verified_key_positions") or []
        via = "taproot_" + summary.get("path", "unknown")
        present = summary.get("signatures_present", 0)
        verified = summary.get("signatures_verified", 0)
    else:
        summary = verify_input_ecdsa(tx, input_index, script_bytes,
                                     prevout["value"])
        positions = [v["key_index"] for v in summary.get("verified", [])]
        via = "ecdsa_bip143"
        present = summary["signatures_present"]
        verified = summary["signatures_verified"]
    return {
        "commitment": str(commitment),
        "signatures_present": present,
        "signatures_verified": verified,
        "verified_positions": positions,
        "via": via,
    }


def bucket_obs_by_txid(conn):
    """input_id, input_index, script fields per bucket script, grouped
    by spending txid."""
    rows = collections.defaultdict(list)
    cur = conn.execute(
        "SELECT o.input_id, i.txid, i.input_index, i.script_sig_hex,"
        " s.script_hex, s.source"
        " FROM script_observations o"
        " JOIN inputs i ON i.input_id = o.input_id"
        " JOIN revealed_scripts s ON s.script_sha256 = o.script_sha256"
        " WHERE o.script_sha256 IN (SELECT script_sha256"
        " FROM temp.bucket_scripts)")
    for r in cur:
        rows[r["txid"]].append(dict(r))
    return rows


def verify_bucket_sample(conn, client, profile, max_txs=VERIFY_SAMPLE_TXS,
                         seed=20261019, budget=None):
    """Fill an empty validation sample with a small mempool-verified one.

    Uses cached transaction payloads first; only cache misses consume
    request budget. Results merge into the profile's verified-position
    aggregates and are returned separately for the report.
    """
    obs = bucket_obs_by_txid(conn)
    already = profile["verified_spend_txs"]
    todo = [t for t in obs if t not in already]
    rng = random.Random(seed)
    rng.shuffle(todo)
    results = []
    fresh = 0
    for txid in todo:
        if len(results) >= max_txs:
            break
        if budget is not None and fresh >= budget:
            results.append({"skipped_for_budget": True})
            break
        try:
            payload = client.tx(txid)
        except Exception as exc:
            results.append({"txid": txid, "error": str(exc)[:120]})
            continue
        if not client.cached_last:
            fresh += 1
        for r in obs[txid]:
            try:
                summary = _verify_payload_input(
                    payload, r["input_index"], r["script_hex"], r["source"],
                    r["script_sig_hex"])
            except Exception as exc:
                results.append({"txid": txid, "error": str(exc)[:120]})
                continue
            if summary is None:
                continue
            summary["txid"] = txid
            summary["input_id"] = r["input_id"]
            results.append(summary)
            profile["validation_inputs"] += 1
            profile["verified_via"][summary["via"]] += 1
            profile["verified_spend_txs"].add(txid)
            positions = sorted(summary["verified_positions"])
            for pos in positions:
                profile["verified_key_positions"][int(pos)] += 1
            profile["verified_position_combinations"][tuple(positions)] += 1
    return results, fresh


# -- deposit-side address history ----------------------------------------------

def deposit_profile(conn, client, bucket, tx_sample=DEPOSIT_SAMPLE_TXS,
                    addr_sample=DEPOSIT_SAMPLE_ADDRESSES, seed=20261019,
                    budget=None):
    """Deposit-side history for the prevout addresses feeding a bucket.

    Two layers: corpus-side reuse (the same deposit address feeding more
    than one sampled spend) and per-address history from mempool.space
    (tx counts, inflow batching, first-seen spread). Cached payloads and
    cached address pages are used first; fresh fetches stop at budget.
    """
    obs = bucket_obs_by_txid(conn)
    txids = sorted(obs)
    rng = random.Random(seed + 1)
    rng.shuffle(txids)
    txids = txids[:tx_sample]

    deposits = []          # {address, type, value, spend_txid}
    fresh = 0
    payload_errors = 0
    for txid in txids:
        if budget is not None and fresh >= budget:
            break
        try:
            payload = client.tx(txid)
        except Exception:
            payload_errors += 1
            continue
        if not client.cached_last:
            fresh += 1
        vin = payload.get("vin") or []
        for r in obs[txid]:
            idx = r["input_index"]
            if idx >= len(vin):
                continue
            po = vin[idx].get("prevout")
            if not po:
                continue
            deposits.append({
                "address": po.get("scriptpubkey_address"),
                "type": po.get("scriptpubkey_type"),
                "value": po.get("value"),
                "spend_txid": txid,
            })

    addr_counts = collections.Counter(d["address"] for d in deposits
                                      if d["address"])
    reuse_corpus = {a: c for a, c in addr_counts.items() if c > 1}
    type_mix = collections.Counter(d["type"] for d in deposits)
    round_values = sum(1 for d in deposits
                       if d["value"] is not None and d["value"] % 1000000 == 0)

    histories = []
    fresh_addr = 0
    sampled = sorted(addr_counts, key=lambda a: (-addr_counts[a], a))
    # Prefer reused addresses, then fill deterministically; cap the fetches.
    chosen = list(reuse_corpus)[:addr_sample]
    for a in sampled:
        if len(chosen) >= addr_sample:
            break
        if a not in chosen:
            chosen.append(a)
    for address in chosen:
        if budget is not None and fresh + fresh_addr >= budget:
            histories.append({"address": address, "skipped_for_budget": True})
            continue
        try:
            history = client.address_txs(address)
        except Exception:
            continue
        if not client.cached_last:
            fresh_addr += 1
        receive_txs = 0
        spend_txs = 0
        max_batch = 0
        first_time = None
        for t in history:
            got = 0
            for vout in t.get("vout") or []:
                if vout.get("scriptpubkey_address") == address:
                    got += 1
            if got:
                receive_txs += 1
                max_batch = max(max_batch, got)
                bt = (t.get("status") or {}).get("block_time")
                if bt and (first_time is None or bt < first_time):
                    first_time = bt
            for vin_item in t.get("vin") or []:
                po = vin_item.get("prevout")
                if po and po.get("scriptpubkey_address") == address:
                    spend_txs += 1
                    break
        histories.append({
            "address": address,
            "txs_on_page": len(history),
            "receive_txs": receive_txs,
            "spend_txs": spend_txs,
            "max_outputs_to_address_in_one_tx": max_batch,
            "first_block_time": first_time,
        })

    seen_first = [h["first_block_time"] for h in histories
                  if h.get("first_block_time")]
    return {
        "sampled_spend_txs": len(txids),
        "payload_errors": payload_errors,
        "deposit_inputs_observed": len(deposits),
        "distinct_deposit_addresses": len(addr_counts),
        "addresses_reused_across_sampled_spends": len(reuse_corpus),
        "deposit_type_mix": dict(type_mix),
        "deposit_values_multiple_of_01btc": round_values,
        "address_histories": histories,
        "fresh_tx_requests": fresh,
        "fresh_address_requests": fresh_addr,
        "first_seen_min": min(seen_first) if seen_first else None,
        "first_seen_max": max(seen_first) if seen_first else None,
    }


# -- crossover detection --------------------------------------------------------

def crossover(conn, buckets):
    """Weak (template-level) and strong (signature-level) crossovers."""
    script_bucket = {}
    for b in buckets:
        for sha in b["members"]:
            script_bucket[sha] = b["bucket_id"]
    _temp_script_table(conn, script_bucket)

    key_buckets = collections.defaultdict(collections.Counter)
    for r in conn.execute(
            "SELECT k.pubkey_hex, k.script_sha256 FROM script_keys k"
            " WHERE k.script_sha256 IN (SELECT script_sha256"
            " FROM temp.bucket_scripts)"):
        key_buckets[r["pubkey_hex"]][script_bucket[r["script_sha256"]]] += 1

    shape_of = {b["bucket_id"]: b["shape"] for b in buckets}
    multi = {}
    for key, bkts in key_buckets.items():
        shapes = {shape_of[b] for b in bkts}
        if len(bkts) >= 2:
            multi[key] = {"buckets": dict(bkts), "n_shapes": len(shapes)}
    by_shapes = collections.Counter(v["n_shapes"] for v in multi.values())
    top_multi = sorted(multi.items(),
                       key=lambda kv: (-kv[1]["n_shapes"],
                                       -sum(kv[1]["buckets"].values())))[:10]

    # Strong crossovers: a key whose SIGNATURE verified in spends of two
    # differently-shaped buckets. Verified keys come from stored
    # validation results (fresh samples merge into the same table).
    strong = []
    verified_keys = collections.defaultdict(collections.Counter)
    for b in buckets:
        _temp_script_table(conn, b["members"])
        cur = conn.execute(
            "SELECT v.verified_key_positions_json, o.script_sha256"
            " FROM validation_results v"
            " JOIN script_observations o ON o.input_id = v.input_id"
            " WHERE o.script_sha256 IN (SELECT script_sha256"
            " FROM temp.bucket_scripts)")
        cache = {}
        for r in cur:
            sha = r["script_sha256"]
            if sha not in cache:
                cache[sha] = {
                    pos: k for pos, k in conn.execute(
                        "SELECT position, pubkey_hex FROM script_keys"
                        " WHERE script_sha256 = ?", (sha,))}
            for pos in json.loads(
                    r["verified_key_positions_json"] or "[]"):
                key = cache[sha].get(int(pos))
                if key:
                    verified_keys[key][b["bucket_id"]] += 1
    for key, bkts in verified_keys.items():
        if len(bkts) >= 2:
            strong.append({"pubkey_hex": key, "verified_in": dict(bkts)})

    return {
        "keys_in_bucket_scripts": len(key_buckets),
        "keys_in_two_or_more_buckets": len(multi),
        "keys_by_distinct_shape_count": dict(sorted(by_shapes.items())),
        "top_multi_bucket_keys": [
            {"pubkey_hex": k, "buckets": v["buckets"],
             "n_shapes": v["n_shapes"]} for k, v in top_multi],
        "strong_crossovers": strong,
        "n_strong_crossovers": len(strong),
    }


# -- Onramp candidate hardening --------------------------------------------------

ONRAMP_CANDIDATE_KEYS = [
    "033f67b4653f6f60081c649081c5626c1d4bf03f6b9f092a713558d29cdbf64987",
    "03a553e30733d7a8df6d390d59cc136e2c9d9cf4e808f3b6ab009beae68dd60822",
]


def onramp_hardening(conn, candidate_keys=None):
    """Position-stability statistics for the recurring cosigner keys.

    The multi-institution hypothesis: the candidate key stays fixed as
    one institution's cosigner while the other quorum positions rotate
    per customer account. Consistent with: many distinct co-keys, few
    repeated co-key sets, candidate position varying or stable per the
    provider's convention. NOT sufficient for attribution: any per-wallet
    service key shows the same shape.
    """
    out = []
    candidate_keys = candidate_keys or ONRAMP_CANDIDATE_KEYS
    for key in candidate_keys:
        rows = conn.execute(
            "SELECT k.script_sha256, k.position, s.template_l2,"
            " s.first_seen_height, s.last_seen_height"
            " FROM script_keys k"
            " JOIN revealed_scripts s ON s.script_sha256 = k.script_sha256"
            " WHERE k.pubkey_hex = ? AND s.threshold = 2 AND s.n_keys = 3"
            " AND s.keys_sorted = 0", (key,)).fetchall()
        scripts = [r["script_sha256"] for r in rows]
        positions = collections.Counter(r["position"] for r in rows)
        cokey_sets = {}
        if scripts:
            _temp_script_table(conn, scripts)
            for r in conn.execute(
                    "SELECT k.script_sha256, k.position, k.pubkey_hex"
                    " FROM script_keys k WHERE k.script_sha256 IN"
                    " (SELECT script_sha256 FROM temp.bucket_scripts)"
                    " AND k.pubkey_hex != ?", (key,)):
                cokey_sets.setdefault(r["script_sha256"], {})[
                    r["position"]] = r["pubkey_hex"]
        sets_counter = collections.Counter(
            tuple(sorted(s.items())) for s in cokey_sets.values())
        cokeys = collections.Counter()
        for s in cokey_sets.values():
            for k in s.values():
                cokeys[k] += 1
        other = next((k for k in candidate_keys if k != key), None)
        same_candidate_pair = 0
        if other:
            same_candidate_pair = sum(
                1 for s in cokey_sets.values() if other in s.values())
        out.append({
            "pubkey_hex": key,
            "n_scripts": len(rows),
            "candidate_position_histogram": dict(sorted(
                positions.items())),
            "height_span": [min((r["first_seen_height"] for r in rows),
                                default=None),
                            max((r["last_seen_height"] for r in rows),
                                default=None)],
            "distinct_co_keys": len(cokeys),
            "distinct_co_key_sets": len(sets_counter),
            "co_key_set_size_histogram": dict(sorted(
                collections.Counter(len(s) for s in cokey_sets.values())
                .items())),
            "top_co_keys": cokeys.most_common(6),
            "top_co_key_sets": [
                {"positions": {pos: pubkey for pos, pubkey in s},
                 "n_scripts": c}
                for s, c in sets_counter.most_common(4)],
            "scripts_containing_other_candidate": same_candidate_pair,
        })
    return out


# -- run -------------------------------------------------------------------------

def run_enrich(config, conn, steps=None, budget=DEFAULT_REQUEST_BUDGET,
               out_dir="reports", verify_sample=VERIFY_SAMPLE_TXS,
               deposit_txs=DEPOSIT_SAMPLE_TXS,
               deposit_addrs=DEPOSIT_SAMPLE_ADDRESSES):
    steps = set(steps or {"profiles", "verify_sample", "deposits",
                          "crossover", "onramp", "report"})
    from .mempool import MempoolClient
    client = MempoolClient(config, conn)
    client.cached_last = True  # set False by get_json on a network fetch

    buckets = select_buckets(conn, os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports", "attribution_matches.json"))
    results = {
        "generated_utc": utc_now_iso(),
        "request_budget": budget,
        "fresh_requests_made": 0,
        "buckets": [],
    }
    remaining = budget

    # Deposit profiles: the six largest buckets by script count.
    deposit_targets = set()
    if "deposits" in steps:
        for b in sorted(buckets, key=lambda b: -len(b["members"]))[:6]:
            deposit_targets.add(b["bucket_id"])

    for b in buckets:
        entry = {
            "bucket_id": b["bucket_id"],
            "origin": b["origin"],
            "providers": b["providers"],
            "n_scripts": len(b["members"]),
        }
        if "profiles" in steps:
            profile = profile_bucket_db(conn, b)
            b["_profile"] = profile
            entry["profile"] = compact_profile(profile)
            entry["bucket_timelock_values"] = b.get("timelock_values")
        if "verify_sample" in steps and \
                b.get("_profile", {}).get("validation_inputs", 0) == 0:
            sample, fresh = verify_bucket_sample(
                conn, client, b["_profile"], max_txs=verify_sample,
                budget=remaining)
            remaining -= fresh
            results["fresh_requests_made"] += fresh
            entry["fresh_verification_sample"] = {
                "spend_txs_attempted": verify_sample,
                "results": sample,
            }
            entry["profile"] = compact_profile(b["_profile"])
        if "deposits" in steps and b["bucket_id"] in deposit_targets:
            dep = deposit_profile(conn, client, b, tx_sample=deposit_txs,
                                  addr_sample=deposit_addrs,
                                  budget=remaining)
            remaining -= dep["fresh_tx_requests"] + dep["fresh_address_requests"]
            results["fresh_requests_made"] += (dep["fresh_tx_requests"] +
                                               dep["fresh_address_requests"])
            entry["deposit_profile"] = dep
        results["buckets"].append(entry)
        print("bucket %s: %d scripts, %d observations" %
              (b["bucket_id"], len(b["members"]),
               entry.get("profile", {}).get("n_observations", 0)))

    if "crossover" in steps:
        results["crossover"] = crossover(conn, buckets)
    if "onramp" in steps:
        results["onramp_candidates"] = onramp_hardening(conn)

    if "report" in steps:
        path = os.path.join(out_dir, "enrichment.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=1, sort_keys=True, default=str)
        print("wrote %s" % path)
    return results
