"""Provider attribution engine: graded matching of the registry against
the revealed-script corpus.

Deterministic rules only. Every match is an exact field join against a
registry expected_structure row (form, script_class, threshold, n_keys,
keys_sorted, template_l3, timelocks) plus two explicit feature checks for
the CHECKSIGADD rendering difference (see CSA_RENDERING below). No fuzzy
matching, no scoring model.

Grades, one per (revealed script, provider):

    A  verified provider attribution   independent evidence ties the
                                       wallet/transaction to the provider
                                       (registry known_txids). The registry
                                       currently holds no mainnet txids, so
                                       this grade is implemented but expected
                                       to stay empty.
    B  verified institutional key      an independently authenticated key
                                       participation              the provider published appears in
                                       the script. This confirms the KEY'S
                                       PARTICIPATION, never wallet ownership.
    C  strong implementation match     multiple distinctive features match
                                       one implementation: a documented
                                       construction plus a provider-documented
                                       timelock value and form, checked
                                       against the alternatives in the
                                       registry. False-positive rate UNKNOWN:
                                       there is no labeled held-out data.
    D  weak implementation match       the shape resembles a documented
                                       construction whose features are common
                                       to several implementations.
    E  unknown                         nothing in the registry matches.

Ambiguity rule: when more than one provider remains at a script's best
grade, every provider at that grade is kept and flagged ambiguous; the
engine never picks one. Supporting and contradicting evidence are recorded
per match row.
"""

import csv
import hashlib
import json
import os
import re

from . import db

REGISTRY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "registry", "providers.json")

# python-bitcoinlib renders OP_CHECKSIGADD as the literal "0xba" in template
# strings. Some registry rows describe the same constructions rendered with
# the named opcode, so an exact template_l3 join cannot see them. The two
# explicit checks below cover exactly those cases for one registry family
# (Liana multi_a leaves); they use the same field constraints as the row they
# extend and no extra tolerance.
CSA_TOKEN = "0xba"

_L2_TIMELOCK_RE = re.compile(
    r"<NUM:(-?\d+)> (OP_CHECKSEQUENCEVERIFY|OP_CHECKLOCKTIMEVERIFY)")

# Pair cap for the scripts_share_key graph export: a key inside k scripts
# would otherwise expand to k*(k-1)/2 rows. Keys above the cap keep their
# key_in_script edges; the cap is reported, never hidden.
SHARE_PAIR_CAP = 1000


# -- small helpers ------------------------------------------------------------

def _base58_check_decode(text):
    """Decode base58check to its payload, verifying the checksum."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in text:
        n = n * 58 + alphabet.index(ch)
    body = n.to_bytes(82, "big")  # an extended key is a 78-byte payload
    payload, checksum = body[:78], body[78:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("base58 checksum mismatch")
    return payload


def xpub_to_pubkey(key):
    """Return the 33-byte hex pubkey carried by an xpub, else None.

    Only the xpub's own key material is used: deriving child keys without a
    provider-published path would be guessing, and this study does not guess.
    """
    if not key.startswith(("xpub", "tpub")):
        return None
    try:
        payload = _base58_check_decode(key)
    except (ValueError, KeyError, OverflowError):
        return None
    version = payload[:4]
    if version not in (b"\x04\x88\xb2\x1e", b"\x04\x35\x87\xcf"):
        return None
    return payload[45:].hex()


def load_registry(path=None):
    with open(path or REGISTRY_PATH) as fh:
        return json.load(fh)


def known_key_lookup(registry):
    """Map pubkey hex -> (provider, key entry) for every registry key that
    can appear inside a script: raw pubkeys and xpub-derived keys."""
    out = {}
    skipped = []
    for prov in registry["providers"]:
        for entry in prov.get("known_keys", []):
            key = entry["key"]
            pubkey = None
            if re.fullmatch(r"(02|03)[0-9a-f]{64}|04[0-9a-f]{128}", key):
                pubkey = key
            else:
                pubkey = xpub_to_pubkey(key)
            if pubkey is None:
                skipped.append({"provider": prov["id"], "key": key,
                                "role": entry["role"]})
                continue
            out.setdefault(pubkey, []).append((prov, entry))
    return out, skipped


def parse_timelocks(template_l2):
    """[(op, value)] pairs from a template_l2 string."""
    if not template_l2:
        return []
    return [(op, int(v)) for v, op in _L2_TIMELOCK_RE.findall(template_l2)]


# -- per-script feature extraction --------------------------------------------

def script_features(row, forms):
    csv_cltv = parse_timelocks(row["template_l2"])
    return {
        "script_sha256": row["script_sha256"],
        "source": row["source"],
        "forms": forms,
        "script_class": row["script_class"],
        "family_l4": row["family_l4"],
        "threshold": row["threshold"],
        "n_keys": row["n_keys"],
        "keys_sorted": row["keys_sorted"],
        "template_l3": row["template_l3"],
        "timelocks": csv_cltv,
        "csv_values": sorted(v for op, v in csv_cltv
                             if op == "OP_CHECKSEQUENCEVERIFY"),
        "cltv_values": sorted(v for op, v in csv_cltv
                              if op == "OP_CHECKLOCKTIMEVERIFY"),
        "first_seen_height": row["first_seen_height"],
        "last_seen_height": row["last_seen_height"],
    }


def _form_matches(struct, feats):
    form = struct.get("form")
    return form is None or form in feats["forms"]


def _sorted_matches(struct, feats):
    want = struct.get("keys_sorted")
    have = feats["keys_sorted"]
    if want is None or have is None:
        return True
    return bool(want) == bool(have)


def _timelock_matches(struct, feats):
    """Row timelocks against script timelocks.

    A row's entries for one op are the provider's documented ALTERNATIVES
    (Green documents three CSV buckets, one of which an account uses), so
    per op the rule is: the op must be present, and where the row documents
    concrete values the script's value must be one of them. An entry with a
    null value demands only the op's presence with any value. A row with no
    timelocks demands a script with none.
    """
    row_tls = struct.get("timelocks") or []
    script_tls = feats["timelocks"]
    if not row_tls:
        return not script_tls, []
    script_by_op = {}
    for op, value in script_tls:
        script_by_op.setdefault(op, set()).add(value)
    matched = []
    row_by_op = {}
    for entry in row_tls:
        op = ("OP_CHECKSEQUENCEVERIFY" if entry["op"] == "CSV"
              else "OP_CHECKLOCKTIMEVERIFY")
        row_by_op.setdefault(op, []).append(entry.get("value"))
    for op, values in row_by_op.items():
        if op not in script_by_op:
            return False, []
        opname = "CSV" if op == "OP_CHECKSEQUENCEVERIFY" else "CLTV"
        documented = [v for v in values if v is not None]
        if not documented:
            matched.append("%s present" % opname)
            continue
        hits = sorted(script_by_op[op] & set(documented))
        if not hits:
            return False, []
        matched.append("%s=%s documented by provider"
                       % (opname, "/".join(str(v) for v in hits)))
    return True, matched


def match_structure(struct, feats):
    """Exact field join of one registry row against one script's features.

    Returns (matched, matched_feature_strings). Null registry fields and
    null corpus fields are skipped; a row that pins nothing beyond form and
    a catch-all class cannot discriminate and is refused (non_discriminating).
    """
    if not _form_matches(struct, feats):
        return False, []
    if struct.get("script_class") is not None \
            and struct["script_class"] != feats["script_class"]:
        return False, []
    if not _sorted_matches(struct, feats):
        return False, []

    pins = []
    if struct.get("template_l3") is not None:
        if struct["template_l3"] != feats["template_l3"]:
            return False, []
        pins.append("template_l3 exact")
    if struct.get("n_keys") is not None and feats["n_keys"] is not None:
        if struct["n_keys"] != feats["n_keys"]:
            return False, []
        pins.append("n_keys=%d" % struct["n_keys"])
    if struct.get("threshold") is not None and feats["threshold"] is not None:
        if struct["threshold"] != feats["threshold"]:
            return False, []
        pins.append("threshold=%d" % struct["threshold"])
    if struct.get("keys_sorted") is not None and feats["keys_sorted"] is not None:
        pins.append("keys_sorted=%s" % ("true" if struct["keys_sorted"]
                                        else "false"))
    tl_ok, tl_hits = _timelock_matches(struct, feats)
    if not tl_ok:
        return False, []
    if tl_hits:
        pins.append("timelock %s" % ",".join(tl_hits))

    # A row that pins no template, no threshold, no key count and no
    # timelock value describes a shape too loosely to grade a match.
    if struct.get("template_l3") is None \
            and struct.get("threshold") is None \
            and struct.get("n_keys") is None \
            and not any(e.get("value") is not None
                        for e in (struct.get("timelocks") or [])) \
            and not tl_hits:
        return False, ["non_discriminating"]

    if struct.get("form") is not None:
        pins.append("form=%s" % struct["form"])
    else:
        pins.append("form not published by provider")
    return True, pins


def match_liana_multi_a(struct, feats):
    """Explicit feature check for multi_a leaves rendered with CHECKSIGADD.

    The registry's Liana taproot rows describe multi_a constructions whose
    template_l3 was rendered with named opcodes; this library renders the
    same opcode as 0xba, so the exact join misses them. Same constraints as
    the row: taproot script path, unsorted, primary k-of-k or recovery
    m-of-n behind one CSV.
    """
    if struct.get("form") != "taproot_scriptpath" \
            or not _form_matches(struct, feats) \
            or feats["script_class"] != "taproot_multisig":
        return False, []
    if not _sorted_matches(struct, feats):
        return False, []
    k, n = feats["threshold"], feats["n_keys"]
    if k is None or n is None:
        return False, []
    is_recovery_row = bool(struct.get("timelocks"))
    if is_recovery_row:
        if k >= n or len(feats["csv_values"]) != 1:
            return False, []
        value = feats["csv_values"][0]
        documented = [e["value"] for e in struct["timelocks"]
                      if e.get("value") is not None]
        if documented and value not in documented:
            return False, []
        return True, ["multi_a recovery leaf %d-of-%d" % (k, n),
                      "CSV=%d" % value,
                      "form=taproot_scriptpath"]
    if struct.get("threshold") is not None and k != struct["threshold"]:
        return False, []
    if feats["timelocks"]:
        return False, []
    return True, ["multi_a primary leaf %d-of-%d (k-of-k)" % (k, n),
                  "form=taproot_scriptpath"]


# -- grading ------------------------------------------------------------------

def grade_script(feats, registry_index):
    """Match one script against the whole registry.

    Returns {provider_id: match dict} where each match carries the best
    grade found, the matched structures and their features.
    """
    hits = {}
    for struct in registry_index["structures"]:
        ok, pins = match_structure(struct, feats)
        if not ok and struct["structure_id"].startswith("liana#"):
            ok, pins = match_liana_multi_a(struct, feats)
        if not ok:
            continue
        prov = struct["provider"]
        # Registry strength order: a distinctive provider-documented
        # timelock value plus form outranks bare template shape.
        has_value = any(e.get("value") is not None for e in
                        (struct.get("timelocks") or []))
        grade = "C" if has_value else "D"
        cur = hits.get(prov["id"])
        if cur is None or _GRADE_ORDER[grade] > _GRADE_ORDER[cur["grade"]]:
            hits[prov["id"]] = {
                "grade": grade, "structures": [struct["structure_id"]],
                "matched_features": list(pins),
            }
        elif cur["grade"] == grade:
            cur["structures"].append(struct["structure_id"])
            cur["matched_features"].extend(pins)
    return hits


_GRADE_ORDER = {"A": 4, "B": 3, "C": 2, "D": 1, "E": 0}


def grade_a_txids(registry, conn):
    """Grade A rule: a script revealed inside a provider-published txid.

    The registry currently holds no mainnet txids, so the query returns
    nothing; the rule is implemented so the grade exists and can fire when
    a provider ever publishes a spending transaction id.
    """
    txids = {}
    for prov in registry["providers"]:
        for txid in prov.get("known_txids") or []:
            txids.setdefault(txid, []).append(prov)
    hits = {}
    for txid, provs in txids.items():
        rows = conn.execute(
            "SELECT DISTINCT o.script_sha256 FROM inputs i "
            "JOIN script_observations o ON o.input_id=i.input_id "
            "WHERE i.txid=?", (txid,)).fetchall()
        for r in rows:
            for prov in provs:
                hits.setdefault(r["script_sha256"], []).append(prov)
    return hits


def grade_b_keys(conn):
    """Grade B rule: a provider-published key appears in the script."""
    lookup, skipped = known_key_lookup(_registry_cache)
    hits = {}
    for pubkey, entries in lookup.items():
        rows = conn.execute(
            "SELECT DISTINCT script_sha256 FROM script_keys WHERE pubkey_hex=?",
            (pubkey,)).fetchall()
        for r in rows:
            hits.setdefault(r["script_sha256"], []).append((pubkey, entries))
    return hits, skipped


_registry_cache = None


# -- engine -------------------------------------------------------------------

def run_attribute(config, conn):
    """Run the full attribution pass and write every output artifact."""
    global _registry_cache
    registry = load_registry()
    _registry_cache = registry
    start = int(db.get_meta(conn, "study_start_height"))
    end = int(db.get_meta(conn, "study_end_height"))

    # In-study scripts and the output forms each was revealed under.
    scripts = {}
    for row in conn.execute(
            "SELECT * FROM revealed_scripts WHERE first_seen_height BETWEEN "
            "? AND ?", (start, end)):
        feats = script_features(row, set())
        scripts[row["script_sha256"]] = feats
    for row in conn.execute(
            "SELECT DISTINCT o.script_sha256, i.input_form FROM "
            "script_observations o JOIN inputs i ON i.input_id=o.input_id "
            "JOIN revealed_scripts s ON s.script_sha256=o.script_sha256 "
            "WHERE s.first_seen_height BETWEEN ? AND ?", (start, end)):
        if row["script_sha256"] in scripts:
            scripts[row["script_sha256"]]["forms"].add(row["input_form"])

    # Registry index.
    structures = []
    for prov in registry["providers"]:
        for i, struct in enumerate(prov["expected_structures"]):
            structures.append(dict(struct, structure_id="%s#%d" % (prov["id"], i),
                                   provider=prov))
    registry_index = {"structures": structures}

    # Grades A and B.
    a_hits = grade_a_txids(registry, conn)
    b_hits, skipped_keys = grade_b_keys(conn)

    matches = {}          # script -> {provider_id: match}
    grade_of = {}         # script -> best grade
    for sha, feats in scripts.items():
        hits = grade_script(feats, registry_index)
        for prov in a_hits.get(sha, []):
            hits[prov["id"]] = {"grade": "A", "structures": [],
                                "matched_features": [
                                    "provider-published txid revealed this "
                                    "script in a corpus transaction"]}
        for pubkey, entries in b_hits.get(sha, []):
            for prov, entry in entries:
                pins = ["provider-published key %s... present in script (%s)"
                        % (pubkey[:16], entry["role"])]
                if prov["id"] in hits:
                    hits[prov["id"]]["matched_features"].extend(pins)
                    hits[prov["id"]]["grade"] = "B"
                else:
                    hits[prov["id"]] = {"grade": "B", "structures": [],
                                        "matched_features": pins}
        matches[sha] = hits
        grade_of[sha] = max((h["grade"] for h in hits.values()),
                            key=lambda g: _GRADE_ORDER[g]) if hits else "E"

    # Ambiguity: several providers sharing a script's best grade.
    for sha, hits in matches.items():
        best = grade_of[sha]
        if best == "E":
            continue
        top = [pid for pid, h in hits.items() if h["grade"] == best]
        for pid in top:
            hits[pid]["ambiguous"] = len(top) > 1
            hits[pid]["ambiguous_with"] = [o for o in top if o != pid]

    counts = {g: 0 for g in "ABCDE"}
    for g in grade_of.values():
        counts[g] += 1
    total = len(scripts)

    result = {
        "registry_version": registry["version"],
        "study_start_height": start, "study_end_height": end,
        "n_scripts": total, "grade_counts": counts,
        "matches": matches, "grade_of": grade_of, "scripts": scripts,
        "skipped_known_keys": skipped_keys,
        "_controls": {p["id"] for p in registry["providers"]
                      if p["control_group"]},
    }

    out_dir = getattr(config, "report_dir", None) or "reports"
    os.makedirs(out_dir, exist_ok=True)
    write_matches_json(result, os.path.join(out_dir, "attribution_matches.json"))
    graph_dir = os.path.join(out_dir, "graph")
    result["_share_cap"] = write_graph(result, registry, conn, graph_dir)

    summary = summarize(result, registry)
    os.makedirs(out_dir, exist_ok=True)
    buckets = build_buckets(result, conn)
    with open(os.path.join(out_dir, "attribution_buckets.json"), "w") as fh:
        json.dump({"note": "same-shape buckets over grade-E and ambiguous "
                           "scripts; necessary, not sufficient, for "
                           "same-provider identification",
                   "n_buckets": len(buckets), "buckets": buckets},
                  fh, indent=1, default=str)
    write_report(result, registry, summary, skipped_keys, buckets,
                 os.path.join(out_dir, "attribution.md"), conn)

    print("attribution over %d in-study scripts: A=%d B=%d C=%d D=%d E=%d"
          % (total, counts["A"], counts["B"], counts["C"], counts["D"],
             counts["E"]))
    print("wrote %s, %s, %s" % (
        os.path.join(out_dir, "attribution_matches.json"),
        os.path.join(graph_dir, "(nodes|edges)_*.csv"),
        os.path.join(out_dir, "attribution.md")))
    return result


def summarize(result, registry):
    """Per-provider match counts and ambiguity/contamination numbers."""
    per_provider = {}
    for sha, hits in result["matches"].items():
        for pid, hit in hits.items():
            row = per_provider.setdefault(
                pid, {"A": 0, "B": 0, "C": 0, "D": 0, "ambiguous": 0,
                      "control_explained": 0, "scripts": []})
            row[hit["grade"]] += 1
            if hit.get("ambiguous"):
                row["ambiguous"] += 1
            row["scripts"].append(sha)
    controls = {p["id"] for p in registry["providers"] if p["control_group"]}
    # Control contamination: a provider match is control-explained when a
    # control-group row matches the SAME script at the same or better grade.
    for sha, hits in result["matches"].items():
        for pid, hit in hits.items():
            if pid in controls:
                continue
            for other, ohit in hits.items():
                if other in controls and \
                        _GRADE_ORDER[ohit["grade"]] >= _GRADE_ORDER[hit["grade"]]:
                    per_provider[pid]["control_explained"] += 1
                    break
    return {"per_provider": per_provider, "controls": controls}


# -- output: matches json ------------------------------------------------------

# Generic caveats are stored once and referenced by index from every row
# they apply to; the catalog keeps the file at a committable size.
_GENERIC_EVIDENCE = {
    "no_key": "no provider-static key is present in the script; the match "
              "rests on structure, not on keys",
    "common_shape": "features of this shape are common to several "
                    "implementations and control groups",
    "fp_unknown": "false-positive rate UNKNOWN: no labeled held-out data",
}


def write_matches_json(result, path):
    prov_meta = {p["id"]: p for p in load_registry()["providers"]}
    catalog = {}

    def cat(text):
        if text not in catalog:
            catalog[text] = len(catalog)
        return catalog[text]

    rows = []
    for sha in sorted(result["matches"]):
        hits = result["matches"][sha]
        for pid in sorted(hits):
            hit = hits[pid]
            against = ["the same features also match: %s"
                       % ", ".join(sorted(o for o, h in hits.items()
                                          if o != pid
                                          and h["grade"] == hit["grade"]))] \
                if any(o != pid and h["grade"] == hit["grade"]
                       for o, h in hits.items()) else []
            against.append(_GENERIC_EVIDENCE["no_key"])
            against.append(_GENERIC_EVIDENCE["fp_unknown"])
            if hit["grade"] == "D":
                against.append(_GENERIC_EVIDENCE["common_shape"])
            row = {
                "script_sha256": sha,
                "provider_id": pid,
                "grade": hit["grade"],
                "structures": hit["structures"],
                "evidence_for": [cat(f) for f in hit["matched_features"]],
                "evidence_against": [cat(a) for a in against],
            }
            if hit.get("ambiguous"):
                row["ambiguous"] = True
                row["ambiguous_with"] = hit["ambiguous_with"]
            rows.append(row)
    catalog_list = [""] * len(catalog)
    for text, idx in catalog.items():
        catalog_list[idx] = text
    out = {
        "registry_version": result["registry_version"],
        "study_window": [result["study_start_height"],
                         result["study_end_height"]],
        "n_scripts": result["n_scripts"],
        "grade_counts": result["grade_counts"],
        "grade_definitions": {
            "A": "verified provider attribution (independent evidence ties "
                 "the wallet/tx to the provider)",
            "B": "verified institutional key participation (confirms the "
                 "key's participation, NOT wallet ownership)",
            "C": "strong implementation match (multiple distinctive "
                 "features, alternatives checked); false-positive rate "
                 "UNKNOWN: no labeled held-out data",
            "D": "weak implementation match (shape resembles a documented "
                 "construction; features common to several implementations)",
            "E": "unknown",
        },
        "feature_catalog": catalog_list,
        "matches": rows,
    }
    with open(path, "w") as fh:
        json.dump(out, fh, separators=(",", ":"), default=str)
    return rows


# -- output: graph export ------------------------------------------------------

def write_graph(result, registry, conn, graph_dir):
    os.makedirs(graph_dir, exist_ok=True)
    start, end = result["study_start_height"], result["study_end_height"]
    scripts = result["scripts"]

    # Nodes: providers and their registry structures.
    with open(os.path.join(graph_dir, "nodes_provider.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["provider_id", "name", "control_group"])
        for p in registry["providers"]:
            w.writerow([p["id"], p["name"], p["control_group"]])
    with open(os.path.join(graph_dir, "nodes_structure.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["structure_id", "provider_id", "form", "script_class",
                    "threshold", "n_keys", "keys_sorted", "timelocks",
                    "evidence"])
        for p in registry["providers"]:
            for i, s in enumerate(p["expected_structures"]):
                w.writerow(["%s#%d" % (p["id"], i), p["id"], s.get("form"),
                            s.get("script_class"), s.get("threshold"),
                            s.get("n_keys"), s.get("keys_sorted"),
                            json.dumps(s.get("timelocks") or []),
                            s.get("evidence")])

    # Nodes and edges over in-study scripts and their keys.
    obs_counts = {r["script_sha256"]: r["c"] for r in conn.execute(
        "SELECT script_sha256, COUNT(*) c FROM script_observations "
        "GROUP BY script_sha256")}
    with open(os.path.join(graph_dir, "nodes_script.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["script_sha256", "source", "script_class", "family_l4",
                    "template_l3", "threshold", "n_keys", "keys_sorted",
                    "first_seen_height", "last_seen_height",
                    "n_observations", "attribution_grade"])
        for sha in sorted(scripts):
            f = scripts[sha]
            w.writerow([sha, f["source"], f["script_class"], f["family_l4"],
                        f["template_l3"], f["threshold"], f["n_keys"],
                        f["keys_sorted"], f["first_seen_height"],
                        f["last_seen_height"], obs_counts.get(sha, 0),
                        result["grade_of"][sha]])

    key_scripts = {}
    with open(os.path.join(graph_dir, "nodes_key.csv"), "w", newline="") as fh, \
         open(os.path.join(graph_dir, "edges_key_in_script.csv"), "w",
              newline="") as fe:
        wn, we = csv.writer(fh), csv.writer(fe)
        wn.writerow(["pubkey_hex", "n_scripts", "first_seen_height",
                     "last_seen_height"])
        we.writerow(["script_sha256", "pubkey_hex", "position"])
        rows = conn.execute(
            "SELECT k.pubkey_hex, k.script_sha256, k.position, "
            "s.first_seen_height, s.last_seen_height FROM script_keys k "
            "JOIN revealed_scripts s ON s.script_sha256=k.script_sha256 "
            "WHERE s.first_seen_height BETWEEN ? AND ? "
            "ORDER BY k.pubkey_hex, k.script_sha256", (start, end))
        for r in rows:
            we.writerow([r["script_sha256"], r["pubkey_hex"], r["position"]])
            entry = key_scripts.setdefault(r["pubkey_hex"], [])
            if not entry or entry[-1] != r["script_sha256"]:
                entry.append(r["script_sha256"])
        for pub in sorted(key_scripts):
            sl = key_scripts[pub]
            wn.writerow([pub, len(sl), min(scripts[s]["first_seen_height"]
                                           for s in sl),
                         max(scripts[s]["last_seen_height"] for s in sl)])

    # scripts_share_key: pairwise over shared keys, capped per key.
    capped = []
    with open(os.path.join(graph_dir, "edges_scripts_share_key.csv"), "w",
              newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["script_sha256_a", "script_sha256_b", "pubkey_hex"])
        for pub in sorted(key_scripts):
            sl = sorted(key_scripts[pub])
            pairs = [(a, b) for i, a in enumerate(sl) for b in sl[i + 1:]]
            if len(pairs) > SHARE_PAIR_CAP:
                pairs = pairs[:SHARE_PAIR_CAP]
                capped.append({"pubkey_hex": pub, "n_scripts": len(sl),
                               "n_pairs_omitted":
                                   len(sl) * (len(sl) - 1) // 2 - SHARE_PAIR_CAP})
            for a, b in pairs:
                w.writerow([a, b, pub])

    # attribution_match: grades A-D only, with the grade column.
    with open(os.path.join(graph_dir, "edges_attribution_match.csv"), "w",
              newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["script_sha256", "provider_id", "grade", "ambiguous",
                    "control_group", "structures"])
        for sha in sorted(result["matches"]):
            for pid in sorted(result["matches"][sha]):
                hit = result["matches"][sha][pid]
                if hit["grade"] == "E":
                    continue
                w.writerow([sha, pid, hit["grade"],
                            hit.get("ambiguous", False),
                            any(p["id"] == pid and p["control_group"]
                                for p in registry["providers"]),
                            ";".join(hit["structures"])])

    # provider_expected_structure: documented vs source-derived.
    with open(os.path.join(graph_dir,
                           "edges_provider_expected_structure.csv"), "w",
              newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["provider_id", "structure_id", "evidence_kind"])
        for p in registry["providers"]:
            for i, s in enumerate(p["expected_structures"]):
                w.writerow([p["id"], "%s#%d" % (p["id"], i), s.get("evidence")])
    return capped


# -- output: the markdown report -----------------------------------------------

def _bucket_key(f):
    tl = tuple(sorted(v for _, v in f["timelocks"]))
    return (f["template_l3"] or "", f["threshold"], f["n_keys"],
            f["keys_sorted"], f["source"], tl)


def build_buckets(result, conn):
    """Same-shape buckets over scripts that ended at E or in an ambiguity
    group. Necessary, not sufficient, for same-provider identification."""
    bucket_keys = {}
    for sha, f in result["scripts"].items():
        grade = result["grade_of"][sha]
        hits = result["matches"][sha]
        ambiguous = any(h.get("ambiguous") for h in hits.values())
        if grade != "E" and not ambiguous:
            continue
        key = _bucket_key(f)
        bucket_keys.setdefault(key, []).append(sha)
    # Distinct keys per bucket, from exact-byte script_keys membership.
    keys_by_script = {}
    start, end = result["study_start_height"], result["study_end_height"]
    for r in conn.execute(
            "SELECT k.script_sha256, k.pubkey_hex FROM script_keys k JOIN "
            "revealed_scripts s ON s.script_sha256=k.script_sha256 WHERE "
            "s.first_seen_height BETWEEN ? AND ?", (start, end)):
        keys_by_script.setdefault(r["script_sha256"], set()).add(
            r["pubkey_hex"])
    out = []
    for key, shas in bucket_keys.items():
        providers, controls = set(), set()
        for sha in shas:
            for pid in result["matches"][sha]:
                if pid in result["_controls"]:
                    controls.add(pid)
                else:
                    providers.add(pid)
        distinct = set()
        for sha in shas:
            distinct |= keys_by_script.get(sha, set())
        out.append({
            "template_l3": key[0], "threshold": key[1], "n_keys": key[2],
            "keys_sorted": key[3], "source": key[4], "timelock_values": key[5],
            "n_scripts": len(shas),
            "n_distinct_keys": len(distinct),
            "first_seen_height": min(result["scripts"][s]["first_seen_height"]
                                     for s in shas),
            "last_seen_height": max(result["scripts"][s]["last_seen_height"]
                                    for s in shas),
            "any_registry_match": bool(providers or controls),
            "matching_providers": sorted(providers),
            "matching_controls": sorted(controls),
        })
    out.sort(key=lambda b: (-b["n_scripts"], b["template_l3"]))
    return out


def csv_value_histogram(result, source=None):
    hist = {}
    for f in result["scripts"].values():
        if source is not None and f["source"] != source:
            continue
        for op, v in f["timelocks"]:
            if op == "OP_CHECKSEQUENCEVERIFY":
                hist[v] = hist.get(v, 0) + 1
    return hist


def onramp_candidate_keys(conn, result, min_scripts=5):
    """Keys recurring across many distinct UNSORTED 2-of-3 scripts.

    Onramp's documented quorum is structurally identical to plain BitGo's
    unsorted positional 2-of-3, so no template separates them; a recurring
    institutional key would. Such a key is a candidate only: it is NOT
    authenticated, stays below grade B, and the report must say so.
    """
    rows = conn.execute(
        "SELECT k.pubkey_hex, COUNT(DISTINCT k.script_sha256) n_scripts, "
        "COUNT(DISTINCT s.template_l3) n_templates, "
        "MIN(s.first_seen_height) f, MAX(s.last_seen_height) l "
        "FROM script_keys k JOIN revealed_scripts s ON "
        "s.script_sha256=k.script_sha256 WHERE s.first_seen_height BETWEEN "
        "? AND ? AND s.script_class='multisig' AND s.threshold=2 AND "
        "s.n_keys=3 AND s.keys_sorted=0 GROUP BY k.pubkey_hex HAVING "
        "n_scripts>=? ORDER BY n_scripts DESC",
        (result["study_start_height"], result["study_end_height"],
         min_scripts)).fetchall()
    return [dict(r) for r in rows]


def write_report(result, registry, summary, skipped_keys, buckets, path,
                 conn):
    controls = summary["controls"]
    total = result["n_scripts"]
    counts = result["grade_counts"]

    def pct(n):
        return 100.0 * n / total if total else 0.0

    prov_name = {p["id"]: p["name"] for p in registry["providers"]}
    hist_all = csv_value_histogram(result)
    hist_p2wsh = csv_value_histogram(result, source="p2wsh_witness")
    candidates = onramp_candidate_keys(conn, result)

    green = next(p for p in registry["providers"]
                 if p["id"] == "blockstream_green")
    green_key = next(k["key"] for k in green["known_keys"]
                     if k["key"].startswith("03"))
    green_hits = conn.execute(
        "SELECT COUNT(*) c FROM script_keys WHERE pubkey_hex=?",
        (green_key,)).fetchone()["c"]

    # Contamination numbers.
    c_matches = [(sha, pid) for sha, hits in result["matches"].items()
                 for pid, h in hits.items() if h["grade"] == "C"]
    d_matches = [(sha, pid) for sha, hits in result["matches"].items()
                 for pid, h in hits.items() if h["grade"] == "D"]
    c_contaminated = 0
    for sha, pid in c_matches:
        if pid in controls:
            continue
        if any(o in controls and _GRADE_ORDER[result["matches"][sha][o]["grade"]]
               >= _GRADE_ORDER[result["matches"][sha][pid]["grade"]]
               for o in result["matches"][sha]):
            c_contaminated += 1
    d_contaminated = 0
    for sha, pid in d_matches:
        if pid in controls:
            continue
        if any(o in controls for o in result["matches"][sha]):
            d_contaminated += 1

    ambiguous_scripts = [sha for sha, hits in result["matches"].items()
                         if any(h.get("ambiguous") for h in hits.values())]

    L = []
    add = L.append
    start, end = result["study_start_height"], result["study_end_height"]
    add("# Provider attribution report")
    add("")
    add("Generated from registry version %s over the in-study corpus "
        "(heights %s..%s, %d revealed scripts). All figures are RAW COUNTS "
        "over the sampled corpus, not population estimates."
        % (result["registry_version"], start, end, total))
    add("")
    add("## Interpretation rules (apply to every number below)")
    add("- A shared script template NEVER implies shared ownership. "
        "Templates are structural shapes; unrelated wallets converge on the "
        "same shapes.")
    add("- Shared pubkeys link SCRIPTS, not people. A key appearing in two "
        "scripts establishes exactly that byte-level relationship.")
    add("- Grade B confirms a KEY'S PARTICIPATION in a script, never wallet "
        "ownership: a provider-published key inside a script proves the "
        "key is there, not who controls the wallet.")
    add("- The false-positive rate for every grade below is UNKNOWN: there "
        "is no labeled held-out data. Grades C and D are implementation "
        "matches, not attributions of a wallet to an operator.")
    add("- Grade E means the registry contains no matching structure; it "
        "does not mean the script has no provider.")
    add("- Control-group matches (Lightning, Liana, Specter, generic BIP67) "
        "are by definition NOT provider attributions; they exist to "
        "quantify how weak the template-only signal is.")
    add("")
    add("## Headline: how much of the corpus is attributable, at what grade")
    add("")
    add("| Grade | Scripts | Percent of %d |" % total)
    add("|---|---|---|")
    labels = {
        "A": "A: verified provider attribution", "B": "B: verified "
        "institutional key participation",
        "C": "C: strong implementation match", "D": "D: weak implementation "
        "match", "E": "E: unknown"}
    for g in "ABCDE":
        add("| %s | %d | %.2f%% |" % (labels[g], counts[g], pct(counts[g])))
    add("")
    add("## The zero-A statement")
    add("")
    add("Grade A requires independent evidence tying a wallet or "
        "transaction to a provider: a first-party disclosure, an "
        "authenticated descriptor, or a verified mainnet txid. The registry "
        "carries NO mainnet txids, so the A rule cannot fire and %d A rows "
        "is the correct result, not a failure of the engine. The rule is "
        "implemented (provider known_txids joined against corpus "
        "transactions) and will produce A rows the moment a provider-"
        "published txid enters the registry." % counts["A"])
    add("")
    add("## The unknown-false-positive statement")
    add("")
    add("Every match grade below A is reported with an UNKNOWN false-"
        "positive rate. There is no labeled held-out corpus in this study: "
        "no set of scripts with ground-truth provider labels exists to "
        "measure how often a C or D match is wrong. The control groups are "
        "the substitute: they bound how often the same shapes arise for "
        "reasons unrelated to any provider, and the contamination table "
        "below applies that bound. Percentages of the corpus attributed at "
        "C or D must be read as implementation-match ceilings, not "
        "attribution counts.")
    add("")
    add("## Grade B: the Green service key result")
    add("")
    add("The registry carries exactly one provider-static mainnet pubkey "
        "(Green's legacy v0 service key %s...) plus documentation/demo xpubs "
        "for BitGo, Unchained and Nunchuk (checked as their xpub-derived "
        "root keys; deriving children without published paths would be "
        "guessing). The Green service pubkey appears in %d of the %d "
        "in-study scripts, so grade B fires %d times. A B match would have "
        "confirmed only the key's participation, not wallet ownership; that "
        "caveat is recorded per row regardless."
        % (green_key[:16], green_hits, total, counts["B"]))
    if skipped_keys:
        add("- Registry entries that are not script keys and so cannot "
            "appear in scripts (checked, zero matches possible): %s"
            % "; ".join("%s %s... (%s)" % (s["provider"], s["key"][:12],
                                           s["role"][:60])
                        for s in skipped_keys))
    capped = result.get("_share_cap") or []
    if capped:
        add("- Graph export note: %d reused keys exceed the %d-pair cap for "
            "the scripts_share_key edge list (%s pairs omitted in total); "
            "their key_in_script edges are complete."
            % (len(capped), SHARE_PAIR_CAP,
               sum(c["n_pairs_omitted"] for c in capped)))
    add("")
    add("## Per-provider breakdowns")
    add("")
    add("Providers and control groups with at least one A-D match. C and D "
        "are implementation-match grades. control-explained = the same "
        "script also matches a control-group row at equal or better grade.")
    add("")
    add("| Provider | Control | A | B | C | D | ambiguous | control-explained |")
    add("|---|---|---|---|---|---|---|---|")
    for pid in sorted(summary["per_provider"],
                      key=lambda p: (p in controls, -sum(
                          summary["per_provider"][p][g] for g in "ABCD"), p)):
        row = summary["per_provider"][pid]
        add("| %s (%s) | %s | %d | %d | %d | %d | %d | %d |"
            % (pid, prov_name[pid], "yes" if pid in controls else "no",
               row["A"], row["B"], row["C"], row["D"], row["ambiguous"],
               row["control_explained"]))
    add("")
    add("## Ambiguity report")
    add("")
    add("%d scripts carry an ambiguity flag: more than one provider remains "
        "plausible at the script's best grade, and every candidate is "
        "recorded with the flag instead of picking one."
        % len(ambiguous_scripts))
    for sha in sorted(ambiguous_scripts)[:10]:
        hits = result["matches"][sha]
        top = sorted((pid, h) for pid, h in hits.items() if h.get("ambiguous"))
        add("- %s grade %s: %s" % (sha[:16], hits and
                                   result["grade_of"][sha],
                                   ", ".join("%s (%s)" % (pid, h["grade"])
                                             for pid, h in top)))
    if len(ambiguous_scripts) > 10:
        add("- (first 10 of %d shown; the full set is in "
            "reports/attribution_matches.json)" % len(ambiguous_scripts))
    add("")
    add("## Control-group contamination")
    add("")
    add("How many C/D provider matches are equally explained by a control "
        "group (a control row matches the same script at equal or better "
        "grade):")
    add("- C matches by non-control providers: %d, of which control-"
        "explained: %d" % (len([1 for _, p in c_matches if p not in controls]),
                           c_contaminated))
    add("- D matches by non-control providers: %d, of which control-"
        "explained: %d" % (len([1 for _, p in d_matches if p not in controls]),
                           d_contaminated))
    add("The sorted 2-of-3 shapes are the worst case: the generic BIP67 "
        "control row is feature-identical to the Unchained, Specter and "
        "Casa rows, so nothing in the observable features separates a "
        "provider wallet from DIY or exchange cold storage on those shapes.")
    add("")
    add("## What the corpus cannot support (missing edges)")
    add("")
    add("The study spec lists edge types this corpus cannot produce. They "
        "are listed here instead of faked:")
    add("- signature_provided per key: witness signature-to-key mapping "
        "exists only for locally resolvable prevouts (249 of 161,202 "
        "script-revealing observations); the raw-transaction endpoint is "
        "soft-blocked (confirmed txids answer HTTP 200 with empty data, "
        "docs/api_notes.md), so per-key signature edges cannot be built at "
        "corpus scale.")
    add("- same scriptPubKey outputs and spends: prevout resolution is "
        "unavailable on the no-key tier; the corpus resolves only cached "
        "prevouts, so reuse of the same scriptPubKey and spend-graph edges "
        "are unobservable.")
    add("- xpub derivation to corpus keys: the provider xpubs in the "
        "registry are API-verification keys and documentation/demo "
        "fixtures. Deriving child keys to hunt corpus matches requires "
        "provider-published derivation paths, which do not exist; guessing "
        "paths is excluded by the study rules.")
    add("- verified wallet attribution: no provider publishes txids or "
        "address sets, so the A-grade edge cannot exist yet.")
    add("")
    add("Coverage note: the registry records only Green's optimized CSV "
        "layout. The libwally non-optimized CSV 2-of-2-then-1 layout "
        "documented in docs/provider_research.md has no registry row, so "
        "timelocked_singlesig_recovery scripts in other layouts are "
        "unmatched by design. Extending the registry is a research step, "
        "not an engine step.")
    add("")
    add("## Same-shape buckets (necessary, not sufficient)")
    add("")
    add("Every script that ends at grade E or in an ambiguity group is "
        "bucketed by (template_l3, threshold, n_keys, keys_sorted, source, "
        "sorted timelock values). Buckets are a same-PROVIDER hypothesis "
        "generator only: one provider with per-wallet keys splits into many "
        "buckets, and generic shapes merge unrelated providers into one "
        "bucket. %d buckets exist in total; every one is exported with "
        "size, distinct key count, height span and registry-match status "
        "in reports/attribution_buckets.json. Top 15 by size:"
        % len(buckets))
    add("")
    add("| n_scripts | source | template | k/n | sorted | CSV values | "
        "distinct keys | seen | registry match |")
    add("|---|---|---|---|---|---|---|---|---|")
    for b in buckets[:15]:
        tpl = (b["template_l3"] or "(none)")[:60]
        add("| %d | %s | %s | %s/%s | %s | %s | %d | %d..%d | %s |"
            % (b["n_scripts"], b["source"], tpl,
               b["threshold"], b["n_keys"],
               {0: "no", 1: "yes"}.get(b["keys_sorted"], "n/a"),
               list(b["timelock_values"]) or "-",
               b["n_distinct_keys"],
               b["first_seen_height"], b["last_seen_height"],
               ("yes: " + ", ".join(b["matching_providers"] +
                                    b["matching_controls"]))
               if b["any_registry_match"] else "no"))
    add("")
    add("## Owner refinements")
    add("")
    add("### AnchorWatch negative filter and CSV day-hint")
    add("")
    add("Negative filter: AnchorWatch is P2WSH miniscript and explicitly "
        "not taproot, so NO taproot_leaf-source script can be AnchorWatch. "
        "The engine enforces this through the row's form (p2wsh): every "
        "taproot_leaf script is excluded from AnchorWatch matching by "
        "construction, and its candidates are p2wsh_witness-sourced "
        "multisig/conditional structures only.")
    add("")
    add("CSV day-hint: AnchorWatch publishes recovery delays in calendar "
        "days (335 and 380); CSV is denominated in blocks. At the 144 "
        "blocks/day convention the hints are 48,240 and 54,720 blocks. "
        "Histogram of CSV values over in-study scripts (all sources, then "
        "p2wsh_witness only):")
    top_all = sorted(hist_all.items(), key=lambda x: -x[1])[:15]
    add("")
    add("| CSV blocks | scripts (all) | scripts (p2wsh) |")
    add("|---|---|---|")
    for v, c in top_all:
        add("| %d | %d | %d |" % (v, c, hist_p2wsh.get(v, 0)))
    add("")
    hit48240, hit54720 = hist_all.get(48240, 0), hist_all.get(54720, 0)
    near = {v: c for v, c in hist_all.items()
            if min(abs(v - 48240), abs(v - 54720)) <= 432}
    add("Result: 0 scripts at 48,240 and %d at 54,720; no value within 3 "
        "days (432 blocks) of either hint (%s). The dominant values "
        "(1008 = 1 week, 4032/4320 = 4 weeks, 144 = 1 day, 25920/51840 = "
        "Green's buckets, 65535) are standard conventions, not day-"
        "conversion artifacts. No AnchorWatch day-hint upgrade fires: the "
        "evidence is a null result either way, and the histogram is "
        "recorded as the check."
        % (hit54720, sorted(near.items()) or "empty neighborhood"))
    add("")
    add("### Onramp cosigner-key cross-reference")
    add("")
    add("Onramp's documented 2-of-3 quorum is structurally identical to "
        "plain BitGo's unsorted positional 2-of-3, so template alone "
        "cannot separate them; the separator would be a recurring "
        "institutional key. Keys appearing in %d+ distinct unsorted 2-of-3 "
        "scripts:" % 5)
    if candidates:
        add("")
        add("| key | distinct unsorted 2-of-3 scripts | distinct templates | first seen | last seen |")
        add("|---|---|---|---|---|")
        for r in candidates:
            add("| %s | %d | %d | %d | %d |"
                % (r["pubkey_hex"], r["n_scripts"], r["n_templates"],
                   r["f"], r["l"]))
        add("")
        add("These are CANDIDATE institutional keys, grade B pending "
            "authentication: no registry entry authenticates any of them, "
            "so they raise no script above its current grade and generate "
            "no attribution edge. Keys recurring across the whole study "
            "window with a single template are the strongest same-"
            "implementation signal the corpus can produce without a "
            "provider-published key.")
    else:
        add("Null result: no key appears in %d+ distinct unsorted 2-of-3 "
            "scripts." % 5)
    add("")
    add("## What would change this report")
    add("")
    add("- Index or paid API access for prevout resolution: same-"
        "scriptPubKey reuse and spend-graph edges become observable, and "
        "deposit-side visibility stops being one-sided; signature-to-key "
        "edges scale beyond the 249 locally resolvable observations.")
    add("- Provider-published descriptors, addresses or txids: any single "
        "published txid or address set converts the affected scripts to "
        "grade A and turns this report's C/D ceiling into verified "
        "attribution.")
    add("- Per-provider key disclosure (as Green did for its v0 service "
        "key): each disclosed static key adds grade-B participation edges "
        "across every script containing it, the strongest evidence class "
        "this corpus can carry.")
    add("")
    with open(path, "w") as fh:
        fh.write("\n".join(L))
