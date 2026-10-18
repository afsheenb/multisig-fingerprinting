"""Public-key reuse index and sharing components.

The index answers section-10 questions with exact byte matching only:

    pubkey -> distinct scripts, observations, co-signing key sets,
    templates, first/last seen.

Four cases are kept apart (do NOT conflate):

    1. one script used repeatedly        (n_scripts == 1, obs high)
    2. one scriptPubKey reused           (not detectable here without
                                          prevout spks; noted honestly)
    3. different scripts, same key       (the cross-wallet signal)
    4. different scripts, several shared keys (stronger signal)

Components are connected by UNION of shared keys within distinct
scripts; template-only similarity contributes nothing.
"""

import json

from . import db


def run_keyindex(conn, min_scripts=2, top=100):
    """Build key_reuse view data and write reports/key_reuse.json."""
    # pubkey -> distinct scripts containing it
    rows = conn.execute(
        "SELECT k.pubkey_hex, COUNT(DISTINCT k.script_sha256) AS n_scripts, "
        "MIN(s.first_seen_height) AS first_seen, "
        "MAX(s.last_seen_height) AS last_seen, "
        "COUNT(DISTINCT s.template_l3) AS n_templates "
        "FROM script_keys k JOIN revealed_scripts s "
        "ON s.script_sha256=k.script_sha256 "
        "GROUP BY k.pubkey_hex ORDER BY n_scripts DESC LIMIT ?",
        (top,)).fetchall()

    entries = []
    for r in rows:
        if r["n_scripts"] < min_scripts:
            break
        scripts = conn.execute(
            "SELECT DISTINCT k.script_sha256, s.script_class, s.family_l4, "
            "s.template_l3, s.threshold, s.n_keys, s.first_seen_height, "
            "s.last_seen_height FROM script_keys k JOIN revealed_scripts s "
            "ON s.script_sha256=k.script_sha256 WHERE k.pubkey_hex=?",
            (r["pubkey_hex"],)).fetchall()
        # Distinct co-signing key sets across those scripts.
        keysets = set()
        for sc in scripts:
            others = conn.execute(
                "SELECT pubkey_hex FROM script_keys WHERE script_sha256=?",
                (sc["script_sha256"],)).fetchall()
            keysets.add(frozenset(o["pubkey_hex"] for o in others))
        entries.append({
            "pubkey": r["pubkey_hex"],
            "n_distinct_scripts": r["n_scripts"],
            "n_distinct_templates": r["n_templates"],
            "n_distinct_cosigner_sets": len(keysets),
            "first_seen_height": r["first_seen"],
            "last_seen_height": r["last_seen"],
            "scripts": [dict(sc) for sc in scripts],
        })

    # Union-find components over shared keys in distinct scripts.
    parent = {}
    def find(a):
        while parent.setdefault(a, a) != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    script_of = {}
    for e in entries:
        for sc in e["scripts"]:
            union(("k", e["pubkey"]), ("s", sc["script_sha256"]))
            script_of[sc["script_sha256"]] = sc

    components = {}
    for node in parent:
        components.setdefault(find(node), []).append(node)
    comp_sizes = {}
    for root, nodes in components.items():
        keys = [n[1] for n in nodes if n[0] == "k"]
        if len(keys) >= 2:
            comp_sizes[root] = {"n_keys": len(keys),
                                "n_scripts": len(nodes) - len(keys)}

    out = {
        "top_reused_keys": entries,
        "n_shared_components_2plus": len(comp_sizes),
        "largest_components": sorted(
            comp_sizes.values(),
            key=lambda c: (-c["n_keys"], -c["n_scripts"]))[:20],
        "note": "exact byte matching only; case 2 (scriptPubKey reuse) is "
                "not observable without prevout resolution; sharing a key "
                "establishes the key relationship, never the owner",
    }
    import os
    os.makedirs("reports", exist_ok=True)
    with open("reports/key_reuse.json", "w") as fh:
        json.dump(out, fh, indent=2, default=str)
    print("key index: %d keys in 2+ distinct scripts, %d shared components"
          % (len(entries), len(comp_sizes)))
    return out
