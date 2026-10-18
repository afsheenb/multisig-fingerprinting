"""Re-run classification over stored revealed scripts.

Used after classifier improvements so the corpus is re-labeled without
spending any request points (classification is local).
"""

from . import scripts as S


def run_classify(conn):
    rows = conn.execute("SELECT script_sha256, script_hex, source "
                        "FROM revealed_scripts").fetchall()
    updated = 0
    for r in rows:
        tapscript = r["source"] == "taproot_leaf"
        a = S.analyze_script(bytes.fromhex(r["script_hex"]), tapscript)
        conn.execute(
            "UPDATE revealed_scripts SET script_class=?, family_l4=?, "
            "template_l2=?, template_l3=?, threshold=?, n_keys=?, "
            "keys_sorted=? WHERE script_sha256=?",
            (a["script_class"], a["family_l4"], a["template_l2"],
             a["template_l3"], a["threshold"], a["n_keys"], a["keys_sorted"],
             r["script_sha256"]))
        updated += 1
    conn.commit()
    print("reclassified %d revealed scripts (0 request points)" % updated)
