"""Phase 1 benchmark: acquisition strategies measured on the only metric
that matters: validated multisig scripts per request point.

Approach A: raw blocks (1 pt each), decode locally, count revealed
multisig scripts in the block window.

Approach B: indexed outputs queries for the same block window
(base cost documented 10 pts/page), counting rows that carry a
spending witness and look multisig. One row is cross-checked against
the raw spending transaction (1 pt) to verify the witness format.
"""

import json

from .ledger import QuotaExhausted, Throttled
from . import decode
from . import scripts as S


def _multisig_count_from_block(conn, client, height):
    payload, cost, _ = client.raw_block(height)
    try:
        block = decode.decode_block(payload["data"][str(height)]["raw_block"],
                                    height)
    except Exception as exc:  # oversized/undecodable block: count honestly
        return {"height": height, "cost": cost, "inputs": 0,
                "multisig_inputs": 0, "error": str(exc)}
    records = decode.extract_input_records(block, height)
    interesting = [r for r in records if r["input_form"] in (
        "p2sh_redeem", "p2wsh", "p2sh_p2wsh", "taproot_scriptpath")]
    return {"height": height, "cost": cost, "inputs": len(records),
            "multisig_inputs": len(interesting), "error": None}


def _indexed_window(conn, client, lo, hi):
    params = {
        "block": "%d..%d" % (lo, hi),
        "limit": 100,
        "offset": 0,
    }
    payload, cost, _ = client.indexed_outputs(params)
    rows = payload.get("data") or []
    ctx = payload.get("context", {})
    return {"rows": rows, "cost": cost, "context": ctx, "params": params}


def run_benchmark(config, conn, blocks=10):
    from .client import Client
    client = Client(config, conn)
    end = int(db_end(conn))
    lo = end - blocks

    results = {"approach_a": [], "approach_b": None}

    # Approach A
    a_points = 0
    a_multisig = 0
    a_inputs = 0
    try:
        for h in range(lo, end + 1):
            r = _multisig_count_from_block(conn, client, h)
            results["approach_a"].append(r)
            a_points += r["cost"]
            a_multisig += r["multisig_inputs"]
            a_inputs += r["inputs"]
            if r["error"]:
                print("block %d error: %s" % (h, r["error"]))
    except (QuotaExhausted, Throttled) as exc:
        print("approach A stopped early: %s" % exc)

    # Approach B: same window, one indexed-outputs page
    try:
        b = _indexed_window(conn, client, lo, end)
        rows = b["rows"]
        b_cost = b["cost"]
        fields = sorted(rows[0].keys()) if rows else []
        n_witness = sum(1 for r in rows if r.get("spending_witness"))
        results["approach_b"] = {
            "cost": b_cost, "rows": len(rows), "fields": fields,
            "rows_with_witness": n_witness, "context": b["context"],
        }
        # Cross-check one row against the raw spending transaction.
        for row in rows:
            stxid = row.get("spending_transaction_hash")
            if stxid and row.get("spending_witness"):
                raw_payload, raw_cost, _ = client.raw_transaction(stxid)
                tx_hex = (raw_payload["data"].get(stxid) or {}).get(
                    "raw_transaction", "")
                match = _compare_witness(row, tx_hex)
                results["approach_b"]["crosscheck"] = {
                    "txid": stxid, "extra_cost": raw_cost, "match": match}
                break
    except (QuotaExhausted, Throttled) as exc:
        print("approach B stopped: %s" % exc)
        b_cost = None

    # Verdict
    a_rate = (a_multisig / a_points) if a_points else 0
    print("\n=== acquisition benchmark (heights %d..%d) ===" % (lo, end))
    print("A raw blocks:      %d pts, %d inputs, %d multisig-bearing -> "
          "%.3f scripts/pt" % (a_points, a_inputs, a_multisig, a_rate))
    if results["approach_b"]:
        b = results["approach_b"]
        n_rows = b["rows"]
        print("B indexed outputs: %s pts, %d rows (%d with witness) -> "
              "%s pts/page" % (b["cost"], n_rows, b["rows_with_witness"],
                               b["cost"]))
        if "crosscheck" in b:
            print("  witness cross-check vs raw tx: %s" %
                  b["crosscheck"]["match"])
    import os
    os.makedirs("reports", exist_ok=True)
    with open("reports/benchmark.json", "w") as fh:
        json.dump(results, fh, indent=2, default=str)
    print("full results: reports/benchmark.json")


def db_end(conn):
    import sqlite3
    row = conn.execute("SELECT value FROM meta WHERE key='study_end_height'"
                       ).fetchone()
    return row["value"] if row else 0


def _compare_witness(row, tx_hex):
    """Compare an indexed-output spending_witness against the raw tx.

    The row's spending_witness should equal the witness stack of the
    input in the spending transaction that consumes the output the row
    describes (transaction_hash + transaction_index identify that
    output; spending_transaction_hash identifies the spender).
    """
    if not tx_hex:
        return "no raw tx fetched"
    from bitcoin.core import CTransaction, b2lx
    tx = CTransaction.deserialize(bytes.fromhex(tx_hex))
    spk_witness = row.get("spending_witness")
    if spk_witness is None:
        return "row carries no spending_witness"
    creating_txid = row.get("transaction_hash")
    vout = row.get("transaction_index")
    for idx, txin in enumerate(tx.vin):
        if b2lx(txin.prevout.hash) == creating_txid and \
                txin.prevout.n == vout:
            stack = []
            if tx.wit.vtxinwit and idx < len(tx.wit.vtxinwit):
                stack = [bytes(i).hex() for i in
                         tx.wit.vtxinwit[idx].scriptWitness.stack]
            raw_joined = json.dumps(stack)
            if isinstance(spk_witness, str):
                equal = spk_witness.strip() == raw_joined or \
                    spk_witness.strip() == "".join(stack)
                return {"equal": equal,
                        "indexed_field": str(spk_witness)[:200],
                        "raw_stack": raw_joined[:200]}
            return {"equal": None, "indexed_field_type":
                    type(spk_witness).__name__}
    return "prevout not found among spending tx inputs"
