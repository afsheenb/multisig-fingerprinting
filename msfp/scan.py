"""Corpus acquisition: sampling plan, block fetching, extraction, storage.

Every fetched block is stored once (blocks table + gzip cache), every
transaction and input is recorded, and every input that reveals a
script is classified and deduplicated into revealed_scripts. Progress
is committed per block, so an interrupted run resumes exactly.
"""

import json
import random
import time

from .ledger import QuotaExhausted, Throttled
from . import decode
from . import scripts as S
from . import db


STUDY_START_UTC = "2023-10-18 00:00:00"


def _ensure_boundary(config, conn, client):
    from .boundary import pin_boundary
    start = db.get_meta(conn, "study_start_height")
    end = db.get_meta(conn, "study_end_height")
    if start is None or end is None:
        pin_boundary(config, conn)
    return (int(db.get_meta(conn, "study_start_height")),
            int(db.get_meta(conn, "study_end_height")))


def build_plan(conn, start, end, n_blocks, seed, include_cache=True):
    """Stratified sampling: regular stride + seeded random offsets.

    The plan covers the whole study period, front-loading nothing.
    Cached blocks (from boundary pinning) are folded in so nothing
    already on disk gets re-requested.
    """
    span = end - start
    stride = span // n_blocks
    rng = random.Random(seed)
    heights = []
    for i in range(n_blocks):
        base = start + i * stride
        heights.append(min(base + rng.randrange(stride), end))
    # Regularly spaced control blocks (every 10th slot, no jitter).
    for i in range(0, n_blocks, 10):
        heights[i] = start + i * stride
    have = {r["height"] for r in conn.execute(
        "SELECT height FROM blocks")}
    for h in sorted(set(heights)):
        if h in have:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO plan(height, strategy) VALUES(?, 'random')",
            (h,))
    conn.commit()


def store_block(conn, height, payload):
    """Decode + store one raw-block payload. Returns input record count."""
    data = payload["data"].get(str(height)) or \
        payload["data"].get(height) or {}
    raw_hex = data.get("raw_block")
    if not raw_hex:
        raise RuntimeError("payload for height %s carries no raw_block" % height)
    block = decode.decode_block(raw_hex, height)
    header = decode.block_header(block)
    conn.execute(
        "INSERT OR REPLACE INTO blocks(height, hash, block_time, n_tx, "
        "fetched_utc, raw_bytes, request_cost) VALUES(?,?,?,?,?,?,?)",
        (height, header["hash"], header["time"], header["n_tx"],
         _now(), len(raw_hex) // 2, payload.get("__request_cost")))
    records = decode.extract_input_records(block, height)
    conn.executemany(
        "INSERT OR IGNORE INTO txs(txid, block_height, version, locktime, "
        "n_inputs, n_outputs, block_time) VALUES(?,?,?,?,?,?,?)",
        [(r["txid"], height, r["tx_version"], r["tx_locktime"],
          r["n_tx_inputs"], r["n_tx_outputs"], r["block_time"])
         for r in records])
    conn.executemany(
        "INSERT OR IGNORE INTO inputs(txid, input_index, block_height, "
        "block_time, prevout_txid, prevout_n, sequence, script_sig_hex, "
        "witness_json, input_form) VALUES(?,?,?,?,?,?,?,?,?,?)",
        [(r["txid"], r["input_index"], r["block_height"], r["block_time"],
          r["prevout_txid"], r["prevout_n"], r["sequence"],
          r["script_sig_hex"], r["witness_json"], r["input_form"])
         for r in records])
    _store_revealed_scripts(conn, records)
    conn.commit()
    return len(records), header


def _store_revealed_scripts(conn, records):
    """Classify + dedupe revealed scripts, link observations."""
    for record in records:
        source, raw = decode.revealed_script_for_input(record)
        if source is None:
            continue
        analysis = S.analyze_script(raw, tapscript=(source == "taproot_leaf"))
        sha = analysis["script_sha256"]
        conn.execute(
            "INSERT OR IGNORE INTO revealed_scripts(script_sha256, "
            "script_hex, source, script_class, family_l4, template_l2, "
            "template_l3, threshold, n_keys, keys_sorted, first_seen_height) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (sha, analysis["script_hex"], source, analysis["script_class"],
             analysis["family_l4"], analysis["template_l2"],
             analysis["template_l3"], analysis["threshold"],
             analysis["n_keys"], analysis["keys_sorted"],
             record["block_height"]))
        conn.execute(
            "UPDATE revealed_scripts SET last_seen_height=?, "
            "n_observations=n_observations+1 WHERE script_sha256=?",
            (record["block_height"], sha))
        for pos, key in enumerate(analysis.get("pubkeys", [])):
            conn.execute(
                "INSERT OR IGNORE INTO script_keys(script_sha256, "
                "pubkey_hex, position) VALUES(?,?,?)",
                (sha, key.hex(), pos))
        input_id = conn.execute(
            "SELECT input_id FROM inputs WHERE txid=? AND input_index=?",
            (record["txid"], record["input_index"])).fetchone()["input_id"]
        conn.execute(
            "INSERT OR REPLACE INTO script_observations(input_id, "
            "script_sha256, n_signatures, sighash_types, executed_branch) "
            "VALUES(?,?,?,?,?)",
            (input_id, sha, record["n_signatures"],
             record["sighash_types"], decode.executed_branch(record)))


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


def run_scan(config, conn, sample=None, height_range=None, resume=False):
    from .client import Client
    client = Client(config, conn)

    if height_range:
        lo, hi = height_range
        heights = list(range(lo, hi + 1))
    else:
        start, end = _ensure_boundary(config, conn, client)
        if sample is not None:
            build_plan(conn, start, end, sample, config.random_seed)
        heights = [r["height"] for r in conn.execute(
            "SELECT height FROM plan WHERE done=0 ORDER BY height")]

    done = 0
    throttles = 0
    total_inputs = 0
    for height in heights:
        already = conn.execute("SELECT 1 FROM blocks WHERE height=?",
                               (height,)).fetchone()
        if already:
            conn.execute("UPDATE plan SET done=1 WHERE height=?", (height,))
            conn.commit()
            continue
        try:
            payload, cost, _ = client.raw_block(height)
        except QuotaExhausted as exc:
            print("STOP: %s" % exc)
            print("progress persisted; rerun with scan --resume "
                  "(or tomorrow's UTC budget)")
            break
        except Throttled as exc:
            throttles += 1
            print("THROTTLED (HTTP %s): cooling down %ss"
                  % (exc.status, config.throttle_cooldown_seconds))
            if throttles > config.max_throttles_per_run:
                print("too many throttles; stopping. progress persisted.")
                break
            time.sleep(config.throttle_cooldown_seconds)
            try:
                payload, cost, _ = client.raw_block(height)
            except (QuotaExhausted, Throttled) as exc2:
                print("STOP after cooldown: %s" % exc2)
                break

        n_inputs, header = store_block(conn, height, payload)
        conn.execute("UPDATE plan SET done=1 WHERE height=?", (height,))
        conn.commit()
        done += 1
        total_inputs += n_inputs
        if done % 10 == 0:
            print("scanned %d blocks (latest %d, %s); inputs %d; points left %s"
                  % (done, height, header["time"], total_inputs,
                     client.limiter.remaining_points()))
    print("scan finished: %d new blocks, %d inputs" % (done, total_inputs))
