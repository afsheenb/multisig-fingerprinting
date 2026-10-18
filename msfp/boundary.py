"""Study-period block-height boundary pinning.

Binary-searches raw blocks for the first block whose header timestamp
is on or after the study start. Every probed block is cached and
recorded, so boundary pinning never wastes points on a refetch and
probed blocks inside the period can join the corpus.
"""

import datetime

from bitcoin.core import CBlock

from . import db
from .ledger import QuotaExhausted, Throttled

STUDY_START = datetime.datetime(
    2023, 10, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)


def _block_time_utc(raw_hex):
    block = CBlock.deserialize(bytes.fromhex(raw_hex))
    return datetime.datetime.fromtimestamp(
        block.nTime, datetime.timezone.utc)


def pin_boundary(config, conn):
    from .client import Client
    client = Client(config, conn)

    stats_payload, _cost, _path = client.stats(fresh=True)
    best = stats_payload["data"]["best_block_height"]
    db.set_meta(conn, "study_end_height", best)

    # Lower anchor: a height safely before the study start. Rough
    # arithmetic (10-minute blocks) puts 2023-10-18 near 812,600; start
    # the search well below that.
    lo, hi = 800_000, best
    # Establish the invariant time(lo) < STUDY_START.
    payload, _c, _p = client.raw_block(lo)
    t_lo = _block_time_utc(payload["data"][str(lo)]["raw_block"])
    if t_lo >= STUDY_START:
        raise RuntimeError("lower anchor %d is not before the study start "
                           "(%s)" % (lo, t_lo))

    while hi - lo > 1:
        mid = (lo + hi) // 2
        payload, _c, _p = client.raw_block(mid)
        t_mid = _block_time_utc(payload["data"][str(mid)]["raw_block"])
        print("probe %d -> %s" % (mid, t_mid.isoformat()))
        if t_mid < STUDY_START:
            lo = mid
        else:
            hi = mid

    db.set_meta(conn, "study_start_height", hi)
    payload, _c, _p = client.raw_block(hi)
    t_hi = _block_time_utc(payload["data"][str(hi)]["raw_block"])
    db.set_meta(conn, "study_start_block_hash", _header_hash(payload, hi))
    db.set_meta(conn, "study_start_block_time", t_hi.isoformat())
    print("study period: height %d (%s) .. %d (best at pin time)"
          % (hi, t_hi.isoformat(), best))


def _header_hash(payload, height):
    from bitcoin.core import b2lx
    block = CBlock.deserialize(
        bytes.fromhex(payload["data"][str(height)]["raw_block"]))
    return b2lx(block.GetHash())
