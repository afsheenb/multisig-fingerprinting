"""Command-line interface.

Commands map one-to-one onto the research phases:

    api-status             show quota ledger state and remaining budget
    probe                  Phase 0 endpoint validation probes
    pin-boundary           locate the study-period block-height boundary
    benchmark-acquisition  Phase 1: raw blocks vs indexed outputs
    scan --sample N        Phase 3: stratified block sampling + extraction
    scan --range S E       scan an explicit height range
    scan --resume          continue the recorded acquisition plan
    validate [--local]     resolve prevouts for a subset; verify commitments
                           and signatures where data allows (--local uses
                           only the corpus cache: zero points)
    validate --mempool     full verification against mempool.space-resolved
                           prevouts, taproot included
    classify               (re)classify stored scripts
    keyindex               build the public-key reuse index + components
    attribute              graded provider attribution against the registry
    report                 Phase 4: preliminary findings + cost report
    enrich                 behavioral enrichment pass over the buckets
    cohorts                anonymous key-anchored custody families (offline)
    corpus-status          corpus, cache size, disk budget
"""

import argparse
import json
import os
import sys

from .config import Config
from . import db


def _open():
    config = Config()
    os.makedirs(config.data_dir, exist_ok=True)
    conn = db.connect(config.db_path)
    return config, conn


def cmd_api_status(args):
    config, conn = _open()
    from .client import Client
    client = Client(config, conn)
    lim = client.limiter
    from .ledger import utc_day
    print("UTC day:            %s" % utc_day())
    print("Points used today:  %s / %s" % (lim.points_used_today(),
                                          config.points_per_day))
    print("Remaining points:   %s" % lim.remaining_points())
    print("Per-minute limit:   %s" % config.requests_per_minute)
    print("Per-second limit:   %s" % config.requests_per_second)
    print("API key configured: %s" % bool(config.api_key))


def cmd_corpus_status(args):
    config, conn = _open()
    cache_dir = os.path.join(config.data_dir, "cache")
    n_cache = len([f for f in os.listdir(cache_dir) if f.endswith(".json.gz")]) \
        if os.path.isdir(cache_dir) else 0
    cache_bytes = sum(os.path.getsize(os.path.join(cache_dir, f))
                      for f in os.listdir(cache_dir)) \
        if os.path.isdir(cache_dir) else 0
    db_bytes = os.path.getsize(config.db_path) if os.path.exists(config.db_path) else 0
    n_blocks = conn.execute("SELECT COUNT(*) c FROM blocks").fetchone()["c"]
    n_txs = conn.execute("SELECT COUNT(*) c FROM txs").fetchone()["c"]
    n_inputs = conn.execute("SELECT COUNT(*) c FROM inputs").fetchone()["c"]
    n_scripts = conn.execute("SELECT COUNT(*) c FROM revealed_scripts").fetchone()["c"]
    print("Blocks fetched:     %s" % n_blocks)
    print("Transactions:       %s" % n_txs)
    print("Inputs examined:    %s" % n_inputs)
    print("Revealed scripts:   %s" % n_scripts)
    print("Cache entries:      %s (%.1f MiB)" % (n_cache, cache_bytes / 1048576))
    print("DB size:            %.1f MiB" % (db_bytes / 1048576))


def cmd_probe(args):
    from .probes import run_probes
    config, conn = _open()
    stages = args.only.split(",") if args.only else None
    run_probes(config, conn, stages=stages)


def cmd_pin_boundary(args):
    from .boundary import pin_boundary
    config, conn = _open()
    pin_boundary(config, conn)


def cmd_benchmark(args):
    from .bench import run_benchmark
    config, conn = _open()
    run_benchmark(config, conn, blocks=args.blocks)


def cmd_scan(args):
    from .scan import run_scan
    config, conn = _open()
    run_scan(config, conn, sample=args.sample, height_range=args.range,
             resume=args.resume)


def cmd_validate(args):
    config, conn = _open()
    if args.local:
        from .verify import run_validation_local
        run_validation_local(config, conn)
        return
    if args.mempool:
        from .verify import run_validation_mempool
        from .mempool import MempoolThrottled
        try:
            run_validation_mempool(config, conn,
                                   count=args.count if args.count
                                   is not None else 1000)
        except MempoolThrottled as exc:
            print("mempool.space throttled: %s" % exc, file=sys.stderr)
            sys.exit(2)
        return
    from .verify import run_validation
    run_validation(config, conn, count=args.count if args.count is not None
                   else 25)


def cmd_classify(args):
    from .classify_cmd import run_classify
    config, conn = _open()
    run_classify(conn)


def cmd_keyindex(args):
    from .keyindex import run_keyindex
    config, conn = _open()
    run_keyindex(conn)


def cmd_attribute(args):
    from .attribute import run_attribute
    config, conn = _open()
    run_attribute(config, conn)


def cmd_report(args):
    from .report import run_report
    config, conn = _open()
    run_report(config, conn)


def cmd_enrich(args):
    from .enrich import run_enrich
    from .mempool import MempoolThrottled
    config, conn = _open()
    try:
        run_enrich(config, conn, steps=args.steps.split(",") if args.steps
                   else None, budget=args.budget,
                   verify_sample=args.verify_sample,
                   deposit_txs=args.deposit_txs,
                   deposit_addrs=args.deposit_addrs)
    except MempoolThrottled as exc:
        print("mempool.space throttled: %s" % exc, file=sys.stderr)
        sys.exit(2)


def cmd_cohorts(args):
    from .cohorts import analyze, write_outputs
    data, members = analyze(args.graph_dir, args.min_shared)
    write_outputs(data, members, args.out_dir)
    print("%d standard scripts; %d exact-key anonymous cohorts, report in %s" % (
        data["n_standard_multisig_scripts"],
        data["n_anonymous_key_cohorts"],args.out_dir))

def main(argv=None):
    parser = argparse.ArgumentParser(prog="msfp", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("api-status").set_defaults(func=cmd_api_status)
    sub.add_parser("corpus-status").set_defaults(func=cmd_corpus_status)
    p = sub.add_parser("probe")
    p.add_argument("--only", default=None,
                   help="comma-separated subset: stats,raw_block,dashboard,"
                        "outputs,transactions")
    p.set_defaults(func=cmd_probe)
    sub.add_parser("pin-boundary").set_defaults(func=cmd_pin_boundary)

    p = sub.add_parser("benchmark-acquisition")
    p.add_argument("--blocks", type=int, default=20)
    p.set_defaults(func=cmd_benchmark)

    p = sub.add_parser("scan")
    p.add_argument("--sample", type=int, default=None)
    p.add_argument("--range", nargs=2, type=int, default=None, metavar=("S", "E"))
    p.add_argument("--resume", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("validate")
    p.add_argument("--count", type=int, default=None,
                   help="sample size (default 1000 with --mempool, "
                        "25 for the Blockchair path)")
    p.add_argument("--local", action="store_true",
                   help="verify against the local corpus cache only; "
                        "zero points, no network requests")
    p.add_argument("--mempool", action="store_true",
                   help="resolve prevouts via the mempool.space REST API "
                        "and run full verification including taproot")
    p.set_defaults(func=cmd_validate)

    sub.add_parser("classify").set_defaults(func=cmd_classify)
    sub.add_parser("keyindex").set_defaults(func=cmd_keyindex)
    sub.add_parser("attribute").set_defaults(func=cmd_attribute)
    sub.add_parser("report").set_defaults(func=cmd_report)

    p = sub.add_parser("enrich")
    p.add_argument("--steps", default=None,
                   help="comma-separated subset: profiles,verify_sample,"
                        "deposits,crossover,onramp,report")
    p.add_argument("--budget", type=int, default=300,
                   help="cap on fresh mempool.space requests this run")
    p.add_argument("--verify-sample", type=int, default=10,
                   help="spend txs to verify per bucket whose validation "
                        "sample is empty")
    p.add_argument("--deposit-txs", type=int, default=20,
                   help="spend txs sampled per deposit-profiled bucket")
    p.add_argument("--deposit-addrs", type=int, default=20,
                   help="deposit addresses profiled per bucket")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("cohorts", help="offline anonymous provider-family detection from graph exports")
    p.add_argument("--graph-dir", default="reports/graph")
    p.add_argument("--out-dir", default="reports/cohorts")
    p.add_argument("--min-shared", type=int, default=5)
    p.set_defaults(func=cmd_cohorts)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("interrupted; progress is persisted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
