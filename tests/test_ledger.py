"""Ledger / rate limiter tests: budget accounting survives restarts,
reservations gate dispatch, and quota statuses never retry."""

import datetime

import pytest

from msfp import db as msfp_db
from msfp.ledger import RateLimiter, QuotaExhausted, utc_day


@pytest.fixture
def conn(tmp_path):
    return msfp_db.connect(str(tmp_path / "t.sqlite3"))


def test_budget_exhaustion(conn):
    lim = RateLimiter(conn, points_per_day=10, per_minute=20, per_second=5)
    lim.check_budget(5)
    for i in range(10):
        lim.record("test", None, 200, 1, 1)
    with pytest.raises(QuotaExhausted):
        lim.check_budget(1)
    assert lim.remaining_points() == 0


def test_ledger_survives_restart(conn):
    lim = RateLimiter(conn, 100, 20, 5)
    lim.record("raw_block", None, 200, 1, 1)
    # A "restart": fresh limiter over the same DB.
    lim2 = RateLimiter(conn, 100, 20, 5)
    assert lim2.points_used_today() == 1
    lim2.check_budget(99)
    with pytest.raises(QuotaExhausted):
        lim2.check_budget(100)


def test_reservation_counts_toward_budget(conn):
    lim = RateLimiter(conn, 10, 20, 5)
    lim.record("indexed_outputs", None, None, 10, None)  # reserved, in flight
    # Reserved-but-unreconciled points still count against the budget.
    with pytest.raises(QuotaExhausted):
        lim.check_budget(1)


def test_reconciliation_uses_actual_cost(conn):
    lim = RateLimiter(conn, 10, 20, 5)
    lim.record("raw_block", None, 200, 5, 1)  # estimated 5, actual 1
    assert lim.points_used_today() == 1
    lim.check_budget(9)
    with pytest.raises(QuotaExhausted):
        lim.check_budget(10)


def test_rolling_minute_window(conn):
    lim = RateLimiter(conn, 1000, per_minute=2, per_second=100)
    lim._wait_slot()
    lim._wait_slot()
    assert len(lim._recent) == 2
    # Simulate an old request dropping out of the window.
    import time
    lim._recent[0] = time.monotonic() - 61
    lim._wait_slot()
    assert len([t for t in lim._recent if t > time.monotonic() - 60]) == 2
