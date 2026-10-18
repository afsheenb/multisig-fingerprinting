"""Shared API rate limiter and request-point ledger.

All Blockchair traffic goes through exactly one RateLimiter instance.
Points are reserved BEFORE a request is dispatched and reconciled
against the authoritative context.request_cost afterwards. The ledger
is persisted in SQLite; the daily budget is recomputed from it at
startup so a process restart can never reset apparent usage.

Quota-style HTTP errors are never blindly retried. Transient 500/503
get bounded exponential backoff. Anything that smells like an IP block
stops automatic acquisition entirely.
"""

import datetime
import time
import threading

# HTTP statuses Blockchair documents for quota/limit conditions.
QUOTA_STATUSES = {402, 429, 430, 434, 435, 436, 437}
TRANSIENT_STATUSES = {500, 503}
# Unexpected/unknown; stop and investigate rather than probing.
STOP_STATUSES = {403}
MAX_TRANSIENT_RETRIES = 4


def utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def utc_day():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


class QuotaExhausted(Exception):
    """The daily point budget is gone; stop acquisition for this UTC day."""


class Throttled(Exception):
    """The provider throttled us; stop the stream, resume only when allowed."""

    def __init__(self, status, retry_after=None):
        self.status = status
        self.retry_after = retry_after
        super().__init__(
            "throttled with HTTP %s (retry_after=%s)" % (status, retry_after)
        )


class IpBlocked(Exception):
    """Do not attempt to circumvent; stop and surface to the operator."""


class RateLimiter:
    def __init__(self, conn, points_per_day, per_minute, per_second):
        self.conn = conn
        self.points_per_day = points_per_day
        self.per_minute = per_minute
        self.per_second = per_second
        self._lock = threading.Lock()
        self._recent = []  # (monotonic_time, ) of dispatched requests
        self._next_ok = 0.0

    def points_used_today(self):
        """Reconciled consumption (actual where known)."""
        day = utc_day()
        row = self.conn.execute(
            "SELECT COALESCE(SUM(actual_cost), 0) AS s "
            "FROM api_ledger WHERE substr(ts_utc, 1, 10) = ?",
            (day,),
        ).fetchone()
        return row["s"]

    def points_reserved_today(self):
        """In-flight estimates not yet reconciled against request_cost."""
        day = utc_day()
        row = self.conn.execute(
            "SELECT COALESCE(SUM(estimated_cost), 0) AS s "
            "FROM api_ledger WHERE substr(ts_utc, 1, 10) = ? "
            "AND actual_cost IS NULL",
            (day,),
        ).fetchone()
        return row["s"]

    def remaining_points(self):
        return self.points_per_day - self.points_used_today()

    def _wait_slot(self):
        now = time.monotonic()
        if now < self._next_ok:
            time.sleep(self._next_ok - now)
        with self._lock:
            now = time.monotonic()
            cutoff_min = now - 60.0
            self._recent = [t for t in self._recent if t > cutoff_min]
            if len(self._recent) >= self.per_minute:
                wait = self._recent[0] + 60.0 - now
                time.sleep(max(wait, 0.0))
            self._recent.append(time.monotonic())
            self._next_ok = time.monotonic() + (1.0 / self.per_second)

    def check_budget(self, estimated_cost):
        """Refuse to proceed if the projected cost exceeds the remaining budget."""
        projected = self.points_used_today() + self.points_reserved_today() \
            + estimated_cost
        if projected > self.points_per_day:
            raise QuotaExhausted(
                "projected points %s (used %s + reserved %s + new %s) would "
                "exceed the daily budget of %s; stopping for %s"
                % (projected, self.points_used_today(),
                   self.points_reserved_today(), estimated_cost,
                   self.points_per_day, utc_day())
            )

    def record(self, endpoint, params, http_status, estimated_cost, actual_cost,
               note=None):
        self.conn.execute(
            "INSERT INTO api_ledger(ts_utc, endpoint, params, http_status, "
            "estimated_cost, actual_cost, note) VALUES(?,?,?,?,?,?,?)",
            (utc_now_iso(), endpoint, params, http_status, estimated_cost,
             actual_cost, note),
        )
        self.conn.commit()
