"""Blockchair API client.

Every request: reserve estimated points -> rate-limit slot -> dispatch ->
reconcile against context.request_cost -> cache the raw response body to
disk (gzip) so nothing is ever downloaded twice.
"""

import gzip
import hashlib
import json
import os
import time

import requests

from .ledger import (
    QuotaExhausted,
    Throttled,
    IpBlocked,
    RateLimiter,
    MAX_TRANSIENT_RETRIES,
    QUOTA_STATUSES,
    TRANSIENT_STATUSES,
    STOP_STATUSES,
)


class Client:
    def __init__(self, config, conn):
        self.config = config
        self.conn = conn
        self.cache_dir = os.path.join(config.data_dir, "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.limiter = RateLimiter(
            conn,
            config.points_per_day,
            config.requests_per_minute,
            config.requests_per_second,
        )
        self.session = requests.Session()
        if config.api_key:
            self.session.headers["X-Key"] = config.api_key

    # -- endpoint helpers ---------------------------------------------------

    def cost_estimate(self, endpoint):
        return self.config.costs.get(endpoint, self.config.costs["unknown"])

    def get_json(self, endpoint_path, cache_key, endpoint_cost_name, params=None,
                 fresh=False):
        """Cached GET returning (data, request_cost, cache_path).

        cache_key must be stable for the same logical request so restarts
        and reruns never re-download the same thing. With fresh=True the
        cache-read branch is skipped, for endpoints whose answer must
        reflect the provider's current state (e.g. stats); a fresh
        request still overwrites the cache and is recorded normally.
        """
        path = self._cache_path(cache_key)
        if not fresh and os.path.exists(path):
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                body = json.load(fh)
            # Cached responses carry their reconciled cost.
            cost = body.get("__request_cost", 0)
            return body, cost, path

        estimated = self.cost_estimate(endpoint_cost_name)
        self.limiter.check_budget(estimated)
        url = self.config.base_url + endpoint_path

        backoff = 2.0
        last_error = None
        for _attempt in range(MAX_TRANSIENT_RETRIES + 1):
            self.limiter._wait_slot()
            try:
                resp = self.session.get(url, params=params or {}, timeout=60)
            except requests.RequestException as exc:
                last_error = exc
                time.sleep(backoff)
                backoff *= 2
                continue

            status = resp.status_code
            if status == 200:
                try:
                    payload = resp.json()
                except ValueError:
                    self._record(endpoint_path, params, status, estimated,
                                 estimated,
                                 note="200 with non-JSON body; treating as %s pts"
                                      % estimated)
                    raise IpBlocked(
                        "non-JSON 200 response from %s; stopping for "
                        "investigation" % url
                    )
                cost = _request_cost(payload, default=estimated)
                # Cache with the reconciled cost embedded.
                payload["__request_cost"] = cost
                payload["__url"] = resp.url
                with gzip.open(path, "wt", encoding="utf-8") as fh:
                    json.dump(payload, fh)
                self._record(endpoint_path, params, status, estimated, cost)
                return payload, cost, path

            if status in QUOTA_STATUSES:
                retry_after = resp.headers.get("Retry-After")
                self._record(endpoint_path, params, status, estimated, estimated,
                             note="quota/limit error; NOT retried")
                raise Throttled(status, retry_after)

            if status in STOP_STATUSES:
                self._record(endpoint_path, params, status, estimated, estimated,
                             note="unexpected status; stopping acquisition")
                raise IpBlocked("HTTP %s from %s" % (status, url))

            if status in TRANSIENT_STATUSES:
                self._record(endpoint_path, params, status, estimated, estimated,
                             note="transient error, backoff %.0fs" % backoff)
                time.sleep(backoff)
                backoff *= 2
                continue

            self._record(endpoint_path, params, status, estimated, estimated,
                         note="unexpected status; not retried")
            raise RuntimeError(
                "unexpected HTTP %s from %s: %s" % (status, url, resp.text[:200])
            )

        raise RuntimeError(
            "exhausted %d transient retries for %s (%s)"
            % (MAX_TRANSIENT_RETRIES, url, last_error)
        )

    # -- typed endpoints ----------------------------------------------------

    def raw_block(self, height):
        payload, cost, path = self.get_json(
            "/bitcoin/raw/block/%d" % height,
            cache_key="raw_block_%d" % height,
            endpoint_cost_name="raw_block",
        )
        return payload, cost, path

    def raw_transaction(self, txid):
        payload, cost, path = self.get_json(
            "/bitcoin/raw/transaction/%s" % txid,
            cache_key="raw_tx_%s" % txid,
            endpoint_cost_name="raw_transaction",
        )
        return payload, cost, path

    def dashboard_block(self, heights):
        key = ",".join(str(h) for h in heights)
        payload, cost, path = self.get_json(
            "/bitcoin/dashboards/block/%s" % key,
            cache_key="dash_block_%s" % hashlib.sha256(key.encode()).hexdigest()[:16],
            endpoint_cost_name="dashboard_block",
        )
        return payload, cost, path

    def dashboard_transaction(self, txid):
        payload, cost, path = self.get_json(
            "/bitcoin/dashboards/transaction/%s" % txid,
            cache_key="dash_tx_%s" % txid,
            endpoint_cost_name="dashboard_transaction",
        )
        return payload, cost, path

    def indexed_outputs(self, params):
        return self.get_json(
            "/bitcoin/outputs",
            cache_key="outputs_%s" % hashlib.sha256(
                json.dumps(params, sort_keys=True).encode()).hexdigest()[:16],
            endpoint_cost_name="indexed_outputs",
            params=params,
        )

    def indexed_transactions(self, params):
        return self.get_json(
            "/bitcoin/transactions",
            cache_key="txs_%s" % hashlib.sha256(
                json.dumps(params, sort_keys=True).encode()).hexdigest()[:16],
            endpoint_cost_name="indexed_transactions",
            params=params,
        )

    def stats(self, fresh=False):
        return self.get_json(
            "/bitcoin/stats",
            cache_key="stats",
            endpoint_cost_name="stats",
            fresh=fresh,
        )

    # -- internals ----------------------------------------------------------

    def _record(self, endpoint, params, status, estimated, actual, note=None):
        self.limiter.record(endpoint, json.dumps(params or {}, sort_keys=True),
                            status, estimated, actual, note)

    def _cache_path(self, cache_key):
        return os.path.join(self.cache_dir, "%s.json.gz" % cache_key)


def _request_cost(payload, default):
    """context.request.cost is authoritative; fall back conservatively."""
    try:
        cost = payload["context"]["request"]["cost"]
        if cost is not None:
            return float(cost)
    except (KeyError, TypeError, ValueError):
        pass
    return default
