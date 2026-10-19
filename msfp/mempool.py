"""mempool.space REST client.

Mirrors the Blockchair client's discipline (every request recorded and
cached; nothing ever downloaded twice) without a point budget: the
service is free and keyless, so politeness IS the budget. Defaults sit
at 1 request/second and 30/minute, far below any plausible limit; the
service documents rate limiting with HTTP 429 and possible bans for
repeated abuse, so a 429 is backed off a fixed 5/15/45-second ladder
and, if it persists, stops the run instead of pushing through.

Confirmed-transaction responses are immutable, so the gzip cache under
data/cache_mempool/ (keyed by URL path) is permanent and is never
invalidated.

Transport: curl is invoked per request instead of a Python HTTP
library. Measured on this host, Python TLS stacks (requests and raw
stdlib sockets) are tarpitted by the network path to mempool.space
(~70 s per response, sometimes minutes) while curl answers in ~0.25 s;
the limiter, ledger, retry ladder, and cache are transport-independent.
"""

import gzip
import hashlib
import json
import os
import subprocess
import time

from .ledger import utc_now_iso


class MempoolThrottled(Exception):
    """The service answered 429 past the full backoff ladder; stop the run."""

    def __init__(self, endpoint, tries):
        self.endpoint = endpoint
        self.tries = tries
        super().__init__(
            "mempool.space throttled %s after %d backoff attempts"
            % (endpoint, tries)
        )


class MempoolError(Exception):
    """A non-recoverable response that is not a throttle."""


# Backoff ladder for a 429, seconds. After the last rung the run stops.
THROTTLE_BACKOFFS = (5, 15, 45)
# Transient (network, 5xx) ladder: same shape; a persistent outage also stops.
TRANSIENT_BACKOFFS = (5, 15, 45)

CURL_MAX_TIME = 60


class MempoolLimiter:
    """Spacing-only limiter: a minimum gap between requests plus a
    per-minute window. No point accounting exists for this source."""

    def __init__(self, per_second, per_minute):
        self.per_second = per_second
        self.per_minute = per_minute
        self._recent = []
        self._next_ok = 0.0

    def wait_slot(self):
        now = time.monotonic()
        if now < self._next_ok:
            time.sleep(self._next_ok - now)
        now = time.monotonic()
        cutoff = now - 60.0
        self._recent = [t for t in self._recent if t > cutoff]
        if len(self._recent) >= self.per_minute:
            time.sleep(max(self._recent[0] + 60.0 - now, 0.0))
        self._recent.append(time.monotonic())
        self._next_ok = time.monotonic() + (1.0 / self.per_second)


class MempoolClient:
    def __init__(self, config, conn):
        self.config = config
        self.conn = conn
        self.base_url = config.mempool_base_url
        self.cache_dir = os.path.join(config.data_dir, "cache_mempool")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.limiter = MempoolLimiter(
            config.mempool_requests_per_second,
            config.mempool_requests_per_minute,
        )

    # -- core request path ---------------------------------------------------

    def get_json(self, endpoint_path, params=None):
        """Cached GET returning (data, cache_path).

        endpoint_path starts with '/'; the cache key is the URL path
        (plus sorted params when present). A cache hit makes no network
        request and leaves no ledger row; every request that does go
        out is recorded in mempool_ledger, throttle or not.
        """
        path = self._cache_path(endpoint_path, params)
        if os.path.exists(path):
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                return json.load(fh), path

        url = self.base_url + endpoint_path
        ladder = None
        for attempt in range(max(len(THROTTLE_BACKOFFS),
                                 len(TRANSIENT_BACKOFFS)) + 1):
            self.limiter.wait_slot()
            try:
                status, body = self._http_get(url)
            except OSError as exc:
                self._record(endpoint_path, None, note="network error: %s" % exc)
                if ladder is None:
                    ladder = TRANSIENT_BACKOFFS
                if attempt >= len(ladder):
                    raise MempoolError(
                        "network errors for %s after %d attempts"
                        % (url, attempt + 1))
                time.sleep(ladder[attempt])
                continue

            if status == 200:
                try:
                    payload = json.loads(body)
                except ValueError:
                    self._record(endpoint_path, status,
                                 note="200 with non-JSON body; stopping")
                    raise MempoolError("non-JSON 200 from %s" % url)
                with gzip.open(path, "wt", encoding="utf-8") as fh:
                    json.dump(payload, fh)
                self._record(endpoint_path, status)
                return payload, path

            if status == 429:
                self._record(endpoint_path, status,
                             note="429 throttle; attempt %d" % (attempt + 1))
                if attempt >= len(THROTTLE_BACKOFFS):
                    raise MempoolThrottled(endpoint_path, attempt)
                time.sleep(THROTTLE_BACKOFFS[attempt])
                continue

            if status >= 500:
                self._record(endpoint_path, status,
                             note="transient server error")
                if ladder is None:
                    ladder = TRANSIENT_BACKOFFS
                if attempt >= len(ladder):
                    raise MempoolError(
                        "HTTP %s for %s after %d attempts"
                        % (status, url, attempt + 1))
                time.sleep(ladder[attempt])
                continue

            self._record(endpoint_path, status, note="unexpected status")
            raise MempoolError("HTTP %s from %s: %s" % (status, url,
                                                        body[:200]))

        raise MempoolError("unreachable retry loop for %s" % url)

    # -- typed endpoints ------------------------------------------------------

    def tx(self, txid):
        data, _path = self.get_json("/tx/%s" % txid)
        return data

    def address_txs(self, address):
        data, _path = self.get_json("/address/%s/txs" % address)
        return data

    # -- internals -------------------------------------------------------------

    def _http_get(self, url):
        """One HTTP GET via curl. Returns (http_status, body_text).

        Raises OSError on transport failure (DNS, connect, timeout).
        """
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", str(CURL_MAX_TIME),
             "-A", "multisig-fingerprinting-study/1.0 (academic; "
                   "polite defaults)",
             "-w", "\n%{http_code}", url],
            capture_output=True, text=True, timeout=CURL_MAX_TIME + 15)
        if proc.returncode != 0:
            raise OSError("curl exit %d: %s"
                          % (proc.returncode, proc.stderr.strip()[:200]))
        body, _, status = proc.stdout.rpartition("\n")
        try:
            return int(status.strip()), body
        except ValueError:
            raise OSError("curl produced no status: %r" % proc.stdout[-80:])

    def _record(self, endpoint, http_status=None, note=None):
        self.conn.execute(
            "INSERT INTO mempool_ledger(ts_utc, endpoint, http_status, note) "
            "VALUES(?,?,?,?)",
            (utc_now_iso(), endpoint, http_status, note),
        )
        self.conn.commit()

    def _cache_path(self, endpoint_path, params):
        if params:
            key = "%s?%s" % (endpoint_path,
                             "&".join("%s=%s" % kv
                                      for kv in sorted(params.items())))
        else:
            key = endpoint_path
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        # Readable prefix for humans browsing the cache dir.
        safe = "".join(c if c.isalnum() or c in "._-" else "_"
                       for c in endpoint_path.strip("/"))[:60]
        return os.path.join(self.cache_dir, "%s_%s.json.gz" % (safe, digest))
