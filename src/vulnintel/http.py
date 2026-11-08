"""HTTP session with retries, backoff and a client-side rate limiter."""

from __future__ import annotations

import logging
import time
from collections import deque

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

USER_AGENT = "vulnintel-warehouse/0.1 (portfolio project)"


def make_session() -> requests.Session:
    retry = Retry(
        total=6,
        backoff_factor=2,  # 2, 4, 8, 16 ... seconds
        status_forcelist=(403, 429, 500, 502, 503, 504),  # NVD answers 403 when throttling
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers["User-Agent"] = USER_AGENT
    return session


class RateLimiter:
    """At most `max_calls` in any rolling `period` seconds (NVD: 5/30s, or 50/30s with a key)."""

    def __init__(self, max_calls: int, period: float, clock=time.monotonic, sleep=time.sleep):
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()
        self._clock = clock
        self._sleep = sleep

    def wait(self) -> None:
        now = self._clock()
        while self._calls and now - self._calls[0] >= self.period:
            self._calls.popleft()
        if len(self._calls) >= self.max_calls:
            delay = self.period - (now - self._calls[0]) + 0.1
            log.debug("rate limit: sleeping %.1fs", delay)
            self._sleep(delay)
            now = self._clock()
            self._calls.popleft()
        self._calls.append(now)
