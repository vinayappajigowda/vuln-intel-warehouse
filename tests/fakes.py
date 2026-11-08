"""Offline stand-ins for the HTTP session, driven by files in tests/fixtures/api."""

from __future__ import annotations

import json
from pathlib import Path

API = Path(__file__).parent / "fixtures" / "api"


class FakeResponse:
    def __init__(self, status: int, content: bytes = b""):
        self.status_code = status
        self.content = content

    def json(self):
        return json.loads(self.content)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Routes NVD / EPSS / KEV URLs to fixture files and records every call."""

    def __init__(self, nvd_pages: list[str] | None = None, nvd_failures: dict | None = None):
        self.calls: list[tuple[str, dict, dict]] = []
        self.nvd_pages = list(nvd_pages or ["nvd_full_page1.json", "nvd_full_page2.json"])
        # {nvd call number (0-based): exception to raise instead of answering}
        self.nvd_failures = dict(nvd_failures or {})
        self._nvd_calls = 0

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, dict(params or {}), dict(headers or {})))
        if "services.nvd.nist.gov" in url:
            n = self._nvd_calls
            self._nvd_calls += 1
            if n in self.nvd_failures:
                raise self.nvd_failures[n]
            if not self.nvd_pages:
                return FakeResponse(200, json.dumps({"totalResults": 0, "vulnerabilities": []}).encode())
            return FakeResponse(200, (API / self.nvd_pages.pop(0)).read_bytes())
        if "epss" in url:
            f = API / url.rsplit("/", 1)[1]
            return FakeResponse(200, f.read_bytes()) if f.exists() else FakeResponse(404)
        if "known_exploited" in url:
            return FakeResponse(200, (API / "kev.json").read_bytes())
        return FakeResponse(404)


class NoWaitLimiter:
    def wait(self):
        pass
