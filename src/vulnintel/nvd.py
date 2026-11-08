"""NVD CVE API 2.0 -> landing zone, incremental on lastModified.

API rules this code respects (https://nvd.nist.gov/developers):
  * base URL https://services.nvd.nist.gov/rest/json/cves/2.0
  * API key goes in the `apiKey` request header
  * lastModStartDate and lastModEndDate must be given together, max 120-day window
  * resultsPerPage max 2000, paginate with startIndex
  * 5 requests / rolling 30 s without a key, 50 with one

First run (no watermark): full load with no date filter (~300K CVEs).
Later runs: everything modified since the last watermark, minus a small overlap so a record
modified while the previous run was in flight is not missed. Duplicates are expected and are
removed in dbt (latest version per CVE wins).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import requests

from .config import Settings
from .http import RateLimiter, make_session
from .landing import batch_id_for, publish_dir, utcnow, write_ndjson
from .state import StateStore

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=120)
OVERLAP = timedelta(minutes=30)
STATE_KEY = "nvd.last_mod_end"
CHECKPOINT_KEY = "nvd.in_progress"


def _fmt(ts: datetime) -> str:
    # e.g. 2026-11-08T02:00:00.000+00:00 (requests URL-encodes the '+')
    return ts.isoformat(timespec="milliseconds")


def windows(start: datetime, end: datetime, size: timedelta = MAX_WINDOW):
    """Split [start, end) into <=120-day windows (NVD rejects anything longer)."""
    cur = start
    while cur < end:
        nxt = min(cur + size, end)
        yield cur, nxt
        cur = nxt


TRANSIENT_ERRORS = (
    requests.exceptions.ConnectionError,  # includes dropped connections and resets
    requests.exceptions.ChunkedEncodingError,  # "Response ended prematurely"
    requests.exceptions.Timeout,
    ValueError,  # truncated / non-JSON body
)
MAX_PAGE_ATTEMPTS = 6


def get_page(
    session: requests.Session,
    limiter: RateLimiter,
    params: dict,
    headers: dict,
    sleep=time.sleep,
) -> dict:
    """One API page, retried on network-level failures.

    urllib3's Retry covers HTTP status codes (403/429/5xx). It does not cover a connection that
    drops while the body is being read, which NVD does from time to time on large pages.
    """
    for attempt in range(1, MAX_PAGE_ATTEMPTS + 1):
        limiter.wait()
        try:
            resp = session.get(NVD_URL, params=params, headers=headers, timeout=120)
            resp.raise_for_status()
            return resp.json()
        except TRANSIENT_ERRORS as exc:
            if attempt == MAX_PAGE_ATTEMPTS:
                raise
            delay = min(10 * 2 ** (attempt - 1), 300)
            log.warning(
                "nvd startIndex=%s attempt %s/%s failed (%s), retrying in %ss",
                params.get("startIndex"),
                attempt,
                MAX_PAGE_ATTEMPTS,
                type(exc).__name__,
                delay,
            )
            sleep(delay)
    raise AssertionError("unreachable")


def fetch_pages(
    session: requests.Session,
    limiter: RateLimiter,
    api_key: str | None,
    window: tuple[datetime, datetime] | None,
    start_index: int = 0,
    sleep=time.sleep,
) -> Iterator[tuple[int, list[dict]]]:
    """Yield (start_index, vulnerabilities) for each page, starting at `start_index`."""
    headers = {"apiKey": api_key} if api_key else {}
    while True:
        params: dict = {"startIndex": start_index, "resultsPerPage": PAGE_SIZE}
        if window:
            params["lastModStartDate"] = _fmt(window[0])
            params["lastModEndDate"] = _fmt(window[1])
        body = get_page(session, limiter, params, headers, sleep=sleep)
        vulns = body.get("vulnerabilities", [])
        total = body.get("totalResults", 0)
        log.info("nvd page startIndex=%s got=%s total=%s", start_index, len(vulns), total)
        if not vulns:
            return
        yield start_index, vulns
        start_index += len(vulns)
        if start_index >= total:
            return


def to_record(item: dict, batch_id: str, ingested_at: str) -> dict:
    cve = item["cve"]
    return {
        "cve_id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "payload": json.dumps(cve, separators=(",", ":")),  # keep the full record, parse in dbt
        "_batch_id": batch_id,
        "_ingested_at": ingested_at,
    }


def _plan(state: StateStore, run_ts: datetime, full_refresh: bool) -> dict:
    watermark = None if full_refresh else state.get(STATE_KEY)
    if watermark:
        start = datetime.fromisoformat(watermark) - OVERLAP
        wins = [[a.isoformat(), b.isoformat()] for a, b in windows(start, run_ts)]
        mode = "incremental"
    else:
        wins = [None]
        mode = "full"
    return {
        "run_ts": run_ts.isoformat(),
        "batch_id": batch_id_for(run_ts),
        "mode": mode,
        "windows": wins,
        "window_idx": 0,
        "start_index": 0,
        "part": 0,
        "records": 0,
    }


def ingest(
    settings: Settings,
    session: requests.Session | None = None,
    limiter: RateLimiter | None = None,
    now: datetime | None = None,
    full_refresh: bool = False,
    sleep=time.sleep,
) -> dict:
    """Land NVD records. Checkpoints after every page, so an interrupted run resumes.

    The checkpoint (state key `nvd.in_progress`) stores the batch, window and next startIndex.
    Re-running after a crash continues the same batch instead of starting the ~420K download over.
    """
    session = session or make_session()
    if not settings.nvd_api_key:
        log.warning("NVD_API_KEY not set: limited to 5 requests / 30 s (a full load takes ~25 min)")
    limiter = limiter or RateLimiter(50 if settings.nvd_api_key else 5, 30.0)
    state = StateStore(settings.state_file)

    ckpt = None if full_refresh else state.get(CHECKPOINT_KEY)
    if ckpt:
        log.info(
            "resuming nvd %s load, batch %s, from startIndex=%s (%s records already landed)",
            ckpt["mode"],
            ckpt["batch_id"],
            ckpt["start_index"],
            ckpt["records"],
        )
    else:
        ckpt = _plan(state, now or utcnow(), full_refresh)
        state.set(CHECKPOINT_KEY, ckpt)
        log.info("nvd %s load, %s window(s), batch %s", ckpt["mode"], len(ckpt["windows"]), ckpt["batch_id"])

    run_ts = datetime.fromisoformat(ckpt["run_ts"])
    batch_id = ckpt["batch_id"]
    final_dir = settings.landing_dir / "nvd" / f"dt={run_ts:%Y-%m-%d}" / f"batch={batch_id}"
    tmp_dir = final_dir.with_name(final_dir.name + ".inprogress")

    for w_idx in range(ckpt["window_idx"], len(ckpt["windows"])):
        raw = ckpt["windows"][w_idx]
        win = (datetime.fromisoformat(raw[0]), datetime.fromisoformat(raw[1])) if raw else None
        first = ckpt["start_index"] if w_idx == ckpt["window_idx"] else 0
        for start_index, page in fetch_pages(
            session, limiter, settings.nvd_api_key, win, start_index=first, sleep=sleep
        ):
            recs = (to_record(item, batch_id, ckpt["run_ts"]) for item in page)
            n = write_ndjson(Path(tmp_dir, f"part-{ckpt['part']:05d}.ndjson"), recs)
            ckpt.update(
                window_idx=w_idx,
                start_index=start_index + len(page),
                part=ckpt["part"] + 1,
                records=ckpt["records"] + n,
            )
            state.set(CHECKPOINT_KEY, ckpt)  # page is on disk: safe to resume after it
        ckpt.update(window_idx=w_idx + 1, start_index=0)
        state.set(CHECKPOINT_KEY, ckpt)

    if ckpt["part"]:
        publish_dir(tmp_dir, final_dir)
    state.set(STATE_KEY, ckpt["run_ts"])
    state.delete(CHECKPOINT_KEY)
    return {
        "source": "nvd",
        "mode": ckpt["mode"],
        "batch_id": batch_id,
        "records": ckpt["records"],
        "files": ckpt["part"],
    }
