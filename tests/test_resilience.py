"""Regression tests for the first real run: NVD dropped the connection at ~256K of 421K CVEs."""

from datetime import datetime, timezone

import pytest
import requests

from fakes import FakeSession, NoWaitLimiter
from vulnintel import nvd
from vulnintel.load import RAW_TABLES, landed_files, load_duckdb
from vulnintel.state import StateStore

RUN1 = datetime(2026, 11, 7, 2, 0, tzinfo=timezone.utc)
DROP = requests.exceptions.ChunkedEncodingError("Response ended prematurely")
NO_SLEEP = lambda s: None  # noqa: E731


def test_dropped_connection_is_retried(settings):
    # call 1 (second page) drops once, then succeeds on retry
    session = FakeSession(nvd_failures={1: DROP})
    out = nvd.ingest(settings, session=session, limiter=NoWaitLimiter(), now=RUN1, sleep=NO_SLEEP)
    assert out["records"] == 4 and out["files"] == 2
    assert [c[1]["startIndex"] for c in session.calls] == [0, 2, 2]  # same page asked again
    assert StateStore(settings.state_file).get(nvd.CHECKPOINT_KEY) is None


def test_crash_then_rerun_resumes_from_checkpoint(settings, monkeypatch):
    monkeypatch.setattr(nvd, "MAX_PAGE_ATTEMPTS", 1)  # give up immediately to simulate a crash
    with pytest.raises(requests.exceptions.ChunkedEncodingError):
        nvd.ingest(
            settings,
            session=FakeSession(nvd_failures={1: DROP}),
            limiter=NoWaitLimiter(),
            now=RUN1,
            sleep=NO_SLEEP,
        )

    ckpt = StateStore(settings.state_file).get(nvd.CHECKPOINT_KEY)
    assert ckpt["start_index"] == 2 and ckpt["records"] == 2 and ckpt["part"] == 1
    assert StateStore(settings.state_file).get(nvd.STATE_KEY) is None  # watermark not advanced

    # half-finished batch must be invisible to the loader
    assert all(landed_files(settings, t) == [] for t in RAW_TABLES)
    assert load_duckdb(settings)["nvd_cves"] == 0

    # re-run: continues at startIndex=2 in the same batch, does not start over
    session = FakeSession(nvd_pages=["nvd_full_page2.json"])
    out = nvd.ingest(settings, session=session, limiter=NoWaitLimiter(), sleep=NO_SLEEP)
    assert [c[1]["startIndex"] for c in session.calls] == [2]
    assert out["records"] == 4 and out["files"] == 2
    assert out["batch_id"] == "20261107T020000Z"
    assert StateStore(settings.state_file).get(nvd.STATE_KEY) == RUN1.isoformat()
    assert load_duckdb(settings)["nvd_cves"] == 4


def test_cli_keeps_going_when_one_source_fails(settings, monkeypatch):
    from vulnintel import cli

    def boom(*a, **k):
        raise DROP

    monkeypatch.setattr(cli.nvd, "ingest", boom)
    monkeypatch.setattr(cli.epss, "ingest", lambda s: {"source": "epss", "records": 1})
    monkeypatch.setattr(cli.kev, "ingest", lambda s: {"source": "kev", "records": 1})
    results, failed = cli._ingest(settings, "all", False)
    assert failed == ["nvd"]
    assert [r["source"] for r in results] == ["nvd", "epss", "kev"]
