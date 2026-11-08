import json
from datetime import datetime, timedelta, timezone

from fakes import FakeSession, NoWaitLimiter
from vulnintel import nvd
from vulnintel.state import StateStore

RUN1 = datetime(2026, 11, 7, 2, 0, tzinfo=timezone.utc)
RUN2 = datetime(2026, 11, 8, 2, 0, tzinfo=timezone.utc)


def test_windows_never_exceed_120_days():
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=300)
    wins = list(nvd.windows(start, end))
    assert len(wins) == 3
    assert all(b - a <= timedelta(days=120) for a, b in wins)
    assert wins[0][0] == start and wins[-1][1] == end
    assert all(wins[i][1] == wins[i + 1][0] for i in range(len(wins) - 1))  # no gaps


def test_full_load_paginates_and_sets_watermark(settings):
    session = FakeSession()
    out = nvd.ingest(settings, session=session, limiter=NoWaitLimiter(), now=RUN1)

    assert out["mode"] == "full" and out["records"] == 4 and out["files"] == 2
    starts = [c[1]["startIndex"] for c in session.calls]
    assert starts == [0, 2]  # second page starts where the first ended
    assert "lastModStartDate" not in session.calls[0][1]  # full load: no date filter
    assert StateStore(settings.state_file).get(nvd.STATE_KEY) == RUN1.isoformat()

    files = sorted(settings.landing_dir.glob("nvd/dt=2026-11-07/batch=*/part-*.ndjson"))
    rec = json.loads(files[0].read_text().splitlines()[0])
    assert rec["cve_id"] == "CVE-2021-44228"
    assert json.loads(rec["payload"])["id"] == rec["cve_id"]  # full record kept for dbt


def test_incremental_uses_watermark_with_overlap(settings):
    nvd.ingest(settings, session=FakeSession(), limiter=NoWaitLimiter(), now=RUN1)
    session = FakeSession(nvd_pages=["nvd_incremental.json"])
    out = nvd.ingest(settings, session=session, limiter=NoWaitLimiter(), now=RUN2)

    assert out["mode"] == "incremental" and out["records"] == 1
    params = session.calls[0][1]
    assert params["lastModStartDate"] == (RUN1 - nvd.OVERLAP).isoformat(timespec="milliseconds")
    assert params["lastModEndDate"] == RUN2.isoformat(timespec="milliseconds")


def test_api_key_sent_as_header_not_query(settings):
    from dataclasses import replace

    s = replace(settings, nvd_api_key="secret")
    session = FakeSession()
    nvd.ingest(s, session=session, limiter=NoWaitLimiter(), now=RUN1)
    _url, params, headers = session.calls[0]
    assert headers == {"apiKey": "secret"}
    assert "apiKey" not in params


def test_no_partial_batch_left_behind(settings):
    nvd.ingest(settings, session=FakeSession(), limiter=NoWaitLimiter(), now=RUN1)
    assert not list(settings.landing_dir.glob("**/*.inprogress"))
    assert not list(settings.landing_dir.glob("**/*.tmp"))
