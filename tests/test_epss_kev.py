import gzip
import json
from datetime import date, datetime, timezone

import pandas as pd
import pytest

from fakes import API, FakeSession
from vulnintel import epss, kev
from vulnintel.http import RateLimiter
from vulnintel.state import StateStore

NOW = datetime(2026, 11, 8, 2, 0, tzinfo=timezone.utc)


def test_parse_epss_keeps_model_version():
    df, meta = epss.parse_epss((API / "epss_scores-2026-11-07.csv.gz").read_bytes(), date(2026, 11, 7))
    assert meta["model_version"] == "v2025.03.14"
    assert len(df) == 4
    assert set(df.columns) >= {"cve_id", "epss", "percentile", "score_date", "model_version"}


@pytest.mark.parametrize(
    "body, msg",
    [
        ("cve,epss,percentile\nCVE-2020-1938,1.7,0.9\n", "outside"),
        ("cve,epss,percentile\nnot-a-cve,0.1,0.9\n", "malformed"),
        ("cve,epss,percentile\nCVE-2020-1938,0.1,0.9\nCVE-2020-1938,0.2,0.9\n", "duplicate"),
    ],
)
def test_parse_epss_rejects_bad_data(body, msg):
    with pytest.raises(epss.DataQualityError, match=msg):
        epss.parse_epss(gzip.compress(body.encode()), date(2026, 1, 1))


def test_epss_backfill_skips_unpublished_today(settings):
    # backfill_days=2 -> 11-06, 11-07, 11-08. Today's file is not in fixtures (404) -> stop cleanly.
    out = epss.ingest(settings, session=FakeSession(), now=NOW)
    assert out["days"] == 2 and out["records"] == 8 and out["missing"] == []
    assert StateStore(settings.state_file).get(epss.STATE_KEY) == "2026-11-07"
    df = pd.read_parquet(settings.landing_dir / "epss/score_date=2026-11-07/epss.parquet")
    assert df["_batch_id"].iloc[0] == "20261108T020000Z"

    # second run the same day fetches only the missing day
    session = FakeSession()
    epss.ingest(settings, session=session, now=NOW)
    assert [c[0].rsplit("-", 3)[-3:] for c in session.calls] == [["2026", "11", "08.csv.gz"]]


def test_kev_snapshot_once_per_day(settings):
    first = kev.ingest(settings, session=FakeSession(), now=NOW)
    second = kev.ingest(settings, session=FakeSession(), now=NOW)
    assert first["records"] == 2 and not first["skipped"]
    assert second["skipped"]


def test_kev_count_mismatch_is_rejected():
    catalog = json.loads((API / "kev.json").read_text())
    catalog["count"] = 3
    with pytest.raises(kev.DataQualityError, match="count"):
        kev.to_records(catalog, "2026-11-08", "b", "t")


def test_rate_limiter_blocks_sixth_call_in_window():
    t = [0.0]
    slept = []
    rl = RateLimiter(
        5, 30.0, clock=lambda: t[0], sleep=lambda s: (slept.append(s), t.__setitem__(0, t[0] + s))
    )
    for _ in range(5):
        rl.wait()
    assert slept == []
    rl.wait()
    assert slept and slept[0] == pytest.approx(30.1)
