from datetime import datetime, timezone

import duckdb

from fakes import FakeSession, NoWaitLimiter
from vulnintel import epss, kev, nvd
from vulnintel.load import load_duckdb

RUN1 = datetime(2026, 11, 7, 2, 0, tzinfo=timezone.utc)
RUN2 = datetime(2026, 11, 8, 2, 0, tzinfo=timezone.utc)


def _counts(settings):
    con = duckdb.connect(str(settings.duckdb_path), read_only=True)
    try:
        return {
            t: con.execute(f"select count(*) from raw.{t}").fetchone()[0]
            for t in ("nvd_cves", "epss_scores", "kev_snapshots")
        }
    finally:
        con.close()


def test_load_is_idempotent_and_incremental(settings):
    nvd.ingest(settings, session=FakeSession(), limiter=NoWaitLimiter(), now=RUN1)
    epss.ingest(settings, session=FakeSession(), now=RUN2)
    kev.ingest(settings, session=FakeSession(), now=RUN2)

    first = load_duckdb(settings)
    assert first == {"nvd_cves": 4, "epss_scores": 8, "kev_snapshots": 2}

    # re-running loads nothing new
    assert load_duckdb(settings) == {"nvd_cves": 0, "epss_scores": 0, "kev_snapshots": 0}
    assert _counts(settings) == {"nvd_cves": 4, "epss_scores": 8, "kev_snapshots": 2}

    # a new incremental NVD batch is appended (dedup happens in dbt staging, not here)
    nvd.ingest(settings, session=FakeSession(["nvd_incremental.json"]), limiter=NoWaitLimiter(), now=RUN2)
    assert load_duckdb(settings)["nvd_cves"] == 1
    assert _counts(settings)["nvd_cves"] == 5
