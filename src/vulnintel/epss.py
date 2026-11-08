"""EPSS daily scores -> landing zone (one Parquet file per score date).

FIRST publishes the full daily file at
    https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz
(about 300K rows). Recent files start with a comment line such as
    #model_version:v2025.03.14,score_date:2025-03-15T12:55:00Z
which we keep, because a model change explains score jumps that are not real-world news.

Keeping every day (not just the latest) is the point: it lets us build EPSS history as a
type-2 slowly changing dimension in week 2 and use "score at publication time" as an ML feature
without leaking future information.
"""

from __future__ import annotations

import gzip
import io
import logging
from datetime import date, datetime, timedelta

import pandas as pd
import requests

from .config import Settings
from .http import make_session
from .landing import batch_id_for, utcnow
from .state import StateStore

log = logging.getLogger(__name__)

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
STATE_KEY = "epss.last_score_date"


class DataQualityError(ValueError):
    pass


def parse_epss(raw_gz: bytes, score_date: date) -> tuple[pd.DataFrame, dict]:
    text = gzip.decompress(raw_gz).decode("utf-8")
    meta: dict = {}
    if text.startswith("#"):
        first, _, text = text.partition("\n")
        for part in first.lstrip("#").split(","):
            key, _, value = part.partition(":")
            meta[key.strip()] = value.strip()
    df = pd.read_csv(io.StringIO(text), dtype={"cve": "string"})
    if "percentile" not in df.columns:  # very old files only had cve,epss
        df["percentile"] = pd.NA

    # contract checks: fail loudly instead of landing bad data
    if df.empty:
        raise DataQualityError(f"EPSS {score_date}: empty file")
    if not df["cve"].str.match(r"^CVE-\d{4}-\d{4,}$").all():
        raise DataQualityError(f"EPSS {score_date}: malformed CVE ids")
    if not df["epss"].between(0, 1).all():
        raise DataQualityError(f"EPSS {score_date}: epss outside [0, 1]")
    if df["cve"].duplicated().any():
        raise DataQualityError(f"EPSS {score_date}: duplicate CVE ids")

    out = pd.DataFrame(
        {
            "cve_id": df["cve"].astype(str),
            "epss": df["epss"].astype("float64"),
            "percentile": pd.to_numeric(df["percentile"], errors="coerce").astype("float64"),
            "score_date": pd.Series([score_date] * len(df), dtype="object"),
            "model_version": meta.get("model_version"),
            "model_score_ts": meta.get("score_date"),
        }
    )
    return out, meta


def dates_to_fetch(last: str | None, today: date, backfill_days: int) -> list[date]:
    start = date.fromisoformat(last) + timedelta(days=1) if last else today - timedelta(days=backfill_days)
    return [start + timedelta(days=i) for i in range((today - start).days + 1)]


def ingest(
    settings: Settings,
    session: requests.Session | None = None,
    now: datetime | None = None,
) -> dict:
    session = session or make_session()
    state = StateStore(settings.state_file)
    run_ts = now or utcnow()
    batch_id = batch_id_for(run_ts)
    today = run_ts.date()

    days = dates_to_fetch(state.get(STATE_KEY), today, settings.epss_backfill_days)
    landed, rows, missing = 0, 0, []
    for d in days:
        out = settings.landing_dir / "epss" / f"score_date={d.isoformat()}" / "epss.parquet"
        if out.exists():
            state.set(STATE_KEY, d.isoformat())
            continue
        resp = session.get(EPSS_URL.format(d=d.isoformat()), timeout=120)
        if resp.status_code == 404:
            if d >= today - timedelta(days=1):
                log.info("EPSS %s not published yet, will pick it up next run", d)
                break
            log.warning("EPSS %s missing upstream, skipping", d)
            missing.append(d.isoformat())
            state.set(STATE_KEY, d.isoformat())
            continue
        resp.raise_for_status()
        df, meta = parse_epss(resp.content, d)
        df["_batch_id"] = batch_id
        df["_ingested_at"] = run_ts.isoformat()
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(".parquet.tmp")
        df.to_parquet(tmp, index=False)
        tmp.replace(out)
        state.set(STATE_KEY, d.isoformat())  # advance one day at a time: safe to resume
        landed += 1
        rows += len(df)
        log.info("EPSS %s: %s rows (model %s)", d, len(df), meta.get("model_version"))
    return {"source": "epss", "batch_id": batch_id, "days": landed, "records": rows, "missing": missing}
