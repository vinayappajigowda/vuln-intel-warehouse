"""CISA Known Exploited Vulnerabilities catalog -> one landed snapshot per day.

The catalog is small (~1.5K entries) and is re-published as a whole, so we snapshot it daily.
Daily snapshots let us see when entries are added, edited (e.g. ransomware flag flips)
or removed, which a single "latest" copy would hide.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

import requests

from .config import Settings
from .http import make_session
from .landing import batch_id_for, utcnow, write_ndjson

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class DataQualityError(ValueError):
    pass


def to_records(catalog: dict, snapshot_date: str, batch_id: str, ingested_at: str) -> list[dict]:
    vulns = catalog.get("vulnerabilities", [])
    expected = catalog.get("count")
    if expected is not None and expected != len(vulns):
        raise DataQualityError(f"KEV count says {expected} but file has {len(vulns)} entries")
    ids = [v["cveID"] for v in vulns]
    if len(ids) != len(set(ids)):
        raise DataQualityError("KEV has duplicate cveID values")
    return [
        {
            "cve_id": v["cveID"],
            "date_added": v.get("dateAdded"),
            "catalog_version": catalog.get("catalogVersion"),
            "catalog_released": catalog.get("dateReleased"),
            "snapshot_date": snapshot_date,
            "payload": json.dumps(v, separators=(",", ":")),
            "_batch_id": batch_id,
            "_ingested_at": ingested_at,
        }
        for v in vulns
    ]


def ingest(
    settings: Settings,
    session: requests.Session | None = None,
    now: datetime | None = None,
    force: bool = False,
) -> dict:
    session = session or make_session()
    run_ts = now or utcnow()
    snapshot_date = run_ts.date().isoformat()
    out = settings.landing_dir / "kev" / f"snapshot_date={snapshot_date}" / "kev.ndjson"
    if out.exists() and not force:
        log.info("KEV snapshot for %s already landed", snapshot_date)
        return {"source": "kev", "snapshot_date": snapshot_date, "records": 0, "skipped": True}

    resp = session.get(KEV_URL, timeout=120)
    resp.raise_for_status()
    recs = to_records(resp.json(), snapshot_date, batch_id_for(run_ts), run_ts.isoformat())
    n = write_ndjson(out, recs)
    log.info("KEV %s: %s entries", snapshot_date, n)
    return {"source": "kev", "snapshot_date": snapshot_date, "records": n, "skipped": False}
