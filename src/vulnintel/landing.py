"""Landing zone (bronze) helpers.

Layout (Hive-style partitions, so BigQuery/Spark/DuckDB can all read them later):

    data/landing/nvd/dt=2026-11-08/batch=20261108T020000Z/part-00000.ndjson
    data/landing/epss/score_date=2026-11-08/epss.parquet
    data/landing/kev/snapshot_date=2026-11-08/kev.ndjson

Files are written to a temp name and renamed, so a reader never sees half a file.
Landed files are never modified: re-processing always starts from them.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def batch_id_for(ts: datetime) -> str:
    return ts.strftime("%Y%m%dT%H%M%SZ")


def write_ndjson(path: Path, records: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    n = 0
    with tmp.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")))
            f.write("\n")
            n += 1
    os.replace(tmp, path)
    return n


def publish_dir(tmp_dir: Path, final_dir: Path) -> None:
    """Atomically move a fully written batch directory into place."""
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    if final_dir.exists():
        shutil.rmtree(final_dir)
    os.replace(tmp_dir, final_dir)
