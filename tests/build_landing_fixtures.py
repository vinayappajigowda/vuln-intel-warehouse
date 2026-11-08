"""Regenerate tests/fixtures/landing from the API fixtures (used by `vulnintel demo` and CI).

python tests/build_landing_fixtures.py
"""

import shutil
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "src"), str(HERE)]

from fakes import FakeSession, NoWaitLimiter  # noqa: E402
from vulnintel import epss, kev, nvd  # noqa: E402
from vulnintel.config import Settings  # noqa: E402

RUN1 = datetime(2026, 11, 7, 2, 0, tzinfo=timezone.utc)
RUN2 = datetime(2026, 11, 8, 2, 0, tzinfo=timezone.utc)

if __name__ == "__main__":
    work = HERE / "fixtures" / "_build"
    shutil.rmtree(work, ignore_errors=True)
    s = replace(Settings.from_env(), data_dir=work, epss_backfill_days=2)
    nvd.ingest(s, session=FakeSession(), limiter=NoWaitLimiter(), now=RUN1)
    nvd.ingest(s, session=FakeSession(["nvd_incremental.json"]), limiter=NoWaitLimiter(), now=RUN2)
    epss.ingest(s, session=FakeSession(), now=RUN2)
    kev.ingest(s, session=FakeSession(), now=RUN2)
    target = HERE / "fixtures" / "landing"
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(work / "landing", target)
    shutil.rmtree(work)
    print("wrote", target)
