"""Command line entry point.

vulnintel ingest nvd|epss|kev|all [--full-refresh]
vulnintel load
vulnintel dbt <any dbt args>     # e.g. vulnintel dbt build, vulnintel dbt source freshness
vulnintel run                    # ingest all -> load -> dbt source freshness -> dbt build
vulnintel demo                   # offline: land the test fixtures, then load them
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import epss, kev, nvd
from .config import Settings
from .load import load

log = logging.getLogger("vulnintel")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DBT_DIR = PROJECT_ROOT / "dbt"


def _demo(settings: Settings) -> dict:
    """Copy fixture files into the landing zone so the whole pipeline runs without internet."""
    fixtures = PROJECT_ROOT / "tests" / "fixtures" / "landing"
    if not fixtures.exists():
        raise SystemExit(f"fixtures not found at {fixtures}")
    shutil.copytree(fixtures, settings.landing_dir, dirs_exist_ok=True)
    return {"demo": "fixtures copied", "load": load(settings)}


def _ingest(settings: Settings, source: str, full_refresh: bool) -> tuple[list[dict], list[str]]:
    """Run each source independently: one failing source must not stop the others."""
    jobs = {
        "nvd": lambda: nvd.ingest(settings, full_refresh=full_refresh),
        "epss": lambda: epss.ingest(settings),
        "kev": lambda: kev.ingest(settings),
    }
    selected = list(jobs) if source == "all" else [source]
    results, failed = [], []
    for name in selected:
        try:
            results.append(jobs[name]())
        except Exception as exc:  # noqa: BLE001 - report and carry on with the next source
            log.exception("%s ingest failed; re-run to resume", name)
            results.append({"source": name, "error": f"{type(exc).__name__}: {exc}"})
            failed.append(name)
    return results, failed


def run_dbt(settings: Settings, args: list[str]) -> int:
    """Run dbt from the dbt folder with absolute paths, so it works from any directory/OS."""
    env = dict(os.environ)
    env["DBT_PROFILES_DIR"] = str(DBT_DIR)
    env["VULNINTEL_DUCKDB_PATH"] = str(settings.duckdb_path)  # already absolute
    exe = shutil.which("dbt", path=str(Path(sys.executable).parent)) or shutil.which("dbt") or "dbt"
    log.info("dbt %s  (warehouse: %s)", " ".join(args), settings.duckdb_path)
    return subprocess.call([exe, *args], cwd=DBT_DIR, env=env)


def _stats(settings: Settings) -> dict:
    """Headline numbers for the design doc, and a quick health check of the warehouse."""
    import duckdb

    if not settings.duckdb_path.exists():
        raise SystemExit(f"no warehouse at {settings.duckdb_path}; run `vulnintel load` first")
    con = duckdb.connect(str(settings.duckdb_path), read_only=True)

    def q(sql: str):
        try:
            return con.execute(sql).fetchall()[0]
        except duckdb.Error as exc:  # table not built yet
            return (f"n/a ({type(exc).__name__})",)

    out = {
        "warehouse_file_gb": round(settings.duckdb_path.stat().st_size / 1e9, 2),
        "raw.nvd_cves rows": q("select count(*) from raw.nvd_cves")[0],
        "raw.nvd_cves distinct CVEs": q("select count(distinct cve_id) from raw.nvd_cves")[0],
        "nvd payload avg / max KB": q(
            "select round(avg(strlen(payload)) / 1024, 1), round(max(strlen(payload)) / 1024, 1) "
            "from raw.nvd_cves"
        ),
        "raw.epss_scores rows": q("select count(*) from raw.epss_scores")[0],
        "epss days / first / last": q(
            "select count(distinct score_date), min(score_date)::varchar, max(score_date)::varchar "
            "from raw.epss_scores"
        ),
        "raw.kev_snapshots rows": q("select count(*) from raw.kev_snapshots")[0],
        "files loaded": q("select count(*) from raw._load_log")[0],
        "staging.stg_nvd__cves": q("select count(*) from staging.stg_nvd__cves")[0],
        "  of which in KEV": q(
            "select count(*) from staging.stg_nvd__cves n where exists (select 1 from "
            "staging.stg_kev__vulnerabilities k where k.cve_id = n.cve_id)"
        )[0],
        "  CVSS v3.1 coverage %": q(
            "select round(100.0 * count(cvss3_base_score) / count(*), 1) from staging.stg_nvd__cves"
        )[0],
        "staging.stg_epss__scores": q("select count(*) from staging.stg_epss__scores")[0],
        "staging.stg_kev__vulnerabilities": q("select count(*) from staging.stg_kev__vulnerabilities")[0],
    }
    con.close()
    return out


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["dbt"]:  # pass everything after `dbt` straight through, flags included
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        return run_dbt(Settings.from_env(), argv[1:] or ["build"])

    parser = argparse.ArgumentParser(prog="vulnintel")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ing = sub.add_parser("ingest", help="pull a source into the landing zone")
    ing.add_argument("source", choices=["nvd", "epss", "kev", "all"])
    ing.add_argument("--full-refresh", action="store_true", help="NVD: ignore watermark and checkpoint")
    sub.add_parser("load", help="load new landed files into the warehouse raw schema")
    sub.add_parser("dbt", help="run dbt with the right paths, e.g. `vulnintel dbt build`")
    sub.add_parser("run", help="ingest all -> load -> freshness -> dbt build")
    sub.add_parser("demo", help="offline demo using test fixtures")
    sub.add_parser("stats", help="row counts and sizes (for the design doc)")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    settings = Settings.from_env()

    code = 0
    if args.cmd == "ingest":
        out, failed = _ingest(settings, args.source, args.full_refresh)
        code = 1 if failed else 0
    elif args.cmd == "load":
        out = load(settings)
    elif args.cmd == "run":
        results, failed = _ingest(settings, "all", False)
        out = {"ingest": results, "load": load(settings)}  # load whatever did land
        json.dump(out, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        run_dbt(settings, ["source", "freshness"])  # warnings only; don't block the build
        dbt_code = run_dbt(settings, ["build"])
        if failed:
            log.error("finished with failed sources: %s (re-run to resume)", ", ".join(failed))
        return 1 if (failed or dbt_code) else 0
    elif args.cmd == "stats":
        out = _stats(settings)
    else:
        out = _demo(settings)

    json.dump(out, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
