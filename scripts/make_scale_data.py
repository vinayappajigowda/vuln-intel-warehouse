"""Fill a DuckDB warehouse's raw schema with production-sized synthetic data, for load-testing dbt.

    python scripts/make_scale_data.py data/scale.duckdb --cves 421000 --epss-days 90

Shapes match the real sources (payloads are real NVD records from the test fixtures with new ids),
so parsing cost is realistic. Includes a second NVD batch that re-delivers 2% of CVEs.
"""

import argparse
import json
import time
from pathlib import Path

import duckdb

API = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "api"
DDL = """
create schema if not exists raw;
create or replace table raw.nvd_cves (cve_id varchar, published varchar, last_modified varchar,
  vuln_status varchar, payload varchar, _batch_id varchar, _ingested_at varchar, _source_file varchar);
create or replace table raw.epss_scores (cve_id varchar, epss double, percentile double,
  score_date date, model_version varchar, model_score_ts varchar, _batch_id varchar,
  _ingested_at varchar, _source_file varchar);
create or replace table raw.kev_snapshots (cve_id varchar, date_added varchar, catalog_version varchar,
  catalog_released varchar, snapshot_date varchar, payload varchar, _batch_id varchar, _ingested_at varchar,
  _source_file varchar);
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--cves", type=int, default=421_000)
    ap.add_argument("--epss-days", type=int, default=90)
    ap.add_argument("--epss-per-day", type=int, default=300_000)
    a = ap.parse_args()
    t0 = time.time()
    con = duckdb.connect(a.db)
    con.execute(DDL)

    templates = []
    for f in ("nvd_full_page1.json", "nvd_full_page2.json", "nvd_incremental.json"):
        templates += [v["cve"] for v in json.loads((API / f).read_text())["vulnerabilities"]]
    # pad descriptions/references so payloads are ~real size (NVD averages a few KB per record)
    for t in templates:
        t["references"] = t["references"] * 25
        t["configurations"] = [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "vulnerable": True}
                        ]
                        * 20
                    }
                ]
            }
        ]
    con.execute("create or replace temp table tpl (i int, payload varchar)")
    con.executemany("insert into tpl values (?, ?)", [(i, json.dumps(t)) for i, t in enumerate(templates)])
    n_tpl = len(templates)

    def ids(n):  # CVE-YYYY-NNNNN spread over 1999-2026
        return "'CVE-' || (1999 + (g % 28)) || '-' || lpad(cast(10000 + g // 28 as varchar), 5, '0')"

    con.execute(f"""
      insert into raw.nvd_cves
      select {ids(a.cves)} as cve_id, '2020-01-01T00:00:00.000', '2025-01-01T00:00:00.000', 'Analyzed',
             replace(tpl.payload, json_extract_string(tpl.payload, '$.id'), {ids(a.cves)}),
             'B1', '2026-11-08T10:00:00+00:00', 'nvd/batch1/part-' || (g // 2000) || '.ndjson'
      from range({a.cves}) r(g) join tpl on tpl.i = g % {n_tpl}""")
    # incremental batch: 2% of CVEs modified again -> duplicates that staging must collapse
    con.execute(f"""
      insert into raw.nvd_cves
      select cve_id, published, '2026-11-08T09:00:00.000', vuln_status, payload,
             'B2', '2026-11-09T10:00:00+00:00', 'nvd/batch2/part-0.ndjson'
      from raw.nvd_cves using sample {max(1, a.cves // 50)} rows""")
    con.execute(f"""
      insert into raw.epss_scores
      select {ids(a.epss_per_day)}, random(), random(), date '2026-08-10' + cast(d as int), 'v2025.03.14',
             null, 'E', '2026-11-08T10:00:00+00:00', 'epss/' || d || '.parquet'
      from range({a.epss_days}) t(d), range({a.epss_per_day}) r(g)""")
    con.execute(f"""
      insert into raw.kev_snapshots
      select {ids(1500)}, '2022-03-03', '2026.11.08', null, '2026-11-08',
             '{{"vendorProject":"Apache","product":"Tomcat","dateAdded":"2022-03-03","dueDate":"2022-03-17",'
             || '"knownRansomwareCampaignUse":"Unknown","requiredAction":"Apply updates"}}',
             'K', '2026-11-08T10:00:00+00:00', 'kev/1.ndjson'
      from range(1500) r(g)""")
    for t in ("nvd_cves", "epss_scores", "kev_snapshots"):
        print(t, con.execute(f"select count(*) from raw.{t}").fetchone()[0])
    con.close()
    print(f"built in {time.time() - t0:.0f}s, size {Path(a.db).stat().st_size / 1e9:.1f} GB")


if __name__ == "__main__":
    main()
