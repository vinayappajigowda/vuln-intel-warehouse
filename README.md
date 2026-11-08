# Vulnerability Intelligence Warehouse

A daily data pipeline that collects **every published CVE (NVD)**, **daily exploit-probability
scores (FIRST EPSS)** and **confirmed in-the-wild exploitation (CISA KEV)** into a warehouse,
models them with dbt, and (week 4) predicts which new CVEs will be added to KEV.

```
NVD API / EPSS CSV / KEV JSON
        │  vulnintel ingest   (incremental, rate-limited, retried, watermarked)
        ▼
data/landing/  (bronze: immutable NDJSON + Parquet, Hive-partitioned)
        │  vulnintel load     (exactly-once per file, via raw._load_log)
        ▼
warehouse raw schema   (DuckDB locally · BigQuery in the cloud)
        │  dbt build          (staging models + 24 data tests)
        ▼
staging → (week 2) SCD2 history + star schema → (week 4) ML features
```

Orchestrated by **Airflow 3** · tested in **GitHub Actions** · see [`docs/design.md`](docs/design.md)
for decisions and trade-offs.

## Quick start

```bash
make setup            # venv + install + copy .env.example to .env
make test             # 14 unit tests, offline
make demo             # whole pipeline on fixtures, offline: land → load → dbt build
```

Real data (add a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) to `.env` first):

```bash
vulnintel run         # ingest all → load → freshness → dbt build  (same on Windows/Mac/Linux)
```

The first run does a full NVD load (~420K CVEs: about 5 min with a key, ~25 min without) and
backfills `VULNINTEL_EPSS_BACKFILL_DAYS` of EPSS (default 90). Later runs are incremental.
If the download is interrupted, just run it again: it resumes from the last saved page.

Step by step: `vulnintel ingest all`, `vulnintel load`, `vulnintel dbt build`.
Always run dbt through `vulnintel dbt ...`: it passes the right paths, from any folder.

Explore the result:

```bash
duckdb data/warehouse.duckdb
```
```sql
-- CVEs in KEV, with today's EPSS and CVSS
select n.cve_id, n.cvss3_base_score, e.epss, k.date_added, k.is_ransomware_linked
from staging.stg_kev__vulnerabilities k
join staging.stg_nvd__cves n using (cve_id)
left join staging.stg_epss__scores e
  on e.cve_id = n.cve_id
 and e.score_date = (select max(score_date) from staging.stg_epss__scores)
where k.snapshot_date = (select max(snapshot_date) from staging.stg_kev__vulnerabilities)
order by e.epss desc nulls last
limit 20;
```

## Performance and load testing

`scripts/make_scale_data.py` builds a production-sized warehouse (421K CVEs with ~4.6 KB JSON
payloads + a duplicate batch, 27M EPSS rows = 90 days x 300K, 1.5K KEV) to load-test dbt.
Measured on a 2-CPU / 7 GB machine:

| Staging as | Build + 24 tests | Peak RAM | Temp spill to disk |
|---|---|---|---|
| views (first version) | 39 s | 5.8 GB | 1.7 GB |
| **tables + narrow-key dedup** | **26 s** | **3.7 GB** | **0** |

On a real Windows laptop the view version took 41 min and spilled until the disk was full
(140 GB): every test re-parsed all NVD JSON, 4 at a time. Fixes: staging materialized as tables,
dedup ranks narrow key columns and joins back (payloads are never sorted), EPSS dedup replaced by a
grain test, and DuckDB guard rails (`DUCKDB_MEMORY_LIMIT`, default 4GB, minimum 2GB;
`DUCKDB_MAX_TEMP`, default 20GiB) so a runaway query fails fast instead of filling the disk.

> Keep the project **outside OneDrive/Dropbox** folders: sync clients try to upload the multi-GB
> database and DuckDB's temp files while they are being written.

`vulnintel stats` prints row counts, sizes and coverage for the design doc.

## Airflow

```bash
make airflow          # docker compose up --build → http://localhost:8080  (no login locally)
```

DAG `vulnintel_daily` (03:30 UTC): `ingest_nvd | ingest_epss | ingest_kev → load_raw → dbt_source_freshness → dbt_build`.

## BigQuery

```bash
pip install -e ".[bigquery]"
gcloud auth application-default login
# .env: VULNINTEL_WAREHOUSE=bigquery, GCP_PROJECT=<your-project>
vulnintel load
cd dbt && DBT_TARGET=prod dbt build
```

The same dbt models run on both engines; the few functions that differ are in
`dbt/macros/cross_db.sql`.

## Project layout

```
src/vulnintel/      ingestion (nvd.py, epss.py, kev.py), loader (load.py), CLI
dbt/                dbt project: sources, staging models, generic + singular tests, macros
airflow/dags/       daily DAG
tests/              unit tests, API fixtures, landing fixtures for the offline demo
docs/design.md      design doc
```

## Engineering notes

* **Idempotent everywhere**: ingestion writes temp files and renames; watermarks move only after a
  source is fully landed; the loader skips files already in `raw._load_log` and never reads
  unfinished (`.inprogress`) batches. Any step can be re-run.
* **Resumable**: NVD ingestion checkpoints after every page. The first real run lost its
  connection at 256K of 421K CVEs; the fix retries dropped connections (urllib3 only retries
  status codes) and resumes from the checkpoint. Covered by `tests/test_resilience.py`.
* **Rate limits**: client-side limiter (5 or 50 requests / 30 s) plus retries with exponential
  backoff on 403/429/5xx (NVD answers 403 when throttling).
* **NVD 120-day window**: incremental ranges are split automatically; 30-min overlap avoids gaps.
* **Contract checks at ingestion**: malformed EPSS or KEV files fail before they are landed.
* **Schema drift**: full NVD JSON is kept in `payload`, so new fields (e.g. CVSS v4) can be
  extracted later without re-downloading.

## Status

- [x] Week 1: ingestion, landing zone, raw loads (DuckDB + BigQuery), staging models, data tests, Airflow, CI
- [ ] Week 2: EPSS SCD2 history, star schema, incremental models
- [ ] Week 3: BigQuery production run, partitioning, cost report, dashboard
- [ ] Week 4: KEV-addition prediction model

Data: NVD (NIST), EPSS (FIRST.org), KEV (CISA). This product uses the NVD API but is not
endorsed or certified by the NVD.
