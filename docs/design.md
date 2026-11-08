# Design doc: Vulnerability Intelligence Warehouse

Status: Week 1 (ingestion + staging) · Owner: Vinay Appaji Gowda

## 1. Problem

Security teams prioritise patching with CVSS, which measures *severity*, not *likelihood of
exploitation*. My Vulnerability Risk Prioritiser showed that patching in CVSS order would have
missed 6 of the 10 riskiest findings on one lab VM. This project builds the data platform
behind that idea at full scale: **every CVE ever published, with daily exploit-likelihood history
and known-exploitation status**, modelled for analytics and ML.

End goal (week 4): predict which newly published CVEs will be added to CISA KEV within 30 days,
using only information available at publication time.

## 2. Sources

| Source | What | Size | Update | Access |
|---|---|---|---|---|
| NVD CVE API 2.0 | CVE records, CVSS, CWE, CPE, references | ~300K CVEs | continuous | REST, paginated (2,000/page), 120-day max date window, 5 req/30 s (50 with key) |
| FIRST EPSS | probability of exploitation in next 30 days | ~300K rows/day | daily | `epss_scores-YYYY-MM-DD.csv.gz` |
| CISA KEV | CVEs confirmed exploited in the wild | ~1.5K entries | weekdays, ad hoc | single JSON file |

Planned (week 2–3): GitHub Security Advisories, OSV, Exploit-DB / Metasploit module dates.

## 3. Architecture

```
            ┌──────────────┐     ┌────────────────────┐     ┌──────────────┐     ┌──────────────┐
 NVD API ──>│              │     │ landing zone       │     │ warehouse    │     │ dbt          │
 EPSS CSV ─>│ vulnintel    │ ──> │ (bronze, immutable)│ ──> │ raw schema   │ ──> │ staging      │
 KEV JSON ─>│ ingest       │     │ NDJSON / Parquet   │     │ DuckDB | BQ  │     │ (int, marts) │
            └──────────────┘     │ Hive partitions    │     │ + _load_log  │     │ + data tests │
                   ▲             └────────────────────┘     └──────────────┘     └──────────────┘
                   │ watermarks                    orchestrated daily by Airflow
```

Layers:

* **Landing (bronze)**: files exactly as received plus ingestion metadata (`_batch_id`,
  `_ingested_at`). Never modified, so any downstream bug can be fixed by re-processing.
* **Raw**: append-only tables, one row per landed record. `raw._load_log` records each loaded
  file so loads are exactly-once and re-runnable.
* **Staging** (dbt views): typed, renamed, deduplicated, one clear grain per model.
* **Intermediate / marts** (week 2): EPSS SCD2 history, star schema, ML feature tables.

## 4. Key decisions and trade-offs

| Decision | Why | Trade-off |
|---|---|---|
| Land files first, then load | Replayable; the warehouse can be rebuilt from files; same files work for DuckDB, BigQuery, Spark | Extra storage (small) |
| Keep full NVD JSON in `payload`, parse in dbt | NVD's schema changes (e.g. CVSS v4 added); new fields can be extracted later without re-downloading | Wide JSON strings in raw |
| Incremental NVD on `lastModified` with a 30-min overlap | A CVE modified while the previous run was in flight is not lost | Some duplicates, removed in staging |
| Watermark moves only after a source is fully landed | A crash means "re-run", never "data gap" | None |
| Keep every EPSS day, not just the latest | Needed for SCD2 history and for leakage-free ML features (score *at* publication time) | ~110M rows/year; fine for BigQuery, and why DuckDB defaults to a 90-day backfill |
| Daily KEV snapshots | Reveals edits (e.g. ransomware flag flips) and removals that "latest only" hides | Tiny |
| DuckDB locally, BigQuery in cloud, same dbt models | Free, fast development and CI; cross-db macros isolate the 4 functions that differ | Must test both targets |
| Staging as tables; dedup on narrow keys then join back | A view re-ran ~40 JSON lookups x 421K rows for every test (41 min, disk full on a laptop); tables do it once. Never sort multi-KB payloads | Staging uses disk (~1 GB) |
| No window dedup on EPSS; grain test instead | Loader guarantees one file per score date, loaded once; sorting 27M rows to dedup was the other big spill | Relies on the loader contract, which the test checks every build |
| DuckDB memory and temp-disk limits in the profile | Fail fast instead of filling the disk | Need >= 2 GB for DuckDB |
| Relationship tests set to `warn` | EPSS/KEV can reference a CVE before NVD publishes it; that is normal, not a failure | Need to watch warnings |

## 5. Data quality

* **At ingestion (contract checks)**: EPSS values in [0,1], valid CVE ids, no duplicate ids;
  KEV `count` matches the number of entries. Bad files fail loudly and are not landed.
* **In dbt**: uniqueness of each model's grain, not-null keys, value ranges, accepted values,
  referential integrity (warn), and a singular test (`KEV due_date >= date_added`).
* **Freshness**: `dbt source freshness` warns after 2 days, errors after 4 (7 for KEV).

## 6. Data model (staging, week 1)

| Model | Grain | Notes |
|---|---|---|
| `stg_nvd__cves` | `cve_id` | latest version; CVSS v3.1 prefers NVD "Primary" over CNA "Secondary" |
| `stg_epss__scores` | `cve_id, score_date` | includes `model_version` (score jumps on model changes are not real-world signals) |
| `stg_kev__vulnerabilities` | `snapshot_date, cve_id` | `is_ransomware_linked` flag |

## 7. Roadmap

* **Week 2**: `int_epss__history` as SCD2 (valid_from / valid_to), `dim_cve`, `dim_cwe`,
  `fct_epss_daily`, `fct_kev_additions`; incremental dbt models; CVSS v4 parsing; CPE vendor/product.
* **Week 3**: BigQuery prod target with partitioning/clustering, GCS landing, cost report;
  Great Expectations or dbt contracts on marts; Looker Studio / Evidence dashboard.
* **Week 4**: ML: predict KEV addition within 30 days of publication. Time-based split,
  features frozen at publication time, PR-AUC vs CVSS-only and EPSS-only baselines,
  MLflow tracking, model card that documents misses.

## 8. Metrics to report (fill in as measured)

* CVEs in warehouse: ___ · EPSS rows: ___ · KEV entries: ___  (`vulnintel stats`)
* Full NVD load time: ___ (with key) · daily incremental run time: ___
* dbt tests: ___ passing · freshness SLA met: ___ % of days
* Cost per month on BigQuery: ___
