"""Daily vulnerability-intelligence pipeline.

    ingest_nvd ─┐
    ingest_epss ├─> load_raw ─> dbt_source_freshness ─> dbt_build
    ingest_kev ─┘

* The three ingests only write files to the landing zone, so they run in parallel.
* load_raw and dbt run one after another (DuckDB allows a single writer).
* Every step is idempotent: retries and backfills are safe.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from airflow.providers.standard.operators.bash import BashOperator
from airflow.sdk import DAG

PROJECT = "/opt/project"
DBT = f"cd {PROJECT} && vulnintel dbt --no-use-colors"

default_args = {
    "owner": "vulnintel",
    "retries": 2,
    "retry_delay": timedelta(minutes=10),
    "retry_exponential_backoff": True,
    "execution_timeout": timedelta(hours=2),  # first full NVD load can take ~15 min without a key
}

with DAG(
    dag_id="vulnintel_daily",
    description="NVD + EPSS + CISA KEV -> landing zone -> warehouse -> dbt",
    schedule="30 3 * * *",  # 03:30 UTC: after EPSS publishes the day's scores
    start_date=datetime(2026, 11, 1),
    catchup=False,  # watermarks handle gaps; no need to replay missed days
    max_active_runs=1,
    default_args=default_args,
    tags=["vulnintel", "ingestion", "dbt"],
) as dag:
    ingest = [
        BashOperator(task_id=f"ingest_{src}", bash_command=f"cd {PROJECT} && vulnintel ingest {src}")
        for src in ("nvd", "epss", "kev")
    ]

    load_raw = BashOperator(task_id="load_raw", bash_command=f"cd {PROJECT} && vulnintel load")

    freshness = BashOperator(task_id="dbt_source_freshness", bash_command=f"{DBT} source freshness")

    dbt_build = BashOperator(task_id="dbt_build", bash_command=f"{DBT} build")

    ingest >> load_raw >> freshness >> dbt_build
