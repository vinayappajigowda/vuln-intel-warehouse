"""Load landed files into the warehouse `raw` schema, exactly once per file.

Each landed file is recorded in raw._load_log. Re-running the loader is safe: files already
loaded are skipped, so a failed run can simply be retried (idempotent loads).

Two targets, same contract:
  * duckdb   - local, free, default for development and CI
  * bigquery - cloud warehouse (load jobs from local files; GCS staging comes later)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from .config import Settings

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RawTable:
    name: str
    glob: str
    fmt: str  # "ndjson" or "parquet"
    columns: dict[str, str]  # column -> DuckDB type


RAW_TABLES = [
    RawTable(
        "nvd_cves",
        "nvd/dt=*/batch=*/part-*.ndjson",
        "ndjson",
        {
            "cve_id": "VARCHAR",
            "published": "VARCHAR",
            "last_modified": "VARCHAR",
            "vuln_status": "VARCHAR",
            "payload": "VARCHAR",
            "_batch_id": "VARCHAR",
            "_ingested_at": "VARCHAR",
        },
    ),
    RawTable(
        "epss_scores",
        "epss/score_date=*/epss.parquet",
        "parquet",
        {
            "cve_id": "VARCHAR",
            "epss": "DOUBLE",
            "percentile": "DOUBLE",
            "score_date": "DATE",
            "model_version": "VARCHAR",
            "model_score_ts": "VARCHAR",
            "_batch_id": "VARCHAR",
            "_ingested_at": "VARCHAR",
        },
    ),
    RawTable(
        "kev_snapshots",
        "kev/snapshot_date=*/kev.ndjson",
        "ndjson",
        {
            "cve_id": "VARCHAR",
            "date_added": "VARCHAR",
            "catalog_version": "VARCHAR",
            "catalog_released": "VARCHAR",
            "snapshot_date": "VARCHAR",
            "payload": "VARCHAR",
            "_batch_id": "VARCHAR",
            "_ingested_at": "VARCHAR",
        },
    ),
]


def _is_unfinished(path: Path) -> bool:
    """Files inside a batch that is still being written (or was interrupted) must not be loaded."""
    return any(part.endswith((".inprogress", ".tmp")) for part in path.parts)


def landed_files(settings: Settings, table: RawTable) -> list[Path]:
    return sorted(p for p in settings.landing_dir.glob(table.glob) if not _is_unfinished(p))


# --------------------------------------------------------------------------- duckdb


def load_duckdb(settings: Settings) -> dict[str, int]:
    import duckdb

    settings.duckdb_path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(settings.duckdb_path))
    try:
        con.execute("CREATE SCHEMA IF NOT EXISTS raw")
        con.execute(
            """CREATE TABLE IF NOT EXISTS raw._load_log (
                   table_name VARCHAR, file_path VARCHAR, row_count BIGINT,
                   loaded_at TIMESTAMP DEFAULT current_timestamp,
                   PRIMARY KEY (table_name, file_path))"""
        )
        summary: dict[str, int] = {}
        for t in RAW_TABLES:
            cols_ddl = ", ".join(f"{c} {ty}" for c, ty in t.columns.items())
            con.execute(f"CREATE TABLE IF NOT EXISTS raw.{t.name} ({cols_ddl}, _source_file VARCHAR)")
            done = {
                r[0]
                for r in con.execute(
                    "SELECT file_path FROM raw._load_log WHERE table_name = ?", [t.name]
                ).fetchall()
            }
            loaded = 0
            for path in landed_files(settings, t):
                rel = path.relative_to(settings.landing_dir).as_posix()
                if rel in done:
                    continue
                col_list = ", ".join(t.columns)
                if t.fmt == "ndjson":
                    struct = "{" + ", ".join(f"'{c}': '{ty}'" for c, ty in t.columns.items()) + "}"
                    reader = f"read_json(?, format='newline_delimited', columns={struct})"
                else:
                    reader = "read_parquet(?)"
                con.execute("BEGIN TRANSACTION")
                try:
                    con.execute(
                        f"INSERT INTO raw.{t.name} SELECT {col_list}, ? FROM {reader}",
                        [rel, str(path)],
                    )
                    n = con.execute(
                        f"SELECT count(*) FROM raw.{t.name} WHERE _source_file = ?", [rel]
                    ).fetchone()[0]
                    con.execute(
                        "INSERT INTO raw._load_log (table_name, file_path, row_count) VALUES (?, ?, ?)",
                        [t.name, rel, n],
                    )
                    con.execute("COMMIT")
                except Exception:
                    con.execute("ROLLBACK")
                    raise
                loaded += n
                log.info("loaded %s rows from %s into raw.%s", n, rel, t.name)
            summary[t.name] = loaded
        return summary
    finally:
        con.close()


# --------------------------------------------------------------------------- bigquery

_BQ_TYPES = {"VARCHAR": "STRING", "DOUBLE": "FLOAT64", "DATE": "DATE", "BIGINT": "INT64"}


def load_bigquery(settings: Settings) -> dict[str, int]:
    from google.cloud import bigquery

    if not settings.gcp_project:
        raise SystemExit("Set GCP_PROJECT in .env to load into BigQuery")
    client = bigquery.Client(project=settings.gcp_project, location=settings.bq_location)
    ds = f"{settings.gcp_project}.{settings.bq_raw_dataset}"
    client.create_dataset(ds, exists_ok=True)
    log_table = f"{ds}._load_log"
    client.query(
        f"CREATE TABLE IF NOT EXISTS `{log_table}` "
        "(table_name STRING, file_path STRING, row_count INT64, loaded_at TIMESTAMP)"
    ).result()

    summary: dict[str, int] = {}
    for t in RAW_TABLES:
        done = {
            r.file_path
            for r in client.query(
                f"SELECT file_path FROM `{log_table}` WHERE table_name = @t",
                job_config=bigquery.QueryJobConfig(
                    query_parameters=[bigquery.ScalarQueryParameter("t", "STRING", t.name)]
                ),
            ).result()
        }
        schema = [bigquery.SchemaField(c, _BQ_TYPES[ty]) for c, ty in t.columns.items()]
        loaded = 0
        for path in landed_files(settings, t):
            rel = path.relative_to(settings.landing_dir).as_posix()
            if rel in done:
                continue
            # load into a per-file staging table, then append with _source_file in one statement
            stage = f"{ds}._stage_{t.name}"
            cfg = bigquery.LoadJobConfig(
                schema=schema,
                write_disposition="WRITE_TRUNCATE",
                source_format=(
                    bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
                    if t.fmt == "ndjson"
                    else bigquery.SourceFormat.PARQUET
                ),
            )
            with path.open("rb") as f:
                client.load_table_from_file(f, stage, job_config=cfg).result()
            cols = ", ".join(t.columns)
            client.query(
                f"""
                CREATE TABLE IF NOT EXISTS `{ds}.{t.name}` AS
                  SELECT {cols}, CAST(NULL AS STRING) AS _source_file FROM `{stage}` WHERE FALSE;
                BEGIN TRANSACTION;
                INSERT INTO `{ds}.{t.name}` SELECT {cols}, @f FROM `{stage}`;
                INSERT INTO `{log_table}`
                  SELECT @t, @f, (SELECT COUNT(*) FROM `{stage}`), CURRENT_TIMESTAMP();
                COMMIT TRANSACTION;
                """,
                job_config=bigquery.QueryJobConfig(
                    query_parameters=[
                        bigquery.ScalarQueryParameter("f", "STRING", rel),
                        bigquery.ScalarQueryParameter("t", "STRING", t.name),
                    ]
                ),
            ).result()
            n = client.get_table(stage).num_rows
            loaded += n
            log.info("loaded %s rows from %s into %s.%s", n, rel, ds, t.name)
        summary[t.name] = loaded
    return summary


def load(settings: Settings) -> dict[str, int]:
    if settings.warehouse == "bigquery":
        return load_bigquery(settings)
    return load_duckdb(settings)
