"""Settings read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _project_path(value: str) -> Path:
    """Relative paths in .env mean "relative to the project folder", wherever you run from."""
    p = Path(value).expanduser()
    return (p if p.is_absolute() else PROJECT_ROOT / p).resolve()


def _load_dotenv(path: Path | None = None) -> None:
    """Tiny .env reader so we don't need python-dotenv. Real env vars win."""
    path = path or (Path(".env") if Path(".env").exists() else PROJECT_ROOT / ".env")
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    nvd_api_key: str | None
    warehouse: str
    duckdb_path: Path
    epss_backfill_days: int
    gcp_project: str | None
    bq_raw_dataset: str
    bq_location: str

    @property
    def landing_dir(self) -> Path:
        return self.data_dir / "landing"

    @property
    def state_file(self) -> Path:
        return self.data_dir / "state" / "watermarks.json"

    @classmethod
    def from_env(cls) -> Settings:
        _load_dotenv()
        data_dir = _project_path(os.getenv("VULNINTEL_DATA_DIR", "data"))
        return cls(
            data_dir=data_dir,
            nvd_api_key=(os.getenv("NVD_API_KEY") or "").strip().strip('"').strip("'") or None,
            warehouse=os.getenv("VULNINTEL_WAREHOUSE", "duckdb").lower(),
            duckdb_path=_project_path(
                os.getenv("VULNINTEL_DUCKDB_PATH") or str(data_dir / "warehouse.duckdb")
            ),
            epss_backfill_days=int(os.getenv("VULNINTEL_EPSS_BACKFILL_DAYS", "90")),
            gcp_project=os.getenv("GCP_PROJECT") or None,
            bq_raw_dataset=os.getenv("BQ_RAW_DATASET", "vulnintel_raw"),
            bq_location=os.getenv("BQ_LOCATION", "US"),
        )
