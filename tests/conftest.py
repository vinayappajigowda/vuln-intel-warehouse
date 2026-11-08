import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from vulnintel.config import Settings  # noqa: E402


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Settings:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("vulnintel.config._load_dotenv", lambda *a, **k: None)  # ignore a dev .env
    for var in ("NVD_API_KEY", "VULNINTEL_DATA_DIR", "VULNINTEL_DUCKDB_PATH", "VULNINTEL_WAREHOUSE"):
        monkeypatch.delenv(var, raising=False)
    s = Settings.from_env()
    return replace(
        s,
        data_dir=tmp_path / "data",
        duckdb_path=tmp_path / "data" / "warehouse.duckdb",
        epss_backfill_days=2,
    )
