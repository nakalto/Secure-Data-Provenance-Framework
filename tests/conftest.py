import importlib
import os
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = str(Path(__file__).resolve().parents[1])
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture()
def isolated_env(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    db_path = data_dir / "provenance.db"

    monkeypatch.setenv("PROV_DATA_DIR", str(data_dir))
    monkeypatch.setenv("PROV_DB_PATH", str(db_path))

    # Reload modules so they pick up new environment (DATA_DIR is read at import time).
    import db

    importlib.reload(db)

    import provenance_engine

    importlib.reload(provenance_engine)

    yield {"data_dir": data_dir, "db_path": db_path}
