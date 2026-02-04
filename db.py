import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator


BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")


def _db_path() -> str:
    return os.environ.get("PROV_DB_PATH", os.path.join(DATA_DIR, "provenance.db"))


def _ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def _connect() -> sqlite3.Connection:
    _ensure_data_dir()
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        # New schema (case-based provenance with file versions and richer audit context).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_uuid TEXT NOT NULL UNIQUE,
              filename TEXT NOT NULL,
              created_time TEXT NOT NULL,
              system_id TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id INTEGER NOT NULL,
              version INTEGER NOT NULL,
              stored_path TEXT NOT NULL,
              file_hash TEXT NOT NULL,
              file_size INTEGER NOT NULL,
              mime_type TEXT,
              upload_time TEXT NOT NULL,
              system_id TEXT NOT NULL,
              FOREIGN KEY(case_id) REFERENCES cases(id)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS provenance_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id INTEGER NOT NULL,
              file_version_id INTEGER,
              action TEXT NOT NULL,
              file_hash TEXT NOT NULL,
              prev_hash TEXT NOT NULL,
              curr_hash TEXT NOT NULL,
              timestamp TEXT NOT NULL,
              system_id TEXT NOT NULL,
              request_id TEXT NOT NULL,
              client_ip TEXT,
              user_agent TEXT,
              record_hmac TEXT NOT NULL,
              FOREIGN KEY(case_id) REFERENCES cases(id),
              FOREIGN KEY(file_version_id) REFERENCES file_versions(id)
            )
            """
        )

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cases_filename ON cases(filename)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_file_versions_case ON file_versions(case_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_case ON provenance_events(case_id)"
        )
