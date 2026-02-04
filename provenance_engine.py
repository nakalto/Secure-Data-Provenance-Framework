import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import mimetypes

from db import get_db, init_db

from utils.crypto_utils import hmac_sha256_hex, sha256_canonical_json


DATA_DIR = os.environ.get(
    "PROV_DATA_DIR", os.path.join(os.path.dirname(__file__), "data")
)
SECRET_KEY_PATH = os.path.join(DATA_DIR, "hmac_secret.key")
SYSTEM_ID_PATH = os.path.join(DATA_DIR, "system_id.txt")


GENESIS_PREV_HASH = "GENESIS"


@dataclass(frozen=True)
class ChainValidationResult:
    ok: bool
    error: Optional[str] = None
    failure_type: Optional[str] = None  # CHAIN | HMAC


def _utc_timestamp() -> str:
    # RFC3339 / ISO8601 with timezone for forensic/audit clarity.
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def load_or_create_hmac_key() -> bytes:
    _ensure_data_dir()
    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "rb") as f:
            key = f.read()
        if len(key) < 32:
            raise ValueError("HMAC key is too short; expected at least 32 bytes")
        return key

    key = secrets.token_bytes(32)
    # Create-only semantics to reduce accidental overwrite.
    fd = os.open(SECRET_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def load_or_create_system_id() -> str:
    _ensure_data_dir()
    if os.path.exists(SYSTEM_ID_PATH):
        with open(SYSTEM_ID_PATH, "r", encoding="utf-8") as f:
            system_id = f.read().strip()
        if system_id:
            return system_id

    system_id = f"host-{secrets.token_hex(8)}"
    fd = os.open(SYSTEM_ID_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(system_id)
    return system_id


def compute_record_hash(record_core: Dict[str, Any]) -> str:
    return sha256_canonical_json(record_core)


def compute_record_hmac(hmac_key: bytes, record_hash_hex: str) -> str:
    return hmac_sha256_hex(hmac_key, record_hash_hex)


def validate_chain(records: List[Dict[str, Any]], hmac_key: bytes) -> ChainValidationResult:
    prev = GENESIS_PREV_HASH
    for idx, rec in enumerate(records):
        for field in (
            "id",
            "case_id",
            "action",
            "file_hash",
            "prev_hash",
            "curr_hash",
            "timestamp",
            "system_id",
            "request_id",
            "record_hmac",
        ):
            if field not in rec:
                return ChainValidationResult(
                    False,
                    f"Missing field '{field}' at index {idx}",
                    "CHAIN",
                )

        if rec["prev_hash"] != prev:
            return ChainValidationResult(
                False,
                f"Chain broken at index {idx}: prev_hash mismatch (expected {prev})",
                "CHAIN",
            )

        core = {
            "case_id": rec["case_id"],
            "file_version_id": rec.get("file_version_id"),
            "action": rec["action"],
            "file_hash": rec["file_hash"],
            "prev_hash": rec["prev_hash"],
            "timestamp": rec["timestamp"],
            "system_id": rec["system_id"],
            "request_id": rec["request_id"],
            "client_ip": rec.get("client_ip"),
            "user_agent": rec.get("user_agent"),
        }

        expected_hash = compute_record_hash(core)
        if rec["curr_hash"] != expected_hash:
            return ChainValidationResult(
                False, f"Record hash mismatch at index {idx}", "CHAIN"
            )

        expected_hmac = compute_record_hmac(hmac_key, expected_hash)
        if rec["record_hmac"] != expected_hmac:
            return ChainValidationResult(False, f"HMAC mismatch at index {idx}", "HMAC")

        prev = rec["curr_hash"]

    return ChainValidationResult(True)


def init_provenance() -> None:
    init_db()
    load_or_create_hmac_key()
    load_or_create_system_id()


def _row_to_dict(row: Any) -> Dict[str, Any]:
    return dict(row)


def _guess_mime_type(filename: str) -> Optional[str]:
    mime, _ = mimetypes.guess_type(filename)
    return mime


def get_or_create_case_by_filename(*, filename: str) -> Dict[str, Any]:
    init_provenance()
    system_id = load_or_create_system_id()
    ts = _utc_timestamp()

    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM cases WHERE filename = ? ORDER BY id DESC LIMIT 1",
            (filename,),
        ).fetchone()
        if row:
            return _row_to_dict(row)

        case_uuid = str(uuid.uuid4())
        cur = conn.execute(
            """
            INSERT INTO cases (case_uuid, filename, created_time, system_id)
            VALUES (?, ?, ?, ?)
            """,
            (case_uuid, filename, ts, system_id),
        )
        case_id = int(cur.lastrowid)
        return {
            "id": case_id,
            "case_uuid": case_uuid,
            "filename": filename,
            "created_time": ts,
            "system_id": system_id,
        }


def get_latest_case_by_filename(filename: str) -> Optional[Dict[str, Any]]:
    init_provenance()
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM cases WHERE filename = ? ORDER BY id DESC LIMIT 1",
            (filename,),
        ).fetchone()
        return _row_to_dict(row) if row else None


def get_case(case_id: int) -> Optional[Dict[str, Any]]:
    init_provenance()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        return _row_to_dict(row) if row else None


def create_file_version(
    *,
    case_id: int,
    stored_path: str,
    file_hash: str,
    file_size: int,
    mime_type: Optional[str],
) -> Dict[str, Any]:
    init_provenance()
    system_id = load_or_create_system_id()
    ts = _utc_timestamp()

    with get_db() as conn:
        cur = conn.execute(
            """
            SELECT COALESCE(MAX(version), 0) + 1 AS next_version
            FROM file_versions
            WHERE case_id = ?
            """,
            (case_id,),
        )
        next_version = int(cur.fetchone()["next_version"])

        cur2 = conn.execute(
            """
            INSERT INTO file_versions (case_id, version, stored_path, file_hash, file_size, mime_type, upload_time, system_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (case_id, next_version, stored_path, file_hash, file_size, mime_type, ts, system_id),
        )
        version_id = int(cur2.lastrowid)
        return {
            "id": version_id,
            "case_id": case_id,
            "version": next_version,
            "stored_path": stored_path,
            "file_hash": file_hash,
            "file_size": file_size,
            "mime_type": mime_type,
            "upload_time": ts,
            "system_id": system_id,
        }


def get_latest_file_version(case_id: int) -> Optional[Dict[str, Any]]:
    init_provenance()
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM file_versions WHERE case_id = ? ORDER BY version DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        return _row_to_dict(row) if row else None


def append_provenance_event(
    *,
    case_id: int,
    file_version_id: Optional[int],
    action: str,
    file_hash: str,
    request_id: str,
    client_ip: Optional[str],
    user_agent: Optional[str],
) -> Dict[str, Any]:
    init_provenance()
    hmac_key = load_or_create_hmac_key()
    system_id = load_or_create_system_id()
    ts = _utc_timestamp()

    with get_db() as conn:
        last = conn.execute(
            "SELECT * FROM provenance_events WHERE case_id = ? ORDER BY id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        prev_hash = last["curr_hash"] if last else GENESIS_PREV_HASH

        core = {
            "case_id": case_id,
            "file_version_id": file_version_id,
            "action": action,
            "file_hash": file_hash,
            "prev_hash": prev_hash,
            "timestamp": ts,
            "system_id": system_id,
            "request_id": request_id,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }
        curr_hash = compute_record_hash(core)
        record_hmac = compute_record_hmac(hmac_key, curr_hash)

        cur = conn.execute(
            """
            INSERT INTO provenance_events
              (case_id, file_version_id, action, file_hash, prev_hash, curr_hash, timestamp, system_id, request_id, client_ip, user_agent, record_hmac)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                file_version_id,
                action,
                file_hash,
                prev_hash,
                curr_hash,
                ts,
                system_id,
                request_id,
                client_ip,
                user_agent,
                record_hmac,
            ),
        )
        event_id = int(cur.lastrowid)
        return {
            "id": event_id,
            "case_id": case_id,
            "file_version_id": file_version_id,
            "action": action,
            "file_hash": file_hash,
            "prev_hash": prev_hash,
            "curr_hash": curr_hash,
            "timestamp": ts,
            "system_id": system_id,
            "request_id": request_id,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "record_hmac": record_hmac,
        }


def list_provenance_events(case_id: int) -> List[Dict[str, Any]]:
    init_provenance()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM provenance_events WHERE case_id = ? ORDER BY id ASC",
            (case_id,),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def validate_case_chain(case_id: int) -> ChainValidationResult:
    init_provenance()
    hmac_key = load_or_create_hmac_key()
    records = list_provenance_events(case_id)
    return validate_chain(records, hmac_key)


def list_recent_cases(limit: int = 10) -> List[Dict[str, Any]]:
    init_provenance()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM cases ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def register_upload_as_new_version(
    *,
    filename: str,
    stored_path: str,
    file_hash: str,
    request_id: str,
    client_ip: Optional[str],
    user_agent: Optional[str],
) -> Dict[str, Any]:
    init_provenance()

    case = get_or_create_case_by_filename(filename=filename)
    case_id = int(case["id"])
    file_size = int(os.path.getsize(stored_path))
    mime_type = _guess_mime_type(filename)

    version = create_file_version(
        case_id=case_id,
        stored_path=stored_path,
        file_hash=file_hash,
        file_size=file_size,
        mime_type=mime_type,
    )

    event = append_provenance_event(
        case_id=case_id,
        file_version_id=int(version["id"]),
        action="CREATE",
        file_hash=file_hash,
        request_id=request_id,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    return {"case": case, "version": version, "event": event}
