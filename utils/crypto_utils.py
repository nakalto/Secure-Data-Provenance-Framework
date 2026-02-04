import hashlib
import hmac
import json
from typing import Any, Dict


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(file_path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj: Dict[str, Any]) -> str:
    # Stable serialization prevents hash mismatches due to key ordering/whitespace.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_canonical_json(obj: Dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(obj).encode("utf-8"))


def hmac_sha256_hex(key: bytes, message_hex: str) -> str:
    # HMAC over the provenance hash (hex string) keeps the record signing simple and deterministic.
    return hmac.new(key, message_hex.encode("utf-8"), hashlib.sha256).hexdigest()
