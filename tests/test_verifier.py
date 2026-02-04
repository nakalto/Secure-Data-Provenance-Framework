import sqlite3

from verifier import verify_file_against_provenance
from provenance_engine import register_upload_as_new_version


def test_verify_valid_and_tampered_file(isolated_env, tmp_path):
    stored = tmp_path / "doc.bin"
    stored.write_bytes(b"original")

    # Register upload.
    reg = register_upload_as_new_version(
        filename="doc.bin",
        stored_path=str(stored),
        file_hash="0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5",
        request_id="req1",
        client_ip="127.0.0.1",
        user_agent="pytest",
    )
    case_id = int(reg["case"]["id"])

    # Verify same content.
    verify_path = tmp_path / "verify.bin"
    verify_path.write_bytes(b"original")

    res = verify_file_against_provenance(
        file_path=str(verify_path),
        filename="doc.bin",
        case_id=case_id,
        request_id="req2",
        client_ip="127.0.0.1",
        user_agent="pytest",
    )
    assert res.status == "VALID"

    # Verify modified content.
    verify_path.write_bytes(b"modified")
    res2 = verify_file_against_provenance(
        file_path=str(verify_path),
        filename="doc.bin",
        case_id=case_id,
        request_id="req3",
        client_ip="127.0.0.1",
        user_agent="pytest",
    )
    assert res2.status == "TAMPERED_FILE"


def test_verify_missing_history(isolated_env, tmp_path):
    f = tmp_path / "unknown.bin"
    f.write_bytes(b"x")

    res = verify_file_against_provenance(
        file_path=str(f),
        filename="unknown.bin",
        case_id=9999,
        request_id="req",
        client_ip=None,
        user_agent=None,
    )
    assert res.status == "MISSING_HISTORY"


def test_verify_tampered_hmac(isolated_env, tmp_path):
    stored = tmp_path / "h.bin"
    stored.write_bytes(b"original")

    reg = register_upload_as_new_version(
        filename="h.bin",
        stored_path=str(stored),
        file_hash="0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5",
        request_id="req1",
        client_ip="127.0.0.1",
        user_agent="pytest",
    )
    case_id = int(reg["case"]["id"])

    conn = sqlite3.connect(isolated_env["db_path"])
    try:
        conn.execute(
            "UPDATE provenance_events SET record_hmac = ? WHERE id = (SELECT MAX(id) FROM provenance_events)",
            ("11" * 32,),
        )
        conn.commit()
    finally:
        conn.close()

    verify_path = tmp_path / "verify.bin"
    verify_path.write_bytes(b"original")

    res = verify_file_against_provenance(
        file_path=str(verify_path),
        filename="h.bin",
        case_id=case_id,
        request_id="req2",
        client_ip="127.0.0.1",
        user_agent="pytest",
    )
    assert res.status == "TAMPERED_HMAC"
