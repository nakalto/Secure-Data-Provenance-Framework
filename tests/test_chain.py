import sqlite3

from provenance_engine import (
    append_provenance_event,
    get_or_create_case_by_filename,
    register_upload_as_new_version,
    validate_case_chain,
)


def test_chain_detects_prev_hash_break(isolated_env, tmp_path):
    # Create a case + a CREATE event.
    fpath = tmp_path / "sample.bin"
    fpath.write_bytes(b"hello")

    reg = register_upload_as_new_version(
        filename="evidence.bin",
        stored_path=str(fpath),
        file_hash="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        request_id="req1",
        client_ip="127.0.0.1",
        user_agent="pytest",
    )
    case_id = int(reg["case"]["id"])

    # Append a VERIFY event.
    append_provenance_event(
        case_id=case_id,
        file_version_id=None,
        action="VERIFY",
        file_hash=reg["version"]["file_hash"],
        request_id="req2",
        client_ip="127.0.0.1",
        user_agent="pytest",
    )

    # Tamper: break the chain by changing prev_hash of the second record.
    conn = sqlite3.connect(isolated_env["db_path"])
    try:
        conn.execute(
            "UPDATE provenance_events SET prev_hash = ? WHERE id = (SELECT MAX(id) FROM provenance_events)",
            ("BAD",),
        )
        conn.commit()
    finally:
        conn.close()

    res = validate_case_chain(case_id)
    assert res.ok is False
    assert res.failure_type == "CHAIN"


def test_chain_detects_hmac_tamper(isolated_env, tmp_path):
    fpath = tmp_path / "sample2.bin"
    fpath.write_bytes(b"hello")

    reg = register_upload_as_new_version(
        filename="evidence2.bin",
        stored_path=str(fpath),
        file_hash="2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        request_id="req1",
        client_ip="127.0.0.1",
        user_agent="pytest",
    )
    case_id = int(reg["case"]["id"])

    conn = sqlite3.connect(isolated_env["db_path"])
    try:
        conn.execute(
            "UPDATE provenance_events SET record_hmac = ? WHERE id = (SELECT MAX(id) FROM provenance_events)",
            ("00" * 32,),
        )
        conn.commit()
    finally:
        conn.close()

    res = validate_case_chain(case_id)
    assert res.ok is False
    assert res.failure_type == "HMAC"
